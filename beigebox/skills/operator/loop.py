"""
Operator agentic loop.

Runs a multi-turn conversation against BeigeBox's /v1/chat/completions,
dispatching all tool calls back through /mcp so wiretap records everything.

Every request carries the same conversation_id so wiretap can correlate
completions, tool calls, and results into one trace per session.

Orientation order (system prompt assembly):
  1. Base instructions + working_dir
  2. OPERATOR.md in working_dir (project-specific instructions)
  3. CLAUDE.md fallback if no OPERATOR.md found
  4. BeigeBox memory recall for the task (your vector store)
  5. extra_context arg (caller-supplied override)

Streaming: pass on_token=callable to receive text tokens as they arrive.
Tool call dispatch and discover_tools expansion work the same in both modes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "http://localhost:1337"
_DEFAULT_MAX_TURNS = 30
_DEFAULT_TIMEOUT = 120.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_base_url() -> str:
    try:
        from beigebox.config import get_config
        port = get_config().get("server", {}).get("port", 1337)
        return f"http://localhost:{port}"
    except Exception:
        return _DEFAULT_BASE_URL


def _mcp_to_openai(t: dict) -> dict:
    return {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("inputSchema", {"type": "object", "properties": {}}),
        },
    }


def _read_orientation_file(working_dir: str) -> str:
    """Read OPERATOR.md, falling back to CLAUDE.md."""
    wd = Path(working_dir).resolve() if working_dir else Path.cwd()
    for name in ("OPERATOR.md", "CLAUDE.md"):
        p = wd / name
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    logger.info("operator orientation: loaded %s (%d chars)", name, len(text))
                    return f"# Project instructions ({name})\n\n{text}"
            except OSError:
                pass
    return ""


async def _fetch_tool_list(
    client: httpx.AsyncClient, base_url: str, session_id: str
) -> list[dict]:
    """Resident tools + discover_tools from BeigeBox MCP (progressive disclosure)."""
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/list", "params": {},
        "conversation_id": session_id,
    }
    resp = await client.post(f"{base_url}/mcp", json=payload)
    resp.raise_for_status()
    tools = resp.json().get("result", {}).get("tools", [])
    return [_mcp_to_openai(t) for t in tools]


# Tools that accept working_dir injection in their JSON input
_WD_AWARE_TOOLS = frozenset({
    "read_file", "write_file", "edit_file", "glob", "search", "directory_tree", "bash",
})


async def _call_tool(
    client: httpx.AsyncClient, base_url: str, session_id: str,
    tool_name: str, tool_input: str,
    *,
    working_dir: str = "",
    profile: str = "",
) -> str | None:
    """
    Call a tool through BeigeBox /mcp.

    Returns the text result, or None if the tool returned isError: True.
    Injects working_dir and profile into JSON inputs for fs/bash tools.
    """
    # Inject working_dir and profile into fs/bash tool inputs
    if working_dir and tool_name in _WD_AWARE_TOOLS:
        try:
            args = json.loads(tool_input) if isinstance(tool_input, str) else {}
            if not isinstance(args, dict):
                args = {}
            args["working_dir"] = working_dir
            if profile and tool_name == "bash":
                args.setdefault("profile", profile)
            tool_input = json.dumps(args)
        except (json.JSONDecodeError, TypeError):
            pass

    payload = {
        "jsonrpc": "2.0", "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": {"input": tool_input}},
        "conversation_id": session_id,
    }
    try:
        resp = await client.post(f"{base_url}/mcp", json=payload, timeout=_DEFAULT_TIMEOUT)
        resp.raise_for_status()
        result = resp.json().get("result", {})
        if result.get("isError", False):
            content = result.get("content", [])
            err_text = (
                "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
                if isinstance(content, list) else str(result)
            )
            logger.debug("tool %s returned isError: %s", tool_name, err_text[:200])
            return None
        content = result.get("content", [])
        if isinstance(content, list):
            return "\n".join(c.get("text", "") for c in content if isinstance(c, dict)) or json.dumps(result)
        return str(result)
    except Exception as exc:
        return f"Tool error: {exc}"


async def _streaming_turn(
    client: httpx.AsyncClient,
    base_url: str,
    body: dict,
    on_token: Callable[[str], None] | None,
) -> tuple[dict, str]:
    """
    Stream one completion turn. Returns (assembled_message, finish_reason).

    Text tokens are passed to on_token as they arrive.
    Tool call deltas are accumulated by index into complete descriptors.
    """
    accumulated_content = ""
    tool_call_chunks: dict[int, dict] = {}  # index -> {id, name, arguments}
    finish_reason = "stop"

    async with client.stream("POST", f"{base_url}/v1/chat/completions", json=body) as resp:
        resp.raise_for_status()
        async for line in resp.aiter_lines():
            if not line.startswith("data: "):
                continue
            data = line[6:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue

            choice = chunk.get("choices", [{}])[0]
            delta = choice.get("delta", {})
            fr = choice.get("finish_reason")
            if fr:
                finish_reason = fr

            # Text token
            token = delta.get("content") or ""
            if token:
                accumulated_content += token
                if on_token:
                    on_token(token)

            # Tool call deltas — accumulate by index
            for tc in delta.get("tool_calls", []):
                idx = tc.get("index", 0)
                if idx not in tool_call_chunks:
                    tool_call_chunks[idx] = {"id": "", "name": "", "arguments": ""}
                if tc.get("id"):
                    tool_call_chunks[idx]["id"] = tc["id"]
                fn = tc.get("function", {})
                if fn.get("name"):
                    tool_call_chunks[idx]["name"] = fn["name"]
                if fn.get("arguments"):
                    tool_call_chunks[idx]["arguments"] += fn["arguments"]

    # Assemble message in the same shape as a non-streaming response
    message: dict[str, Any] = {"role": "assistant", "content": accumulated_content or None}
    if tool_call_chunks:
        message["tool_calls"] = [
            {
                "id": v["id"] or f"call_{idx}",
                "type": "function",
                "function": {"name": v["name"], "arguments": v["arguments"]},
            }
            for idx, v in sorted(tool_call_chunks.items())
        ]

    return message, finish_reason


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def run(
    task: str,
    *,
    model: str = "",
    working_dir: str = "",
    profile: str = "code-task",
    max_turns: int = _DEFAULT_MAX_TURNS,
    system_prompt: str = "",
    base_url: str = "",
    api_key: str = "none",
    extra_context: str = "",
    on_token: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """
    Run the operator loop for the given task.

    Parameters
    ----------
    task:        The user's task description.
    model:       Model name (BeigeBox routes it). Defaults to BeigeBox default.
    working_dir: Project root. Sets SafePath scope for fs/bash tools.
    profile:     Sandbox profile for bash (code-task | deploy-task | audit-task | open).
    max_turns:   Hard stop on conversation turns.
    system_prompt: Override the auto-generated system prompt entirely.
    base_url:    BeigeBox base URL. Auto-detected from config if empty.
    api_key:     BeigeBox API key. "none" accepted by default.
    extra_context: Appended to system prompt after orientation.
    on_token:    Callback receiving streamed text tokens. Enables streaming mode.

    Returns
    -------
    dict: answer, turns, session_id, tool_calls
    """
    resolved_url = base_url or _get_base_url()
    session_id = str(uuid.uuid4())

    # Pin working dir for this async context — fs and bash tools read this.
    if working_dir:
        from beigebox.tools._ctx import set_working_dir
        set_working_dir(working_dir)

    from beigebox.tools._ctx import get_working_dir
    wd = working_dir or str(get_working_dir())

    # --- System prompt assembly ---
    if not system_prompt:
        system_prompt = (
            "You are an autonomous operator. Complete the user's task using the tools available. "
            "Think step by step. Use tools to gather information before acting. "
            f"Working directory: {wd}. All file paths are relative to this directory. "
            "When the task is fully complete, respond with your final answer and stop."
        )

    # OPERATOR.md / CLAUDE.md — project-specific instructions
    orientation_file = _read_orientation_file(wd)
    if orientation_file:
        system_prompt += f"\n\n{orientation_file}"

    if extra_context:
        system_prompt += f"\n\n{extra_context}"

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task},
    ]

    tool_call_log: list[dict] = []
    final_answer = ""
    turns = 0

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=_DEFAULT_TIMEOUT,
    ) as client:
        tools = await _fetch_tool_list(client, resolved_url, session_id)
        logger.info("operator session=%s model=%s tools=%d stream=%s",
                    session_id, model or "default", len(tools), on_token is not None)

        # Memory orientation — query vector store with task before first turn.
        # Surfaces relevant prior context without consuming a model turn.
        recalled = await _call_tool(client, resolved_url, session_id, "memory", task)
        if recalled:
            messages[0]["content"] += f"\n\nRelevant context from memory:\n{recalled}"
            logger.info("operator memory orientation: %d chars", len(recalled))

        known_tool_names = {t["function"]["name"] for t in tools}

        for turn in range(max_turns):
            turns = turn + 1

            body: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "stream": on_token is not None,
                "conversation_id": session_id,
            }
            if tools:
                body["tools"] = tools
                body["tool_choice"] = "auto"

            try:
                if on_token is not None:
                    message, finish_reason = await _streaming_turn(
                        client, resolved_url, body, on_token
                    )
                else:
                    resp = await client.post(
                        f"{resolved_url}/v1/chat/completions",
                        json=body, timeout=_DEFAULT_TIMEOUT,
                    )
                    resp.raise_for_status()
                    choice = resp.json().get("choices", [{}])[0]
                    message = choice.get("message", {})
                    finish_reason = choice.get("finish_reason", "stop")
            except Exception as exc:
                logger.error("completion error turn=%d: %s", turns, exc)
                final_answer = f"Error on turn {turns}: {exc}"
                break

            messages.append(message)

            if finish_reason == "stop" or not message.get("tool_calls"):
                final_answer = message.get("content") or ""
                logger.info("operator done session=%s turns=%d", session_id, turns)
                break

            # Dispatch tool calls through BeigeBox /mcp
            tool_results = []
            for tc in message.get("tool_calls", []):
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")

                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    args = {}

                tool_input = args.get("input", raw_args)

                if on_token:
                    on_token(f"\n[{tool_name}]\n")

                logger.info("operator tool=%s session=%s", tool_name, session_id)
                result_text = await _call_tool(
                    client, resolved_url, session_id, tool_name, tool_input,
                    working_dir=wd, profile=profile,
                )

                # None means the tool returned isError — surface a clear message
                if result_text is None:
                    result_text = f"Error: tool '{tool_name}' returned an error. Check BeigeBox logs."

                # discover_tools expands the active tool list for this session
                if tool_name == "discover_tools":
                    try:
                        discovered = json.loads(result_text)
                        if isinstance(discovered, list):
                            for dt in discovered:
                                if isinstance(dt, dict) and dt.get("name") not in known_tool_names:
                                    tools.append(_mcp_to_openai(dt))
                                    known_tool_names.add(dt["name"])
                                    logger.info("operator discovered tool=%s", dt["name"])
                    except (json.JSONDecodeError, TypeError):
                        pass

                tool_call_log.append({
                    "turn": turns, "tool": tool_name,
                    "input": tool_input, "result": result_text[:500],
                })
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": result_text,
                })

            messages.extend(tool_results)

        else:
            final_answer = f"[Stopped after {max_turns} turns]"
            logger.warning("operator max_turns=%d session=%s", max_turns, session_id)

    return {
        "answer": final_answer,
        "turns": turns,
        "session_id": session_id,
        "tool_calls": tool_call_log,
    }
