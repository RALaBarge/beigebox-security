"""
OperatorTool — exposes the operator skill as a callable BeigeBox tool.

Registered in the tool registry under the name "operator". This lets any
MCP client (Claude Code, external scripts, other operators) invoke the
agentic loop via /mcp tools/call without needing to run the CLI directly.

The tool is sync (Tool protocol requires run(input_text) -> str) but the
operator loop is async. We run it in a thread with its own event loop to
avoid conflicts with BeigeBox's FastAPI event loop.

Input JSON
----------
{
  "task": "find all TODO comments and summarize them",
  "model": "qwen2.5-coder:7b",      // optional
  "working_dir": "/path/to/project", // optional
  "profile": "code-task",            // optional
  "max_turns": 20                    // optional
}

Or pass a plain string — it's treated as the task.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import threading

logger = logging.getLogger(__name__)


class OperatorTool:
    description = (
        "Run a multi-step agentic task through the BeigeBox operator loop. "
        "The operator uses available tools (file read/write, search, bash, web) "
        "to complete the task autonomously. All calls are logged to wiretap. "
        'Input JSON: {"task": "your task description"} '
        'Optional: "model", "working_dir", "profile" (code-task|deploy-task|audit-task|open), "max_turns".'
    )

    def run(self, input_text: str) -> str:
        try:
            params = json.loads(input_text)
            if not isinstance(params, dict):
                params = {"task": input_text.strip()}
        except json.JSONDecodeError:
            params = {"task": input_text.strip()}

        task = params.get("task", "")
        if not task:
            return "Error: task required"

        kwargs = {
            "task": task,
            "model": params.get("model", ""),
            "working_dir": params.get("working_dir", ""),
            "profile": params.get("profile", "code-task"),
            "max_turns": int(params.get("max_turns", 30)),
        }

        from beigebox.skills.operator.loop import run

        result_holder: list[dict | Exception] = []

        def _run_in_thread() -> None:
            try:
                result_holder.append(asyncio.run(run(**kwargs)))
            except Exception as exc:
                result_holder.append(exc)

        t = threading.Thread(target=_run_in_thread, daemon=True)
        t.start()
        t.join(timeout=600)

        if t.is_alive():
            return "Error: operator timed out after 600s"
        if not result_holder:
            return "Error: operator thread returned no result"

        outcome = result_holder[0]
        if isinstance(outcome, Exception):
            logger.error("OperatorTool error: %s", outcome)
            return f"Error: {outcome}"

        result = outcome

        answer = result.get("answer", "")
        turns = result.get("turns", 0)
        session_id = result.get("session_id", "")
        n_tools = len(result.get("tool_calls", []))

        footer = f"\n\n[{turns} turns · {n_tools} tool calls · session {session_id}]"
        return (answer or "[no answer]") + footer
