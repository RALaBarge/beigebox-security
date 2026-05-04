"""
Per-route security policy engine — a small WAF-style DSL.

Policies are declared in ``config.yaml`` under ``security.policies`` and
enforced by :class:`PolicyMiddleware`. The intent is to let an operator
ratchet down request shape on a per-route basis without writing code:

    security:
      policies:
        enabled: true
        default:
          max_body_bytes: 1048576       # 1 MiB
          max_messages: 100
          max_tool_args_depth: 8
          max_attachments: 10
          allowed_content_types: ["application/json", "text/plain", "multipart/form-data"]
          rate_cap_rpm: 1000
        rules:
          - match: { path: "/v1/chat/completions", method: "POST" }
            max_body_bytes: 524288
            max_messages: 50
            rate_cap_rpm: 200
          - match: { path: "/v1/embeddings" }
            max_body_bytes: 2097152
          - match: { path: "/pen-mcp" }
            max_body_bytes: 65536
            rate_cap_rpm: 30

Match semantics: first rule whose ``match.path`` (fnmatch glob) and
``match.method`` (case-insensitive, optional) matches the request wins.
Unset fields fall through to ``default``. If neither default nor rule
sets a field, the field is unenforced.

Rate cap is per-rule, in-process, sliding 60s window keyed on (rule_id,
client_ip). It runs alongside the per-key auth rate limit — the two are
independent ceilings.

Body-shape checks (max_messages, max_tool_args_depth, max_attachments)
parse the body once. Non-JSON bodies skip those checks gracefully.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    rule_id: str
    path_glob: str = "*"
    method: str | None = None  # uppercase, or None = any
    max_body_bytes: int | None = None
    max_messages: int | None = None
    max_tool_args_depth: int | None = None
    # Total serialized JSON size cap for tool-related fields in the body
    # (``tools``, ``tool_calls``, and any inline ``arguments`` / ``args``).
    # Closes the "10 MB args array → wrapped binary OOMs" DoS that the
    # depth check alone can't catch.
    max_tool_args_bytes: int | None = None
    # Longest single string-value cap inside any tool-args structure. A 10 MB
    # single-string arg is the canonical bypass for the bytes-cap above when
    # the wrapper is fed a big JSON envelope around one giant string.
    max_tool_arg_string_length: int | None = None
    max_attachments: int | None = None
    allowed_content_types: list[str] | None = None
    rate_cap_rpm: int | None = None

    def matches(self, path: str, method: str) -> bool:
        if not fnmatch.fnmatch(path, self.path_glob):
            return False
        if self.method and self.method != method.upper():
            return False
        return True


@dataclass
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str = ""
    code: str = ""

    @classmethod
    def ok(cls, rule_id: str) -> "PolicyDecision":
        return cls(allowed=True, rule_id=rule_id)

    @classmethod
    def deny(cls, rule_id: str, reason: str, code: str) -> "PolicyDecision":
        return cls(allowed=False, rule_id=rule_id, reason=reason, code=code)


def _max_depth(obj: Any, current: int = 0) -> int:
    """Return the max nesting depth of nested dicts/lists in *obj*."""
    if isinstance(obj, dict):
        return max((_max_depth(v, current + 1) for v in obj.values()), default=current)
    if isinstance(obj, list):
        return max((_max_depth(v, current + 1) for v in obj), default=current)
    return current


def _max_string_length(obj: Any) -> int:
    """Return the longest string value found anywhere inside *obj*.

    Walks dicts and lists recursively. Used to enforce the tool-arg
    string-length cap independent of total bytes — a 10 MB single string
    field defeats a bytes cap if the wrapper trims whitespace before
    counting, but the per-string cap catches it directly.
    """
    if isinstance(obj, str):
        return len(obj)
    if isinstance(obj, dict):
        best = 0
        for k, v in obj.items():
            if isinstance(k, str) and len(k) > best:
                best = len(k)
            n = _max_string_length(v)
            if n > best:
                best = n
        return best
    if isinstance(obj, list):
        best = 0
        for v in obj:
            n = _max_string_length(v)
            if n > best:
                best = n
        return best
    return 0


def _tool_args_payloads(parsed: Any) -> list[Any]:
    """Collect every tool-related sub-structure worth size-checking.

    Looks at three OpenAI-shaped fields:
      * ``tools`` — array of tool definitions (with nested JSON-Schema args).
      * ``tool_calls`` — assistant-emitted calls; each ``function.arguments``
        is a *string* of JSON, which we treat as a single string for the
        per-string cap and let the total-bytes pass over the raw value.
      * ``messages[*].tool_calls`` — same shape, embedded in chat history.

    Returns a list of objects to feed to size/length walkers. Order is not
    significant; the policy check treats them as a single aggregate.
    """
    payloads: list[Any] = []
    if not isinstance(parsed, dict):
        return payloads
    tools = parsed.get("tools")
    if isinstance(tools, list):
        payloads.append(tools)
    top_calls = parsed.get("tool_calls")
    if isinstance(top_calls, list):
        payloads.append(top_calls)
    msgs = parsed.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            if isinstance(m, dict):
                tc = m.get("tool_calls")
                if isinstance(tc, list):
                    payloads.append(tc)
    return payloads


class PolicyEngine:
    """Compiles + matches rules. Stateless across requests except rate windows."""

    def __init__(self, cfg: dict | None = None):
        pol_cfg = ((cfg or {}).get("security") or {}).get("policies") or {}
        self.enabled: bool = bool(pol_cfg.get("enabled", False))
        # Trusted edge proxies whose X-Forwarded-For / X-Real-IP we honor for
        # client-IP resolution. Anything else falls back to the direct socket
        # peer so a client can't spoof their rate-limit bucket.
        self.trusted_proxies: set[str] = set(pol_cfg.get("trusted_proxies", []) or [])

        default_block = pol_cfg.get("default") or {}
        self._default = PolicyRule(
            rule_id="default",
            path_glob="*",
            method=None,
            max_body_bytes=default_block.get("max_body_bytes"),
            max_messages=default_block.get("max_messages"),
            max_tool_args_depth=default_block.get("max_tool_args_depth"),
            max_tool_args_bytes=default_block.get("max_tool_args_bytes"),
            max_tool_arg_string_length=default_block.get("max_tool_arg_string_length"),
            max_attachments=default_block.get("max_attachments"),
            allowed_content_types=default_block.get("allowed_content_types"),
            rate_cap_rpm=default_block.get("rate_cap_rpm"),
        )

        self._rules: list[PolicyRule] = []
        for idx, raw in enumerate(pol_cfg.get("rules", []) or []):
            match = raw.get("match") or {}
            self._rules.append(PolicyRule(
                rule_id=f"rule_{idx}_{match.get('path', '*')}",
                path_glob=match.get("path", "*"),
                method=(match.get("method") or "").upper() or None,
                max_body_bytes=raw.get("max_body_bytes"),
                max_messages=raw.get("max_messages"),
                max_tool_args_depth=raw.get("max_tool_args_depth"),
                max_tool_args_bytes=raw.get("max_tool_args_bytes"),
                max_tool_arg_string_length=raw.get("max_tool_arg_string_length"),
                max_attachments=raw.get("max_attachments"),
                allowed_content_types=raw.get("allowed_content_types"),
                rate_cap_rpm=raw.get("rate_cap_rpm"),
            ))

        self._rate_lock = Lock()
        self._rate_windows: dict[tuple[str, str], deque[float]] = {}

        if self.enabled:
            logger.info(
                "PolicyEngine enabled (%d rules + default; default body cap=%s)",
                len(self._rules), self._default.max_body_bytes,
            )

    def resolve(self, path: str, method: str) -> PolicyRule:
        """Return the first matching rule, with default values folded in."""
        for r in self._rules:
            if r.matches(path, method):
                return PolicyRule(
                    rule_id=r.rule_id,
                    path_glob=r.path_glob,
                    method=r.method,
                    max_body_bytes=r.max_body_bytes if r.max_body_bytes is not None else self._default.max_body_bytes,
                    max_messages=r.max_messages if r.max_messages is not None else self._default.max_messages,
                    max_tool_args_depth=r.max_tool_args_depth if r.max_tool_args_depth is not None else self._default.max_tool_args_depth,
                    max_tool_args_bytes=r.max_tool_args_bytes if r.max_tool_args_bytes is not None else self._default.max_tool_args_bytes,
                    max_tool_arg_string_length=r.max_tool_arg_string_length if r.max_tool_arg_string_length is not None else self._default.max_tool_arg_string_length,
                    max_attachments=r.max_attachments if r.max_attachments is not None else self._default.max_attachments,
                    allowed_content_types=r.allowed_content_types or self._default.allowed_content_types,
                    rate_cap_rpm=r.rate_cap_rpm if r.rate_cap_rpm is not None else self._default.rate_cap_rpm,
                )
        return self._default

    def check(
        self,
        path: str,
        method: str,
        content_type: str | None,
        body_bytes: bytes | None,
        client_ip: str | None,
    ) -> PolicyDecision:
        if not self.enabled:
            return PolicyDecision.ok("disabled")

        rule = self.resolve(path, method)

        # Content-Type allowlist
        if rule.allowed_content_types:
            ct = (content_type or "").split(";")[0].strip().lower()
            if ct and not any(fnmatch.fnmatch(ct, p.lower()) for p in rule.allowed_content_types):
                return PolicyDecision.deny(
                    rule.rule_id,
                    f"content-type '{ct}' not in allowlist for {path}",
                    "content_type_not_allowed",
                )

        # Body size cap
        body_size = len(body_bytes) if body_bytes is not None else 0
        if rule.max_body_bytes is not None and body_size > rule.max_body_bytes:
            return PolicyDecision.deny(
                rule.rule_id,
                f"body {body_size} bytes exceeds {rule.max_body_bytes}",
                "body_too_large",
            )

        # Rate cap (per (rule_id, client_ip))
        if rule.rate_cap_rpm and rule.rate_cap_rpm > 0:
            ip = client_ip or "anon"
            with self._rate_lock:
                window = self._rate_windows.setdefault((rule.rule_id, ip), deque())
                now = time.monotonic()
                while window and now - window[0] > 60.0:
                    window.popleft()
                if len(window) >= rule.rate_cap_rpm:
                    return PolicyDecision.deny(
                        rule.rule_id,
                        f"rate cap {rule.rate_cap_rpm} rpm exceeded for {ip} on {rule.rule_id}",
                        "rate_cap_exceeded",
                    )
                window.append(now)

        # Shape checks against parsed JSON body (best-effort).
        needs_parse = (
            rule.max_messages is not None
            or rule.max_tool_args_depth is not None
            or rule.max_tool_args_bytes is not None
            or rule.max_tool_arg_string_length is not None
            or rule.max_attachments is not None
        )
        if body_bytes and needs_parse:
            try:
                parsed = json.loads(body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None

            if parsed is not None:
                if rule.max_messages is not None:
                    msgs = parsed.get("messages") if isinstance(parsed, dict) else None
                    if isinstance(msgs, list) and len(msgs) > rule.max_messages:
                        return PolicyDecision.deny(
                            rule.rule_id,
                            f"messages count {len(msgs)} exceeds {rule.max_messages}",
                            "too_many_messages",
                        )

                if rule.max_attachments is not None:
                    atts = parsed.get("attachments") if isinstance(parsed, dict) else None
                    if isinstance(atts, list) and len(atts) > rule.max_attachments:
                        return PolicyDecision.deny(
                            rule.rule_id,
                            f"attachments count {len(atts)} exceeds {rule.max_attachments}",
                            "too_many_attachments",
                        )

                if rule.max_tool_args_depth is not None:
                    tools = parsed.get("tools") if isinstance(parsed, dict) else None
                    if isinstance(tools, list):
                        for tool in tools:
                            if _max_depth(tool) > rule.max_tool_args_depth:
                                return PolicyDecision.deny(
                                    rule.rule_id,
                                    f"tool argument nesting exceeds {rule.max_tool_args_depth}",
                                    "tool_args_too_deep",
                                )

                # Tool-args byte volume + per-string length caps. Both walk
                # the same payload list (tools / tool_calls / messages.*.tool_calls)
                # so an authenticated caller can't smuggle a 10 MB blob past
                # the body cap by hiding it as a tool argument when the body
                # cap is generous (e.g. /v1/embeddings).
                if (
                    rule.max_tool_args_bytes is not None
                    or rule.max_tool_arg_string_length is not None
                ):
                    payloads = _tool_args_payloads(parsed)
                    if payloads:
                        if rule.max_tool_args_bytes is not None:
                            try:
                                serialized = json.dumps(payloads, ensure_ascii=False, default=str)
                            except (TypeError, ValueError):
                                serialized = ""
                            size = len(serialized.encode("utf-8", errors="ignore"))
                            if size > rule.max_tool_args_bytes:
                                return PolicyDecision.deny(
                                    rule.rule_id,
                                    f"tool args {size} bytes exceeds {rule.max_tool_args_bytes}",
                                    "tool_args_too_large",
                                )
                        if rule.max_tool_arg_string_length is not None:
                            longest = 0
                            for p in payloads:
                                n = _max_string_length(p)
                                if n > longest:
                                    longest = n
                            if longest > rule.max_tool_arg_string_length:
                                return PolicyDecision.deny(
                                    rule.rule_id,
                                    f"tool arg string length {longest} exceeds "
                                    f"{rule.max_tool_arg_string_length}",
                                    "tool_arg_string_too_long",
                                )

        return PolicyDecision.ok(rule.rule_id)


__all__ = ["PolicyEngine", "PolicyRule", "PolicyDecision"]
