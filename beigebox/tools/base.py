"""Tool contract for the BeigeBox tool registry.

`Tool` is a runtime-checkable Protocol — tools satisfy it structurally,
no inheritance required. This keeps the existing tool classes unchanged
while letting `ToolRegistry` type-annotate its dict and (optionally)
runtime-check that anything registered actually conforms.

Contract (every tool must provide):
    description : str
        Human-readable description surfaced in MCP `tools/list`. The MCP
        server uses this to populate the tool schema's description field
        so callers know what the tool does and how to format input.

    run(input_text: str) -> str | dict
        Execute the tool. Single string input, conventionally named
        `input_text` / `input_str` / `query` / `expression` / `url` per
        tool — Protocol structural subtyping accepts any of those.

        Return:
          - str: text result for the caller (most tools).
          - dict: media result wrapped via beigebox/tools/_media — must
            carry the `__beigebox_mcp_content__` sentinel so MCP can
            unwrap into native content blocks (images, etc.). Text-only
            consumers fall back through `_text_fallback` in the registry.

Notes:
- All current tools are sync. Async tools are not part of the contract
  today; if needed in the future, extend the Protocol with an async
  variant rather than overloading `run`.
- Validation is *not* a tool concern. `ToolRegistry` runs
  `ParameterValidator.validate_tool_input(name, input_text)` (from
  `beigebox/tools/validation.py`) before invoking `tool.run(...)`.
- Constructor signatures vary per tool — they take whatever config they
  need. The registry instantiates them once at startup with the right
  config; the Protocol does not constrain `__init__`.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Tool(Protocol):
    """Structural contract for any object registered in `ToolRegistry`."""

    description: str

    def run(self, input_text: str) -> str | dict[str, Any]:
        ...


__all__ = ["Tool"]
