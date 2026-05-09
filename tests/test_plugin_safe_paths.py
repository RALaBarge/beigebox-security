"""
Tests that SafePath is correctly applied in plugin entry points.

Covers:
  1. DocParserTool.run() — path traversal rejected with "Refused:" prefix
  2. DocParserTool.run() — null-byte injection rejected
  3. DocParserTool.run() — absolute escape (/etc/passwd) rejected
  4. repo_tool._read_file() — path traversal with root → "Refused:"
  5. repo_tool._read_file() — absolute path without root → resolved as-given (no SafePath)
  6. repo_tool._read_file() — traversal without root is NOT guarded (documents the design)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


# ── DocParserTool ─────────────────────────────────────────────────────────────

class TestDocParserToolSafePath:
    """DocParserTool.run() must refuse traversal attempts before touching the FS."""

    def _make_tool(self):
        import sys, importlib, importlib.util
        spec = importlib.util.spec_from_file_location(
            "doc_parser_plugin",
            Path(__file__).parent.parent / "plugins" / "doc_parser.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["doc_parser_plugin"] = mod
        spec.loader.exec_module(mod)
        return mod.DocParserTool()

    def test_traversal_relative_rejected(self):
        tool = self._make_tool()
        result = tool.run("../../../etc/passwd")
        assert result.startswith("Refused:"), f"Expected refusal, got: {result!r}"

    def test_traversal_double_dot_rejected(self):
        tool = self._make_tool()
        result = tool.run("../../shadow")
        assert result.startswith("Refused:"), f"Expected refusal, got: {result!r}"

    def test_absolute_escape_rejected(self):
        tool = self._make_tool()
        # /etc/passwd is outside workspace/in/ — SafePath should refuse it
        result = tool.run("/etc/passwd")
        assert result.startswith("Refused:"), f"Expected refusal, got: {result!r}"

    def test_null_byte_rejected(self):
        tool = self._make_tool()
        # Null byte injection — should raise or refuse before filesystem call
        try:
            result = tool.run("file\x00.txt")
        except (ValueError, UnicodeEncodeError):
            pass  # acceptable — raised before returning
        else:
            # If it returns, it must be a refusal or not-found, not actual file content
            assert "Refused:" in result or "not found" in result.lower() or "error" in result.lower()

    def test_valid_relative_name_not_refused(self, tmp_path):
        """A plain filename that doesn't exist gets a 'not found' response, not 'Refused:'."""
        tool = self._make_tool()
        # Patch _WORKSPACE_IN so we don't need the real dir to exist
        with patch("doc_parser_plugin._WORKSPACE_IN", tmp_path):
            result = tool.run("report.pdf")
        # Should be a "not found" message, not a traversal refusal
        assert not result.startswith("Refused:"), \
            f"Valid filename was unexpectedly refused: {result!r}"


# ── RepoTool._read_file ───────────────────────────────────────────────────────

class TestRepoToolSafePath:
    """repo_tool._read_file() applies SafePath when root is given."""

    def _make_tool(self):
        import sys, importlib.util
        spec = importlib.util.spec_from_file_location(
            "repo_tool_plugin",
            Path(__file__).parent.parent / "plugins" / "repo_tool.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["repo_tool_plugin"] = mod
        spec.loader.exec_module(mod)
        return mod.RepoTool()

    def test_traversal_with_root_rejected(self, tmp_path):
        tool = self._make_tool()
        result = tool._read_file({"path": "../../../etc/passwd", "root": str(tmp_path)})
        assert result.startswith("Refused:"), f"Expected refusal, got: {result!r}"

    def test_traversal_absolute_outside_root_rejected(self, tmp_path):
        tool = self._make_tool()
        result = tool._read_file({"path": "/etc/passwd", "root": str(tmp_path)})
        assert result.startswith("Refused:"), f"Expected refusal, got: {result!r}"

    def test_valid_path_within_root_allowed(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello world")
        tool = self._make_tool()
        result = tool._read_file({"path": "hello.txt", "root": str(tmp_path)})
        assert "hello world" in result, f"Expected file content, got: {result!r}"

    def test_no_root_resolves_absolute(self, tmp_path):
        """Without a root, the path is resolved as-given — no SafePath guard.
        This is the documented design: root=None means caller takes responsibility.
        """
        target = tmp_path / "readme.txt"
        target.write_text("no root guard")
        tool = self._make_tool()
        result = tool._read_file({"path": str(target)})
        assert "no root guard" in result, f"Expected file content, got: {result!r}"

    def test_missing_path_returns_error(self):
        tool = self._make_tool()
        result = tool._read_file({})
        assert "required" in result.lower() or "error" in result.lower()
