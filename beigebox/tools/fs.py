"""
Filesystem tools for the operator.

All tools scope paths through SafePath using the configured working_dir.
Input is a JSON string; tools parse it and return plain text results.

Tools
-----
read_file       Read file contents, optionally with line-number range.
write_file      Create or overwrite a file.
edit_file       Find-and-replace edit (exact string match, first occurrence).
glob            Recursive glob pattern over the working directory.
search          Regex content search across files.
directory_tree  Recursive directory listing as an indented tree.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from pathlib import Path

from beigebox.security.safe_path import SafePath, UnsafePathError
from beigebox.tools._ctx import get_working_dir as _get_working_dir

logger = logging.getLogger(__name__)

_MAX_READ_BYTES = 200 * 1024   # 200 KB read cap
_MAX_SEARCH_MATCHES = 200


def _resolve_wd(params: dict) -> Path:
    """Return working dir from params override, contextvar, or config fallback."""
    wd_override = params.get("working_dir", "")
    if wd_override:
        return Path(wd_override).resolve()
    return _get_working_dir()


def _safe(path_value: str, wd: Path) -> Path:
    return SafePath(path_value, base=wd).path


def _parse(input_text: str) -> dict:
    try:
        result = json.loads(input_text)
        return result if isinstance(result, dict) else {"path": input_text.strip()}
    except json.JSONDecodeError:
        return {"path": input_text.strip()}


# ---------------------------------------------------------------------------
# ReadFileTool
# ---------------------------------------------------------------------------

class ReadFileTool:
    description = (
        'Read a file. Input JSON: {"path": "relative/path.py"} '
        'Optional: "offset" (start line, 1-based), "limit" (max lines). '
        "Returns file contents with line numbers."
    )

    def run(self, input_text: str) -> str:
        params = _parse(input_text)
        path_str = params.get("path", "")
        if not path_str:
            return "Error: path required"
        wd = _resolve_wd(params)
        try:
            p = _safe(path_str, wd)
        except UnsafePathError as exc:
            return f"Error: {exc}"
        if not p.exists():
            return f"Error: {path_str!r} not found"
        if not p.is_file():
            return f"Error: {path_str!r} is not a file"

        try:
            raw = p.read_bytes()
        except OSError as exc:
            return f"Error reading file: {exc}"

        if len(raw) > _MAX_READ_BYTES:
            raw = raw[:_MAX_READ_BYTES]
            truncated = True
        else:
            truncated = False

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            return f"Error decoding file: {exc}"

        lines = text.splitlines(keepends=True)
        offset = max(1, int(params.get("offset", 1))) - 1  # convert to 0-based
        limit = params.get("limit")
        if limit is not None:
            lines = lines[offset: offset + int(limit)]
        else:
            lines = lines[offset:]

        numbered = "".join(f"{offset + i + 1}\t{line}" for i, line in enumerate(lines))
        suffix = "\n... [truncated at 200KB]" if truncated else ""
        return numbered + suffix


# ---------------------------------------------------------------------------
# WriteFileTool
# ---------------------------------------------------------------------------

class WriteFileTool:
    description = (
        'Write or overwrite a file. Input JSON: {"path": "relative/path.py", "content": "..."} '
        "Creates parent directories as needed. Returns confirmation."
    )

    def run(self, input_text: str) -> str:
        params = _parse(input_text)
        path_str = params.get("path", "")
        content = params.get("content")
        if not path_str:
            return "Error: path required"
        if content is None:
            return "Error: content required"
        wd = _resolve_wd(params)
        try:
            p = _safe(path_str, wd)
        except UnsafePathError as exc:
            return f"Error: {exc}"
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        except OSError as exc:
            return f"Error writing file: {exc}"
        return f"Written {len(content)} chars to {p}"


# ---------------------------------------------------------------------------
# EditFileTool
# ---------------------------------------------------------------------------

class EditFileTool:
    description = (
        'Edit a file by exact string replacement. '
        'Input JSON: {"path": "...", "old": "exact string to find", "new": "replacement"} '
        "Replaces the first occurrence. Returns a short diff summary."
    )

    def run(self, input_text: str) -> str:
        params = _parse(input_text)
        path_str = params.get("path", "")
        old = params.get("old", "")
        new = params.get("new", "")
        if not path_str:
            return "Error: path required"
        if not old:
            return "Error: old string required"
        wd = _resolve_wd(params)
        try:
            p = _safe(path_str, wd)
        except UnsafePathError as exc:
            return f"Error: {exc}"
        if not p.exists():
            return f"Error: {path_str!r} not found"
        try:
            original = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"Error reading file: {exc}"
        if old not in original:
            return f"Error: old string not found in {path_str!r}"
        updated = original.replace(old, new, 1)
        try:
            p.write_text(updated, encoding="utf-8")
        except OSError as exc:
            return f"Error writing file: {exc}"
        old_lines = old.count("\n") + 1
        new_lines = new.count("\n") + 1
        return f"Edited {path_str}: replaced {old_lines}-line block with {new_lines}-line block"


# ---------------------------------------------------------------------------
# GlobTool
# ---------------------------------------------------------------------------

class GlobTool:
    description = (
        'Find files by glob pattern. Input JSON: {"pattern": "**/*.py"} '
        'Optional: "base" sub-directory within working dir. '
        "Returns newline-separated matched paths (relative to working dir)."
    )

    def run(self, input_text: str) -> str:
        params = _parse(input_text)
        pattern = params.get("pattern", "")
        if not pattern:
            return "Error: pattern required"

        wd = _resolve_wd(params)
        base_str = params.get("base", "")
        if base_str:
            try:
                base = _safe(base_str, wd)
            except UnsafePathError as exc:
                return f"Error: {exc}"
        else:
            base = wd

        try:
            matches = sorted(base.glob(pattern))
        except Exception as exc:
            return f"Error: {exc}"

        paths = []
        for m in matches:
            if not m.is_file():
                continue
            try:
                m.resolve().relative_to(wd.resolve())
            except ValueError:
                continue  # glob matched outside working_dir via symlink
            paths.append(str(m.relative_to(wd)))

        if not paths:
            return "No matches"
        return "\n".join(paths)


# ---------------------------------------------------------------------------
# SearchTool
# ---------------------------------------------------------------------------

class SearchTool:
    description = (
        'Search file contents with a regex. '
        'Input JSON: {"pattern": "regex", "path": "."} '
        'Optional: "include" glob filter (e.g. "*.py"), "ignore_case": true. '
        f"Returns up to {_MAX_SEARCH_MATCHES} matches as path:line:content."
    )

    def run(self, input_text: str) -> str:
        params = _parse(input_text)
        pattern = params.get("pattern", "")
        if not pattern:
            return "Error: pattern required"

        path_str = params.get("path", ".")
        wd = _resolve_wd(params)
        try:
            search_root = _safe(path_str, wd)
        except UnsafePathError as exc:
            return f"Error: {exc}"

        include = params.get("include", "*")
        flags = re.IGNORECASE if params.get("ignore_case") else 0
        try:
            rx = re.compile(pattern, flags)
        except re.error as exc:
            return f"Error: invalid regex: {exc}"
        matches: list[str] = []

        for root, dirs, files in os.walk(search_root):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fnmatch.fnmatch(fname, include):
                    continue
                fpath = Path(root) / fname
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        rel = str(fpath.relative_to(wd))
                        matches.append(f"{rel}:{lineno}:{line.rstrip()}")
                        if len(matches) >= _MAX_SEARCH_MATCHES:
                            return "\n".join(matches) + f"\n... [capped at {_MAX_SEARCH_MATCHES} matches]"

        return "\n".join(matches) if matches else "No matches"


# ---------------------------------------------------------------------------
# DirectoryTreeTool
# ---------------------------------------------------------------------------

class DirectoryTreeTool:
    description = (
        'List directory contents as an indented tree. '
        'Input JSON: {"path": "."} '
        'Optional: "depth" (default 3), "include_hidden": false. '
        "Returns tree as plain text."
    )

    def run(self, input_text: str) -> str:
        params = _parse(input_text)
        path_str = params.get("path", ".")
        wd = _resolve_wd(params)
        try:
            root = _safe(path_str, wd)
        except UnsafePathError as exc:
            return f"Error: {exc}"
        if not root.is_dir():
            return f"Error: {path_str!r} is not a directory"

        max_depth = int(params.get("depth", 3))
        include_hidden = bool(params.get("include_hidden", False))
        wd_resolved = wd.resolve()
        lines: list[str] = [str(root.relative_to(wd))]

        def _walk(directory: Path, prefix: str, depth: int) -> None:
            if depth > max_depth:
                return
            try:
                entries = sorted(directory.iterdir(), key=lambda e: (e.is_file(), e.name))
            except PermissionError:
                return
            entries = [e for e in entries if include_hidden or not e.name.startswith(".")]
            for i, entry in enumerate(entries):
                connector = "└── " if i == len(entries) - 1 else "├── "
                lines.append(f"{prefix}{connector}{entry.name}")
                if entry.is_dir() and not entry.is_symlink():
                    extension = "    " if i == len(entries) - 1 else "│   "
                    _walk(entry, prefix + extension, depth + 1)

        _walk(root, "", 1)
        return "\n".join(lines)
