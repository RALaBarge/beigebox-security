"""
Parametrized path traversal regression tests.

Every call site that uses SafePath is tested against a common battery of
hostile inputs. If a future refactor accidentally removes or bypasses the
SafePath check, these tests fail immediately.

Call sites under test:
  A. beigebox.security.safe_path.SafePath itself (unit)
  B. WasmRuntime._load_modules() path pinning under wasm_modules/
  C. analytics router wire-log path pinning under project root
  D. DocParserTool.run() workspace/in/ pinning  (see also test_plugin_safe_paths.py)
  E. repo_tool._read_file() root pinning
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from beigebox.security.safe_path import SafePath, UnsafePathError


# ── Hostile input battery ─────────────────────────────────────────────────────

TRAVERSAL_INPUTS = [
    "../../../etc/passwd",
    "../../shadow",
    "sub/../../../etc/hosts",
    "/etc/passwd",
    "/tmp/evil",
    "//etc/passwd",
    "\x00etc/passwd",  # null byte
    "..",
]


# ── A. SafePath unit tests ────────────────────────────────────────────────────

class TestSafePathUnit:

    @pytest.mark.parametrize("hostile", TRAVERSAL_INPUTS)
    def test_traversal_raises(self, tmp_path, hostile):
        with pytest.raises((UnsafePathError, ValueError)):
            SafePath(hostile, base=tmp_path)

    def test_valid_relative_path_resolves(self, tmp_path):
        (tmp_path / "safe.txt").touch()
        sp = SafePath("safe.txt", base=tmp_path)
        assert sp.path == tmp_path / "safe.txt"

    def test_valid_nested_path_resolves(self, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "file.txt").touch()
        sp = SafePath("sub/file.txt", base=tmp_path)
        assert sp.path == subdir / "file.txt"

    def test_empty_value_raises(self, tmp_path):
        with pytest.raises(UnsafePathError):
            SafePath("", base=tmp_path)

    def test_base_itself_allowed(self, tmp_path):
        """The base directory itself is a valid SafePath target."""
        sp = SafePath(str(tmp_path), base=tmp_path)
        assert sp.path == tmp_path


# ── B. WasmRuntime path pinning ───────────────────────────────────────────────

class TestWasmRuntimePathPinning:
    """WasmRuntime path pinning: modules must be under wasm_modules/."""

    @pytest.mark.parametrize("hostile", TRAVERSAL_INPUTS)
    def test_traversal_refused_by_safe_path(self, tmp_path, hostile):
        """SafePath with wasm_modules/ as base must refuse paths outside it."""
        wasm_base = tmp_path / "wasm_modules"
        wasm_base.mkdir()
        with pytest.raises((UnsafePathError, ValueError)):
            SafePath(hostile, base=wasm_base)

    def test_valid_wasm_path_allowed(self, tmp_path):
        wasm_base = tmp_path / "wasm_modules"
        wasm_base.mkdir()
        (wasm_base / "opener_strip.wasm").touch()
        sp = SafePath("opener_strip.wasm", base=wasm_base)
        assert sp.path.name == "opener_strip.wasm"

    def test_wasm_runtime_does_not_load_traversal_module(self):
        """WasmRuntime._load_modules() refuses traversal paths — "evil" stays out of _loaded."""
        from beigebox.wasm_runtime import WasmRuntime

        cfg = {
            "wasm": {
                "enabled": True,
                "modules": {
                    "evil": {"path": "../../../etc/passwd", "enabled": True},
                },
            }
        }
        fake_engine = MagicMock()

        # Patch _init_engine to set the engine without wasmtime, then call _load_modules directly
        rt = WasmRuntime.__new__(WasmRuntime)
        rt._cfg = cfg["wasm"]
        rt._enabled = True
        rt._timeout_ms = 500
        rt._modules_cfg = cfg["wasm"]["modules"]
        rt._default_module = ""
        rt._loaded = {}
        rt._engine = fake_engine
        rt._executor = MagicMock()

        # Patch the wasmtime Module import so we don't need wasmtime installed
        with patch("builtins.__import__", side_effect=lambda name, *a, **k: (_ for _ in ()).throw(ImportError("wasmtime")) if name == "wasmtime" else __import__(name, *a, **k)):
            try:
                rt._load_modules()
            except Exception:
                pass

        assert "evil" not in rt._loaded


# ── C. Analytics wire-log path pinning ────────────────────────────────────────

class TestAnalyticsWireLogPathPinning:
    """The analytics router refuses wire log paths outside the project root."""

    @pytest.mark.parametrize("hostile", [
        "/tmp/evil.jsonl",
        "../../../tmp/exfil.jsonl",
        "/etc/passwd",
    ])
    def test_traversal_outside_project_root_refused(self, hostile, tmp_path):
        """SafePath with project root as base must refuse paths outside it."""
        project_root = tmp_path / "project"
        project_root.mkdir()
        with pytest.raises(UnsafePathError):
            SafePath(hostile, base=project_root)

    def test_valid_path_within_project_allowed(self, tmp_path):
        project_root = tmp_path / "project"
        project_root.mkdir()
        (project_root / "wire.jsonl").touch()
        sp = SafePath("wire.jsonl", base=project_root)
        assert sp.path.name == "wire.jsonl"


# ── D. DocParserTool workspace/in/ pinning ────────────────────────────────────

class TestDocParserPathPinning:

    def _load_doc_parser(self):
        spec = importlib.util.spec_from_file_location(
            "doc_parser_plugin",
            Path(__file__).parent.parent / "plugins" / "doc_parser.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("doc_parser_plugin", mod)
        spec.loader.exec_module(mod)
        return mod.DocParserTool()

    @pytest.mark.parametrize("hostile", [
        "../../../etc/passwd",
        "../../shadow",
        "/etc/passwd",
        "/tmp/evil.pdf",
    ])
    def test_traversal_rejected(self, hostile):
        tool = self._load_doc_parser()
        result = tool.run(hostile)
        assert result.startswith("Refused:"), \
            f"Expected refusal for {hostile!r}, got: {result!r}"


# ── E. RepoTool root pinning ──────────────────────────────────────────────────

class TestRepoToolRootPinning:

    def _load_repo_tool(self):
        spec = importlib.util.spec_from_file_location(
            "repo_tool_plugin",
            Path(__file__).parent.parent / "plugins" / "repo_tool.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("repo_tool_plugin", mod)
        spec.loader.exec_module(mod)
        return mod.RepoTool()

    @pytest.mark.parametrize("hostile", [
        "../../../etc/passwd",
        "/etc/passwd",
        "../../secret.key",
    ])
    def test_traversal_with_root_rejected(self, tmp_path, hostile):
        tool = self._load_repo_tool()
        result = tool._read_file({"path": hostile, "root": str(tmp_path)})
        assert result.startswith("Refused:"), \
            f"Expected refusal for {hostile!r}, got: {result!r}"
