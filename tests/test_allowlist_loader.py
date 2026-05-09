"""
Tests for the plugin allow-list enforcement in both plugin loaders.

Covers:
  1. load_backend_plugins — allowed=None  → loads everything + deprecation warning
  2. load_backend_plugins — allowed=[]    → loads nothing
  3. load_backend_plugins — allowed=[stem] → loads only matching files
  4. load_backend_plugins — world-writable dir → refuses with error log
  5. load_plugins (tool plugins) — same four cases
  6. load_plugins — per-plugin enabled=false → skips that plugin
"""
from __future__ import annotations

import os
import stat
import textwrap
import logging
from unittest.mock import patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_plugin(path, stem: str, class_name: str = None, backend: bool = False):
    """Write a minimal valid plugin file at path/stem.py."""
    cls = class_name or (stem.title().replace("_", "") + ("Backend" if backend else "Tool"))
    if backend:
        content = textwrap.dedent(f"""\
            from beigebox.backends.base import BaseBackend
            from beigebox.backends.base import BackendResponse

            class {cls}(BaseBackend):
                async def forward(self, body):
                    return BackendResponse(ok=False, backend_name=self.name)
                async def forward_stream(self, body):
                    return
                    yield
                async def health_check(self):
                    return False
        """)
    else:
        content = textwrap.dedent(f"""\
            PLUGIN_NAME = "{stem}"

            class {cls}:
                def run(self, query: str) -> str:
                    return "result from {stem}"
        """)
    (path / f"{stem}.py").write_text(content)


# ── Backend plugin loader ──────────────────────────────────────────────────────

class TestLoadBackendPlugins:

    def test_allowed_none_loads_all_with_warning(self, tmp_path, caplog):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "alpha", backend=True)
        _write_plugin(plugins_dir, "beta", backend=True)

        import beigebox.backends.plugin_loader as _bl
        with patch.object(_bl, "_PROJECT_ROOT", tmp_path), \
             caplog.at_level(logging.WARNING, logger="beigebox.security.plugin_safety"):
            result = _bl.load_backend_plugins(str(plugins_dir), cfg=None)

        # Deprecation warning fired
        assert any("allow-list" in r.message.lower() or "backwards compat" in r.message.lower()
                   for r in caplog.records), \
            f"Expected deprecation warning, got: {[r.message for r in caplog.records]}"

    def test_allowed_empty_list_loads_nothing(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "alpha", backend=True)

        import beigebox.backends.plugin_loader as _bl
        with patch.object(_bl, "_PROJECT_ROOT", tmp_path):
            result = _bl.load_backend_plugins(str(plugins_dir), cfg={"backend_plugins": {"allowed": []}})
        assert result == {}

    def test_allowed_list_loads_only_matching(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "alpha", backend=True)
        _write_plugin(plugins_dir, "beta", backend=True)

        import beigebox.backends.plugin_loader as _bl
        with patch.object(_bl, "_PROJECT_ROOT", tmp_path):
            result = _bl.load_backend_plugins(str(plugins_dir), cfg={"backend_plugins": {"allowed": ["alpha"]}})
        # beta must NOT be loaded
        assert "beta" not in result

    def test_world_writable_dir_refused(self, tmp_path, caplog):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        current_mode = stat.S_IMODE(plugins_dir.stat().st_mode)
        plugins_dir.chmod(current_mode | stat.S_IWOTH)

        import beigebox.backends.plugin_loader as _bl
        with patch.object(_bl, "_PROJECT_ROOT", tmp_path), \
             caplog.at_level(logging.ERROR, logger="beigebox.backends.plugin_loader"):
            result = _bl.load_backend_plugins(str(plugins_dir), cfg=None)

        assert result == {}
        assert any("world-writable" in r.message.lower() or "refusing" in r.message.lower()
                   for r in caplog.records), \
            f"Expected refusal log, got: {[r.message for r in caplog.records]}"

        plugins_dir.chmod(current_mode & ~stat.S_IWOTH)

    def test_nonexistent_dir_returns_empty(self, tmp_path):
        import beigebox.backends.plugin_loader as _bl
        with patch.object(_bl, "_PROJECT_ROOT", tmp_path):
            result = _bl.load_backend_plugins(str(tmp_path / "does_not_exist"), cfg=None)
        assert result == {}


# ── Tool plugin loader ─────────────────────────────────────────────────────────

class TestLoadToolPlugins:

    def _tools_cfg(self, allowed=None, extra: dict | None = None):
        cfg = {"plugins": {"enabled": True}}
        if allowed is not None:
            cfg["plugins"]["allowed"] = allowed
        if extra:
            cfg["plugins"].update(extra)
        return cfg

    def test_allowed_none_loads_all_with_warning(self, tmp_path, caplog):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "greeter")
        _write_plugin(plugins_dir, "counter")

        import beigebox.tools.plugin_loader as _tl
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path), \
             caplog.at_level(logging.WARNING, logger="beigebox.security.plugin_safety"):
            result = _tl.load_plugins(str(plugins_dir), self._tools_cfg())

        assert len(result) >= 1
        assert any("allow-list" in r.message.lower() or "backwards compat" in r.message.lower()
                   for r in caplog.records), \
            f"Expected deprecation warning, got: {[r.message for r in caplog.records]}"

    def test_allowed_empty_list_loads_nothing(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "greeter")

        import beigebox.tools.plugin_loader as _tl
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path):
            result = _tl.load_plugins(str(plugins_dir), self._tools_cfg(allowed=[]))
        assert result == {}

    def test_allowed_list_loads_only_matching(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "greeter")
        _write_plugin(plugins_dir, "counter")

        import beigebox.tools.plugin_loader as _tl
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path):
            result = _tl.load_plugins(str(plugins_dir), self._tools_cfg(allowed=["greeter"]))
        assert "greeter" in result
        assert "counter" not in result

    def test_world_writable_dir_refused(self, tmp_path, caplog):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        current_mode = stat.S_IMODE(plugins_dir.stat().st_mode)
        plugins_dir.chmod(current_mode | stat.S_IWOTH)

        import beigebox.tools.plugin_loader as _tl
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path), \
             caplog.at_level(logging.ERROR, logger="beigebox.tools.plugin_loader"):
            result = _tl.load_plugins(str(plugins_dir), self._tools_cfg())

        assert result == {}
        assert any("world-writable" in r.message.lower() or "refusing" in r.message.lower()
                   for r in caplog.records), \
            f"Expected refusal log, got: {[r.message for r in caplog.records]}"

        plugins_dir.chmod(current_mode & ~stat.S_IWOTH)

    def test_nonexistent_dir_returns_empty(self, tmp_path):
        import beigebox.tools.plugin_loader as _tl
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path):
            result = _tl.load_plugins(str(tmp_path / "does_not_exist"), self._tools_cfg())
        assert result == {}

    def test_per_plugin_disabled_flag_skips_plugin(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "greeter")

        import beigebox.tools.plugin_loader as _tl
        cfg = {"plugins": {"enabled": True, "allowed": ["greeter"], "greeter": {"enabled": False}}}
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path):
            result = _tl.load_plugins(str(plugins_dir), cfg)
        assert "greeter" not in result

    def test_plugins_master_switch_disabled_loads_nothing(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _write_plugin(plugins_dir, "greeter")

        import beigebox.tools.plugin_loader as _tl
        cfg = {"plugins": {"enabled": False}}
        with patch.object(_tl, "_PROJECT_ROOT", tmp_path):
            result = _tl.load_plugins(str(plugins_dir), cfg)
        assert result == {}
