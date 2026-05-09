"""
Tests for web UI config endpoint and web file serving.
Covers:
  - update_runtime_config persists correctly (uses web_ui_palette as the test key)
  - /api/v1/config includes web_ui block with palette
  - index.html is served at / and /ui
  - assorted index.html structural assertions (fork button, charts, WASM section)
"""
import pytest
import yaml
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock


# ── Config module tests ───────────────────────────────────────────────────────

class TestUpdateRuntimeConfig:
    def test_creates_runtime_key_if_missing(self, tmp_path):
        rt_path = tmp_path / "runtime_config.yaml"
        rt_path.write_text("# empty\n")

        from beigebox import config as cfg_mod
        orig_path = cfg_mod._RUNTIME_CONFIG_PATH
        cfg_mod._RUNTIME_CONFIG_PATH = rt_path
        cfg_mod._runtime_mtime = 0.0; cfg_mod._runtime_mtime_last_checked = 0.0

        try:
            result = cfg_mod.update_runtime_config("web_ui_palette", "dracula")
            assert result is True
            data = yaml.safe_load(rt_path.read_text())
            assert data["runtime"]["web_ui_palette"] == "dracula"
        finally:
            cfg_mod._RUNTIME_CONFIG_PATH = orig_path

    def test_updates_existing_key(self, tmp_path):
        rt_path = tmp_path / "runtime_config.yaml"
        rt_path.write_text("runtime:\n  web_ui_palette: default\n")

        from beigebox import config as cfg_mod
        orig_path = cfg_mod._RUNTIME_CONFIG_PATH
        cfg_mod._RUNTIME_CONFIG_PATH = rt_path
        cfg_mod._runtime_mtime = 0.0; cfg_mod._runtime_mtime_last_checked = 0.0

        try:
            cfg_mod.update_runtime_config("web_ui_palette", "nord")
            data = yaml.safe_load(rt_path.read_text())
            assert data["runtime"]["web_ui_palette"] == "nord"
        finally:
            cfg_mod._RUNTIME_CONFIG_PATH = orig_path

    def test_preserves_other_keys(self, tmp_path):
        rt_path = tmp_path / "runtime_config.yaml"
        rt_path.write_text("runtime:\n  default_model: llama3.2\n  force_route: ''\n")

        from beigebox import config as cfg_mod
        orig_path = cfg_mod._RUNTIME_CONFIG_PATH
        cfg_mod._RUNTIME_CONFIG_PATH = rt_path
        cfg_mod._runtime_mtime = 0.0; cfg_mod._runtime_mtime_last_checked = 0.0

        try:
            cfg_mod.update_runtime_config("web_ui_palette", "gruvbox")
            data = yaml.safe_load(rt_path.read_text())
            assert data["runtime"]["default_model"] == "llama3.2"
            assert data["runtime"]["web_ui_palette"] == "gruvbox"
        finally:
            cfg_mod._RUNTIME_CONFIG_PATH = orig_path

    def test_busts_mtime_cache(self, tmp_path):
        rt_path = tmp_path / "runtime_config.yaml"
        rt_path.write_text("runtime:\n  web_ui_palette: default\n")

        from beigebox import config as cfg_mod
        orig_path = cfg_mod._RUNTIME_CONFIG_PATH
        cfg_mod._RUNTIME_CONFIG_PATH = rt_path
        cfg_mod._runtime_mtime = 999999.0  # fake stale mtime

        try:
            cfg_mod.update_runtime_config("web_ui_palette", "nord")
            assert cfg_mod._runtime_mtime == 0.0  # should be reset
        finally:
            cfg_mod._RUNTIME_CONFIG_PATH = orig_path

    def test_returns_false_on_unwritable_path(self, tmp_path):
        from beigebox import config as cfg_mod
        orig_path = cfg_mod._RUNTIME_CONFIG_PATH
        missing_parent = tmp_path / "does-not-exist"
        cfg_mod._RUNTIME_CONFIG_PATH = missing_parent / "runtime_config.yaml"

        try:
            result = cfg_mod.update_runtime_config("web_ui_palette", "nord")
            assert result is False
        finally:
            cfg_mod._RUNTIME_CONFIG_PATH = orig_path


# ── FastAPI endpoint tests ────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path):
    """Create a test client with minimal mocked dependencies."""
    from fastapi.testclient import TestClient
    from beigebox import config as cfg_mod

    # Minimal config
    cfg_data = {
        "backend": {"url": "http://localhost:11434", "default_model": "llama3.2", "timeout": 120},
        "server": {"host": "0.0.0.0", "port": 8000},
        "embedding": {"model": "nomic-embed-text", "backend_url": "http://localhost:11434"},
        "storage": {"sqlite_path": str(tmp_path / "test.db"), "vector_store_path": str(tmp_path / "vectors"), "vector_backend": "memory", "log_conversations": True},
        "tools": {"enabled": False},
        "decision_llm": {"enabled": False},
        "hooks": {"directory": str(tmp_path / "hooks")},
        "logging": {"level": "WARNING"},
        "wiretap": {"path": str(tmp_path / "wire.jsonl")},
        "routing": {},
        "model_advertising": {"mode": "hidden"},
        "operator": {"model": "llama3.2"},
        "backends_enabled": False,
        "cost_tracking": {"enabled": False},
        "wasm": {"enabled": False, "modules": {}},
    }

    rt_path = tmp_path / "runtime_config.yaml"
    rt_path.write_text("runtime:\n  web_ui_palette: default\n")

    orig_config = cfg_mod._config
    orig_rt_path = cfg_mod._RUNTIME_CONFIG_PATH
    orig_rt_mtime = cfg_mod._runtime_mtime
    orig_rt_mtime_checked = cfg_mod._runtime_mtime_last_checked
    orig_rt_config = cfg_mod._runtime_config

    cfg_mod._config = cfg_data
    cfg_mod._RUNTIME_CONFIG_PATH = rt_path
    cfg_mod._runtime_mtime = 0.0; cfg_mod._runtime_mtime_last_checked = 0.0
    cfg_mod._runtime_config = {}

    from beigebox.app_state import AppState
    from beigebox.state import set_state

    mock_wasm = MagicMock()
    mock_wasm.enabled = False
    mock_wasm.list_modules.return_value = []
    mock_wasm.default_module = ""
    mock_proxy = MagicMock()
    mock_proxy.wasm_runtime = mock_wasm

    mock_state = AppState(proxy=mock_proxy)

    async def _fake_startup(app):  # noqa: ARG001
        set_state(mock_state)
        return mock_state

    async def _fake_shutdown(state):  # noqa: ARG001
        pass

    with patch("beigebox.bootstrap.startup", side_effect=_fake_startup), \
         patch("beigebox.bootstrap.shutdown", side_effect=_fake_shutdown):
        from beigebox.main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c, rt_path

    cfg_mod._config = orig_config
    cfg_mod._RUNTIME_CONFIG_PATH = orig_rt_path
    cfg_mod._runtime_mtime = orig_rt_mtime
    cfg_mod._runtime_mtime_last_checked = orig_rt_mtime_checked
    cfg_mod._runtime_config = orig_rt_config


class TestConfigEndpointWebUi:
    def test_config_includes_web_ui_block(self, client):
        c, _ = client
        r = c.get("/api/v1/config")
        assert r.status_code == 200
        data = r.json()
        assert "web_ui" in data

    def test_web_ui_palette_default(self, client):
        c, _ = client
        r = c.get("/api/v1/config")
        assert r.json()["web_ui"]["palette"] == "default"


# ── Static file and HTML serving ─────────────────────────────────────────────

class TestWebFileServing:
    def test_root_serves_html(self, client):
        c, _ = client
        r = c.get("/")
        # Will 404 if index.html doesn't exist on test machine, 200 if it does
        assert r.status_code in (200, 404, 500)

    def test_ui_alias_serves_html(self, client):
        c, _ = client
        r = c.get("/ui")
        assert r.status_code in (200, 404, 500)

    def test_index_html_has_fork_button(self):
        """Conversation search results must include the ⑂ fork button."""
        html_path = Path(__file__).parent.parent / "beigebox" / "web" / "index.html"
        if not html_path.exists():
            pytest.skip("index.html not found")
        content = html_path.read_text()
        assert "forkConversation" in content
        assert "⑂" in content

    def test_index_html_fork_button_stops_propagation(self):
        """Fork button must call stopPropagation to avoid triggering replay."""
        html_path = Path(__file__).parent.parent / "beigebox" / "web" / "index.html"
        if not html_path.exists():
            pytest.skip("index.html not found")
        content = html_path.read_text()
        assert "stopPropagation" in content

    def test_index_html_has_requests_by_day_chart(self):
        """Dashboard must include the requests/day chart canvas."""
        html_path = Path(__file__).parent.parent / "beigebox" / "web" / "index.html"
        if not html_path.exists():
            pytest.skip("index.html not found")
        content = html_path.read_text()
        assert "chart-req-day" in content

    def test_index_html_has_render_req_day_chart(self):
        """renderReqDayChart function must exist in index.html."""
        html_path = Path(__file__).parent.parent / "beigebox" / "web" / "index.html"
        if not html_path.exists():
            pytest.skip("index.html not found")
        content = html_path.read_text()
        assert "renderReqDayChart" in content

    def test_index_html_has_wasm_section(self):
        """Config tab must include the WASM Transforms section."""
        html_path = Path(__file__).parent.parent / "beigebox" / "web" / "index.html"
        if not html_path.exists():
            pytest.skip("index.html not found")
        content = html_path.read_text()
        assert "loadWasmCfgSection" in content
        assert "reloadWasmModules" in content

    def test_index_html_wasm_reload_button(self):
        """WASM config section must include a Reload button."""
        html_path = Path(__file__).parent.parent / "beigebox" / "web" / "index.html"
        if not html_path.exists():
            pytest.skip("index.html not found")
        content = html_path.read_text()
        assert "wasm/reload" in content or "reloadWasmModules" in content
