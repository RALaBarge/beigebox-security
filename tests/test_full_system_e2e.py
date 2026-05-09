"""
Full-system e2e tests — proxy + FastAPI layer working together.

These tests boot the real FastAPI application (via TestClient) with the
bootstrap.startup / bootstrap.shutdown patched to inject mock state,
then hit actual HTTP endpoints and assert on the JSON responses.

Focus: integration between the router, auth middleware, WASM config
endpoint, and the config endpoint — all the wiring that is only tested
end-to-end by going through the real ASGI stack.

Tests that require postgres or a real DB are not included — the storage
backend is configured to "memory" throughout.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Shared fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def e2e_client(tmp_path_factory):
    """A module-scoped TestClient that boots the real app once for all e2e tests."""
    from fastapi.testclient import TestClient
    from beigebox import config as cfg_mod
    from beigebox.app_state import AppState
    from beigebox.state import set_state

    tmp_path = tmp_path_factory.mktemp("e2e")

    cfg_data = {
        "backend": {"url": "http://localhost:11434", "default_model": "llama3.2", "timeout": 120},
        "server": {"host": "0.0.0.0", "port": 8000},
        "embedding": {"model": "nomic-embed-text", "backend_url": "http://localhost:11434"},
        "storage": {
            "sqlite_path": str(tmp_path / "test.db"),
            "vector_store_path": str(tmp_path / "vectors"),
            "vector_backend": "memory",
            "log_conversations": False,
        },
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
        "wasm": {
            "enabled": False,
            "default_module": "opener_strip",
            "timeout_ms": 500,
            "modules": {
                "opener_strip": {
                    "path": "./wasm_modules/opener_strip.wasm",
                    "enabled": True,
                    "description": "Strip openers",
                },
                "pii_redactor": {
                    "path": "./wasm_modules/pii_redactor.wasm",
                    "enabled": False,
                    "description": "Redact PII",
                },
            },
        },
    }

    rt_path = tmp_path / "runtime_config.yaml"
    rt_path.write_text("runtime:\n  web_ui_palette: nord\n")

    orig_config  = cfg_mod._config
    orig_rt_path = cfg_mod._RUNTIME_CONFIG_PATH
    orig_rt_cfg  = cfg_mod._runtime_config
    orig_rt_mt   = cfg_mod._runtime_mtime

    cfg_mod._config = cfg_data
    cfg_mod._RUNTIME_CONFIG_PATH = rt_path
    cfg_mod._runtime_mtime  = 0.0
    cfg_mod._runtime_config = {}

    mock_wasm = MagicMock()
    mock_wasm.enabled = False
    mock_wasm.list_modules.return_value = ["opener_strip"]
    mock_wasm.default_module = "opener_strip"
    mock_wasm.reload.return_value = ["opener_strip"]
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
            yield c, mock_wasm, cfg_data

    cfg_mod._config = orig_config
    cfg_mod._RUNTIME_CONFIG_PATH = orig_rt_path
    cfg_mod._runtime_config = orig_rt_cfg
    cfg_mod._runtime_mtime  = orig_rt_mt


# ── Config endpoint ───────────────────────────────────────────────────────────

class TestConfigEndpointE2E:

    def test_config_returns_200(self, e2e_client):
        c, _, _ = e2e_client
        r = c.get("/api/v1/config")
        assert r.status_code == 200

    def test_config_has_wasm_block(self, e2e_client):
        c, _, _ = e2e_client
        data = c.get("/api/v1/config").json()
        assert "wasm" in data

    def test_wasm_block_shape(self, e2e_client):
        c, _, _ = e2e_client
        wasm = c.get("/api/v1/config").json()["wasm"]
        assert "enabled" in wasm
        assert "default_module" in wasm
        assert "modules" in wasm
        assert isinstance(wasm["modules"], list)

    def test_wasm_modules_cfg_present(self, e2e_client):
        c, _, _ = e2e_client
        wasm = c.get("/api/v1/config").json()["wasm"]
        assert "modules_cfg" in wasm
        assert "opener_strip" in wasm["modules_cfg"]
        assert "pii_redactor" in wasm["modules_cfg"]

    def test_wasm_modules_cfg_description(self, e2e_client):
        c, _, _ = e2e_client
        wasm = c.get("/api/v1/config").json()["wasm"]
        assert wasm["modules_cfg"]["opener_strip"]["description"] == "Strip openers"

    def test_web_ui_palette_from_runtime_config(self, e2e_client):
        c, _, _ = e2e_client
        data = c.get("/api/v1/config").json()
        assert "web_ui" in data
        # The runtime config has palette=nord
        assert data["web_ui"]["palette"] == "nord"

    def test_backend_url_in_config(self, e2e_client):
        c, _, cfg_data = e2e_client
        data = c.get("/api/v1/config").json()
        assert "backend" in data
        assert data["backend"]["url"] == cfg_data["backend"]["url"]


# ── WASM reload endpoint ──────────────────────────────────────────────────────

class TestWasmReloadE2E:

    def test_wasm_reload_returns_ok(self, e2e_client):
        c, _, _ = e2e_client
        r = c.post("/api/v1/wasm/reload")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_wasm_reload_returns_module_list(self, e2e_client):
        c, mock_wasm, _ = e2e_client
        mock_wasm.reload.return_value = ["opener_strip"]
        r = c.post("/api/v1/wasm/reload")
        assert r.json()["modules"] == ["opener_strip"]

    def test_wasm_reload_calls_runtime_reload(self, e2e_client):
        c, mock_wasm, _ = e2e_client
        mock_wasm.reload.reset_mock()
        c.post("/api/v1/wasm/reload")
        mock_wasm.reload.assert_called_once()


# ── Well-known agent card ─────────────────────────────────────────────────────

class TestAgentCardE2E:

    def test_agent_card_returns_200(self, e2e_client):
        c, _, _ = e2e_client
        r = c.get("/.well-known/agent-card.json")
        assert r.status_code == 200

    def test_agent_card_has_required_fields(self, e2e_client):
        c, _, _ = e2e_client
        data = c.get("/.well-known/agent-card.json").json()
        assert "name" in data
        assert "url" in data
        assert "capabilities" in data
        assert data["name"] == "beigebox"

    def test_agent_card_streaming_capability(self, e2e_client):
        c, _, _ = e2e_client
        data = c.get("/.well-known/agent-card.json").json()
        assert data["capabilities"]["streaming"] is True


# ── Probe endpoint URL validation ─────────────────────────────────────────────

class TestProbeUrlValidationE2E:
    """End-to-end: file:// URLs must be rejected by the live /api/v1/probe endpoint."""

    def test_file_url_rejected_400(self, e2e_client):
        c, _, _ = e2e_client
        r = c.post("/api/v1/probe", json={"url": "file:///etc/passwd"})
        assert r.status_code == 400

    def test_missing_url_rejected_400(self, e2e_client):
        c, _, _ = e2e_client
        r = c.post("/api/v1/probe", json={})
        assert r.status_code == 400

    def test_invalid_json_body_rejected_400(self, e2e_client):
        c, _, _ = e2e_client
        r = c.post(
            "/api/v1/probe",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 400
