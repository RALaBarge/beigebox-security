"""
Tests for POST /api/v1/probe — the server-side HTTP probe endpoint.

Covers:
  1. No auth configured → endpoint is accessible (admin-allowed)
  2. Request carries an admin key → endpoint is accessible
  3. Request carries a non-admin key → 403 Forbidden
  4. file:// URL → 400, refused by validate_backend_url
  5. URL with embedded credentials → 400, refused
  6. gopher:// URL → 400, refused
  7. Valid http URL but connection fails → 200 with error key (not a server error)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from unittest.mock import patch as _patch_httpx

from beigebox.app_state import AppState
from beigebox.state import set_state


# ── Shared fixture ────────────────────────────────────────────────────────────

@pytest.fixture
def probe_client(tmp_path):
    """FastAPI test client with the probe endpoint exposed and no auth."""
    from fastapi.testclient import TestClient
    from beigebox import config as cfg_mod

    cfg_data = {
        "backend": {"url": "http://localhost:11434", "default_model": "llama3.2", "timeout": 120},
        "server": {"host": "0.0.0.0", "port": 8000},
        "embedding": {"model": "nomic-embed-text", "backend_url": "http://localhost:11434"},
        "storage": {
            "sqlite_path": str(tmp_path / "test.db"),
            "vector_store_path": str(tmp_path / "vectors"),
            "vector_backend": "memory",
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
        "wasm": {"enabled": False, "modules": {}},
    }

    rt_path = tmp_path / "runtime_config.yaml"
    rt_path.write_text("runtime: {}\n")

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
    mock_wasm.list_modules.return_value = []
    mock_wasm.default_module = ""
    mock_proxy = MagicMock()
    mock_proxy.wasm_runtime = mock_wasm

    # No auth_registry → auth is disabled → all calls treated as admin
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
            yield c

    cfg_mod._config = orig_config
    cfg_mod._RUNTIME_CONFIG_PATH = orig_rt_path
    cfg_mod._runtime_config = orig_rt_cfg
    cfg_mod._runtime_mtime  = orig_rt_mt


@pytest.fixture
def authed_probe_client(tmp_path):
    """Test client where auth IS enabled — exposes admin vs non-admin distinction."""
    from fastapi.testclient import TestClient
    from beigebox import config as cfg_mod

    cfg_data = {
        "backend": {"url": "http://localhost:11434", "default_model": "llama3.2", "timeout": 120},
        "server": {"host": "0.0.0.0", "port": 8000},
        "embedding": {"model": "nomic-embed-text", "backend_url": "http://localhost:11434"},
        "storage": {
            "sqlite_path": str(tmp_path / "test.db"),
            "vector_store_path": str(tmp_path / "vectors"),
            "vector_backend": "memory",
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
        "wasm": {"enabled": False, "modules": {}},
    }

    rt_path = tmp_path / "runtime_config.yaml"
    rt_path.write_text("runtime: {}\n")

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
    mock_wasm.list_modules.return_value = []
    mock_wasm.default_module = ""
    mock_proxy = MagicMock()
    mock_proxy.wasm_runtime = mock_wasm

    # Build a mock auth_registry that IS enabled
    admin_meta = MagicMock()
    admin_meta.admin = True

    user_meta = MagicMock()
    user_meta.admin = False

    mock_auth = MagicMock()
    mock_auth.is_enabled.return_value = True
    # lookup is called by ApiKeyMiddleware; we'll inject auth_key into request.state directly
    mock_auth.lookup.return_value = None

    mock_state = AppState(proxy=mock_proxy, auth_registry=mock_auth)

    async def _fake_startup(app):  # noqa: ARG001
        set_state(mock_state)
        return mock_state

    async def _fake_shutdown(state):  # noqa: ARG001
        pass

    with patch("beigebox.bootstrap.startup", side_effect=_fake_startup), \
         patch("beigebox.bootstrap.shutdown", side_effect=_fake_shutdown):
        from beigebox.main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c, mock_auth, admin_meta, user_meta

    cfg_mod._config = orig_config
    cfg_mod._RUNTIME_CONFIG_PATH = orig_rt_path
    cfg_mod._runtime_config = orig_rt_cfg
    cfg_mod._runtime_mtime  = orig_rt_mt


# ── No-auth path ──────────────────────────────────────────────────────────────

class TestProbeNoAuth:
    """With no auth configured every call is treated as admin-allowed."""

    def test_missing_url_returns_400(self, probe_client):
        r = probe_client.post("/api/v1/probe", json={})
        assert r.status_code == 400
        assert "url required" in r.json()["error"]

    def test_file_url_refused(self, probe_client):
        r = probe_client.post("/api/v1/probe", json={"url": "file:///etc/passwd"})
        assert r.status_code == 400
        data = r.json()
        assert "refused" in data["error"].lower() or "error" in data

    def test_embedded_creds_refused(self, probe_client):
        r = probe_client.post("/api/v1/probe", json={"url": "http://user:pass@localhost:11434/"})
        assert r.status_code == 400

    def test_gopher_refused(self, probe_client):
        r = probe_client.post("/api/v1/probe", json={"url": "gopher://evil.example/x"})
        assert r.status_code == 400

    def test_private_ip_not_refused(self, probe_client):
        """Private IPs are allowed — the probe exists to reach internal services.
        The URL will fail to connect (no real server) but the 400 refusal must NOT fire.
        A conn error response has an 'error' key, not 'refused'.
        """
        r = probe_client.post(
            "/api/v1/probe",
            json={"url": "http://192.168.1.50:18765/health", "method": "GET", "timeout": 0.1},
        )
        # Must be 200 (connection attempted, possibly failed) — not 400 (refused by us)
        assert r.status_code == 200
        data = r.json()
        # Either a successful response dict OR a connection error dict — not a SafePath refusal
        assert "status" in data or "error" in data
        if "error" in data:
            assert "refused" not in data["error"].lower() or "connection" in data["error"].lower()


# ── URL validation — _require_admin check ─────────────────────────────────────

class TestRequireAdmin:
    """_require_admin behavior via the probe endpoint when auth is enabled."""

    def test_no_auth_state_allows_all(self):
        """When state has no auth_registry, _require_admin returns None (allow)."""
        from beigebox.routers._shared import _require_admin
        mock_request = MagicMock()
        mock_state = AppState()  # no auth_registry

        with patch("beigebox.routers._shared.maybe_state", return_value=mock_state):
            result = _require_admin(mock_request)
        assert result is None

    def test_auth_disabled_allows_all(self):
        """When auth_registry.is_enabled() is False, _require_admin returns None."""
        from beigebox.routers._shared import _require_admin
        mock_request = MagicMock()

        mock_auth = MagicMock()
        mock_auth.is_enabled.return_value = False
        mock_state = AppState(auth_registry=mock_auth)

        with patch("beigebox.routers._shared.maybe_state", return_value=mock_state):
            result = _require_admin(mock_request)
        assert result is None

    def test_admin_key_allows(self):
        """An admin key in request.state.auth_key must pass through."""
        from beigebox.routers._shared import _require_admin
        from fastapi.responses import JSONResponse

        admin_meta = MagicMock()
        admin_meta.admin = True

        mock_request = MagicMock()
        mock_request.state.auth_key = admin_meta

        mock_auth = MagicMock()
        mock_auth.is_enabled.return_value = True
        mock_state = AppState(auth_registry=mock_auth)

        with patch("beigebox.routers._shared.maybe_state", return_value=mock_state):
            result = _require_admin(mock_request)
        assert result is None

    def test_non_admin_key_returns_403(self):
        """A non-admin key must produce a 403 JSONResponse."""
        from beigebox.routers._shared import _require_admin
        from fastapi.responses import JSONResponse

        user_meta = MagicMock()
        user_meta.admin = False

        mock_request = MagicMock()
        mock_request.state.auth_key = user_meta

        mock_auth = MagicMock()
        mock_auth.is_enabled.return_value = True
        mock_state = AppState(auth_registry=mock_auth)

        with patch("beigebox.routers._shared.maybe_state", return_value=mock_state):
            result = _require_admin(mock_request)
        assert isinstance(result, JSONResponse)
        assert result.status_code == 403

    def test_no_auth_key_on_request_returns_403(self):
        """When auth is enabled but no key was attached (e.g. missing header), deny."""
        from beigebox.routers._shared import _require_admin
        from fastapi.responses import JSONResponse

        mock_request = MagicMock()
        mock_request.state.auth_key = None

        mock_auth = MagicMock()
        mock_auth.is_enabled.return_value = True
        mock_state = AppState(auth_registry=mock_auth)

        with patch("beigebox.routers._shared.maybe_state", return_value=mock_state):
            result = _require_admin(mock_request)
        assert isinstance(result, JSONResponse)
        assert result.status_code == 403
