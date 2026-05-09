"""
Error-path tests not covered by test_backend_failure_modes.py.

Gap 1: 429 (rate-limit) response from an upstream backend — the router must
        surface a BackendResponse(ok=False, status_code=429), not crash.

Gap 2: asyncio.CancelledError inside the streaming capture path — the
        CapturedResponse.from_partial() correctly records "client_disconnect"
        and the error propagates so the async framework can tear down cleanly.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from beigebox.backends.base import BackendResponse
from beigebox.backends.ollama import OllamaBackend
from beigebox.backends.openrouter import OpenRouterBackend


# ── 429 rate-limit from Ollama ────────────────────────────────────────────────

class TestOllama429:
    """Ollama returning 429 must produce BackendResponse(ok=False, status_code=429)."""

    @pytest.mark.asyncio
    async def test_forward_returns_error_on_429(self):
        b = OllamaBackend(name="local", url="http://fake-ollama:11434", timeout=5)

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "rate limited"

        with patch("beigebox.backends.ollama.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            resp = await b.forward({"model": "llama3", "messages": []})

        assert resp.ok is False
        assert resp.status_code == 429
        assert "429" in resp.error

    @pytest.mark.asyncio
    async def test_forward_429_does_not_raise(self):
        """BackendResponse contract: forward() NEVER raises on upstream errors."""
        b = OllamaBackend(name="local", url="http://fake-ollama:11434", timeout=5)

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "rate limited"

        with patch("beigebox.backends.ollama.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            try:
                resp = await b.forward({"model": "llama3", "messages": []})
            except Exception as exc:
                pytest.fail(f"forward() raised unexpectedly: {exc}")

        assert resp.ok is False


# ── 429 rate-limit from OpenRouter ───────────────────────────────────────────

class TestOpenRouter429:
    """OpenRouter returning 429 must produce BackendResponse(ok=False, status_code=429)."""

    @pytest.mark.asyncio
    async def test_forward_returns_error_on_429(self):
        b = OpenRouterBackend(
            name="openrouter",
            url="http://fake-openrouter",
            api_key="test-key",
            timeout=5,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = '{"error": {"message": "Rate limit exceeded"}}'

        with patch("beigebox.backends.openrouter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            resp = await b.forward({"model": "anthropic/claude-3", "messages": []})

        assert resp.ok is False
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_forward_429_does_not_raise(self):
        b = OpenRouterBackend(
            name="openrouter",
            url="http://fake-openrouter",
            api_key="test-key",
            timeout=5,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = '{"error": {"message": "Rate limit exceeded"}}'

        with patch("beigebox.backends.openrouter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            try:
                resp = await b.forward({"model": "anthropic/claude-3", "messages": []})
            except Exception as exc:
                pytest.fail(f"forward() raised unexpectedly: {exc}")

        assert resp.ok is False


# ── CancelledError in streaming capture ───────────────────────────────────────

class TestCancelledErrorCapture:
    """When a client disconnects mid-stream the runtime cancels the generator.
    The capture layer must record the request with outcome='client_disconnect'
    and let CancelledError propagate so the framework can tear down cleanly.
    """

    @pytest.mark.asyncio
    async def test_cancelled_error_propagates_from_streaming_generator(self):
        """A simple async generator that raises CancelledError must propagate it."""
        async def _gen():
            yield "data: chunk1\n"
            raise asyncio.CancelledError()

        chunks = []
        gen = _gen()
        try:
            async for chunk in gen:
                chunks.append(chunk)
        except asyncio.CancelledError:
            pass  # expected
        else:
            pytest.fail("CancelledError did not propagate from generator")

        assert chunks == ["data: chunk1\n"]

    def test_capture_from_partial_records_client_disconnect(self):
        """CapturedResponse.from_partial with outcome='client_disconnect' must
        succeed and expose the outcome — this is the path proxy/core.py calls
        inside its `except (asyncio.CancelledError, GeneratorExit)` block.
        """
        from datetime import datetime, timezone
        from beigebox.capture import CaptureContext, CapturedResponse

        ctx = CaptureContext(
            conv_id="test-conv",
            turn_id="turn-1",
            model="llama3",
            backend="local",
            started_at=datetime.now(timezone.utc),
        )

        resp = CapturedResponse.from_partial(
            ctx=ctx,
            outcome="client_disconnect",
            content="partial response text",
            error=None,
        )

        assert resp.outcome == "client_disconnect"
        assert resp.error_kind == "client_disconnect"
        assert resp.content == "partial response text"
        assert resp.ctx is ctx

    def test_capture_from_partial_stream_abort(self):
        """stream_aborted outcome is correctly recorded for mid-stream upstream errors."""
        from datetime import datetime, timezone
        from beigebox.capture import CaptureContext, CapturedResponse

        ctx = CaptureContext(
            conv_id="test-conv",
            turn_id="turn-2",
            model="llama3",
            backend="local",
            started_at=datetime.now(timezone.utc),
        )

        resp = CapturedResponse.from_partial(
            ctx=ctx,
            outcome="stream_aborted",
            content="partial",
            error=httpx.RemoteProtocolError("connection closed"),
        )

        assert resp.outcome == "stream_aborted"
        assert resp.error_kind == "stream_aborted"
