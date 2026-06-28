"""OpenAI-compatible + Ollama-compatible proxy endpoints.

Extracted from beigebox/main.py (B-2). Includes:
- /v1/chat/completions (the main proxy entry — handles streaming + non-stream)
- /v1/models, /v1/embeddings, /v1/completions
- OpenAI passthroughs: /v1/files/, /v1/fine_tuning/, /v1/assistants/
- Ollama-native passthroughs: /api/tags, /api/chat, /api/generate,
  /api/pull, /api/push, /api/delete, /api/copy, /api/show, /api/embed,
  /api/embeddings, /api/ps, /api/version

All passthroughs route through ``_wire_and_forward`` (in ``_shared.py``)
which logs to wiretap and streams the upstream response verbatim.
"""
from __future__ import annotations

import logging

import httpx
import os
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from beigebox.config import get_config, get_ollama_backend_url
from beigebox.routers._shared import _wire_and_forward
from beigebox.state import get_state

logger = logging.getLogger(__name__)


router = APIRouter()


# ---------------------------------------------------------------------------
# Core OpenAI-compat endpoints
# ---------------------------------------------------------------------------

@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """Main proxy endpoint. Accepts OpenAI-format chat completion requests,
    intercepts for logging/embedding, forwards to backend.
    """
    body = await request.json()

    # Model ACL — check here where the body is already parsed
    model = body.get("model", "")
    _auth_key = getattr(request.state, "auth_key", None)
    _st = get_state()
    if _auth_key is not None and model and _st.auth_registry and not _st.auth_registry.check_model(_auth_key, model):
        return JSONResponse(
            {
                "error": {
                    "message": f"Model '{model}' not permitted for key '{_auth_key.name}'.",
                    "type": "invalid_request_error",
                    "code": "model_not_allowed",
                }
            },
            status_code=403,
        )

    # Inject the key name as a special body field so the routing rules engine
    # can match on BB_AUTH_KEY conditions. The proxy strips it before forwarding.
    if _auth_key:
        body["_bb_auth_key"] = _auth_key.name

    stream = body.get("stream", False)

    # Extract client info for anomaly detection
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    if stream:
        return StreamingResponse(
            _st.proxy.forward_chat_completion_stream(body, client_ip=client_ip, user_agent=user_agent),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
    else:
        data = await _st.proxy.forward_chat_completion(body, client_ip=client_ip, user_agent=user_agent)
        return JSONResponse(data)


@router.get("/v1/models")
async def list_models():
    """Forward model listing to backend."""
    data = await get_state().proxy.list_models()
    return JSONResponse(data)


@router.post("/v1/embeddings")
async def embeddings(request: Request):
    """Embeddings — forward to backend, logged."""
    return await _wire_and_forward(request, "embeddings")


@router.post("/v1/completions")
async def completions(request: Request):
    """Legacy completions — forward to backend."""
    return await _wire_and_forward(request, "completions")


# ---------------------------------------------------------------------------
# OpenAI passthroughs (files, fine-tuning, assistants, audio)
# ---------------------------------------------------------------------------

@router.api_route("/v1/files/{path:path}", methods=["GET", "POST", "DELETE"])
async def files_passthrough(path: str, request: Request):
    return await _wire_and_forward(request, f"files/{path}")


@router.api_route("/v1/fine_tuning/{path:path}", methods=["GET", "POST", "DELETE"])
async def fine_tuning_passthrough(path: str, request: Request):
    return await _wire_and_forward(request, f"fine_tuning/{path}")


@router.api_route("/v1/assistants/{path:path}", methods=["GET", "POST", "DELETE", "PUT"])
async def assistants_passthrough(path: str, request: Request):
    return await _wire_and_forward(request, f"assistants/{path}")


# ---------------------------------------------------------------------------
# Audio proxy (TTS + STT) — forwards with API key injection
# ---------------------------------------------------------------------------

def _get_api_key() -> str:
    """Resolve an API key for upstream auth, preferring OpenRouter from backends."""
    cfg = get_config()
    for b in cfg.get("backends", []):
        key = os.path.expandvars(b.get("api_key", ""))
        if key:
            return key
    return os.environ.get("OPENROUTER_API_KEY", "")


async def _audio_forward(request: Request, base_url: str, route_label: str, media_type: str = "application/octet-stream") -> StreamingResponse:
    """Forward audio requests to the configured STT/TTS backend.

    Same as _wire_and_forward but injects beigebox's API key so the upstream
    backend can authenticate without the client needing their own key.
    """
    _st = get_state()
    body = await request.body()
    path = request.url.path
    # Strip the /v1 prefix if the base_url already includes it
    if base_url.endswith("/v1") and path.startswith("/v1/"):
        path = path[3:]
    query = request.url.query
    target = f"{base_url}{path}"
    if query:
        target += f"?{query}"

    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    api_key = _get_api_key()
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    if _st.proxy and _st.proxy.wire:
        try:
            body_preview = body[:400].decode("utf-8", errors="replace") if body else ""
        except Exception:
            body_preview = ""
        _st.proxy.wire.log(
            direction="internal",
            role="proxy",
            content=f"[{request.method}] {route_label} → {target}\n{body_preview}",
            model="",
            conversation_id="",
        )

    async def _stream():
        resp_status = None
        total_bytes = 0
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    request.method,
                    target,
                    headers=headers,
                    content=body,
                ) as resp:
                    resp_status = resp.status_code
                    async for chunk in resp.aiter_bytes():
                        total_bytes += len(chunk)
                        yield chunk
        finally:
            if _st.proxy and _st.proxy.wire:
                _st.proxy.wire.log(
                    direction="outbound",
                    role="proxy",
                    content=f"[{request.method}] {route_label} ← HTTP {resp_status} ({total_bytes} bytes)",
                )

    return StreamingResponse(_stream(), media_type=media_type)


@router.post("/v1/audio/speech")
async def audio_speech(request: Request):
    """OpenAI-compatible TTS — forward to configured TTS backend.

    Injects beigebox's OpenRouter API key into the forwarded request so the
    upstream backend can authenticate the call. The client does not need to
    provide its own API key.
    """
    cfg = get_config()
    voice_cfg = cfg.get("voice", {})
    tts_url = voice_cfg.get("tts_url", "")
    if not tts_url:
        return JSONResponse(
            {"error": {"message": "TTS not configured (set voice.tts_url in config.yaml)", "type": "invalid_request_error"}},
            status_code=503,
        )
    tts_url = tts_url.rstrip("/")
    return await _audio_forward(request, tts_url, "audio/speech", "audio/mpeg")


@router.post("/v1/audio/transcriptions")
async def audio_transcriptions(request: Request):
    """OpenAI-compatible STT — forward to configured STT backend.

    Injects beigebox's OpenRouter API key into the forwarded request so the
    upstream backend can authenticate the call. The client does not need to
    provide its own API key.
    """
    cfg = get_config()
    voice_cfg = cfg.get("voice", {})
    stt_url = voice_cfg.get("stt_url", "")
    if not stt_url:
        return JSONResponse(
            {"error": {"message": "STT not configured (set voice.stt_url in config.yaml)", "type": "invalid_request_error"}},
            status_code=503,
        )
    stt_url = stt_url.rstrip("/")
    return await _audio_forward(request, stt_url, "audio/transcriptions")


# ---------------------------------------------------------------------------
# Ollama-native passthroughs (frontends that speak Ollama directly)
# ---------------------------------------------------------------------------

def _ollama_base_url() -> str:
    """Return the local Ollama URL from config.

    Ollama-native routes must target this directly, not get_primary_backend_url()
    which may return OpenRouter. When OpenRouter is the primary backend its URL
    contains a path component (/api/v1) that, prepended to /api/tags, forms a
    double-path that OpenRouter serves as HTML — the original bug.
    """
    return get_ollama_backend_url() or get_config().get("backend", {}).get("url", "http://localhost:11434").rstrip("/")


async def _ollama_forward(path: str, fallback: dict) -> JSONResponse:
    """GET a path from the local Ollama backend; return fallback JSON on any error."""
    url = f"{_ollama_base_url()}{path}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception as exc:
        logger.warning("Ollama unreachable at %s (%s) — returning empty fallback", url, exc)
        return JSONResponse(fallback)


@router.api_route("/api/tags", methods=["GET"])
async def ollama_tags(request: Request):
    """Ollama model list — forward to local Ollama; return empty list if unavailable."""
    return await _ollama_forward("/api/tags", {"models": []})


@router.api_route("/api/chat", methods=["POST"])
async def ollama_chat(request: Request):
    """Ollama native chat — forward and log."""
    return await _wire_and_forward(request, "ollama/chat", override_base_url=_ollama_base_url())


@router.api_route("/api/generate", methods=["POST"])
async def ollama_generate(request: Request):
    """Ollama native generate — forward and log."""
    return await _wire_and_forward(request, "ollama/generate", override_base_url=_ollama_base_url())


@router.api_route("/api/pull", methods=["POST"])
async def ollama_pull(request: Request):
    """Ollama model pull — forward and log."""
    return await _wire_and_forward(request, "ollama/pull", override_base_url=_ollama_base_url())


@router.api_route("/api/push", methods=["POST"])
async def ollama_push(request: Request):
    return await _wire_and_forward(request, "ollama/push", override_base_url=_ollama_base_url())


@router.api_route("/api/delete", methods=["DELETE", "POST"])
async def ollama_delete(request: Request):
    return await _wire_and_forward(request, "ollama/delete", override_base_url=_ollama_base_url())


@router.api_route("/api/copy", methods=["POST"])
async def ollama_copy(request: Request):
    return await _wire_and_forward(request, "ollama/copy", override_base_url=_ollama_base_url())


@router.api_route("/api/show", methods=["POST"])
async def ollama_show(request: Request):
    return await _wire_and_forward(request, "ollama/show", override_base_url=_ollama_base_url())


@router.api_route("/api/embed", methods=["POST"])
async def ollama_embed(request: Request):
    """Ollama embed — forward and log."""
    return await _wire_and_forward(request, "ollama/embed", override_base_url=_ollama_base_url())


@router.api_route("/api/embeddings", methods=["POST"])
async def ollama_embeddings(request: Request):
    return await _wire_and_forward(request, "ollama/embeddings", override_base_url=_ollama_base_url())


@router.api_route("/api/ps", methods=["GET"])
async def ollama_ps(request: Request):
    """Ollama running processes — forward to local Ollama; return empty list if unavailable."""
    return await _ollama_forward("/api/ps", {"models": []})


@router.api_route("/api/version", methods=["GET"])
async def ollama_version(request: Request):
    return await _wire_and_forward(request, "ollama/version", override_base_url=_ollama_base_url())
