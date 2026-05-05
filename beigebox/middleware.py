"""
HTTP middleware: API-key auth, web-UI session auth, security headers.

Three Starlette `BaseHTTPMiddleware` classes plus the supporting
`_emit_auth_denied` helper and the path allow/deny constants. Lives
outside main.py so the entry point stays a thin wiring file; the
middleware classes themselves are independent of FastAPI app
construction and can be added to any compatible app via
`add_middleware()`.

Dependencies (kept narrow):
  - beigebox.state.maybe_state   — read-only AppState lookup
  - beigebox.web_auth.COOKIE_SESSION
  - beigebox.config.get_config
  - beigebox.auth.KeyMeta        — for synthesizing pseudo-keys when a
                                    dynamic API key is verified through
                                    the api_keys repo
"""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from beigebox.config import get_config
from beigebox.state import maybe_state
from beigebox.web_auth import COOKIE_SESSION

logger = logging.getLogger(__name__)


# ── Path allow/deny lists ────────────────────────────────────────────────────

# Paths that never require API-key auth (web UI, health checks, OAuth flow)
_AUTH_EXEMPT = frozenset(["/", "/ui", "/beigebox/health", "/api/v1/status"])
_AUTH_EXEMPT_PREFIXES = ("/web/", "/auth/")

# Paths that WebAuthMiddleware protects when OAuth is active
_WEB_UI_PATHS = frozenset(["/", "/ui"])
_WEB_UI_PREFIXES = ("/web/",)


# ── Auth denial wire emit ────────────────────────────────────────────────────

def _emit_auth_denied(reason_code: str, principal_name: str, principal_type: str,
                      endpoint_path: str, request: Request | None = None) -> None:
    """Emit an `auth_denied` wire event before a 401/403/429 return.

    Per the observability rubric: auth denials must never be silent — they're
    load-bearing for breach forensics and rate-limit tuning. ``request``, when
    provided, is mined for ``client_ip`` and ``user_agent`` so the event has
    enough context for an analyst to triage without a separate lookup.

    Best-effort: failure to emit MUST NOT block the deny response. We log
    (not silently swallow) the failure so a broken wire dispatcher surfaces
    in the stdlib log instead of disappearing.
    """
    if not (maybe_state() and maybe_state().proxy and maybe_state().proxy.wire):
        return
    meta: dict = {
        "reason_code": reason_code,
        "principal_name": principal_name,
        "principal_type": principal_type,
        "endpoint": endpoint_path,
    }
    if request is not None:
        try:
            meta["client_ip"] = request.client.host if request.client else None
            meta["user_agent"] = request.headers.get("user-agent")
        except Exception:  # request introspection — keep meta partial on failure
            pass
    try:
        maybe_state().proxy.wire.log(
            direction="inbound",
            role="auth",
            content=f"deny {reason_code}: {principal_name or '?'} → {endpoint_path}",
            event_type="auth_denied",
            source="auth_middleware",
            meta=meta,
        )
    except Exception:
        logger.warning("auth_denied wire emit failed", exc_info=True)


# ── Middleware classes ───────────────────────────────────────────────────────

class ApiKeyMiddleware(BaseHTTPMiddleware):
    """
    Multi-key API guard backed by agentauth keychain storage.

    Reads from the global auth_registry (built at startup from config auth.keys).
    Falls back to the legacy single auth.api_key for backwards compatibility.
    Auth disabled when no keys are configured.

    Per-key enforcement:
      - Endpoint ACL (allowed_endpoints glob patterns)
      - Model ACL  (allowed_models glob patterns — checked in chat endpoint)
      - Rate limit (allowed_models rate_limit_rpm rolling 60-second window)

    Accepts the token via:
      Authorization: Bearer <token>
      api-key: <token>          (OpenAI-style header)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if maybe_state() is None or maybe_state().auth_registry is None or not maybe_state().auth_registry.is_enabled():
            return await call_next(request)

        path = request.url.path
        if path in _AUTH_EXEMPT or any(path.startswith(p) for p in _AUTH_EXEMPT_PREFIXES):
            return await call_next(request)

        # Extract token. Querystring (?api_key=...) is intentionally NOT accepted
        # — it leaks via access logs, browser history, referrers, and proxy logs.
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = request.headers.get("api-key", "")

        meta = maybe_state().auth_registry.validate(token)

        # If static key validation fails, try dynamic API keys from database
        if meta is None and maybe_state().api_keys and token:
            user_id = maybe_state().api_keys.verify(token)
            if user_id:
                # Synthesize a pseudo-KeyMeta for the dynamic key. Default
                # rate limit comes from config (not unlimited).
                from beigebox.auth import KeyMeta
                cfg = get_config()
                default_rate_limit = cfg.get("auth", {}).get("dynamic_key_rate_limit_rpm", 100)
                meta = KeyMeta(
                    name=f"user:{user_id[:8]}",
                    allowed_models=["*"],
                    allowed_endpoints=["*"],
                    rate_limit_rpm=default_rate_limit,
                )

        if meta is None:
            _emit_auth_denied("invalid_api_key", "unknown", "api_key", path, request)
            return JSONResponse(
                {
                    "error": {
                        "message": "Invalid or missing API key.",
                        "type": "invalid_request_error",
                        "code": "invalid_api_key",
                    }
                },
                status_code=401,
            )

        if not maybe_state().auth_registry.check_rate_limit(meta):
            _emit_auth_denied("rate_limit_exceeded", meta.name, "api_key", path, request)
            return JSONResponse(
                {
                    "error": {
                        "message": f"Rate limit exceeded for key '{meta.name}' ({meta.rate_limit_rpm} rpm).",
                        "type": "rate_limit_error",
                        "code": "rate_limit_exceeded",
                    }
                },
                status_code=429,
            )

        if not maybe_state().auth_registry.check_endpoint(meta, path):
            _emit_auth_denied("endpoint_not_allowed", meta.name, "api_key", path, request)
            return JSONResponse(
                {
                    "error": {
                        "message": f"Endpoint '{path}' not permitted for key '{meta.name}'.",
                        "type": "invalid_request_error",
                        "code": "endpoint_not_allowed",
                    }
                },
                status_code=403,
            )

        # Store key metadata in request state so downstream endpoints can check model ACL
        request.state.auth_key = meta
        return await call_next(request)


class WebAuthMiddleware(BaseHTTPMiddleware):
    """
    Gates web UI paths behind a signed session cookie when OAuth is enabled.

    API paths (/v1/, /api/) are not touched — those use Bearer token auth.
    The OAuth flow paths (/auth/*) are always exempt.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if maybe_state() is None:
            return await call_next(request)

        oauth_enabled = maybe_state().web_auth is not None and maybe_state().web_auth.is_enabled()

        if not oauth_enabled:
            return await call_next(request)

        path = request.url.path

        if path.startswith("/auth/"):
            return await call_next(request)

        is_web = path in _WEB_UI_PATHS or any(path.startswith(p) for p in _WEB_UI_PREFIXES)
        if not is_web:
            return await call_next(request)

        # Validate session cookie
        token = request.cookies.get(COOKIE_SESSION, "")
        user = maybe_state().web_auth.verify_session(token) if token else None

        if user is None:
            from starlette.responses import RedirectResponse
            providers = maybe_state().web_auth.list_providers()
            login_path = f"/auth/{providers[0]}/login" if providers else "/"
            return RedirectResponse(url=login_path, status_code=302)

        request.state.web_user = user
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach security headers to every response.

    HSTS is config-gated — `security.hsts.enabled: true` in config.yaml enables
    `Strict-Transport-Security`. Default off because:
      - Browsers ignore HSTS over plain http:// (it's only honored on https://).
      - But once a browser sees HSTS for a host, it pins it; an operator who
        set HSTS during a TLS-terminated test and later switched back to plain
        http:// would lock themselves out.
    Operators running BeigeBox behind nginx/caddy with TLS should enable HSTS
    explicitly (recommended).
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        sec_cfg = (get_config().get("security") or {})
        hsts_cfg = sec_cfg.get("hsts") or {}
        if hsts_cfg.get("enabled", False):
            # Auto-suppress over plain http:// — this catches the operator
            # who flips the flag locally before TLS is wired up. Browsers
            # would ignore the header on http:// anyway, but skipping it on
            # the response means we never advertise HSTS for a non-TLS host
            # (avoids confusion in audit tooling). The check honors a trusted
            # edge proxy's X-Forwarded-Proto first, then falls back to the
            # request scheme directly.
            forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
            req_scheme = forwarded_proto or request.url.scheme.lower()
            if req_scheme == "https":
                max_age = int(hsts_cfg.get("max_age", 31536000))
                parts = [f"max-age={max_age}"]
                if hsts_cfg.get("include_subdomains", True):
                    parts.append("includeSubDomains")
                if hsts_cfg.get("preload", False):
                    parts.append("preload")
                response.headers["Strict-Transport-Security"] = "; ".join(parts)

        # CSP: self + blob: (audio/image preview) + no inline scripts except index.html
        # eval is blocked; data: URIs restricted to images only.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response


def _resolve_client_ip(request: Request, trusted_proxies: set[str]) -> str | None:
    """Return the real client IP, honoring X-Forwarded-For only from trusted proxies.

    The remote address must be in ``trusted_proxies`` for the forwarded header
    to be trusted. Otherwise we use ``request.client.host`` as the source of
    truth — this prevents an arbitrary client from spoofing their rate-limit
    bucket by setting ``X-Forwarded-For: <other ip>``.

    Forwarded chain semantics: when the header is trusted, the *leftmost*
    address (the original client) is taken. Some setups invert this; configure
    your edge proxy to emit the chain in standard order.
    """
    direct = request.client.host if request.client else None
    if direct and direct in trusted_proxies:
        xff = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
    return direct


class PolicyMiddleware(BaseHTTPMiddleware):
    """Per-route WAF-style policy enforcement.

    Reads ``security.policies`` from config and enforces body size, content-
    type allowlist, rate caps, message/attachment count, and tool-arg
    nesting depth. See :mod:`beigebox.security.policy` for the DSL.

    Order: runs *after* ApiKey/WebAuth so deny events have a principal in
    request.state when available, but before the route handler so an
    over-large body never reaches a parser.

    Three hardening layers added beyond the original DSL:
      1. **Content-Length pre-check** — reject before the body is buffered if
         the declared length exceeds the rule's cap. Closes the obvious
         "claim 1 GB body, force the proxy to buffer it" DoS.
      2. **Trusted-proxy real-IP resolution** — only trust X-Forwarded-For /
         X-Real-IP when the request comes from a configured edge proxy. See
         ``security.policies.trusted_proxies`` (list of IPs).
      3. **Body re-injection** — buffered body is fed back to downstream
         handlers via ``request._receive`` so they don't have to know.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        from beigebox.security.policy import PolicyEngine

        st = maybe_state()
        engine: PolicyEngine | None = getattr(st, "policy_engine", None) if st else None
        if engine is None or not engine.enabled:
            return await call_next(request)

        path = request.url.path
        method = request.method
        content_type = request.headers.get("content-type", "")
        client_ip = _resolve_client_ip(request, engine.trusted_proxies)

        rule = engine.resolve(path, method)
        max_body = rule.max_body_bytes

        # Content-Length pre-check — refuse before buffering anything.
        # Also reject Transfer-Encoding: chunked (bypasses Content-Length check).
        if max_body is not None:
            # Reject chunked encoding when body size limits are enforced.
            # Chunked requests don't have Content-Length, so they would skip
            # the pre-check and force full buffering up to max_body.
            transfer_encoding = request.headers.get("transfer-encoding", "").lower()
            if transfer_encoding == "chunked":
                _emit_auth_denied(
                    "body_too_large", _principal_name(request), "policy", path, request,
                )
                return JSONResponse(
                    {
                        "error": {
                            "message": (
                                f"Request denied by policy '{rule.rule_id}': "
                                f"Transfer-Encoding: chunked not allowed (policy enforces body size limits)"
                            ),
                            "type": "policy_denied",
                            "code": "body_too_large",
                        }
                    },
                    status_code=413,
                )

            try:
                declared_len = int(request.headers.get("content-length") or "0")
            except ValueError:
                declared_len = 0
            if declared_len > max_body:
                _emit_auth_denied(
                    "body_too_large", _principal_name(request), "policy", path, request,
                )
                return JSONResponse(
                    {
                        "error": {
                            "message": (
                                f"Request denied by policy '{rule.rule_id}': "
                                f"declared body {declared_len} bytes exceeds {max_body}"
                            ),
                            "type": "policy_denied",
                            "code": "body_too_large",
                        }
                    },
                    status_code=413,
                )

        body = b""
        if method in {"POST", "PUT", "PATCH"}:
            body = await request.body()

            async def _receive():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = _receive  # type: ignore[attr-defined]

        decision = engine.check(path, method, content_type, body, client_ip)
        if not decision.allowed:
            _emit_auth_denied(decision.code, _principal_name(request), "policy", path, request)
            if decision.code == "rate_cap_exceeded":
                status = 429
            elif decision.code in (
                "body_too_large",
                "tool_args_too_large",
                "tool_arg_string_too_long",
            ):
                status = 413
            else:
                status = 400
            return JSONResponse(
                {
                    "error": {
                        "message": f"Request denied by policy '{decision.rule_id}': {decision.reason}",
                        "type": "policy_denied",
                        "code": decision.code,
                    }
                },
                status_code=status,
            )

        return await call_next(request)


def _principal_name(request: Request) -> str:
    principal = getattr(request.state, "auth_key", None)
    return getattr(principal, "name", "unknown")


__all__ = [
    "ApiKeyMiddleware",
    "WebAuthMiddleware",
    "SecurityHeadersMiddleware",
    "PolicyMiddleware",
]
