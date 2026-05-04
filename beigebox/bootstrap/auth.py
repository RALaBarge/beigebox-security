"""Auth subsystem bootstrap.

Builds:
  - MultiKeyAuthRegistry (always — runtime decides whether keys are required)
  - WebAuthManager        (always — runtime decides whether OAuth is enabled)

Top-level ``auth.enabled`` flag (default ``True``) short-circuits BOTH
the API-key middleware and the web-auth middleware when set to ``False``,
so BeigeBox runs wide open (single-user dev mode). The flag is read here
once and threaded into both subsystems.

Hard-stop on misconfigured auth: when ``auth.enabled=true`` but no keys
resolve (no legacy ``api_key``, no ``keys`` whose tokens loaded), refuse
to start. The previous behavior was to silently fall through to
pass-through, which is the most common deployment footgun.

Operators who genuinely want an open instance must:
  - Set ``auth.enabled=false`` in config.yaml (intended path for dev), OR
  - Set the env var ``BEIGEBOX_ALLOW_EMPTY_AUTH=1`` (unusual: integration
    tests, transient bring-up). Note: there is **no config-file flag** for
    this — config files are too easy to forge or copy by accident.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from beigebox.auth import MultiKeyAuthRegistry
from beigebox.web_auth import WebAuthManager

logger = logging.getLogger(__name__)


class AuthMisconfiguredError(RuntimeError):
    """Raised when auth.enabled=true but no keys are usable."""


@dataclass
class AuthBundle:
    auth_registry: MultiKeyAuthRegistry
    web_auth: WebAuthManager


def build_auth(cfg: dict, users: Any) -> AuthBundle:  # noqa: ARG001 — users reserved for future use
    auth_cfg = cfg.get("auth", {})
    enabled = bool(auth_cfg.get("enabled", True))

    auth_registry = MultiKeyAuthRegistry(auth_cfg)

    if enabled and not auth_registry.is_enabled():
        configured_keys = [k.get("name", "?") for k in auth_cfg.get("keys", []) if k.get("name")]
        legacy = bool(auth_cfg.get("api_key", "").strip())
        msg = (
            "Auth misconfigured: auth.enabled=true but no keys resolved.\n"
            f"  legacy api_key set: {legacy}\n"
            f"  configured key names: {configured_keys or '(none)'}\n"
            "Likely cause: each key in auth.keys needs a token in either the OS keychain "
            "(`agentauth add <name>`) or BB_<NAME>_TOKEN env var. None were found.\n"
            "To run BeigeBox with auth fully off, set auth.enabled=false in config.yaml.\n"
            "To explicitly accept this state (rare — e.g. integration tests), "
            "set the env var BEIGEBOX_ALLOW_EMPTY_AUTH=1 (no config-file equivalent)."
        )
        if os.environ.get("BEIGEBOX_ALLOW_EMPTY_AUTH") == "1":
            logger.warning(
                "Auth empty but BEIGEBOX_ALLOW_EMPTY_AUTH=1 — proceeding wide open. "
                "Never use this in production."
            )
        else:
            raise AuthMisconfiguredError(msg)

    web_auth = WebAuthManager(auth_cfg.get("web_ui", {}), enabled=enabled)

    return AuthBundle(
        auth_registry=auth_registry,
        web_auth=web_auth,
    )


__all__ = ["AuthBundle", "AuthMisconfiguredError", "build_auth"]
