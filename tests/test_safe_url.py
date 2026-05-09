"""Tests for beigebox.security.safe_url."""

from __future__ import annotations

import pytest

from beigebox.security.safe_url import (
    SsrfRefusedError,
    validate_backend_url,
    validate_browser_ws_url,
    validate_remote_probe_url,
    validate_url,
    validate_webhook_url,
)


# --- core validate_url -------------------------------------------------------


def test_validate_url_accepts_https_public():
    assert validate_url("https://api.openai.com/v1/chat") == "https://api.openai.com/v1/chat"


def test_validate_url_accepts_http_public():
    assert validate_url("http://example.com/path?q=1") == "http://example.com/path?q=1"


def test_validate_url_rejects_file_scheme():
    with pytest.raises(SsrfRefusedError, match="scheme"):
        validate_url("file:///etc/passwd")


def test_validate_url_rejects_gopher_scheme():
    with pytest.raises(SsrfRefusedError, match="scheme"):
        validate_url("gopher://example.com/")


def test_validate_url_rejects_javascript_scheme():
    with pytest.raises(SsrfRefusedError, match="scheme"):
        validate_url("javascript:alert(1)")


def test_validate_url_rejects_embedded_credentials():
    with pytest.raises(SsrfRefusedError, match="credentials"):
        validate_url("http://attacker:pw@target.example/")


def test_validate_url_rejects_loopback_ipv4():
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_url("http://127.0.0.1/admin")


def test_validate_url_rejects_loopback_ipv6():
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_url("http://[::1]/admin")


def test_validate_url_rejects_private_rfc1918():
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_url("http://10.0.0.5/")


def test_validate_url_rejects_link_local():
    """AWS metadata server pattern."""
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_url("http://169.254.169.254/latest/meta-data/")


def test_validate_url_accepts_private_when_deny_disabled():
    assert validate_url("http://10.0.0.5/", deny_private=False) == "http://10.0.0.5/"


def test_validate_url_rejects_empty_string():
    with pytest.raises(SsrfRefusedError, match="non-empty"):
        validate_url("")


def test_validate_url_rejects_non_string():
    with pytest.raises(SsrfRefusedError, match="non-empty string"):
        validate_url(None)  # type: ignore[arg-type]


def test_validate_url_rejects_no_host():
    with pytest.raises(SsrfRefusedError, match="no host"):
        validate_url("https:///path")


def test_validate_url_allow_hosts_set():
    allow = {"api.openai.com", "openrouter.ai"}
    assert validate_url("https://api.openai.com/v1", allow_hosts=allow)
    with pytest.raises(SsrfRefusedError, match="not in allow-list"):
        validate_url("https://other.example/", allow_hosts=allow)


def test_validate_url_allow_hosts_callable():
    allow = lambda h: h.endswith(".internal.example.com")
    assert validate_url("https://api.internal.example.com/", allow_hosts=allow)
    with pytest.raises(SsrfRefusedError, match="not in allow-list"):
        validate_url("https://api.external.example.com/", allow_hosts=allow)


# --- preset wrappers ---------------------------------------------------------


def test_backend_url_allows_localhost():
    """Backends can legitimately run on localhost/LAN."""
    assert validate_backend_url("http://localhost:11434/v1") == "http://localhost:11434/v1"
    assert validate_backend_url("http://192.168.1.50:8080") == "http://192.168.1.50:8080"


def test_backend_url_rejects_file():
    with pytest.raises(SsrfRefusedError, match="scheme"):
        validate_backend_url("file:///etc/passwd")


def test_browser_ws_url_allows_local_ws():
    assert validate_browser_ws_url("ws://localhost:9222/devtools/browser/abc")
    assert validate_browser_ws_url("wss://localhost:9223/devtools/browser/abc")


def test_browser_ws_url_rejects_https():
    """ws/wss only, not http/https."""
    with pytest.raises(SsrfRefusedError, match="scheme"):
        validate_browser_ws_url("https://localhost:9222/")


def test_webhook_url_rejects_localhost():
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_webhook_url("http://127.0.0.1/internal-hook")


def test_webhook_url_accepts_public():
    assert validate_webhook_url("https://hooks.slack.com/services/T/B/X")


def test_remote_probe_url_rejects_aws_metadata():
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_remote_probe_url("http://169.254.169.254/latest/meta-data/")


def test_remote_probe_url_rejects_loopback():
    with pytest.raises(SsrfRefusedError, match="private/loopback"):
        validate_remote_probe_url("http://localhost/admin")
