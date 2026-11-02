"""Tests for the CORS origin policy.

The dashboard is normally opened on the same machine as the backend, but a
self-hosted detector is also expected to be opened from a phone or a second
laptop on the same network. The browser then refuses to let that page call the
API unless the private address it was served from is allowed, which is exactly
what happened when a dashboard on `http://10.140.125.196:8080` could not reach
`http://<same host>:8000` and silently fell back to its own server engine.

Pinned here: private-network and extension origins are allowed, and a public
origin is not — an arbitrary internet page must not be able to use the
operator's backend as a scanning service.
"""
from __future__ import annotations

import re

import pytest

from app.core.config import get_settings

ALLOWED = [
    "chrome-extension://abcdefghijklmnop",
    "http://localhost:8080",
    "https://localhost:5173",
    "http://127.0.0.1:8080",
    "http://10.140.125.196:8080",
    "https://10.0.0.5",
    "http://192.168.1.42:3000",
    "http://172.16.4.7:8080",
    "http://172.31.255.254:8080",
    "http://my-laptop.local:8080",
]

REFUSED = [
    "https://evil.example.com",
    "http://phishpa1.top",
    "https://example.org:8080",
    "http://172.32.0.1:8080",  # just outside the 172.16/12 private block
    "http://8.8.8.8:8080",
    "null",
    "",
]


@pytest.fixture(scope="module")
def origin_regex() -> re.Pattern[str]:
    return re.compile(get_settings().CORS_ORIGIN_REGEX)


@pytest.mark.parametrize("origin", ALLOWED)
def test_private_and_extension_origins_are_allowed(origin_regex, origin):
    assert origin_regex.match(origin), f"{origin} should be allowed to call the API"


@pytest.mark.parametrize("origin", REFUSED)
def test_public_origins_are_refused(origin_regex, origin):
    assert not origin_regex.match(origin), f"{origin} must not be allowed"


def test_allow_origin_regex_is_configurable(monkeypatch):
    """An operator can narrow or widen the policy through the environment."""
    monkeypatch.setenv("CORS_ORIGIN_REGEX", r"^https://dashboard\.internal$")
    get_settings.cache_clear()
    try:
        pattern = re.compile(get_settings().CORS_ORIGIN_REGEX)
        assert pattern.match("https://dashboard.internal")
        assert not pattern.match("http://10.140.125.196:8080")
    finally:
        monkeypatch.delenv("CORS_ORIGIN_REGEX", raising=False)
        get_settings.cache_clear()


def test_preflight_from_a_lan_origin_is_answered(client):
    """The real check: a browser preflight from a LAN page must succeed."""
    resp = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://10.140.125.196:8080",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://10.140.125.196:8080"


def test_preflight_from_a_public_origin_gets_no_allow_header(client):
    resp = client.options(
        "/api/v1/health",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.headers.get("access-control-allow-origin") is None
