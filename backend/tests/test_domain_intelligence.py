"""Regression tests for domain intelligence (RDAP age, redirect handling).

The bug these cover: `rdap.org` is a *bootstrap* service. It never answers a
query itself — it 302-redirects to the authoritative registry RDAP server
(`rdap.publicinterestregistry.org` for `.org`, Verisign for `.com`, ...).
`_rdap_lookup` created its httpx client without `follow_redirects`, so every
single lookup observed a 302, fell into the `else` branch and was recorded as
`not_found`. `domain_age_days` was therefore *always* null and the domain layer
reported "Domain age could not be determined" for every target — including
domains registered in 1999.

A pure unit test on the date parser would not have caught that, so these tests
drive the real redirect chain through `httpx.MockTransport` while letting the
production code build the client itself. If the `follow_redirects` argument is
ever dropped again, the 302 is not followed and the tests fail.
"""
from __future__ import annotations

import httpx
import pytest

from app.analyzers.domain import intelligence
from app.analyzers.domain.intelligence import (
    _domain_age_days,
    _extract_registration_event,
    _rdap_lookup,
)


def _rdap_payload(created: str | None = "2001-01-13T00:12:14.754Z", action: str = "registration") -> dict:
    payload: dict = {"handle": "12345_DOMAIN_ORG", "ldhName": "WIKIPEDIA.ORG"}
    if created is not None:
        payload["events"] = [{"eventAction": action, "eventDate": created}]
    return payload


@pytest.fixture
def bootstrap_transport(monkeypatch):
    """Install a MockTransport that 302s like the real rdap.org bootstrap."""

    def install(payload: dict | None = None, redirect: bool = True, fail_status: int | None = None):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            target = "https://rdap.publicinterestregistry.org/rdap/domain/wikipedia.org"
            if request.url.host == "rdap.org":
                if not redirect:
                    return httpx.Response(fail_status or 200, json=payload or {})
                return httpx.Response(302, headers={"Location": target})
            if fail_status is not None:
                return httpx.Response(fail_status, json={})
            return httpx.Response(200, json=payload or {})

        transport = httpx.MockTransport(handler)
        real_client = httpx.AsyncClient

        def factory(**kwargs):
            # Preserve exactly what the production code asks for; the transport
            # only replaces the wire, not the client's redirect behaviour.
            return real_client(transport=transport, **kwargs)

        monkeypatch.setattr(intelligence.httpx, "AsyncClient", factory)
        return calls

    return install


async def test_rdap_follows_the_bootstrap_redirect_and_reads_the_registration_date(bootstrap_transport):
    calls = bootstrap_transport(_rdap_payload("2001-01-13T00:12:14.754Z"))

    result = await _rdap_lookup("wikipedia.org", timeout=5.0)

    assert result["status"] == "ok", "the 302 from rdap.org must be followed"
    assert result["created"] == "2001-01-13T00:12:14.754Z"
    # Both hops were actually requested: the bootstrap, then the registry.
    assert len(calls) == 2
    assert calls[0].startswith("https://rdap.org/")
    assert "publicinterestregistry.org" in calls[1]


async def test_rdap_does_not_treat_a_missing_registration_event_as_success(bootstrap_transport):
    bootstrap_transport(_rdap_payload(None))

    result = await _rdap_lookup("wikipedia.org", timeout=5.0)

    assert result["status"] == "ok"
    assert result["created"] is None


async def test_rdap_404_is_reported_as_not_found(bootstrap_transport):
    bootstrap_transport(redirect=False, fail_status=404)

    result = await _rdap_lookup("unregistered-example.invalid", timeout=5.0)

    assert result["status"] == "not_found"


async def test_rdap_5xx_is_reported_as_unavailable_not_not_found(bootstrap_transport):
    """A registry outage must not be read as 'this domain has no registration'."""
    bootstrap_transport(redirect=False, fail_status=503)

    result = await _rdap_lookup("wikipedia.org", timeout=5.0)

    assert result["status"] == "unavailable"


async def test_rdap_network_failure_is_unavailable(monkeypatch):
    def boom(**kwargs):
        raise httpx.ConnectError("dns exploded")

    monkeypatch.setattr(intelligence.httpx, "AsyncClient", boom)

    result = await _rdap_lookup("wikipedia.org", timeout=1.0)
    assert result["status"] == "unavailable"


@pytest.mark.parametrize(
    "action",
    ["registration", "registered", "created", "Domain Registration"],
)
def test_registration_event_accepts_the_spellings_registries_actually_use(action):
    data = {"events": [{"eventAction": action, "eventDate": "2019-05-05T00:00:00Z"}]}
    assert _extract_registration_event(data) == "2019-05-05T00:00:00Z"


def test_registration_event_prefers_registration_over_other_events():
    data = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2019-05-05T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ]
    }
    assert _extract_registration_event(data) == "2019-05-05T00:00:00Z"


def test_registration_event_handles_missing_events_key():
    assert _extract_registration_event({}) is None


def test_domain_age_days_parses_the_rdap_zulu_timestamp():
    assert _domain_age_days("2001-01-13T00:12:14.754Z") > 8000


def test_domain_age_days_returns_none_for_unparseable_input():
    assert _domain_age_days(None) is None
    assert _domain_age_days("not-a-date") is None
