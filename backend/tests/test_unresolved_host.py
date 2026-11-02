"""A host that does not resolve is a finding, not a failed scan.

Typing a typo (`g0gle.com`) or an unregistered name used to end at the SSRF
guard's DNS lookup, which raised a refusal and the API answered `400`, so the
dashboard could only show "This host does not resolve — ... nothing was
fetched and no layer could be evaluated". That is the wrong product behaviour
twice over: the name itself is evidence (a lookalike of a brand), and "does not
resolve" is a *result* — an unregistered domain cannot be serving a credential
page — not a scanner error.

These tests pin both halves: the guard still refuses to fetch such a host, and
the endpoints carry on to a scored report.
"""
from __future__ import annotations

import socket

import pytest

from app.api.v1 import routes
from app.core.security import HostUnresolvedError, SSRFBlockedError, guard_url
from app.schemas.analysis import LayerEvidence


class _StubResult:
    """Stands in for AnalysisResult: the routes only call `model_dump`."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def model_dump(self, mode: str = "python") -> dict:  # noqa: ARG002
        return self._payload


def _nxdomain(monkeypatch) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def test_unresolved_host_is_its_own_kind_of_guard_refusal(monkeypatch):
    _nxdomain(monkeypatch)

    with pytest.raises(HostUnresolvedError) as excinfo:
        guard_url("https://g0gle.com/")

    assert excinfo.value.hostname == "g0gle.com"
    # It still derives from the guard error, so nothing is ever fetched.
    assert isinstance(excinfo.value, SSRFBlockedError)
    assert "g0gle.com" in str(excinfo.value)


def test_url_endpoint_scans_an_unresolved_domain_instead_of_rejecting_it(client, monkeypatch):
    _nxdomain(monkeypatch)
    calls: dict[str, object] = {}

    async def fake_run_analysis(input_type, target, **kwargs):  # noqa: ARG001
        calls.update({"target": target, **kwargs})
        return _StubResult({"analysis_id": "stub", "risk_level": "SAFE"})

    monkeypatch.setattr(routes, "run_analysis", fake_run_analysis)

    resp = client.post("/api/v1/analyze/url", json={"url": "g0gle.com", "fetch_page": True})

    assert resp.status_code == 200, resp.text
    # The report names a well-formed URL, not the bare string that was typed.
    assert calls["target"] == "https://g0gle.com"
    # The name is passed down so the pipeline can explain the missing page…
    assert calls["unresolved_host"] == "g0gle.com"
    # …and no fetch is attempted against a host with no address.
    assert calls["fetch_page_flag"] is False


def test_stream_endpoint_returns_a_verdict_for_an_unresolved_domain(client, monkeypatch):
    _nxdomain(monkeypatch)
    calls: dict[str, object] = {}

    async def fake_run_analysis(input_type, target, **kwargs):  # noqa: ARG001
        calls.update({"target": target, **kwargs})
        return _StubResult({"analysis_id": "stub", "threat_score": 8.0, "risk_level": "SAFE"})

    monkeypatch.setattr(routes, "run_analysis", fake_run_analysis)

    resp = client.post(
        "/api/v1/analyze/url/stream", json={"url": "https://g00gle.com/", "fetch_page": True}
    )

    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    assert calls["unresolved_host"] == "g00gle.com"
    assert '"type": "final"' in resp.text


def test_pipeline_reports_an_unresolved_page_as_the_finding(monkeypatch):
    """The report says what is true (no page can exist), not that a layer broke."""
    from app.services import pipeline

    async def fake_analyze_domain(hostname, timeout=None):  # noqa: ARG001
        return LayerEvidence(
            layer="domain",
            risk_score=5.0,
            indicators=[
                "No registration record for this domain (RDAP) and no DNS address — "
                "the name is unregistered or lapsed, so no page can be served from it"
            ],
            details={"registration_status": "not_registered", "dns": {"status": "unavailable"}},
        )

    monkeypatch.setattr(pipeline, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(pipeline, "save_analysis", lambda *a, **k: None)  # noqa: ARG005

    import asyncio

    result = asyncio.run(
        pipeline.run_analysis(
            "url",
            "https://g0gle-typo-unresolved.example/",
            url="https://g0gle-typo-unresolved.example/",
            fetch_page_flag=True,
            unresolved_host="g0gle-typo-unresolved.example",
            skip_llm=True,
        )
    )

    page = next(layer for layer in result.layer_evidence if layer.layer == "webpage")
    assert page.details["page_fetch_outcome"] == "unresolved"
    assert page.details["dns_unresolved"] is True
    assert page.unavailable is True
    # The reader is told why there is no page, in words, in the assessment.
    assert "does not resolve" in page.notes
    assert "webpage.unavailable" in result.degraded
    assert 0.0 <= result.threat_score <= 100.0
