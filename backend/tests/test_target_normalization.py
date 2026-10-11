"""Typing a hostname is not an error.

Two defects motivated these tests:

1. Typing `hianime.to` in the dashboard sent the string to the backend
   verbatim. The SSRF guard read an empty scheme and refused the whole request
   with `Scheme '' is not allowed`, so the most natural way to name a site was
   the one way that could never be scanned. Nothing normalised the input.

2. When the page fetch failed, the pipeline still ran the Playwright
   screenshot. On an unreachable host that rendered the browser's own error
   page, cost ~26s of CPU, and still reported "visual: unavailable" — while the
   report said only `webpage.fetch_failed`, with no hint that the host had
   simply never answered.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.security import (
    SSRFBlockedError,
    guard_user_target,
    normalize_url_input,
)
from app.schemas.analysis import LayerEvidence
from app.services import pipeline as pipeline_module

# --------------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("hianime.to", "https://hianime.to"),
        ("  hianime.to  ", "https://hianime.to"),
        ("example.com/login?next=/home", "https://example.com/login?next=/home"),
        ("www.wikipedia.org", "https://www.wikipedia.org"),
        ("sub.domain.co.uk:8443/path", "https://sub.domain.co.uk:8443/path"),
        # Already absolute: untouched.
        ("https://example.com/x", "https://example.com/x"),
        ("http://example.com/x", "http://example.com/x"),
        ("HTTPS://EXAMPLE.COM/X", "https://EXAMPLE.COM/X"),
        # Protocol-relative and single-slash typos.
        ("//example.com/x", "https://example.com/x"),
        ("https:/example.com", "https://example.com"),
        ("http:example.com", "http://example.com"),
        # Quotes / angle brackets from a paste.
        ('"https://example.com"', "https://example.com"),
        ("<https://example.com>", "https://example.com"),
        # A pasted sentence: the first token is the target.
        ("scan https://example.com now", "https://example.com"),
        # Non-web schemes survive so the guard can name them.
        ("javascript:alert(1)", "javascript:alert(1)"),
        ("mailto:billing@example.com", "mailto:billing@example.com"),
        ("file:///etc/passwd", "file:///etc/passwd"),
        ("", ""),
        ("   ", ""),
    ],
)
def test_normalize_url_input(typed, expected):
    assert normalize_url_input(typed) == expected


def test_guard_user_target_returns_the_url_that_was_actually_validated():
    url, resolved = guard_user_target("example.com")

    assert url == "https://example.com"
    assert resolved.hostname == "example.com"


def test_guard_user_target_still_blocks_a_non_web_scheme():
    with pytest.raises(SSRFBlockedError) as excinfo:
        guard_user_target("javascript:alert(1)")

    assert "javascript" in str(excinfo.value)


def test_guard_user_target_still_blocks_internal_hosts():
    with pytest.raises(SSRFBlockedError):
        guard_user_target("localhost:8000/admin")


def test_guard_user_target_rejects_an_empty_target():
    with pytest.raises(SSRFBlockedError):
        guard_user_target("   ")


# --------------------------------------------------------------------------- #
# API boundary
# --------------------------------------------------------------------------- #


def test_analyze_url_accepts_a_bare_hostname(client: TestClient, monkeypatch):
    """The reported bug: `hianime.to` must reach the pipeline, not a 400."""
    seen: dict = {}

    async def fake_run_analysis(input_type, target, **kwargs):
        seen["input_type"] = input_type
        seen["target"] = target
        seen["url"] = kwargs.get("url")
        return {"stub": True}

    monkeypatch.setattr(pipeline_module, "run_analysis", fake_run_analysis)
    import app.api.v1.routes as routes

    monkeypatch.setattr(routes, "run_analysis", fake_run_analysis)

    resp = client.post("/api/v1/analyze/url", json={"url": "example.com"})

    assert resp.status_code == 200, resp.text
    assert seen["target"] == "https://example.com"
    assert seen["url"] == "https://example.com"


def test_analyze_url_error_names_the_scheme_it_refused(client: TestClient):
    resp = client.post("/api/v1/analyze/url", json={"url": "javascript:alert(1)"})

    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "javascript" in detail, "the refusal must name the scheme it rejected"
    assert "http" in detail, "and say what is accepted instead"


# --------------------------------------------------------------------------- #
# pipeline: a failed fetch must not pay for a screenshot
# --------------------------------------------------------------------------- #


def _stub_layers(monkeypatch, *, fetch_result, visual_recorder):
    async def fake_fetch_page(url, timeout, max_bytes):
        return fetch_result

    async def fake_domain(hostname, timeout):
        return LayerEvidence(layer="domain", risk_score=0.0, indicators=[], details={})

    async def fake_visual(*args, **kwargs):
        visual_recorder.append(True)
        return {"status": "unavailable", "reason": "stubbed"}

    monkeypatch.setattr(pipeline_module, "fetch_page", fake_fetch_page)
    monkeypatch.setattr(pipeline_module, "analyze_domain", fake_domain)
    monkeypatch.setattr(pipeline_module, "analyze_visual", fake_visual)
    monkeypatch.setattr(pipeline_module, "save_analysis", lambda *a, **k: None)


@pytest.mark.asyncio
async def test_failed_fetch_skips_the_screenshot_and_explains_why(monkeypatch):
    visual_calls: list[bool] = []
    _stub_layers(
        monkeypatch,
        fetch_result=(None, ["webpage.fetch_failed:ConnectTimeout"]),
        visual_recorder=visual_calls,
    )

    result = await pipeline_module.run_analysis(
        "url",
        "https://unreachable-host-for-test.invalid/",
        url="https://unreachable-host-for-test.invalid/",
        fetch_page_flag=True,
        skip_llm=True,
        raw_input={"url": "https://unreachable-host-for-test.invalid/"},
    )

    assert visual_calls == [], "no screenshot may be captured without a page to render"
    webpage = next(layer for layer in result.layer_evidence if layer.layer == "webpage")
    assert webpage.unavailable is True
    assert "ConnectTimeout" not in str(webpage.details.get("page_fetch_failed"))
    assert "timed out" in webpage.details["page_fetch_failed"]
    indicators = webpage.details["visual_indicators"]
    assert any("Not attempted" in item for item in indicators)
    assert any("timed out" in item for item in indicators)


@pytest.mark.asyncio
async def test_successful_fetch_still_runs_the_visual_comparison(monkeypatch):
    visual_calls: list[bool] = []
    _stub_layers(
        monkeypatch,
        fetch_result=("<html><body>hello</body></html>", []),
        visual_recorder=visual_calls,
    )

    await pipeline_module.run_analysis(
        "url",
        "https://reachable-host-for-test.invalid/",
        url="https://reachable-host-for-test.invalid/",
        fetch_page_flag=True,
        skip_llm=True,
        raw_input={"url": "https://reachable-host-for-test.invalid/"},
    )

    assert visual_calls == [True], "a page that was read must still be compared visually"


@pytest.mark.asyncio
async def test_pipeline_normalises_a_scheme_less_url_itself(monkeypatch):
    """The pipeline must not depend on its callers for normalisation."""
    called: dict = {}

    async def fake_fetch_page(url, timeout, max_bytes):
        called["url"] = url
        return ("<html></html>", [])

    async def fake_domain(hostname, timeout):
        return LayerEvidence(layer="domain", risk_score=0.0, indicators=[], details={})

    monkeypatch.setattr(pipeline_module, "fetch_page", fake_fetch_page)
    monkeypatch.setattr(pipeline_module, "analyze_domain", fake_domain)
    monkeypatch.setattr(pipeline_module, "save_analysis", lambda *a, **k: None)
    monkeypatch.setattr(
        pipeline_module,
        "analyze_visual",
        lambda *a, **k: _async({"status": "unavailable", "reason": "stubbed"}),
    )

    result = await pipeline_module.run_analysis(
        "url",
        "bare-host-for-test.invalid",
        url="bare-host-for-test.invalid",
        fetch_page_flag=True,
        skip_llm=True,
        raw_input={"url": "bare-host-for-test.invalid"},
    )

    assert called["url"] == "https://bare-host-for-test.invalid"
    assert result.target == "https://bare-host-for-test.invalid"


def _async(value):
    async def _inner():
        return value

    return _inner()
