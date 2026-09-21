"""Tests for the page fetch, the LLM page digest and the `use_llm` fast path.

Three bugs motivated these:

1. `fetch_page` never looked at the HTTP status. A 403 body is the server's
   refusal notice, not the page — but it was parsed as page content, so the
   webpage layer reported "no forms, no credentials, no external resources"
   for a page it had never read. Wikipedia alone answers 403 to the library
   default User-Agent with a 126-byte notice, which was silently treated as a
   clean page.

2. There was no User-Agent at all, which is what caused (1) on most of the web.

3. `use_llm` was not even a request field: callers could not skip the local LLM,
   which is by far the slowest stage of a scan.
"""
from __future__ import annotations

import httpx
import pytest

from app.analyzers.webpage import analyzer
from app.analyzers.webpage.analyzer import build_llm_page_digest, fetch_page

_WIKI_STUB = b"Please set a user-agent and respect our robot policy."


@pytest.fixture
def stub_transport(monkeypatch):
    """Serve canned responses and record the headers the fetch actually sent."""

    def install(response: httpx.Response):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["headers"] = dict(request.headers)
            seen["url"] = str(request.url)
            return response

        real_client = httpx.AsyncClient

        def factory(**kwargs):
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(analyzer.httpx, "AsyncClient", factory)
        monkeypatch.setattr(analyzer, "guard_url", lambda url: None)
        return seen

    return install


# --------------------------------------------------------------------------- #
# fetch_page status handling
# --------------------------------------------------------------------------- #

async def test_a_403_is_reported_as_a_failure_not_parsed_as_the_page(stub_transport):
    stub_transport(httpx.Response(403, content=_WIKI_STUB))

    html, degraded = await fetch_page("https://en.wikipedia.org/wiki/Phishing", 5, 1_000_000)

    assert html is None, "a refusal body must never be analysed as page content"
    assert "webpage.http_403" in degraded


async def test_a_404_is_reported_as_a_failure(stub_transport):
    stub_transport(httpx.Response(404, content=b"<html>not found</html>"))

    html, degraded = await fetch_page("https://example.com/missing", 5, 1_000_000)

    assert html is None
    assert "webpage.http_404" in degraded


async def test_a_500_is_reported_as_a_failure(stub_transport):
    stub_transport(httpx.Response(500, content=b"<html>boom</html>"))

    html, degraded = await fetch_page("https://example.com/", 5, 1_000_000)

    assert html is None
    assert "webpage.http_500" in degraded


async def test_a_200_body_is_returned(stub_transport):
    stub_transport(httpx.Response(200, content=b"<html><title>ok</title></html>"))

    html, degraded = await fetch_page("https://example.com/", 5, 1_000_000)

    assert html is not None and "ok" in html
    assert degraded == []


async def test_the_fetch_sends_a_browser_user_agent_not_the_library_default(stub_transport):
    seen = stub_transport(httpx.Response(200, content=b"<html></html>"))

    await fetch_page("https://example.com/", 5, 1_000_000)

    agent = seen["headers"].get("user-agent", "")
    assert "python-httpx" not in agent.lower()
    assert agent.startswith("Mozilla/5.0")
    assert "accept-language" in {k.lower() for k in seen["headers"]}


# --------------------------------------------------------------------------- #
# LLM page digest
# --------------------------------------------------------------------------- #

_PHISH_HTML = """
<html><head><title>Sign in to PayPal</title></head><body>
  <form action="https://collect.evil-domain.top/post">
    <label>Email</label><input type="email" name="email">
    <label>Password</label><input type="password" name="password">
    <input type="hidden" name="csrf">
    <input type="checkbox" name="remember">
    <button type="submit">Sign in to PayPal</button>
  </form>
  <img src="/assets/paypal-logo.png" alt="PayPal">
  <iframe src="https://tracker.example/px"></iframe>
  <meta http-equiv="refresh" content="3">
  <script>var x=1;</script>
</body></html>
"""


def test_digest_surfaces_the_security_relevant_structure():
    digest = build_llm_page_digest(_PHISH_HTML, "https://paypa1-secure.top/login")

    assert "title: Sign in to PayPal" in digest
    assert "forms: 1" in digest
    assert "[external]" in digest, "a form posting to another domain is the key signal"
    assert "password" in digest
    assert "brands_mentioned: paypal" in digest
    assert "iframes: 1" in digest
    assert "meta_refresh: yes" in digest


def test_digest_skips_non_credential_inputs_that_used_to_eat_the_budget():
    digest = build_llm_page_digest(_PHISH_HTML, "https://paypa1-secure.top/login")

    assert "checkbox" not in digest
    assert "hidden" not in digest


def test_digest_is_bounded_by_max_chars():
    big = "<html><body>" + ("<p>filler text here</p>" * 5000) + "</body></html>"

    digest = build_llm_page_digest(big, "https://example.com/", max_chars=800)

    assert len(digest) <= 800


def test_digest_handles_empty_and_junk_input():
    assert build_llm_page_digest("", "https://example.com/") == ""
    assert build_llm_page_digest("<html></html>", "https://example.com/").startswith("page_url:")


def test_digest_marks_a_same_domain_form_as_internal():
    html = '<html><body><form action="/session"><input type="password" name="p"></form></body></html>'

    digest = build_llm_page_digest(html, "https://github.com/login")

    assert "/session" in digest
    assert "[external]" not in digest


# --------------------------------------------------------------------------- #
# use_llm request field
# --------------------------------------------------------------------------- #

def test_use_llm_defaults_to_true_on_both_request_models():
    from app.schemas.analysis import PageAnalyzeRequest, URLAnalyzeRequest

    assert URLAnalyzeRequest(url="https://example.com").use_llm is True
    assert PageAnalyzeRequest(url="https://example.com").use_llm is True


def test_use_llm_false_is_accepted_and_survives_model_validation():
    from app.schemas.analysis import URLAnalyzeRequest

    payload = URLAnalyzeRequest(url="https://example.com", use_llm=False)

    assert payload.use_llm is False
    assert payload.model_dump()["use_llm"] is False


def test_timings_field_is_present_on_results():
    from app.schemas.analysis import AnalysisResult

    assert "timings" in AnalysisResult.model_fields
