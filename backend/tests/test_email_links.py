"""Tests for destination evidence of links carried by an email.

Before this existed an email scan examined the message text and nothing else: no
page of its own to fetch, so no URL layer, no domain lookup and no ML pass. A
message that read innocuously and pointed one link at a fresh typosquat scored as
safe. These pin what the module scores, what it refuses to touch, and that it
never opens the link.
"""
from __future__ import annotations

import asyncio

import pytest

from app.analyzers.email.links import analyze_email_links, http_hrefs, split_link
from app.schemas.analysis import LayerEvidence
from app.scoring.engine import compute_layer_weighted_score


def test_split_link_keeps_the_pair_form_and_bare_hrefs_apart():
    assert split_link("Sign in|https://example.com/login") == (
        "Sign in",
        "https://example.com/login",
    )
    assert split_link("https://example.com/login") == ("", "https://example.com/login")


def test_only_http_links_are_considered():
    pairs = http_hrefs(
        [
            "mailto:help@example.com",
            "javascript:alert(1)",
            "Read|https://example.com/a",
            "Read again|https://example.com/a",
        ]
    )

    assert pairs == [("Read", "https://example.com/a")]


@pytest.mark.asyncio
async def test_no_link_means_no_link_evidence():
    assert await analyze_email_links([]) is None
    assert await analyze_email_links(["mailto:a@b.co"]) is None


@pytest.mark.asyncio
async def test_the_worst_destination_is_the_one_scored():
    """A malicious link must not be hidden behind benign ones in a newsletter."""
    link = await analyze_email_links(
        [
            "Home|https://joinsuperset.com/",
            "Settings|https://joinsuperset.com/settings",
            "Verify|https://paypa1-support.top/login",
        ],
        guard=False,
    )

    assert link is not None
    assert link["href"] == "https://paypa1-support.top/login"
    assert link["url_layer"].layer == "url"
    assert link["url_layer"].risk_score > 0
    assert link["url_layer"].details["links_in_message"] == 3
    assert link["url_layer"].details["link_destinations"][0]["href"].endswith("/login")


@pytest.mark.asyncio
async def test_link_evidence_is_corroborative_and_discloses_it_was_not_opened():
    link = await analyze_email_links(["Notice|https://paypa1-support.top/login"], guard=False)

    details = link["url_layer"].details
    assert details["source"] == "email_link"
    assert details["corroborative"] is True
    assert details["page_fetched"] is False
    assert "not opened" in (link["url_layer"].notes or "")


@pytest.mark.asyncio
async def test_an_internal_destination_is_never_looked_up():
    """Same SSRF rule as a typed target: the message must not probe the network.

    `127.0.0.1` is rejected by the guard without any DNS query, so `domain_host`
    is withheld and the reason is disclosed rather than silently dropped.
    """
    link = await analyze_email_links(
        ["Admin|http://127.0.0.1:8080/admin"], guard=True
    )

    assert link is not None
    assert link["domain_host"] is None
    assert "not looked up" in (link["url_layer"].notes or "")


def _layer(name: str, score: float, **details) -> LayerEvidence:
    return LayerEvidence(layer=name, risk_score=score, indicators=[], details=details)


def test_corroborative_link_evidence_raises_a_verdict():
    score = compute_layer_weighted_score(
        [_layer("email", 20.0), _layer("url", 90.0, corroborative=True)]
    )

    assert score == pytest.approx(81.0)


def test_corroborative_link_evidence_never_lowers_a_verdict():
    """A clean link is not evidence *for* the message, so it cannot average it down.

    Averaging used to mean a 30/100 "verify your account" email fell back under
    the SAFE ceiling as soon as one of its links pointed at a benign domain.
    """
    score = compute_layer_weighted_score(
        [_layer("email", 30.0), _layer("url", 0.0, corroborative=True)]
    )

    assert score == pytest.approx(30.0)


@pytest.mark.asyncio
async def test_the_end_to_end_email_path_scores_the_link_destination(monkeypatch):
    """Wiring: the pipeline turns link evidence into layers and a verdict."""
    from app.services import pipeline

    async def fake_links(links, guard=True):  # noqa: ARG001
        return {
            "url_layer": LayerEvidence(
                layer="url",
                risk_score=88.0,
                indicators=["Possible typosquat of 'paypal' (edit distance 1)"],
                details={"corroborative": True, "source": "email_link"},
            ),
            "href": "https://paypa1-support.top/login",
            "text": "Verify",
            "domain_host": None,
        }

    monkeypatch.setattr(pipeline, "analyze_email_links", fake_links)

    result = await pipeline.run_analysis(
        "email",
        "billing@acme-corp.com",
        email_fields={
            "sender": "billing@acme-corp.com",
            "subject": "Invoice 4471",
            "body": "Please review the attached invoice.",
            "links": ["Verify|https://paypa1-support.top/login"],
        },
        skip_llm=True,
    )

    layers = {layer.layer: layer for layer in result.layer_evidence}
    assert "url" in layers, "the link destination must reach the report"
    assert layers["url"].details["source"] == "email_link"
    assert result.threat_score >= 65, result.threat_score
    # The message itself is still the target of the record, not the link.
    assert result.target == "billing@acme-corp.com"
