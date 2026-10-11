"""Tests for the streaming URL scan endpoint.

The stream exists so that a scan's deterministic layers can be reported while
the local LLM verdict is still being computed, so these tests pin the framing
(each phase is its own frame, in order) and the refusal path (a rejected target
is a plain 4xx, never a half-open stream).
"""
from __future__ import annotations

import json

from app.api.v1 import routes


class _StubResult:
    """Stands in for AnalysisResult: the route only calls `model_dump`."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def model_dump(self, mode: str = "python") -> dict:  # noqa: ARG002
        return self._payload


def _parse_sse(text: str) -> list[dict]:
    events: list[dict] = []
    for frame in text.split("\n\n"):
        for line in frame.splitlines():
            if line.startswith("data:"):
                events.append(json.loads(line[5:].strip()))
    return events


def test_stream_refuses_unsafe_scheme_without_opening_a_stream(client):
    resp = client.post("/api/v1/analyze/url/stream", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 400
    # A refusal must stay a normal error response: a 200 stream that never
    # carries a verdict is indistinguishable from a hang on the client.
    assert "text/event-stream" not in resp.headers.get("content-type", "")


def test_stream_demo_emits_started_then_final(client):
    resp = client.post(
        "/api/v1/analyze/url/stream", json={"url": "http://example.com", "demo": True}
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    events = _parse_sse(resp.text)
    assert events[0]["type"] == "started"
    assert events[-1]["type"] == "final"
    assert events[-1]["result"]["risk_level"]


def test_stream_reports_each_phase_before_the_verdict(client, monkeypatch):
    """Progress frames are ordered and precede the final result."""

    async def fake_run_analysis(input_type, target, **kwargs):  # noqa: ARG001
        on_event = kwargs.get("on_event")
        if on_event is not None:
            await on_event(
                {"type": "layer", "layer_evidence": [{"layer": "url", "risk_score": 12.0}]}
            )
            await on_event(
                {
                    "type": "provisional",
                    "provisional": True,
                    "threat_score": 12.0,
                    "risk_level": "SAFE",
                }
            )
        return _StubResult({"analysis_id": "stub", "threat_score": 12.0, "risk_level": "SAFE"})

    monkeypatch.setattr(routes, "run_analysis", fake_run_analysis)

    resp = client.post("/api/v1/analyze/url/stream", json={"url": "https://example.com"})
    assert resp.status_code == 200
    events = _parse_sse(resp.text)
    assert [e["type"] for e in events] == ["started", "layer", "provisional", "final"]
    assert events[-1]["result"]["analysis_id"] == "stub"


def test_stream_surfaces_a_pipeline_failure_as_an_error_frame(client, monkeypatch):
    async def boom(*args, **kwargs):  # noqa: ARG001
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(routes, "run_analysis", boom)

    resp = client.post("/api/v1/analyze/url/stream", json={"url": "https://example.com"})
    assert resp.status_code == 200
    events = _parse_sse(resp.text)
    assert events[-1]["type"] == "error"
    # The reason is logged, never leaked to the client.
    assert "exploded" not in json.dumps(events)
