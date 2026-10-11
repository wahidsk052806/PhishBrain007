"""Screenshot-evidence retention.

The stored screenshot is the most sensitive artefact the backend keeps, so it
is purged on its own, shorter clock than the analysis record: the verdict
(score, indicators, evidence) survives, the image does not. These tests pin
that contract — the aged sweep strips images only, and "clear all visual
evidence" strips them immediately while keeping the analyses.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.db.models import AnalysisRecord
from app.db.repository import (
    clear_visual_evidence,
    get_analysis,
    purge_visual_evidence,
)
from app.db.session import session_scope


def _result_with_screenshot(analysis_id: str, created_at: datetime) -> dict:
    return {
        "analysis_id": analysis_id,
        "created_at": created_at.isoformat(),
        "input_type": "url",
        "target": "https://example.com/login",
        "threat_score": 42.0,
        "risk_level": "SUSPICIOUS",
        "confidence": 0.5,
        "indicators": ["test indicator"],
        "layer_evidence": [
            {
                "layer": "webpage",
                "risk_score": 42.0,
                "indicators": ["page has a password field"],
                "details": {
                    "has_password_field": True,
                    # The image this policy targets.
                    "screenshot_data_url": "data:image/jpeg;base64,AAAA",
                },
            }
        ],
        "visual": {"status": "ok", "screenshot_data_url": "data:image/jpeg;base64,AAAA"},
        "explanation": "test",
        "recommended_action": "test",
        "soc_event": {},
        "latency_ms": 1.0,
    }


def _insert(analysis_id: str, created_at: datetime) -> None:
    with session_scope() as session:
        session.merge(
            AnalysisRecord(
                analysis_id=analysis_id,
                created_at=created_at,
                input_type="url",
                target="https://example.com/login",
                threat_score=42.0,
                risk_level="SUSPICIOUS",
                confidence=0.5,
                demo=False,
                result_json=_result_with_screenshot(analysis_id, created_at),
            )
        )


def _details(stored: dict) -> dict:
    return stored["layer_evidence"][0]["details"]


def test_aged_sweep_strips_only_the_screenshot_and_keeps_the_analysis():
    old_id = "test-visual-old"
    _insert(old_id, datetime.now(timezone.utc) - timedelta(days=2))

    changed = purge_visual_evidence(days=1)

    assert changed >= 1
    stored = get_analysis(old_id)
    assert stored is not None
    # The verdict survives…
    assert stored["threat_score"] == 42.0
    assert stored["indicators"] == ["test indicator"]
    assert stored["layer_evidence"][0]["indicators"] == ["page has a password field"]
    # …only the image is gone, from both places it can live.
    assert "screenshot_data_url" not in _details(stored)
    assert "screenshot_data_url" not in stored.get("visual", {})


def test_fresh_evidence_is_not_swept_before_its_retention_window():
    fresh_id = "test-visual-fresh"
    _insert(fresh_id, datetime.now(timezone.utc))

    purge_visual_evidence(days=7)

    stored = get_analysis(fresh_id)
    assert stored is not None
    assert _details(stored)["screenshot_data_url"].startswith("data:image/jpeg")


def test_clear_all_visual_evidence_strips_every_thumbnail_now():
    fresh_id = "test-visual-clear"
    _insert(fresh_id, datetime.now(timezone.utc))

    changed = clear_visual_evidence()

    assert changed >= 1
    stored = get_analysis(fresh_id)
    assert stored is not None
    assert "screenshot_data_url" not in _details(stored)
    # Clearing evidence must never delete the analysis itself.
    assert stored["analysis_id"] == fresh_id


def test_sweep_is_idempotent_and_reports_nothing_to_do():
    clean_id = "test-visual-clean"
    _insert(clean_id, datetime.now(timezone.utc))
    clear_visual_evidence()
    assert "screenshot_data_url" not in _details(get_analysis(clean_id) or {})

    # Nothing left to strip, so a second sweep changes no records.
    assert clear_visual_evidence() == 0


def test_visual_evidence_endpoints_expose_and_clear(client):
    policy = client.get("/api/v1/visual-evidence/policy")
    assert policy.status_code == 200
    body = policy.json()
    assert isinstance(body["retention_days"], int)
    assert "auto_purge_enabled" in body

    cleared = client.post("/api/v1/visual-evidence/clear")
    assert cleared.status_code == 200
    assert "cleared" in cleared.json()

    purged = client.post("/api/v1/visual-evidence/purge-expired")
    assert purged.status_code == 200
    assert "retention_days" in purged.json()


def test_config_reports_the_visual_retention_window(client):
    resp = client.get("/api/v1/config")
    assert resp.status_code == 200
    assert isinstance(resp.json()["visual_retention_days"], int)
