"""Build SOC (Security Operations Center) events from analysis results."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.analysis import PrefilterEvidence, RiskLevel, SOCEvent

_SEVERITY_MAP = {
    RiskLevel.SAFE: "low",
    RiskLevel.SUSPICIOUS: "medium",
    RiskLevel.HIGH_RISK: "high",
}


def build_soc_event(
    analysis_id: str,
    target: str,
    threat_score: float,
    risk_level: RiskLevel,
    indicators: list[str],
    degraded: list[str] | None = None,
    prefilter: PrefilterEvidence | None = None,
) -> SOCEvent:
    """Construct a SOCEvent from analysis results, suitable for downstream
    SIEM/SOAR ingestion.

    The ML prefilter's contribution travels with the event: a downstream
    consumer needs to know whether an ML model moved the score, how much, and
    at what weight, otherwise it cannot tell a rule-derived score apart from
    one the learned signal pushed up.
    """
    return SOCEvent(
        event_id=str(uuid.uuid4()),
        analysis_id=analysis_id,
        timestamp=datetime.now(timezone.utc),
        source="phishbrain",
        event_type="phishing_analysis",
        severity=_SEVERITY_MAP.get(risk_level, "medium"),
        threat_score=threat_score,
        risk_level=risk_level,
        indicators=indicators[:20],
        target_identifier=target,
        degraded=degraded or [],
        prefilter=prefilter,
    )
