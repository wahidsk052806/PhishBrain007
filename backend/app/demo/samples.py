"""Deterministic offline demo analyses.

Used whenever a request sets `demo=true`, or as a safety-net fallback if the
live pipeline cannot run at all (e.g. required deps unavailable). No network
calls are made from this module.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from app.schemas.analysis import (
    AnalysisResult,
    LayerEvidence,
    LLMAssessment,
    RiskLevel,
)
from app.soc.events import build_soc_event

_DEMO_TARGETS = {
    "url": {
        "high": "http://paypa1-secure-login.verify-account.xyz/signin.php?redirect=account",
        "safe": "https://www.paypal.com/signin",
    },
    "email": {
        "high": "security-alert@paypa1-support.com",
        "safe": "no-reply@paypal.com",
    },
    "page": {
        "high": "http://microsoft-office365-verify.top/login",
        "safe": "https://www.office.com",
    },
}


def _bucket_for(target: str) -> str:
    """Deterministically pick a risk bucket from the target string so the
    same demo input always yields the same demo output."""
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
    return "high" if int(digest[:2], 16) % 2 == 0 else "safe"


def _layers_for(input_type: str, bucket: str) -> list[LayerEvidence]:
    if bucket == "high":
        layers = [
            LayerEvidence(
                layer="url",
                risk_score=82.0,
                indicators=[
                    "Possible typosquat of 'paypal' (similarity 92%)",
                    "Suspicious keywords in path/query: signin, redirect",
                    "URL contains an open-redirect style parameter",
                ],
                details={"demo": True},
            ),
            LayerEvidence(
                layer="domain",
                risk_score=76.0,
                indicators=["Domain registered recently (6 days ago)", "Could not establish a valid TLS certificate"],
                details={"demo": True},
            ),
            LayerEvidence(
                layer="email",
                risk_score=70.0,
                indicators=["Urgency language detected: act now, immediately", "Reply-To domain differs from sender domain"],
                details={"demo": True},
            ),
            LayerEvidence(
                layer="webpage",
                risk_score=75.0,
                indicators=["Page requests credential-like fields: password", "Form submits to a different domain: paypa1-support.com"],
                details={"demo": True},
            ),
        ]
    else:
        layers = [
            LayerEvidence(layer="url", risk_score=4.0, indicators=[], details={"demo": True}),
            LayerEvidence(layer="domain", risk_score=6.0, indicators=[], details={"demo": True}),
            LayerEvidence(layer="email", risk_score=2.0, indicators=[], details={"demo": True}),
            LayerEvidence(layer="webpage", risk_score=3.0, indicators=[], details={"demo": True}),
        ]
    return [l for l in layers if l.layer == input_type or input_type == "all"] or layers


def build_demo_result(input_type: str, target: str) -> AnalysisResult:
    """Return a fully-formed, deterministic AnalysisResult for demo mode."""
    bucket = _bucket_for(target)
    layers = _layers_for(input_type, bucket)

    if bucket == "high":
        threat_score = 84.0
        risk_level = RiskLevel.HIGH_RISK
        confidence = 0.91
        llm = LLMAssessment(
            verdict=RiskLevel.HIGH_RISK,
            phishing_likelihood=0.93,
            confidence=0.9,
            key_indicators=["Brand impersonation", "Credential harvesting form", "Newly registered domain"],
            reasoning_summary="Demo mode: this sample combines brand impersonation, a newly registered domain, and a credential-harvesting form.",
            recommended_action="Do not click links, enter credentials, or open attachments. Report and block this sender/site.",
            score_adjustment=4.0,
        )
        explanation = (
            "Overall assessment: HIGH_RISK. This is a deterministic offline demo sample illustrating a "
            "typical phishing pattern: brand impersonation combined with a newly registered domain and a "
            "credential-harvesting form."
        )
        action = "Do not click links, enter credentials, or open attachments. Report and block this sender/site."
        indicators = [i for l in layers for i in l.indicators] + llm.key_indicators
    else:
        threat_score = 3.0
        risk_level = RiskLevel.SAFE
        confidence = 0.88
        llm = LLMAssessment(
            verdict=RiskLevel.SAFE,
            phishing_likelihood=0.02,
            confidence=0.85,
            key_indicators=[],
            reasoning_summary="Demo mode: this sample resembles a legitimate, well-established brand domain with no phishing indicators.",
            recommended_action="No action required.",
            score_adjustment=0.0,
        )
        explanation = "Overall assessment: SAFE. This deterministic offline demo sample shows no phishing indicators."
        action = "No action required. Continue with normal caution."
        indicators = []

    analysis_id = str(uuid.uuid4())
    soc_event = build_soc_event(
        analysis_id=analysis_id,
        target=target,
        threat_score=threat_score,
        risk_level=risk_level,
        indicators=indicators,
        degraded=["demo_mode"],
    )

    return AnalysisResult(
        analysis_id=analysis_id,
        created_at=datetime.now(timezone.utc),
        input_type=input_type,
        target=target,
        threat_score=threat_score,
        risk_level=risk_level,
        confidence=confidence,
        indicators=indicators,
        layer_evidence=layers,
        llm_assessment=llm,
        explanation=explanation,
        recommended_action=action,
        soc_event=soc_event,
        latency_ms=12.5,
        degraded=["demo_mode"],
        demo=True,
    )
