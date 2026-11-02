"""Pydantic request/response models for the analysis API."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"


class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")
    dom_summary: Optional[str] = Field(default=None, description="Optional caller-supplied DOM text summary")
    fetch_page: bool = Field(default=False, description="Whether the backend should fetch the page itself")
    # The local LLM verdict is the slowest part of a scan on CPU. Callers that
    # need a fast triage result can turn it off and get the deterministic
    # layers (URL, domain, webpage, prefilter) on their own.
    use_llm: bool = Field(default=True, description="Run the local LLM assessment step")
    demo: bool = Field(default=False)


class EmailAnalyzeRequest(BaseModel):
    sender: str = Field(..., description="From address")
    reply_to: Optional[str] = Field(default=None)
    display_name: Optional[str] = Field(default=None)
    subject: str = Field(default="")
    body: str = Field(default="")
    raw_headers: Optional[str] = Field(default=None, description="Raw email headers, if available")
    links: list[str] = Field(default_factory=list)
    has_attachments: bool = Field(default=False)
    # Set by the browser extension when the sender quoted an earlier message and
    # only the new part was sent for scoring. Recorded in the evidence so a
    # report never silently scores less than the reader can see.
    has_quoted_content: bool = Field(default=False)
    # The same fast path the URL and page endpoints expose. A message can be
    # triaged on its deterministic layers alone; without this field the flag was
    # silently dropped and every email scan waited out the model.
    use_llm: bool = Field(default=True, description="Run the local LLM assessment step")
    demo: bool = Field(default=False)


class PageAnalyzeRequest(BaseModel):
    url: str
    html: Optional[str] = Field(default=None, description="Caller-supplied HTML source")
    dom_summary: Optional[str] = Field(default=None)
    fetch_page: bool = Field(default=False)
    screenshot_base64: Optional[str] = Field(default=None)
    use_llm: bool = Field(default=True, description="Run the local LLM assessment step")
    demo: bool = Field(default=False)


class LayerEvidence(BaseModel):
    layer: str
    risk_score: float = Field(..., ge=0, le=100)
    indicators: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    unavailable: bool = Field(default=False)
    notes: Optional[str] = None


class LLMAssessment(BaseModel):
    """Exact structured JSON contract expected from the LLM."""

    model_config = ConfigDict(extra="ignore")

    verdict: RiskLevel
    phishing_likelihood: float = Field(..., ge=0, le=1)
    confidence: float = Field(..., ge=0, le=1)
    key_indicators: list[str] = Field(default_factory=list)
    reasoning_summary: str = Field(default="")
    recommended_action: str = Field(default="")
    score_adjustment: float = Field(default=0.0, ge=-15, le=15)
    # Which local model produced this. None means the deterministic fallback
    # ran, so the dashboard can show "unavailable" honestly instead of naming a
    # model that never saw the input.
    model: Optional[str] = None


class SOCEvent(BaseModel):
    event_id: str
    analysis_id: str
    timestamp: datetime
    source: str = "phishbrain"
    event_type: str = "phishing_analysis"
    severity: str
    threat_score: float
    risk_level: RiskLevel
    indicators: list[str]
    target_identifier: str
    degraded: list[str] = Field(default_factory=list)
    # Machine-learning contribution to `threat_score`, so a SIEM/SOAR consumer
    # can see whether (and with what weight) the CatBoost prefilter moved the
    # score, without having to re-derive it from the layer evidence.
    prefilter: Optional["PrefilterEvidence"] = None


class PrefilterEvidence(BaseModel):
    """Contribution of the ML prefilter to the final score.

    Exposed so a score can be audited: `blended` is False whenever the
    deterministic fallback was used (or no URL was available), in which case
    `score` contributed nothing to `threat_score`.
    """

    # `model_trained` matches the dashboard/extension contract but collides
    # with pydantic's reserved `model_` namespace, so opt out of that guard.
    model_config = ConfigDict(protected_namespaces=())

    model_trained: bool
    score: Optional[float] = Field(default=None, ge=0, le=100)
    method: str = ""
    weight: float = Field(default=0.0, ge=0, le=0.5)
    blended: bool = False
    note: str = ""
    # Score the multi-layer engine produced before the prefilter was blended in,
    # so the contribution (`score` at `weight`) can be read off directly.
    layer_score: Optional[float] = Field(default=None, ge=0, le=100)
    # The model's own class-weighted probability, before calibration. Kept so a
    # reviewer can see exactly how much the calibration moved the number.
    raw_score: Optional[float] = Field(default=None, ge=0, le=100)
    calibrated: bool = False
    # What the deployed artifact claims about itself: the gate tier it cleared
    # (see ml/evaluation/gate.py) and where its metrics were measured. A
    # prefilter that never passed its own bar must not be presented as validated.
    gate_tier: Optional[str] = None
    gate_passed: Optional[bool] = None
    split: Optional[str] = None
    trained_at: Optional[str] = None
    # The operating point the model was validated at (probability space). A
    # score below it is not "suspicious" no matter how large the number looks.
    decision_threshold: Optional[float] = Field(default=None, ge=0, le=1)
    score_above_threshold: Optional[bool] = None


SOCEvent.model_rebuild()


class AnalysisResult(BaseModel):
    analysis_id: str
    created_at: datetime
    input_type: str
    target: str
    threat_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(..., ge=0, le=1)
    indicators: list[str] = Field(default_factory=list)
    layer_evidence: list[LayerEvidence] = Field(default_factory=list)
    prefilter: Optional[PrefilterEvidence] = None
    llm_assessment: Optional[LLMAssessment] = None
    explanation: str
    recommended_action: str
    soc_event: SOCEvent
    latency_ms: float
    # Per-phase wall-clock milliseconds. A single `latency_ms` number hid where
    # a scan actually spent its time (page fetch vs domain lookups vs the
    # screenshot vs local LLM inference), which made "the scan is slow"
    # impossible to act on without profiling the process by hand.
    timings: dict[str, float] = Field(default_factory=dict)
    degraded: list[str] = Field(default_factory=list)
    demo: bool = Field(default=False)


class FeedbackRequest(BaseModel):
    analysis_id: str
    correct: bool
    comment: Optional[str] = None


class HealthStatus(BaseModel):
    status: str
    ollama: str
    database: str
    cache: str
    app_env: str
    # Which implementation is actually in use. "database: ok" on SQLite and
    # "database: ok" on Postgres looked identical while being very different
    # deployments, and the same was true of the in-memory cache versus Valkey.
    database_backend: str = Field(default="unknown")
    cache_backend: str = Field(default="unknown")


class ConfigResponse(BaseModel):
    app_env: str
    llm_provider: str
    ollama_model: str
    weights: dict[str, float]
    safe_threshold: int
    suspicious_threshold: int
    brands: list[str]
    allowed_schemes: list[str]
    store_raw_email: bool
    retention_days: int
    # How long stored screenshot evidence is kept before the automatic sweep
    # drops it — separate from (and normally shorter than) `retention_days`,
    # because the image of a visited page is more sensitive than its verdict.
    visual_retention_days: int
