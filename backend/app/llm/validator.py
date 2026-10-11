"""Validate and sanitize raw LLM output into the strict LLMAssessment schema.

The rules that matter here are about *representation*, not meaning. A small
local model (llama3.2 on CPU) answers the same question in whichever vocabulary
it prefers: `"verdict": "Phishing"` instead of `"HIGH_RISK"`, `80` instead of
`0.8`, a bare string where a list is expected. All of those carry the verdict
the pipeline asked for.

Treating them as malformed used to cost a second full inference (~30s of CPU on
this machine) and, when the retry failed the same way, replaced the model's
actual reasoning with the rules-only fallback — so the strictest possible
parsing produced both the slowest and the least informative scans. Values are
therefore normalised into the schema instead of rejected, while genuinely
unparseable output still falls through to `None`.
"""
from __future__ import annotations

import json
import re

from pydantic import ValidationError

from app.schemas.analysis import LLMAssessment, RiskLevel

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

# Every spelling of a verdict these models actually emit, mapped onto the enum.
VERDICT_SYNONYMS: dict[str, RiskLevel] = {
    "high_risk": RiskLevel.HIGH_RISK,
    "highrisk": RiskLevel.HIGH_RISK,
    "high risk": RiskLevel.HIGH_RISK,
    "high-risk": RiskLevel.HIGH_RISK,
    "phishing": RiskLevel.HIGH_RISK,
    "phish": RiskLevel.HIGH_RISK,
    "malicious": RiskLevel.HIGH_RISK,
    "scam": RiskLevel.HIGH_RISK,
    "fraud": RiskLevel.HIGH_RISK,
    "malware": RiskLevel.HIGH_RISK,
    "danger": RiskLevel.HIGH_RISK,
    "dangerous": RiskLevel.HIGH_RISK,
    "critical": RiskLevel.HIGH_RISK,
    "unsafe": RiskLevel.HIGH_RISK,
    "suspicious": RiskLevel.SUSPICIOUS,
    "suspicion": RiskLevel.SUSPICIOUS,
    "sus": RiskLevel.SUSPICIOUS,
    "likely_phishing": RiskLevel.SUSPICIOUS,
    "likely phishing": RiskLevel.SUSPICIOUS,
    "possibly_phishing": RiskLevel.SUSPICIOUS,
    "possible_phishing": RiskLevel.SUSPICIOUS,
    "possible phishing": RiskLevel.SUSPICIOUS,
    "medium": RiskLevel.SUSPICIOUS,
    "moderate": RiskLevel.SUSPICIOUS,
    "warning": RiskLevel.SUSPICIOUS,
    "unknown": RiskLevel.SUSPICIOUS,
    "safe": RiskLevel.SAFE,
    "clean": RiskLevel.SAFE,
    "benign": RiskLevel.SAFE,
    "legitimate": RiskLevel.SAFE,
    "legit": RiskLevel.SAFE,
    "low": RiskLevel.SAFE,
    "low_risk": RiskLevel.SAFE,
    "low risk": RiskLevel.SAFE,
    "none": RiskLevel.SAFE,
    "no risk": RiskLevel.SAFE,
    "ok": RiskLevel.SAFE,
    "trusted": RiskLevel.SAFE,
}

# Fallbacks used only when the model omitted a required numeric field but did
# state a verdict. They are deliberately neutral/consistent rather than
# flattering: the verdict stays exactly as the model gave it.
_LIKELIHOOD_FOR_VERDICT = {
    RiskLevel.SAFE: 0.1,
    RiskLevel.SUSPICIOUS: 0.5,
    RiskLevel.HIGH_RISK: 0.9,
}
_NEUTRAL_CONFIDENCE = 0.5


def strip_chain_of_thought(raw: str) -> str:
    """Remove any <think> blocks so chain-of-thought never surfaces."""
    return THINK_BLOCK_RE.sub("", raw or "").strip()


def extract_json_object(raw: str) -> str | None:
    cleaned = strip_chain_of_thought(raw)
    match = JSON_OBJECT_RE.search(cleaned)
    return match.group(0) if match else None


def _as_ratio(value: object) -> float | None:
    """Coerce a model-supplied score into 0-1.

    Accepts 0.8 (already a ratio), 80 (a percentage — a very common answer), and
    numeric strings. Anything outside 0-100 is clamped rather than rejected.
    """
    if isinstance(value, bool) or value is None:
        return None
    number: float | None = None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if match:
            try:
                number = float(match.group(0))
            except ValueError:
                number = None
    if number is None:
        return None
    if number > 1.0:
        number = number / 100.0
    return round(min(1.0, max(0.0, number)), 3)


def _as_verdict(value: object) -> RiskLevel | None:
    if isinstance(value, RiskLevel):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if text in VERDICT_SYNONYMS:
        return VERDICT_SYNONYMS[text]
    # "SUSPICIOUS_PHISHING" / "high-risk phishing" and similar compounds: match
    # on the strongest signal present rather than on exact equality.
    for token, level in VERDICT_SYNONYMS.items():
        if re.search(rf"(^|[^a-z]){re.escape(token)}([^a-z]|$)", text):
            return level
    return None


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        return [str(v).strip() for v in value.values() if str(v).strip()]
    if isinstance(value, (list, tuple)):
        items = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                items.append(text)
        return items
    return [str(value)]


def _as_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value if v)
    return str(value)


def _as_adjustment(value: object) -> float:
    if isinstance(value, bool) or value is None:
        return 0.0
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return max(-15.0, min(15.0, number))


def _normalize_payload(data: dict) -> dict:
    """Map a model's own vocabulary onto the strict schema."""
    verdict = _as_verdict(
        data.get("verdict") if "verdict" in data else data.get("risk_level") or data.get("classification")
    )
    likelihood = _as_ratio(
        data.get("phishing_likelihood")
        if "phishing_likelihood" in data
        else data.get("likelihood", data.get("phishing_score", data.get("score")))
    )
    confidence = _as_ratio(data.get("confidence", data.get("certainty")))

    # One of the two carries the answer; derive the other if it is missing.
    if likelihood is not None:
        # When the model's words and its number disagree, the number wins: a
        # synonym can be hedged or negated ("low risk of phishing"), a number
        # cannot.
        verdict = (
            RiskLevel.HIGH_RISK
            if likelihood >= 0.65
            else RiskLevel.SUSPICIOUS
            if likelihood >= 0.30
            else RiskLevel.SAFE
        )
    elif verdict is not None:
        likelihood = _LIKELIHOOD_FOR_VERDICT[verdict]
    else:
        # No interpretable verdict at all: let the caller retry / fall back.
        return {}

    return {
        "verdict": verdict,
        "phishing_likelihood": likelihood,
        "confidence": _NEUTRAL_CONFIDENCE if confidence is None else confidence,
        "key_indicators": _as_str_list(
            data.get("key_indicators", data.get("indicators", data.get("red_flags")))
        )[:8],
        "reasoning_summary": _as_text(
            data.get("reasoning_summary", data.get("reasoning", data.get("explanation")))
        ),
        "recommended_action": _as_text(
            data.get("recommended_action", data.get("recommendation", data.get("action")))
        ),
        "score_adjustment": _as_adjustment(data.get("score_adjustment", data.get("adjustment"))),
    }


def validate_llm_output(raw: str) -> LLMAssessment | None:
    """Return a validated LLMAssessment, or None if the output could not be
    parsed/validated (caller should retry once, then fall back)."""
    json_str = extract_json_object(raw)
    if not json_str:
        return None
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    normalized = _normalize_payload(data)
    if not normalized:
        return None
    try:
        return LLMAssessment.model_validate(normalized)
    except ValidationError:
        return None
