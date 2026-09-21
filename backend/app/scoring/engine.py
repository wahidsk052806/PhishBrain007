"""Deterministic weighted scoring engine blended with a bounded LLM adjustment.

Score composition:

    layers  --(normalised weights)-->  layer score
    layer score --(PREFILTER_WEIGHT)-->+ trained prefilter score  = base score
    base score  --(bounded LLM adjustment)-->  final threat score

The prefilter only participates when a *trained* model produced its number. The
rule-based fallback is itself derived from the layer risks, so folding it back
in would count the same evidence twice and inflate every score.
"""
from __future__ import annotations

from app.core.config import get_settings
from app.schemas.analysis import LayerEvidence, LLMAssessment, RiskLevel

LLM_ADJUSTMENT_CLAMP = 15.0


def compute_layer_weighted_score(layers: list[LayerEvidence]) -> float:
    settings = get_settings()
    weights = settings.layer_weights
    available = [l for l in layers if not l.unavailable]
    if not available:
        return 0.0
    weight_sum = sum(weights.get(l.layer, 0.0) for l in available) or 1.0
    score = sum(weights.get(l.layer, 0.0) * l.risk_score for l in available) / weight_sum
    # A single strong, high-confidence layer must not be averaged down by layers
    # that were merely neutral or missing. Floor the composite at 90% of the
    # strongest available layer so a confirmed typosquat stays HIGH_RISK even
    # when the page fetch or RDAP lookups fail.
    max_layer = max((l.risk_score for l in available), default=0.0)
    score = max(score, max_layer * 0.9)
    return max(0.0, min(100.0, score))


def blend_prefilter_score(
    layer_score: float,
    prefilter_score: float | None,
    model_trained: bool,
    weight: float | None = None,
) -> tuple[float, bool, float]:
    """Blend a trained prefilter score into the layer score.

    Returns ``(score, blended, weight_used)``. The weight is clamped to
    [0, 0.5] so a misconfiguration cannot let the lexical-only model dominate
    the corroborated layer evidence, and the prefilter is ignored entirely when
    no trained model produced it (see the module docstring).
    """
    settings = get_settings()
    effective_weight = settings.PREFILTER_WEIGHT if weight is None else weight
    effective_weight = max(0.0, min(0.5, float(effective_weight)))

    if prefilter_score is None or not model_trained or effective_weight == 0.0:
        return layer_score, False, 0.0

    prefilter_score = max(0.0, min(100.0, float(prefilter_score)))
    blended = (1.0 - effective_weight) * layer_score + effective_weight * prefilter_score
    return max(0.0, min(100.0, blended)), True, effective_weight


def apply_llm_adjustment(base_score: float, llm: LLMAssessment | None) -> float:
    if llm is None:
        return base_score
    adjustment = max(-LLM_ADJUSTMENT_CLAMP, min(LLM_ADJUSTMENT_CLAMP, llm.score_adjustment))
    return max(0.0, min(100.0, base_score + adjustment))


def classify_risk(score: float) -> RiskLevel:
    settings = get_settings()
    if score < settings.SAFE_THRESHOLD:
        return RiskLevel.SAFE
    if score < settings.SUSPICIOUS_THRESHOLD:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.HIGH_RISK


def compute_confidence(layers: list[LayerEvidence], llm: LLMAssessment | None, degraded: list[str]) -> float:
    total_layers = len(layers) or 1
    available_layers = len([l for l in layers if not l.unavailable])
    coverage = available_layers / total_layers
    penalty = min(0.3, 0.05 * len(degraded))
    llm_conf = llm.confidence if llm else 0.5
    confidence = 0.5 * coverage + 0.3 * llm_conf + 0.2 * (1 - penalty)
    return round(max(0.0, min(1.0, confidence)), 3)


def build_explanation(
    layers: list[LayerEvidence],
    llm: LLMAssessment | None,
    risk_level: RiskLevel,
    prefilter_score: float | None = None,
    prefilter_weight: float = 0.0,
) -> str:
    parts = [f"Overall assessment: {risk_level.value}."]
    for layer in layers:
        if layer.unavailable:
            parts.append(f"{layer.layer.capitalize()} layer: unavailable ({layer.notes or 'no data'}).")
            continue
        if layer.indicators:
            parts.append(
                f"{layer.layer.capitalize()} layer (risk {layer.risk_score:.0f}/100): "
                + "; ".join(layer.indicators[:4])
                + "."
            )
        else:
            parts.append(f"{layer.layer.capitalize()} layer (risk {layer.risk_score:.0f}/100): no notable indicators.")
    if prefilter_score is not None and prefilter_weight > 0:
        parts.append(
            f"ML prefilter (CatBoost): {prefilter_score:.0f}/100, contributing "
            f"{prefilter_weight:.0%} of the base score."
        )
    if llm:
        parts.append(f"LLM assessment: {llm.reasoning_summary}")
    return " ".join(parts)


def recommend_action(risk_level: RiskLevel) -> str:
    return {
        RiskLevel.SAFE: "No action required. Continue with normal caution.",
        RiskLevel.SUSPICIOUS: "Proceed with caution: verify sender/domain through a separate trusted channel before interacting.",
        RiskLevel.HIGH_RISK: "Do not click links, enter credentials, or open attachments. Report and block this sender/site.",
    }[risk_level]


def score_analysis(
    layers: list[LayerEvidence],
    llm: LLMAssessment | None,
    degraded: list[str],
    prefilter_score: float | None = None,
    prefilter_model_trained: bool = False,
    prefilter_weight: float | None = None,
) -> dict:
    layer_score = compute_layer_weighted_score(layers)
    base_score, prefilter_blended, weight_used = blend_prefilter_score(
        layer_score, prefilter_score, prefilter_model_trained, prefilter_weight
    )
    final_score = apply_llm_adjustment(base_score, llm)
    risk_level = classify_risk(final_score)
    confidence = compute_confidence(layers, llm, degraded)
    explanation = build_explanation(
        layers, llm, risk_level,
        prefilter_score=prefilter_score if prefilter_blended else None,
        prefilter_weight=weight_used,
    )
    action = recommend_action(risk_level)

    indicators: list[str] = []
    for layer in layers:
        indicators.extend(layer.indicators)
    # Surface the learned signal only when it is actually flagging something —
    # otherwise every analysed URL would carry a "prefilter says 12/100" note.
    if prefilter_blended and prefilter_score is not None and prefilter_score >= 70:
        indicators.append(
            f"Machine-learning prefilter rated this URL {prefilter_score:.0f}/100 for phishing"
        )
    if llm:
        indicators.extend(llm.key_indicators)
    # de-duplicate while preserving order
    seen = set()
    unique_indicators = []
    for ind in indicators:
        if ind not in seen:
            seen.add(ind)
            unique_indicators.append(ind)

    return {
        "layer_score": round(layer_score, 2),
        "base_score": round(base_score, 2),
        "threat_score": round(final_score, 2),
        "risk_level": risk_level,
        "confidence": confidence,
        "explanation": explanation,
        "recommended_action": action,
        "indicators": unique_indicators,
        "prefilter_blended": prefilter_blended,
        "prefilter_weight": weight_used,
    }
