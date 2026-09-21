from app.schemas.analysis import LayerEvidence, RiskLevel
from app.scoring.engine import (
    blend_prefilter_score,
    classify_risk,
    compute_layer_weighted_score,
    score_analysis,
)


def test_classify_thresholds():
    assert classify_risk(0) == RiskLevel.SAFE
    assert classify_risk(50) == RiskLevel.SUSPICIOUS
    assert classify_risk(90) == RiskLevel.HIGH_RISK


def test_weighted_score_ignores_unavailable_layers():
    layers = [
        LayerEvidence(layer="url", risk_score=100, indicators=[], details={}),
        LayerEvidence(layer="domain", risk_score=0, indicators=[], details={}, unavailable=True),
    ]
    score = compute_layer_weighted_score(layers)
    assert score == 100.0


def test_score_analysis_end_to_end():
    layers = [LayerEvidence(layer="url", risk_score=90, indicators=["bad"], details={})]
    result = score_analysis(layers, None, degraded=[])
    assert result["risk_level"] == RiskLevel.HIGH_RISK
    assert "bad" in result["indicators"]


def test_strong_layer_not_diluted_by_neutral_layer():
    # Confirmed typosquat (url 80) + neutral domain layer must stay HIGH_RISK,
    # not average down to 45.
    layers = [
        LayerEvidence(layer="url", risk_score=80, indicators=["typosquat"], details={}),
        LayerEvidence(layer="domain", risk_score=10, indicators=[], details={}),
    ]
    result = score_analysis(layers, None, degraded=[])
    assert result["threat_score"] == 72
    assert result["risk_level"] == RiskLevel.HIGH_RISK


def test_prefilter_not_blended_without_a_trained_model():
    # The rule-based fallback is derived from the layer risks, so folding it back
    # in would double-count the same evidence.
    layers = [LayerEvidence(layer="url", risk_score=10, indicators=[], details={})]
    result = score_analysis(layers, None, degraded=["ml.deterministic_fallback"],
                            prefilter_score=95.0, prefilter_model_trained=False)
    assert result["prefilter_blended"] is False
    assert result["prefilter_weight"] == 0.0
    assert result["threat_score"] == 10.0
    assert result["risk_level"] == RiskLevel.SAFE


def test_trained_prefilter_raises_score_by_its_configured_weight():
    layers = [LayerEvidence(layer="url", risk_score=20, indicators=[], details={})]
    result = score_analysis(layers, None, degraded=[],
                            prefilter_score=100.0, prefilter_model_trained=True,
                            prefilter_weight=0.25)
    # 0.75 * 20 + 0.25 * 100 = 40
    assert result["layer_score"] == 20.0
    assert result["base_score"] == 40.0
    assert result["threat_score"] == 40.0
    assert result["prefilter_blended"] is True
    assert "ML prefilter" in result["explanation"]
    assert any("prefilter" in ind for ind in result["indicators"])


def test_prefilter_cannot_dominate_the_layer_evidence():
    # A lone maximal prefilter score must not lift a clean analysis above SAFE.
    layers = [LayerEvidence(layer="url", risk_score=5, indicators=[], details={})]
    score, blended, weight = blend_prefilter_score(5.0, 100.0, True, weight=0.5)
    assert blended is True
    assert weight == 0.5
    assert score == 52.5
    assert classify_risk(score) == RiskLevel.SUSPICIOUS

    # Weight is clamped, so a misconfigured value cannot break the invariant.
    clamped_score, _, clamped_weight = blend_prefilter_score(5.0, 100.0, True, weight=0.99)
    assert clamped_weight == 0.5
    assert clamped_score == 52.5


def test_low_prefilter_scores_are_not_echoed_as_indicators():
    layers = [LayerEvidence(layer="url", risk_score=0, indicators=[], details={})]
    result = score_analysis(layers, None, degraded=[],
                            prefilter_score=12.0, prefilter_model_trained=True)
    assert result["prefilter_blended"] is True
    assert not any("Machine-learning prefilter" in ind for ind in result["indicators"])
