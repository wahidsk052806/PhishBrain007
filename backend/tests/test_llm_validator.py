from app.llm.validator import extract_json_object, validate_llm_output


def test_validates_correct_json():
    raw = '{"verdict": "HIGH_RISK", "phishing_likelihood": 0.9, "confidence": 0.8, ' \
          '"key_indicators": ["a"], "reasoning_summary": "x", "recommended_action": "y", "score_adjustment": 5}'
    result = validate_llm_output(raw)
    assert result is not None
    assert result.verdict.value == "HIGH_RISK"


def test_strips_think_block_and_extracts_json():
    raw = '<think>secret reasoning</think>{"verdict": "SAFE", "phishing_likelihood": 0.1, ' \
          '"confidence": 0.5, "key_indicators": [], "reasoning_summary": "ok", "recommended_action": "none", "score_adjustment": 0}'
    obj = extract_json_object(raw)
    assert "secret reasoning" not in obj


def test_invalid_json_returns_none():
    assert validate_llm_output("not json at all") is None
