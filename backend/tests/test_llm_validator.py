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


# --------------------------------------------------------------------------- #
# Normalising what the local model actually answers
#
# The pipeline used to reject all of these, which cost a second ~30s inference
# and then dropped the model's reasoning for the rules-only fallback. The
# meanings are unambiguous, so they are normalised into the schema instead.
# --------------------------------------------------------------------------- #


def test_verdict_synonym_is_normalised():
    # llama3.2 answers "Phishing", not "HIGH_RISK".
    raw = '{"verdict": "Phishing", "phishing_likelihood": 0.9, "confidence": 0.8}'

    result = validate_llm_output(raw)

    assert result is not None
    assert result.verdict.value == "HIGH_RISK"


def test_percentage_scores_are_rescaled_to_ratios():
    # 80 means 0.8; the field is a 0-1 float.
    raw = '{"verdict": "Phishing", "phishing_likelihood": 80, "confidence": 80}'

    result = validate_llm_output(raw)

    assert result is not None
    assert result.phishing_likelihood == 0.8
    assert result.confidence == 0.8


def test_verdict_is_derived_when_only_a_score_is_given():
    raw = '{"phishing_likelihood": 0.72, "confidence": 0.5}'

    result = validate_llm_output(raw)

    assert result is not None
    assert result.verdict.value == "HIGH_RISK"


def test_score_is_derived_when_only_a_verdict_is_given():
    raw = '{"verdict": "low risk", "confidence": 0.6}'

    result = validate_llm_output(raw)

    assert result is not None
    assert result.verdict.value == "SAFE"
    assert result.phishing_likelihood <= 0.3


def test_the_number_wins_over_a_hedged_verdict_word():
    raw = '{"verdict": "safe", "phishing_likelihood": 0.7, "confidence": 0.5}'

    result = validate_llm_output(raw)

    assert result is not None
    assert result.verdict.value == "HIGH_RISK"


def test_scalar_fields_are_coerced_into_their_schema_shapes():
    raw = (
        '{"verdict": "SUSPICIOUS", "phishing_likelihood": 0.5, "confidence": 0.5, '
        '"key_indicators": "a single string", "reasoning": "because", '
        '"recommendation": "verify", "score_adjustment": 99}'
    )

    result = validate_llm_output(raw)

    assert result is not None
    assert result.key_indicators == ["a single string"]
    assert result.reasoning_summary == "because"
    assert result.recommended_action == "verify"
    assert result.score_adjustment == 15.0, "an out-of-range adjustment is clamped, not fatal"


def test_a_payload_with_no_interpretable_verdict_still_returns_none():
    assert validate_llm_output('{"confidence": 0.5}') is None


def test_the_real_model_answer_validates_on_the_first_attempt():
    """The exact shape observed from llama3.2 in production, verbatim."""
    raw = (
        '{"verdict": "Phishing", "phishing_likelihood": 80, "confidence": 0.8, '
        '"key_indicators": ["unavailable webpage", "no TLS", "registered domain 3.1 years ago"], '
        '"reasoning_summary": "The website is unavailable, has no TLS.", '
        '"recommended_action": "Avoid the website."}'
    )

    result = validate_llm_output(raw)

    assert result is not None
    assert result.verdict.value == "HIGH_RISK"
    assert len(result.key_indicators) == 3
    assert result.score_adjustment == 0.0


class TestOllamaWarmup:
    """Startup warm-up must never be able to break startup."""

    def test_unreachable_ollama_returns_false_instead_of_raising(self):
        import asyncio

        from app.core.config import Settings
        from app.llm.ollama_client import warm_up_ollama

        settings = Settings(OLLAMA_BASE_URL="http://127.0.0.1:9")  # nothing listens here
        assert asyncio.run(warm_up_ollama(settings)) is False

    def test_warmup_is_on_by_default_and_can_be_disabled(self):
        from app.core.config import Settings

        assert Settings().LLM_WARMUP_ON_STARTUP is True
        assert Settings(LLM_WARMUP_ON_STARTUP=False).LLM_WARMUP_ON_STARTUP is False
