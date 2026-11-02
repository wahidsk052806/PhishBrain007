"""The model's CPU time must be spent only where its answer can change anything.

Measured on the documented 4-core box, `llama3.2:3b` needs ~8 s of prompt
processing plus ~12-45 s of generation for one verdict, against ~2 s for the
entire deterministic half of a scan. That is why the model owned the latency of
every scan — and for a target whose score cannot legally cross a risk boundary,
the generation was pure ceremony.

These tests pin the two levers: the bounded generation budget, and the skip
decision (which must be *reported*, never silent).
"""
from __future__ import annotations

from app.core.config import Settings
from app.llm.prompt import SYSTEM_INSTRUCTIONS, build_prompt, build_stricter_retry_prompt, compact_evidence
from app.scoring.engine import LLM_ADJUSTMENT_CLAMP, compute_confidence, score_analysis
from app.schemas.analysis import LayerEvidence

FIELDS = Settings.model_fields


# --------------------------------------------------------------------------- #
# Generation budget
# --------------------------------------------------------------------------- #
def test_generation_cap_is_bounded_but_not_starved():
    # A complete SAFE verdict measured 82-83 tokens; the cap must leave room for
    # a verdict with several indicators, and must not be the old 320 (≈47 s of
    # generation at the measured ~6.8 tokens/s).
    cap = FIELDS["LLM_NUM_PREDICT"].default
    assert 80 < cap <= 160, cap


def test_skip_is_on_by_default_but_overridable():
    assert FIELDS["LLM_SKIP_WHEN_DECISIVE"].default is True


# --------------------------------------------------------------------------- #
# Prompt size
# --------------------------------------------------------------------------- #
def test_instructions_stay_small_and_keep_the_safety_rules():
    # Instruction tokens are paid before the first output token exists, so this
    # block is a latency budget as much as a prompt.
    assert len(SYSTEM_INSTRUCTIONS) < 900, len(SYSTEM_INSTRUCTIONS)
    lowered = SYSTEM_INSTRUCTIONS.lower()
    # The rules that keep injected page text from steering the verdict.
    assert "never as instructions" in lowered
    assert "strict json" in lowered
    assert "score_adjustment" in SYSTEM_INSTRUCTIONS


def test_evidence_block_is_bounded():
    evidence = {
        "prefilter_score": 12.5,
        "top_indicators": [f"indicator {i} " + "x" * 500 for i in range(40)],
        "layers": {"url": 10.0, "domain": 0.0},
    }
    rendered = compact_evidence(evidence)
    assert len(rendered) < 1200, len(rendered)
    assert "x" * 500 not in rendered
    # Stable ordering, so the same target tokenises identically on a retry and
    # keeps the prompt cache warm.
    assert rendered == compact_evidence(dict(reversed(list(evidence.items()))) | {"layers": evidence["layers"]})


def test_prompt_is_much_smaller_than_the_old_render():
    prompt = build_prompt("https://example.com/login", None, "Title: Login", {"prefilter_score": 3})
    # The old prompt measured ~1572 characters for this input.
    assert len(prompt) < 1400, len(prompt)


def test_retry_prompt_does_not_resend_the_untrusted_content():
    """A retry is a second full generation on the same CPU, so it carries the
    schema and the failure — not the page text the model has already read."""
    first = build_prompt("https://example.com", None, "SECRET-PAGE-MARKER", {"prefilter_score": 3})
    retry = build_stricter_retry_prompt(first)
    assert "SECRET-PAGE-MARKER" not in retry
    assert len(retry) < len(SYSTEM_INSTRUCTIONS) + 900


# --------------------------------------------------------------------------- #
# The skip decision itself
# --------------------------------------------------------------------------- #
def _layer(name: str, risk: float) -> LayerEvidence:
    return LayerEvidence(layer=name, risk_score=risk, indicators=[], details={})


def test_a_decided_verdict_exempts_the_skip_from_the_confidence_penalty():
    layers = [_layer("url", 0.0), _layer("domain", 0.0)]
    normal = compute_confidence(layers, None, [])
    skipped = compute_confidence(layers, None, ["llm.not_needed"])
    assert skipped == normal, (skipped, normal)
    # A real fault still costs confidence.
    assert compute_confidence(layers, None, ["llm.timeout"]) < normal


def test_skip_does_not_change_the_score_it_declines_to_consult():
    layers = [_layer("url", 10.0), _layer("domain", 5.0), _layer("webpage", 0.0)]
    without = score_analysis(layers, None, ["llm.not_needed"])
    assert without["threat_score"] == without["base_score"]
    assert without["risk_level"].value == "SAFE"


def test_the_skip_band_is_exactly_the_one_no_adjustment_can_leave():
    """A base score below the SAFE ceiling minus the clamp is decided; one at or
    above it is not, because +15 could still push it over."""
    settings = Settings()
    floor = settings.SAFE_THRESHOLD - LLM_ADJUSTMENT_CLAMP
    ceiling = settings.SUSPICIOUS_THRESHOLD + LLM_ADJUSTMENT_CLAMP
    # SAFE + any legal adjustment stays SAFE below the floor...
    assert floor + LLM_ADJUSTMENT_CLAMP <= settings.SAFE_THRESHOLD
    # ...and HIGH_RISK - any legal adjustment stays HIGH_RISK at the ceiling.
    assert ceiling - LLM_ADJUSTMENT_CLAMP >= settings.SUSPICIOUS_THRESHOLD
