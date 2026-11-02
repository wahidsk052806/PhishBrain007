"""The LLM must not be budgeted like a HTTP fetch.

Regression guard for the Compose deployment where every scan reported "the
model did not answer within the scan deadline": the verdict shared the 20 s
network deadline, so a CPU model was cancelled mid-generation, and each cancel
also aborted Ollama's model load — the model could never become resident.

These assert the *shipped defaults*, not `Settings()`, because a developer `.env`
in the checkout may override them and the point is what a fresh deployment gets.
"""
from __future__ import annotations

from app.core.config import Settings

FIELDS = Settings.model_fields


def test_llm_budget_is_separate_from_the_network_deadline():
    assert FIELDS["LLM_TIMEOUT_SECONDS"].default > FIELDS["ANALYSIS_TIMEOUT_SECONDS"].default
    # Loading weights is slower than one request, so the warm-up needs the most.
    assert FIELDS["LLM_WARMUP_TIMEOUT_SECONDS"].default >= FIELDS["LLM_TIMEOUT_SECONDS"].default


def test_default_model_fits_the_documented_hardware():
    # 4 CPU / 8 GB is the documented minimum; llama3.1:8b needs ~4.9 GB resident
    # and measured ~293 s per verdict there, so 3B is the default and 8B is opt-in.
    assert FIELDS["OLLAMA_MODEL"].default == "llama3.2:3b"


def test_visual_budget_is_not_a_slice_of_the_fetch_deadline():
    assert FIELDS["VISUAL_TIMEOUT_SECONDS"].default > FIELDS["ANALYSIS_TIMEOUT_SECONDS"].default / 2
