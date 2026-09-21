"""Validate and sanitize raw LLM output into the strict LLMAssessment schema."""
from __future__ import annotations

import json
import re

from pydantic import ValidationError

from app.schemas.analysis import LLMAssessment

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def strip_chain_of_thought(raw: str) -> str:
    """Remove any <think> blocks so chain-of-thought never surfaces."""
    return THINK_BLOCK_RE.sub("", raw or "").strip()


def extract_json_object(raw: str) -> str | None:
    cleaned = strip_chain_of_thought(raw)
    match = JSON_OBJECT_RE.search(cleaned)
    return match.group(0) if match else None


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
    try:
        return LLMAssessment.model_validate(data)
    except ValidationError:
        return None
