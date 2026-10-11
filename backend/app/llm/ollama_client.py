"""HTTP client for a local Ollama server, with retry + deterministic fallback."""
from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.llm.prompt import build_prompt, build_stricter_retry_prompt
from app.llm.validator import validate_llm_output
from app.schemas.analysis import LLMAssessment, RiskLevel

logger = get_logger(__name__)


def _deterministic_fallback_assessment(deterministic_evidence: dict) -> LLMAssessment:
    """Rules-only assessment used when the LLM is unreachable or keeps
    returning malformed output. Derived purely from deterministic evidence."""
    avg = deterministic_evidence.get("prefilter_score", 0.0) / 100.0
    if avg >= 0.65:
        verdict = RiskLevel.HIGH_RISK
    elif avg >= 0.30:
        verdict = RiskLevel.SUSPICIOUS
    else:
        verdict = RiskLevel.SAFE
    return LLMAssessment(
        verdict=verdict,
        phishing_likelihood=round(min(1.0, max(0.0, avg)), 3),
        confidence=0.4,
        key_indicators=deterministic_evidence.get("top_indicators", [])[:5],
        reasoning_summary="LLM unavailable; assessment derived from deterministic rule-based evidence only.",
        recommended_action="Review flagged indicators manually." if verdict != RiskLevel.SAFE else "No action required.",
        score_adjustment=0.0,
    )


async def get_llm_assessment(
    url: str | None,
    email_summary: str | None,
    webpage_summary: str | None,
    deterministic_evidence: dict,
) -> tuple[LLMAssessment, bool]:
    """Returns (assessment, degraded). degraded=True means we fell back to
    the deterministic rules-only assessment."""
    settings = get_settings()
    prompt = build_prompt(url, email_summary, webpage_summary, deterministic_evidence)

    raw_output = await _call_ollama(prompt, settings)
    if raw_output is not None:
        assessment = validate_llm_output(raw_output)
        if assessment is not None:
            # Name the model that produced the verdict, so the dashboard does not
            # report "model: unavailable" next to a real model assessment.
            assessment.model = settings.OLLAMA_MODEL
            return assessment, False

        retry_prompt = build_stricter_retry_prompt(raw_output)
        raw_retry = await _call_ollama(retry_prompt, settings)
        if raw_retry is not None:
            assessment = validate_llm_output(raw_retry)
            if assessment is not None:
                assessment.model = settings.OLLAMA_MODEL
                return assessment, False

    return _deterministic_fallback_assessment(deterministic_evidence), True


async def warm_up_ollama(settings) -> bool:
    """Load the model into memory before the first scan needs it.

    Loading llama3.2 from disk costs ~30 s of CPU, and without this the first
    scan after a restart paid for it (measured: 73.8 s first scan vs 37-43 s
    warm). Deliberately small and best-effort — a missing Ollama must not stop
    the backend from starting, it just means the LLM layer degrades on the first
    request as it always did.
    """
    try:
        async with httpx.AsyncClient(timeout=settings.ANALYSIS_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": "ok",
                    "stream": False,
                    "keep_alive": settings.LLM_KEEP_ALIVE,
                    # One token: the point is the load, not the completion.
                    "options": {"num_predict": 1},
                },
            )
            if resp.status_code != 200:
                logger.info(
                    "Ollama warm-up skipped",
                    extra={"extra_fields": {"status": resp.status_code}},
                )
                return False
            logger.info("Ollama model warm", extra={"extra_fields": {"model": settings.OLLAMA_MODEL}})
            return True
    except Exception as exc:  # noqa: BLE001
        logger.info("Ollama warm-up failed", extra={"extra_fields": {"error": str(exc)}})
        return False


async def _call_ollama(prompt: str, settings) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=settings.ANALYSIS_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    # Deterministic security verdict, and bounded output: the
                    # JSON schema needs ~120 tokens, so an uncapped generation
                    # just burns CPU. `keep_alive` stops the model being evicted
                    # between scans, which is what made some scans ~3x slower
                    # than others for no visible reason.
                    "keep_alive": settings.LLM_KEEP_ALIVE,
                    "options": {
                        "temperature": 0,
                        "num_predict": settings.LLM_NUM_PREDICT,
                        "num_ctx": settings.LLM_NUM_CTX,
                    },
                },
            )
            if resp.status_code != 200:
                logger.warning("Ollama non-200 response", extra={"extra_fields": {"status": resp.status_code}})
                return None
            data = resp.json()
            return data.get("response")
    except Exception as exc:  # noqa: BLE001
        logger.info("Ollama call failed", extra={"extra_fields": {"error": str(exc)}})
        return None
