"""Version 1 API routes for PhishBrain."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from app.cache.store import get_cache
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import SSRFBlockedError, guard_url
from app.db.repository import (
    clear_history,
    get_analysis,
    list_alerts,
    list_history,
    save_feedback,
)
from app.db.session import get_engine
from app.demo.samples import build_demo_result
from app.schemas.analysis import (
    ConfigResponse,
    EmailAnalyzeRequest,
    FeedbackRequest,
    HealthStatus,
    PageAnalyzeRequest,
    URLAnalyzeRequest,
)
from app.services.pipeline import run_analysis

logger = get_logger(__name__)
router = APIRouter()


def _error_response(exc: Exception, status_code: int = 500) -> HTTPException:
    logger.error("API error", extra={"extra_fields": {"error": str(exc)}})
    return HTTPException(status_code=status_code, detail="An internal error occurred while processing the request.")


@router.post("/analyze/url")
async def analyze_url_endpoint(payload: URLAnalyzeRequest):
    try:
        if payload.demo:
            return build_demo_result("url", payload.url)
        try:
            guard_url(payload.url)
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=400, detail=f"URL rejected: {exc}") from exc

        result = await run_analysis(
            "url",
            payload.url,
            url=payload.url,
            dom_summary=payload.dom_summary,
            fetch_page_flag=payload.fetch_page,
            skip_llm=not payload.use_llm,
            raw_input=payload.model_dump(),
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.post("/analyze/email")
async def analyze_email_endpoint(payload: EmailAnalyzeRequest):
    try:
        if payload.demo:
            return build_demo_result("email", payload.sender)

        result = await run_analysis(
            "email",
            payload.sender,
            email_fields=payload.model_dump(),
            raw_input=payload.model_dump(),
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.post("/analyze/page")
async def analyze_page_endpoint(payload: PageAnalyzeRequest):
    try:
        if payload.demo:
            return build_demo_result("page", payload.url)
        if not payload.html and payload.fetch_page:
            try:
                guard_url(payload.url)
            except SSRFBlockedError as exc:
                raise HTTPException(status_code=400, detail=f"URL rejected: {exc}") from exc

        result = await run_analysis(
            "page",
            payload.url,
            url=payload.url,
            html=payload.html,
            dom_summary=payload.dom_summary,
            fetch_page_flag=payload.fetch_page,
            screenshot_base64=payload.screenshot_base64,
            skip_llm=not payload.use_llm,
            raw_input=payload.model_dump(),
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.get("/analysis/{analysis_id}")
async def get_analysis_endpoint(analysis_id: str):
    try:
        result = get_analysis(analysis_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.get("/history")
async def history_endpoint(limit: int = Query(default=50, ge=1, le=500)):
    try:
        return {"items": list_history(limit=limit)}
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.get("/alerts")
async def alerts_endpoint(limit: int = Query(default=50, ge=1, le=500)):
    try:
        return {"items": list_alerts(limit=limit)}
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.post("/history/clear")
async def history_clear_endpoint():
    try:
        removed = clear_history()
        return {"cleared": removed}
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.post("/feedback")
async def feedback_endpoint(payload: FeedbackRequest):
    try:
        save_feedback(payload.analysis_id, payload.correct, payload.comment)
        return {"status": "recorded"}
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.get("/export/{analysis_id}")
async def export_endpoint(analysis_id: str, format: str = Query(default="json", pattern="^(json|csv)$")):
    try:
        result = get_analysis(analysis_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Analysis not found")

        if format == "json":
            return result

        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["field", "value"])
        for key in ("analysis_id", "created_at", "input_type", "target", "threat_score", "risk_level", "confidence", "explanation", "recommended_action"):
            writer.writerow([key, result.get(key)])
        writer.writerow(["indicators", "; ".join(result.get("indicators", []))])
        return PlainTextResponse(content=buffer.getvalue(), media_type="text/csv")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.get("/health", response_model=HealthStatus)
async def health_endpoint():
    settings = get_settings()

    db_status = "ok"
    try:
        engine = get_engine()
        with engine.connect():
            pass
    except Exception:  # noqa: BLE001
        db_status = "unavailable"

    cache = get_cache()
    cache_status = "ok" if cache.ping() else "unavailable"

    ollama_status = "unknown"
    try:
        import httpx

        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags")
            ollama_status = "ok" if resp.status_code == 200 else "unavailable"
    except Exception:  # noqa: BLE001
        ollama_status = "unavailable"

    overall = "ok" if db_status == "ok" else "degraded"
    return HealthStatus(
        status=overall,
        ollama=ollama_status,
        database=db_status,
        cache=cache_status,
        app_env=settings.APP_ENV,
    )


@router.get("/config", response_model=ConfigResponse)
async def config_endpoint():
    settings = get_settings()
    return ConfigResponse(
        app_env=settings.APP_ENV,
        llm_provider=settings.LLM_PROVIDER,
        ollama_model=settings.OLLAMA_MODEL,
        # Layer weights exclude the prefilter's share; report the ML share
        # explicitly so the composite score can be reconstructed from /config.
        weights={**settings.layer_weights, "prefilter": settings.PREFILTER_WEIGHT},
        safe_threshold=settings.SAFE_THRESHOLD,
        suspicious_threshold=settings.SUSPICIOUS_THRESHOLD,
        brands=settings.brands,
        allowed_schemes=settings.allowed_schemes,
        store_raw_email=settings.STORE_RAW_EMAIL,
        retention_days=settings.RETENTION_DAYS,
    )
