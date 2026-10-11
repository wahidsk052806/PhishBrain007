"""Version 1 API routes for PhishBrain."""
from __future__ import annotations

import asyncio
import csv
import io
import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse

from app.cache.store import get_cache
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import SSRFBlockedError, guard_user_target
from app.db.repository import (
    clear_history,
    clear_visual_evidence,
    get_analysis,
    list_alerts,
    list_history,
    purge_visual_evidence,
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

# Server-Sent Events framing. `no-transform` and `X-Accel-Buffering` stop
# intermediaries from buffering the stream into a single late response, which
# would defeat the point of streaming at all.
_SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, default=str)}\n\n"


def _error_response(exc: Exception, status_code: int = 500) -> HTTPException:
    logger.error("API error", extra={"extra_fields": {"error": str(exc)}})
    return HTTPException(status_code=status_code, detail="An internal error occurred while processing the request.")


@router.post("/analyze/url")
async def analyze_url_endpoint(payload: URLAnalyzeRequest):
    try:
        if payload.demo:
            return build_demo_result("url", payload.url)
        # A bare host (`hianime.to`) is a valid thing to type, so the target is
        # normalised to an absolute URL before the SSRF guard sees it. The
        # normalised form is what gets scanned and named in the report.
        try:
            target, _ = guard_user_target(payload.url)
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=400, detail=f"URL rejected: {exc}") from exc

        request_payload = payload.model_dump()
        request_payload["url"] = target
        result = await run_analysis(
            "url",
            target,
            url=target,
            dom_summary=payload.dom_summary,
            fetch_page_flag=payload.fetch_page,
            skip_llm=not payload.use_llm,
            raw_input=request_payload,
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.post("/analyze/url/stream")
async def analyze_url_stream_endpoint(payload: URLAnalyzeRequest):
    """Run a URL scan and stream its progress as Server-Sent Events.

    A full scan on CPU-only hardware spends most of its wall time inside the
    local LLM, so the single-response endpoint made a useful report appear only
    after ~30s of nothing. This emits each deterministic layer, the pre-filter
    contribution and a clearly-labelled provisional score as soon as they
    exist, then the LLM verdict and the final scored result — so the report
    fills in progressively instead of hanging on a spinner.

    Events: `started`, `layer`, `layers`, `prefilter`, `provisional`, `llm`,
    `final`, `error`. The final event carries the same payload as the
    non-streaming endpoint.
    """
    try:
        # Normalise and guard before opening the stream, so a refusal is still a
        # plain 4xx with the same body the non-streaming endpoint returns.
        if payload.demo:
            demo_result = build_demo_result("url", payload.url)

            async def demo_stream():
                yield _sse({"type": "started", "target": payload.url})
                yield _sse({"type": "final", "result": demo_result.model_dump(mode="json")})

            return StreamingResponse(demo_stream(), media_type="text/event-stream", headers=_SSE_HEADERS)

        try:
            target, _ = guard_user_target(payload.url)
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=400, detail=f"URL rejected: {exc}") from exc

        request_payload = payload.model_dump()
        request_payload["url"] = target
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc

    queue: asyncio.Queue = asyncio.Queue()
    _finished = object()

    async def on_event(event: dict) -> None:
        await queue.put(event)

    async def runner() -> None:
        try:
            result = await run_analysis(
                "url",
                target,
                url=target,
                dom_summary=payload.dom_summary,
                fetch_page_flag=payload.fetch_page,
                skip_llm=not payload.use_llm,
                raw_input=request_payload,
                on_event=on_event,
            )
            await queue.put({"type": "final", "result": result.model_dump(mode="json")})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("streamed scan failed", extra={"extra_fields": {"error": str(exc)}})
            await queue.put(
                {"type": "error", "message": "The scan failed before a verdict was produced."}
            )
        finally:
            await queue.put(_finished)

    task = asyncio.create_task(runner())

    async def event_stream():
        try:
            yield _sse({"type": "started", "target": target})
            while True:
                item = await queue.get()
                if item is _finished:
                    break
                yield _sse(item)
        finally:
            # The client hung up: stop the scan rather than leave it running
            # with nowhere to deliver its result.
            task.cancel()

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers=_SSE_HEADERS)


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
        # A caller-supplied HTML body carries its own target; otherwise the
        # URL is normalised exactly as the URL endpoint does, so a bare host
        # works here too.
        target = payload.url
        if not payload.html and payload.fetch_page:
            try:
                target, _ = guard_user_target(payload.url)
            except SSRFBlockedError as exc:
                raise HTTPException(status_code=400, detail=f"URL rejected: {exc}") from exc

        request_payload = payload.model_dump()
        request_payload["url"] = target
        result = await run_analysis(
            "page",
            target,
            url=target,
            html=payload.html,
            dom_summary=payload.dom_summary,
            fetch_page_flag=payload.fetch_page,
            screenshot_base64=payload.screenshot_base64,
            skip_llm=not payload.use_llm,
            raw_input=request_payload,
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


@router.get("/visual-evidence/policy")
async def visual_evidence_policy_endpoint():
    """The active screenshot-evidence retention policy.

    Exposed so the dashboard can show the *real* configured window instead of
    hard-coding one, and so an operator can confirm the sweep is enabled.
    """
    settings = get_settings()
    return {
        "retention_days": settings.VISUAL_RETENTION_DAYS,
        "auto_purge_enabled": settings.VISUAL_AUTO_PURGE_ENABLED,
        "screenshot_mode": settings.VISUAL_SCREENSHOT_MODE,
    }


@router.post("/visual-evidence/clear")
async def visual_evidence_clear_endpoint():
    """Strip every stored screenshot thumbnail now, keeping the analyses.

    Deliberately not a delete of the analysis: a user clearing visual evidence
    is asking to stop the images being stored, not to lose their history.
    """
    try:
        cleared = clear_visual_evidence()
        return {"cleared": cleared}
    except Exception as exc:  # noqa: BLE001
        raise _error_response(exc) from exc


@router.post("/visual-evidence/purge-expired")
async def visual_evidence_purge_endpoint():
    """Run the aged-evidence sweep on demand (what the scheduler does)."""
    try:
        settings = get_settings()
        purged = purge_visual_evidence()
        return {"purged": purged, "retention_days": settings.VISUAL_RETENTION_DAYS}
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
        database_backend="postgres" if settings.DATABASE_URL.startswith("postgres") else "sqlite",
        cache_backend=cache.backend,
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
        visual_retention_days=settings.VISUAL_RETENTION_DAYS,
    )
