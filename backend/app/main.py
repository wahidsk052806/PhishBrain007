"""FastAPI application entrypoint for PhishBrain."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.routes import router as v1_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.repository import purge_expired, purge_visual_evidence
from app.db.session import init_db
from app.llm.ollama_client import warm_up_ollama
from app.ml.prefilter import get_prefilter

configure_logging()
logger = get_logger(__name__)

CORS_ORIGIN_REGEX = r"^(chrome-extension://.*|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$"


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Rejects requests whose declared Content-Length exceeds the configured cap."""

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > settings.MAX_REQUEST_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large."},
                    )
            except ValueError:
                pass
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("PhishBrain backend starting up")
    # Background warm-ups. Neither is allowed to delay startup or to fail it:
    # the model loads and the LLM warms while the process is already serving.
    warmups = asyncio.create_task(_warm_up())
    # Retention was configured but never enforced: `purge_expired` existed and
    # was never called from anywhere, so RETENTION_DAYS only ever described an
    # intention. The loop now actually applies both policies.
    retention = asyncio.create_task(_retention_loop())
    try:
        yield
    finally:
        warmups.cancel()
        retention.cancel()
        logger.info("PhishBrain backend shutting down")


async def _retention_loop() -> None:
    """Apply the analysis and screenshot-evidence retention policies.

    Runs once at startup and then on the configured interval. Both sweeps are
    blocking DB work, so they run in a worker thread and never touch startup or
    a request's latency.
    """
    settings = get_settings()
    interval = max(1, settings.VISUAL_PURGE_INTERVAL_MINUTES) * 60
    while True:
        try:
            expired = await asyncio.to_thread(purge_expired)
            if expired:
                logger.info("Purged expired analyses", extra={"extra_fields": {"count": expired}})
            if settings.VISUAL_AUTO_PURGE_ENABLED:
                stripped = await asyncio.to_thread(purge_visual_evidence)
                if stripped:
                    logger.info(
                        "Purged aged screenshot evidence",
                        extra={
                            "extra_fields": {
                                "count": stripped,
                                "retention_days": settings.VISUAL_RETENTION_DAYS,
                            }
                        },
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.info("Retention sweep failed", extra={"extra_fields": {"error": str(exc)}})
        await asyncio.sleep(interval)


async def _warm_up() -> None:
    """Preload the prefilter model and the LLM so the first scan is not slow.

    Measured on this machine: without the LLM warm-up the first scan after a
    restart took 73.8 s against 37-43 s for the next ones, because llama3.2 had
    to be paged in mid-request.
    """
    settings = get_settings()
    try:
        # CatBoost load is CPU-bound and blocking, so keep it off the event loop.
        await asyncio.to_thread(get_prefilter)
    except Exception as exc:  # noqa: BLE001
        logger.info("Prefilter warm-up failed", extra={"extra_fields": {"error": str(exc)}})
    if settings.LLM_WARMUP_ON_STARTUP:
        await warm_up_ollama(settings)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="PhishBrain API",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(MaxBodySizeMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=CORS_ORIGIN_REGEX,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):  # noqa: ARG001
        logger.error("Unhandled exception", extra={"extra_fields": {"path": str(request.url), "error": str(exc)}})
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred while processing the request."},
        )

    app.include_router(v1_router, prefix="/api/v1")

    @app.get("/")
    async def root():
        return {"service": "phishbrain", "status": "running", "app_env": settings.APP_ENV}

    return app


app = create_app()
