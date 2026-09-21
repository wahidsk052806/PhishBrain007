"""FastAPI application entrypoint for PhishBrain."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.routes import router as v1_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import init_db

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
    yield
    logger.info("PhishBrain backend shutting down")


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
