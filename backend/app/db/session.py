"""SQLAlchemy engine/session management."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.models import Base

logger = get_logger(__name__)

_engine = None
_SessionLocal: sessionmaker | None = None


def sqlalchemy_url(url: str) -> str:
    """Name the Postgres driver that this project actually installs.

    SQLAlchemy resolves a bare ``postgresql://`` URL to psycopg2, but the
    requirements pin psycopg 3 (``psycopg[binary]``) and do not install psycopg2.
    In a Compose deployment that mismatch was invisible in the UI: the scan
    itself still answered, while the app logged "Database initialization
    failed: No module named 'psycopg2'", every analysis failed to persist, the
    history page stayed empty and ``/health`` reported ``degraded`` without
    saying which subsystem was down. Spelling the driver out makes the URL and
    the installed package agree. SQLite URLs are returned unchanged.
    """
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {}
        url = sqlalchemy_url(settings.DATABASE_URL)
        if url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        _engine = create_engine(url, connect_args=connect_args, future=True)
    return _engine


def get_sessionmaker() -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False, class_=Session)
    return _SessionLocal


def init_db() -> None:
    """Create tables if they do not already exist. Never raises; logs on failure
    so the app can still start in a degraded state."""
    try:
        Base.metadata.create_all(bind=get_engine())
    except Exception as exc:  # noqa: BLE001
        logger.error("Database initialization failed", extra={"extra_fields": {"error": str(exc)}})


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
