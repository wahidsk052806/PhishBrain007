"""Repository layer: persistence for analyses and feedback."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.privacy import redact_raw_email_if_needed
from app.db.models import AnalysisRecord, FeedbackRecord
from app.db.session import session_scope
from app.schemas.analysis import AnalysisResult

logger = get_logger(__name__)


def _sanitize_raw_input(raw_input: dict | None) -> dict | None:
    """Respect STORE_RAW_EMAIL when persisting caller-supplied raw content."""
    if not raw_input:
        return raw_input
    settings = get_settings()
    sanitized = dict(raw_input)
    if "body" in sanitized:
        if not settings.STORE_RAW_EMAIL:
            sanitized["body"] = redact_raw_email_if_needed(sanitized.get("body"))
    if "raw_headers" in sanitized:
        if not settings.STORE_RAW_EMAIL:
            sanitized["raw_headers"] = redact_raw_email_if_needed(sanitized.get("raw_headers"))
    return sanitized


def save_analysis(result: AnalysisResult, raw_input: dict | None = None) -> None:
    try:
        with session_scope() as session:
            record = AnalysisRecord(
                analysis_id=result.analysis_id,
                created_at=result.created_at,
                input_type=result.input_type,
                target=result.target,
                threat_score=result.threat_score,
                risk_level=result.risk_level.value,
                confidence=result.confidence,
                demo=result.demo,
                result_json=json.loads(result.model_dump_json()),
                raw_input_json=_sanitize_raw_input(raw_input),
            )
            session.merge(record)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to persist analysis", extra={"extra_fields": {"error": str(exc)}})


def get_analysis(analysis_id: str) -> dict | None:
    try:
        with session_scope() as session:
            record = session.get(AnalysisRecord, analysis_id)
            if record is None:
                return None
            return record.result_json
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch analysis", extra={"extra_fields": {"error": str(exc)}})
        return None


def list_history(limit: int = 50) -> list[dict]:
    try:
        with session_scope() as session:
            stmt = select(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).limit(limit)
            records = session.execute(stmt).scalars().all()
            return [r.result_json for r in records]
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch history", extra={"extra_fields": {"error": str(exc)}})
        return []


def list_alerts(limit: int = 50) -> list[dict]:
    """Return the highest-severity recent analyses (SUSPICIOUS/HIGH_RISK)."""
    try:
        with session_scope() as session:
            stmt = (
                select(AnalysisRecord)
                .where(AnalysisRecord.risk_level.in_(["SUSPICIOUS", "HIGH_RISK"]))
                .order_by(AnalysisRecord.created_at.desc())
                .limit(limit)
            )
            records = session.execute(stmt).scalars().all()
            return [r.result_json for r in records]
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch alerts", extra={"extra_fields": {"error": str(exc)}})
        return []


def clear_history() -> int:
    try:
        with session_scope() as session:
            result = session.execute(delete(AnalysisRecord))
            return result.rowcount or 0
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to clear history", extra={"extra_fields": {"error": str(exc)}})
        return 0


def save_feedback(analysis_id: str, correct: bool, comment: str | None) -> None:
    try:
        with session_scope() as session:
            session.add(FeedbackRecord(analysis_id=analysis_id, correct=correct, comment=comment))
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to persist feedback", extra={"extra_fields": {"error": str(exc)}})


def purge_expired() -> int:
    """Delete analyses older than RETENTION_DAYS. Safe to call repeatedly."""
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.RETENTION_DAYS)
    try:
        with session_scope() as session:
            result = session.execute(delete(AnalysisRecord).where(AnalysisRecord.created_at < cutoff))
            return result.rowcount or 0
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to purge expired analyses", extra={"extra_fields": {"error": str(exc)}})
        return 0
