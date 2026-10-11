"""Repository layer: persistence for analyses and feedback."""
from __future__ import annotations

import copy
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


# The key a stored evidence image lives under. It appears in a layer's
# `details` (the backend pipeline attaches it there) and, for results the
# dashboard/extension normalise, in the layer's `evidence`.
_SCREENSHOT_KEY = "screenshot_data_url"


def _without_screenshot_evidence(payload: object) -> object | None:
    """Return `payload` with every screenshot data URL removed, or None if clean.

    A *copy* is returned rather than mutating in place: `result_json` is a plain
    SQLAlchemy JSON column, which does not track in-place mutation, so an edited
    dict would never be flushed. Returning None when there was nothing to strip
    lets the caller skip the write (and avoids rewriting every clean record on
    each sweep).
    """
    if not isinstance(payload, dict):
        return None

    found = False

    def _strip(container: object) -> None:
        nonlocal found
        if isinstance(container, dict) and container.pop(_SCREENSHOT_KEY, None) is not None:
            found = True

    for layer in payload.get("layer_evidence") or []:
        if isinstance(layer, dict):
            _strip(layer.get("details"))
            _strip(layer.get("evidence"))
    # Defensive: some callers serialise a keyed `layers` record instead.
    layers = payload.get("layers")
    if isinstance(layers, dict):
        for layer in layers.values():
            if isinstance(layer, dict):
                _strip(layer.get("details"))
                _strip(layer.get("evidence"))
    _strip(payload.get("visual"))

    if not found:
        return None
    return payload


def _strip_screenshot_evidence(cutoff: datetime | None) -> int:
    """Strip stored screenshot evidence from records older than `cutoff`.

    `cutoff=None` means every record. Returns the number of records changed.
    """
    try:
        with session_scope() as session:
            stmt = select(AnalysisRecord)
            if cutoff is not None:
                stmt = stmt.where(AnalysisRecord.created_at < cutoff)
            records = session.execute(stmt).scalars().all()
            changed = 0
            for record in records:
                # Copy first: the strip must not touch the identity-mapped dict
                # before we know whether anything was removed.
                candidate = _without_screenshot_evidence(copy.deepcopy(record.result_json))
                if candidate is None:
                    continue
                record.result_json = candidate
                changed += 1
            return changed
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to purge screenshot evidence", extra={"extra_fields": {"error": str(exc)}})
        return 0


def purge_visual_evidence(days: int | None = None) -> int:
    """Delete stored screenshot thumbnails older than the retention window.

    Runs on its own (shorter) clock than `purge_expired`: the analysis record
    keeps its score and indicators, only the image is dropped. Safe to call
    repeatedly — a sweep with nothing to do writes nothing.
    """
    settings = get_settings()
    window = settings.VISUAL_RETENTION_DAYS if days is None else max(0, days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=window)
    return _strip_screenshot_evidence(cutoff)


def clear_visual_evidence() -> int:
    """Strip every stored screenshot thumbnail immediately ("clear all")."""
    return _strip_screenshot_evidence(cutoff=None)


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
