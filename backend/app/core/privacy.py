"""Privacy helpers: PII masking and raw-email redaction."""
from __future__ import annotations

import re

from app.core.config import get_settings

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){2,4}\d{2,4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
NAME_HEADER_RE = re.compile(r'"?([A-Z][a-zA-Z]+(?:\s[A-Z][a-zA-Z]+)+)"?\s*<')


def mask_email(address: str) -> str:
    match = EMAIL_RE.search(address or "")
    if not match:
        return address
    local, _, domain = match.group(0).partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_text_pii(text: str) -> str:
    if not text:
        return text
    masked = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), text)
    masked = NAME_HEADER_RE.sub(lambda m: "*" * len(m.group(1)) + " <", masked)
    masked = CREDIT_CARD_RE.sub("[REDACTED_CARD]", masked)
    return masked


def redact_raw_email_if_needed(raw_body: str | None) -> str | None:
    """Redacts/drops the raw email body based on STORE_RAW_EMAIL setting."""
    settings = get_settings()
    if raw_body is None:
        return None
    if settings.STORE_RAW_EMAIL:
        return raw_body
    return "[REDACTED: STORE_RAW_EMAIL=false]"
