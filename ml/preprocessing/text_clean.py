"""
text_clean.py
--------------
Generic text-cleaning utilities shared by the email and URL feature
extractors. These are pure-python / stdlib-only so the ML pipeline can run
without heavy NLP dependencies.
"""
from __future__ import annotations

import html
import re
import unicodedata

_WHITESPACE_RE = re.compile(r"\s+")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_NON_PRINTABLE_RE = re.compile(r"[^\x20-\x7E\n]")


def normalize_unicode(text: str) -> str:
    """NFKC-normalize text to collapse visually-confusable / homoglyph forms."""
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text)


def strip_html(text: str) -> str:
    """Remove HTML tags and unescape entities, returning plain text."""
    if not text:
        return ""
    unescaped = html.unescape(text)
    return _HTML_TAG_RE.sub(" ", unescaped)


def collapse_whitespace(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def strip_non_printable(text: str) -> str:
    return _NON_PRINTABLE_RE.sub("", text)


def extract_urls(text: str) -> list[str]:
    """Extract raw http(s) URLs found in free text (email body, etc.)."""
    if not text:
        return []
    return _URL_RE.findall(text)


def clean_text(text: str, *, strip_markup: bool = True) -> str:
    """Full cleaning pipeline used before tokenization / feature extraction."""
    if not text:
        return ""
    out = normalize_unicode(text)
    if strip_markup:
        out = strip_html(out)
    out = strip_non_printable(out)
    out = collapse_whitespace(out)
    return out


def word_tokens(text: str) -> list[str]:
    """Very small tokenizer: lowercase word tokens, alnum only."""
    cleaned = clean_text(text)
    return re.findall(r"[a-z0-9]+", cleaned.lower())
