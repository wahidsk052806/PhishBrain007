"""
email_features.py
------------------
Email-level feature extraction for the PhishBrain prefilter model.

Mirrors the intended contract of the backend's email analyzer
(backend/app/analyzers/email/): header hygiene (SPF/DKIM/DMARC presence as
reported by the MTA headers, when available), sender/display-name
mismatches, urgency language, and embedded-URL statistics (reusing
url_features.py). No mail-server or DNS calls are made here — only
static analysis of a parsed email (headers + body) is performed, which is
what an offline dataset (e.g. Enron/Nazario-style headers, or exported
.eml files) provides.

Input is a plain dict so this module has no dependency on a specific email
parsing library; scripts/data/prepare_dataset.py is responsible for turning
raw .eml files into this dict shape via Python's stdlib `email` package.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, fields

from ml.preprocessing.text_clean import clean_text, extract_urls, word_tokens
from ml.preprocessing.url_features import extract_url_features

_URGENCY_WORDS = (
    "urgent", "immediately", "verify your account", "suspended", "expire",
    "click here", "act now", "limited time", "password will expire",
    "unauthorized", "unusual activity", "confirm your identity",
)
_GENERIC_GREETING_RE = re.compile(r"\b(dear (customer|user|member|sir|madam)|valued customer)\b", re.I)


@dataclass
class EmailFeatures:
    subject_length: int = 0
    body_length: int = 0
    num_urls: int = 0
    max_url_suspicious_keyword_count: int = 0
    mean_url_entropy: float = 0.0
    num_ip_host_urls: int = 0
    has_spf_pass: int = 0
    has_dkim_pass: int = 0
    has_dmarc_pass: int = 0
    sender_display_name_mismatch: int = 0
    reply_to_differs_from_from: int = 0
    num_attachments: int = 0
    has_urgency_language: int = 0
    urgency_keyword_count: int = 0
    has_generic_greeting: int = 0
    num_exclamation_marks: int = 0
    subject_has_re_fwd_spoof: int = 0
    html_to_text_ratio: float = 0.0

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


FEATURE_NAMES: list[str] = [f.name for f in fields(EmailFeatures)]


def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().strip(">")


def extract_email_features(email_record: dict) -> EmailFeatures:
    """
    email_record expected keys (all optional, missing -> default/empty):
      subject, body_text, body_html, from_address, from_display_name,
      reply_to, auth_results (dict with spf/dkim/dmarc -> 'pass'/'fail'/...),
      attachments (list), raw_headers (str)
    """
    feats = EmailFeatures()
    subject = email_record.get("subject") or ""
    body_text = email_record.get("body_text") or ""
    body_html = email_record.get("body_html") or ""
    combined = f"{subject}\n{body_text}"

    feats.subject_length = len(subject)
    feats.body_length = len(body_text)
    feats.num_exclamation_marks = combined.count("!")
    feats.has_generic_greeting = int(bool(_GENERIC_GREETING_RE.search(body_text)))
    feats.num_attachments = len(email_record.get("attachments") or [])
    feats.html_to_text_ratio = (len(body_html) / len(body_text)) if body_text else 0.0

    lowered = combined.lower()
    feats.urgency_keyword_count = sum(kw in lowered for kw in _URGENCY_WORDS)
    feats.has_urgency_language = int(feats.urgency_keyword_count > 0)

    subj_lower = subject.lower()
    feats.subject_has_re_fwd_spoof = int(
        (subj_lower.startswith("re:") or subj_lower.startswith("fwd:"))
        and "thread_id" not in email_record
    )

    urls = extract_urls(body_html) + extract_urls(body_text)
    urls = list(dict.fromkeys(urls))
    feats.num_urls = len(urls)
    if urls:
        url_feats = [extract_url_features(u) for u in urls]
        feats.max_url_suspicious_keyword_count = max(f.suspicious_keyword_count for f in url_feats)
        feats.mean_url_entropy = sum(f.domain_entropy for f in url_feats) / len(url_feats)
        feats.num_ip_host_urls = sum(f.has_ip_host for f in url_feats)

    auth = email_record.get("auth_results") or {}
    feats.has_spf_pass = int(str(auth.get("spf", "")).lower() == "pass")
    feats.has_dkim_pass = int(str(auth.get("dkim", "")).lower() == "pass")
    feats.has_dmarc_pass = int(str(auth.get("dmarc", "")).lower() == "pass")

    from_addr = email_record.get("from_address") or ""
    display_name = email_record.get("from_display_name") or ""
    reply_to = email_record.get("reply_to") or ""
    if display_name and "@" in display_name:
        feats.sender_display_name_mismatch = int(
            _domain_of(display_name) != _domain_of(from_addr)
        )
    feats.reply_to_differs_from_from = int(
        bool(reply_to) and _domain_of(reply_to) != _domain_of(from_addr)
    )

    return feats


def extract_email_features_dict(email_record: dict) -> dict:
    return extract_email_features(email_record).to_dict()
