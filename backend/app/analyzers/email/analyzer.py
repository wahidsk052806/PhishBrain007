"""Email content & header analysis: spoofing, social-engineering language, SPF/DKIM/DMARC."""
from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

from app.core.config import get_settings
from app.schemas.analysis import LayerEvidence

URGENCY_TERMS = ["urgent", "immediately", "act now", "expire", "within 24 hours", "final notice", "asap"]
THREAT_TERMS = ["suspend", "terminate", "legal action", "penalty", "unauthorized access", "locked", "closed"]
CREDENTIAL_TERMS = ["verify your account", "confirm your password", "login to continue", "reset your password", "update your billing"]
FINANCIAL_TERMS = ["wire transfer", "bank account", "invoice attached", "payment required", "gift card", "cryptocurrency", "bitcoin"]
PRIZE_TERMS = ["you have won", "claim your prize", "lottery", "free gift", "reward waiting"]

WEIGHTS = {
    "urgency": 6,
    "threat": 8,
    "credential": 10,
    "financial": 8,
    "prize": 10,
}


def _term_hits(text: str, terms: list[str]) -> list[str]:
    lowered = text.lower()
    return [t for t in terms if t in lowered]


def _extract_domain(address: str) -> str:
    """Registrable domain of an email address *or* URL, with a host fallback.

    `tldextract` returns an empty `registered_domain` whenever the suffix is not
    in the public-suffix list — common with phishing on cheap or newly delegated
    TLDs. Returning "" there made every spoofing comparison silently no-op
    (an empty domain fails the `sender_domain and ...` guard), so a `.tld`
    sender was treated as unparseable rather than suspicious. Fall back to the
    host itself, which still separates "paypal.com" from "paypal-secure.top".
    """
    if not address:
        return ""
    match = re.search(r"@([\w.-]+)", address)
    raw = match.group(1) if match else address
    # Strip scheme, credentials, port and path so URLs are handled too.
    raw = raw.split("://")[-1].split("@")[-1].split("/")[0].split("?")[0]
    host = raw.split(":")[0].strip(".").lower()
    if not host:
        return ""
    ext = tldextract.extract(host)
    return ext.registered_domain or host


def _parse_auth_header(raw_headers: str | None, mechanism: str) -> str:
    if not raw_headers:
        return "Not available from browser context"
    match = re.search(rf"{mechanism}=([a-zA-Z]+)", raw_headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return "not_found"


def analyze_email(
    sender: str,
    reply_to: str | None,
    display_name: str | None,
    subject: str,
    body: str,
    links: list[str] | None = None,
    raw_headers: str | None = None,
    has_attachments: bool = False,
) -> LayerEvidence:
    settings = get_settings()
    links = links or []
    indicators: list[str] = []
    score = 0.0
    text = f"{subject}\n{body}"

    sender_domain = _extract_domain(sender)
    reply_domain = _extract_domain(reply_to) if reply_to else ""

    if reply_to and reply_domain and sender_domain and reply_domain != sender_domain:
        score += 18
        indicators.append(f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})")

    if display_name:
        for brand in settings.brands:
            if brand in display_name.lower() and sender_domain and brand not in sender_domain.lower():
                score += 20
                indicators.append(f"Display name references '{brand}' but sender domain is '{sender_domain}'")
                break

    urgency_hits = _term_hits(text, URGENCY_TERMS)
    threat_hits = _term_hits(text, THREAT_TERMS)
    credential_hits = _term_hits(text, CREDENTIAL_TERMS)
    financial_hits = _term_hits(text, FINANCIAL_TERMS)
    prize_hits = _term_hits(text, PRIZE_TERMS)

    for name, hits in (
        ("urgency", urgency_hits), ("threat", threat_hits), ("credential", credential_hits),
        ("financial", financial_hits), ("prize", prize_hits),
    ):
        if hits:
            score += min(WEIGHTS[name] * len(hits), WEIGHTS[name] * 3)
            indicators.append(f"{name.capitalize()} language detected: {', '.join(hits[:3])}")

    # Link text vs href mismatch requires paired data, so links are passed as
    # "text|href" when the caller has both. Plain hrefs carry no text to compare
    # and are skipped.
    mismatched_links = 0
    for link in links:
        if "|" in link:
            text_part, _, href_part = link.partition("|")
            text_domain = _extract_domain(text_part)
            href_domain = _extract_domain(href_part)
            if text_domain and href_domain and text_domain != href_domain:
                mismatched_links += 1
    if mismatched_links:
        score += 20
        indicators.append(f"{mismatched_links} link(s) have visible text domain mismatched with actual href")

    brand_domain_mismatch = False
    for brand in settings.brands:
        if brand in text.lower() and sender_domain and brand not in sender_domain.lower():
            brand_domain_mismatch = True
            break
    if brand_domain_mismatch:
        score += 12
        indicators.append("Email references a brand not matching the sending domain")

    if has_attachments and (credential_hits or financial_hits or threat_hits):
        score += 8
        indicators.append("Attachment present alongside high-pressure/financial language")

    spf = _parse_auth_header(raw_headers, "spf")
    dkim = _parse_auth_header(raw_headers, "dkim")
    dmarc = _parse_auth_header(raw_headers, "dmarc")
    for label, result in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
        if result == "fail":
            score += 15
            indicators.append(f"{label} authentication failed")

    score = max(0.0, min(100.0, score))
    details = {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "urgency_hits": urgency_hits,
        "threat_hits": threat_hits,
        "credential_hits": credential_hits,
        "financial_hits": financial_hits,
        "prize_hits": prize_hits,
        "mismatched_links": mismatched_links,
        "brand_domain_mismatch": brand_domain_mismatch,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "has_attachments": has_attachments,
    }
    return LayerEvidence(layer="email", risk_score=score, indicators=indicators, details=details, unavailable=False)
