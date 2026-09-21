"""Domain intelligence: RDAP, DNS/nameservers, TLS certificate, domain age."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

import httpx
import tldextract

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.analysis import LayerEvidence

logger = get_logger(__name__)

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
NEW_DOMAIN_DAYS = 90
# rdap.org never answers a query itself: it 302-redirects to the authoritative
# registry RDAP server (e.g. rdap.publicinterestregistry.org for .org). With
# httpx's default `follow_redirects=False` every lookup therefore came back 302
# and was recorded as `not_found`, so `domain_age_days` was *always* null and
# the domain layer reported "Domain age could not be determined" for every
# target, including domains registered in 2001.
RDAP_MAX_REDIRECTS = 5


def _registered_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    return ext.registered_domain or hostname


def _extract_registration_event(data: dict) -> str | None:
    """Return the registration date from an RDAP domain object.

    RFC 9083 spells the event action `registration`; a few registries use the
    legacy synonym `registered`, and a handful expose only `created`. Accept
    all three rather than silently reporting an unknown age.
    """
    for event in data.get("events", []) or []:
        action = (event.get("eventAction") or "").lower()
        if action in {"registration", "registered", "created", "domain registration"}:
            return event.get("eventDate")
    return None


async def _rdap_lookup(domain: str, timeout: float) -> dict:
    result = {"status": "unavailable", "created": None, "raw": None}
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, max_redirects=RDAP_MAX_REDIRECTS
        ) as client:
            resp = await client.get(
                RDAP_BOOTSTRAP.format(domain=domain),
                headers={"Accept": "application/rdap+json, application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                created = _extract_registration_event(data)
                result = {
                    "status": "ok",
                    "created": created,
                    "raw": {"handle": data.get("handle"), "ldhName": data.get("ldhName")},
                }
            elif resp.status_code == 404:
                # Genuine "no RDAP record" (unregistered/newly delegated).
                result = {"status": "not_found", "created": None, "raw": None}
            else:
                result = {"status": "unavailable", "created": None, "raw": None}
    except Exception as exc:  # noqa: BLE001
        logger.info("RDAP lookup failed", extra={"extra_fields": {"domain": domain, "error": str(exc)}})
        result = {"status": "unavailable", "created": None, "raw": None}
    return result


def _dns_lookup(hostname: str) -> dict:
    info = {"status": "unavailable", "addresses": [], "nameservers": []}
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(hostname, None)})
        info["addresses"] = addrs
        info["status"] = "ok"
    except Exception as exc:  # noqa: BLE001
        logger.info("DNS A-record lookup failed", extra={"extra_fields": {"hostname": hostname, "error": str(exc)}})
        return info
    try:
        ns = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        info["nameservers"] = []  # socket module can't fetch NS records without dnspython
    except Exception:  # noqa: BLE001
        pass
    return info


def _tls_lookup(hostname: str, timeout: float) -> dict:
    info = {"status": "unavailable", "issuer": None, "not_after": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                info = {
                    "status": "ok",
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "not_after": cert.get("notAfter"),
                }
    except Exception as exc:  # noqa: BLE001
        logger.info("TLS lookup failed", extra={"extra_fields": {"hostname": hostname, "error": str(exc)}})
    return info


def _domain_age_days(created_iso: str | None) -> int | None:
    if not created_iso:
        return None
    try:
        created = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - created).days
    except Exception:  # noqa: BLE001
        return None


async def analyze_domain(hostname: str, timeout: float | None = None) -> LayerEvidence:
    settings = get_settings()
    timeout = timeout or settings.ANALYSIS_TIMEOUT_SECONDS
    degraded: list[str] = []
    indicators: list[str] = []
    score = 0.0

    domain = _registered_domain(hostname)
    is_punycode = "xn--" in hostname.lower()

    # RDAP (network) and TLS (blocking socket handshake) are independent, so
    # run them concurrently and keep DNS off the event loop. Sequentially they
    # cost up to 8s + 5s of the per-layer budget for no reason.
    rdap, tls_info = await asyncio.gather(
        _rdap_lookup(domain, timeout=min(timeout, 8.0)),
        asyncio.to_thread(_tls_lookup, hostname, min(timeout, 5.0)),
    )
    if rdap["status"] == "unavailable":
        degraded.append("domain.rdap")
    dns_info = await asyncio.to_thread(_dns_lookup, hostname)
    if dns_info["status"] == "unavailable":
        degraded.append("domain.dns")
    if tls_info["status"] == "unavailable":
        degraded.append("domain.tls")

    age_days = _domain_age_days(rdap.get("created"))
    if age_days is not None and age_days < NEW_DOMAIN_DAYS:
        score += 30
        indicators.append(f"Domain registered recently ({age_days} days ago)")
    elif age_days is not None:
        years = age_days / 365.25
        indicators.append(f"Domain registered {years:.1f} years ago")
    else:
        indicators.append("Domain age could not be determined")

    if is_punycode:
        score += 12
        indicators.append("Registered domain uses punycode encoding")

    if tls_info["status"] != "ok":
        score += 8
        indicators.append("Could not establish a valid TLS certificate")

    if dns_info["status"] != "ok":
        score += 5
        indicators.append("DNS resolution unavailable/failed for this host")

    score = max(0.0, min(100.0, score))
    details = {
        "registered_domain": domain,
        "rdap": rdap,
        "dns": dns_info,
        "tls": tls_info,
        "domain_age_days": age_days,
        "is_punycode": is_punycode,
    }
    return LayerEvidence(
        layer="domain",
        risk_score=score,
        indicators=indicators,
        details=details,
        unavailable=len(degraded) == 3,
        notes="; ".join(degraded) if degraded else None,
    )
