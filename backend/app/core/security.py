"""Security helpers: SSRF guarding, HTML sanitization, prompt sanitization."""
from __future__ import annotations

import html
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from app.core.config import get_settings

INTERNAL_HOSTNAME_PATTERNS = (
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
)

PROMPT_INJECTION_MARKERS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard the above",
    "system prompt",
    "you are now",
    "act as",
    "new instructions",
    "</data>",
    "<data>",
    "```system",
]


# IPv6 prefixes that *carry* an IPv4 address rather than being a real IPv6
# destination. They matter because `ipaddress` classifies them as
# reserved/private, so a naive check rejects them — while the address they
# actually route to is often an ordinary public IPv4 host. That produced a
# false positive on any NAT64/DNS64 network: e.g. www.paypal.com resolved to
# `64:ff9b::9765:9d15`, which is the public address 151.101.157.21 behind
# 64:ff9b::/96, and every such URL was refused with "resolves to blocked
# address" — leaving the dashboard to fall back to its model-less built-in
# scanner. The guard must judge the *embedded* address, not the wrapper.
NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")  # RFC 6052
NAT64_LOCAL_USE = ipaddress.IPv6Network("64:ff9b:1::/48")  # RFC 8215
SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")  # RFC 3056


class SSRFBlockedError(Exception):
    """Raised when a URL/host fails the SSRF safety checks."""


@dataclass
class ResolvedHost:
    hostname: str
    ip_addresses: list[str]


def _is_blocked_v4(ip: ipaddress.IPv4Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address a transition/translation address routes to.

    Handles IPv4-mapped (`::ffff:a.b.c.d`), NAT64 well-known and local-use
    prefixes, and 6to4. Returns None for a genuine IPv6 destination, and also
    for malformed NAT64 local-use addresses (whose middle 16 bits must be zero,
    per RFC 8215) so an unrecognised form is never silently trusted.
    """
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    if ip in NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in NAT64_LOCAL_USE:
        # 64:ff9b:1::/48 prefixes a 16-bit reserved field (RFC 8215) before the
        # IPv4 in the last 32 bits. Require every bit between the prefix and the
        # IPv4 to be zero, so a non-conforming form is blocked rather than
        # trusted with a half-parsed address.
        if (int(ip) >> 32) & ((1 << 48) - 1):
            return None
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in SIX_TO_FOUR:
        # 2002:<IPv4>:<subnet id>:... - the IPv4 sits in bits 16..47.
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            # Judge where the address actually leads, not the wrapper.
            return _is_blocked_v4(embedded)
    return _is_blocked_v4(ip) if isinstance(ip, ipaddress.IPv4Address) else (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


# Schemes a human may legitimately paste that are *not* web targets. They are
# left untouched so `validate_scheme` refuses them by name rather than the
# normaliser silently rewriting `javascript:alert(1)` into a hostname and
# attempting to scan it.
NON_WEB_SCHEMES = (
    "javascript",
    "data",
    "file",
    "ftp",
    "ftps",
    "blob",
    "about",
    "chrome",
    "mailto",
    "tel",
    "sms",
    "ws",
    "wss",
    "view-source",
)

_MAX_TARGET_CHARS = 2048


def normalize_url_input(raw: str) -> str:
    """Turn what a person actually types into an absolute http(s) URL.

    Nothing used to do this, so typing a bare host — `hianime.to` — reached the
    SSRF guard as a scheme-less string and the scan was refused outright with
    `Scheme '' is not allowed`. Rejecting `hianime.to` while accepting
    `https://hianime.to` is not a security decision, it is an input-parsing
    gap: every browser address bar, and every competing scanner, accepts the
    host form. Normalising here means every caller (dashboard, extension,
    curl) gets the same behaviour.

    Rules, in order:
      * `host[:port][/path...]`            -> `https://` + that
      * `//host/path` (protocol-relative)   -> `https://host/path`
      * `https:/host` / `http:/host` typos  -> `https://host`
      * an explicit `http(s)://` URL        -> unchanged
      * a known non-web scheme              -> unchanged, so the guard still
        rejects it with a message naming the scheme

    A pasted sentence ("scan example.com now") is reduced to the one token that
    is shaped like a target, rather than blindly taking the first word: the
    alternative was a confusing "host does not resolve" for a word that was
    never a host.
    """
    if not isinstance(raw, str):
        return ""
    text = raw.strip().strip("<>").strip().strip('"').strip("'").strip()
    if not text:
        return ""
    text = text[:_MAX_TARGET_CHARS]
    tokens = text.split()
    if len(tokens) > 1:
        text = (
            next((t for t in tokens if re.match(r"^(https?://|//)", t, re.IGNORECASE)), None)
            or next((t for t in tokens if "." in t and not t.startswith(".")), None)
            or tokens[0]
        )

    lowered = text.lower()
    for scheme in NON_WEB_SCHEMES:
        if lowered.startswith(f"{scheme}:"):
            return text

    explicit = re.match(r"^(https?):(/*)(.*)$", text, re.IGNORECASE)
    if explicit:
        scheme, slashes, rest = explicit.group(1).lower(), explicit.group(2), explicit.group(3)
        if slashes == "//" and rest:
            return f"{scheme}://{rest}"
        # `https:/host`, `https:host` or a bare `https:` are all typos for a
        # web URL; repair them instead of failing with no explanation.
        if rest:
            return f"{scheme}://{rest.lstrip('/')}"
        return text

    if text.startswith("//"):
        return f"https:{text}"

    return f"https://{text}"


def validate_scheme(url: str) -> str:
    settings = get_settings()
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in settings.allowed_schemes:
        raise SSRFBlockedError(
            f"Scheme '{scheme}' is not allowed (this scanner only accepts "
            f"{', '.join(settings.allowed_schemes)})"
        )
    return scheme


def resolve_and_guard_host(url: str) -> ResolvedHost:
    """Resolve a URL's host and reject anything pointing at internal
    infrastructure. Never raises for unexpected errors other than the
    dedicated SSRFBlockedError."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname")

    lowered = hostname.lower().rstrip(".")
    if lowered in INTERNAL_HOSTNAME_PATTERNS or lowered.endswith(".local") or lowered.endswith(".internal"):
        raise SSRFBlockedError(f"Internal hostname blocked: {hostname}")

    # If hostname is already a literal IP, validate directly.
    try:
        ipaddress.ip_address(hostname)
        if _is_private_ip(hostname):
            raise SSRFBlockedError(f"Blocked private/reserved IP literal: {hostname}")
        return ResolvedHost(hostname=hostname, ip_addresses=[hostname])
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {exc}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise SSRFBlockedError(f"No addresses resolved for {hostname}")

    for ip in ips:
        if _is_private_ip(ip):
            raise SSRFBlockedError(f"{hostname} resolves to blocked address {ip}")

    return ResolvedHost(hostname=hostname, ip_addresses=ips)


def guard_url(url: str) -> ResolvedHost:
    """Full SSRF guard: validates scheme then resolves & checks host."""
    validate_scheme(url)
    return resolve_and_guard_host(url)


def guard_user_target(raw: str) -> tuple[str, ResolvedHost]:
    """Normalise a user-supplied target and guard it, returning both.

    Callers must scan the *returned* URL, not the raw input: the normalised
    form is what was validated and what the report will name as the target.
    """
    url = normalize_url_input(raw)
    if not url:
        raise SSRFBlockedError("No URL supplied")
    return url, guard_url(url)


def enforce_size_cap(data: bytes | str, max_bytes: int) -> None:
    size = len(data.encode("utf-8")) if isinstance(data, str) else len(data)
    if size > max_bytes:
        raise ValueError(f"Payload of {size} bytes exceeds cap of {max_bytes} bytes")


_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)


def sanitize_html_to_text(raw_html: str, max_chars: int = 20000) -> str:
    """Strip scripts/styles/tags and unescape entities, producing safe plain text."""
    if not raw_html:
        return ""
    cleaned = _SCRIPT_STYLE_RE.sub(" ", raw_html)
    cleaned = _TAG_RE.sub(" ", cleaned)
    cleaned = html.unescape(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_chars]


def sanitize_prompt_text(text: str, max_chars: int = 8000) -> str:
    """Neutralize prompt-injection markers and clearly delimit untrusted data
    before it is embedded into an LLM prompt."""
    if not text:
        return ""
    cleaned = text[:max_chars]
    cleaned = cleaned.replace("```", "'''")
    for marker in PROMPT_INJECTION_MARKERS:
        pattern = re.compile(re.escape(marker), re.IGNORECASE)
        cleaned = pattern.sub("[neutralized]", cleaned)
    # Collapse repeated control-ish chars often used in injection attempts.
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    return cleaned


def delimit_untrusted(label: str, text: str) -> str:
    safe = sanitize_prompt_text(text)
    return f"<<<BEGIN_UNTRUSTED_{label}>>>\n{safe}\n<<<END_UNTRUSTED_{label}>>>"
