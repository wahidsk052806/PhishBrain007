"""Webpage content analysis: forms, credential fields, resources, redirects."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx
import tldextract
from bs4 import BeautifulSoup

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import SSRFBlockedError, enforce_size_cap, guard_url
from app.schemas.analysis import LayerEvidence

logger = get_logger(__name__)

CREDENTIAL_FIELD_PATTERNS = ["password", "passwd", "pwd", "otp", "one-time", "one_time", "cvv", "cvc", "card"]
OBFUSCATION_PATTERNS = [
    r"eval\s*\(", r"unescape\s*\(", r"fromCharCode", r"document\.write\s*\(",
    r"atob\s*\(", r"String\.fromCharCode",
]


def fetch_headers() -> dict[str, str]:
    """Browser-ish request headers for fetching a target page.

    Library-default headers get refused by a large share of the web, and a
    refusal body parsed as page content is worse than no fetch at all: it makes
    the webpage layer report a clean bill of health for a page it never read.
    """
    settings = get_settings()
    return {
        "User-Agent": settings.FETCH_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": settings.FETCH_ACCEPT_LANGUAGE,
    }


async def fetch_page(url: str, timeout: float, max_bytes: int) -> tuple[str | None, list[str]]:
    """Fetch a page HTML with SSRF guard + size cap. Never raises.

    Returns (html, degraded). `html` is None whenever the page could not be
    read, including for a non-2xx response: a 403/404/500 body is the server's
    notice, not the page, and analysing it produced silent false negatives.
    """
    degraded: list[str] = []
    try:
        guard_url(url)
    except SSRFBlockedError as exc:
        logger.warning("Blocked SSRF-unsafe fetch", extra={"extra_fields": {"url": url, "error": str(exc)}})
        degraded.append("webpage.fetch_blocked")
        return None, degraded

    try:
        async with httpx.AsyncClient(
            # Connect gets its own, shorter budget. A host that is unreachable
            # (firewalled, geo-blocked, off) does not answer a SYN at all, and
            # letting the *whole* layer timeout be the connect timeout meant a
            # dead host cost 20s+ before the scan could say so.
            timeout=httpx.Timeout(timeout, connect=min(8.0, timeout)),
            follow_redirects=True,
            max_redirects=3,
            headers=fetch_headers(),
        ) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code >= 400:
                    logger.info(
                        "Page fetch returned an error status",
                        extra={"extra_fields": {"url": url, "status": resp.status_code}},
                    )
                    degraded.append(f"webpage.http_{resp.status_code}")
                    return None, degraded
                chunks = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        degraded.append("webpage.truncated")
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)
                return body.decode(resp.encoding or "utf-8", errors="replace"), degraded
    except Exception as exc:  # noqa: BLE001
        # The failure *kind* is carried in the code so the report can explain
        # what actually happened. "webpage.fetch_failed" alone sent a reader
        # looking for a bug in the scanner when the real answer was "this host
        # does not answer us", and it skipped the browser capture phase without
        # saying why.
        reason = type(exc).__name__
        logger.info("Page fetch failed", extra={"extra_fields": {"url": url, "error": str(exc)}})
        degraded.append(f"webpage.fetch_failed:{reason}")
        return None, degraded


def _has_credential_field(soup: BeautifulSoup) -> list[str]:
    hits = []
    for inp in soup.find_all("input"):
        attrs = " ".join([
            str(inp.get("type", "")), str(inp.get("name", "")), str(inp.get("id", "")),
            str(inp.get("placeholder", "")),
        ]).lower()
        for pattern in CREDENTIAL_FIELD_PATTERNS:
            if pattern in attrs:
                hits.append(pattern)
    return sorted(set(hits))


def analyze_html(html_content: str, page_url: str, brands: list[str] | None = None) -> LayerEvidence:
    settings = get_settings()
    brands = brands if brands is not None else settings.brands
    indicators: list[str] = []
    score = 0.0
    details: dict = {}

    try:
        enforce_size_cap(html_content, settings.MAX_FETCH_BYTES)
    except ValueError:
        html_content = html_content[: settings.MAX_FETCH_BYTES]

    soup = BeautifulSoup(html_content or "", "html.parser")
    parsed_page = urlparse(page_url)
    page_domain = tldextract.extract(page_url).registered_domain

    forms = soup.find_all("form")
    credential_fields = _has_credential_field(soup)
    if credential_fields:
        score += 20
        indicators.append(f"Page requests credential-like fields: {', '.join(credential_fields)}")

    insecure_form_targets = []
    for form in forms:
        action = form.get("action") or ""
        if action:
            full = urljoin(page_url, action)
            if urlparse(full).scheme == "http" and parsed_page.scheme == "https":
                insecure_form_targets.append(full)
            action_domain = tldextract.extract(full).registered_domain
            if action_domain and page_domain and action_domain != page_domain:
                score += 15
                indicators.append(f"Form submits to a different domain: {action_domain}")
    if insecure_form_targets:
        score += 10
        indicators.append("Form submits credentials over insecure HTTP")

    external_resources = 0
    for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")):
        for el in soup.find_all(tag):
            src = el.get(attr)
            if not src:
                continue
            full = urljoin(page_url, src)
            res_domain = tldextract.extract(full).registered_domain
            if res_domain and page_domain and res_domain != page_domain:
                external_resources += 1
    if external_resources > 10:
        score += 8
        indicators.append(f"Large number of externally hosted resources ({external_resources})")
    details["external_resource_count"] = external_resources

    iframes = soup.find_all("iframe")
    if iframes:
        score += 6
        indicators.append(f"Page embeds {len(iframes)} iframe(s)")

    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if meta_refresh:
        score += 10
        indicators.append("Page uses meta-refresh redirect")

    obfuscated_hits = 0
    for script in soup.find_all("script"):
        text = script.string or ""
        for pattern in OBFUSCATION_PATTERNS:
            if re.search(pattern, text):
                obfuscated_hits += 1
    if obfuscated_hits:
        score += min(15, obfuscated_hits * 5)
        indicators.append("Inline JavaScript contains obfuscation-style patterns")

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    favicon = None
    icon_tag = soup.find("link", rel=re.compile("icon", re.I))
    if icon_tag and icon_tag.get("href"):
        favicon = urljoin(page_url, icon_tag["href"])

    # Impersonation is a *claim*, not a mention.
    #
    # This used to fire on any occurrence of a brand name anywhere in the HTML,
    # which flagged every legitimate page that links to other companies:
    # github.com/login was scored 48/100 SUSPICIOUS purely because its page
    # mentions "google", "microsoft" and "amazon" — in its SSO buttons and
    # footer links. A page impersonates a brand when it *presents itself* as
    # that brand and asks for a secret: the brand name in the title or a
    # heading, plus a credential-like field. Body mentions are recorded for
    # transparency but no longer score on their own.
    brand_mentions = [b for b in brands if b in (html_content or "").lower()]
    heading_text = " ".join(
        tag.get_text(" ", strip=True) for tag in soup.find_all(["h1", "h2", "h3"])
    ).lower()
    title_lower = title.lower()
    brands_claimed = [b for b in brands if b in title_lower or b in heading_text]
    brand_domain_mismatch = False
    if brands_claimed and credential_fields and page_domain:
        for b in brands_claimed:
            if b not in page_domain.lower():
                brand_domain_mismatch = True
                break
    if brand_domain_mismatch:
        score += 20
        indicators.append(
            f"Page presents itself as {brands_claimed} (title/heading) and asks for credentials, "
            f"but is served from '{page_domain}'"
        )

    if parsed_page.scheme != "https":
        score += 6
        indicators.append("Page is not served over HTTPS")

    details.update({
        "title": title,
        "favicon": favicon,
        "form_count": len(forms),
        "credential_fields": credential_fields,
        "iframe_count": len(iframes),
        "meta_refresh": bool(meta_refresh),
        "brand_mentions": brand_mentions,
        "brands_claimed": brands_claimed,
        "brand_domain_mismatch": brand_domain_mismatch,
        "page_domain": page_domain,
        "is_https": parsed_page.scheme == "https",
    })

    score = max(0.0, min(100.0, score))
    return LayerEvidence(layer="webpage", risk_score=score, indicators=indicators, details=details, unavailable=False)


def build_llm_page_digest(html_content: str, page_url: str, max_chars: int = 1200) -> str:
    """Condense a fetched page into the security-relevant facts, for the LLM.

    Feeding the model raw page prose is both the wrong input and the wrong
    cost: on CPU, prefill dominates the scan (measured: a 4,000-character
    Wikipedia extract took 101s, a 1,200-character digest 29s, no page at all
    25s). A phishing verdict depends on what the page *asks for* — which fields,
    which brand, where the form posts — not on article text, and those facts fit
    in a few hundred characters.

    Visible text is still included, truncated, because social-engineering
    wording is a real signal; it is just not allowed to own the budget.
    """
    if not html_content:
        return ""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:  # noqa: BLE001
        return ""

    page_domain = tldextract.extract(page_url).registered_domain
    lines: list[str] = [f"page_url: {page_url}"]

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    if title:
        lines.append(f"title: {title[:120]}")

    forms = soup.find_all("form")
    if forms:
        actions = []
        for form in forms[:3]:
            action = form.get("action") or "(none)"
            full = urljoin(page_url, action) if action != "(none)" else ""
            action_domain = tldextract.extract(full).registered_domain if full else ""
            marker = "" if (not action_domain or action_domain == page_domain) else " [external]"
            actions.append(f"{action[:60]}{marker}")
        lines.append(f"forms: {len(forms)} -> {'; '.join(actions)}")

    # Only credential-relevant inputs. A nav-heavy page is otherwise full of
    # checkboxes and hidden fields that say nothing about intent while eating
    # the whole budget (the first version of this digest did exactly that).
    _INTERESTING_INPUTS = {"text", "password", "email", "tel", "number", "search", "url"}
    seen_fields: list[str] = []
    password_fields = 0
    for inp in soup.find_all("input"):
        itype = str(inp.get("type", "text")).lower()
        if itype in ("hidden", "checkbox", "radio", "submit", "button", "image"):
            continue
        if itype == "password":
            password_fields += 1
        if itype not in _INTERESTING_INPUTS and itype != "password":
            continue
        descriptor = inp.get("name") or inp.get("id") or inp.get("placeholder") or itype
        value = f"{itype}:{str(descriptor)[:24]}"
        if value not in seen_fields:
            seen_fields.append(value)
        if len(seen_fields) >= 8:
            break
    if seen_fields:
        lines.append(f"input_fields: {', '.join(seen_fields)}")
    if password_fields:
        lines.append(f"password_fields: {password_fields}")

    # Buy a fixed share of the budget for visible copy: social-engineering
    # wording is real evidence, but it must not crowd out the structure above.
    text_budget = min(400, max(0, max_chars // 3))
    text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
    if text and text_budget:
        lines.append(f"visible_text: {text[:text_budget]}")

    # Distinguish a brand the page *claims* to be from one it merely links to.
    # Passing an undifferentiated mention list to the model invited it to read
    # "links to google/microsoft" (an SSO button) as "pretends to be google".
    brands = [b for b in get_settings().brands if b in (html_content or "").lower()]
    if brands:
        heading_text = " ".join(
            tag.get_text(" ", strip=True) for tag in soup.find_all(["h1", "h2", "h3"])
        ).lower()
        title_lower = (soup.title.get_text(strip=True) if soup.title else "").lower()
        claimed = [b for b in brands if b in title_lower or b in heading_text]
        if claimed:
            lines.append(f"brands_claimed: {', '.join(claimed)}")
        else:
            lines.append(f"brand_mentions_in_body: {', '.join(brands)}")

    for img in soup.find_all("img")[:4]:
        alt = (img.get("alt") or "").strip()
        src = (img.get("src") or "").strip()
        if alt or src:
            lines.append(f"img: alt={alt[:30]!r} src={(src.split('/')[-1] or '')[:40]!r}")

    if soup.find("iframe"):
        lines.append(f"iframes: {len(soup.find_all('iframe'))}")
    if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        lines.append("meta_refresh: yes")

    return "\n".join(lines)[:max_chars]


async def analyze_webpage(
    url: str,
    html_content: str | None = None,
    dom_summary: str | None = None,
    fetch_page_flag: bool = False,
    timeout: float | None = None,
) -> LayerEvidence:
    settings = get_settings()
    timeout = timeout or settings.ANALYSIS_TIMEOUT_SECONDS
    degraded: list[str] = []

    if not html_content and fetch_page_flag:
        html_content, fetch_degraded = await fetch_page(url, timeout=timeout, max_bytes=settings.MAX_FETCH_BYTES)
        degraded.extend(fetch_degraded)

    if not html_content and dom_summary:
        # Build a very small synthetic HTML wrapper so BeautifulSoup can still
        # extract textual signals from a caller-supplied DOM summary.
        html_content = f"<html><body>{dom_summary}</body></html>"

    if not html_content:
        return LayerEvidence(
            layer="webpage",
            risk_score=0.0,
            indicators=[],
            details={},
            unavailable=True,
            notes="No page content available (fetch disabled/failed and no DOM summary supplied)",
        )

    evidence = analyze_html(html_content, url)
    if degraded:
        evidence.notes = ((evidence.notes + "; ") if evidence.notes else "") + "; ".join(degraded)
    return evidence
