"""Destination evidence for the links an email carries.

The email layer compares what a link *says* with where it *points*. It never
asks whether the destination is itself a phishing host, because it only ever saw
strings. That left the most common attack shape — innocuous prose, one link to a
brand-new typosquat — completely unexamined: with no page fetch, no domain
lookup and no ML pass for `input_type="email"`, a message whose only evidence is
its link scored exactly as if the link were clean.

This module closes that gap without opening the link:

* every http(s) href in the message is scored with the URL layer (pure string
  work: typosquatting, suspicious TLD, credentials in the URL, redirect
  parameters, homographs, IP hosts);
* the riskiest destination is chosen, so a single malicious link is not hidden
  behind twenty benign ones;
* its host is put through the same SSRF guard a user-typed target gets before any
  DNS/RDAP work happens;
* the page is deliberately **not** fetched. Opening a link server-side reports
  the message as read (tracking pixels and redirects), and the reader has not
  clicked it yet — so the destination's own content, forms and screenshot are
  disclosed as not examined rather than guessed at.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from app.analyzers.url.features import analyze_url
from app.core.security import HostUnresolvedError, SSRFBlockedError, guard_url
from app.schemas.analysis import LayerEvidence

# A newsletter can carry dozens of links and re-scoring every one is wasted work:
# the destination that matters is the worst one. Ten is enough to catch a
# malicious link buried in a footer without paying for the whole list.
MAX_LINKS_SCORED = 10
# How many ranked destinations are kept in the evidence. The report shows the
# strongest few; the rest are summarised by count.
MAX_LINKS_RECORDED = 5


def split_link(entry: str) -> tuple[str, str]:
    """`"text|href"` → `(text, href)`; a bare href comes back as `("", href)`.

    The extension sends the pair form whenever it can see the anchor text, which
    is what makes a label/href comparison possible at all.
    """
    text, separator, href = entry.partition("|")
    if not separator:
        return "", entry.strip()
    return text.strip(), href.strip()


def http_hrefs(links: list[str] | None) -> list[tuple[str, str]]:
    """Unique http(s) `(text, href)` pairs, in the order the message lists them."""
    seen: set[str] = set()
    pairs: list[tuple[str, str]] = []
    for entry in links or []:
        text, href = split_link(entry)
        if not href.lower().startswith(("http://", "https://")):
            continue
        if href in seen:
            continue
        seen.add(href)
        pairs.append((text, href))
    return pairs


async def analyze_email_links(
    links: list[str] | None, guard: bool = True
) -> dict | None:
    """Score the message's link destinations.

    Returns ``None`` when the message carries no http(s) link, otherwise::

        {
          "url_layer": LayerEvidence,   # layer="url", corroborative evidence
          "href": str,                  # the destination that was scored
          "text": str,                  # its visible label, if known
          "domain_host": str | None,    # host safe to look up, else None
        }

    The caller runs the domain layer for ``domain_host`` (network-bound, and
    therefore better placed next to the other concurrent layers). ``guard=False``
    exists for tests that must not resolve anything.
    """
    candidates = http_hrefs(links)
    if not candidates:
        return None

    scored: list[tuple[float, str, str, LayerEvidence]] = []
    for text, href in candidates[:MAX_LINKS_SCORED]:
        try:
            layer = analyze_url(href)
        except Exception:  # noqa: BLE001 - one malformed href must not fail the scan
            continue
        scored.append((layer.risk_score, text, href, layer))
    if not scored:
        return None

    # Highest risk wins; `max` is stable, so equal scores keep message order and
    # the report names the first such link rather than a random one.
    risk, text, href, url_layer = max(scored, key=lambda item: item[0])
    host = urlparse(href).hostname or ""

    domain_host: str | None = host or None
    guard_note: str | None = None
    if host and guard:
        try:
            await asyncio.to_thread(guard_url, href)
        except HostUnresolvedError:
            # Not a failed scan: a link the reader is asked to click that has no
            # DNS address cannot serve anything, which is worth saying out loud.
            # Deliberately *not* scored: a resolver hiccup on a healthy domain
            # looks identical from here, and this backend is often deployed with
            # a DNS path nobody has inspected. The URL layer already scores what
            # the string itself claims, so an unregistered typosquat still rises.
            domain_host = None
            guard_note = f"the link host {host} does not resolve"
            url_layer.details["dns_unresolved"] = True
            url_layer.indicators.append(
                f"Link destination {host} does not resolve to any address"
            )
        except SSRFBlockedError as exc:
            domain_host = None
            guard_note = f"the link host was not looked up ({exc})"
        except Exception as exc:  # noqa: BLE001 - resolution is best effort
            domain_host = None
            guard_note = f"the link host could not be resolved ({exc})"

    ranked = sorted(scored, key=lambda item: -item[0])
    url_layer.details = {
        **url_layer.details,
        # Marks this layer as evidence *about one part of the target* rather than
        # a second view of the target: the scoring engine lets it raise the
        # verdict, never average it down (see scoring/engine.py).
        "source": "email_link",
        "corroborative": True,
        "email_href": href,
        "email_link_text": text or None,
        "links_in_message": len(candidates),
        "links_scored": len(scored),
        "link_destinations": [
            {"text": label or None, "href": link, "risk": round(link_risk, 2)}
            for link_risk, label, link, _ in ranked[:MAX_LINKS_RECORDED]
        ],
        "page_fetched": False,
    }

    notes = [
        "Scored as the destination of a link in the message, not as the message's own page.",
        "The link was not opened: reading it server-side would report the message as read "
        "to its sender, so the destination's own content, forms and screenshot are not part "
        "of this verdict.",
    ]
    if guard_note:
        notes.append(guard_note[0].upper() + guard_note[1:] + ".")
    url_layer.notes = " ".join(notes)

    return {"url_layer": url_layer, "href": href, "text": text, "domain_host": domain_host}
