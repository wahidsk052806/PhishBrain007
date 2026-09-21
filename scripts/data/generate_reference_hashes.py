"""Build the visual brand-clone reference set in data/reference_hashes.json.

Run this on a machine with Playwright + Chromium installed (the same setup the
backend needs for the visual layer). Two kinds of reference are collected per
brand, because they are good at very different things:

* **icons** (`favicons`) — the brand's favicon/logo file. This is the signal
  that actually identifies a brand clone. The artefact is a small static file:
  an exact copy (which is what a phishing kit serves, copied or hotlinked)
  hashes to distance 0, while *distinct* brand icons sit 20+ bits apart. The
  backend only names a brand within 8 bits.
* **screenshots** (`references`) — homepage and sign-in page captures. Kept as
  a coarse similarity figure. A live page's own screenshot can drift 30+ bits
  from its stored reference because hero art, consent banners and A/B layouts
  change, so this is advisory and never names a brand on its own if the closest
  two brands are close together.

    python scripts/data/generate_reference_hashes.py
    python scripts/data/generate_reference_hashes.py --brand paypal --brand chase
    python scripts/data/generate_reference_hashes.py --dry-run     # list only
    python scripts/data/generate_reference_hashes.py --refresh     # re-capture

Progress is written after every capture, so an interrupted run resumes instead
of discarding what it already collected. The brand list comes from the backend's
configured BRAND_LIST so the two cannot drift apart.
"""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import imagehash  # type: ignore[import-untyped]
from PIL import Image
from playwright.async_api import async_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = REPO_ROOT / "data" / "reference_hashes.json"

# Homepage first (stable, rarely behind a bot wall), then the real sign-in page.
BRAND_REFERENCE_URLS: dict[str, list[str]] = {
    "paypal": ["https://www.paypal.com/", "https://www.paypal.com/signin"],
    "microsoft": ["https://www.microsoft.com/", "https://login.microsoftonline.com/"],
    "apple": ["https://www.apple.com/", "https://appleid.apple.com/sign-in"],
    "google": ["https://www.google.com/", "https://accounts.google.com/signin"],
    "amazon": ["https://www.amazon.com/", "https://www.amazon.com/ap/signin"],
    "facebook": ["https://www.facebook.com/", "https://www.facebook.com/login"],
    "netflix": ["https://www.netflix.com/", "https://www.netflix.com/login"],
    "bankofamerica": [
        "https://www.bankofamerica.com/",
        "https://www.bankofamerica.com/online-banking/sign-in/",
    ],
    "chase": ["https://www.chase.com/", "https://www.chase.com/digital/online-banking"],
    "wellsfargo": [
        "https://www.wellsfargo.com/",
        "https://connect.secure.wellsfargo.com/auth/login/present",
    ],
    "dropbox": ["https://www.dropbox.com/", "https://www.dropbox.com/login"],
    "linkedin": ["https://www.linkedin.com/", "https://www.linkedin.com/login"],
    "instagram": [
        "https://www.instagram.com/",
        "https://www.instagram.com/accounts/login/",
    ],
    "docusign": ["https://www.docusign.com/", "https://account.docusign.com/"],
    "adobe": ["https://www.adobe.com/", "https://auth.services.adobe.com/en_US/sign-in"],
    "outlook": ["https://outlook.live.com/", "https://login.live.com/"],
    "office365": ["https://www.office.com/", "https://login.microsoftonline.com/"],
}

VIEWPORT = {"width": 1280, "height": 800}
# Playwright's default UA announces "HeadlessChrome", which several brand sites
# (Adobe, Amazon) answer with a bot wall or a redirect loop instead of the real
# page. Presenting the same Chromium as an ordinary browser is the difference
# between capturing the sign-in form and capturing nothing.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
# Cookie banners and hero animations settle late; a fixed pause keeps captures
# closer to each other between runs than `networkidle` (which never fires on
# pages with long-polling ads) or an immediate screenshot.
SETTLE_MS = 3000
DEFAULT_TIMEOUT_MS = 25000

# Ask the page for its declared icon, preferring the larger apple-touch icon,
# which pHashes far more stably than a 16x16 favicon.
_ICON_SELECTOR_JS = """
() => {
  const pick = (sel) => {
    const el = document.querySelector(sel);
    return el && el.href ? el.href : null;
  };
  return (
    pick('link[rel="apple-touch-icon"]') ||
    pick('link[rel="apple-touch-icon-precomposed"]') ||
    pick('link[rel~="icon"]') ||
    pick('link[rel="shortcut icon"]')
  );
}
"""


def _backend_settings() -> tuple[list[str], str]:
    """Read the backend's brand list and fetch User-Agent without importing the app.

    Sharing one User-Agent matters: the backend renders probe pages with
    `FETCH_USER_AGENT`, so capturing references with anything else would compare
    two differently-rendered images.
    """
    sys.path.insert(0, str(REPO_ROOT / "backend"))
    try:
        from app.core.config import get_settings

        settings = get_settings()
        return list(settings.brands), str(settings.FETCH_USER_AGENT)
    except Exception as exc:  # noqa: BLE001
        print(f"! could not read backend settings ({exc}); falling back to local defaults")
        return [], DEFAULT_USER_AGENT
    finally:
        sys.path.pop(0)


def _phash(image_bytes: bytes) -> str | None:
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception:  # noqa: BLE001
        return None


async def capture(page, url: str, timeout_ms: int) -> bytes | None:
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        await page.wait_for_timeout(SETTLE_MS)
        return await page.screenshot(type="png")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! capture failed: {type(exc).__name__}: {exc}")
        return None


async def capture_icon(page, page_url: str, timeout_ms: int) -> tuple[str | None, bytes | None]:
    """Return (icon_url, image_bytes) for the page currently loaded."""
    candidates: list[str] = []
    try:
        declared = await page.evaluate(_ICON_SELECTOR_JS)
        if isinstance(declared, str) and declared:
            candidates.append(declared)
    except Exception:  # noqa: BLE001
        pass

    origin = urlparse(page_url)
    if origin.scheme and origin.netloc:
        candidates.append(f"{origin.scheme}://{origin.netloc}/favicon.ico")

    for candidate in candidates:
        try:
            response = await page.request.get(candidate, timeout=timeout_ms)
            if not response.ok:
                continue
            body = await response.body()
            # SVG (and other vector) icons have no pixel grid to hash.
            if body and not candidate.lower().endswith(".svg"):
                return candidate, body
        except Exception:  # noqa: BLE001
            continue
    return None, None


def _load_existing() -> dict:
    if not OUTPUT_PATH.exists():
        return {}
    try:
        return json.loads(OUTPUT_PATH.read_text() or "{}")
    except json.JSONDecodeError:
        return {}


def _normalize(raw: object) -> dict[str, list[dict]]:
    """Read either the v1 flat format or a previous run of this script."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[dict]] = {}
    for brand, value in raw.items():
        entries = value if isinstance(value, list) else [{"phash": value}]
        cleaned = []
        for entry in entries:
            if isinstance(entry, str):
                cleaned.append({"url": None, "phash": entry, "captured_at": None})
            elif isinstance(entry, dict) and isinstance(entry.get("phash"), str):
                cleaned.append(
                    {
                        "url": entry.get("url"),
                        "phash": entry["phash"],
                        "captured_at": entry.get("captured_at"),
                    }
                )
        if cleaned:
            out[str(brand).lower()] = cleaned
    return out


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brand", action="append", default=[], help="only (re)capture this brand; repeatable")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--dry-run", action="store_true", help="list the planned captures and exit")
    parser.add_argument("--refresh", action="store_true", help="re-capture what is already present")
    parser.add_argument("--icons-only", action="store_true", help="skip screenshots, only refresh icons")
    parser.add_argument("--user-agent", default=None, help="override the User-Agent (defaults to the backend's FETCH_USER_AGENT)")
    args = parser.parse_args()

    configured, backend_ua = _backend_settings()
    if args.user_agent is None:
        args.user_agent = backend_ua
        print(f"using the backend's User-Agent: {args.user_agent[:60]}...")
    for brand in (b for b in configured if b not in BRAND_REFERENCE_URLS):
        print(f"! configured brand '{brand}' has no reference URLs; add it to BRAND_REFERENCE_URLS")
    for brand in (b for b in BRAND_REFERENCE_URLS if configured and b not in configured):
        print(f"note: reference URLs exist for '{brand}' but it is not in the backend BRAND_LIST")

    targets = {b: u for b, u in BRAND_REFERENCE_URLS.items() if not args.brand or b in args.brand}
    if not targets:
        print("nothing to do (no matching brands)")
        return 1

    if args.dry_run:
        for brand, urls in sorted(targets.items()):
            for url in urls:
                print(f"{brand:15s} {url}")
            print(f"{brand:15s} + <declared icon / favicon.ico>")
        return 0

    raw = _load_existing()
    shots = _normalize(raw.get("references") if isinstance(raw.get("references"), dict) else raw)
    icons = _normalize(raw.get("favicons"))
    now = datetime.now(timezone.utc).isoformat()
    failures: list[str] = []
    unchanged: list[str] = []

    def persist() -> None:
        """Write after every capture so a long run stays resumable.

        Capturing 30+ real brand pages over a slow link can outlive a shell
        timeout; saving only at the end meant one interrupted run threw away
        every hash it had already collected.
        """
        payload = {
            "version": 3,
            "generated_at": now,
            "description": (
                "Brand references for backend/app/analyzers/webpage/visual.py. "
                "'favicons' are stable brand-icon hashes and are what identify a clone "
                "(an exact copy is 0 bits away, distinct brands are 20+ apart). "
                "'references' are homepage/sign-in screenshots, used only as a coarse "
                "similarity figure because live pages drift from their own captures."
            ),
            "favicons": {b: icons[b] for b in sorted(icons)},
            "references": {b: shots[b] for b in sorted(shots)},
        }
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--no-sandbox"])
        try:
            page = await browser.new_page(viewport=VIEWPORT, user_agent=args.user_agent)
            for brand, urls in sorted(targets.items()):
                print(f"- {brand}")

                # ---- screenshots -------------------------------------------------
                if not args.icons_only:
                    have = {e.get("url") for e in shots.get(brand, [])}
                    entries = shots.get(brand, [])
                    for url in urls:
                        if url in have and not args.refresh:
                            print(f"    = {url} (already captured)")
                            unchanged.append(f"{brand}:{url}")
                            continue
                        shot = await capture(page, url, args.timeout_ms)
                        if not shot:
                            # One retry for sites that bounce the first navigation
                            # (Amazon 302s to a locale and interrupts the original
                            # request, which succeeds on the second attempt).
                            print(f"    ~ retrying {url}")
                            try:
                                await page.goto("about:blank", timeout=5000)
                            except Exception:  # noqa: BLE001
                                # The page sits on a failed-navigation error
                                # document; the retry below replaces it anyway.
                                pass
                            shot = await capture(page, url, args.timeout_ms)
                        if not shot:
                            failures.append(f"{brand}:{url}")
                            continue
                        phash = _phash(shot)
                        if not phash:
                            failures.append(f"{brand}:{url} (undecodable)")
                            continue
                        entries = [e for e in entries if e.get("url") != url]
                        entries.append({"url": url, "phash": phash, "captured_at": now})
                        shots[brand] = entries
                        print(f"    + {url} -> {phash}", flush=True)
                        persist()

                # ---- brand icon --------------------------------------------------
                # Always read the icon from the brand's homepage rather than from
                # whatever page the screenshot loop left loaded, so the result is
                # the same whether or not this run captured screenshots.
                try:
                    await page.goto(urls[0], wait_until="domcontentloaded", timeout=args.timeout_ms)
                    await page.wait_for_timeout(1000)
                except Exception as exc:  # noqa: BLE001
                    print(f"    ! could not load {urls[0]} for icon lookup: {type(exc).__name__}")
                icon = await capture_icon(page, urls[0], args.timeout_ms)
                icon_url, icon_bytes = icon
                if icon_bytes:
                    phash = _phash(icon_bytes)
                    if phash:
                        icons[brand] = [
                            {
                                "url": icon_url,
                                "phash": phash,
                                "captured_at": now,
                                "bytes": len(icon_bytes),
                            }
                        ]
                        print(f"    + icon {icon_url} -> {phash}", flush=True)
                        persist()
                    else:
                        print(f"    ! icon undecodable: {icon_url}")
                        failures.append(f"{brand}:icon")
                else:
                    print("    ! no brand icon found")
                    failures.append(f"{brand}:icon")
        finally:
            await browser.close()

    print(f"\nWrote {sum(len(v) for v in shots.values())} screenshot hashes across {len(shots)} brands")
    print(f"      {sum(len(v) for v in icons.values())} brand icons across {len(icons)} brands")
    print(f"      -> {OUTPUT_PATH}")
    if unchanged:
        print(f"  ({len(unchanged)} screenshot(s) already present, use --refresh to re-capture)")
    if failures:
        print(f"  {len(failures)} capture(s) failed:")
        for f in failures:
            print(f"    - {f}")
    if configured:
        for label, data in (("icon", icons), ("screenshot", shots)):
            uncovered = [b for b in configured if b not in data]
            if uncovered:
                print(f"  brands with no {label} reference: {', '.join(uncovered)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
