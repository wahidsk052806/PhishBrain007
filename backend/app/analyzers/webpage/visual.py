"""Optional visual/screenshot-based brand-impersonation check.

Uses Playwright (if installed and browsers are provisioned) to capture a
screenshot, then perceptual-hashes it and compares against locally stored
reference hashes. Never claims a brand identification it cannot support.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import sys
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import SSRFBlockedError, guard_url

logger = get_logger(__name__)

# The reference fingerprints live in the repo's top-level data/ directory.
# Depending on how the backend is deployed the file can sit at a few levels
# above this module, so probe the known layouts in order.
_CANDIDATE_HASH_PATHS = (
    # dev checkout: <repo>/data/reference_hashes.json
    Path(__file__).resolve().parents[4] / "data" / "reference_hashes.json",
    # container / bundled layout: <backend-root>/data/reference_hashes.json
    Path(__file__).resolve().parents[3] / "data" / "reference_hashes.json",
    # fall back to the process working directory (e.g. running from repo root)
    Path.cwd() / "data" / "reference_hashes.json",
)


def _reference_hashes_path() -> Path | None:
    for candidate in _CANDIDATE_HASH_PATHS:
        if candidate.exists():
            return candidate
    return None


# A brand is only *named* when its best hash is at least this many bits closer
# than the next-best brand. Generic sign-in pages look alike (two fields on
# white), so without a margin the closest match is close to a coin flip and the
# report would confidently blame the wrong brand.
AMBIGUITY_MARGIN = 3


def _normalize_references(raw: object) -> dict[str, list[str]]:
    """Accept both reference-set layouts and return {brand: [phash, ...]}.

    * v1 (flat, one hash per brand):  ``{"paypal": "99c6e63119c6ee31"}``
    * v2 (multi-reference):           ``{"references": {"paypal": [{"phash": ...}, ...]}}``
      where each entry may be a bare hash string or an object with a `phash`.

    Multiple references per brand are what make this layer actually usable:
    a clone imitates a *sign-in page*, and a single homepage fingerprint is
    frequently 20+ bits away from it (measured: 24 bits), i.e. never a match.
    """
    if not isinstance(raw, dict):
        return {}

    # The file can be either the legacy flat map {brand: hash} or a versioned
    # envelope {version, favicons, references, ...}. Distinguish them by their
    # keys rather than by the shape of `references`: otherwise a malformed
    # `"references": "nope"` fell through to `body = raw` and was parsed as a
    # brand literally named "references".
    if isinstance(raw.get("references"), dict):
        body: dict = raw["references"]
    elif any(k in raw for k in ("version", "generated_at", "description", "references", "favicons")):
        return {}
    else:
        body = raw

    out: dict[str, list[str]] = {}
    for brand, value in body.items():
        entries = value if isinstance(value, list) else [value]
        hashes: list[str] = []
        for entry in entries:
            if isinstance(entry, str):
                hashes.append(entry)
            elif isinstance(entry, dict) and isinstance(entry.get("phash"), str):
                hashes.append(entry["phash"])
        if hashes:
            out[str(brand).lower()] = hashes
    return out


def _load_reference_file() -> dict:
    path = _reference_hashes_path()
    if path is None:
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001
        logger.info("Failed loading reference hashes", extra={"extra_fields": {"path": str(path), "error": str(exc)}})
    return {}


def _load_reference_hashes() -> dict[str, list[str]]:
    """Full-page screenshot references, {brand: [phash, ...]}."""
    return _normalize_references(_load_reference_file())


def _load_brand_favicons() -> dict[str, list[str]]:
    """Brand *icon* references, {brand: [phash, ...]}.

    These are the signal that actually identifies a brand clone. A full-page
    screenshot of a live brand page is dominated by rotating hero art, consent
    banners and A/B-tested layout, so re-capturing the very same page can land
    30+ bits from its own stored reference (measured: login.microsoftonline.com
    vs its own reference = 31). A brand's icon, by contrast, is a small static
    file: an exact copy hashes to distance 0, while *distinct* brand icons stay
    20+ bits apart (measured pairwise across nine brands: min 20). That gap is
    what makes an icon match worth acting on and a screenshot match not.
    """
    raw = _load_reference_file()
    section = raw.get("favicons")
    return _normalize_references(section) if isinstance(section, dict) else {}


def _to_wireframe(img):
    """Edge-only rendering of a screenshot: layout without content.

    Colour is discarded and only strong intensity gradients survive, so a
    reviewer can see the page's *structure* (where the logo, fields and buttons
    sit) without the screenshot being a readable copy of the page. That is the
    point of the wireframe mode: show the evidence, keep nothing worth leaking.
    """
    from PIL import ImageFilter, ImageOps

    edges = ImageOps.grayscale(img).filter(ImageFilter.FIND_EDGES)
    return edges.point(lambda p: 0 if p > 28 else 255, mode="L").convert("RGB")


def _thumbnail_data_url(image_bytes: bytes) -> str | None:
    """Downscaled data URL of the captured screenshot, per the configured mode.

    Returns None when mode is "off" or no imaging library is available — the
    report then simply omits the image rather than breaking the scan.
    """
    settings = get_settings()
    mode = settings.VISUAL_SCREENSHOT_MODE
    if mode == "off":
        return None
    try:
        from PIL import Image
    except Exception:  # noqa: BLE001
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:  # noqa: BLE001
        return None

    max_width = max(64, int(settings.VISUAL_SCREENSHOT_MAX_WIDTH))
    if img.width > max_width:
        ratio = max_width / img.width
        img = img.resize((max_width, max(1, round(img.height * ratio))), Image.LANCZOS)

    buffer = io.BytesIO()
    if mode == "wireframe":
        _to_wireframe(img).save(buffer, format="PNG", optimize=True)
        mime = "image/png"
    else:
        img.save(buffer, format="JPEG", quality=70, optimize=True)
        mime = "image/jpeg"
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _phash_from_bytes(image_bytes: bytes):
    try:
        import imagehash
        from PIL import Image
    except Exception:  # noqa: BLE001
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return imagehash.phash(img)
    except Exception:  # noqa: BLE001
        return None


# An exact copy of a brand icon hashes to 0 bits; the closest *different*
# brand icon measured 20 bits away. 8 sits well inside that gap, so an icon
# match names a brand without the ambiguity a screenshot match suffers from.
FAVICON_MATCH_MAX_DISTANCE = 8


class ScreenshotUnavailable(Exception):
    """A screenshot could not be captured, with a specific reason.

    Carrying the reason matters: the caller surfaces it to the user, and a
    blanket "Playwright not installed or navigation failed" made a real,
    fixable failure (blocked navigation, launch error, timeout) indistinguishable
    from a missing dependency.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def capture_screenshot(url: str, timeout_ms: int = 30000) -> bytes | None:
    """Capture a screenshot with Playwright, or raise `ScreenshotUnavailable`.

    The URL is passed through the same SSRF guard used by the HTML fetcher, and
    the post-redirect URL is re-validated before the screenshot is taken.
    """
    try:
        guard_url(url)
    except SSRFBlockedError as exc:
        logger.info("Screenshot blocked by SSRF guard", extra={"extra_fields": {"url": url, "error": str(exc)}})
        raise ScreenshotUnavailable(f"the target was blocked by the SSRF guard ({exc})") from exc

    try:
        from playwright.async_api import async_playwright
    except Exception as exc:  # noqa: BLE001
        raise ScreenshotUnavailable(
            f"Playwright is not installed in this environment ({type(exc).__name__})"
        ) from exc

    # Same User-Agent the reference set was captured with, so a probe renders
    # the same way its reference did; also avoids the sites that refuse
    # Playwright's default "HeadlessChrome" string.
    settings = get_settings()

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox"])
            try:
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 800},
                    user_agent=settings.FETCH_USER_AGENT,
                    locale="en-US",
                )

                async def _route(route, request):  # noqa: ANN001
                    # Re-validate every top-level navigation (covers redirects).
                    if request.is_navigation_request():
                        try:
                            guard_url(request.url)
                        except SSRFBlockedError as exc:
                            logger.info(
                                "Screenshot navigation blocked by SSRF guard",
                                extra={"extra_fields": {"url": request.url, "error": str(exc)}},
                            )
                            await route.abort()
                            return
                    await route.continue_()

                await page.route("**/*", _route)
                await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")

                # Final safety net: validate the URL we actually landed on.
                guard_url(page.url)

                screenshot = await page.screenshot(type="png")
                return screenshot
            finally:
                await browser.close()
    except SSRFBlockedError as exc:
        logger.info("Screenshot blocked after redirect", extra={"extra_fields": {"url": url, "error": str(exc)}})
        raise ScreenshotUnavailable(f"navigation redirected to a blocked address ({exc})") from exc
    except NotImplementedError:
        # This loop cannot spawn subprocesses (uvicorn on Windows forces the
        # selector loop), so drive Playwright from a worker thread instead.
        logger.info(
            "Async screenshot capture unsupported on this event loop; retrying with the "
            "sync Playwright API",
            extra={"extra_fields": {"url": url}},
        )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _capture_screenshot_sync, url, timeout_ms)
    except Exception as exc:  # noqa: BLE001
        logger.info("Screenshot capture failed", extra={"extra_fields": {"url": url, "error": str(exc)}})
        raise ScreenshotUnavailable(f"{type(exc).__name__}: {exc}") from exc



def _capture_screenshot_sync(url: str, timeout_ms: int = 30000) -> bytes:
    """Capture with Playwright's *sync* API, off the event loop.

    Why this exists: uvicorn forces `WindowsSelectorEventLoopPolicy` on Windows
    (`uvicorn/loops/asyncio.py`), and the async Playwright API launches its
    driver with `asyncio.create_subprocess_exec`, which a Selector loop does not
    implement. It therefore raised a bare `NotImplementedError` and **every**
    screenshot taken inside the running server failed, leaving the visual layer
    permanently "unavailable" even with Chromium installed. The sync API spawns
    the driver as an ordinary subprocess; running it in a worker thread keeps it
    off the loop and avoids Playwright's "sync API inside the asyncio loop"
    guard, because that guard only inspects the calling thread.

    It also has to repair the *event-loop policy*: the sync API creates its own
    loop internally to talk to the driver, and uvicorn sets
    `WindowsSelectorEventLoopPolicy` process-wide, so that loop is a selector
    loop too — and a selector loop cannot spawn subprocesses, which is where the
    bare `NotImplementedError` came from. Restoring the platform default
    (Proactor, which is what `asyncio.run` uses) for the duration of the capture
    fixes it; already-running loops are unaffected, since a policy only governs
    loop *creation*.
    """
    try:
        guard_url(url)
    except SSRFBlockedError as exc:
        raise ScreenshotUnavailable(f"the target was blocked by the SSRF guard ({exc})") from exc

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        raise ScreenshotUnavailable(
            f"Playwright is not installed in this environment ({type(exc).__name__})"
        ) from exc

    settings = get_settings()
    saved_policy = asyncio.get_event_loop_policy()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page(
                    viewport={"width": 1280, "height": 800},
                    user_agent=settings.FETCH_USER_AGENT,
                    locale="en-US",
                )

                def _route(route, request):  # noqa: ANN001
                    if request.is_navigation_request():
                        try:
                            guard_url(request.url)
                        except SSRFBlockedError as exc:
                            logger.info(
                                "Screenshot navigation blocked by SSRF guard",
                                extra={"extra_fields": {"url": request.url, "error": str(exc)}},
                            )
                            route.abort()
                            return
                    route.continue_()

                page.route("**/*", _route)
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                guard_url(page.url)
                return page.screenshot(type="png")
            finally:
                browser.close()
    except SSRFBlockedError as exc:
        raise ScreenshotUnavailable(f"navigation redirected to a blocked address ({exc})") from exc
    except Exception as exc:  # noqa: BLE001
        raise ScreenshotUnavailable(f"{type(exc).__name__}: {exc}") from exc
    finally:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(saved_policy)


async def _fetch_brand_asset(url: str, timeout: float = 8.0, max_bytes: int = 512_000) -> bytes | None:
    """Fetch a small, unauthenticated image (a favicon) through the SSRF guard."""
    import httpx

    try:
        guard_url(url)
    except SSRFBlockedError as exc:
        logger.info("Brand-asset fetch blocked by SSRF guard", extra={"extra_fields": {"url": url, "error": str(exc)}})
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, max_redirects=3) as client:
            resp = await client.get(url, headers={"Accept": "image/*"})
            if resp.status_code != 200:
                return None
            content = resp.content[:max_bytes]
    except Exception as exc:  # noqa: BLE001
        logger.info("Brand-asset fetch failed", extra={"extra_fields": {"url": url, "error": str(exc)}})
        return None
    return content or None


def compare_brand_icon(image_bytes: bytes) -> dict:
    """Identify the brand whose icon this page serves.

    Because phishing kits routinely copy or hotlink the impersonated brand's
    icon, this is a direct brand-clone signal — and unlike the screenshot
    comparison it is stable, since the compared artefact is a static file.
    """
    references = _load_brand_favicons()
    if not references:
        return {"status": "unavailable", "reason": "no brand icon references configured"}

    phash = _phash_from_bytes(image_bytes)
    if phash is None:
        return {"status": "unavailable", "reason": "icon could not be decoded"}

    try:
        import imagehash
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "reason": "imagehash unavailable"}

    ranked: list[tuple[str, int]] = []
    for brand, ref_hashes in references.items():
        best: int | None = None
        for ref_hash_str in ref_hashes:
            try:
                distance = int(phash - imagehash.hex_to_hash(ref_hash_str))
            except Exception:  # noqa: BLE001
                continue
            if best is None or distance < best:
                best = distance
        if best is not None:
            ranked.append((brand, best))

    if not ranked:
        return {"status": "unavailable", "reason": "no comparable brand icon hashes"}

    ranked.sort(key=lambda kv: kv[1])
    brand, distance = ranked[0]
    runner_up = ranked[1] if len(ranked) > 1 else None

    matched = distance <= FAVICON_MATCH_MAX_DISTANCE
    return {
        "status": "ok",
        "phash": str(phash),
        "closest_brand": brand if matched else None,
        "hash_distance": distance,
        "matched": matched,
        "runner_up_brand": runner_up[0] if runner_up else None,
        "runner_up_distance": runner_up[1] if runner_up else None,
        "reference_count": sum(len(v) for v in references.values()),
    }


def compare_against_references(image_bytes: bytes) -> dict:
    phash = _phash_from_bytes(image_bytes)
    if phash is None:
        return {"status": "unavailable", "reason": "imagehash/Pillow unavailable or decode failed"}

    references = _load_reference_hashes()
    if not references:
        return {"status": "unavailable", "reason": "no reference hashes configured", "phash": str(phash)}

    try:
        import imagehash
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "reason": "imagehash unavailable"}

    # Per brand, keep the closest of its references (homepage, sign-in page, ...).
    per_brand: dict[str, int] = {}
    for brand, ref_hashes in references.items():
        best_for_brand: int | None = None
        for ref_hash_str in ref_hashes:
            try:
                ref_hash = imagehash.hex_to_hash(ref_hash_str)
            except Exception:  # noqa: BLE001
                continue
            distance = int(phash - ref_hash)
            if best_for_brand is None or distance < best_for_brand:
                best_for_brand = distance
        if best_for_brand is not None:
            per_brand[brand] = best_for_brand

    if not per_brand:
        return {"status": "unavailable", "reason": "no comparable reference hashes", "phash": str(phash)}

    ranked = sorted(per_brand.items(), key=lambda kv: kv[1])
    best_brand, best_distance = ranked[0]
    runner_up_brand, runner_up_distance = ranked[1] if len(ranked) > 1 else (None, None)

    similar = best_distance <= 10
    ambiguous = (
        similar
        and runner_up_distance is not None
        and (runner_up_distance - best_distance) < AMBIGUITY_MARGIN
    )

    return {
        "status": "ok",
        "phash": str(phash),
        # Never name a brand we cannot separate from the runner-up.
        "closest_brand": best_brand if (similar and not ambiguous) else None,
        "hash_distance": best_distance,
        "visually_similar": similar,
        "ambiguous": ambiguous,
        "runner_up_brand": runner_up_brand if similar else None,
        "runner_up_distance": runner_up_distance if similar else None,
        "reference_count": sum(len(v) for v in references.values()),
    }


async def analyze_visual(
    url: str,
    screenshot_base64: str | None = None,
    favicon_url: str | None = None,
) -> dict:
    """Compare a page against the local brand reference set.

    Two independent comparisons are reported:

    * `icon` — the brand whose *icon* this page serves. Stable and strong: an
      exact copy is 0 bits away while distinct brands sit 20+ apart, so a hit
      is real brand-clone evidence.
    * the screenshot perceptual hash — a coarse similarity figure. Deliberately
      advisory only, because a live page's own screenshot can drift 30+ bits
      from its stored reference.

    The icon match is what populates `closest_brand`; the screenshot can only
    do so when the page is genuinely near a reference *and* unambiguously
    closer than the runner-up.
    """
    icon: dict = {"status": "unavailable", "reason": "no favicon URL available for this page"}
    if favicon_url:
        icon_bytes = await _fetch_brand_asset(favicon_url)
        if icon_bytes is not None:
            icon = compare_brand_icon(icon_bytes)
        else:
            icon = {"status": "unavailable", "reason": "page icon could not be fetched"}

    image_bytes: bytes | None = None
    if screenshot_base64:
        try:
            image_bytes = base64.b64decode(screenshot_base64)
        except Exception:  # noqa: BLE001
            image_bytes = None

    if image_bytes is None:
        try:
            image_bytes = await capture_screenshot(url)
        except ScreenshotUnavailable as exc:
            # The icon comparison may still have produced a usable answer, so
            # report what we have instead of discarding it.
            if icon.get("matched"):
                return {
                    "status": "ok",
                    "phash": None,
                    "closest_brand": icon["closest_brand"],
                    "hash_distance": None,
                    "visually_similar": False,
                    "screenshot_reason": f"screenshot capture unavailable: {exc.reason}",
                    "screenshot_data_url": None,
                    "icon": icon,
                }
            return {
                "status": "unavailable",
                "reason": f"screenshot capture unavailable: {exc.reason}",
                "icon": icon,
            }

    if image_bytes is None:
        return {"status": "unavailable", "reason": "screenshot capture produced no image", "icon": icon}

    # The evidence image, downscaled and rendered per the configured mode. It is
    # computed once here and attached to every return path below so a caller
    # never has to guess whether a screenshot existed.
    thumbnail = _thumbnail_data_url(image_bytes)

    shot = compare_against_references(image_bytes)
    if shot.get("status") != "ok":
        if icon.get("matched"):
            return {"status": "ok", "closest_brand": icon["closest_brand"], "icon": icon, "screenshot_data_url": thumbnail, **{
                k: shot.get(k) for k in ("phash", "hash_distance")
            }}
        return {**shot, "icon": icon, "screenshot_data_url": thumbnail}

    # Prefer the icon verdict: it is the one with real separating power.
    if icon.get("matched"):
        shot["closest_brand"] = icon["closest_brand"]
    shot["icon"] = icon
    shot["screenshot_data_url"] = thumbnail
    return shot
