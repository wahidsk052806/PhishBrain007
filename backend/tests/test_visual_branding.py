"""Tests for the brand-clone reference set and the icon matcher.

Two bugs motivated these:

1. `data/reference_hashes.json` held one homepage screenshot per brand for only
   10 of the 17 configured brands, and the match threshold was 10 bits. A live
   brand page drifts far more than that from its own stored capture (measured:
   login.microsoftonline.com vs its own reference = 31 bits), so `possible_brand`
   was null on every scan — the layer could never name a brand.

2. The loader only understood the flat `{"brand": "hash"}` layout, so a
   multi-reference set would have parsed as nothing.

The fix compares a *static* artefact — the page's brand icon — where an exact
copy is 0 bits away and distinct brands are 20+ apart, and reports screenshot
similarity only as an advisory figure.
"""
from __future__ import annotations

import io
import json

import pytest
from PIL import Image

from app.analyzers.webpage import visual
from app.analyzers.webpage.visual import (
    AMBIGUITY_MARGIN,
    FAVICON_MATCH_MAX_DISTANCE,
    ScreenshotUnavailable,
    _normalize_references,
    compare_brand_icon,
    compare_against_references,
)


def _png_bytes(seed: int, size: int = 64) -> bytes:
    """A deterministic, non-uniform image so its phash is stable and unique."""
    img = Image.new("RGB", (size, size))
    pixels = img.load()
    for x in range(size):
        for y in range(size):
            pixels[x, y] = (
                (x * (seed + 3)) % 256,
                (y * (seed + 7)) % 256,
                ((x + y) * (seed + 11)) % 256,
            )
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _write_references(tmp_path, payload: dict):
    path = tmp_path / "reference_hashes.json"
    path.write_text(json.dumps(payload))
    return path


@pytest.fixture
def reference_file(tmp_path, monkeypatch):
    """Point the visual layer at a temporary reference set."""

    def install(payload: dict):
        path = _write_references(tmp_path, payload)
        monkeypatch.setattr(visual, "_reference_hashes_path", lambda: path)
        return path

    return install


# --------------------------------------------------------------------------- #
# Reference-set parsing
# --------------------------------------------------------------------------- #

def test_normalize_accepts_the_legacy_flat_format():
    assert _normalize_references({"paypal": "abc123"}) == {"paypal": ["abc123"]}


def test_normalize_accepts_the_v2_reference_lists():
    raw = {"references": {"paypal": [{"phash": "a"}, {"phash": "b"}]}}
    assert _normalize_references(raw) == {"paypal": ["a", "b"]}


def test_normalize_keeps_multiple_references_per_brand():
    raw = {"references": {"paypal": "a", "chase": ["b", "c"]}}
    assert _normalize_references(raw) == {"paypal": ["a"], "chase": ["b", "c"]}


def test_normalize_drops_entries_without_a_usable_hash():
    raw = {"references": {"paypal": [{"phash": "a"}, {"url": "no-hash-here"}, {}], "chase": []}}
    assert _normalize_references(raw) == {"paypal": ["a"]}


def test_normalize_lowercases_brand_keys():
    assert _normalize_references({"PayPal": "abc"}) == {"paypal": ["abc"]}


def test_normalize_is_total_for_garbage():
    assert _normalize_references(None) == {}
    assert _normalize_references([]) == {}
    assert _normalize_references({"references": "nope"}) == {}


# --------------------------------------------------------------------------- #
# Icon matching
# --------------------------------------------------------------------------- #

def test_an_exact_icon_copy_identifies_its_brand(reference_file):
    from app.analyzers.webpage.visual import _phash_from_bytes

    png = _png_bytes(1)
    phash = str(_phash_from_bytes(png))
    reference_file({"favicons": {"paypal": [{"phash": phash}]}})

    result = compare_brand_icon(png)

    assert result["status"] == "ok"
    assert result["closest_brand"] == "paypal"
    assert result["hash_distance"] == 0
    assert result["matched"] is True


def test_an_unrelated_icon_does_not_identify_any_brand(reference_file):
    from app.analyzers.webpage.visual import _phash_from_bytes

    png = _png_bytes(1)
    reference_file({"favicons": {"paypal": [{"phash": str(_phash_from_bytes(_png_bytes(99)))}]}})

    result = compare_brand_icon(png)

    assert result["status"] == "ok"
    # Distance is well outside the match window *and* reported honestly.
    assert result["matched"] is False
    assert result["closest_brand"] is None
    assert result["hash_distance"] > FAVICON_MATCH_MAX_DISTANCE


def test_the_best_reference_wins_across_multiple_per_brand(reference_file):
    from app.analyzers.webpage.visual import _phash_from_bytes

    png = _png_bytes(5)
    reference_file(
        {
            "favicons": {
                "chase": [{"phash": str(_phash_from_bytes(_png_bytes(40)))}],
                "paypal": [{"phash": str(_phash_from_bytes(_png_bytes(41)))}],
                "amazon": [{"phash": str(_phash_from_bytes(_png_bytes(5)))}],
            }
        }
    )

    result = compare_brand_icon(png)

    assert result["closest_brand"] == "amazon"
    assert result["hash_distance"] == 0


def test_no_reference_set_is_reported_as_unavailable_not_a_non_match(reference_file):
    reference_file({"favicons": {}})

    result = compare_brand_icon(_png_bytes(1))

    assert result["status"] == "unavailable"
    assert "reason" in result


def test_undecodable_icon_bytes_are_reported_as_unavailable(reference_file):
    from app.analyzers.webpage.visual import _phash_from_bytes

    reference_file({"favicons": {"paypal": [{"phash": str(_phash_from_bytes(_png_bytes(1)))}]}})

    result = compare_brand_icon(b"not an image")

    assert result["status"] == "unavailable"


# --------------------------------------------------------------------------- #
# Screenshot comparison: advisory only, and never ambiguous
# --------------------------------------------------------------------------- #

def test_two_indistinguishable_brands_are_not_attributed(reference_file):
    """A generic sign-in page must not be blamed on an arbitrary brand."""
    from app.analyzers.webpage.visual import _phash_from_bytes

    png = _png_bytes(3)
    phash = str(_phash_from_bytes(png))
    # Both brands share the same fingerprint: impossible to tell them apart.
    reference_file({"references": {"paypal": [phash], "chase": [phash]}})

    result = compare_against_references(png)

    assert result["visually_similar"] is True
    assert result["ambiguous"] is True
    assert result["closest_brand"] is None
    assert AMBIGUITY_MARGIN > 0


def test_a_clear_screenshot_match_is_attributed(reference_file):
    from app.analyzers.webpage.visual import _phash_from_bytes

    png = _png_bytes(3)
    reference_file(
        {
            "references": {
                "paypal": [str(_phash_from_bytes(png))],
                "chase": [str(_phash_from_bytes(_png_bytes(77)))],
            }
        }
    )

    result = compare_against_references(png)

    assert result["closest_brand"] == "paypal"
    assert result["ambiguous"] is False
    assert result["runner_up_brand"] == "chase"


# --------------------------------------------------------------------------- #
# analyze_visual orchestration
# --------------------------------------------------------------------------- #

async def test_analyze_visual_keeps_the_icon_verdict_when_the_screenshot_fails(
    reference_file, monkeypatch
):
    """The icon match is the strong signal, so a capture failure must not lose it."""
    from app.analyzers.webpage.visual import _phash_from_bytes

    png = _png_bytes(8)
    reference_file({"favicons": {"microsoft": [{"phash": str(_phash_from_bytes(png))}]}})

    async def _icon(url):
        return png

    async def _capture(url, timeout_ms=30000):
        raise ScreenshotUnavailable("chromium died")

    monkeypatch.setattr(visual, "_fetch_brand_asset", _icon)
    monkeypatch.setattr(visual, "capture_screenshot", _capture)

    result = await visual.analyze_visual(
        "https://login-secure.example/login",
        favicon_url="https://login-secure.example/favicon.ico",
    )

    assert result["status"] == "ok"
    assert result["closest_brand"] == "microsoft"
    assert "chromium died" in result["screenshot_reason"]
