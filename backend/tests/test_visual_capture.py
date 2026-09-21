"""Regression tests for screenshot capture in the visual layer.

The bug these cover: `uvicorn ... --reload` sets
`WindowsSelectorEventLoopPolicy` process-wide on Windows
(`uvicorn/loops/asyncio.py`, `use_subprocess=True`). The async Playwright API
launches its driver with `asyncio.create_subprocess_exec`, which a selector loop
does not implement, so it raised a bare `NotImplementedError` and the visual
layer reported "unavailable" forever — even with Chromium installed and the same
capture working fine in a standalone script.
"""
from __future__ import annotations

import asyncio

import pytest

from app.analyzers.webpage import visual
from app.analyzers.webpage.visual import ScreenshotUnavailable, analyze_visual, capture_screenshot


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """Keep the tests hermetic: the guard would otherwise resolve real hosts."""
    monkeypatch.setattr(visual, "guard_url", lambda url: None)


def test_falls_back_to_sync_capture_when_loop_cannot_spawn_subprocesses(monkeypatch):
    class _Raises:
        async def __aenter__(self):
            raise NotImplementedError

        async def __aexit__(self, *exc):
            return False

    import playwright.async_api as async_api

    monkeypatch.setattr(async_api, "async_playwright", lambda: _Raises())

    seen: dict[str, str] = {}

    def _fake_sync_capture(url: str, timeout_ms: int = 30000) -> bytes:
        seen["url"] = url
        return b"png-bytes"

    monkeypatch.setattr(visual, "_capture_screenshot_sync", _fake_sync_capture)

    png = asyncio.run(capture_screenshot("https://example.com/login"))
    assert png == b"png-bytes"
    assert seen["url"] == "https://example.com/login"


def test_sync_fallback_failure_is_reported_as_a_screenshot_reason(monkeypatch):
    class _Raises:
        async def __aenter__(self):
            raise NotImplementedError

        async def __aexit__(self, *exc):
            return False

    import playwright.async_api as async_api

    monkeypatch.setattr(async_api, "async_playwright", lambda: _Raises())

    def _fake_sync_capture(url: str, timeout_ms: int = 30000) -> bytes:
        raise ScreenshotUnavailable("Error: net::ERR_CONNECTION_REFUSED")

    monkeypatch.setattr(visual, "_capture_screenshot_sync", _fake_sync_capture)

    with pytest.raises(ScreenshotUnavailable) as excinfo:
        asyncio.run(capture_screenshot("https://example.com/login"))
    assert "ERR_CONNECTION_REFUSED" in excinfo.value.reason


def test_analyze_visual_reports_the_specific_capture_reason(monkeypatch):
    async def _capture(url, timeout_ms=30000):
        raise ScreenshotUnavailable("Playwright is not installed in this environment")

    monkeypatch.setattr(visual, "capture_screenshot", _capture)

    result = asyncio.run(analyze_visual("https://example.com/"))
    assert result["status"] == "unavailable"
    assert "screenshot capture unavailable" in result["reason"]
    assert "Playwright is not installed" in result["reason"]


def test_analyze_visual_reports_blocked_targets_distinctly(monkeypatch):
    from app.core.security import SSRFBlockedError

    def _block(url):
        raise SSRFBlockedError("example.com resolves to blocked address 127.0.0.1")

    monkeypatch.setattr(visual, "guard_url", _block)

    result = asyncio.run(analyze_visual("https://example.com/"))
    assert result["status"] == "unavailable"
    assert "SSRF guard" in result["reason"]
