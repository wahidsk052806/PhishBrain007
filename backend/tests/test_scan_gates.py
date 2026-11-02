"""Admission gates for the CPU-bound layers, and the CORS origins they protect.

Why these exist: on a shared deployment the expensive part of a scan is a
Chromium render and a llama.cpp generation, both single-threaded. Nothing
limited them *across* scans, so three visitors scanning at once made every
request miss its own deadline — a healthy server reporting "the model did not
answer". These tests pin the behaviour that fixes it: a bounded number of scans
get the slot, the rest wait briefly and then finish with the deterministic
layers, clearly labelled.
"""
from __future__ import annotations

import asyncio
import re

import pytest

from app.core.concurrency import reset_scan_gates, scan_slot
from app.core.config import Settings, get_settings

ORIGINS = {
    "chrome-extension://abcdefghijklmnop",
    "moz-extension://11111111-2222-3333-4444-555555555555",
}


@pytest.fixture(autouse=True)
def _fresh_gates():
    reset_scan_gates()
    get_settings.cache_clear()
    yield
    reset_scan_gates()
    get_settings.cache_clear()


@pytest.fixture
def settings(monkeypatch):
    def apply(**values: object) -> Settings:
        for key, value in values.items():
            monkeypatch.setenv(key, str(value))
        get_settings.cache_clear()
        return get_settings()

    return apply


async def test_only_the_configured_number_of_scans_hold_the_model(settings):
    settings(MAX_CONCURRENT_LLM_SCANS=1, SCAN_QUEUE_TIMEOUT_SECONDS=0.05)

    held = asyncio.Event()
    release = asyncio.Event()

    async def holder() -> bool:
        async with scan_slot("llm") as admitted:
            held.set()
            await release.wait()
            return admitted

    first = asyncio.create_task(holder())
    await held.wait()  # the first scan is inside the model slot

    # A second scan cannot start a second generation, and does not hang for the
    # whole LLM budget either: it waits out the queue and gives up.
    async with scan_slot("llm") as admitted:
        assert admitted is False

    release.set()
    assert await first is True

    # Once released, the next scan is admitted immediately.
    async with scan_slot("llm") as admitted:
        assert admitted is True


async def test_a_queued_scan_takes_the_slot_when_it_frees_up(settings):
    settings(MAX_CONCURRENT_LLM_SCANS=1, SCAN_QUEUE_TIMEOUT_SECONDS=2.0)

    held = asyncio.Event()
    release = asyncio.Event()

    async def holder() -> None:
        async with scan_slot("llm"):
            held.set()
            await release.wait()

    first = asyncio.create_task(holder())
    await held.wait()

    async def waiter() -> bool:
        async with scan_slot("llm") as admitted:
            return admitted

    queued = asyncio.create_task(waiter())
    await asyncio.sleep(0.05)
    release.set()

    assert await queued is True
    await first


async def test_layers_do_not_block_each_other(settings):
    settings(MAX_CONCURRENT_LLM_SCANS=1, MAX_CONCURRENT_VISUAL_SCANS=1, SCAN_QUEUE_TIMEOUT_SECONDS=0)

    release = asyncio.Event()

    async def llm_holder() -> None:
        async with scan_slot("llm"):
            await release.wait()

    holder = asyncio.create_task(llm_holder())
    await asyncio.sleep(0.01)

    # The screenshot layer has its own slot: a busy model must not stop the
    # visual pass, which is independent of it.
    async with scan_slot("visual") as admitted:
        assert admitted is True
    async with scan_slot("llm") as admitted:
        assert admitted is False

    release.set()
    await holder


async def test_no_queue_timeout_means_skip_instead_of_waiting(settings):
    settings(MAX_CONCURRENT_LLM_SCANS=1, SCAN_QUEUE_TIMEOUT_SECONDS=0)

    release = asyncio.Event()

    async def holder() -> None:
        async with scan_slot("llm"):
            await release.wait()

    task = asyncio.create_task(holder())
    await asyncio.sleep(0.01)

    started = asyncio.get_running_loop().time()
    async with scan_slot("llm") as admitted:
        assert admitted is False
    assert asyncio.get_running_loop().time() - started < 0.5

    release.set()
    await task


def test_defaults_are_sized_for_one_small_host():
    fresh = Settings()

    # One at a time is what a 4-core box can actually finish; the queue is short
    # enough that a user sees a verdict rather than a spinner.
    assert fresh.MAX_CONCURRENT_LLM_SCANS == 1
    assert fresh.MAX_CONCURRENT_VISUAL_SCANS == 1
    assert 0 < fresh.SCAN_QUEUE_TIMEOUT_SECONDS <= 60


def test_cors_allows_both_extension_schemes_and_refuses_the_open_internet():
    regex = re.compile(Settings().CORS_ORIGIN_REGEX)

    for origin in ORIGINS:
        assert regex.fullmatch(origin), origin
    # The dashboard on loopback and a LAN address still work for self-hosting.
    assert regex.fullmatch("http://localhost:8080")
    assert regex.fullmatch("http://192.168.1.20:8080")
    # But an arbitrary page must not be able to borrow the operator's backend.
    assert not regex.fullmatch("https://evil.example")
    assert not regex.fullmatch("https://phishbrain007.app")


def test_a_production_origin_can_be_allowed_without_opening_everything(settings):
    # The value deploy/env.production.example ships.
    configured = settings(
        CORS_ORIGIN_REGEX=(
            r"^((?:chrome|moz)-extension://.*|https://(?:www\.)?phishbrain007\.app)$"
        )
    )
    regex = re.compile(configured.CORS_ORIGIN_REGEX)

    assert regex.fullmatch("https://phishbrain007.app")
    assert regex.fullmatch("https://www.phishbrain007.app")
    assert regex.fullmatch("moz-extension://11111111-2222-3333-4444-555555555555")
    assert not regex.fullmatch("https://evil.example")
    # The deployed backend is reachable from a stranger's page only through the
    # extension, never directly by the site it is scanning.
    assert not regex.fullmatch("http://localhost:8080")
