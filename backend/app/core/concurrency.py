"""Global admission gates for the two CPU-bound layers of a scan.

A scan's expensive work is CPU-bound and single-threaded in practice: Chromium
rendering a page for the screenshot comparison, and llama.cpp generating a
verdict. The pipeline already runs those two *sequentially inside one scan* for
exactly that reason (overlapping them measured 53.9 s against ~26 s).

Nothing limited them *across* scans, which is fine on a laptop used by one person
and fatal on a shared deployment: with a 4-core box, three visitors scanning at
once made every request slower than its own deadline, so all three came back
with "the model did not answer within the scan deadline" — a full-capacity
server reporting total failure. These gates keep the box honest: a bounded number
of scans run the expensive layer, the rest queue for a short while, and a request
that cannot get a slot in time finishes *without* that layer while saying so in
`degraded` (never silently, and never with the score pretending the layer ran).

They are process-local on purpose: the deployment this exists for is one host
running one Uvicorn worker. Multiple workers would need a shared limiter, which
is a different design (queue + worker pool), not a bigger constant.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Literal

from app.core.config import get_settings

SlotKind = Literal["llm", "visual"]

_semaphores: dict[str, asyncio.Semaphore] = {}
_limits: dict[str, int] = {}


def _semaphore(kind: SlotKind, limit: int) -> asyncio.Semaphore:
    """One semaphore per layer, rebuilt when the configured limit changes.

    Rebuilding on a changed limit keeps tests and operator overrides honest: a
    semaphore created with the old ceiling would otherwise silently outlive it.
    """
    if kind not in _semaphores or _limits.get(kind) != limit:
        _semaphores[kind] = asyncio.Semaphore(limit)
        _limits[kind] = limit
    return _semaphores[kind]


def reset_scan_gates() -> None:
    """Forget every gate. Tests use this; the server never needs it."""
    _semaphores.clear()
    _limits.clear()


def _limit_for(kind: SlotKind) -> int:
    settings = get_settings()
    return max(
        1,
        settings.MAX_CONCURRENT_LLM_SCANS
        if kind == "llm"
        else settings.MAX_CONCURRENT_VISUAL_SCANS,
    )


async def _acquire(semaphore: asyncio.Semaphore, wait_seconds: float) -> bool:
    if wait_seconds <= 0:
        # No waiting allowed: only run when a slot is free right now.
        if semaphore.locked():
            return False
        await semaphore.acquire()
        return True
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=wait_seconds)
        return True
    except asyncio.TimeoutError:
        return False


@asynccontextmanager
async def scan_slot(kind: SlotKind) -> AsyncIterator[bool]:
    """Hold one slot for `kind`, or yield False when the queue is too long.

    The caller must treat `False` as "this layer did not run" — add the matching
    `degraded` code and carry on with the layers that did.
    """
    settings = get_settings()
    semaphore = _semaphore(kind, _limit_for(kind))
    admitted = await _acquire(semaphore, max(0.0, settings.SCAN_QUEUE_TIMEOUT_SECONDS))
    try:
        yield admitted
    finally:
        if admitted:
            semaphore.release()
