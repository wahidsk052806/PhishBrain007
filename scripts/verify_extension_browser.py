"""Load the built browser extension in a real Chromium and check it boots.

The extension had been typechecked and unit-tested but never actually loaded in
a browser, so anything that only fails at runtime — a manifest that Chromium
rejects, a service worker that throws on registration, a popup whose module
graph breaks under the extension CSP — would have shipped unnoticed.

    python scripts/verify_extension_browser.py
    python scripts/verify_extension_browser.py --dist extension/dist --headed

Exits non-zero if the extension does not load, the service worker never starts,
or the popup raises. Run `bun run build` in extension/ first.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIST = REPO_ROOT / "extension" / "dist"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=DEFAULT_DIST)
    parser.add_argument("--headed", action="store_true", help="run with a visible window")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    dist = args.dist.resolve()
    if not (dist / "manifest.json").exists():
        print(f"! no manifest.json in {dist} — run `bun run build` in extension/ first")
        return 2

    from playwright.sync_api import sync_playwright

    manifest = json.loads((dist / "manifest.json").read_text())
    print(f"extension: {manifest.get('name')} v{manifest.get('version')} (MV{manifest.get('manifest_version')})")
    print(f"loading from: {dist}")

    failures: list[str] = []
    console_errors: list[str] = []

    # A fresh profile every run. Reusing one is not just untidy: a run started
    # headless (where Chromium refuses to load extensions) leaves a profile
    # behind, and every later run then silently loads no extension at all.
    profile_dir = Path(tempfile.mkdtemp(prefix="phishbrain-ext-profile-"))

    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=not args.headed,
            args=[
                f"--disable-extensions-except={dist}",
                f"--load-extension={dist}",
                "--no-sandbox",
            ],
        )
        try:
            context.on("weberror", lambda err: console_errors.append(str(err)))

            # --- service worker (MV3 background) ------------------------------
            # Chromium ignores extensions entirely in headless mode; say so
            # rather than reporting a confusing "worker never started".
            worker = None
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                workers = [w for w in context.service_workers if w.url.startswith("chrome-extension://")]
                if workers:
                    worker = workers[0]
                    break
                time.sleep(0.25)

            if worker is None:
                hint = (
                    " (Chromium does not load extensions in headless mode — rerun with --headed)"
                    if not args.headed
                    else ""
                )
                failures.append(f"the MV3 service worker never started{hint}")
                print(f"  [FAIL] service worker did not start{hint}")
            else:
                print(f"  [ OK ] service worker started: {worker.url}")

            # --- popup page ---------------------------------------------------
            if worker is not None:
                extension_id = worker.url.split("//")[1].split("/")[0]
                print(f"  [ OK ] extension id: {extension_id}")
                popup = context.new_page()
                popup.on("console", lambda msg: console_errors.append(f"[{msg.type}] {msg.text}")
                        if msg.type == "error" else None)
                popup.on("pageerror", lambda err: console_errors.append(f"[pageerror] {err}"))
                try:
                    popup.goto(f"chrome-extension://{extension_id}/popup.html", timeout=15000)
                    popup.wait_for_timeout(2500)
                    text = (popup.inner_text("body") or "").strip()
                    mounted = len(text) > 0
                    print(f"  [{' OK ' if mounted else 'FAIL'}] popup rendered ({len(text)} chars): "
                          f"{text[:80]!r}")
                    if not mounted:
                        failures.append("the popup rendered nothing (React root never mounted)")
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"popup failed to load: {type(exc).__name__}: {exc}")
                    print(f"  [FAIL] popup: {exc}")

                # --- options page ---------------------------------------------
                options = context.new_page()
                options.on("pageerror", lambda err: console_errors.append(f"[options pageerror] {err}"))
                try:
                    options.goto(f"chrome-extension://{extension_id}/options.html", timeout=15000)
                    options.wait_for_timeout(2000)
                    text = (options.inner_text("body") or "").strip()
                    print(f"  [{' OK ' if text else 'FAIL'}] options page rendered ({len(text)} chars)")
                    if not text:
                        failures.append("the options page rendered nothing")
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"options page failed to load: {type(exc).__name__}: {exc}")
                    print(f"  [FAIL] options: {exc}")
        finally:
            context.close()

    shutil.rmtree(profile_dir, ignore_errors=True)

    if console_errors:
        print("\nconsole errors:")
        for line in console_errors[:20]:
            print(f"  - {line}")
        failures.extend(console_errors[:5])

    print()
    if failures:
        print(f"FAILED: {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("PASSED: the extension loads and its pages render in a real Chromium")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
