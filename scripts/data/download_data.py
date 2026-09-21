#!/usr/bin/env python3
"""
download_data.py
------------------
OPT-IN downloader for small, PUBLIC phishing/legitimate-URL feeds, used to
build a local training dataset for ml/. This script is:

  - Opt-in: it does nothing unless explicitly invoked with --confirm.
  - Non-destructive: it only writes new files under data/raw/, never
    deletes or overwrites files outside that directory.
  - Offline-safe: network failures are caught and reported; the script
    exits 0 (success, "skipped") rather than crashing, so it is safe to
    wire into CI or setup scripts.

Feeds (check current Terms of Service / licence before redistributing):
  - Tranco top-sites list (https://tranco-list.eu/) — benign-domain
    baseline. Cite Tranco per their site's instructions if you publish
    results derived from it.
  - OpenPhish free feed (https://openphish.com/) — a short list of
    recently reported phishing URLs; delayed vs. the paid feed.
  - PhishTank (https://phishtank.org/) — community-reported phishing URLs;
    an API key may be required for the full feed, and it is heavily
    rate-limited. This script only attempts the small "online valid" CSV
    which historically has been publicly reachable without a key; if it
    fails, it is skipped gracefully.

None of these feeds' data is committed to the repository (see
data/README.md). This script only downloads to your local `data/raw/`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlretrieve

RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"

FEEDS = {
    "tranco": {
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "filename": "tranco_top1m.csv.zip",
        "notes": "Benign domain baseline. Cite Tranco if you publish results.",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "filename": "openphish_feed.txt",
        "notes": "Free feed is delayed/rate-limited vs. paid feed. Check ToS.",
    },
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "filename": "phishtank_online_valid.csv",
        "notes": "Community-reported; may require an API key for reliable access.",
    },
}


def download_feed(name: str, spec: dict, dest_dir: Path) -> bool:
    dest = dest_dir / spec["filename"]
    print(f"[{name}] {spec['notes']}")
    try:
        urlretrieve(spec["url"], dest)  # noqa: S310 - explicit opt-in public feed
        print(f"[{name}] saved -> {dest}")
        return True
    except (URLError, OSError, TimeoutError) as exc:
        print(f"[{name}] SKIPPED (offline or unreachable): {exc}")
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--confirm", action="store_true",
                         help="Required flag to actually perform downloads (opt-in).")
    parser.add_argument("--feeds", nargs="*", choices=list(FEEDS), default=list(FEEDS),
                         help="Subset of feeds to download.")
    args = parser.parse_args(argv)

    if not args.confirm:
        print("This script downloads data from third-party public feeds and is opt-in.")
        print("Re-run with --confirm to proceed. No files will be created otherwise.")
        print("Feeds available:", ", ".join(FEEDS))
        return 0

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    any_success = False
    for name in args.feeds:
        ok = download_feed(name, FEEDS[name], RAW_DIR)
        any_success = any_success or ok

    if not any_success:
        print("No feeds could be downloaded (likely offline). This is not an error; "
              "re-run later or provide your own data under data/raw/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
