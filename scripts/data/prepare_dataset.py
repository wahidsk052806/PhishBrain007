#!/usr/bin/env python3
"""
prepare_dataset.py
--------------------
Turns raw downloaded feeds (data/raw/) into a labeled feature table
(data/processed/prefilter_dataset.csv) suitable for ml/training/train_prefilter.py.

Sources and labels
~~~~~~~~~~~~~~~~~~
  - PhishTank / OpenPhish  -> label 1 (phishing)
  - Tranco top-sites       -> label 0 (benign, bare homepages)
  - Tranco `www.` expansion-> label 0 (benign, bare subdomain homepages; DERIVED)
  - benign_urls.txt        -> label 0 (benign, real deep URLs)

Observation timestamps
~~~~~~~~~~~~~~~~~~~~~~
Two of the sources carry a **real observation time**, and both are preserved
here as the `timestamp` column so the prefilter can be evaluated the way it is
deployed (see ml/zero_day_split.py):

  - PhishTank `submission_time` — when the community first reported the
    campaign. This is what makes a genuine *zero-day* split possible: the
    phishing timeline is real, spanning years, so the model can be trained on
    the past and scored on later, unseen domains.
  - Wayback capture time (`benign_urls.jsonl`) — when the Internet Archive
    observed the benign URL. Collected by scripts/data/fetch_benign_urls.py.

Every row also records `timestamp_source`: `phishtank-submission_time`,
`wayback-cdx-capture`, or `none`. Nothing is fabricated — OpenPhish and Tranco
carry no observation time at all, so those rows are marked `none` and
ml/zero_day_split.py keeps them out of the zero-day test set instead of
guessing a date for them.

The `www.` expansion is the one *derived* source here, and it is labelled
`tranco-www` so anyone can exclude it. It exists because Tranco lists apex
domains only, while phishing hosts overwhelmingly live on subdomains: with no
benign subdomain homepages at all, the model learns "bare URL on a subdomain
=> phishing" and scores something as ordinary as `https://www.wikipedia.org`
as ~99% phishing. Asserting that `https://www.<top-5000-domain>` is benign is
a safe, conventional domain expansion — but it is an inference from the
ranking, not an observed capture, hence the separate source label.

The last one matters: phishing feeds are almost entirely *deep* URLs (they
carry a path), while Tranco's list is *bare homepages*. On that mix alone a
model learns "this URL has a path ⇒ phishing" and flags ordinary pages. The
tranco/wayback split therefore also records a structural `has_path` column
(and a `source` column) so training can detect and neutralise that shortcut
instead of silently learning it — see ml/evaluation/gate.py and the
--structure-weights handling in ml/training/train_prefilter.py.

If data/raw/ is empty, this script exits gracefully with guidance instead
of writing a fabricated dataset.
"""
from __future__ import annotations

import csv
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.preprocessing.url_features import extract_url_features_dict, partition_host  # noqa: E402

RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"
PROCESSED_DIR = Path(__file__).resolve().parents[2] / "data" / "processed"
BENIGN_URLS_FILE = RAW_DIR / "benign_urls.txt"
BENIGN_STATE_FILE = RAW_DIR / "benign_urls.jsonl"
TRANCO_LIMIT = 5000

TIMESTAMP_SOURCE_PHISHTANK = "phishtank-submission_time"
TIMESTAMP_SOURCE_WAYBACK = "wayback-cdx-capture"
TIMESTAMP_SOURCE_NONE = "none"


def _read_openphish(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def _read_phishtank_csv(path: Path) -> list[tuple[str, str]]:
    """Return ``(url, submission_time)`` pairs.

    `submission_time` is PhishTank's own first-report time and is kept verbatim
    (ISO-8601 with offset); an absent value stays empty rather than being
    replaced with the download date.
    """
    rows: list[tuple[str, str]] = []
    with path.open(newline="", encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            u = row.get("url")
            if u:
                rows.append((u, (row.get("submission_time") or "").strip()))
    return rows


def _read_benign_urls(path: Path) -> list[str]:
    """Real benign deep URLs collected by scripts/data/fetch_benign_urls.py."""
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_benign_captures(state_path: Path) -> dict[str, str]:
    """Map benign URL -> the archive's real capture time.

    Reads the fetcher's append-only state file, taking the earliest capture
    recorded for each URL (a URL re-queried for a later window must not lose
    the observation time already established for it).
    """
    captures: dict[str, str] = {}
    if not state_path.exists():
        return captures
    import json

    for line in state_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:  # noqa: BLE001 - tolerate a truncated final line
            continue
        for url, stamp in (entry.get("captures") or {}).items():
            if stamp and (url not in captures or stamp < captures[url]):
                captures[url] = stamp
    return captures


def _hostname(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _has_path(url: str) -> int:
    try:
        return int(bool(urlsplit(url).path.strip("/")))
    except ValueError:
        return 0


def _has_subdomain(url: str) -> int:
    """1 when the URL sits on a subdomain (uses public-suffix rules)."""
    host = _hostname(url)
    if not host:
        return 0
    try:
        subdomain, _, _ = partition_host(host)
    except Exception:  # noqa: BLE001
        return 0
    return int(bool(subdomain))


def _structure(has_path: int, has_subdomain: int) -> str:
    """Composite structural signature used to de-confound training.

    Both axes are confounded in the raw feeds: phishing feeds are deep URLs on
    hostnames, while Tranco is apex-domain homepages. Grouping on the pair lets
    the training weights neutralise each combination independently.
    """
    return f"path{has_path}_sub{has_subdomain}"


def _read_tranco_domains(path: Path, limit: int = TRANCO_LIMIT) -> list[str]:
    domains: list[str] = []
    with zipfile.ZipFile(path) as zf:
        inner = zf.namelist()[0]
        with zf.open(inner) as fh:
            for i, raw_line in enumerate(fh):
                if i >= limit:
                    break
                line = raw_line.decode("utf-8", errors="ignore").strip()
                parts = line.split(",")
                if len(parts) == 2 and parts[1].strip():
                    domains.append(parts[1].strip().lower())
    return domains


def _is_apex(host: str) -> bool:
    try:
        subdomain, domain, _ = partition_host(host)
    except Exception:  # noqa: BLE001
        return False
    return bool(domain) and not subdomain


def main() -> int:
    if not RAW_DIR.exists() or not any(RAW_DIR.iterdir()):
        print(f"No raw data found in {RAW_DIR}.")
        print("Run scripts/data/download_data.py --confirm first, or place your own")
        print("data (with 'url' and 'label' columns) under data/raw/.")
        print("Not evaluated: dataset preparation skipped.")
        return 0

    # (url, label, source, timestamp, timestamp_source) tuples, kept separate so
    # provenance survives. A missing timestamp is left empty on purpose: an
    # invented date would silently corrupt the time-based split.
    samples: list[tuple[str, int, str, str, str]] = []

    openphish = RAW_DIR / "openphish_feed.txt"
    if openphish.exists():
        samples += [(u, 1, "openphish", "", TIMESTAMP_SOURCE_NONE)
                    for u in _read_openphish(openphish)]

    phishtank = RAW_DIR / "phishtank_online_valid.csv"
    if phishtank.exists():
        samples += [(u, 1, "phishtank", t, TIMESTAMP_SOURCE_PHISHTANK if t else TIMESTAMP_SOURCE_NONE)
                    for u, t in _read_phishtank_csv(phishtank)]

    tranco = RAW_DIR / "tranco_top1m.csv.zip"
    if tranco.exists():
        domains = _read_tranco_domains(tranco)
        samples += [(f"https://{d}", 0, "tranco", "", TIMESTAMP_SOURCE_NONE) for d in domains]
        # Derived (not observed) benign subdomain homepages; see the module
        # docstring. Only expand genuine apex entries — Tranco also contains
        # hosts like `www.google.com`, which must not become `www.www.google.com`.
        samples += [
            (f"https://www.{d}", 0, "tranco-www", "", TIMESTAMP_SOURCE_NONE)
            for d in domains if _is_apex(d)
        ]

    if BENIGN_URLS_FILE.exists():
        captures = _read_benign_captures(BENIGN_STATE_FILE)
        samples += [
            (u, 0, "wayback-benign", captures.get(u, ""),
             TIMESTAMP_SOURCE_WAYBACK if captures.get(u) else TIMESTAMP_SOURCE_NONE)
            for u in _read_benign_urls(BENIGN_URLS_FILE)
        ]

    if not samples:
        print("Raw data directory exists but no recognized feed files were found.")
        print("Not evaluated: dataset preparation skipped.")
        return 0

    rows = []
    seen: set[str] = set()
    for url, label, source, timestamp, timestamp_source in samples:
        if not url or url in seen:
            continue
        seen.add(url)
        feats = extract_url_features_dict(url)
        has_path = _has_path(url)
        has_subdomain = _has_subdomain(url)
        feats.update({
            "url": url,
            # A real hostname (not the full URL) so domain grouping / zero-day
            # splitting in the training scripts actually means something.
            "domain": _hostname(url),
            "label": label,
            "source": source,
            "timestamp": timestamp,
            "timestamp_source": timestamp_source,
            "has_path": has_path,
            "has_subdomain": has_subdomain,
            "structure": _structure(has_path, has_subdomain),
        })
        rows.append(feats)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "prefilter_dataset.csv"
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    by_source: dict[str, int] = {}
    for row in rows:
        by_source[row["source"]] = by_source.get(row["source"], 0) + 1
    print(f"Wrote {len(rows)} rows to {out_path}")
    for source, count in sorted(by_source.items()):
        print(f"  {source:16s} {count}")
    structural = {}
    for row in rows:
        key = (row["label"], row["structure"])
        structural[key] = structural.get(key, 0) + 1
    print("  label/structure distribution (structure = path/subdomain):")
    for (label, structure), count in sorted(structural.items()):
        name = "phishing" if label == 1 else "benign  "
        print(f"    {name} {structure}: {count}")
    empty_cells = [
        structure for structure in sorted({row["structure"] for row in rows})
        if structural.get((0, structure), 0) == 0
    ]
    if empty_cells:
        print(
            "WARNING: no benign URLs in these structural cells: "
            + ", ".join(empty_cells)
            + ". The model can still learn that signature as a phishing shortcut; "
            "run scripts/data/fetch_benign_urls.py --confirm to fill them."
        )
    stamped = [row for row in rows if row["timestamp"]]
    print(f"  real observation timestamps: {len(stamped)}/{len(rows)} rows "
          f"({len(stamped) / len(rows):.1%})")
    by_ts_source: dict[str, int] = {}
    for row in rows:
        key = row["timestamp_source"]
        by_ts_source[key] = by_ts_source.get(key, 0) + 1
    for key, count in sorted(by_ts_source.items()):
        print(f"    timestamp_source={key:26s} {count}")
    for label, name in ((1, "phishing"), (0, "benign  ")):
        cell = [row for row in rows if row["label"] == label]
        if cell:
            share = sum(1 for row in cell if row["timestamp"]) / len(cell)
            print(f"    {name} rows with a timestamp: {share:.1%} ({len(cell)} rows)")
    if stamped:
        times = sorted(row["timestamp"] for row in stamped)
        print(f"  observation window: {times[0]} .. {times[-1]}")
        print("  A leakage-free time-ordered split (and therefore a real zero-day "
              "detection rate) is available from this dataset: rows without a "
              "timestamp are kept out of the zero-day test set rather than "
              "assigned an invented date.")
    else:
        print("NOTE: no real 'timestamp' column was available from these feeds, so "
              "the zero-day split cannot be used meaningfully on this particular "
              "dataset unless you add real observation timestamps.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
