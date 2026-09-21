#!/usr/bin/env python3
"""
fetch_benign_urls.py
--------------------
OPT-IN collection of **benign URLs that contain real paths**, used to fix a
structural shortcut in the prefilter training set.

Why this exists
~~~~~~~~~~~~~~~
The bundled feeds are structurally mismatched:

  - Phishing feeds (OpenPhish, PhishTank) are *deep* URLs — they almost
    always carry a path and often a query string.
  - Tranco's top-sites list is *bare homepages* (`https://google.com`).

Trained on that mix, CatBoost trivially learns "this URL has a path ⇒
phishing", scores ordinary pages like `https://en.wikipedia.org/wiki/Phishing`
at ~100%, and stops being a useful prefilter. `ml/README.md` and
`data/README.md` describe the same caveat.

This script adds the missing half: real, deep URLs harvested from the
Internet Archive's public CDX index (https://web.archive.org/) for a sample
of Tranco domains. Every URL is a real capture of a real page, not a
fabricated or rewritten one.

Safety / etiquette
~~~~~~~~~~~~~~~~~~
  - Opt-in: does nothing without ``--confirm``.
  - Non-destructive: only writes under ``data/raw/``.
  - Offline-safe: network failures skip a domain and never crash the run.
  - Resumable: results are appended to a JSONL state file, so re-running
    continues where the previous run stopped (already-fetched domains are
    skipped) instead of re-hammering the archive.
  - Politeness: a small fixed worker pool, a per-request timeout, and a
    deliberate stagger between requests.

Usage
~~~~~
    python scripts/data/fetch_benign_urls.py --confirm
    python scripts/data/fetch_benign_urls.py --confirm --max-domains 400 --target 6000
    python scripts/data/fetch_benign_urls.py --confirm --state-file data/raw/benign_urls.jsonl

Outputs
~~~~~~~
  - ``data/raw/benign_urls.txt``    — one URL per line (consumed by prepare_dataset.py)
  - ``data/raw/benign_urls.jsonl``  — provenance/state (one line per domain),
    including each URL's **real capture timestamp** from the CDX index

Observation timestamps
~~~~~~~~~~~~~~~~~~~~~~
Every CDX row carries the archive's own capture time, so each collected URL
gets a real ``captured_at`` observation time instead of a fabricated one
(``prepare_dataset.py`` turns it into the ``timestamp`` column). That is what
makes a leakage-free, time-ordered split — and therefore a genuine zero-day
detection rate — possible: ``ml/zero_day_split.py`` can hold out URLs observed
after a cutoff, not just a random sample of them. Use ``--capture-from`` /
``--capture-to`` to restrict captures to a window that lines up with the
phishing side's observation window.

Check the Internet Archive's terms before redistributing anything derived
from this data.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "data" / "raw"
TRANCO_ZIP = RAW_DIR / "tranco_top1m.csv.zip"
DEFAULT_OUT = RAW_DIR / "benign_urls.txt"
DEFAULT_STATE = RAW_DIR / "benign_urls.jsonl"

CDX_ENDPOINT = "http://web.archive.org/cdx/search/cdx"
USER_AGENT = "PhishBrain-benign-corpus/1.0 (+local ML training data prep)"

# Only characters that legitimately appear in a URL path/query. Anything
# outside this set (spaces, quotes, backslashes, control bytes, "|||", ...)
# is a junk capture, not a real page.
# Real page paths are alphanumeric words joined by '/', '-', '_', '.' and
# percent-escapes. Deliberately narrow: browser/scanner junk like
# `/,a.innerHTML=` or `/(means` must not enter the benign corpus, or the model
# learns "weird punctuation ⇒ the real site", which is a fresh artifact.
_PATH_CHARS = re.compile(r"^[A-Za-z0-9._~%/\-]*$")
# Query strings legitimately contain '&', '=', '?' and '+' as well.
_QUERY_CHARS = re.compile(r"^[A-Za-z0-9._~%/?&=+\-]*$")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{2,}")

# Percent-encoded characters that only ever show up in scanner noise or
# malformed captures (quotes, angle brackets, backslashes, pipes, NUL, space).
_JUNK_ENCODINGS = (
    "%22", "%3c", "%3e", "%5c", "%7c", "%00", "%20",
    "%e2%80%8e",  # zero-width space
    "%ef%bb%bf",  # byte-order mark
    "%c2%a0",     # non-breaking space
)

# Static-asset extensions. A benign corpus of `.js`/`.gif`/`.css` URLs would
# just replace the "has a path ⇒ phishing" shortcut with "ends in .js ⇒
# benign", which is equally useless for scoring real pages — so drop them and
# keep page-like URLs (including .html/.php/.asp style paths).
_ASSET_EXTENSIONS = {
    "gif", "jpg", "jpeg", "png", "webp", "svg", "ico", "bmp", "tif", "tiff",
    "css", "js", "mjs", "json", "xml", "txt", "map", "wasm", "woff", "woff2",
    "ttf", "otf", "eot", "pdf", "zip", "gz", "tar", "tgz", "rar", "7z",
    "swf", "mp3", "mp4", "m4a", "avi", "mov", "wmv", "webm", "ogg",
    "csv", "xls", "xlsx", "doc", "docx", "ppt", "pptx", "rss", "atom",
}

# Reserved/infrastructure prefixes that are not user-facing pages.
_DROP_PREFIXES = ("well-known", "cgi-bin", "cgi", "_next", "_nuxt", "cdn-cgi")


def _normalize_default_port(parts) -> str:
    host = parts.netloc
    if host.endswith(":80") and parts.scheme == "http":
        host = host[:-3]
    elif host.endswith(":443") and parts.scheme == "https":
        host = host[:-4]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))


def clean_url(url: str, domain: str) -> str | None:
    """Return a normalized URL, or None if it is junk/not a real deep page.

    The filters below are intentionally conservative: a benign corpus that
    contains scanner noise (`http://microsoft.com/%22?`) would teach the model
    to associate nonsense characters with legitimate sites, which is just a
    different artifact from the one we are removing.
    """
    url = (url or "").strip()
    if not url or len(url) > 300:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None

    host = (parts.hostname or "").lower()
    if host != domain and not host.endswith("." + domain):
        return None

    path, query = parts.path or "", parts.query or ""
    is_homepage = len(path.strip("/")) < 2

    if is_homepage and host == domain:
        # Tranco already supplies apex homepages (`https://wikipedia.org`).
        return None
    # A *subdomain* homepage (`https://www.wikipedia.org/`) is kept on purpose.
    # Real traffic is full of them, but the benign side of the feeds has almost
    # none (Tranco is apex-only) while phishing hosts very often sit on a
    # subdomain — so excluding them hands the model a second shortcut:
    # "bare URL on a subdomain => phishing".

    if not _PATH_CHARS.match(path) or not _QUERY_CHARS.match(query):
        return None
    if "&" in path or " " in url or "//" in path or "\\" in url:
        return None
    if any(token in url.lower() for token in _JUNK_ENCODINGS):
        return None

    if not is_homepage:
        if not _ALNUM_RUN.search(path):
            return None
        segments = [s for s in path.split("/") if s]
        if segments[0].lower().lstrip(".") in _DROP_PREFIXES:
            return None
        last = segments[-1].lower()
        if "." in last and last.rsplit(".", 1)[1] in _ASSET_EXTENSIONS:
            return None

    return _normalize_default_port(parts)


def split_ranks(lines, sample_pool: int, sample_seed: int, max_domains: int, start_rank: int):
    """Pick a deterministic pseudo-random sample of Tranco domains.

    Sampling rather than taking the head of the list avoids the mega-sites
    (google.com, facebook.com, ...) whose archives are enormous, slow to
    query, and give a poor path yield — and it spreads the benign corpus
    across many more distinct hosts.
    """
    domains: list[str] = []
    for i, line in enumerate(lines):
        if i >= sample_pool:
            break
        if i < start_rank:
            continue
        parts = line.decode("utf-8", errors="ignore").strip().split(",")
        if len(parts) == 2 and parts[1]:
            domains.append(parts[1].strip().lower())
    rng = random.Random(sample_seed)
    rng.shuffle(domains)
    return domains[:max_domains]


def load_tranco_domains(path: Path, *, sample_pool: int, sample_seed: int,
                        max_domains: int, start_rank: int) -> list[str]:
    with zipfile.ZipFile(path) as zf:
        inner = zf.namelist()[0]
        with zf.open(inner) as fh:
            lines = list(fh)
    return split_ranks(lines, sample_pool, sample_seed, max_domains, start_rank)


def load_state(state_path: Path) -> dict[str, dict]:
    """Read the append-only state file, unioning URLs for repeated domains.

    A `--refetch` run re-queries a domain with different limits, so it can
    legitimately return fewer kept URLs than the earlier attempt (a higher
    `--limit` changes which rows `pick_diverse` sees). Unioning rather than
    letting the newest entry win means a later run can only ever add URLs,
    never silently drop ones a previous run had already collected.
    """
    state: dict[str, dict] = {}
    if not state_path.exists():
        return state
    for line in state_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:  # noqa: BLE001 - tolerate a truncated final line
            continue
        domain = entry.get("domain")
        if not domain:
            continue
        previous = state.get(domain)
        if previous is None:
            state[domain] = dict(entry)
            continue
        merged = list(dict.fromkeys([
            *(previous.get("urls") or []),
            *(entry.get("urls") or []),
        ]))
        # A URL's observation time only ever comes from the archive, so an
        # earlier real capture time is always at least as good as a later one;
        # never overwrite a known timestamp with a missing one.
        captures = {
            k: v for k, v in (previous.get("captures") or {}).items() if v
        }
        for url, stamp in (entry.get("captures") or {}).items():
            if stamp and not captures.get(url):
                captures[url] = stamp
        state[domain] = {
            **previous,
            **{k: v for k, v in entry.items() if k not in ("urls", "status", "reason", "captures")},
            "status": entry.get("status", previous.get("status")),
            "urls": merged,
            "captures": captures,
        }
    return state


def query_wayback(domain: str, *, limit: int, timeout: float,
                  capture_from: str | None = None,
                  capture_to: str | None = None) -> list[tuple[str, str]]:
    """Return ``(url, capture_timestamp)`` pairs for a domain.

    ``collapse=urlkey`` keeps one row per distinct URL; combined with
    ``capture_from`` that row is the URL's first capture inside the window, so
    the timestamp is a real observation time rather than an invented one.
    """
    params = {
        "url": domain,
        "matchType": "domain",
        "collapse": "urlkey",
        "limit": str(limit),
        "fl": "original,timestamp",
        "output": "json",
        "filter": "statuscode:200",
    }
    if capture_from:
        params["from"] = capture_from
    if capture_to:
        params["to"] = capture_to
    request = urllib.request.Request(
        f"{CDX_ENDPOINT}?{urllib.parse.urlencode(params)}",
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        raw = response.read().decode("utf-8", errors="ignore")
    if not raw.strip() or raw.lstrip().startswith("<"):
        return []  # empty result or an HTML error page
    rows = json.loads(raw)
    pairs: list[tuple[str, str]] = []
    for row in rows[1:]:
        if not row:
            continue
        url = row[0]
        stamp = row[1] if len(row) > 1 else ""
        if url:
            pairs.append((url, _parse_cdx_timestamp(stamp)))
    return pairs


def _parse_cdx_timestamp(value: str) -> str:
    """Convert a CDX ``YYYYMMDDhhmmss`` stamp to ISO-8601 UTC.

    Returns ``""`` when the stamp is absent or malformed, so callers can tell
    "no real observation time" apart from a real one instead of inventing one.
    """
    value = (value or "").strip()
    if len(value) != 14 or not value.isdigit():
        return ""
    return (f"{value[0:4]}-{value[4:6]}-{value[6:8]}T"
            f"{value[8:10]}:{value[10:12]}:{value[12:14]}+00:00")


def pick_diverse(pairs: list[tuple[str, str]], per_domain: int) -> list[tuple[str, str]]:
    """Prefer distinct sections of a site, then distinct sub-paths.

    Round-robin across first path segments so one heavily-archived section
    cannot fill a host's whole quota with near-identical URLs.
    """
    buckets: dict[str, list[tuple[str, str]]] = {}
    for url, stamp in pairs:
        segments = [s for s in urlsplit(url).path.split("/") if s]
        key = segments[0].lower() if segments else ""
        buckets.setdefault(key, []).append((url, stamp))
    picked: list[tuple[str, str]] = []
    for _ in range(per_domain):
        progressed = False
        for key in sorted(buckets):
            if len(picked) >= per_domain:
                break
            if buckets[key]:
                picked.append(buckets[key].pop(0))
                progressed = True
        if not progressed:
            break
    return picked


def job(domain: str, limit: int, per_domain: int, timeout: float,
        capture_from: str | None = None, capture_to: str | None = None) -> dict:
    started = time.time()
    try:
        raw_rows = query_wayback(domain, limit=limit, timeout=timeout,
                                 capture_from=capture_from, capture_to=capture_to)
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "domain": domain,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "status": "skipped",
            "reason": f"{type(exc).__name__}: {exc}",
            "raw_count": 0,
            "elapsed_ms": round((time.time() - started) * 1000, 1),
            "urls": [],
            "captures": {},
        }

    seen: set[str] = set()
    cleaned: list[tuple[str, str]] = []
    for url, stamp in raw_rows:
        normalized = clean_url(url, domain)
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append((normalized, stamp))

    picked = pick_diverse(cleaned, per_domain)
    return {
        "domain": domain,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "status": "ok",
        "reason": None,
        "raw_count": len(raw_rows),
        "elapsed_ms": round((time.time() - started) * 1000, 1),
        "urls": [url for url, _ in picked],
        "captures": {url: stamp for url, stamp in picked if stamp},
    }


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--confirm", action="store_true",
                   help="Required flag to actually contact the archive (opt-in).")
    p.add_argument("--tranco", type=Path, default=TRANCO_ZIP,
                   help="Tranco CSV zip used as the benign domain list.")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--state-file", type=Path, default=DEFAULT_STATE)
    p.add_argument("--max-domains", type=int, default=300,
                   help="How many domains to query in this/overall run.")
    p.add_argument("--target", type=int, default=6000,
                   help="Stop once this many usable URLs have been collected.")
    p.add_argument("--per-domain", type=int, default=6,
                   help="Maximum URLs to keep per domain.")
    p.add_argument("--limit", type=int, default=200,
                   help="Raw CDX rows to request per domain.")
    p.add_argument("--timeout", type=float, default=25.0,
                   help="Per-request timeout in seconds; slow domains are skipped.")
    p.add_argument("--workers", type=int, default=3,
                   help="Concurrent CDX requests (kept small out of politeness).")
    p.add_argument("--stagger", type=float, default=0.3,
                   help="Seconds to wait between launching requests.")
    p.add_argument("--sample-pool", type=int, default=200_000,
                   help="Sample domains from this many Tranco ranks.")
    p.add_argument("--sample-seed", type=int, default=42)
    p.add_argument("--start-rank", type=int, default=0)
    p.add_argument("--refetch", action="store_true",
                   help="Re-query domains already in the state file (use with a higher "
                        "--per-domain/--limit to deepen the corpus). Newer entries win.")
    p.add_argument("--capture-from", type=str, default=None,
                   help="Only keep captures at/after this CDX date (YYYY, YYYYMM, or "
                        "YYYYMMDD). Use it to line the benign observation window up with "
                        "the phishing feed's.")
    p.add_argument("--capture-to", type=str, default=None,
                   help="Only keep captures at/before this CDX date.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not args.confirm:
        print("This script contacts the Internet Archive (https://web.archive.org/) and is opt-in.")
        print("Re-run with --confirm to proceed. No files will be created otherwise.")
        return 0

    if not args.tranco.exists():
        print(f"Tranco list not found at {args.tranco}.")
        print("Run `python scripts/data/download_data.py --confirm` first.")
        print("Not evaluated: benign URL collection skipped.")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    state = load_state(args.state_file)

    candidates = load_tranco_domains(
        args.tranco,
        sample_pool=args.sample_pool,
        sample_seed=args.sample_seed,
        max_domains=args.max_domains + len(state),
        start_rank=args.start_rank,
    )
    if args.refetch:
        # Deepen domains we already know yield usable URLs, rather than paying
        # the same request cost to discover brand new ones.
        known = [d for d in state if d in set(candidates)]
        # Deepest archives first: those domains have proven they hold usable
        # page URLs, and unioning means a repeat visit can only add more.
        ranked = sorted(known, key=lambda d: -len(state[d].get("urls") or []))
        todo = ranked[: args.max_domains]
    else:
        todo = [d for d in candidates if d not in state][: args.max_domains]

    print(f"Archive: {CDX_ENDPOINT}")
    print(f"Domains already collected: {len(state)} | queued now: {len(todo)}"
          + (" (refetching)" if args.refetch else ""))
    if not todo:
        print("Nothing new to fetch; rewriting the URL list from existing state.")

    state_lock = threading.Lock()
    # Count URLs (not domains) already on disk, using the superseding entries.
    total_urls = sum(len(entry.get("urls") or []) for entry in state.values())

    state_fh = args.state_file.open("a", encoding="utf-8")

    def run(index_domain: tuple[int, str]) -> dict:
        index, domain = index_domain
        time.sleep(args.stagger * (index % max(1, args.workers)))
        result = job(domain, args.limit, args.per_domain, args.timeout,
                     args.capture_from, args.capture_to)
        with state_lock:
            state_fh.write(json.dumps(result) + "\n")
            state_fh.flush()
            kept = len(result["urls"])
            marker = "ok " if result["status"] == "ok" else "skip"
            print(f"  [{marker}] {domain:34s} kept={kept:2d} raw={result['raw_count']:4d} "
                  f"{result['elapsed_ms']/1000:5.1f}s"
                  + ("" if result["status"] == "ok" else f"  ({result['reason']})"))
        return result

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for result in pool.map(run, list(enumerate(todo))):
                total_urls += len(result["urls"])
                if total_urls >= args.target:
                    print(f"Reached target of {args.target} URLs; stopping early.")
                    break
    finally:
        state_fh.close()

    # Rebuild the flat URL list from state (deduplicated, stable order).
    final_state = load_state(args.state_file)
    ordered: list[str] = []
    seen: set[str] = set()
    captures: dict[str, str] = {}
    for entry in final_state.values():
        for url in entry.get("urls") or []:
            if url not in seen:
                seen.add(url)
                ordered.append(url)
        for url, stamp in (entry.get("captures") or {}).items():
            if stamp and url not in captures:
                captures[url] = stamp
    args.out.write_text("\n".join(ordered) + ("\n" if ordered else ""), encoding="utf-8")

    stamped = sum(1 for url in ordered if url in captures)
    ok_domains = sum(1 for entry in final_state.values() if entry.get("status") == "ok")
    print(f"\nWrote {len(ordered)} unique benign URLs from {ok_domains} domains to {args.out}")
    print(f"Provenance/state: {args.state_file}")
    if ordered:
        print(f"Real capture timestamps: {stamped}/{len(ordered)} URLs "
              f"({stamped / len(ordered):.1%})")
    else:
        print("No URLs collected.")
    if ordered and stamped < len(ordered):
        print("NOTE: URLs without a capture timestamp are kept as unlabelled-by-time rows; "
              "prepare_dataset.py marks them timestamp_source=none and the time-based "
              "split keeps them out of the zero-day test set rather than guessing.")
    if len(ordered) < 1000:
        print("WARNING: fewer than 1000 URLs collected. Re-run later to accumulate more "
              "(the run resumes automatically), or raise --max-domains.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
