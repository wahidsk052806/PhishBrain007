# data/

No copyrighted, private, or redistributable phishing/legitimate-site
datasets are committed to this repository, for licence and privacy
reasons.

## What goes here
- `data/raw/` — raw downloads from public feeds (created by
  `scripts/data/download_data.py`, opt-in only). Gitignored contents.
- `data/processed/` — cleaned/labeled feature tables produced by
  `scripts/data/prepare_dataset.py`. Gitignored contents.

Only this `README.md` and a `.gitkeep` placeholder are tracked in git.

## Getting data yourself
1. `python scripts/data/download_data.py --confirm` — fetches small public
   feeds (PhishTank, OpenPhish, Tranco top sites) **only if you opt in** and
   are online. Respect each feed's Terms of Service and licence before using
   the data for anything beyond local research/testing:
   - PhishTank: https://phishtank.org/ (registration + API key may be required; data is community-contributed)
   - OpenPhish: https://openphish.com/ (free feed is rate-limited/delayed; check current ToS)
   - Tranco: https://tranco-list.eu/ (top-sites list, citation requested — see their site for the citation format)
2. `python scripts/data/fetch_benign_urls.py --confirm` — collects **benign
   URLs that contain real paths** (plus subdomain homepages) from the Internet
   Archive's public CDX index, over a sample of Tranco domains. Also opt-in,
   resumable (re-running accumulates more), and offline-safe. Check the
   Internet Archive's terms before redistributing anything derived from it.
   Without this step the phishing feeds (deep URLs) and Tranco (apex homepages)
   are structurally mismatched, and the model learns "URL has a path ⇒
   phishing". See ml/README.md.

   The archive also reports **when it captured each URL**, and that capture
   time is kept as the URL's observation time. It is what allows a real
   time-ordered (zero-day) evaluation of benign traffic, so avoid editing the
   state file's `captures` map by hand. Use `--capture-from` / `--capture-to`
   if you want the benign observation window to line up with the phishing
   feed's — a narrower window means fewer URLs, because the archive returns one
   capture per URL inside it.
3. `python scripts/data/prepare_dataset.py` — turns raw downloads into a
   labeled feature table for training, including the structural `has_path` /
   `has_subdomain` / `structure` columns used to de-confound training. The
   `tranco-www` rows are a *derived* expansion of the Tranco apex list (labelled
   separately so they can be excluded) that supplies benign subdomain homepages.
   It also writes `timestamp` / `timestamp_source`, carrying each row's **real**
   observation time where one exists (see above) and leaving it empty otherwise —
   no dates are fabricated. The step prints the resulting coverage, and the
   training/evaluation scripts report the zero-day detection rate on that basis.
4. `python scripts/data/train_prefilter.py` / `evaluate.py` — train and
   evaluate the prefilter model. Training refuses to deploy a model that does
   not clear the bar in `ml/evaluation/gate.py`.

If you skip all of the above, the ML pipeline still runs end-to-end and
reports "Not evaluated" everywhere a real metric would go.
