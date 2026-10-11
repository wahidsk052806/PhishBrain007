# PhishBrain ML Pipeline

This directory contains the offline ML pipeline that trains and evaluates
the CatBoost **prefilter** model used by the backend's PREFILTER stage.

## Layout
- `preprocessing/` — feature extraction, mirroring the backend's URL/email
  analyzer contract (`url_features.py`, `email_features.py`, `text_clean.py`).
- `models/prefilter_catboost.py` — train/save/load/predict_proba wrapper
  around CatBoost. Saves to `backend/models/prefilter.cbm`.
- `training/train_prefilter.py` — CLI to train from a prepared dataset,
  with optional strict time-based (zero-day) split, held-out evaluation and
  the deployment gate.
- `evaluation/metrics.py`, `evaluation/report.py` — real metrics only; if no
  dataset/model exists, the report explicitly prints "Not evaluated".
- `evaluation/gate.py` — the **minimum acceptance bar** a candidate model must
  clear before it can be deployed, as two named tiers (`strict`, `triage`). See
  below.
- `evaluation/calibration.py` — monotone Platt correction turning the
  class-weighted score into a probability, plus expected calibration error.
  Opt-in (`--calibrate`); see the section on why it is off by default.
- `zero_day_split.py` — leakage-free time-ordered train/test split, driven
  by real observation timestamps.

## Quick start
```bash
pip install -r ml/requirements.txt
python scripts/data/download_data.py --confirm       # opt-in, public feeds
python scripts/data/fetch_benign_urls.py --confirm   # benign URLs *with paths*
python scripts/data/prepare_dataset.py
python ml/training/train_prefilter.py --data data/processed/prefilter_dataset.csv
python ml/evaluation/report.py --data data/processed/prefilter_dataset.csv
```

No dataset or trained model is bundled with this repo. Until you run the
steps above with real data, `ml/evaluation/reports/latest.md` will read
"Not evaluated" for every metric — this is intentional, not a bug.

## Zero-day evaluation (real observation timestamps)

The headline metric is **`zero_day_detection_rate`**: the share of phishing URLs
caught whose registrable domain never appeared in training. It only means
something if the split is ordered by time, so `prepare_dataset.py` preserves the
observation times the feeds actually provide instead of inventing any:

| Source | Observation time | Column value |
|---|---|---|
| PhishTank | first community report | `timestamp_source=phishtank-submission_time` |
| Internet Archive captures | when the archive fetched the URL | `timestamp_source=wayback-cdx-capture` |
| OpenPhish, Tranco, `tranco-www` | none available | `timestamp_source=none` |

`--split auto` (the default) therefore trains on rows observed **before** a
cutoff and scores rows observed **at or after** it, then drops every test
phishing row whose registrable domain training had already seen. Rows with no
observation time are kept out of the test set (`--undated-policy train`) rather
than assigned a date. `--cutoff 2026-07-01` pins the boundary so numbers stay
comparable as data accumulates; `--split random` is still available but is
labelled in the output as *not* a zero-day measurement.

Two honest caveats the reports state explicitly:

- **Timestamp coverage.** Benign URLs only carry a real observation time when
they came from the archive (`fetch_benign_urls.py`); Tranco rows have none, so
the dated slice is smaller than the dataset. Every report prints the coverage.
- **Domain holdout scope.** `--dedup-scope positives` (default) holds out test
  *phishing* domains, because a phishing domain is a campaign and reappearing on
  both sides of the cutoff is real leakage. It does not hold out benign domains:
  with a purely lexical feature set (`preprocessing/url_features.py` has no
domain-identity input) a shared benign domain cannot hand the model an answer,
  and holding it out would make the false-positive rate unmeasurable. Reports
  print how many benign test rows share a training domain, and
  `--dedup-scope all` gives the strict variant.

## The deployment gate

Training does **not** end with an unconditional `save()`. The candidate is
scored on a held-out split, and `ml/evaluation/gate.py` must pass before
`backend/models/prefilter.cbm` is written. Otherwise the run exits non-zero,
leaves any previously deployed model alone, and records the failing checks in
`ml/evaluation/reports/train_gate.{json,md}`. The bar covers recall,
precision, ROC-AUC, the overall false-positive rate, a false-positive ceiling
restricted to **benign URLs that have a path**, and per-sample latency.

The same bar is enforced in CI: `.github/workflows/prefilter-gate.yml`
re-downloads the feeds, rebuilds the dataset, retrains and **fails the build
when the candidate misses the bar**. A red run there is the gate working — the
candidate was refused, nothing was deployed, and the job prints the gate report
(also uploaded as an artifact). Do not "fix" it by loosening the thresholds
without deciding, deliberately, that the lower bar is acceptable for a security
signal.

### Two tiers, and why the default is the lower one

`GATE_TIERS` names two bars instead of quietly relaxing one:

- **`strict`** — the defaults above: the bar for a stage trusted to decide on
  its own (e.g. letting the prefilter short-circuit the pipeline).
- **`triage`** — the bar the **default** run enforces: recall may be lower
  because the URL, domain, webpage and LLM layers exist to catch the remainder,
  while the false-positive ceilings stay tight because false alarms are what
  cost user trust. It is the honest bar for a component that contributes
  `PREFILTER_WEIGHT` (15%) of the blended score and is disclosed in every report.

The reason for the split is measured, not aesthetic: on the honest time split,
the lowest threshold that satisfies `max_false_positive_rate` reaches only ~0.79
recall, so no purely lexical model can clear `strict`. Gating on `strict`
therefore guaranteed a permanently red job *and* left an unvalidated model
deployed — the worst of both. Every run evaluates and reports **both** tiers,
and the artifact records the tier it cleared (`gate.tier`, `gate.strict_passed`),
so "deployed" is never read as "precision-grade".

### Small samples and the false-positive ceiling

The triage tier widens the false-positive ceilings by 1.96 standard errors of the
*measured* benign sample and prints the allowance next to the threshold
(today: 110 benign test rows, +5.6pp). This is not a discount: the estimate's own
standard error is ~2.9pp, so an exact ceiling would reject candidates over a
difference smaller than the measurement's noise. The allowance shrinks by itself
as benign data grows — and `--dedup-scope all` (hold out benign domains too) is
available when you want the strictest reading.

The zero-day detection rate is *reported* but not *gated*: it is only
measurable on a dataset with timestamps, and a missing measurement must not be
confused with a failed one.

## Structural confounds (and why the dataset needs more than the feeds)

Phishing feeds are deep URLs; Tranco is apex homepages; phishing hosts live on
subdomains more often than ranked benign sites do. Trained naively on that mix,
CatBoost learns **"has a path ⇒ phishing"** and **"bare URL on a subdomain ⇒
phishing"** — scoring `https://en.wikipedia.org/wiki/Phishing` or
`https://www.wikipedia.org` as near-certain phishing.

Two mechanisms address this:

1. `scripts/data/fetch_benign_urls.py` adds real benign URLs *with paths* (and
   subdomain homepages) captured from the Internet Archive, and
   `scripts/data/prepare_dataset.py` emits a composite `structure` column
   (`pathX_subY`) describing each URL.
2. `train_prefilter.py --structure-weights` (default on) re-weights rows so the
   label carries no information about the structure bucket. Structural columns
   are also excluded from the feature set.

Use `--no-structure-weights` to see the difference: it measurably raises false
positives on ordinary deep pages.

## Probability calibration and the decision threshold

The model is trained with balanced class weights (the feeds are ~15:1
phishing:benign, so an unweighted fit collapses to "always phishing"). Those
weights are a prior shift, so the raw score is **not** the probability that a URL
is phishing — `ml/evaluation/calibration.py` implements the monotone Platt
correction for it, and `ml/training/train_prefilter.py` can fit and store one in
the model's metadata (the backend replays it verbatim at inference).

**Both `--calibrate` and `--select-threshold` are off by default, on measured
evidence.** A fitted map is only as good as the class mix of the data it is
fitted on, and every slice this dataset can offer is phishing-heavy — the benign
side of the observation window is only 110 rows:

| Fit on | Effect on the honest test split |
|---|---|
| Random slice of the training period | FPR@0.5 **0.11 → 0.31** (worse) |
| Latest 10% of the training period | degenerate (recent benign rows ≈ 0), threshold collapsed to 1.0, recall 0 |

So the served score stays the model's own class-weighted number, and the honest
response is to *disclose* the operating point rather than to dress it up: every
scan reports `decision_threshold` and `score_above_threshold`, so a reader can
tell whether 42/100 is over the line the model was validated at (it is not — the
validated point is 50/100). Re-enable the switches once benign coverage of the
observation window improves; the code paths and their tests are in place for
that day.

A caveat worth stating plainly: with benign test data this thin, the
false-positive rate is the noisiest number in the report. The denominator is
recorded (`metrics.benign_rows`) so the sampling error can always be recomputed.

## Interpreting a failing gate

A candidate that misses the bar is usually telling you something real about the
data rather than about CatBoost. The two failures seen on the bundled public
feeds are worth knowing about:

- **High false positives on benign URLs with a path** — the structural shortcut
  from the feeds (phishing URLs are deep, Tranco rows are homepages). Fix by
  running `fetch_benign_urls.py` (more benign deep URLs), not by lowering
  `--max-benign-path-fpr`.
- **Recall below the floor on new domains** — phishing on free hosting
  (`*.vercel.app`, `*.weebly.com`, ...) is lexically indistinguishable from
  ordinary pages. No purely lexical model can reach a high recall on it; the
  honest responses are to add features (page content, domain age, brand
  similarity) or to accept and document the lower recall.

## Feature contract note
`preprocessing/url_features.py` is written to mirror the feature semantics
expected from the backend's URL analyzer (`backend/app/analyzers/url/`).
Because the backend is developed independently, keep the feature names in
sync if the backend's schema changes — the model itself is agnostic to
exact column names as long as train and inference use the same ones.
