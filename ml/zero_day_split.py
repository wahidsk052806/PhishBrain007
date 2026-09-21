"""
zero_day_split.py
------------------
Strict time-based train/test split used to estimate "zero-day" phishing
detection performance: how well the prefilter generalizes to campaigns and
domains that did NOT exist at training time.

This deliberately avoids the classic mistake of a random split, which leaks
future information (e.g. a phishing kit's domain appearing in both train
and test) and produces inflated accuracy numbers. Rules enforced here:

  1. A single cutoff timestamp separates train (< cutoff) from test (>= cutoff).
  2. Any registrable domain seen in train is REMOVED from test (no leakage
     of the exact same domain across the boundary, e.g. long-lived
     campaigns or re-labeled data).
  3. Optional group leakage check: if a `group_id` column (e.g. campaign id,
     phishing kit fingerprint) is provided, groups are exclusively assigned
     to either train or test based on their earliest timestamp.

Why the domain holdout is scoped to positives
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rule 2 exists because a phishing *domain* is a campaign: if the same URL or host
appears on both sides of the cutoff, the test row is not zero-day and the
metric is inflated. That is real leakage, so positives whose registrable domain
appears in training are always dropped (`dedup_scope="positives"`, the
default).

The same rule applied to *benign* rows leaks nothing, because there is no label
to leak: the benign class has no campaign structure, and the prefilter's only
inputs are lexical URL features (lengths, character counts, entropies, ratios,
TLD flags) with no domain-identity feature at all — see
ml/preprocessing/url_features.py. A model cannot recognise "this is
wikipedia.org"; it can only recognise short, word-like hostnames. So keeping a
benign test row whose domain was also seen during training shares only lexical
*style*, not an answer. Applying the strict rule to benign rows anyway is
available (`dedup_scope="all"`) but on datasets whose dated benign URLs all come
from long-lived domains it can make the false-positive rate unmeasurable,
which is worse than measuring it and saying so. Whichever mode is used, the
number of benign test rows that overlap a training domain is reported as
`negatives_domain_overlap` so nobody has to guess how strict the run was.

Where the timestamps come from
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nothing here invents a date. `scripts/data/prepare_dataset.py` only fills the
`timestamp` column from real observation times — PhishTank's `submission_time`
for phishing URLs and the Internet Archive's capture time for benign URLs — and
records the origin in `timestamp_source`.

Rows with **no** observation time (OpenPhish, Tranco and the derived
`www.` expansion) cannot honestly be placed on the timeline, so the default
`undated_policy="train"` puts them in the training half only. That is the
conservative direction: it can only give the model *more* benign training data,
it never leaks a test row's label, and it keeps the test set strictly
"observed after the cutoff". `undated_policy="drop"` discards them instead, and
`"error"` refuses to run — useful if a caller wants to be told that its
timestamps are too sparse to trust.

If the dataset has no usable timestamps at all, callers should treat results as
"Not evaluated" (see ml/evaluation/report.py) rather than fabricate numbers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

UNDATED_POLICIES = ("train", "drop", "error")
DEDUP_SCOPES = ("positives", "all")


@dataclass
class SplitResult:
    train: pd.DataFrame
    test: pd.DataFrame
    cutoff: pd.Timestamp
    zero_day_domains: set
    dropped_leaked_rows: int
    # Coverage details so a caller can describe *what* was actually measured
    # instead of presenting a split over a handful of dated rows as if it
    # covered the whole dataset.
    timestamped_rows: int = 0
    undated_rows: int = 0
    undated_policy: str = "train"
    undated_in_train: int = 0
    dedup_scope: str = "positives"
    # Benign test rows that share a registrable domain with training. Empty when
    # dedup_scope="all"; when populated it quantifies how strict the
    # false-positive measurement was (see the module docstring).
    negatives_domain_overlap: int = 0
    domains: dict = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        total = self.timestamped_rows + self.undated_rows
        return self.timestamped_rows / total if total else 0.0


def registrable_domain(hostname: str) -> str:
    """Best-effort registrable domain ("en.wikipedia.org" -> "wikipedia.org").

    Exposed publicly because both the split and the evaluation report must
    group by the *registrable* domain: a phishing kit usually rotates through
    subdomains of one registered domain, and comparing subdomains verbatim
    would let the same registrable domain appear on both sides of the cutoff.
    """
    try:
        import tldextract
        ext = tldextract.extract(hostname or "")
        return f"{ext.domain}.{ext.suffix}".strip(".")
    except ImportError:
        parts = (hostname or "").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (hostname or "")


# Backwards-compatible private alias.
_registrable_domain = registrable_domain


def time_based_split(
    df: pd.DataFrame,
    *,
    timestamp_col: str = "timestamp",
    domain_col: Optional[str] = "domain",
    group_col: Optional[str] = None,
    cutoff: Optional[pd.Timestamp] = None,
    test_fraction: float = 0.2,
    undated_policy: str = "train",
    dedup_scope: str = "positives",
    label_col: str = "label",
) -> SplitResult:
    """
    Split df into (train, test) with a strict time boundary and domain-level
    de-duplication so that "zero-day" test examples are truly unseen.

    If `cutoff` is not given, it is computed so that the last `test_fraction`
    of the *timestamped* rows fall into the test set. Rows without a usable
    timestamp are handled by `undated_policy` (see the module docstring); they
    never enter the test set.
    """
    if undated_policy not in UNDATED_POLICIES:
        raise ValueError(f"undated_policy must be one of {UNDATED_POLICIES}, got {undated_policy!r}.")
    if dedup_scope not in DEDUP_SCOPES:
        raise ValueError(f"dedup_scope must be one of {DEDUP_SCOPES}, got {dedup_scope!r}.")
    if timestamp_col not in df.columns:
        raise ValueError(f"'{timestamp_col}' column required for time-based split.")

    data = df.copy()
    data[timestamp_col] = pd.to_datetime(data[timestamp_col], utc=True, errors="coerce")
    undated = data[data[timestamp_col].isna()].copy()
    stamped = data[data[timestamp_col].notna()].sort_values(timestamp_col).copy()

    if stamped.empty:
        raise ValueError("No rows with valid timestamps to split on.")

    if undated_policy == "error" and len(undated):
        raise ValueError(
            f"{len(undated)} of {len(data)} rows have no observation timestamp; "
            "refusing to run a time-based split that silently ignores them."
        )

    if cutoff is None:
        cutoff_idx = int(len(stamped) * (1 - test_fraction))
        cutoff_idx = min(max(cutoff_idx, 0), len(stamped) - 1)
        cutoff = stamped.iloc[cutoff_idx][timestamp_col]

    train = stamped[stamped[timestamp_col] < cutoff].copy()
    test = stamped[stamped[timestamp_col] >= cutoff].copy()

    undated_in_train = 0
    if len(undated):
        if undated_policy == "train":
            # Keep them, but with no timestamp so nothing downstream mistakes
            # them for dated rows.
            undated_in_train = len(undated)
            train = pd.concat([train, undated], ignore_index=True)
        # "drop" simply leaves them out.

    if train.empty or test.empty:
        raise ValueError(
            "Time-based split produced an empty train or test set "
            f"(cutoff={cutoff}, timestamped rows={len(stamped)})."
        )

    dropped = 0
    negatives_domain_overlap = 0
    zero_day_domains: set = set()
    train_domains: set = set()
    test_domains: set = set()
    if domain_col and domain_col in data.columns:
        train_domains = set(train[domain_col].map(registrable_domain))
        test = test.copy()
        test["_reg_domain"] = test[domain_col].map(registrable_domain)
        seen_domain = test["_reg_domain"].isin(train_domains)
        if dedup_scope == "all" or label_col not in test.columns:
            leaked_mask = seen_domain
        else:
            # Only positives are held out: see the module docstring for why a
            # shared benign domain is not leakage for a lexical-only model.
            leaked_mask = seen_domain & (test[label_col] == 1)
            negatives_domain_overlap = int((seen_domain & (test[label_col] == 0)).sum())
        dropped = int(leaked_mask.sum())
        test = test[~leaked_mask].copy()
        test_domains = set(test["_reg_domain"].unique())
        zero_day_domains = test_domains - train_domains
        test = test.drop(columns=["_reg_domain"])

    if group_col and group_col in data.columns:
        # Ensure each group is entirely on one side, keyed by its first
        # occurrence timestamp relative to cutoff.
        first_seen = stamped.groupby(group_col)[timestamp_col].min()
        train_groups = set(first_seen[first_seen < cutoff].index)
        test = test[~test[group_col].isin(train_groups)].copy()

    if test.empty:
        raise ValueError(
            "Time-based split left no test rows after removing domains already "
            "seen in training; the dataset is too concentrated in time."
        )

    return SplitResult(
        train=train.reset_index(drop=True),
        test=test.reset_index(drop=True),
        cutoff=cutoff,
        zero_day_domains=zero_day_domains,
        dropped_leaked_rows=dropped,
        timestamped_rows=len(stamped),
        undated_rows=len(undated),
        undated_policy=undated_policy,
        undated_in_train=undated_in_train,
        dedup_scope=dedup_scope,
        negatives_domain_overlap=negatives_domain_overlap,
        domains={
            "train": len(train_domains),
            "test": len(test_domains),
            "zero_day": len(zero_day_domains),
        },
    )
