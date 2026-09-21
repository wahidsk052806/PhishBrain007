"""Error analysis for a prefilter candidate (diagnostics, not a gate).

Trains the same model on the same leakage-free split as `train_prefilter.py`
and then reports *what* the misses look like — the registrable domains behind
false negatives (missed phishing) and false positives (flagged benign), and how
many sit on free hosting. It never writes a model, so it is safe to point at a
candidate the deployment gate would refuse.

    python ml/evaluation/diagnose_errors.py --data data/processed/prefilter_dataset.csv
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml.evaluation.metrics import classification_metrics  # noqa: E402
from ml.models.prefilter_catboost import PrefilterCatBoost  # noqa: E402
from ml.preprocessing.url_features import FEATURE_NAMES  # noqa: E402
from ml.training.train_prefilter import (  # noqa: E402
    BENIGN_PATH_COL,
    compute_structure_weights,
)
from ml.zero_day_split import time_based_split  # noqa: E402

from ml.preprocessing.url_features import FREE_HOST_DOMAINS as FREE_HOSTS  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path,
                        default=REPO_ROOT / "data" / "processed" / "prefilter_dataset.csv")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--no-structure-weights", action="store_true")
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    feature_cols = [c for c in FEATURE_NAMES if c in df.columns]
    if not feature_cols:
        print("no feature columns found")
        return 1

    split = time_based_split(
        df,
        timestamp_col="timestamp",
        domain_col="domain" if "domain" in df.columns else None,
        cutoff=None,
        test_fraction=0.2,
        undated_policy="train",
        dedup_scope="positives",
        label_col="label",
    )
    train_df, test_df = split.train, split.test
    print(f"cutoff={split.cutoff}  train={len(train_df)}  test={len(test_df)}")
    print(f"unseen domains in test: {len(split.zero_day_domains)}")
    print(f"test label counts: {test_df['label'].value_counts().to_dict()}\n")

    val_df = None
    val_size = int(len(df) * 0.1)
    if 0 < val_size < len(train_df):
        pool = train_df.sample(frac=1.0, random_state=7)
        val_df, train_df = pool.iloc[:val_size], pool.iloc[val_size:]

    sample_weight = None
    if not args.no_structure_weights and "structure" in df.columns:
        sample_weight = compute_structure_weights(train_df, "label", "structure")

    model = PrefilterCatBoost(params={
        "iterations": args.iterations,
        "depth": args.depth,
        "learning_rate": args.learning_rate,
    })
    X_val = y_val = None
    if val_df is not None:
        X_val, y_val = val_df[feature_cols], val_df["label"]
    model.train(train_df[feature_cols], train_df["label"], X_val, y_val,
                feature_names=feature_cols, sample_weight=sample_weight)

    proba = model.predict_proba(test_df[feature_cols])
    scores = proba[:, 1] if proba.ndim == 2 else proba
    pred = (scores >= args.threshold).astype(int)

    metrics = classification_metrics(test_df["label"], pred, scores)
    print("metrics:", {k: (round(v, 4) if isinstance(v, (int, float)) else v)
                       for k, v in metrics.items()})
    if BENIGN_PATH_COL in test_df.columns:
        from ml.evaluation.metrics import subgroup_false_positive_rate
        fpr_path = subgroup_false_positive_rate(
            test_df["label"], pred, test_df[BENIGN_PATH_COL].to_numpy() == 1
        )
        print(f"fpr_benign_with_path: {fpr_path}")
    print()

    work = test_df.copy()
    work["score"] = scores
    work["pred"] = pred
    work["registered"] = work["domain"].astype(str).str.lower()
    work["free_host"] = work["registered"].isin(FREE_HOSTS)

    for title, frame in (
        ("FALSE NEGATIVES (phishing scored safe)", work[(work.label == 1) & (work.pred == 0)]),
        ("FALSE POSITIVES (benign scored phishing)", work[(work.label == 0) & (work.pred == 1)]),
    ):
        print(f"=== {title}: {len(frame)} of {int((work.label == (1 if 'NEG' in title else 0)).sum())} ===")
        if frame.empty:
            print("  (none)\n")
            continue
        print(f"  on known free hosting: {int(frame['free_host'].sum())}")
        print("  top registrable domains:")
        for domain, count in Counter(frame["registered"]).most_common(args.top):
            print(f"    {count:5d}  {domain}")
        print("  sample URLs:")
        for url in frame["url"].head(10):
            print(f"    {str(url)[:120]}")
        print()

    print("=== score distribution by class ===")
    for label, name in ((1, "phishing"), (0, "benign")):
        series = work.loc[work.label == label, "score"]
        if series.empty:
            continue
        print(f"  {name:9s} n={len(series):6d} mean={series.mean():.3f} "
              f"p10={np.quantile(series, 0.10):.3f} p50={np.quantile(series, 0.50):.3f} "
              f"p90={np.quantile(series, 0.90):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
