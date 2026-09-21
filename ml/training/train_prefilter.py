#!/usr/bin/env python3
"""
train_prefilter.py
-------------------
CLI to train the PhishBrain CatBoost prefilter model from a prepared,
labeled dataset (CSV/Parquet with feature columns + a `label` column, plus
optionally `timestamp`/`domain`/`group_id` columns for a leakage-free
time-based split).

Training no longer ends with an unconditional `save()`. The candidate model is
scored on a held-out split and must clear the minimum bar in
`ml/evaluation/gate.py` before it is written to `--output`; otherwise the run
exits non-zero and leaves whatever model was already deployed untouched. The
metrics and the gate verdict are always written to
`ml/evaluation/reports/train_gate.{json,md}` so a rejected run is still
auditable.

Usage:
    python ml/training/train_prefilter.py \
        --data data/processed/prefilter_dataset.csv \
        --label-col label \
        --test-fraction 0.2 \
        --output backend/models/prefilter.cbm

Two dataset properties matter here:

  - `--split` decides **which rows** judge the model. `auto` (the default) uses
    a leakage-free time-ordered split whenever the dataset carries real
    observation timestamps (PhishTank `submission_time` for phishing, archive
    capture times for benign — see scripts/data/prepare_dataset.py), and only
    falls back to a seeded random split, saying so, when it cannot. That
    matters because a random split re-scores rows the model trained on and
    reports optimistic numbers, whereas the time split answers the question
    deployment actually asks: does this catch phishing on domains it has never
    seen? The answer is reported as `zero_day_detection_rate`, measured on test
    rows observed *after* the cutoff whose registrable domain never appears in
    training.
  - `--structure-weights` (default on) re-weights rows so the label carries no
    information about whether a URL has a path. Without it, Tranco's
    bare-homepage benign set against deep phishing feeds teaches the model
    "has a path => phishing". See the gate module for the full explanation.

If --data is not provided or the file does not exist, this script exits
gracefully printing "Not evaluated" style guidance instead of crashing or
fabricating a model — no dataset is bundled with this repo (see
data/README.md for why).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from ml.evaluation.gate import GateThresholds, evaluate_gate, render_gate_markdown  # noqa: E402
from ml.evaluation.metrics import (  # noqa: E402
    classification_metrics,
    measure_latency_ms,
    subgroup_false_positive_rate,
    zero_day_detection_rate,
)
from ml.models.prefilter_catboost import PrefilterCatBoost, DEFAULT_MODEL_PATH  # noqa: E402
from ml.zero_day_split import (  # noqa: E402
    DEDUP_SCOPES,
    UNDATED_POLICIES,
    registrable_domain,
    time_based_split,
)

REPORT_DIR = Path(__file__).resolve().parents[1] / "evaluation" / "reports"
# Composite `pathX_subY` signature emitted by scripts/data/prepare_dataset.py.
DEFAULT_STRUCTURE_COL = "structure"
# Older datasets only carried the path axis.
FALLBACK_STRUCTURE_COL = "has_path"
# The gate's "benign URLs with a path" metric is always about this one axis,
# independently of which column is used for structure weighting.
BENIGN_PATH_COL = "has_path"

# Columns that identify a row rather than describe the URL. The structural
# columns are in here on purpose: they are the artifacts we are trying to
# remove, so they must not be model inputs either.
NON_FEATURE_COLUMNS = {
    "url", "domain", "source", "timestamp", "group_id",
    DEFAULT_STRUCTURE_COL, FALLBACK_STRUCTURE_COL, "has_subdomain",
}


def load_dataset(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path)


def select_feature_columns(df: pd.DataFrame, label_col: str, extra_excluded: set[str]) -> list[str]:
    excluded = {label_col, *NON_FEATURE_COLUMNS, *extra_excluded}
    return [c for c in df.columns if c not in excluded and pd.api.types.is_numeric_dtype(df[c])]


def compute_structure_weights(df: pd.DataFrame, label_col: str, structure_col: str) -> np.ndarray:
    """Weights that make the label independent of URL structure.

    Within every structural bucket (e.g. ``has_path`` = 0 or 1) the benign rows
    and the phishing rows are given equal *total* weight, so the classifier
    gains nothing by learning the bucket. Buckets themselves keep weight
    proportional to their real size, so the mix of bare vs deep URLs seen in
    training still resembles the source data. Weights are then rescaled to a
    mean of 1 so the configured learning rate keeps its usual meaning.

    This matters because the bundled feeds are structurally mismatched:
    93% of phishing URLs carry a path versus ~0% of Tranco's homepage list, so
    the unweighted optimum is "has a path => phishing" — a model that scores
    ordinary deep pages as ~100% phishing.
    """
    weights = pd.Series(0.0, index=df.index, dtype=float)
    for _, bucket in df.groupby(structure_col):
        bucket_mass = len(bucket) / 2.0
        for label in (0, 1):
            cell = bucket[bucket[label_col] == label]
            if len(cell):
                weights[cell.index] = bucket_mass / len(cell)
    mean = float(weights[weights > 0].mean()) if (weights > 0).any() else 1.0
    return (weights / (mean or 1.0)).to_numpy()


def describe_structure(df: pd.DataFrame, label_col: str, structure_col: str,
                       path_col: str = BENIGN_PATH_COL) -> str:
    total = len(df)
    rows = [
        f"label={label} {structure_col}={bucket}: {len(cell)} "
        f"({len(cell)/total:.1%} of rows)"
        for (label, bucket), cell in df.groupby([label_col, structure_col])
    ]
    if path_col in df.columns:
        benign_deep = ((df[label_col] == 0) & (df[path_col] == 1)).mean()
        phishing_deep = ((df[label_col] == 1) & (df[path_col] == 1)).mean()
        rows.append(
            f"deep-URL share — benign {benign_deep:.1%} vs phishing {phishing_deep:.1%}"
            + (
                "  (mismatch: treat 'has a path' as a confound, not a signal)"
                if abs(benign_deep - phishing_deep) > 0.10
                else "  (comparable)"
            )
        )
        for label, name in ((0, "benign"), (1, "phishing")):
            cell = df[df[label_col] == label]
            sub = None
            if "has_subdomain" in df.columns:
                sub = float(cell["has_subdomain"].mean())
            if sub is not None:
                rows.append(f"subdomain share — {name} {sub:.1%}")
    return "\n".join(rows)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Train the PhishBrain CatBoost prefilter.")
    p.add_argument("--data", type=Path, default=None, help="Path to labeled dataset (CSV/Parquet).")
    p.add_argument("--label-col", type=str, default="label")
    p.add_argument("--split", choices=("auto", "time", "random"), default="auto",
                   help="auto (default): time-ordered split when the dataset has real "
                        "observation timestamps, else a seeded random split. time: require "
                        "the zero-day split. random: always shuffle (optimistic; not a "
                        "zero-day measurement).")
    p.add_argument("--time-split", action="store_true",
                   help="Deprecated alias for --split time.")
    p.add_argument("--undated-policy", choices=UNDATED_POLICIES, default="train",
                   help="What to do with rows that have no observation timestamp: keep them "
                        "in training only (default), drop them, or refuse to run.")
    p.add_argument("--dedup-scope", choices=DEDUP_SCOPES, default="positives",
                   help="Domain holdout between train and test: 'positives' (default) drops "
                        "test phishing on domains seen in training, which is where leakage "
                        "is real; 'all' also holds out benign domains, which can make the "
                        "false-positive rate unmeasurable. See ml/zero_day_split.py.")
    p.add_argument("--timestamp-col", type=str, default="timestamp")
    p.add_argument("--domain-col", type=str, default="domain")
    p.add_argument("--group-col", type=str, default=None)
    p.add_argument("--cutoff", type=str, default=None,
                   help="Fixed observation cutoff (e.g. 2026-07-01) instead of deriving one "
                        "from --test-fraction. A fixed cutoff makes the zero-day number "
                        "comparable between runs (and stable in CI) as data grows.")
    p.add_argument("--test-fraction", type=float, default=0.2)
    p.add_argument("--output", type=Path, default=DEFAULT_MODEL_PATH)
    p.add_argument("--iterations", type=int, default=500)
    p.add_argument("--depth", type=int, default=6)
    p.add_argument("--learning-rate", type=float, default=0.05)
    p.add_argument("--threshold", type=float, default=0.5,
                   help="Decision threshold used when computing gate metrics.")

    structure = p.add_argument_group("structure de-confounding")
    structure.add_argument("--structure-weights", action=argparse.BooleanOptionalAction, default=True,
                           help="Re-weight rows so URL structure carries no label information (default: on).")
    structure.add_argument("--structure-col", type=str, default=DEFAULT_STRUCTURE_COL,
                           help=f"Column describing URL structure (default: {DEFAULT_STRUCTURE_COL}; "
                                f"falls back to {FALLBACK_STRUCTURE_COL} on older datasets).")

    gate = p.add_argument_group("deployment gate")
    gate.add_argument("--min-recall", type=float, default=GateThresholds.min_recall)
    gate.add_argument("--min-precision", type=float, default=GateThresholds.min_precision)
    gate.add_argument("--min-roc-auc", type=float, default=GateThresholds.min_roc_auc)
    gate.add_argument("--max-fpr", type=float, default=GateThresholds.max_false_positive_rate)
    gate.add_argument("--max-benign-path-fpr", type=float,
                      default=GateThresholds.max_false_positive_rate_benign_path,
                      help="Ceiling for false positives among benign URLs that have a path.")
    gate.add_argument("--max-latency-ms", type=float,
                      default=GateThresholds.max_mean_per_sample_latency_ms)
    gate.add_argument("--report-dir", type=Path, default=REPORT_DIR)
    return p


def thresholds_from_args(args) -> GateThresholds:
    return GateThresholds(
        min_recall=args.min_recall,
        min_precision=args.min_precision,
        min_roc_auc=args.min_roc_auc,
        max_false_positive_rate=args.max_fpr,
        max_false_positive_rate_benign_path=args.max_benign_path_fpr,
        max_mean_per_sample_latency_ms=args.max_latency_ms,
    )


def write_report(report: dict, gate_result: dict, thresholds: GateThresholds, report_dir: Path) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "train_gate.json").write_text(json.dumps(
        {"report": report, "gate": gate_result, "thresholds": thresholds.as_dict()}, indent=2
    ))
    lines = [
        "# PhishBrain Prefilter — Training Gate",
        "",
        f"Generated: {report.get('generated_at')}",
        "",
        f"Dataset: `{report.get('dataset_path')}` "
        f"(train {report.get('n_train_rows')} / test {report.get('n_test_rows')} rows)",
        f"Split: {report.get('split')}",
        f"Model written to: `{report.get('model_path')}`",
        "",
        render_gate_markdown(gate_result, thresholds),
    ]
    zero_day = report.get("zero_day")
    metrics = report.get("metrics") or {}
    value = metrics.get("zero_day_detection_rate")
    lines += [
        "## Zero-day detection",
        "",
        (f"Detection rate on phishing URLs whose registrable domain was never seen in "
         f"training: **{value:.4f}**" if value is not None else
         "Not measured: this run used a seeded random split, so no held-out-future "
         "phishing exists to measure against. Re-run on a dataset with real "
         "observation timestamps (--split time)."),
        "",
    ]
    if zero_day:
        lines += [
            f"Cutoff: {zero_day['cutoff']} (rows observed at/after it form the test set)",
            f"Zeros-day basis: {zero_day['test_phishing_rows_on_unseen_domains']} phishing "
            f"URLs across {zero_day['unseen_domains']} unseen domains, of "
            f"{zero_day['test_rows_on_unseen_domains']} test rows",
            f"Timestamp coverage: {zero_day['timestamped_rows']} dated rows "
            f"({zero_day['timestamp_coverage']:.1%}); {zero_day['undated_rows']} undated rows "
            f"kept out of the test set",
            f"False positives were measured on {zero_day['test_benign_rows']} benign rows "
            f"({zero_day['negatives_domain_overlap']} of them on a domain also seen in "
            f"training; --dedup-scope {zero_day['dedup_scope']})",
            "",
        ]
    (report_dir / "train_gate.md").write_text("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.data is None or not args.data.exists():
        print("No dataset provided or file not found.")
        print("Not evaluated: training requires a real, labeled dataset.")
        print("See data/README.md and scripts/data/download_data.py / prepare_dataset.py.")
        return 0

    df = load_dataset(args.data)
    if args.label_col not in df.columns:
        print(f"Dataset is missing required label column '{args.label_col}'.")
        print("Not evaluated: cannot train without labels.")
        return 1

    if args.structure_col not in df.columns and args.structure_col == DEFAULT_STRUCTURE_COL \
            and FALLBACK_STRUCTURE_COL in df.columns:
        print(f"No '{DEFAULT_STRUCTURE_COL}' column; falling back to "
              f"'{FALLBACK_STRUCTURE_COL}' (regenerate the dataset to add the subdomain axis).")
        args.structure_col = FALLBACK_STRUCTURE_COL

    feature_cols = select_feature_columns(
        df,
        args.label_col,
        {args.timestamp_col, args.domain_col, args.group_col or "", args.structure_col},
    )
    if not feature_cols:
        print("Not evaluated: no numeric feature columns found in the dataset.")
        return 1

    requested = "time" if args.time_split else args.split
    has_timestamp = args.timestamp_col in df.columns
    if requested == "time" and not has_timestamp:
        print(f"--split time requested but '{args.timestamp_col}' column is missing.")
        print("Not evaluated: cannot perform a leakage-free split without observation "
              "timestamps. Re-run scripts/data/prepare_dataset.py on feeds that carry them.")
        return 1

    split = None
    split_mode = requested
    if requested == "auto":
        split_mode = "time" if (has_timestamp and df[args.timestamp_col].notna().any()) else "random"
        print(f"--split auto selected a {'time-ordered (zero-day)' if split_mode == 'time' else 'seeded random'}"
              f" split.")

    if split_mode == "time":
        try:
            split = time_based_split(
                df,
                timestamp_col=args.timestamp_col,
                domain_col=args.domain_col if args.domain_col in df.columns else None,
                group_col=args.group_col,
                cutoff=pd.Timestamp(args.cutoff, tz="UTC") if args.cutoff else None,
                test_fraction=args.test_fraction,
                undated_policy=args.undated_policy,
                dedup_scope=args.dedup_scope,
                label_col=args.label_col,
            )
        except ValueError as exc:
            print(f"Not evaluated: {exc}")
            return 1
        train_df, test_df = split.train, split.test
        print("Time-ordered split (this is the zero-day measurement):")
        print(f"  cutoff={split.cutoff}  test = rows observed at/after the cutoff")
        print(f"  timestamp coverage: {split.timestamped_rows} dated rows "
              f"({split.coverage:.1%} of the dataset)")
        print(f"  undated rows ({split.undated_rows}) handled by policy '{args.undated_policy}'"
              + (f" -> {split.undated_in_train} kept in training only" if split.undated_in_train else ""))
        print(f"  train={len(train_df)} rows, test={len(test_df)} rows "
              f"(dropped {split.dropped_leaked_rows} test rows whose domain was seen in training)")
        print(f"  unseen (zero-day) domains in test: {len(split.zero_day_domains)}")
        if split.negatives_domain_overlap:
            print(f"  note: {split.negatives_domain_overlap} benign test rows sit on a domain "
                  f"also seen in training (--dedup-scope positives). Scoring a lexical-only "
                  f"model cannot benefit from that overlap, but it is reported so the "
                  f"false-positive rate is not read more strictly than it was measured.")
    else:
        shuffled = df.sample(frac=1.0, random_state=42)
        cutoff_idx = int(len(shuffled) * (1 - args.test_fraction))
        train_df, test_df = shuffled.iloc[:cutoff_idx], shuffled.iloc[cutoff_idx:]
        print("Using a seeded random 80/20 split; this is NOT a zero-day measurement "
              "because the model has seen rows from the same campaigns during training.")

    if train_df.empty or test_df.empty:
        print("Not evaluated: split produced an empty train or test set (dataset too small "
              "or too concentrated in time). Provide more data.")
        return 1

    # Early stopping needs its own slice: tuning on the test set would make the
    # metrics that the deployment gate judges optimistic.
    val_df = None
    val_size = int(len(df) * 0.1)
    if 0 < val_size < len(train_df):
        pool = train_df.sample(frac=1.0, random_state=7)
        val_df, train_df = pool.iloc[:val_size], pool.iloc[val_size:]
        print(f"Validation slice for early stopping: {len(val_df)} rows (kept out of training)")

    has_structure = args.structure_col in df.columns
    if has_structure:
        print("\nStructural distribution (whole dataset):")
        for line in describe_structure(df, args.label_col, args.structure_col).splitlines():
            print(f"  {line}")
    else:
        print(f"\nNo '{args.structure_col}' column: cannot assess or neutralise the "
              f"'has a path => phishing' confound.")

    X_train, y_train = train_df[feature_cols], train_df[args.label_col]
    X_test, y_test = test_df[feature_cols], test_df[args.label_col]

    sample_weight = None
    weights_used = False
    if args.structure_weights and has_structure:
        sample_weight = compute_structure_weights(train_df, args.label_col, args.structure_col)
        weights_used = True
        print(f"Structure weights enabled on '{args.structure_col}': the label no longer "
              f"correlates with URL structure in the training objective.")
    elif args.structure_weights:
        print("Structure weights requested but the structure column is missing; training "
              "with natural row weights.")

    model = PrefilterCatBoost(params={
        "iterations": args.iterations,
        "depth": args.depth,
        "learning_rate": args.learning_rate,
    })
    X_val = y_val = None
    if val_df is not None:
        X_val, y_val = val_df[feature_cols], val_df[args.label_col]

    try:
        model.train(X_train, y_train, X_val, y_val, feature_names=feature_cols,
                    sample_weight=sample_weight)
    except RuntimeError as exc:
        print(f"Training failed: {exc}")
        return 1

    # ---- evaluate on the held-out split -----------------------------------
    proba = model.predict_proba(X_test)
    y_proba = proba[:, 1] if proba.ndim == 2 else proba
    y_pred = (y_proba >= args.threshold).astype(int)

    metrics = classification_metrics(y_test, y_pred, y_proba)
    if BENIGN_PATH_COL in test_df.columns:
        metrics["false_positive_rate_benign_with_path"] = subgroup_false_positive_rate(
            y_test, y_pred, test_df[BENIGN_PATH_COL].to_numpy() == 1
        )
    else:
        print(f"Note: '{BENIGN_PATH_COL}' column absent, so the benign-with-path "
              f"false-positive check will count as unmeasured and block deployment.")

    # ---- zero-day detection: phishing on domains never seen in training ----
    zero_day = None
    if split is not None and args.domain_col in test_df.columns:
        test_reg = test_df[args.domain_col].map(registrable_domain)
        unseen_mask = test_reg.isin(split.zero_day_domains).to_numpy()
        zero_day = {
            "cutoff": str(split.cutoff),
            "unseen_domains": len(split.zero_day_domains),
            "test_rows_on_unseen_domains": int(unseen_mask.sum()),
            "test_phishing_rows_on_unseen_domains": int(
                ((y_test.to_numpy() == 1) & unseen_mask).sum()
            ),
            "timestamped_rows": split.timestamped_rows,
            "undated_rows": split.undated_rows,
            "timestamp_coverage": round(split.coverage, 4),
            "dedup_scope": split.dedup_scope,
            "negatives_domain_overlap": split.negatives_domain_overlap,
            "dropped_leaked_rows": split.dropped_leaked_rows,
            "test_benign_rows": int((y_test.to_numpy() == 0).sum()),
        }
        metrics["zero_day_detection_rate"] = zero_day_detection_rate(
            y_test.to_numpy()[unseen_mask], y_pred[unseen_mask]
        )
    else:
        metrics["zero_day_detection_rate"] = None

    latency = measure_latency_ms(model.predict_proba, X_test)
    metrics.update({
        "mean_batch_latency_ms": latency["mean_batch_latency_ms"],
        "mean_per_sample_latency_ms": latency["mean_per_sample_latency_ms"],
    })

    print("\nHeld-out metrics:")
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc",
                "false_positive_rate", "false_positive_rate_benign_with_path",
                "zero_day_detection_rate", "mean_per_sample_latency_ms"):
        value = metrics.get(key)
        print(f"  {key:38s} {'not measured' if value is None else f'{value:.4f}'}")
    print(f"  confusion matrix: TP={metrics['true_positives']} FN={metrics['false_negatives']} "
          f"FP={metrics['false_positives']} TN={metrics['true_negatives']}")
    if zero_day:
        print(f"  zero-day basis: cutoff {zero_day['cutoff']}, "
              f"{zero_day['test_phishing_rows_on_unseen_domains']} phishing URLs on "
              f"{zero_day['unseen_domains']} domains never in training "
              f"({zero_day['test_rows_on_unseen_domains']} test rows total)")
    elif split_mode == "time":
        print("  zero-day detection rate: not measured (no domain column to group on)")

    thresholds = thresholds_from_args(args)
    gate_result = evaluate_gate(metrics, thresholds)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "evaluated",
        "dataset_path": str(args.data),
        "model_path": str(args.output),
        "n_rows": int(len(df)),
        "n_train_rows": int(len(train_df)),
        "n_test_rows": int(len(test_df)),
        "decision_threshold": args.threshold,
        "feature_names": feature_cols,
        "structure_weights": weights_used,
        "structure_col": args.structure_col if has_structure else None,
        "split_mode": split_mode,
        "split": (
            f"time-ordered zero-day split at cutoff {split.cutoff} "
            f"({split.dropped_leaked_rows} test rows dropped as same-domain-as-training)"
            if split is not None else
            "seeded random split (no usable observation timestamps)"
        ),
        "zero_day": zero_day,
        "metrics": metrics,
    }

    print("\nDeployment gate: " + ("PASSED" if gate_result["passed"] else "FAILED"))
    for check in gate_result["checks"]:
        comparator = ">=" if check["kind"] == "min" else "<="
        observed = "not measured" if check["observed"] is None else f"{check['observed']:.4f}"
        print(f"  [{'PASS' if check['passed'] else 'FAIL'}] {check['label']}: {observed} "
              f"(need {comparator} {check['threshold']:.4f})")

    if not gate_result["passed"]:
        write_report(report, gate_result, thresholds, args.report_dir)
        print("\nREFUSING TO DEPLOY: the candidate model did not clear the minimum bar, so "
              f"nothing was written to {args.output}.")
        for reason in gate_result["failures"]:
            print(f"  - {reason}")
        print(f"Report: {args.report_dir / 'train_gate.md'}")
        if args.output.exists():
            print("An existing model at that path was left untouched — the previous "
                  "deployment is still what the backend loads.")
        else:
            print("No model is deployed: the backend keeps reporting "
                  "'ml.deterministic_fallback' rather than using a model that fails its own bar.")
        return 1

    model.meta_extra = {
        "trained_at": report["generated_at"],
        "dataset_path": report["dataset_path"],
        "n_train_rows": report["n_train_rows"],
        "n_test_rows": report["n_test_rows"],
        "structure_weights": weights_used,
        # Recorded so a deployed artifact says what its numbers were measured on:
        # a random-split metric set is not a zero-day measurement.
        "split_mode": split_mode,
        "split": report["split"],
        "zero_day": zero_day,
        "metrics": metrics,
        "gate": {"passed": True, "thresholds": thresholds.as_dict()},
    }
    saved_path = model.save(args.output)
    write_report(report, gate_result, thresholds, args.report_dir)
    print(f"\nModel saved to {saved_path}")
    print(f"Report: {args.report_dir / 'train_gate.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
