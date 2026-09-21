#!/usr/bin/env python3
"""
report.py
----------
Generates an evaluation report (Markdown + JSON) for the PhishBrain
prefilter model.

Design principle: NEVER fabricate metrics. If no trained model and/or no
labeled dataset is present, every metric field is written out explicitly as
"Not evaluated" (JSON: null with a "status": "not_evaluated" flag) rather
than omitted or guessed. This keeps the report always runnable/producible
in CI or on a fresh checkout, and makes it obvious to readers (and to
README.md) that no real accuracy numbers exist yet.

Zero-day detection
~~~~~~~~~~~~~~~~~~
The headline number is `zero_day_detection_rate`: the share of phishing URLs
caught whose **registrable domain never appeared in training**. It is only
real when the dataset carries genuine observation timestamps, which is why
scripts/data/prepare_dataset.py preserves PhishTank's `submission_time` and
the archive's capture time instead of inventing a date. With them, this report
reproduces the trainer's leakage-free split exactly (`ml/zero_day_split.py`):
train on rows observed before a cutoff, then score rows observed after it,
after removing any domain that training had already seen. Rows with no
observation time are kept out of the test set, never assigned one.

The report states the *basis* of every zero-day figure (cutoff, how many
phishing URLs and domains it rests on, how much of the dataset carried a
timestamp) so a number computed from a small dated slice cannot be mistaken
for one computed from the whole dataset.

Usage:
    python ml/evaluation/report.py \
        --model backend/models/prefilter.cbm \
        --data data/processed/prefilter_dataset.csv \
        --label-col label \
        --out ml/evaluation/reports/latest
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.evaluation.gate import GateThresholds, evaluate_gate, render_gate_markdown  # noqa: E402
from ml.evaluation.metrics import (  # noqa: E402
    classification_metrics,
    measure_latency_ms,
    subgroup_false_positive_rate,
    zero_day_detection_rate,
)
from ml.models.prefilter_catboost import PrefilterCatBoost, DEFAULT_MODEL_PATH, model_exists  # noqa: E402
from ml.zero_day_split import (  # noqa: E402
    DEDUP_SCOPES,
    UNDATED_POLICIES,
    registrable_domain,
    time_based_split,
)

NOT_EVALUATED = "Not evaluated"

# Identifier/structural columns are never features (see ml/training/train_prefilter.py).
NON_FEATURE_COLUMNS = {
    "url", "domain", "source", "timestamp", "timestamp_source", "group_id",
    "has_path", "has_subdomain", "structure",
}

METRIC_KEYS = [
    "accuracy", "precision", "recall", "f1", "roc_auc",
    "false_positive_rate", "false_positive_rate_benign_with_path",
    "zero_day_detection_rate",
    "mean_batch_latency_ms", "mean_per_sample_latency_ms",
]


def _not_evaluated_report(reason: str) -> dict:
    return {
        "status": "not_evaluated",
        "reason": reason,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": {k: None for k in METRIC_KEYS},
        "zero_day": None,
        "note": NOT_EVALUATED,
        # An unevaluated model cannot have cleared the deployment bar.
        "gate": evaluate_gate({k: None for k in METRIC_KEYS}),
    }


def _fmt(value):
    return NOT_EVALUATED if value is None else f"{value:.4f}"


def render_markdown(report: dict) -> str:
    lines = [
        "# PhishBrain Prefilter — Evaluation Report",
        "",
        f"Generated: {report.get('generated_at', NOT_EVALUATED)}",
        "",
    ]
    if report.get("status") == "not_evaluated":
        lines += [
            "## Status: Not evaluated",
            "",
            f"Reason: {report.get('reason', NOT_EVALUATED)}",
            "",
            "No accuracy, precision, recall, F1, ROC-AUC, false-positive-rate, "
            "zero-day-detection-rate, or latency figures are available because "
            "no trained model and/or labeled dataset were found. This project "
            "does not ship a bundled/proprietary dataset (see data/README.md). "
            "Run `scripts/data/download_data.py` (opt-in, public feeds only), "
            "`scripts/data/prepare_dataset.py`, then "
            "`scripts/data/train_prefilter.py` and re-run this report to "
            "populate real numbers.",
            "",
            "| Metric | Value |",
            "|---|---|",
        ]
        for k in report["metrics"]:
            lines.append(f"| {k} | {NOT_EVALUATED} |")
        if report.get("gate"):
            lines += ["", render_gate_markdown(report["gate"])]
        return "\n".join(lines) + "\n"

    m = report["metrics"]
    lines += [
        "## Status: Evaluated",
        "",
        f"Dataset: `{report.get('dataset_path')}` ({report.get('n_test_rows')} test rows)",
        f"Split: {report.get('split', NOT_EVALUATED)}",
        f"Decision threshold: {report.get('decision_threshold', 0.5)}",
        f"Model: `{report.get('model_path')}`",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Accuracy | {m['accuracy']:.4f} |",
        f"| Precision | {m['precision']:.4f} |",
        f"| Recall | {m['recall']:.4f} |",
        f"| F1 | {m['f1']:.4f} |",
        f"| ROC-AUC | {_fmt(m['roc_auc'])} |",
        f"| False Positive Rate | {_fmt(m['false_positive_rate'])} |",
        f"| False Positive Rate (benign URLs with a path) | "
        f"{_fmt(m.get('false_positive_rate_benign_with_path'))} |",
        f"| Mean Batch Latency (ms) | {m['mean_batch_latency_ms']:.3f} |",
        f"| Mean Per-Sample Latency (ms) | {m['mean_per_sample_latency_ms']:.4f} |",
        "",
        "Confusion matrix: "
        f"TP={m.get('true_positives')} FP={m.get('false_positives')} "
        f"FN={m.get('false_negatives')} TN={m.get('true_negatives')}",
    ]

    zero_day = report.get("zero_day")
    lines += [
        "",
        "## Zero-day detection",
        "",
    ]
    if zero_day:
        lines += [
            f"**Detection rate on phishing whose registrable domain was never seen in "
            f"training: {_fmt(m.get('zero_day_detection_rate'))}**",
            "",
            f"Cutoff: {zero_day['cutoff']} — every test row was observed at or after it.",
            f"Basis: {zero_day['test_phishing_rows_on_unseen_domains']} phishing URLs across "
            f"{zero_day['unseen_domains']} domains unseen in training "
            f"({zero_day['test_rows_on_unseen_domains']} test rows on unseen domains, of "
            f"{report['n_test_rows']} total).",
            f"Timestamp coverage: {zero_day['timestamped_rows']} rows had a real observation "
            f"time ({zero_day['timestamp_coverage']:.1%}); {zero_day['undated_rows']} undated "
            f"rows were kept out of the test set rather than assigned a date "
            f"({zero_day['dropped_leaked_rows']} further test rows were dropped because "
            f"training had already seen their domain).",
            f"False positive rate basis: {zero_day['test_benign_rows']} benign test rows, "
            f"{zero_day['test_benign_rows_on_unseen_domains']} of them on a domain unseen in "
            f"training and {zero_day['negatives_domain_overlap']} on a domain training had "
            f"already seen (domain holdout scope `{zero_day['dedup_scope']}`). With lexical "
            f"URL features only, a shared benign domain cannot hand the model an answer — "
            f"but `--dedup-scope all` measures the stricter variant if you need it.",
        ]
    else:
        lines += [
            f"**{NOT_EVALUATED}** — this run used a split that cannot measure zero-day "
            "generalization (no usable observation timestamps), so no held-out-future "
            "phishing exists to score against. Re-run on a dataset that carries "
            "`timestamp` values to populate this section.",
        ]

    if report.get("gate"):
        lines += ["", render_gate_markdown(report["gate"])]
    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate PhishBrain prefilter evaluation report.")
    p.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    p.add_argument("--data", type=Path, default=None)
    p.add_argument("--label-col", type=str, default="label")
    p.add_argument("--timestamp-col", type=str, default="timestamp")
    p.add_argument("--domain-col", type=str, default="domain")
    p.add_argument("--undated-policy", choices=UNDATED_POLICIES, default="train",
                   help="Rows without an observation timestamp: keep them out of the test "
                        "set (default), drop them, or fail. Mirrors the trainer.")
    p.add_argument("--dedup-scope", choices=DEDUP_SCOPES, default="positives",
                   help="Domain holdout between train and test; must match the trainer so "
                        "this report describes the same split.")
    p.add_argument("--cutoff", type=str, default=None,
                   help="Fixed observation cutoff (e.g. 2026-07-01); must match the trainer "
                        "so the two describe the same held-out period.")
    p.add_argument("--test-fraction", type=float, default=0.2)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--structure-col", type=str, default="has_path",
                   help="Structural column used for the benign-with-path false-positive check "
                        "(this specific metric is always the path axis).")
    p.add_argument("--out", type=Path, default=Path("ml/evaluation/reports/latest"))
    p.add_argument("--min-recall", type=float, default=GateThresholds.min_recall)
    p.add_argument("--min-precision", type=float, default=GateThresholds.min_precision)
    p.add_argument("--min-roc-auc", type=float, default=GateThresholds.min_roc_auc)
    p.add_argument("--max-fpr", type=float, default=GateThresholds.max_false_positive_rate)
    p.add_argument("--max-benign-path-fpr", type=float,
                   default=GateThresholds.max_false_positive_rate_benign_path)
    p.add_argument("--max-latency-ms", type=float,
                   default=GateThresholds.max_mean_per_sample_latency_ms)
    return p


def _thresholds(args) -> GateThresholds:
    return GateThresholds(
        min_recall=args.min_recall,
        min_precision=args.min_precision,
        min_roc_auc=args.min_roc_auc,
        max_false_positive_rate=args.max_fpr,
        max_false_positive_rate_benign_path=args.max_benign_path_fpr,
        max_mean_per_sample_latency_ms=args.max_latency_ms,
    )


def _evaluate(args) -> dict:
    """Score the deployed model on a held-out split.

    Raises ValueError with a human-readable reason when the data cannot support
    an evaluation; the caller turns that into a "Not evaluated" report so the
    report is always producible.
    """
    import numpy as np
    import pandas as pd

    df = pd.read_csv(args.data) if args.data.suffix.lower() != ".parquet" else pd.read_parquet(args.data)
    if args.label_col not in df.columns:
        raise ValueError(f"Dataset missing label column '{args.label_col}'.")

    model = PrefilterCatBoost.load(args.model)
    feature_cols = model.feature_names or [
        c for c in df.columns
        if c not in {args.label_col, args.timestamp_col, args.domain_col,
                     args.structure_col, *NON_FEATURE_COLUMNS}
    ]

    has_time = (args.timestamp_col in df.columns
                and df[args.timestamp_col].notna().any())
    zero_day = None
    split = None
    if has_time:
        split = time_based_split(
            df, timestamp_col=args.timestamp_col,
            domain_col=args.domain_col if args.domain_col in df.columns else None,
            cutoff=pd.Timestamp(args.cutoff, tz="UTC") if args.cutoff else None,
            test_fraction=args.test_fraction,
            undated_policy=args.undated_policy,
            dedup_scope=args.dedup_scope,
            label_col=args.label_col,
        )
        test_df = split.test
        zero_day_domains = split.zero_day_domains
        split_note = (
            f"zero-day split at cutoff {split.cutoff} "
            f"({split.dropped_leaked_rows} test rows dropped as "
            f"same-domain-as-training; {split.undated_rows} undated rows "
            f"kept out of the test set via --undated-policy {split.undated_policy}; "
            f"domain holdout scope '{split.dedup_scope}')"
        )
    else:
        # Mirror ml/training/train_prefilter.py exactly so these metrics
        # describe the model's held-out behaviour. Sampling freely from the
        # whole table would mostly re-score rows the model trained on and
        # report optimistic numbers.
        shuffled = df.sample(frac=1.0, random_state=42)
        cutoff_idx = int(len(shuffled) * (1 - args.test_fraction))
        test_df = shuffled.iloc[cutoff_idx:]
        zero_day_domains = set()
        split_note = ("seeded random split reproduced from training "
                      "(no usable timestamp column), so these are the same "
                      "held-out rows the deployment gate scored — and NOT a "
                      "zero-day measurement")

    X_test = test_df[feature_cols]
    y_test = test_df[args.label_col]
    proba = model.predict_proba(X_test)
    y_proba = proba[:, 1] if proba.ndim == 2 else proba
    y_pred = (y_proba >= args.threshold).astype(int)

    metrics = classification_metrics(y_test, y_pred, y_proba)
    if args.structure_col in test_df.columns:
        metrics["false_positive_rate_benign_with_path"] = subgroup_false_positive_rate(
            y_test, y_pred, test_df[args.structure_col].to_numpy() == 1
        )

    if split is not None and args.domain_col in test_df.columns and zero_day_domains:
        # Compare on the *registrable* domain: the split groups that way, while
        # the column holds the full hostname, so a verbatim isin() would match
        # almost nothing and silently report the metric as unmeasured.
        test_reg = test_df[args.domain_col].map(registrable_domain)
        unseen_mask = test_reg.isin(zero_day_domains).to_numpy()
        y_test_arr = y_test.to_numpy()
        y_pred_arr = np.asarray(y_pred)
        metrics["zero_day_detection_rate"] = zero_day_detection_rate(
            y_test_arr[unseen_mask], y_pred_arr[unseen_mask]
        )
        zero_day = {
            "cutoff": str(split.cutoff),
            "unseen_domains": len(zero_day_domains),
            "test_rows_on_unseen_domains": int(unseen_mask.sum()),
            "test_phishing_rows_on_unseen_domains": int(((y_test_arr == 1) & unseen_mask).sum()),
            "test_benign_rows_on_unseen_domains": int(((y_test_arr == 0) & unseen_mask).sum()),
            "test_benign_rows": int((y_test_arr == 0).sum()),
            "timestamped_rows": split.timestamped_rows,
            "undated_rows": split.undated_rows,
            "timestamp_coverage": round(split.coverage, 4),
            "dropped_leaked_rows": split.dropped_leaked_rows,
            "dedup_scope": split.dedup_scope,
            "negatives_domain_overlap": split.negatives_domain_overlap,
        }
    else:
        metrics["zero_day_detection_rate"] = None

    latency = measure_latency_ms(model.predict_proba, X_test)
    metrics.update({
        "mean_batch_latency_ms": latency["mean_batch_latency_ms"],
        "mean_per_sample_latency_ms": latency["mean_per_sample_latency_ms"],
    })

    return {
        "status": "evaluated",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_path": str(args.model),
        "dataset_path": str(args.data),
        "split": split_note,
        "zero_day": zero_day,
        "n_test_rows": int(len(test_df)),
        "n_train_rows": int(len(df) - len(test_df)),
        "decision_threshold": args.threshold,
        "metrics": metrics,
        "gate": evaluate_gate(metrics, _thresholds(args)),
        "thresholds": _thresholds(args).as_dict(),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    if not model_exists(args.model):
        report = _not_evaluated_report(f"No trained model found at {args.model}.")
    elif args.data is None or not args.data.exists():
        report = _not_evaluated_report("No dataset provided for evaluation.")
    else:
        try:
            report = _evaluate(args)
        except (ValueError, KeyError) as exc:
            report = _not_evaluated_report(f"Evaluation unavailable: {exc}")

    (args.out.with_suffix(".json")).write_text(json.dumps(report, indent=2))
    (args.out.with_suffix(".md")).write_text(render_markdown(report))
    print(f"Report written to {args.out.with_suffix('.json')} and {args.out.with_suffix('.md')}")
    print(f"Status: {report['status']}")
    if report.get("zero_day"):
        metrics = report["metrics"]
        print(f"Zero-day detection rate: {_fmt(metrics.get('zero_day_detection_rate'))} "
              f"(basis: {report['zero_day']['test_phishing_rows_on_unseen_domains']} phishing "
              f"URLs on {report['zero_day']['unseen_domains']} unseen domains)")
    gate = report.get("gate")
    if gate:
        print("Deployment gate: " + ("PASSED" if gate["passed"] else "FAILED"))
        for reason in gate["failures"]:
            print(f"  - {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
