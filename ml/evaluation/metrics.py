"""
metrics.py
-----------
Evaluation metrics for the PhishBrain prefilter model: standard
classification metrics plus phishing-specific ones (false positive rate,
zero-day detection rate) and inference latency.

Every function here operates on real arrays/values passed in by the
caller — nothing is hard-coded or fabricated. If ml/evaluation/report.py
has no dataset/model to evaluate, it never calls these functions and
instead emits "Not evaluated" placeholders.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def classification_metrics(y_true, y_pred, y_proba: Optional[np.ndarray] = None) -> dict:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_proba is not None and len(set(y_true.tolist())) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    else:
        metrics["roc_auc"] = None

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics["true_negatives"] = int(tn)
    metrics["false_positives"] = int(fp)
    metrics["false_negatives"] = int(fn)
    metrics["true_positives"] = int(tp)
    metrics["false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) > 0 else None
    return metrics


def subgroup_false_positive_rate(y_true, y_pred, mask) -> Optional[float]:
    """False-positive rate restricted to the negatives inside a subgroup.

    Aggregate FPR can hide a confounded model: one that learned "this URL has
    a path ⇒ phishing" looks acceptable overall while flagging normal deep
    pages almost every time. Splitting benign traffic by URL structure is what
    makes that visible. Returns None when the subgroup contains no negatives,
    so callers can tell "clean" apart from "never measured".
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    mask = np.asarray(mask, dtype=bool)
    negatives = mask & (y_true == 0)
    total_negatives = int(negatives.sum())
    if total_negatives == 0:
        return None
    false_positives = int(((y_pred == 1) & negatives).sum())
    return float(false_positives / total_negatives)


def zero_day_detection_rate(y_true_zero_day, y_pred_zero_day) -> Optional[float]:
    """
    Detection (recall) rate restricted to rows that are confirmed zero-day
    positives (phishing samples whose domain/campaign was never seen in
    training — see ml/zero_day_split.py). Returns None if there are no
    positive zero-day examples to evaluate against.
    """
    y_true_zero_day = np.asarray(y_true_zero_day)
    y_pred_zero_day = np.asarray(y_pred_zero_day)
    positives = y_true_zero_day == 1
    if positives.sum() == 0:
        return None
    return float(recall_score(y_true_zero_day[positives], y_pred_zero_day[positives], zero_division=0))


def measure_latency_ms(predict_fn: Callable[[Any], Any], X, n_repeats: int = 5) -> dict:
    """Measure per-batch and per-sample inference latency in milliseconds."""
    n = len(X) if hasattr(X, "__len__") else 1
    timings = []
    for _ in range(n_repeats):
        start = time.perf_counter()
        predict_fn(X)
        timings.append((time.perf_counter() - start) * 1000)
    batch_ms = float(np.mean(timings))
    return {
        "batch_size": n,
        "mean_batch_latency_ms": batch_ms,
        "mean_per_sample_latency_ms": batch_ms / n if n else None,
        "repeats": n_repeats,
    }
