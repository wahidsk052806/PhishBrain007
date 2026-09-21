"""
gate.py
--------
Minimum acceptance bar for the PhishBrain prefilter model.

The prefilter feeds a *security* decision, so a newly trained model must not be
deployed just because training finished. `train_prefilter.py` runs this gate on
a held-out split and refuses to write the model when any check fails; the same
checks are reported (never re-interpreted) by `ml/evaluation/report.py`.

What the bar is protecting against
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  - **A model that never fires** — high accuracy by calling everything benign.
    Caught by `min_recall`.
  - **A model that always fires** — catches every phishing URL by flagging
    ordinary traffic too. Caught by `min_precision` and the false-positive
    ceilings. This is the exact failure the bundled feeds produce on their own:
    phishing URLs carry a path, Tranco benign domains do not, so the model
    learns "has a path ⇒ phishing" and flags normal pages.
  - **A model that is confounded rather than predictive** — caught by
    `max_false_positive_rate_benign_path`, which measures false positives
    *only* on benign URLs that do carry a path. A shortcut model looks fine in
    aggregate but fails loudly here.
  - **A model that ranks poorly** — caught by `min_roc_auc`, independent of the
    0.5 decision threshold.

Thresholds are deliberately modest rather than tuned to a particular run, and
every one of them is overridable from the CLI so an operator can tighten (or,
knowingly, loosen) the bar. A gate that no model can pass is not a gate; it is
a wall — but if a candidate genuinely cannot clear these numbers it is not
worth shipping, and the honest outcome is to ship nothing.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Metrics that a gate check can read. Keys match the dict produced by
# ml.evaluation.metrics.classification_metrics plus the subgroup FPR added by
# the training/evaluation scripts.
METRIC_LABELS = {
    "recall": "Recall (phishing caught)",
    "precision": "Precision",
    "roc_auc": "ROC-AUC",
    "false_positive_rate": "False positive rate (all benign)",
    "false_positive_rate_benign_with_path": "False positive rate (benign URLs with a path)",
}


@dataclass(frozen=True)
class GateThresholds:
    """Minimum acceptance bar. Override from the CLI as needed."""

    min_recall: float = 0.90
    min_precision: float = 0.85
    min_roc_auc: float = 0.95
    max_false_positive_rate: float = 0.05
    max_false_positive_rate_benign_path: float = 0.10
    # Latency ceiling for the whole scored batch; a prefilter that is slower
    # than the layers it is meant to short-circuit has no reason to exist.
    max_mean_per_sample_latency_ms: float = 5.0
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _checks(thresholds: GateThresholds) -> list[dict]:
    return [
        {
            "metric": "recall",
            "kind": "min",
            "threshold": thresholds.min_recall,
            "why": "a prefilter that misses most phishing URLs is not doing its job",
        },
        {
            "metric": "precision",
            "kind": "min",
            "threshold": thresholds.min_precision,
            "why": "alerting on ordinary traffic destroys trust in the score",
        },
        {
            "metric": "roc_auc",
            "kind": "min",
            "threshold": thresholds.min_roc_auc,
            "why": "the ranking must be separable, not just the 0.5 cut-off",
        },
        {
            "metric": "false_positive_rate",
            "kind": "max",
            "threshold": thresholds.max_false_positive_rate,
            "why": "benign browsing must not be flagged",
        },
        {
            "metric": "false_positive_rate_benign_with_path",
            "kind": "max",
            "threshold": thresholds.max_false_positive_rate_benign_path,
            "why": "catches a model that learned 'URL has a path' instead of phishing signals",
        },
        {
            "metric": "mean_per_sample_latency_ms",
            "kind": "max",
            "threshold": thresholds.max_mean_per_sample_latency_ms,
            "why": "the prefilter must stay cheap enough to run on every URL",
        },
    ]


def evaluate_gate(metrics: dict, thresholds: GateThresholds | None = None) -> dict:
    """Return ``{passed, checks, failures}`` for a metrics dict.

    A missing (``None``) metric counts as a failure: an unmeasured requirement
    is not a satisfied requirement.
    """
    thresholds = thresholds or GateThresholds()
    results: list[dict] = []
    failures: list[str] = []

    for check in _checks(thresholds):
        metric = check["metric"]
        value = metrics.get(metric)
        if value is None:
            verdict = False
            observed = None
        elif check["kind"] == "min":
            observed = float(value)
            verdict = observed >= check["threshold"]
        else:
            observed = float(value)
            verdict = observed <= check["threshold"]
        results.append({
            "metric": metric,
            "label": METRIC_LABELS.get(metric, metric),
            "kind": check["kind"],
            "threshold": check["threshold"],
            "observed": observed,
            "passed": verdict,
            "why": check["why"],
        })
        if not verdict:
            comparator = ">=" if check["kind"] == "min" else "<="
            shown = "not measured" if observed is None else f"{observed:.4f}"
            failures.append(
                f"{METRIC_LABELS.get(metric, metric)}: {shown} (required {comparator} "
                f"{check['threshold']:.4f})"
            )

    return {"passed": not failures, "checks": results, "failures": failures}


def render_gate_markdown(result: dict, thresholds: GateThresholds | None = None) -> str:
    thresholds = thresholds or GateThresholds()
    lines = [
        "## Deployment gate: " + ("PASSED" if result["passed"] else "FAILED"),
        "",
        f"Thresholds: {thresholds.as_dict()}",
        "",
        "| Requirement | Threshold | Observed | Result |",
        "|---|---|---|---|",
    ]
    for check in result["checks"]:
        comparator = ">=" if check["kind"] == "min" else "<="
        observed = "not measured" if check["observed"] is None else f"{check['observed']:.4f}"
        lines.append(
            f"| {check['label']} | {comparator} {check['threshold']:.4f} | "
            f"{observed} | {'PASS' if check['passed'] else 'FAIL'} |"
        )
    if result["failures"]:
        lines += [
            "",
            "**Model rejected — not deployed.** Reasons:",
            "",
        ]
        lines += [f"- {reason}" for reason in result["failures"]]
    return "\n".join(lines) + "\n"
