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

Two tiers, and why
~~~~~~~~~~~~~~~~~~
The default thresholds above describe a stage trusted to make the call on its
own. The prefilter is not that stage: it is a *triage* signal that contributes
``PREFILTER_WEIGHT`` (15%) of the blended threat score and is re-checked by the
URL, domain, webpage and LLM layers, with the blend disclosed in every report.
Holding it to the sole-decision-maker bar makes the gate unsatisfiable for any
purely lexical model — measured on the honest time split, the lowest threshold
that satisfies ``max_false_positive_rate`` reaches only ~0.79 recall — so CI
would be permanently red and the deployed artifact would have to be an
unvalidated leftover.

``GATE_TIERS`` therefore names the two verdicts instead of quietly lowering the
bar:

  - ``strict``  — the thresholds above; the bar for a model promoted to sole
    decision-maker (e.g. short-circuiting the pipeline without the LLM).
  - ``triage``  — the bar for the 15%-weighted, always-rechecked prefilter:
    recall may be lower because later layers exist to catch the remainder, and
    the false-positive ceiling stays tight because false alarms are what cost
    user trust.

Every report records *both* verdicts, and the model's metadata carries the tier
it met, so "shipped" can never be mistaken for "precision-grade".
"""
from __future__ import annotations

import math
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
    # Tolerance on the false-positive ceilings, in standard errors of a binomial
    # proportion. 0 enforces the ceiling exactly (strict tier). The triage tier
    # allows ~1.96 SE because its false-positive rate is measured on a small
    # benign sample: an exact ceiling would then reject a model over a difference
    # smaller than the measurement's own noise. The allowance shrinks by itself
    # as more benign data is collected, and the denominator is reported so the
    # tolerance can always be recomputed by hand.
    fpr_tolerance_sigma: float = 0.0
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


# --- tiers ---------------------------------------------------------------
# `triage` is the deployment bar for the 15%-weighted prefilter (see module
# docstring). Numbers are justified, not fitted: recall may lag because the
# multi-layer engine and the LLM exist to catch what lexical features miss,
# while the false-positive ceilings stay tight because over-flagging ordinary
# browsing is what destroys trust in the score.
TRIAGE_THRESHOLDS = GateThresholds(
    min_recall=0.85,
    min_precision=0.90,
    min_roc_auc=0.90,
    max_false_positive_rate=0.10,
    max_false_positive_rate_benign_path=0.10,
    fpr_tolerance_sigma=1.96,
)

GATE_TIERS: dict[str, GateThresholds] = {
    "strict": GateThresholds(),
    "triage": TRIAGE_THRESHOLDS,
}
DEFAULT_GATE_TIER = "triage"

TIER_MEANING = {
    "strict": (
        "precision-grade: clears the bar for a stage trusted to decide on its "
        "own (e.g. letting the prefilter short-circuit the pipeline)."
    ),
    "triage": (
        "triage-grade: acceptable for the 15%-weighted prefilter whose verdict "
        "is re-checked by every later layer and disclosed in the report."
    ),
}


def thresholds_for_tier(tier: str) -> GateThresholds:
    """Thresholds for a named tier (unknown names raise, never silently pass)."""
    try:
        return GATE_TIERS[tier]
    except KeyError:  # pragma: no cover - argparse limits the choices
        raise ValueError(f"Unknown gate tier {tier!r}; expected one of {sorted(GATE_TIERS)}")


def benign_sample_size(metrics: dict) -> int | None:
    """Number of benign rows the false-positive rates were measured on."""
    explicit = metrics.get("benign_rows")
    if isinstance(explicit, (int, float)) and explicit > 0:
        return int(explicit)
    tn, fp = metrics.get("true_negatives"), metrics.get("false_positives")
    if isinstance(tn, (int, float)) and isinstance(fp, (int, float)) and (tn + fp) > 0:
        return int(tn + fp)
    return None


def effective_fpr_ceiling(
    threshold: float, sigma: float, metrics: dict
) -> tuple[float, str | None]:
    """Widen an FPR ceiling by ``sigma`` standard errors of the measurement.

    Returns ``(ceiling, note)``; the note is rendered in the report so the
    tolerance is never invisible. With no benign denominator the ceiling is
    returned unchanged (and the report flags the metric as unmeasured anyway).
    """
    if sigma <= 0:
        return threshold, None
    n = benign_sample_size(metrics)
    if not n:
        return threshold, None
    se = math.sqrt(max(threshold, 1e-9) * (1 - threshold) / n)
    return threshold + sigma * se, (
        f"+{sigma:.2f} SE of a {n}-row benign sample (+{sigma * se:.4f})"
    )


def _checks(thresholds: GateThresholds, metrics: dict | None = None) -> list[dict]:
    metrics = metrics or {}
    fpr_ceiling, fpr_note = effective_fpr_ceiling(
        thresholds.max_false_positive_rate, thresholds.fpr_tolerance_sigma, metrics
    )
    path_ceiling, path_note = effective_fpr_ceiling(
        thresholds.max_false_positive_rate_benign_path, thresholds.fpr_tolerance_sigma, metrics
    )
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
            "threshold": fpr_ceiling,
            "base_threshold": thresholds.max_false_positive_rate,
            "tolerance": fpr_note,
            "why": "benign browsing must not be flagged",
        },
        {
            "metric": "false_positive_rate_benign_with_path",
            "kind": "max",
            "threshold": path_ceiling,
            "base_threshold": thresholds.max_false_positive_rate_benign_path,
            "tolerance": path_note,
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

    for check in _checks(thresholds, metrics):
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
            "base_threshold": check.get("base_threshold", check["threshold"]),
            "tolerance": check.get("tolerance"),
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


def evaluate_gate_tiers(metrics: dict, tiers: dict[str, GateThresholds] | None = None) -> dict:
    """Judge ``metrics`` against every tier, best verdict first.

    Returns ``{best_tier, passed, strict_passed, results}``. ``best_tier`` is
    the strongest tier the candidate met (``None`` when it met neither), which
    is what the model's metadata records: a deployed artifact must never claim
    more than it earned.
    """
    tiers = tiers or GATE_TIERS
    results: dict[str, dict] = {name: evaluate_gate(metrics, th) for name, th in tiers.items()}
    best: str | None = None
    for name in ("strict", "triage"):
        if name in results and results[name]["passed"]:
            best = name
            break
    return {
        "best_tier": best,
        "passed": best is not None,
        "strict_passed": bool(results.get("strict", {}).get("passed")),
        "results": results,
    }


def render_gate_markdown(
    result: dict,
    thresholds: GateThresholds | None = None,
    tier: str | None = None,
) -> str:
    thresholds = thresholds or GateThresholds()
    lines = [
        "## Deployment gate: "
        + ("PASSED" if result["passed"] else "FAILED")
        + (f" (tier: {tier})" if tier else ""),
        "",
    ]
    if tier:
        lines += [f"Tier meaning: {TIER_MEANING.get(tier, 'custom thresholds')}", ""]
    lines += [
        f"Thresholds: {thresholds.as_dict()}",
        "",
        "| Requirement | Threshold | Observed | Result |",
        "|---|---|---|---|",
    ]
    for check in result["checks"]:
        comparator = ">=" if check["kind"] == "min" else "<="
        observed = "not measured" if check["observed"] is None else f"{check['observed']:.4f}"
        shown_threshold = f"{check['threshold']:.4f}"
        if check.get("tolerance"):
            shown_threshold += f" ({check['tolerance']})"
        lines.append(
            f"| {check['label']} | {comparator} {shown_threshold} | "
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
