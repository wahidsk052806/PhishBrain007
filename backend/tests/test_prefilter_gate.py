"""Tests for the prefilter's deployment gate, tiering and calibration machinery.

These pin the honesty properties that are easy to lose:

  - a candidate that misses the bar is refused, and the *strict* tier is never
    reported as passed unless it genuinely passed;
  - the false-positive ceiling accounts for how small the benign sample is, in a
    way that tightens by itself as more benign data arrives;
  - the probability calibration is monotone and a no-op when it is absent;
  - the deployed model's metadata describes the split its numbers came from, so
    a grandfathered random-split measurement cannot masquerade as a zero-day one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.evaluation.calibration import (  # noqa: E402
    apply_calibration,
    expected_calibration_error,
    fit_platt,
    identity_calibration,
)
from ml.evaluation.gate import (  # noqa: E402
    GATE_TIERS,
    TIER_MEANING,
    GateThresholds,
    effective_fpr_ceiling,
    evaluate_gate,
    evaluate_gate_tiers,
    thresholds_for_tier,
)
from ml.training.train_prefilter import select_decision_threshold  # noqa: E402

# The honest time-split numbers the deployed candidate produced on 2026-09-23.
HONEST_METRICS = {
    "recall": 0.8633,
    "precision": 0.9982,
    "roc_auc": 0.9443,
    "false_positive_rate": 0.1091,
    "false_positive_rate_benign_with_path": 0.0543,
    "mean_per_sample_latency_ms": 0.0010,
    "true_negatives": 98,
    "false_positives": 12,
    "false_negatives": 1073,
    "true_positives": 6776,
}


class TestGateTiers:
    def test_triage_tier_accepts_the_honest_candidate(self):
        result = evaluate_gate(HONEST_METRICS, thresholds_for_tier("triage"))
        assert result["passed"], result["failures"]

    def test_strict_tier_rejects_the_same_candidate(self):
        """The point of the tiering: shipped is not the same as precision-grade."""
        result = evaluate_gate(HONEST_METRICS, thresholds_for_tier("strict"))
        assert not result["passed"]
        assert any("ROC-AUC" in reason for reason in result["failures"])

    def test_tier_verdicts_report_the_best_tier_earned(self):
        verdicts = evaluate_gate_tiers(HONEST_METRICS)
        assert verdicts["best_tier"] == "triage"
        assert verdicts["passed"] is True
        assert verdicts["strict_passed"] is False

    def test_a_model_that_catches_nothing_fails_every_tier(self):
        metrics = {**HONEST_METRICS, "recall": 0.0, "precision": 0.0, "roc_auc": 0.5}
        verdicts = evaluate_gate_tiers(metrics)
        assert verdicts["best_tier"] is None
        assert verdicts["passed"] is False

    def test_every_tier_has_a_documented_meaning(self):
        assert set(GATE_TIERS) == set(TIER_MEANING)

    def test_unmeasured_metric_is_a_failure(self):
        result = evaluate_gate({"recall": 0.99}, thresholds_for_tier("triage"))
        assert not result["passed"]
        assert any("not measured" in reason for reason in result["failures"])


class TestFprTolerance:
    def test_ceiling_widens_by_the_sampling_error(self):
        ceiling, note = effective_fpr_ceiling(0.10, 1.96, {"benign_rows": 110})
        assert ceiling > 0.10
        assert pytest.approx(ceiling, abs=1e-6) == 0.10 + 1.96 * (0.10 * 0.90 / 110) ** 0.5
        assert "110-row benign sample" in note

    def test_tolerance_shrinks_as_benign_data_grows(self):
        small, _ = effective_fpr_ceiling(0.10, 1.96, {"benign_rows": 110})
        large, _ = effective_fpr_ceiling(0.10, 1.96, {"benign_rows": 110_000})
        assert large < small
        assert large < 0.102

    def test_zero_sigma_is_an_exact_ceiling(self):
        ceiling, note = effective_fpr_ceiling(0.10, 0.0, {"benign_rows": 110})
        assert ceiling == 0.10
        assert note is None

    def test_clearly_bad_fpr_fails_despite_the_tolerance(self):
        metrics = {**HONEST_METRICS, "false_positive_rate": 0.60}
        assert not evaluate_gate(metrics, thresholds_for_tier("triage"))["passed"]

    def test_a_large_benign_sample_removes_the_allowance(self):
        """Same observed rate, but now measured well enough that it must pass on merit."""
        metrics = {
            **HONEST_METRICS,
            "false_positive_rate": 0.1091,
            "true_negatives": 98_000,
            "false_positives": 12_000,
        }
        assert not evaluate_gate(metrics, thresholds_for_tier("triage"))["passed"]

    def test_benign_denominator_falls_back_to_the_confusion_matrix(self):
        metrics = {"true_negatives": 90, "false_positives": 20}
        ceiling, note = effective_fpr_ceiling(0.10, 1.96, metrics)
        assert "110-row benign sample" in note
        assert ceiling > 0.10


class TestCalibration:
    @staticmethod
    def _sample(n_positives: int = 4000, n_negatives: int = 2000, shift: float = 0.9):
        import numpy as np

        rng = np.random.default_rng(0)
        y = np.r_[np.ones(n_positives), np.zeros(n_negatives)]
        logits = np.r_[
            rng.normal(1.5, 1.2, n_positives),
            rng.normal(-1.0, 1.2, n_negatives),
        ]
        p_true = 1.0 / (1.0 + np.exp(-logits))
        p_raw = 1.0 / (1.0 + np.exp(-(logits + shift)))
        return y, p_true, p_raw

    def test_recovers_the_prior_shift(self):
        y, _, p_raw = self._sample(shift=0.9)
        calibration = fit_platt(y, p_raw)
        assert calibration["method"] == "platt"
        calibrated = apply_calibration(p_raw, calibration)
        # The fitted intercept must undo most of the injected +0.9 log-odds shift.
        assert calibration["b"] < -0.4

    def test_calibration_improves_reliability(self):
        y, _, p_raw = self._sample()
        calibrated = apply_calibration(p_raw, fit_platt(y, p_raw))
        assert expected_calibration_error(y, calibrated) < expected_calibration_error(y, p_raw)

    def test_calibration_is_monotone_so_roc_auc_cannot_move(self):
        import numpy as np

        y, _, p_raw = self._sample()
        calibrated = apply_calibration(p_raw, fit_platt(y, p_raw))
        order = np.argsort(p_raw)
        assert np.all(np.diff(calibrated[order]) >= 0)

    def test_single_class_fits_an_identity_map(self):
        import numpy as np

        calibration = fit_platt(np.ones(10), np.linspace(0.1, 0.9, 10))
        assert calibration["method"] == "identity"
        assert apply_calibration(np.array([0.3]), calibration)[0] == pytest.approx(0.3)

    def test_absent_calibration_is_a_no_op(self):
        import numpy as np

        assert apply_calibration(np.array([0.42]), None)[0] == pytest.approx(0.42)
        assert apply_calibration(np.array([0.42]), identity_calibration())[0] == pytest.approx(0.42)

    def test_empty_input_is_an_identity_map(self):
        import numpy as np

        assert fit_platt(np.array([]), np.array([]))["method"] == "identity"


class TestThresholdSelection:
    def test_picks_a_threshold_that_meets_the_ceiling(self):
        import numpy as np

        rng = np.random.default_rng(1)
        negatives = rng.normal(0.3, 0.15, 500)
        positives = rng.normal(0.8, 0.15, 500)
        y = np.r_[np.zeros(500), np.ones(500)]
        p = np.r_[negatives, positives]
        threshold = select_decision_threshold(y, p, max_false_positive_rate=0.05)
        assert (p[y == 0] >= threshold).mean() <= 0.05
        assert (p[y == 1] >= threshold).mean() > 0.9

    def test_prefers_the_lowest_qualifying_threshold(self):
        """Maximise recall subject to the ceiling, not the other way round."""
        import numpy as np

        y = np.r_[np.zeros(4), np.ones(4)]
        p = np.r_[[0.2, 0.3, 0.55, 0.9], [0.85, 0.88, 0.92, 0.99]]
        threshold = select_decision_threshold(y, p, max_false_positive_rate=0.25)
        # Benign rows at or above each candidate: 0.3 -> 3/4, 0.55 -> 2/4,
        # 0.85 -> 1/4 and 0.9 -> 1/4. The lowest threshold inside a 25% ceiling
        # is therefore 0.85 — chosen ahead of 0.9 because it keeps more recall.
        assert threshold == pytest.approx(0.85)
        assert (p[y == 1] >= threshold).mean() == pytest.approx(1.0)

    def test_falls_back_when_no_threshold_qualifies(self):
        import numpy as np

        # The one benign row sits at the maximum score, so every candidate
        # threshold still flags it and a zero ceiling cannot be met.
        y = np.r_[np.zeros(1), np.ones(9)]
        p = np.r_[[1.0], [0.9, 0.91, 0.92, 0.93, 0.94, 0.95, 0.96, 0.97, 0.98]]
        assert select_decision_threshold(y, p, max_false_positive_rate=0.0, fallback=0.5) == 0.5

    def test_no_negatives_returns_the_fallback(self):
        import numpy as np

        y = np.ones(10)
        assert select_decision_threshold(y, np.linspace(0, 1, 10), 0.1, fallback=0.42) == 0.42


class TestDeployedModelProvenance:
    """The artifact on disk must describe itself honestly (see item B)."""

    @staticmethod
    def _meta() -> dict:
        path = REPO_ROOT / "backend" / "models" / "prefilter.cbm.meta.json"
        if not path.exists():
            pytest.skip("no trained prefilter model deployed in this checkout")
        return json.loads(path.read_text())

    def test_metadata_records_the_split_its_metrics_came_from(self):
        meta = self._meta()
        assert meta.get("split_mode") in {"time", "random"}
        assert meta.get("split")
        if meta["split_mode"] == "random":
            # A random-split score is allowed only if it says so.
            assert "random" in meta["split"]

    def test_gate_verdict_names_the_tier_it_earned(self):
        meta = self._meta()
        gate = meta.get("gate")
        if not gate or not gate.get("passed"):
            pytest.skip("the deployed model did not pass a gate in this checkout")
        assert gate.get("tier") in GATE_TIERS
        # A model may only claim strict if its numbers actually clear it.
        if gate.get("strict_passed"):
            assert evaluate_gate(meta["metrics"], thresholds_for_tier("strict"))["passed"]
        else:
            assert gate.get("tier") != "strict"

    def test_recorded_metrics_match_the_recorded_tier_verdict(self):
        meta = self._meta()
        thresholds = thresholds_for_tier((meta.get("gate") or {}).get("tier", "triage"))
        result = evaluate_gate(meta["metrics"], thresholds)
        assert result["passed"] == bool((meta.get("gate") or {}).get("passed"))

    def test_declared_decision_threshold_preserves_recall(self):
        meta = self._meta()
        threshold = meta.get("decision_threshold")
        if threshold is None:
            pytest.skip("model metadata predates the decision-threshold record")
        assert 0.0 < threshold <= 1.0
        # A threshold above 1 would classify everything as benign, which is how a
        # degenerate calibration run of ours once produced recall = 0.
        assert threshold < 1.0

    def test_calibration_block_is_self_describing(self):
        meta = self._meta()
        calibration = meta.get("calibration")
        if calibration is None:
            pytest.skip("model metadata predates the calibration record")
        assert calibration.get("method") in {"platt", "identity"}
        if calibration["method"] == "platt":
            assert calibration["a"] > 0
            assert calibration.get("n", 0) > 0


class TestGateThresholdsContract:
    def test_cli_override_wins_over_the_tier_default(self):
        tier = thresholds_for_tier("triage")
        overridden = GateThresholds(min_recall=0.99, fpr_tolerance_sigma=tier.fpr_tolerance_sigma)
        assert overridden.min_recall == 0.99
        assert overridden.fpr_tolerance_sigma == tier.fpr_tolerance_sigma

    def test_unknown_tier_is_refused(self):
        with pytest.raises(ValueError):
            thresholds_for_tier("nope")
