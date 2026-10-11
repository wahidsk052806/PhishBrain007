"""
calibration.py
--------------
Turn the prefilter's raw score into a probability that means what it says.

Why this is needed
~~~~~~~~~~~~~~~~~~
The classifier is trained with CatBoost's ``auto_class_weights="Balanced"``
because the phishing feeds outnumber the benign baseline roughly 15:1 — without
balancing, the model collapses to "always phishing". Balanced weighting is
exactly a shift of the class priors, and the resulting score is therefore NOT
the probability that a URL is phishing: benign URLs come out of the model
inflated (ordinary pages scoring 40-80 out of 100) which the backend then
reports as a risk contribution.

The correction is principled rather than cosmetic. If the model is fit with
weights ``w0``/``w1``, the weighted posterior ``p_b`` relates to the true
posterior ``p`` through a constant shift in log-odds::

    logit(p_b) = logit(p) + log(w1 / w0)

so a single-feature logistic regression on ``logit(p_b)`` recovers ``p``::

    logit(p) = a * logit(p_b) + b

``fit_platt`` estimates ``a`` and ``b`` by Newton/IRLS on held-out data using
plain NumPy (no extra dependency), and ``apply_calibration`` replays them. The
transform is strictly monotone, so it cannot change ROC-AUC or the ranking of
URLs — it only makes the number printable as a probability and keeps a 0.5
decision threshold meaningful.

When a fit is impossible (only one class present, or degenerate scores) the
identity map is returned and labelled ``identity`` so callers can tell "not
calibrated" apart from "calibrated with a no-op".
"""
from __future__ import annotations

import numpy as np

_EPS = 1e-6
# Guard rails: a calibration that inverts the ranking would be a bug, and an
# extreme slope means the fit latched onto a handful of points.
MIN_SLOPE = 0.05
MAX_SLOPE = 20.0


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(np.asarray(p, dtype=float), _EPS, 1.0 - _EPS)
    return np.log(p / (1.0 - p))


def _sigmoid(z: np.ndarray) -> np.ndarray:
    z = np.asarray(z, dtype=float)
    return 1.0 / (1.0 + np.exp(-np.clip(z, -60.0, 60.0)))


def identity_calibration(reason: str = "not fitted") -> dict:
    return {"method": "identity", "a": 1.0, "b": 0.0, "n": 0, "reason": reason}


def fit_platt(y_true, p_raw, max_iter: int = 100, tol: float = 1e-10) -> dict:
    """Fit ``logit(p_true) = a * logit(p_raw) + b`` on held-out data.

    One-dimensional logistic regression (a.k.a. Platt scaling) solved with
    Newton-Raphson; the Hessian is 2x2 and closed-form, so this converges in a
    handful of iterations on tens of thousands of rows.

    The fit must use data the model never trained on — passing training rows
    would calibrate on the model's own memorised (over-confident) scores.
    """
    y = np.asarray(y_true, dtype=float).ravel()
    p = np.asarray(p_raw, dtype=float).ravel()
    if y.size != p.size or y.size == 0:
        return identity_calibration("empty sample")
    if len(np.unique(y)) < 2:
        return identity_calibration("only one class present")

    x = _logit(p)
    # Standardise so Newton behaves for very peaked score distributions.
    x_mean = float(x.mean())
    x_std = float(x.std()) or 1.0
    z = (x - x_mean) / x_std

    a, b = 1.0, 0.0
    for _ in range(max_iter):
        q = _sigmoid(a * z + b)
        w = np.maximum(q * (1.0 - q), 1e-12)
        grad = np.array([
            float(np.sum((q - y) * z)),
            float(np.sum(q - y)),
        ])
        h00 = float(np.sum(w * z * z))
        h01 = float(np.sum(w * z))
        h11 = float(np.sum(w))
        hess = np.array([[h00, h01], [h01, h11]])
        try:
            step = np.linalg.solve(hess + np.eye(2) * 1e-9, grad)
        except np.linalg.LinAlgError:  # pragma: no cover - defensive
            break
        a -= step[0]
        b -= step[1]
        if float(np.max(np.abs(step))) < tol:
            break

    # Un-standardise back to raw logit space.
    slope = float(a / x_std)
    intercept = float(b - a * x_mean / x_std)
    if not np.isfinite(slope) or not np.isfinite(intercept) or slope <= 0:
        return identity_calibration("degenerate fit")
    if not (MIN_SLOPE <= slope <= MAX_SLOPE):
        return identity_calibration(f"implausible slope {slope:.4f}")

    return {
        "method": "platt",
        "a": slope,
        "b": intercept,
        "n": int(y.size),
        "positives": int((y == 1).sum()),
        "negatives": int((y == 0).sum()),
    }


def apply_calibration(p_raw, calibration: dict | None) -> np.ndarray:
    """Replay a fitted calibration. Missing/identity -> the input, unchanged."""
    p = np.asarray(p_raw, dtype=float)
    if not calibration or calibration.get("method") != "platt":
        return p
    a = calibration.get("a")
    b = calibration.get("b")
    if a is None or b is None:
        return p
    return _sigmoid(float(a) * _logit(p) + float(b))


def expected_calibration_error(y_true, p, n_bins: int = 10) -> float | None:
    """Mean |confidence - accuracy| over equal-width probability bins.

    Reported alongside the metrics so a calibration change is visible as a
    number instead of an assertion.
    """
    y = np.asarray(y_true, dtype=float).ravel()
    p = np.asarray(p, dtype=float).ravel()
    if y.size == 0:
        return None
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (p >= lo) & (p < hi if hi < 1.0 else p <= hi)
        if not mask.any():
            continue
        total += (mask.sum() / y.size) * abs(float(p[mask].mean()) - float(y[mask].mean()))
    return float(total)
