"""Inference-side replay of the prefilter's probability calibration.

The prefilter is trained with balanced class weights (see
`ml/preprocessing/url_features.py` for why), which makes its raw score a
*shifted* probability rather than a real one. `ml/evaluation/calibration.py`
fits a monotone Platt map on held-out data and the training CLI stores it in the
model's `.meta.json`; this module replays that exact map at inference time so
the score served by the API is the one that was validated.

Like `app/ml/url_features.py`, the ML package is imported from the repo root
when it is discoverable and skipped otherwise, so the backend degrades to the
uncalibrated score instead of failing.
"""
from __future__ import annotations

import sys
from typing import Callable, Optional

from app.ml.url_features import _locate_ml_root

_apply_calibration: Optional[Callable] = None


def _load() -> None:
    global _apply_calibration
    root = _locate_ml_root()
    if root is not None and str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from ml.evaluation.calibration import (  # type: ignore[import-not-found]
            apply_calibration as _apply,
        )
    except Exception:  # noqa: BLE001 - optional dependency at runtime
        return
    _apply_calibration = _apply


_load()


def calibration_available() -> bool:
    return _apply_calibration is not None


def apply_calibration(p: float, calibration: dict | None) -> float:
    """Replay a fitted calibration on a single probability.

    Returns the input unchanged when calibration is unavailable or the map is
    the identity, so callers never have to special-case "no calibration".
    """
    if _apply_calibration is None or not calibration:
        return float(p)
    if calibration.get("method") != "platt":
        return float(p)
    return float(_apply_calibration([p], calibration)[0])
