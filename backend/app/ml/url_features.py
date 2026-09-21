"""Inference-side URL features for the CatBoost prefilter.

The prefilter model is trained from `ml/preprocessing/url_features.py` (see
ml/README.md). To guarantee train/inference parity this module reuses that
extractor instead of re-implementing it — the same approach the training CLI
takes when it adds the repo root to `sys.path`.

If the ML package cannot be imported (unusual deployment layout), inference
degrades gracefully: the prefilter simply stays on its deterministic fallback
rather than scoring with mismatched features.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional

_extract_url_features_dict: Optional[Callable[[str], dict]] = None
_ml_feature_names: list[str] = []


def _locate_ml_root() -> Optional[Path]:
    """Find the directory that contains `ml/preprocessing/url_features.py`.

    Covers the two supported layouts: a dev checkout (`<repo>/backend/app/ml/`
    -> repo root is three levels up) and the Docker image (cwd `/app` already
    contains `ml/`).
    """
    for candidate in (Path(__file__).resolve().parents[3], Path.cwd()):
        if (candidate / "ml" / "preprocessing" / "url_features.py").exists():
            return candidate
    return None


def _load() -> None:
    global _extract_url_features_dict, _ml_feature_names
    root = _locate_ml_root()
    if root is not None and str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from ml.preprocessing.url_features import (  # type: ignore[import-not-found]
            FEATURE_NAMES,
            extract_url_features_dict,
        )
    except Exception:  # noqa: BLE001 - optional dependency at runtime
        return
    _extract_url_features_dict = extract_url_features_dict
    _ml_feature_names = list(FEATURE_NAMES)


_load()


def ml_features_available() -> bool:
    return _extract_url_features_dict is not None


def training_feature_names() -> list[str]:
    """Feature names the training pipeline produces, in their native order."""
    return list(_ml_feature_names)


def extract_prefilter_features(url: str) -> dict:
    """Lexical URL features identical to the ones the prefilter was trained on."""
    if _extract_url_features_dict is None:
        return {}
    return _extract_url_features_dict(url)
