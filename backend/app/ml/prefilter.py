"""CatBoost-based prefilter with deterministic fallback when no model is trained.

When a model is present it is fed the *same* lexical URL features it was
trained on (via app.ml.url_features, which reuses the ml/ training extractor),
so training actually changes pipeline behaviour. Without a model — or for
non-URL inputs — the documented rule-based fallback is used.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from app.ml.url_features import (
    extract_prefilter_features,
    ml_features_available,
    training_feature_names,
)

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "prefilter.cbm"
META_PATH = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".meta.json")


class Prefilter:
    def __init__(self) -> None:
        self.model = None
        self.model_trained = False
        self.feature_names: list[str] = training_feature_names()
        self._try_load()

    def _try_load(self) -> None:
        if not MODEL_PATH.exists():
            return
        try:
            from catboost import CatBoostClassifier

            model = CatBoostClassifier()
            model.load_model(str(MODEL_PATH))
        except Exception:  # noqa: BLE001
            self.model = None
            self.model_trained = False
            return
        self.model = model
        self.feature_names = self._resolve_feature_names(model)
        self.model_trained = True

    @staticmethod
    def _resolve_feature_names(model) -> list[str]:
        """Prefer the names baked into the model file, then its meta sidecar."""
        try:
            names = list(model.feature_names_)
        except Exception:  # noqa: BLE001
            names = []
        if not names and META_PATH.exists():
            try:
                names = json.loads(META_PATH.read_text()).get("feature_names") or []
            except Exception:  # noqa: BLE001
                names = []
        return names or training_feature_names()

    def _vectorize(self, features: dict) -> np.ndarray:
        vec = [float(features.get(k, 0.0) or 0.0) for k in self.feature_names]
        return np.array([vec], dtype=float)

    def _deterministic_fallback(self, features: dict) -> float:
        """Documented weighted-average fallback used whenever no trained
        CatBoost model is present on disk. This is NOT a learned model and
        makes no accuracy claims; it is a transparent, auditable heuristic."""
        weights = {
            "url_risk": 0.30, "domain_risk": 0.25, "email_risk": 0.25, "webpage_risk": 0.20,
        }
        base = sum(weights[k] * float(features.get(k, 0.0)) for k in weights)
        bonus = 0.0
        if features.get("is_ip_host"):
            bonus += 8
        if features.get("suspicious_tld"):
            bonus += 5
        if features.get("is_punycode") or features.get("homograph_suspected"):
            bonus += 8
        if not features.get("is_https", True):
            bonus += 3
        return max(0.0, min(100.0, base + bonus))

    def score(self, features: dict) -> dict:
        url = features.get("url")
        if self.model_trained and self.model is not None and url and ml_features_available():
            try:
                lexical = extract_prefilter_features(str(url))
                proba = self.model.predict_proba(self._vectorize(lexical))[0][1]
                return {"score": float(proba) * 100.0, "model_trained": True, "method": "catboost"}
            except Exception:  # noqa: BLE001
                pass
        return {
            "score": self._deterministic_fallback(features),
            "model_trained": False,
            "method": "deterministic_weighted_fallback",
        }


_prefilter_singleton: Prefilter | None = None


def get_prefilter() -> Prefilter:
    global _prefilter_singleton
    if _prefilter_singleton is None:
        _prefilter_singleton = Prefilter()
    return _prefilter_singleton
