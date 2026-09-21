"""
prefilter_catboost.py
----------------------
Lightweight CatBoost binary classifier used as the "PREFILTER" stage of the
PhishBrain pipeline (CAPTURE -> PARSE -> PREFILTER -> ...). Its job is to
cheaply score URL/email lexical features and short-circuit obviously
benign traffic before the more expensive multi-layer extraction + LLM
stages run.

Public API:
    model = PrefilterCatBoost()
    model.train(X_train, y_train, X_val=None, y_val=None)
    model.save(path)                 # -> backend/models/prefilter.cbm
    model = PrefilterCatBoost.load(path)
    proba = model.predict_proba(X)   # -> np.ndarray shape (n, 2) or (n,)

CatBoost is an optional dependency (see ml/requirements.txt). If it is not
installed, importing this module still succeeds; calling train/predict will
raise a clear RuntimeError instructing the user to `pip install catboost`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

try:
    from catboost import CatBoostClassifier, Pool
    _HAS_CATBOOST = True
except ImportError:  # pragma: no cover
    _HAS_CATBOOST = False

DEFAULT_MODEL_PATH = Path("backend/models/prefilter.cbm")
DEFAULT_PARAMS: dict[str, Any] = {
    "iterations": 500,
    "depth": 6,
    "learning_rate": 0.05,
    "loss_function": "Logloss",
    "eval_metric": "AUC",
    "random_seed": 42,
    "verbose": False,
    # Public phishing feeds massively outnumber the benign baseline (roughly
    # 15:1 with the bundled scripts), so without this the model collapses to
    # "always phishing" and scores obviously benign URLs as ~100%.
    "auto_class_weights": "Balanced",
}


class PrefilterCatBoost:
    """Thin, dependency-checked wrapper around CatBoostClassifier."""

    def __init__(self, params: Optional[dict[str, Any]] = None):
        self.params = {**DEFAULT_PARAMS, **(params or {})}
        self.feature_names: list[str] | None = None
        self._model = None
        # Free-form provenance (gate verdict, weighting scheme, ...) persisted
        # into the .meta.json sidecar so a deployed model can explain itself.
        self.meta_extra: dict[str, Any] = {}

    def _require_catboost(self) -> None:
        if not _HAS_CATBOOST:
            raise RuntimeError(
                "catboost is not installed. Run `pip install -r ml/requirements.txt` "
                "to train or load the prefilter model."
            )

    def train(
        self,
        X_train,
        y_train,
        X_val=None,
        y_val=None,
        feature_names: Optional[list[str]] = None,
        early_stopping_rounds: int = 50,
        sample_weight=None,
    ) -> "PrefilterCatBoost":
        """Train the classifier.

        ``sample_weight`` lets the caller re-weight rows — used by the training
        CLI to stop the model latching onto a structural artifact of the feeds
        (see ml/evaluation/gate.py).
        """
        self._require_catboost()
        self.feature_names = feature_names or (
            list(X_train.columns) if hasattr(X_train, "columns") else None
        )
        self._model = CatBoostClassifier(**self.params)
        eval_set = None
        if X_val is not None and y_val is not None:
            eval_set = Pool(X_val, y_val)
        self._model.fit(
            Pool(X_train, y_train, weight=sample_weight),
            eval_set=eval_set,
            early_stopping_rounds=early_stopping_rounds if eval_set is not None else None,
            use_best_model=eval_set is not None,
        )
        return self

    def predict_proba(self, X):
        self._require_catboost()
        if self._model is None:
            raise RuntimeError("Model has not been trained or loaded yet.")
        return self._model.predict_proba(X)

    def predict(self, X, threshold: float = 0.5):
        proba = self.predict_proba(X)
        phishing_scores = proba[:, 1] if proba.ndim == 2 else proba
        return (phishing_scores >= threshold).astype(int)

    def save(self, path: str | Path = DEFAULT_MODEL_PATH) -> Path:
        self._require_catboost()
        if self._model is None:
            raise RuntimeError("Cannot save an untrained model.")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._model.save_model(str(path))
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        meta_path.write_text(json.dumps({
            "feature_names": self.feature_names,
            "params": self.params,
            **self.meta_extra,
        }, indent=2))
        return path

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL_PATH) -> "PrefilterCatBoost":
        if not _HAS_CATBOOST:
            raise RuntimeError(
                "catboost is not installed. Run `pip install -r ml/requirements.txt` "
                "to load the prefilter model."
            )
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"No prefilter model found at {path}. Train one with "
                f"`python ml/training/train_prefilter.py` or "
                f"`python scripts/data/train_prefilter.py`."
            )
        instance = cls()
        model = CatBoostClassifier()
        model.load_model(str(path))
        instance._model = model
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            instance.feature_names = meta.get("feature_names")
            instance.params.update(meta.get("params", {}))
        return instance

    @property
    def is_loaded(self) -> bool:
        return self._model is not None


def model_exists(path: str | Path = DEFAULT_MODEL_PATH) -> bool:
    return Path(path).exists()
