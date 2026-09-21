#!/usr/bin/env python3
"""Thin wrapper so `python scripts/data/train_prefilter.py` works the same
as `python ml/training/train_prefilter.py` (kept for discoverability
alongside download_data.py / prepare_dataset.py / evaluate.py)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.training.train_prefilter import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
