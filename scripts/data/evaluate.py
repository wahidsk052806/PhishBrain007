#!/usr/bin/env python3
"""Thin wrapper around ml/evaluation/report.py for discoverability under
scripts/data/ alongside the other dataset/training scripts."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.evaluation.report import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
