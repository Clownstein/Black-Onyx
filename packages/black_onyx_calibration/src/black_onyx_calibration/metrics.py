"""Calibration quality metrics (ECE, Brier)."""

from __future__ import annotations

import numpy as np


def expected_calibration_error(
    probs: list[float] | np.ndarray,
    labels: list[int] | np.ndarray,
    *,
    n_bins: int = 10,
) -> float:
    """Expected Calibration Error with equal-width bins on [0, 1]."""
    p = np.asarray(probs, dtype=np.float64).ravel()
    y = np.asarray(labels, dtype=np.float64).ravel()
    if p.size == 0 or p.size != y.size:
        return 0.0
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = float(p.size)
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        if i == n_bins - 1:
            mask = (p >= lo) & (p <= hi)
        else:
            mask = (p >= lo) & (p < hi)
        if not np.any(mask):
            continue
        conf = float(p[mask].mean())
        acc = float(y[mask].mean())
        ece += (mask.sum() / n) * abs(acc - conf)
    return float(ece)


def brier_score(
    probs: list[float] | np.ndarray,
    labels: list[int] | np.ndarray,
) -> float:
    """Mean squared error between probabilities and binary labels."""
    p = np.asarray(probs, dtype=np.float64).ravel()
    y = np.asarray(labels, dtype=np.float64).ravel()
    if p.size == 0 or p.size != y.size:
        return 0.0
    return float(np.mean((p - y) ** 2))
