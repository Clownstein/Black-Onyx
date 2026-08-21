"""Shared score calibration helpers for Black Onyx models."""

from __future__ import annotations

from black_onyx_calibration.calibrator import (
    CalibrationArtifact,
    Calibrator,
    fit_isotonic,
    fit_platt,
    load_calibrator,
    save_calibrator,
)
from black_onyx_calibration.metrics import brier_score, expected_calibration_error

__version__ = "0.1.0"

__all__ = [
    "CalibrationArtifact",
    "Calibrator",
    "brier_score",
    "expected_calibration_error",
    "fit_isotonic",
    "fit_platt",
    "load_calibrator",
    "save_calibrator",
    "__version__",
]
