from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from black_onyx_calibration import (
    Calibrator,
    CalibrationArtifact,
    brier_score,
    expected_calibration_error,
    fit_isotonic,
    fit_platt,
    load_calibrator,
    save_calibrator,
)


def test_platt_calibrate_monotonic() -> None:
    art = CalibrationArtifact(method="platt", scale=2.0, bias=-1.0)
    cal = Calibrator(art)
    assert cal.calibrate(0.0) < cal.calibrate(1.0)
    assert 0.0 <= cal.calibrate(0.5) <= 1.0


def test_identity_clamp() -> None:
    cal = Calibrator(CalibrationArtifact(method="identity"))
    assert cal.calibrate(1.5) == 1.0
    assert cal.calibrate(-0.2) == 0.0


def test_fit_platt_and_roundtrip(tmp_path: Path) -> None:
    rng = np.random.default_rng(0)
    raw = rng.uniform(0, 1, size=200)
    labels = (raw > 0.55).astype(int)
    art = fit_platt(raw, labels)
    path = tmp_path / "calibration.json"
    save_calibrator(art, path)
    loaded = load_calibrator(path)
    assert loaded.artifact.method in ("platt", "identity")
    out = loaded.calibrate_many(raw)
    assert out.shape == (200,)
    assert float(out.min()) >= 0.0
    assert float(out.max()) <= 1.0


def test_fit_isotonic() -> None:
    raw = np.linspace(0, 1, 50)
    labels = (raw > 0.4).astype(int)
    art = fit_isotonic(raw, labels)
    cal = Calibrator(art)
    assert cal.calibrate(0.1) <= cal.calibrate(0.9) + 1e-6


def test_legacy_scale_bias_load(tmp_path: Path) -> None:
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps({"scale": 1.5, "bias": -0.2}), encoding="utf-8")
    cal = load_calibrator(path)
    assert cal.artifact.method == "platt"
    assert cal.artifact.scale == 1.5


def test_ece_brier() -> None:
    probs = [0.1, 0.2, 0.8, 0.9]
    labels = [0, 0, 1, 1]
    assert expected_calibration_error(probs, labels) >= 0.0
    assert 0.0 <= brier_score(probs, labels) <= 1.0
