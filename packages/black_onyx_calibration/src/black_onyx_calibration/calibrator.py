"""Platt (sigmoid) and isotonic calibrators with JSON/joblib sidecars."""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np

Method = Literal["platt", "isotonic", "identity"]


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


@dataclass
class CalibrationArtifact:
    method: Method = "platt"
    # Platt: calibrated = sigmoid(scale * raw + bias)
    scale: float = 1.0
    bias: float = 0.0
    # Isotonic: piecewise linear on sorted x_thresholds -> y_thresholds
    x_thresholds: list[float] | None = None
    y_thresholds: list[float] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationArtifact:
        method = str(data.get("method", "platt"))
        if method not in ("platt", "isotonic", "identity"):
            method = "platt"
        return cls(
            method=method,  # type: ignore[arg-type]
            scale=float(data.get("scale", 1.0)),
            bias=float(data.get("bias", 0.0)),
            x_thresholds=(
                [float(x) for x in data["x_thresholds"]]
                if data.get("x_thresholds") is not None
                else None
            ),
            y_thresholds=(
                [float(y) for y in data["y_thresholds"]]
                if data.get("y_thresholds") is not None
                else None
            ),
        )


class Calibrator:
    """Apply a fitted calibration artifact to raw anomaly scores."""

    def __init__(self, artifact: CalibrationArtifact | None = None) -> None:
        self.artifact = artifact or CalibrationArtifact(method="identity")

    def calibrate(self, raw: float) -> float:
        art = self.artifact
        if art.method == "identity":
            return float(min(1.0, max(0.0, raw)))
        if art.method == "platt":
            return float(min(1.0, max(0.0, _sigmoid(art.scale * raw + art.bias))))
        xs = art.x_thresholds or []
        ys = art.y_thresholds or []
        if not xs or not ys or len(xs) != len(ys):
            return float(min(1.0, max(0.0, raw)))
        if raw <= xs[0]:
            return float(min(1.0, max(0.0, ys[0])))
        if raw >= xs[-1]:
            return float(min(1.0, max(0.0, ys[-1])))
        # Linear interpolate between neighboring knots.
        for i in range(1, len(xs)):
            if raw <= xs[i]:
                x0, x1 = xs[i - 1], xs[i]
                y0, y1 = ys[i - 1], ys[i]
                if x1 == x0:
                    return float(min(1.0, max(0.0, y1)))
                t = (raw - x0) / (x1 - x0)
                return float(min(1.0, max(0.0, y0 + t * (y1 - y0))))
        return float(min(1.0, max(0.0, ys[-1])))

    def calibrate_many(self, raws: list[float] | np.ndarray) -> np.ndarray:
        arr = np.asarray(raws, dtype=np.float64).ravel()
        return np.asarray([self.calibrate(float(x)) for x in arr], dtype=np.float64)


def fit_platt(
    raw_scores: list[float] | np.ndarray,
    labels: list[int] | np.ndarray,
    *,
    max_iter: int = 100,
) -> CalibrationArtifact:
    """Fit Platt scaling (logistic on raw scores). Falls back to identity if sklearn missing."""
    x = np.asarray(raw_scores, dtype=np.float64).ravel()
    y = np.asarray(labels, dtype=np.float64).ravel()
    if x.size == 0 or x.size != y.size:
        return CalibrationArtifact(method="identity")
    try:
        from sklearn.linear_model import LogisticRegression

        clf = LogisticRegression(max_iter=max_iter, solver="lbfgs")
        clf.fit(x.reshape(-1, 1), y.astype(int))
        scale = float(clf.coef_.ravel()[0])
        bias = float(clf.intercept_.ravel()[0])
        return CalibrationArtifact(method="platt", scale=scale, bias=bias)
    except Exception:  # noqa: BLE001
        # Simple closed-form fallback: map mean positives/negatives via scale/bias heuristic.
        pos = x[y >= 0.5]
        neg = x[y < 0.5]
        if pos.size == 0 or neg.size == 0:
            return CalibrationArtifact(method="platt", scale=1.0, bias=0.0)
        mid = 0.5 * (float(pos.mean()) + float(neg.mean()))
        spread = max(1e-3, float(pos.mean() - neg.mean()))
        scale = 4.0 / spread
        bias = -scale * mid
        return CalibrationArtifact(method="platt", scale=scale, bias=bias)


def fit_isotonic(
    raw_scores: list[float] | np.ndarray,
    labels: list[int] | np.ndarray,
) -> CalibrationArtifact:
    """Fit isotonic regression; falls back to Platt if sklearn missing."""
    x = np.asarray(raw_scores, dtype=np.float64).ravel()
    y = np.asarray(labels, dtype=np.float64).ravel()
    if x.size == 0 or x.size != y.size:
        return CalibrationArtifact(method="identity")
    try:
        from sklearn.isotonic import IsotonicRegression

        iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        iso.fit(x, y)
        xs = [float(v) for v in np.asarray(iso.X_thresholds_).ravel()]
        ys = [float(v) for v in np.asarray(iso.y_thresholds_).ravel()]
        return CalibrationArtifact(method="isotonic", x_thresholds=xs, y_thresholds=ys)
    except Exception:  # noqa: BLE001
        return fit_platt(x, y)


def save_calibrator(artifact: CalibrationArtifact, path: Path | str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact.to_dict(), indent=2) + "\n", encoding="utf-8")


def load_calibrator(path: Path | str) -> Calibrator:
    target = Path(path)
    if not target.is_file():
        return Calibrator(CalibrationArtifact(method="identity"))
    data = json.loads(target.read_text(encoding="utf-8"))
    # Backward compatible with log-model {scale, bias} without method.
    if "method" not in data and ("scale" in data or "bias" in data):
        data = {**data, "method": "platt"}
    return Calibrator(CalibrationArtifact.from_dict(data))
