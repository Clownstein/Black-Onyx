from __future__ import annotations

from typing import Any

import numpy as np

METRIC_ORDER = [
    "cpu.utilization",
    "memory.working_set",
    "http.request_rate",
    "http.error_rate",
    "http.duration.p95",
    "queue.depth",
    "db.pool.utilization",
]

# 7 values + 7 missingness flags
INPUT_DIM = 14

try:
    import torch
    from torch import nn

    _TORCH = True
except ImportError:  # pragma: no cover
    torch = None  # type: ignore
    nn = None  # type: ignore
    _TORCH = False


if _TORCH:

    class TranAD(nn.Module):
        """TranAD-style compact transformer for multivariate time series.

        Encoder + reconstruction decoder; anomaly score from mean absolute
        residual. Per-feature residuals feed contributors (diagnosis).
        Paper: arXiv:2201.07284.
        """

        def __init__(
            self,
            input_dim: int = INPUT_DIM,
            hidden_size: int = 96,
            num_layers: int = 3,
            num_heads: int = 4,
            intermediate_size: int = 256,
            window_length: int = 60,
            dropout: float = 0.1,
        ) -> None:
            super().__init__()
            self.input_proj = nn.Linear(input_dim, hidden_size)
            self.pos = nn.Parameter(torch.randn(1, window_length, hidden_size) * 0.02)
            layer = nn.TransformerEncoderLayer(
                d_model=hidden_size,
                nhead=num_heads,
                dim_feedforward=intermediate_size,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
            # Reconstruction head (TranAD-style focus on residuals)
            self.decoder = nn.Sequential(
                nn.LayerNorm(hidden_size),
                nn.Linear(hidden_size, intermediate_size),
                nn.GELU(),
                nn.Linear(intermediate_size, input_dim),
            )
            # Optional classification head kept for ONNX score export compatibility
            self.score_head = nn.Sequential(nn.LayerNorm(hidden_size), nn.Linear(hidden_size, 1))
            self.window_length = window_length
            self.input_dim = input_dim

        def reconstruct(self, x: torch.Tensor) -> torch.Tensor:
            t = x.shape[1]
            h = self.input_proj(x) + self.pos[:, :t, :]
            encoded = self.encoder(h)
            return self.decoder(encoded)

        def residuals(self, x: torch.Tensor) -> torch.Tensor:
            """Per-timestep, per-feature absolute reconstruction error. Shape [B, T, F]."""
            recon = self.reconstruct(x)
            return torch.abs(x - recon)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """Return anomaly score in [0, 1] from mean residual (+ mild head)."""
            resid = self.residuals(x)
            # Mean over time and features → raw residual magnitude
            mean_resid = resid.mean(dim=(1, 2))
            t = x.shape[1]
            h = self.input_proj(x) + self.pos[:, :t, :]
            encoded = self.encoder(h)
            pooled = encoded.mean(dim=1)
            head_score = torch.sigmoid(self.score_head(pooled)).squeeze(-1)
            # Blend reconstruction residual (TranAD) with head for stable [0,1]
            resid_score = torch.sigmoid(4.0 * (mean_resid - 0.15))
            return 0.7 * resid_score + 0.3 * head_score

        def feature_residuals(self, x: torch.Tensor) -> torch.Tensor:
            """Mean absolute residual per input feature channel. Shape [B, F]."""
            return self.residuals(x).mean(dim=1)

    # Primary name + backward-compatible alias
    MultivariateMetricTransformer = TranAD
    MetricsTransformer = TranAD
else:  # pragma: no cover

    class TranAD:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("torch is required for TranAD")

    MultivariateMetricTransformer = TranAD
    MetricsTransformer = TranAD


class IsolationForestFallback:
    """sklearn IsolationForest fallback when transformer artifacts are unavailable."""

    def __init__(self) -> None:
        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
        )
        self.fitted = False

    def fit(self, windows: np.ndarray) -> None:
        # windows: [N, T, F] -> flatten
        x = windows.reshape(windows.shape[0], -1)
        self.model.fit(x)
        self.fitted = True

    def score(self, window: np.ndarray) -> float:
        x = window.reshape(1, -1)
        # decision_function: higher = more normal; convert to anomaly score in [0,1]
        raw = float(-self.model.decision_function(x)[0])
        return float(1.0 / (1.0 + np.exp(-raw)))


def window_to_tensor(batch: dict[str, Any], length: int = 60) -> np.ndarray:
    values = batch.get("values") or {}
    missing = batch.get("missingness") or {}
    cols = []
    for name in METRIC_ORDER:
        v = list(values.get(name) or [0.0] * length)[:length]
        m = list(missing.get(name) or [0.0] * length)[:length]
        if len(v) < length:
            v = v + [0.0] * (length - len(v))
        if len(m) < length:
            m = m + [1.0] * (length - len(m))
        cols.append(v)
        cols.append(m)
    arr = np.asarray(cols, dtype=np.float32).T
    return arr


def contributor_errors(batch: dict[str, Any], top_k: int = 3) -> list[dict[str, Any]]:
    """Rank metrics by absolute deviation from baseline mean (first half of window)."""
    values = batch.get("values") or {}
    scored: list[dict[str, Any]] = []
    for name in METRIC_ORDER:
        series = list(values.get(name) or [])
        if not series:
            continue
        mid = max(1, len(series) // 2)
        baseline = float(np.mean(series[:mid])) if mid else 0.0
        recent = float(np.mean(series[mid:])) if mid < len(series) else float(np.mean(series))
        error = abs(recent - baseline)
        scored.append(
            {
                "metric": name,
                "error": round(error, 6),
                "observed": round(recent, 6),
                "expected": round(baseline, 6),
            }
        )
    scored.sort(key=lambda item: item["error"], reverse=True)
    return scored[:top_k]


def reconstruction_contributors(
    residuals_per_feature: np.ndarray,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """Map TranAD per-channel residuals (value channels only) to contributor dicts."""
    # residuals_per_feature: [F=14] alternating value/missingness
    scored: list[dict[str, Any]] = []
    for i, name in enumerate(METRIC_ORDER):
        idx = i * 2  # value channel
        if idx >= len(residuals_per_feature):
            break
        err = float(residuals_per_feature[idx])
        scored.append(
            {
                "metric": name,
                "error": round(err, 6),
                "type": "reconstruction_residual",
            }
        )
    scored.sort(key=lambda item: item["error"], reverse=True)
    return scored[:top_k]


def heuristic_score(batch: dict[str, Any]) -> dict[str, Any]:
    values = batch.get("values") or {}
    error = values.get("http.error_rate") or [0.0]
    lat = values.get("http.duration.p95") or [0.0]
    cpu = values.get("cpu.utilization") or [0.0]
    pool = values.get("db.pool.utilization") or [0.0]
    score = min(
        0.99,
        0.1
        + float(np.mean(error)) * 2.0
        + float(np.mean(lat)) / 50.0
        + max(0.0, float(np.mean(cpu)) - 0.8)
        + max(0.0, float(np.mean(pool)) - 0.7),
    )
    severity = "low"
    if score >= 0.93:
        severity = "critical"
    elif score >= 0.80:
        severity = "high"
    elif score >= 0.60:
        severity = "medium"
    return {
        "risk_score": round(float(score), 4),
        "raw_score": round(float(score), 4),
        "calibrated_score": round(float(score), 4),
        "severity": severity,
        "model_name": "metrics-model",
        "model_version": "1.2.0-heuristic",
        "contributors": contributor_errors(batch),
        "evidence": {
            "profile": batch.get("profile", "web_service_v1"),
            "missing_fraction": batch.get("missing_fraction"),
            "mean_error_rate": float(np.mean(error)) if error else 0.0,
        },
    }
