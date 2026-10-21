from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
METRICS_MODEL = ROOT / "models" / "metrics-model"
if str(METRICS_MODEL) not in sys.path:
    sys.path.insert(0, str(METRICS_MODEL))

from metrics_model.model import heuristic_score  # noqa: E402


def _series(baseline: float, n: int = 60) -> list[float]:
    return [baseline] * n


def test_spike_and_drift_score_higher_than_control() -> None:
    control = heuristic_score(
        {
            "values": {
                "http.error_rate": _series(0.01),
                "http.duration.p95": _series(25.0),
                "cpu.utilization": _series(0.35),
                "db.pool.utilization": _series(0.4),
            }
        }
    )
    spike = heuristic_score(
        {
            "values": {
                "http.error_rate": _series(0.01, 45) + [0.45] * 15,
                "http.duration.p95": _series(25.0, 45) + [220.0] * 15,
                "cpu.utilization": _series(0.35),
                "db.pool.utilization": _series(0.4, 45) + [0.95] * 15,
            }
        }
    )
    drift = heuristic_score(
        {
            "values": {
                "http.error_rate": [0.02 + i * 0.01 for i in range(60)],
                "http.duration.p95": [30.0 + i * 3.0 for i in range(60)],
                "cpu.utilization": [0.4 + i * 0.01 for i in range(60)],
                "db.pool.utilization": [0.5 + i * 0.008 for i in range(60)],
            }
        }
    )

    assert spike["risk_score"] > control["risk_score"]
    assert drift["risk_score"] > control["risk_score"]
