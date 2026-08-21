import importlib.util
import sys
from pathlib import Path

import torch
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from metrics_model.model import (
    MultivariateMetricTransformer,
    contributor_errors,
    heuristic_score,
    window_to_tensor,
)
from training.train import load_dataset

EXAMPLE_DATASET = Path(__file__).resolve().parents[1] / "training" / "examples" / "platform_windows.jsonl"


def test_platform_dataset_uses_runtime_metric_order():
    windows, labels = load_dataset(EXAMPLE_DATASET)
    assert windows.shape == (8, 60, 14)
    assert set(labels.tolist()) == {0.0, 1.0}
    assert windows[0, 0, 0] == 0.31


def _load_metrics_app():
    path = ROOT / "inference" / "app.py"
    spec = importlib.util.spec_from_file_location("metrics_inference_app", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["metrics_inference_app"] = mod
    # Ensure package-relative imports inside app resolve against metrics-model.
    sys.path.insert(0, str(ROOT))
    spec.loader.exec_module(mod)
    return mod.app


app = _load_metrics_app()


def test_forward_shape():
    model = MultivariateMetricTransformer(window_length=16)
    x = torch.rand(2, 16, 14)
    out = model(x)
    assert out.shape == (2,)


def test_heuristic_and_contributors():
    batch = {
        "values": {
            "http.error_rate": [0.01] * 30 + [0.4] * 30,
            "http.duration.p95": [20.0] * 30 + [200.0] * 30,
            "db.pool.utilization": [0.2] * 30 + [0.95] * 30,
            "cpu.utilization": [0.2] * 60,
        },
        "profile": "web_service_v1",
    }
    result = heuristic_score(batch)
    assert result["risk_score"] > 0.5
    contrib = contributor_errors(batch)
    assert contrib
    assert contrib[0]["error"] >= contrib[-1]["error"]
    arr = window_to_tensor({"values": {"cpu.utilization": [0.1] * 60}}, length=60)
    assert arr.shape == (60, 14)


def test_predict_endpoint_fails_closed_without_trained_artifact():
    client = TestClient(app)
    resp = client.post(
        "/v1/predict",
        json={
            "values": {
                "http.error_rate": [0.01] * 30 + [0.5] * 30,
                "db.pool.utilization": [0.2] * 30 + [0.9] * 30,
            }
        },
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"] == "A trained metrics model artifact is required"
