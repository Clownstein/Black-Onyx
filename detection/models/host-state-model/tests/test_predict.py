from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from host_state_model.scorer import HostStateScorer
from inference.app import app

EXAMPLE_REQUESTS = Path(__file__).resolve().parents[1] / "examples" / "platform_requests.jsonl"


def test_platform_request_examples_are_directly_scoreable() -> None:
    scorer = HostStateScorer()
    rows = [json.loads(line) for line in EXAMPLE_REQUESTS.read_text(encoding="utf-8").splitlines()]
    scores = [scorer.predict(row)["results"][0]["calibrated_score"] for row in rows]
    assert scores == [0.18, 0.91, 0.54, 0.26, 0.08, 0.12, 0.89]
    assert rows[-1]["source_feature"]["detections"]


def test_passthrough_calibrated() -> None:
    scorer = HostStateScorer()
    out = scorer.predict(
        {
            "request_id": "r1",
            "tenant_id": "t1",
            "items": [{"sequence_id": "s1", "calibrated_score": 0.77}],
        }
    )
    assert out["results"][0]["calibrated_score"] == 0.77
    assert out["model_name"] == "host-state-model"


def test_predict_http() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/predict",
        json={
            "request_id": "r2",
            "tenant_id": "t1",
            "model_name": "host-state-model",
            "items": [{"feature_id": "f1", "severity": "high", "rule_hits": [{"rule_id": "R1"}]}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["calibrated_score"] >= 0.4
    assert client.get("/health/live").json()["status"] == "alive"
