"""Unit tests for stable finding ids used for Kafka retry idempotency."""

from __future__ import annotations

from inference_worker.findings import build_finding


def test_stable_finding_id_is_deterministic():
    feature = {
        "tenant_id": "t1",
        "asset_id": "a1",
        "service_id": "svc",
        "feature_id": "feat-1",
        "window_start": "2026-07-26T12:00:00+00:00",
        "window_end": "2026-07-26T12:05:00+00:00",
    }
    predict = {
        "model_name": "log-model",
        "model_version": "1",
        "calibrated_score": 0.7,
        "raw_score": 0.7,
        "contributors": [{"type": "t", "contribution": 0.5, "template_id": "x"}],
    }
    a = build_finding("log-model", feature, predict)
    b = build_finding("log-model", feature, predict)
    assert a["finding_id"] == b["finding_id"] == "feat-1"
