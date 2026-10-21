"""Tests for training-orchestrator drift metrics."""

from __future__ import annotations

from training_orchestrator.drift import compute_drift_metrics


def test_drift_computes_ece_from_calibration_feedback() -> None:
    payload = compute_drift_metrics(
        "log-model",
        observed={
            "calibration_probs": [0.1, 0.2, 0.85, 0.9],
            "calibration_labels": [0, 0, 1, 1],
            "score_distribution_psi": 0.1,
        },
    )
    assert payload["output_drift"]["calibration_against_analyst_feedback_ece"] > 0.0
    assert payload["output_drift"]["brier_score"] >= 0.0
    assert payload["model_name"] == "log-model"


def test_drift_marks_missing_data_and_ignores_other_modalities() -> None:
    empty = compute_drift_metrics("host-state-model", observed={})
    assert empty["evidence_status"] == "insufficient_data"
    assert empty["recommendation"] == "insufficient_data"
    network = compute_drift_metrics(
        "network-model",
        observed={"template_distribution_psi": 9.0, "network_service_and_peer_distribution_psi": 0.2},
    )
    assert network["overall_score"] == 0.2
