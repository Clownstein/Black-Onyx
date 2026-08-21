"""Drift metrics structure matching platform §13.8."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def compute_drift_metrics(
    model_name: str, observed: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Compute drift metrics from persisted aggregate observations.

    Missing observations produce a zero-data baseline instead of fabricated
    healthy-looking values.
    """
    observed = observed or {}
    input_drift = {
        "template_distribution_psi": float(observed.get("template_distribution_psi", 0.0)),
        "unknown_template_rate": float(observed.get("unknown_template_rate", 0.0)),
        "code_language_and_path_distribution_psi": float(
            observed.get("code_language_and_path_distribution_psi", 0.0)
        ),
        "network_service_and_peer_distribution_psi": float(
            observed.get("network_service_and_peer_distribution_psi", 0.0)
        ),
        "metrics_value_distribution_psi": float(
            observed.get("metrics_value_distribution_psi", 0.0)
        ),
        "missingness_rate": float(observed.get("missingness_rate", 0.0)),
        "sequence_length_mean_delta": float(observed.get("sequence_length_mean_delta", 0.0)),
        "event_rate_delta": float(observed.get("event_rate_delta", 0.0)),
    }
    output_drift = {
        "score_distribution_psi": float(observed.get("score_distribution_psi", 0.0)),
        "alert_rate": float(observed.get("alert_rate", 0.0)),
        "contributor_distribution_psi": float(observed.get("contributor_distribution_psi", 0.0)),
        "calibration_against_analyst_feedback_ece": float(
            observed.get("calibration_against_analyst_feedback_ece", 0.0)
        ),
    }
    concept_drift = {
        "falling_precision": bool(observed.get("falling_precision", False)),
        "rising_false_positive_rate": bool(observed.get("rising_false_positive_rate", False)),
        "missed_seeded_incidents": int(observed.get("missed_seeded_incidents", 0)),
        "changes_after_major_architecture_or_deployment_shifts": bool(
            observed.get("changes_after_major_architecture_or_deployment_shifts", False)
        ),
        "precision_delta": float(observed.get("precision_delta", 0.0)),
        "false_positive_rate_delta": float(observed.get("false_positive_rate_delta", 0.0)),
    }

    overall = (
        input_drift["template_distribution_psi"]
        + input_drift["unknown_template_rate"]
        + output_drift["score_distribution_psi"]
        + output_drift["calibration_against_analyst_feedback_ece"]
    ) / 4.0
    if concept_drift["falling_precision"] or concept_drift["rising_false_positive_rate"]:
        overall = max(overall, 0.55)
    recommendation = "monitor"
    if overall >= 0.5:
        recommendation = "retrain_candidate"
    elif overall >= 0.25:
        recommendation = "investigate"

    return {
        "model_name": model_name,
        "computed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "input_drift": input_drift,
        "output_drift": output_drift,
        "concept_drift": concept_drift,
        "overall_score": round(overall, 4),
        "recommendation": recommendation,
    }
