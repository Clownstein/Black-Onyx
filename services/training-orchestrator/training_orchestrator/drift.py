"""Drift metrics structure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from black_onyx_calibration import brier_score, expected_calibration_error


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
        "brier_score": float(observed.get("brier_score", 0.0)),
    }
    cal_probs = observed.get("calibration_probs")
    cal_labels = observed.get("calibration_labels")
    if isinstance(cal_probs, list) and isinstance(cal_labels, list) and cal_probs and cal_labels:
        output_drift["calibration_against_analyst_feedback_ece"] = expected_calibration_error(
            cal_probs, cal_labels
        )
        output_drift["brier_score"] = brier_score(cal_probs, cal_labels)
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

    modality = model_name.removesuffix("-model").casefold()
    modality_features = {
        "log": ("template_distribution_psi", "unknown_template_rate", "sequence_length_mean_delta", "event_rate_delta"),
        "code": ("code_language_and_path_distribution_psi", "unknown_template_rate", "sequence_length_mean_delta", "event_rate_delta"),
        "network": ("network_service_and_peer_distribution_psi", "sequence_length_mean_delta", "event_rate_delta"),
        "metrics": ("metrics_value_distribution_psi", "missingness_rate", "event_rate_delta"),
    }
    delta_keys = {"sequence_length_mean_delta", "event_rate_delta"}
    selected_features = modality_features.get(modality, ())
    score_keys = (
        *selected_features, "score_distribution_psi", "alert_rate", "contributor_distribution_psi",
        "calibration_against_analyst_feedback_ece", "brier_score",
    )
    drift_components = [
        abs(float(observed[key])) if key in delta_keys else float(observed[key])
        for key in score_keys
        if isinstance(observed.get(key), (int, float)) and not isinstance(observed.get(key), bool)
    ]
    has_calibration_samples = (
        isinstance(cal_probs, list) and isinstance(cal_labels, list) and len(cal_probs) > 0
        and len(cal_probs) == len(cal_labels) and len(cal_probs) <= 10000
    )
    evidence_status = "available" if drift_components or has_calibration_samples or any(
        key in observed for key in (
            "falling_precision", "rising_false_positive_rate", "missed_seeded_incidents",
            "changes_after_major_architecture_or_deployment_shifts",
        )
    ) else "insufficient_data"
    overall = sum(drift_components) / len(drift_components) if drift_components else 0.0
    if concept_drift["falling_precision"] or concept_drift["rising_false_positive_rate"]:
        overall = max(overall, 0.55)
    recommendation = "insufficient_data" if evidence_status == "insufficient_data" else "monitor"
    if evidence_status == "available" and overall >= 0.5:
        recommendation = "retrain_candidate"
    elif evidence_status == "available" and overall >= 0.25:
        recommendation = "investigate"

    return {
        "model_name": model_name,
        "computed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "input_drift": input_drift,
        "output_drift": output_drift,
        "concept_drift": concept_drift,
        "overall_score": round(overall, 4),
        "evidence_status": evidence_status,
        "recommendation": recommendation,
    }
