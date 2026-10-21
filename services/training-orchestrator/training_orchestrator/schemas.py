from datetime import datetime
import math
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AliasName = Literal["champion", "canary", "shadow", "candidate"]


class _ModelNameModel(BaseModel):
    model_config = ConfigDict(protected_namespaces=())


class TrainingJobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    dataset_id: str | None = Field(default=None, max_length=128)
    source_query: str | None = Field(default=None, max_length=8192)
    time_range_start: str | None = Field(default=None, max_length=64)
    time_range_end: str | None = Field(default=None, max_length=64)
    excluded_incidents: list[str] = Field(default_factory=list, max_length=10_000)
    created_by: str = Field(min_length=1, max_length=320)
    hyperparameters: dict[str, Any] = Field(default_factory=dict, max_length=128)
    run_async: bool = True
    dataset_path: str | None = Field(default=None, min_length=1, max_length=4096)
    dataset_reviewed: bool = False
    demo_synthetic: bool = False

    @model_validator(mode="after")
    def require_dataset_boundary(self) -> "TrainingJobCreate":
        if not self.dataset_path and not self.demo_synthetic:
            raise ValueError("dataset_path is required unless demo_synthetic=true")
        if self.dataset_path and not self.demo_synthetic and not self.dataset_reviewed:
            raise ValueError("dataset_reviewed=true is required for production training")
        return self


class TrainingJobResponse(_ModelNameModel):
    job_id: str
    tenant_id: str
    model_name: str
    status: str
    version: str | None = None
    message: str | None = None
    package_path: str | None = None
    dataset_manifest: dict[str, Any] | None = None
    synthetic_data: bool = False
    attempt_count: int = 0
    max_attempts: int = 3
    claimed_by: str | None = None
    lease_expires_at: datetime | None = None
    heartbeat_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    failure_reason: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class PromoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: AliasName = "champion"


class PromoteResponse(_ModelNameModel):
    model_name: str
    alias: AliasName
    version: str
    previous_version: str | None = None


class RollbackResponse(_ModelNameModel):
    model_name: str
    alias: str = "champion"
    version: str
    previous_version: str | None = None


class DriftMetricsResponse(_ModelNameModel):
    model_name: str
    computed_at: str
    input_drift: dict[str, Any]
    output_drift: dict[str, Any]
    concept_drift: dict[str, Any]
    overall_score: float
    evidence_status: str
    recommendation: str


class DriftObservationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    observed: dict[str, Any] = Field(default_factory=dict, max_length=256)

    @field_validator("observed")
    @classmethod
    def validate_calibration_samples(cls, value: dict[str, Any]) -> dict[str, Any]:
        psi_keys = {
            "template_distribution_psi", "code_language_and_path_distribution_psi",
            "network_service_and_peer_distribution_psi", "metrics_value_distribution_psi",
            "score_distribution_psi", "contributor_distribution_psi",
        }
        rate_keys = {"unknown_template_rate", "missingness_rate", "alert_rate"}
        for key, raw in value.items():
            if key in {"calibration_probs", "calibration_labels"} or isinstance(raw, (list, dict, str, bool)):
                continue
            if isinstance(raw, (int, float)):
                number = float(raw)
                if not math.isfinite(number):
                    raise ValueError(f"{key} must be finite")
                if key in psi_keys and number < 0:
                    raise ValueError(f"{key} cannot be negative")
                if key in rate_keys and not 0 <= number <= 1:
                    raise ValueError(f"{key} must be in [0,1]")
        missed = value.get("missed_seeded_incidents")
        if missed is not None and (isinstance(missed, bool) or not isinstance(missed, int) or missed < 0):
            raise ValueError("missed_seeded_incidents must be a non-negative integer")
        probabilities = value.get("calibration_probs")
        labels = value.get("calibration_labels")
        if probabilities is None and labels is None:
            return value
        if not isinstance(probabilities, list) or not isinstance(labels, list):
            raise ValueError("calibration_probs and calibration_labels must be supplied together")
        if len(probabilities) != len(labels) or len(probabilities) > 10000:
            raise ValueError("calibration samples must be paired and contain at most 10000 values")
        try:
            valid = all(math.isfinite(float(prob)) and 0.0 <= float(prob) <= 1.0 for prob in probabilities) and all(
                int(label) in (0, 1) and float(label) == int(label) for label in labels
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("calibration probabilities must be in [0,1] and labels must be 0 or 1")
        return value
