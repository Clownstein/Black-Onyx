from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

AliasName = Literal["champion", "canary", "shadow", "candidate"]


class _ModelNameModel(BaseModel):
    model_config = ConfigDict(protected_namespaces=())


class TrainingJobCreate(BaseModel):
    tenant_id: str = "tenant-acme"
    dataset_id: str | None = None
    source_query: str = "SELECT * FROM normalized_logs"
    time_range_start: str = "2026-06-01T00:00:00Z"
    time_range_end: str = "2026-07-15T00:00:00Z"
    excluded_incidents: list[str] = Field(default_factory=list)
    created_by: str = Field(min_length=1, max_length=320)
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    run_async: bool = True


class TrainingJobResponse(_ModelNameModel):
    job_id: str
    tenant_id: str
    model_name: str
    status: str
    version: str | None = None
    message: str | None = None
    package_path: str | None = None
    dataset_manifest: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class PromoteRequest(BaseModel):
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
    recommendation: str


class DriftObservationCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    observed: dict[str, Any] = Field(default_factory=dict)
