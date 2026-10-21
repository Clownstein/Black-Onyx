"""Log modality event and feature contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from black_onyx_contracts.envelope import AssetRef, SourceRef, TraceRef
from black_onyx_contracts.log_raw import LogRawEvent, LogResource

__all__ = [
    "LogRawEvent",
    "LogResource",
    "LogRawPayload",
    "LogParameter",
    "LogNormalizedEvent",
    "LogFeatureEvent",
    "LogFeatureSequence",
]


class LogRawPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    severity: str = "INFO"
    facility: str | None = None
    logger: str | None = None
    message: str
    structured: dict[str, Any] | None = None
    resource: LogResource | None = None


class LogParameter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: str
    value_hash: str | None = None
    category: str | None = None


class LogNormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    event_id: str
    event_type: str = "log.normalized"
    tenant_id: str
    occurred_at: datetime
    ingested_at: datetime
    source: SourceRef
    asset: AssetRef
    trace: TraceRef | None = None
    template_id: str
    template: str
    parameters: list[LogParameter] = Field(default_factory=list)
    sequence_key: str
    severity: str = "INFO"
    logger: str | None = None
    masked_message: str | None = None
    labels: dict[str, str] | None = None


class LogFeatureEvent(BaseModel):
    """Single tokenized event inside a feature sequence."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    template_id: str
    severity: str = "INFO"
    logger: str | None = None
    occurred_at: datetime
    delta_ms: int = 0
    parameter_categories: list[str] = Field(default_factory=list)
    is_novel_template: bool = False


class LogFeatureSequence(BaseModel):
    """Windowed sequence published to logs.features."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    sequence_id: str
    event_type: str = "log.feature_sequence"
    tenant_id: str
    asset_id: str
    service_id: str | None = None
    sequence_key: str
    feature_version: str = "1.0"
    processor_version: str = "1.0.0"
    window_start: datetime
    window_end: datetime
    events: list[LogFeatureEvent] = Field(min_length=1)
    idempotency_key: str
    labels: dict[str, str] | None = None
