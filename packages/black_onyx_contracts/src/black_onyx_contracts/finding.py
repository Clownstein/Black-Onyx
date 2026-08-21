"""Finding schema models (platform section 10.2)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityHint = Literal["low", "medium", "high", "critical"]


class FindingWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: datetime
    end: datetime


# Backward-compatible alias used by correlation-engine tests/docs.
TimeWindow = FindingWindow


class FindingContributor(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str | None = None
    contribution: float = 0.0
    template_id: str | None = None
    position: int | None = None
    summary: str | None = None


class FindingCompliance(BaseModel):
    """Optional security-profile pack/check enrichment on a finding."""

    model_config = ConfigDict(extra="allow")

    profile_pack_ids: list[str] = Field(default_factory=list)
    check_ids: list[str] = Field(default_factory=list)
    surfaces: list[str] = Field(default_factory=list)
    automation: Literal["auto", "manual", "hybrid"] | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    schema_version: str = Field(default="1.0", pattern=r"^[0-9]+\.[0-9]+$")
    finding_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    finding_type: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)
    service_id: str | None = Field(default=None, max_length=256)
    model_name: str = Field(min_length=1, max_length=128)
    model_version: str = Field(min_length=1, max_length=64)
    feature_version: str | None = Field(default=None, max_length=64)
    raw_score: float
    calibrated_score: float = Field(ge=0.0, le=1.0)
    severity_hint: SeverityHint | None = None
    window: FindingWindow
    contributors: list[FindingContributor | dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None
    category: list[str] = Field(default_factory=list)
    occurred_at: datetime | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    compliance: FindingCompliance | None = None
