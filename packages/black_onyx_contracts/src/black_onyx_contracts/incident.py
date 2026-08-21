"""Incident schema models (platform section 10.8)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IncidentStatus = Literal[
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "closed",
    "suppressed",
]
IncidentSeverity = Literal["low", "medium", "high", "critical"]
IncidentDisposition = Literal[
    "true_positive",
    "false_positive",
    "expected_change",
    "maintenance",
    "benign_anomaly",
    "duplicate",
    "unknown",
]


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    status: IncidentStatus = "open"
    severity: IncidentSeverity | str
    risk_score: float = Field(ge=0.0, le=1.0)
    category: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    assets: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    deployment_id: str | None = Field(default=None, max_length=256)
    commit: str | None = Field(default=None, max_length=128)
    finding_ids: list[str] = Field(default_factory=list)
    summary: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    assigned_to: str | None = Field(default=None, max_length=256)
    disposition: IncidentDisposition | None = None
    fingerprint: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    site_id: str | None = Field(default=None, max_length=128)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    external_links: dict[str, Any] = Field(default_factory=dict)
    models: list[str] = Field(default_factory=list)


class IncidentComment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment_id: str
    incident_id: str
    tenant_id: str
    author: str
    body: str
    created_at: datetime


class IncidentTimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_id: str
    incident_id: str
    tenant_id: str
    event_type: str
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    actor: str | None = None
