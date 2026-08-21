from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceItem(BaseModel):
    kind: str
    model: str = ""
    title: str = ""
    detail: str = ""
    score: float | None = None
    timestamp: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class IncidentCreate(BaseModel):
    incident_id: str | None = None
    title: str
    status: str = "open"
    severity: str
    risk_score: float = 0.0
    category: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    assets: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    summary: str | None = None
    disposition: str | None = None
    assigned_to: str | None = None
    models: list[str] = Field(default_factory=list)
    deployment_id: str | None = None
    commit: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None


class IncidentPatch(BaseModel):
    title: str | None = None
    status: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    assigned_to: str | None = None
    summary: str | None = None
    category: list[str] | None = None
    finding_ids: list[str] | None = None
    last_seen: datetime | None = None


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    tenant_id: str
    title: str
    status: str
    severity: str
    risk_score: float
    category: list[str]
    first_seen: datetime
    last_seen: datetime
    assets: list[str]
    services: list[str]
    finding_ids: list[str]
    summary: str | None = None
    disposition: str | None = None
    assigned_to: str | None = None
    models: list[str] = Field(default_factory=list)
    deployment_id: str | None = None
    commit: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None


class IncidentListResponse(BaseModel):
    items: list[IncidentRead] = Field(default_factory=list)
    next_cursor: str | None = None


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class CommentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    comment_id: str
    incident_id: str
    author: str
    body: str
    created_at: datetime


class DispositionCreate(BaseModel):
    disposition: str
    note: str | None = None


class TimelineEvent(BaseModel):
    entry_id: str | None = None
    occurred_at: datetime
    event_type: str
    summary: str
    refs: dict[str, Any] = Field(default_factory=dict)
    actor: str | None = None


class DeploymentEventCreate(BaseModel):
    deployment_id: str | None = None
    service_id: str = Field(min_length=1, max_length=256)
    environment: str = Field(min_length=1, max_length=128)
    commit_sha: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=128)
    status: str = Field(default="succeeded", min_length=1, max_length=64)
    deployed_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)


class DeploymentEventRead(DeploymentEventCreate):
    model_config = ConfigDict(from_attributes=True)

    deployment_id: str
    tenant_id: str
    created_at: datetime


class SavedHuntCreate(BaseModel):
    hunt_id: str | None = None
    name: str = Field(min_length=1, max_length=256)
    query: str = Field(min_length=1, max_length=16000)
    query_type: str = Field(default="text", max_length=64)
    filters: dict[str, Any] = Field(default_factory=dict)


class SavedHuntRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    hunt_id: str
    tenant_id: str
    name: str
    query: str
    query_type: str
    filters: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: datetime
    updated_at: datetime


class AnalystFeedbackCreate(BaseModel):
    finding_id: str | None = Field(default=None, max_length=128)
    label: str = Field(
        min_length=1,
        max_length=64,
        pattern="^(true_positive|false_positive|expected_change|benign|needs_review|missed_detection)$",
    )
    note: str | None = Field(default=None, max_length=8000)


class AnalystFeedbackRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    feedback_id: str
    tenant_id: str
    incident_id: str
    finding_id: str | None = None
    label: str
    note: str | None = None
    actor: str
    created_at: datetime


class NotificationSettingWrite(BaseModel):
    setting_id: str | None = Field(default=None, max_length=128)
    channel: str = Field(
        min_length=1,
        max_length=64,
        pattern="^(email|webhook|slack|teams)$",
    )
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)


class NotificationSettingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    setting_id: str
    tenant_id: str
    channel: str
    enabled: bool
    config: dict[str, Any] = Field(default_factory=dict)
    updated_by: str
    created_at: datetime
    updated_at: datetime


class CapabilityState(BaseModel):
    status: str
    capability: str
    reason: str | None = None
    retry_after_seconds: int | None = None


class HealthDependencies(BaseModel):
    status: str
    database: str
    oidc: dict[str, Any]


class FindingWindow(BaseModel):
    start: datetime
    end: datetime


class FindingCreate(BaseModel):
    finding_id: str | None = None
    finding_type: str
    asset_id: str
    service_id: str | None = None
    model_name: str = ""
    model_version: str | None = None
    feature_version: str | None = None
    raw_score: float = 0.0
    calibrated_score: float = 0.0
    severity_hint: str | None = None
    window: FindingWindow
    contributors: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None
    category: list[str] = Field(default_factory=list)
    compliance: dict[str, Any] | None = None
    # Allow callers to pass extra fields preserved in payload.
    schema_version: str = "1.0"


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    tenant_id: str
    finding_type: str
    asset_id: str
    service_id: str | None = None
    model_name: str
    model_version: str | None = None
    raw_score: float
    calibrated_score: float
    severity_hint: str | None = None
    window: FindingWindow
    contributors: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    category: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)


class FindingListResponse(BaseModel):
    items: list[FindingRead] = Field(default_factory=list)
    next_cursor: str | None = None


class FindingEvidenceResponse(BaseModel):
    finding_id: str
    evidence_refs: list[str] = Field(default_factory=list)
    contributors: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)


class SearchRequest(BaseModel):
    query: str = ""
    types: list[str] = Field(default_factory=lambda: ["incident", "finding"])
    limit: int = Field(default=50, ge=1, le=200)


class SearchHit(BaseModel):
    type: str
    id: str
    title: str
    summary: str | None = None
    score: float | None = None
    refs: dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    items: list[SearchHit] = Field(default_factory=list)


class SecurityProfileCreate(BaseModel):
    profile_id: str | None = None
    name: str
    selected_packs: list[str] = Field(default_factory=list)
    asset_scope: list[str] = Field(default_factory=list)
    enabled_surfaces: list[str] = Field(default_factory=list)
    schedule: str = "on_demand"
    strictness: str = "baseline"
    merge_policy: str = "union_strictest"
    active: bool = True


class SecurityProfilePatch(BaseModel):
    name: str | None = None
    selected_packs: list[str] | None = None
    asset_scope: list[str] | None = None
    enabled_surfaces: list[str] | None = None
    schedule: str | None = None
    strictness: str | None = None
    merge_policy: str | None = None
    active: bool | None = None


class SecurityProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    profile_id: str
    tenant_id: str
    name: str
    selected_packs: list[str] = Field(default_factory=list)
    asset_scope: list[str] = Field(default_factory=list)
    enabled_surfaces: list[str] = Field(default_factory=list)
    schedule: str
    strictness: str
    merge_policy: str
    active: bool
    preview: dict[str, Any] | None = None


class ProfileAttestRequest(BaseModel):
    check_id: str
    note: str | None = None
    evidence_links: list[str] = Field(default_factory=list)


class ProfileExceptionCreate(BaseModel):
    check_id: str
    rationale: str
    owner: str
    expires_at: datetime | None = None


class CertificationPackageRequest(BaseModel):
    target: str = Field(description="soc2|pci_dss_4|cmmc_l2|fedramp_mod")
    include_unknown: bool = True
