from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKeyConstraint,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from incident_api.db import Base


class IncidentRow(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "incident_id", name="uq_incidents_tenant_incident"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    severity: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    category: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    services: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    disposition: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True)
    models: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    deployment_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CommentRow(Base):
    __tablename__ = "incident_comments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "comment_id", name="uq_comments_tenant_comment"),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_comments_tenant_incident",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    comment_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    author: Mapped[str] = mapped_column(String(256), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditRow(Base):
    __tablename__ = "incident_audit"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_incident_audit_tenant_incident",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "finding_id", name="uq_findings_tenant_finding"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    finding_type: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    asset_id: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    service_id: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    calibrated_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity_hint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Full finding JSON as published by inference / correlation.
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IncidentFindingRow(Base):
    __tablename__ = "incident_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_incident_findings_tenant_incident",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.finding_id"],
            name="fk_incident_findings_tenant_finding",
            ondelete="CASCADE",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TimelineRow(Base):
    __tablename__ = "incident_timeline"
    __table_args__ = (
        UniqueConstraint("tenant_id", "entry_id", name="uq_timeline_tenant_entry"),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_timeline_tenant_incident",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    entry_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    actor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DeploymentEventRow(Base):
    __tablename__ = "deployment_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "deployment_id",
            name="uq_deployments_tenant_deployment",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    deployment_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    service_id: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="succeeded")
    deployed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SavedHuntRow(Base):
    __tablename__ = "saved_hunts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "hunt_id", name="uq_saved_hunts_tenant_hunt"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    hunt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    query_type: Mapped[str] = mapped_column(String(64), nullable=False, default="text")
    filters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AnalystFeedbackRow(Base):
    __tablename__ = "analyst_feedback"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "feedback_id",
            name="uq_feedback_tenant_feedback",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_feedback_tenant_incident",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.finding_id"],
            name="fk_feedback_tenant_finding",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    feedback_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class NotificationSettingRow(Base):
    __tablename__ = "notification_settings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "setting_id",
            name="uq_notification_settings_tenant_setting",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    setting_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    channel: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class OperationalAuditRow(Base):
    __tablename__ = "operational_audit"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SecurityProfileRow(Base):
    __tablename__ = "security_profiles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "profile_id", name="uq_security_profiles_tenant_profile"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    selected_packs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    asset_scope: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    enabled_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    schedule: Mapped[str] = mapped_column(String(64), nullable=False, default="on_demand")
    strictness: Mapped[str] = mapped_column(String(64), nullable=False, default="baseline")
    merge_policy: Mapped[str] = mapped_column(String(64), nullable=False, default="union_strictest")
    active: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ProfileCheckStateRow(Base):
    __tablename__ = "profile_check_state"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "profile_id",
            "check_id",
            name="uq_profile_check_state_tenant_profile_check",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "profile_id"],
            ["security_profiles.tenant_id", "security_profiles.profile_id"],
            name="fk_profile_state_tenant_profile",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ProfileAttestationRow(Base):
    __tablename__ = "profile_attestations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "attestation_id",
            name="uq_attestations_tenant_attestation",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "profile_id"],
            ["security_profiles.tenant_id", "security_profiles.profile_id"],
            name="fk_attestations_tenant_profile",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    attestation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(String(256), nullable=False)
    author: Mapped[str] = mapped_column(String(256), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_links: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    attested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProfileExceptionRow(Base):
    __tablename__ = "profile_exceptions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "exception_id",
            name="uq_exceptions_tenant_exception",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "profile_id"],
            ["security_profiles.tenant_id", "security_profiles.profile_id"],
            name="fk_exceptions_tenant_profile",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    exception_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(String(256), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
