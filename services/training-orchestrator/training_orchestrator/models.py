from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from training_orchestrator.db import Base


class TrainingJob(Base):
    __tablename__ = "training_jobs"
    __table_args__ = (
        Index("ix_training_jobs_queue", "status", "lease_expires_at"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_training_jobs_tenant_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_manifest_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    synthetic_data: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    claimed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ModelAlias(Base):
    __tablename__ = "model_aliases"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "model_name", "alias", name="uq_model_alias_tenant"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ModelVersionHistory(Base):
    __tablename__ = "model_version_history"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "model_name", "version", name="uq_model_version_tenant"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DriftObservation(Base):
    __tablename__ = "drift_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    observation: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ModelServingDesired(Base):
    """Version and signed package each alias must serve (the serving SoR)."""

    __tablename__ = "model_serving_desired"
    __table_args__ = (
        UniqueConstraint("tenant_id", "model_name", "alias", name="uq_model_serving_desired"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(64), nullable=False)
    # A null package is a durable tombstone that tells every replica to unload
    # this alias and confirms that removal at the current generation.
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    package_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ModelServingInstance(Base):
    """What one model-service replica last reported it actually serves."""

    __tablename__ = "model_serving_instances"
    __table_args__ = (
        UniqueConstraint("tenant_id", "model_name", "instance_id", "alias", name="uq_model_serving_instance"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String(128), nullable=False)
    alias: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    package_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ModelServingLease(Base):
    """Durable serialization lease for one tenant/model/alias transition."""

    __tablename__ = "model_serving_leases"
    __table_args__ = (
        UniqueConstraint("tenant_id", "model_name", "alias", name="uq_model_serving_lease"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(64), nullable=False)
    lease_token: Mapped[str] = mapped_column(String(36), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
