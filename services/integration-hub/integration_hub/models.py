from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from integration_hub.db import Base


class TheHiveDryRun(Base):
    __tablename__ = "thehive_dry_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DfirCollectRequest(Base):
    __tablename__ = "dfir_collect_requests"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "request_id",
            name="uq_dfir_requests_tenant_request",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False)
    artifact: Mapped[str] = mapped_column(String(256), nullable=False, default="Generic.Client.Info")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
