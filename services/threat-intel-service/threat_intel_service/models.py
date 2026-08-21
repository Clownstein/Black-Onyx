from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel_service.db import Base


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint(
            "observable_type",
            "observable_value",
            "source",
            name="uq_indicators_type_value_source",
        ),
    )

    indicator_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    observable_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    observable_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    tlp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    labels: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    campaigns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    raw_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class FeedHealth(Base):
    __tablename__ = "feed_health"

    feed_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    indicator_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class FeedCheckpoint(Base):
    __tablename__ = "feed_checkpoints"

    feed_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    etag: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
