from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from asset_registry.db import Base


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "asset_id", name="uq_assets_tenant_asset"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    service_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    owner_team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    network_zone: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expected_peers: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    tags: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
