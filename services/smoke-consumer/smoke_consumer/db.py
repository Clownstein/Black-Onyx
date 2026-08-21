from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    String,
    UniqueConstraint,
    create_engine,
    func,
    inspect,
    select,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from smoke_consumer.config import settings


class Base(DeclarativeBase):
    pass


class IngestedEvent(Base):
    __tablename__ = "ingested_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", name="uq_ingested_events_tenant_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    if "ingested_events" not in set(inspect(engine).get_table_names()):
        raise RuntimeError(
            "smoke-consumer schema is not migrated; missing ingested_events"
        )


def upsert_event(
    tenant_id: str,
    event_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> bool:
    """Idempotent upsert on (tenant_id, event_id). Returns True when a row was inserted."""
    with SessionLocal() as session:
        stmt = (
            pg_insert(IngestedEvent)
            .values(
                tenant_id=tenant_id,
                event_id=event_id,
                event_type=event_type,
                payload=payload,
            )
            .on_conflict_do_nothing(constraint="uq_ingested_events_tenant_event")
            .returning(IngestedEvent.id)
        )
        result = session.execute(stmt).scalar_one_or_none()
        session.commit()
        return result is not None


def count_events() -> int:
    with SessionLocal() as session:
        return session.scalar(select(func.count()).select_from(IngestedEvent)) or 0


def event_exists(tenant_id: str, event_id: str) -> bool:
    with SessionLocal() as session:
        row = session.scalar(
            select(IngestedEvent.id).where(
                IngestedEvent.tenant_id == tenant_id,
                IngestedEvent.event_id == event_id,
            )
        )
        return row is not None
