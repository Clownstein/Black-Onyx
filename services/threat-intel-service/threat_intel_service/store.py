"""Indicator persistence: upsert, match, expire, feed health."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from ulid import ULID

from threat_intel_service.models import FeedCheckpoint, FeedHealth, Indicator


def _now() -> datetime:
    return datetime.now(timezone.utc)


def upsert_indicator(session: Session, data: dict[str, Any]) -> Indicator:
    """Insert or update an indicator keyed by (type, value, source)."""
    observable_type = str(data["observable_type"])
    observable_value = str(data["observable_value"])
    source = str(data["source"])
    indicator_id = str(data.get("indicator_id") or f"ind-{ULID()}")

    existing = session.scalar(
        select(Indicator).where(
            Indicator.observable_type == observable_type,
            Indicator.observable_value == observable_value,
            Indicator.source == source,
        )
    )
    if existing is not None:
        existing.confidence = int(data.get("confidence", existing.confidence))
        if "tlp" in data:
            existing.tlp = data.get("tlp")
        if "tenant_id" in data:
            existing.tenant_id = data.get("tenant_id")
        if "valid_from" in data:
            existing.valid_from = data.get("valid_from")
        if "valid_until" in data:
            existing.valid_until = data.get("valid_until")
        if "labels" in data:
            existing.labels = list(data.get("labels") or [])
        if "campaigns" in data:
            existing.campaigns = list(data.get("campaigns") or [])
        if "mitre_techniques" in data:
            existing.mitre_techniques = list(data.get("mitre_techniques") or [])
        if "raw_json" in data:
            existing.raw_json = data.get("raw_json")
        session.flush()
        return existing

    row = Indicator(
        indicator_id=indicator_id,
        tenant_id=data.get("tenant_id"),
        observable_type=observable_type,
        observable_value=observable_value,
        source=source,
        confidence=int(data.get("confidence", 50)),
        tlp=data.get("tlp"),
        valid_from=data.get("valid_from"),
        valid_until=data.get("valid_until"),
        labels=list(data.get("labels") or []),
        campaigns=list(data.get("campaigns") or []),
        mitre_techniques=list(data.get("mitre_techniques") or []),
        raw_json=data.get("raw_json"),
    )
    session.add(row)
    session.flush()
    return row


def match_observables(
    session: Session,
    observables: list[dict[str, str]],
    *,
    now: datetime | None = None,
) -> list[Indicator]:
    """Return active indicators matching any of the given {type, value} pairs."""
    if not observables:
        return []
    now = now or _now()
    clauses = []
    for obs in observables:
        otype = str(obs.get("type") or obs.get("observable_type") or "").strip()
        value = str(obs.get("value") or obs.get("observable_value") or "").strip()
        if not otype or not value:
            continue
        clauses.append(
            (Indicator.observable_type == otype) & (Indicator.observable_value == value)
        )
    if not clauses:
        return []

    stmt = select(Indicator).where(or_(*clauses))
    rows = list(session.scalars(stmt).all())
    active: list[Indicator] = []
    for row in rows:
        if row.valid_until is not None:
            until = row.valid_until
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            if until < now:
                continue
        active.append(row)
    return active


def expire_stale(session: Session, *, now: datetime | None = None) -> int:
    """Delete indicators whose valid_until is in the past. Returns deleted count."""
    now = now or _now()
    rows = list(session.scalars(select(Indicator).where(Indicator.valid_until.is_not(None))).all())
    deleted = 0
    for row in rows:
        until = row.valid_until
        if until is None:
            continue
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        if until < now:
            session.delete(row)
            deleted += 1
    session.flush()
    return deleted


def record_feed_health(
    session: Session,
    feed_name: str,
    *,
    status: str,
    error: str | None = None,
    indicator_count: int | None = None,
) -> FeedHealth:
    now = _now()
    row = session.get(FeedHealth, feed_name)
    if row is None:
        row = FeedHealth(feed_name=feed_name)
        session.add(row)
    row.last_sync_at = now
    row.last_status = status
    row.last_error = error
    if indicator_count is not None:
        row.indicator_count = indicator_count
    else:
        count = session.scalar(
            select(func.count()).select_from(Indicator).where(Indicator.source == feed_name)
        )
        row.indicator_count = int(count or 0)
    session.flush()
    return row


def get_feed_checkpoint(session: Session, feed_name: str) -> FeedCheckpoint | None:
    return session.get(FeedCheckpoint, feed_name)


def update_feed_checkpoint(
    session: Session,
    feed_name: str,
    *,
    cursor: str | None,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FeedCheckpoint:
    row = session.get(FeedCheckpoint, feed_name)
    if row is None:
        row = FeedCheckpoint(feed_name=feed_name)
        session.add(row)
    row.cursor = cursor
    row.etag = etag
    row.last_modified = last_modified
    row.updated_at = _now()
    session.flush()
    return row


def list_feed_health(session: Session) -> list[dict[str, Any]]:
    rows = list(session.scalars(select(FeedHealth).order_by(FeedHealth.feed_name)).all())
    if rows:
        return [
            {
                "feed_name": r.feed_name,
                "last_sync_at": r.last_sync_at.isoformat() if r.last_sync_at else None,
                "last_status": r.last_status,
                "last_error": r.last_error,
                "indicator_count": r.indicator_count,
            }
            for r in rows
        ]
    # Fallback: summarize by source when no sync rows yet
    counts = session.execute(
        select(Indicator.source, func.count()).group_by(Indicator.source)
    ).all()
    return [
        {
            "feed_name": source,
            "last_sync_at": None,
            "last_status": "unknown",
            "last_error": None,
            "indicator_count": int(count),
        }
        for source, count in counts
    ]


def list_indicators(
    session: Session,
    *,
    q: str | None = None,
    observable_type: str | None = None,
    limit: int = 100,
) -> list[Indicator]:
    stmt = select(Indicator)
    if observable_type:
        stmt = stmt.where(Indicator.observable_type == observable_type)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Indicator.observable_value.ilike(like),
                Indicator.indicator_id.ilike(like),
                Indicator.source.ilike(like),
            )
        )
    stmt = stmt.order_by(Indicator.created_at.desc()).limit(limit)
    return list(session.scalars(stmt).all())


__all__ = [
    "upsert_indicator",
    "match_observables",
    "expire_stale",
    "record_feed_health",
    "get_feed_checkpoint",
    "update_feed_checkpoint",
    "list_feed_health",
    "list_indicators",
]
