"""Shared correlation bucket store (memory or Redis)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Protocol

from correlation_engine.config import settings
from correlation_engine.scoring import FindingView

logger = logging.getLogger("correlation-engine.store")


def _finding_to_dict(f: FindingView) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "finding_type": f.finding_type,
        "tenant_id": f.tenant_id,
        "asset_id": f.asset_id,
        "service_id": f.service_id,
        "calibrated_score": f.calibrated_score,
        "model_name": f.model_name,
        "contributors": f.contributors,
        "context": f.context,
        "window_start": f.window_start.isoformat() if f.window_start else None,
        "window_end": f.window_end.isoformat() if f.window_end else None,
    }


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _finding_from_dict(data: dict[str, Any]) -> FindingView:
    return FindingView(
        finding_id=str(data["finding_id"]),
        finding_type=str(data.get("finding_type") or "unknown"),
        tenant_id=str(data["tenant_id"]),
        asset_id=str(data.get("asset_id") or "unknown"),
        service_id=data.get("service_id"),
        calibrated_score=float(data.get("calibrated_score") or 0.0),
        model_name=str(data.get("model_name") or "unknown"),
        contributors=list(data.get("contributors") or []),
        context=dict(data.get("context") or {}),
        window_start=_parse_dt(data.get("window_start")),
        window_end=_parse_dt(data.get("window_end")),
    )


class BucketState:
    def __init__(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        service_id: str | None,
        findings: list[FindingView] | None = None,
        last_updated: datetime | None = None,
        incident_id: str | None = None,
        last_publish_ok: bool = False,
    ) -> None:
        self.tenant_id = tenant_id
        self.asset_id = asset_id
        self.service_id = service_id
        self.findings = findings or []
        self.last_updated = last_updated or datetime.now(timezone.utc)
        self.incident_id = incident_id
        self.last_publish_ok = last_publish_ok

    def to_json(self) -> str:
        return json.dumps(
            {
                "tenant_id": self.tenant_id,
                "asset_id": self.asset_id,
                "service_id": self.service_id,
                "findings": [_finding_to_dict(f) for f in self.findings],
                "last_updated": self.last_updated.isoformat(),
                "incident_id": self.incident_id,
                "last_publish_ok": self.last_publish_ok,
            },
            default=str,
        )

    @classmethod
    def from_json(cls, raw: str) -> BucketState:
        data = json.loads(raw)
        return cls(
            tenant_id=str(data["tenant_id"]),
            asset_id=str(data["asset_id"]),
            service_id=data.get("service_id"),
            findings=[_finding_from_dict(f) for f in data.get("findings") or []],
            last_updated=_parse_dt(data.get("last_updated")) or datetime.now(timezone.utc),
            incident_id=data.get("incident_id"),
            last_publish_ok=bool(data.get("last_publish_ok")),
        )


class BucketStore(Protocol):
    def get(self, key: str) -> BucketState | None: ...

    def put(self, key: str, bucket: BucketState) -> None: ...


class MemoryBucketStore:
    def __init__(self) -> None:
        self._buckets: dict[str, BucketState] = {}

    def get(self, key: str) -> BucketState | None:
        return self._buckets.get(key)

    def put(self, key: str, bucket: BucketState) -> None:
        self._buckets[key] = bucket


class RedisBucketStore:
    def __init__(self, url: str, *, ttl_seconds: int) -> None:
        import redis

        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._ttl = max(60, ttl_seconds)
        self._prefix = "corr:bucket:"

    def get(self, key: str) -> BucketState | None:
        raw = self._client.get(self._prefix + key)
        if not raw:
            return None
        return BucketState.from_json(str(raw))

    def put(self, key: str, bucket: BucketState) -> None:
        self._client.setex(self._prefix + key, self._ttl, bucket.to_json())


def build_bucket_store() -> BucketStore:
    url = (settings.redis_url or "").strip()
    ttl = int(settings.initial_window_minutes * 60 * 2)
    if not url:
        logger.info("correlation bucket store: memory")
        return MemoryBucketStore()
    try:
        store = RedisBucketStore(url, ttl_seconds=ttl)
        # Fail fast if Redis is unreachable.
        store._client.ping()  # type: ignore[attr-defined]
        logger.info("correlation bucket store: redis (%s)", url)
        return store
    except Exception:  # noqa: BLE001
        logger.exception("redis unavailable; falling back to in-memory buckets")
        return MemoryBucketStore()
