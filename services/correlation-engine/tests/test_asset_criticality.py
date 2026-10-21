from __future__ import annotations

from datetime import datetime, timezone

import pytest

from correlation_engine import asset_criticality
from correlation_engine.config import settings
from correlation_engine.engine import CorrelationEngine
from correlation_engine.store import MemoryBucketStore


@pytest.mark.asyncio
async def test_criticality_lookup_is_scoped_by_tenant_and_asset(monkeypatch: pytest.MonkeyPatch) -> None:
    asset_criticality._cache.clear()
    monkeypatch.setattr(settings, "asset_registry_url", "http://asset-registry")
    monkeypatch.setattr(settings, "asset_registry_service_key", "service-key")
    monkeypatch.setattr(settings, "asset_registry_required", True)
    calls: list[tuple[str, dict[str, str]]] = []

    class Response:
        status_code = 200

        def __init__(self, tenant_id: str) -> None:
            self.tenant_id = tenant_id

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"tenant_id": self.tenant_id, "asset_id": "host/one", "criticality": 0.9}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, url: str, *, headers: dict[str, str]) -> Response:
            calls.append((url, headers))
            return Response(headers["X-Tenant-Id"])

    monkeypatch.setattr(asset_criticality.httpx, "AsyncClient", lambda **_kwargs: Client())

    assert await asset_criticality.resolve_asset_criticality("tenant-a", "host/one") == 0.9
    assert await asset_criticality.resolve_asset_criticality("tenant-a", "host/one") == 0.9
    assert await asset_criticality.resolve_asset_criticality("tenant-b", "host/one") == 0.9
    assert len(calls) == 2
    assert calls[0][0].endswith("/api/v1/assets/host%2Fone")
    assert calls[0][1] == {"X-Tenant-Id": "tenant-a", "X-Service-Key": "service-key"}
    assert calls[1][1]["X-Tenant-Id"] == "tenant-b"


@pytest.mark.asyncio
async def test_production_lookup_rejects_registry_failure_and_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_criticality._cache.clear()
    monkeypatch.setattr(settings, "asset_registry_url", "http://asset-registry")
    monkeypatch.setattr(settings, "asset_registry_service_key", "service-key")
    monkeypatch.setattr(settings, "asset_registry_required", True)

    class Response:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"tenant_id": "foreign-tenant", "asset_id": "host-1", "criticality": 1.0}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, *_args, **_kwargs) -> Response:
            return Response()

    monkeypatch.setattr(asset_criticality.httpx, "AsyncClient", lambda **_kwargs: Client())
    with pytest.raises(RuntimeError, match="lookup failed"):
        await asset_criticality.resolve_asset_criticality("tenant-a", "host-1")


def test_risk_scoring_uses_the_registry_criticality() -> None:
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "finding_id": "fnd-criticality",
        "finding_type": "log_anomaly",
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "model_name": "log-model",
        "calibrated_score": 0.7,
        "window": {"start": now, "end": now},
    }
    low = CorrelationEngine(store=MemoryBucketStore()).ingest_finding(
        payload, asset_criticality=0.1,
    )
    high = CorrelationEngine(store=MemoryBucketStore()).ingest_finding(
        payload, asset_criticality=0.9,
    )
    assert low is not None and high is not None
    assert high["risk_score"] > low["risk_score"]
