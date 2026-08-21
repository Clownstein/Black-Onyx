"""Regression: failed publish must not permanently drop an incident."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from correlation_engine.engine import CorrelationEngine
from correlation_engine.store import MemoryBucketStore


def _finding(fid: str = "fnd-1") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "finding_id": fid,
        "finding_type": "log_anomaly",
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "service_id": "payments-api",
        "calibrated_score": 0.9,
        "model_name": "log-model",
        "contributors": [{"type": "template", "contribution": 0.8, "template_id": "auth"}],
        "context": {},
        "window": {"start": now, "end": now},
    }


@pytest.mark.asyncio
async def test_failed_publish_allows_retry_on_redelivery(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = CorrelationEngine(store=MemoryBucketStore())
    incident = engine.ingest_finding(_finding())
    assert incident is not None
    incident_id = incident["incident_id"]

    # First publish fails (incident-api blip).
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise httpx.HTTPError("boom")

    monkeypatch.setattr("correlation_engine.engine.httpx.AsyncClient", FakeClient)

    with pytest.raises(httpx.HTTPError):
        await engine.publish_incident(incident)

    # Duplicate redelivery must rebuild incident for retry (not silently drop).
    again = engine.ingest_finding(_finding())
    assert again is not None
    assert again["incident_id"] == incident_id

    # Successful publish then suppresses further duplicates.
    class OkResp:
        def raise_for_status(self) -> None:
            return None

    class OkClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return OkResp()

    monkeypatch.setattr("correlation_engine.engine.httpx.AsyncClient", OkClient)
    # suppress notification path noise by marking suppress
    again["suppress_notification"] = True
    await engine.publish_incident(again)

    dropped = engine.ingest_finding(_finding())
    assert dropped is None
