"""Integration test: gateway -> Redpanda -> smoke consumer -> Postgres.

Skipped automatically when local dependencies are unavailable.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone

import pytest

try:
    import httpx
    from kafka import KafkaAdminClient, KafkaProducer
    from sqlalchemy import create_engine, text
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


GATEWAY_URL = os.getenv("INGEST_GATEWAY_URL", "http://localhost:8080")
SMOKE_URL = os.getenv("SMOKE_CONSUMER_URL", "http://localhost:8082")
API_KEY = os.getenv("API_KEYS", "dev-ingest-key").split(",")[0].strip()
KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:19092")
DATABASE_URL = os.getenv(
    "SMOKE_DATABASE_URL",
    "postgresql+psycopg://anomaly:anomaly@localhost:5432/smoke",
)


def _deps_available() -> bool:
    if httpx is None:
        return False
    try:
        KafkaAdminClient(bootstrap_servers=KAFKA_BROKERS, request_timeout_ms=2000).close()
    except Exception:
        return False
    try:
        with httpx.Client(timeout=2.0) as client:
            live = client.get(f"{GATEWAY_URL}/health/live")
            smoke = client.get(f"{SMOKE_URL}/health/live")
            if live.status_code != 200 or smoke.status_code != 200:
                return False
    except Exception:
        return False
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(not _deps_available(), reason="compose stack / services not available")


def _ulid_like() -> str:
    # Deterministic-enough Crockford ULID shape for tests (timestamp + randomness).
    # Prefer real ULIDs when the gateway is fed production collectors.
    from ulid import ULID

    return str(ULID())


def test_event_reaches_postgres() -> None:
    event_id = _ulid_like()
    tenant_id = f"tenant-smoke-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    event = {
        "schema_version": "1.0",
        "event_id": event_id,
        "event_type": "log.raw",
        "tenant_id": tenant_id,
        "occurred_at": now,
        "ingested_at": now,
        "source": {"collector_id": "integration-test", "source_type": "test"},
        "asset": {"asset_id": "host-smoke-01", "service_id": "smoke", "environment": "dev"},
        "message": "phase0 smoke event",
    }

    with httpx.Client(timeout=10.0) as client:
        response = client.post(
            f"{GATEWAY_URL}/api/v1/ingest/logs",
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            content=json.dumps({"events": [event]}),
        )
    assert response.status_code in (200, 207), response.text
    body = response.json()
    assert body["accepted"] >= 1

    engine = create_engine(DATABASE_URL)
    deadline = time.time() + 30
    found = False
    while time.time() < deadline:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT event_id FROM ingested_events "
                    "WHERE tenant_id = :tenant_id AND event_id = :event_id"
                ),
                {"tenant_id": tenant_id, "event_id": event_id},
            ).first()
            if row is not None:
                found = True
                break
        time.sleep(1)
    assert found, f"event {event_id} not observed in ingested_events within timeout"


def test_kafka_publish_direct_roundtrip() -> None:
    """Fallback broker check that does not require the Go gateway binary."""
    event_id = _ulid_like()
    tenant_id = f"tenant-kafka-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    event = {
        "schema_version": "1.0",
        "event_id": event_id,
        "event_type": "log.raw",
        "tenant_id": tenant_id,
        "occurred_at": now,
        "ingested_at": now,
        "source": {"collector_id": "integration-test", "source_type": "test"},
        "asset": {"asset_id": "host-smoke-01"},
    }
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BROKERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    producer.send("logs.raw", key=f"{tenant_id}:{event_id}".encode(), value=event)
    producer.flush(10)
    producer.close()

    engine = create_engine(DATABASE_URL)
    deadline = time.time() + 30
    found = False
    while time.time() < deadline:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT 1 FROM ingested_events "
                    "WHERE tenant_id = :tenant_id AND event_id = :event_id"
                ),
                {"tenant_id": tenant_id, "event_id": event_id},
            ).first()
            if row is not None:
                found = True
                break
        time.sleep(1)
    assert found
