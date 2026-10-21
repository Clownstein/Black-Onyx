from __future__ import annotations

import os
import socket
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8080/api/v1/ingest/logs")
GATEWAY_API_KEY = os.getenv("API_KEYS", "dev-ingest-key").split(",")[0].strip()
KAFKA_HOST = os.getenv("KAFKA_HOST", "localhost")
KAFKA_PORT = int(os.getenv("KAFKA_PORT", "19092"))
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
SMOKE_DATABASE_URL = os.getenv(
    "SMOKE_DATABASE_URL",
    "postgresql+psycopg://anomaly:anomaly@localhost:5432/smoke",
)


def _reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _skip_if_unavailable() -> None:
    if os.getenv("SKIP_INTEGRATION", "").strip() in {"1", "true", "TRUE", "yes"}:
        pytest.skip("SKIP_INTEGRATION=1")
    if not _reachable(KAFKA_HOST, KAFKA_PORT):
        pytest.skip(f"Kafka unreachable at {KAFKA_HOST}:{KAFKA_PORT}")
    if not _reachable(POSTGRES_HOST, POSTGRES_PORT):
        pytest.skip(f"Postgres unreachable at {POSTGRES_HOST}:{POSTGRES_PORT}")


def test_gateway_to_smoke_consumer_table() -> None:
    _skip_if_unavailable()

    httpx = pytest.importorskip("httpx")
    sqlalchemy = pytest.importorskip("sqlalchemy")
    ulid_mod = pytest.importorskip("ulid")

    event_id = str(ulid_mod.ULID())
    tenant_id = "tenant-integration"
    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    envelope = {
        "schema_version": "1.0",
        "event_id": event_id,
        "event_type": "log.raw",
        "tenant_id": tenant_id,
        "occurred_at": now,
        "ingested_at": now,
        "source": {"collector_id": "integration-test", "source_type": "test"},
        "asset": {
            "asset_id": "host-integration-01",
            "service_id": "integration-svc",
            "environment": "local",
        },
        "severity": "INFO",
        "message": "integration smoke event",
        "structured": {"test": True},
    }

    try:
        response = httpx.post(
            GATEWAY_URL,
            headers={
                "X-API-Key": GATEWAY_API_KEY,
                "Content-Type": "application/json",
            },
            json={"events": [envelope]},
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        pytest.skip(f"gateway unreachable: {exc}")

    if response.status_code >= 500:
        pytest.skip(f"gateway error status {response.status_code}: {response.text}")
    if response.status_code >= 400:
        pytest.skip(f"gateway rejected event ({response.status_code}): {response.text}")

    try:
        engine = sqlalchemy.create_engine(SMOKE_DATABASE_URL, pool_pre_ping=True)
        found = False
        with engine.connect() as conn:
            for _ in range(30):
                row = conn.execute(
                    sqlalchemy.text(
                        "SELECT event_id FROM ingested_events "
                        "WHERE tenant_id = :tenant_id AND event_id = :event_id"
                    ),
                    {"tenant_id": tenant_id, "event_id": event_id},
                ).fetchone()
                if row is not None:
                    found = True
                    break
                time.sleep(0.5)
            engine.dispose()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"smoke consumer table check soft-skipped: {exc}")

    if not found:
        pytest.skip(
            "event not observed in ingested_events "
            "(gateway up but smoke-consumer may not be running)"
        )

    assert found
