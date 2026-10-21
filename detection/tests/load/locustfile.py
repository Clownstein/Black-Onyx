"""Basic ingest load test against the Go gateway."""

from __future__ import annotations

import time
from uuid import uuid4

from locust import HttpUser, between, task


def _ulid_like() -> str:
    # Not a true ULID; gateway may accept opaque IDs depending on validator config.
    return "01J" + uuid4().hex[:23].upper()


class IngestUser(HttpUser):
    wait_time = between(0.01, 0.05)

    @task
    def ingest_logs(self) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "events": [
                {
                    "schema_version": "1.0",
                    "event_id": _ulid_like(),
                    "event_type": "log.raw",
                    "tenant_id": "tenant-load",
                    "occurred_at": now,
                    "ingested_at": now,
                    "source": {"collector_id": "load", "source_type": "locust"},
                    "asset": {
                        "asset_id": "host-load-1",
                        "service_id": "payments-api",
                        "environment": "load",
                    },
                    "severity": "INFO",
                    "message": "health ok",
                }
            ]
        }
        self.client.post(
            "/api/v1/ingest/logs",
            json=payload,
            headers={"X-API-Key": "dev-ingest-key"},
            name="ingest_logs",
        )
