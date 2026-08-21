"""Enroll the Black Onyx host itself as an asset, so telemetry has an owner.

Runs as a one-shot on `up`. Enrollment must happen *before* telemetry arrives:
the heartbeat monitor in host-state-processor derives "should be reporting" from
the enrolled-asset list, so an unenrolled host is invisible rather than alerting.

Idempotent by construction — uses `PUT /api/v1/assets/{asset_id}`, which upserts,
so re-running on every `up` is safe (`POST` deliberately still 409s).
"""

from __future__ import annotations

import os
import sys
import time

import httpx

REGISTRY_URL = os.environ.get("ENROLL_REGISTRY_URL", "http://asset-registry:8081")
TENANT_ID = os.environ.get("ENROLL_TENANT_ID", "tenant-demo")
ASSET_ID = os.environ.get("ENROLL_ASSET_ID", "black-onyx-self")
ASSET_NAME = os.environ.get("ENROLL_ASSET_NAME", ASSET_ID)
ENVIRONMENT = os.environ.get("ENROLL_ENVIRONMENT", "production")
CRITICALITY = float(os.environ.get("ENROLL_CRITICALITY", "0.8"))
SERVICE_KEY = os.environ.get("ENROLL_SERVICE_KEY", "")
TIMEOUT = float(os.environ.get("ENROLL_TIMEOUT_SECONDS", "5"))
ATTEMPTS = int(os.environ.get("ENROLL_ATTEMPTS", "30"))
BACKOFF = float(os.environ.get("ENROLL_BACKOFF_SECONDS", "2"))


def enroll() -> dict:
    url = f"{REGISTRY_URL.rstrip('/')}/api/v1/assets/{ASSET_ID}"
    headers = {"X-Tenant-Id": TENANT_ID}
    if SERVICE_KEY:
        headers["X-Service-Key"] = SERVICE_KEY
    body = {
        "asset_type": "host",
        "name": ASSET_NAME,
        "environment": ENVIRONMENT,
        "criticality": CRITICALITY,
        "tags": {"role": "black-onyx-self-monitor", "managed_by": "compose"},
        "active": True,
    }

    last_error: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                response = client.put(url, headers=headers, json=body)
            if response.status_code in (200, 201):
                return {"status": response.status_code, "body": response.json()}
            # 4xx other than transient startup errors will not fix themselves.
            if 400 <= response.status_code < 500 and response.status_code != 404:
                raise RuntimeError(
                    f"enrollment rejected ({response.status_code}): {response.text}"
                )
            last_error = RuntimeError(
                f"unexpected status {response.status_code}: {response.text}"
            )
        except httpx.HTTPError as exc:
            last_error = exc
        print(
            f"[enroll] attempt {attempt}/{ATTEMPTS} not ready ({last_error}); retrying",
            flush=True,
        )
        time.sleep(BACKOFF)

    raise SystemExit(f"[enroll] failed after {ATTEMPTS} attempts: {last_error}")


if __name__ == "__main__":
    result = enroll()
    verb = "created" if result["status"] == 201 else "updated"
    print(f"[enroll] {verb} asset {ASSET_ID!r} in tenant {TENANT_ID!r}", flush=True)
    sys.exit(0)
