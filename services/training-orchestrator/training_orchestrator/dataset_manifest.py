"""Dataset manifest writer matching platform §13.2."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_dataset_manifest(
    *,
    dataset_id: str,
    tenant_id: str,
    model_type: str,
    schema_version: str = "1.2",
    feature_version: str = "3.0",
    source_query: str,
    time_range_start: str,
    time_range_end: str,
    excluded_incidents: list[str] | None = None,
    event_count: int = 0,
    sequence_count: int = 0,
    created_by: str,
    content_payload: bytes | None = None,
) -> dict[str, Any]:
    payload = content_payload or json.dumps(
        {
            "dataset_id": dataset_id,
            "tenant_id": tenant_id,
            "source_query": source_query,
            "time_range": {"start": time_range_start, "end": time_range_end},
            "excluded_incidents": excluded_incidents or [],
        },
        sort_keys=True,
    ).encode("utf-8")
    content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    return {
        "dataset_id": dataset_id,
        "tenant_id": tenant_id,
        "model_type": model_type,
        "schema_version": schema_version,
        "feature_version": feature_version,
        "source_query": source_query,
        "time_range": {
            "start": time_range_start,
            "end": time_range_end,
        },
        "excluded_incidents": list(excluded_incidents or []),
        "event_count": event_count,
        "sequence_count": sequence_count,
        "content_hash": content_hash,
        "created_by": created_by,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def write_dataset_manifest(path: Path, manifest: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
