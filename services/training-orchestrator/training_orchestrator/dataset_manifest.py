"""Dataset manifest writer for training jobs."""

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
    source_query: str | None,
    time_range_start: str | None,
    time_range_end: str | None,
    excluded_incidents: list[str] | None = None,
    event_count: int = 0,
    sequence_count: int = 0,
    created_by: str,
    content_payload: bytes | None = None,
    content_hash: str | None = None,
) -> dict[str, Any]:
    if content_hash is None:
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
    if not content_hash.startswith("sha256:") or len(content_hash) != 71:
        raise ValueError("content_hash must be a sha256 digest")
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


def inspect_reviewed_dataset(path: Path, *, tenant_id: str, model_type: str) -> dict[str, Any]:
    """Count and describe the actual reviewed JSONL rows used for training."""
    sample_count = 0
    event_count = 0
    features: set[str] = set()
    expected_type = {"log": "logs.features", "network": "network.features",
                     "metrics": "metrics.features", "code": "code.features"}.get(model_type)
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid reviewed dataset JSON at line {line_number}") from exc
            if not isinstance(row, dict) or row.get("tenant_id") != tenant_id:
                raise ValueError(f"reviewed dataset tenant mismatch at line {line_number}")
            if expected_type and row.get("event_type") != expected_type:
                raise ValueError(f"reviewed dataset modality mismatch at line {line_number}")
            sample_count += 1
            if model_type == "log":
                events = row.get("events")
                if not isinstance(events, list) or not events:
                    raise ValueError(f"reviewed log sequence is empty at line {line_number}")
                event_count += len(events)
                features.update(f"events.{key}" for item in events if isinstance(item, dict) for key in item)
            elif model_type == "network":
                flows = row.get("flows")
                if not isinstance(flows, list) or not flows:
                    raise ValueError(f"reviewed network flows are empty at line {line_number}")
                event_count += len(flows)
                features.update(f"flows.{key}" for item in flows if isinstance(item, dict) for key in item)
                features.update(f"aggregates.{key}" for key in row.get("aggregates", {}))
            elif model_type == "metrics":
                values = row.get("values")
                if not isinstance(values, dict) or not values:
                    raise ValueError(f"reviewed metrics values are empty at line {line_number}")
                event_count += 1
                features.update(f"values.{key}" for key in values)
            elif model_type == "code":
                event_count += 1
                features.update(f"diff_stats.{key}" for key in row.get("diff_stats", {}))
                features.update(f"text_features.{key}" for key in row.get("text_features", {}))
            else:
                raise ValueError("unsupported reviewed dataset modality")
    if not sample_count or not features:
        raise ValueError("reviewed dataset has no samples or features")
    return {"event_count": event_count, "sequence_count": sample_count,
            "feature_schema": {"features": sorted(features), "source": "reviewed_dataset"}}
