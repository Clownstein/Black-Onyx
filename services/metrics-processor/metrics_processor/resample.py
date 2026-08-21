from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.utcfromtimestamp(ts)
    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text).replace(tzinfo=None)


def extract_samples(event: dict[str, Any]) -> list[dict[str, Any]]:
    payload = event.get("payload") or event.get("extensions") or event
    occurred = event.get("occurred_at") or payload.get("timestamp")
    asset = event.get("asset") or {}
    asset_id = str(asset.get("asset_id") or payload.get("asset_id") or "unknown")
    tenant_id = str(event.get("tenant_id") or "default")

    metrics = payload.get("metrics")
    samples: list[dict[str, Any]] = []
    if isinstance(metrics, dict):
        for name, value in metrics.items():
            samples.append(
                {
                    "tenant_id": tenant_id,
                    "asset_id": asset_id,
                    "timestamp": _parse_ts(occurred),
                    "name": str(name),
                    "value": float(value),
                }
            )
    elif "name" in payload and "value" in payload:
        samples.append(
            {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "timestamp": _parse_ts(occurred or payload.get("timestamp")),
                "name": str(payload["name"]),
                "value": float(payload["value"]),
            }
        )
    else:
        raise ValueError("metrics payload missing metrics map or name/value")
    return samples


def resample_series(
    samples: list[dict[str, Any]],
    metric_names: list[str],
    *,
    interval_seconds: int = 60,
) -> dict[str, list[tuple[datetime, float | None, bool]]]:
    """
    Resample onto a fixed interval.
    Returns metric -> list of (ts, value|None, was_missing).
    Missing points are forward-filled when possible and marked missing=True.
    """
    if not samples:
        return {name: [] for name in metric_names}

    by_metric: dict[str, list[tuple[datetime, float]]] = {name: [] for name in metric_names}
    for sample in samples:
        name = sample["name"]
        if name not in by_metric:
            continue
        by_metric[name].append((sample["timestamp"], float(sample["value"])))

    all_ts = [s["timestamp"] for s in samples]
    start = min(all_ts).replace(second=0, microsecond=0)
    end = max(all_ts).replace(second=0, microsecond=0)
    if end < start:
        end = start

    grid: list[datetime] = []
    cursor = start
    while cursor <= end:
        grid.append(cursor)
        cursor += timedelta(seconds=interval_seconds)
    if not grid:
        grid = [start]

    out: dict[str, list[tuple[datetime, float | None, bool]]] = {}
    for name in metric_names:
        points = sorted(by_metric.get(name, []), key=lambda x: x[0])
        idx = 0
        last: float | None = None
        series: list[tuple[datetime, float | None, bool]] = []
        for ts in grid:
            while idx < len(points) and points[idx][0] <= ts + timedelta(seconds=interval_seconds / 2):
                last = points[idx][1]
                idx += 1
            # exact/near sample?
            present = any(abs((p[0] - ts).total_seconds()) <= interval_seconds / 2 for p in points)
            if present:
                # use nearest within bucket
                nearest = min(points, key=lambda p: abs((p[0] - ts).total_seconds()))
                series.append((ts, nearest[1], False))
                last = nearest[1]
            else:
                series.append((ts, last, True))  # forward-fill + missingness
        out[name] = series
    return out


def log_transform(name: str, value: float, heavy_tailed: set[str]) -> float:
    if name in heavy_tailed:
        return math.log1p(max(value, 0.0))
    return value
