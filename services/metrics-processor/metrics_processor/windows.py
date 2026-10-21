from __future__ import annotations

from datetime import datetime
from typing import Any

from metrics_processor.profile import HEAVY_TAILED
from metrics_processor.resample import log_transform


def build_metric_windows(
    series: dict[str, list[tuple[datetime, float | None, bool]]],
    *,
    asset_id: str,
    tenant_id: str,
    profile: str,
    window_length: int = 60,
    stride: int = 5,
    max_missing_fraction: float = 0.10,
) -> list[dict[str, Any]]:
    if not series:
        return []
    metric_names = list(series.keys())
    length = min(len(series[name]) for name in metric_names)
    if length < window_length:
        # Still emit a shorter window for demos/tests when enough points exist.
        if length < 4:
            return []
        window_length = length

    windows: list[dict[str, Any]] = []
    start = 0
    while start + window_length <= length:
        values: dict[str, list[float]] = {}
        missing: dict[str, list[float]] = {}
        missing_count = 0
        total = window_length * len(metric_names)
        for name in metric_names:
            chunk = series[name][start : start + window_length]
            vals: list[float] = []
            miss: list[float] = []
            for _ts, value, was_missing in chunk:
                if value is None:
                    vals.append(0.0)
                    miss.append(1.0)
                    missing_count += 1
                else:
                    vals.append(log_transform(name, value, HEAVY_TAILED))
                    miss.append(1.0 if was_missing else 0.0)
                    if was_missing:
                        missing_count += 1
            values[name] = vals
            missing[name] = miss

        frac = missing_count / max(total, 1)
        if frac > max_missing_fraction:
            start += stride
            continue

        t0 = series[metric_names[0]][start][0]
        t1 = series[metric_names[0]][start + window_length - 1][0]
        windows.append(
            {
                "schema_version": "1.0",
                "event_type": "metrics.features",
                "feature_version": "metrics.features.v1",
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "profile": profile,
                "window_start": t0.isoformat(),
                "window_end": t1.isoformat(),
                "window_length": window_length,
                "stride": stride,
                "missing_fraction": round(frac, 4),
                "values": values,
                "missingness": missing,
                "time_features": {
                    "hour_of_day": t0.hour,
                    "day_of_week": t0.weekday(),
                },
            }
        )
        start += stride
    return windows
