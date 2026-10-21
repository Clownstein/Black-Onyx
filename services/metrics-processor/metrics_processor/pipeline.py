from __future__ import annotations

from collections import defaultdict
from typing import Any

from metrics_processor.config import settings
from metrics_processor.profile import profile_metric_names
from metrics_processor.resample import extract_samples, resample_series
from metrics_processor.windows import build_metric_windows


class MetricsPipeline:
    def __init__(self) -> None:
        self.processed = 0
        self.published = 0
        self.errors = 0

    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        samples_by_asset: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            try:
                for sample in extract_samples(event):
                    key = (sample["tenant_id"], sample["asset_id"])
                    samples_by_asset[key].append(sample)
                self.processed += 1
            except Exception:
                self.errors += 1

        metric_names = profile_metric_names(settings.profile)
        features: list[dict[str, Any]] = []
        for (tenant_id, asset_id), samples in samples_by_asset.items():
            series = resample_series(
                samples,
                metric_names,
                interval_seconds=settings.sample_interval_seconds,
            )
            windows = build_metric_windows(
                series,
                asset_id=asset_id,
                tenant_id=tenant_id,
                profile=settings.profile,
                window_length=settings.window_length,
                stride=settings.stride,
                max_missing_fraction=settings.max_missing_fraction,
            )
            features.extend(windows)
            self.published += len(windows)
        return features
