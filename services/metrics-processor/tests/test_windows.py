from datetime import datetime, timedelta

from metrics_processor.profile import WEB_SERVICE_V1_METRICS
from metrics_processor.windows import build_metric_windows


def test_build_windows_length_and_stride():
    series = {}
    base = datetime(2024, 1, 1)
    for name in WEB_SERVICE_V1_METRICS:
        series[name] = [
            (base + timedelta(minutes=i), float(i % 7), False) for i in range(20)
        ]
    windows = build_metric_windows(
        series,
        asset_id="web-1",
        tenant_id="t1",
        profile="web_service_v1",
        window_length=10,
        stride=5,
        max_missing_fraction=0.5,
    )
    assert len(windows) >= 2
    assert windows[0]["window_length"] == 10
    assert "missingness" in windows[0]
    assert set(windows[0]["values"]) == set(WEB_SERVICE_V1_METRICS)
