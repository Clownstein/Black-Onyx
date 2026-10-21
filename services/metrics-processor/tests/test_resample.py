from datetime import datetime, timedelta

from metrics_processor.profile import WEB_SERVICE_V1_METRICS
from metrics_processor.resample import extract_samples, resample_series


def test_extract_and_resample_marks_missing():
    base = datetime(2024, 1, 1, 0, 0, 0)
    events = []
    for i in range(5):
        metrics = {name: float(i) for name in WEB_SERVICE_V1_METRICS}
        # drop one metric occasionally
        if i == 2:
            del metrics["queue.depth"]
        events.append(
            {
                "tenant_id": "t1",
                "occurred_at": (base + timedelta(minutes=i)).isoformat() + "Z",
                "asset": {"asset_id": "web-1"},
                "payload": {"metrics": metrics},
            }
        )

    samples = []
    for event in events:
        samples.extend(extract_samples(event))

    series = resample_series(samples, WEB_SERVICE_V1_METRICS, interval_seconds=60)
    assert len(series["cpu.utilization"]) == 5
    # forward-filled queue.depth at minute 2 should be marked missing
    q = series["queue.depth"]
    assert any(was_missing for _ts, _v, was_missing in q)
