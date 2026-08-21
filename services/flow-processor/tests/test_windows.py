from datetime import datetime, timedelta

from flow_processor.windows import build_windows


def test_build_windows_stride_and_min():
    flows = []
    for i in range(20):
        flows.append(
            {
                "occurred_at": (datetime(2024, 1, 1) + timedelta(seconds=i)).isoformat(),
                "asset_id": "a1",
                "tenant_id": "t1",
                "peer_hash": f"p{i}",
                "dst_port": 80,
                "bytes": 100,
                "packets": 1,
                "failed": False,
                "dst_is_external": False,
                "src_is_external": False,
                "protocol": "tcp",
            }
        )
    windows = build_windows(flows, max_events=256, stride_events=64, minimum_events=4)
    assert len(windows) >= 1
    assert windows[0]["event_count"] >= 4
    assert "aggregates" in windows[0]
