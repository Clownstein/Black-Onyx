from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from host_state_processor.config import settings
from host_state_processor.heartbeat import (
    ExpectedAsset,
    HeartbeatMonitor,
    TelemetryGap,
    gap_to_finding,
    select_stale_assets,
    severity_for_gap,
)

NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)
ASSET = ExpectedAsset(tenant_id="tenant-a", asset_id="host-1", name="onyx-host")


def test_reporting_asset_is_not_stale() -> None:
    last_seen = {("tenant-a", "host-1"): NOW - timedelta(seconds=60)}
    gaps = select_stale_assets([ASSET], last_seen, NOW, 900, NOW - timedelta(hours=1))
    assert gaps == []


def test_silent_asset_is_stale() -> None:
    last_seen = {("tenant-a", "host-1"): NOW - timedelta(seconds=1800)}
    gaps = select_stale_assets([ASSET], last_seen, NOW, 900, NOW - timedelta(hours=1))
    assert len(gaps) == 1
    assert gaps[0].never_seen is False
    assert gaps[0].silent_seconds == pytest.approx(1800)


def test_never_seen_asset_is_stale_once_watched_long_enough() -> None:
    """An agent that never starts must still alert — that is the whole point."""
    gaps = select_stale_assets([ASSET], {}, NOW, 900, NOW - timedelta(hours=1))
    assert len(gaps) == 1
    assert gaps[0].never_seen is True


def test_never_seen_asset_is_quiet_right_after_restart() -> None:
    """Guard against a restart alerting on the entire fleet at once."""
    gaps = select_stale_assets([ASSET], {}, NOW, 900, NOW - timedelta(seconds=30))
    assert gaps == []


def test_severity_escalates_with_silence() -> None:
    assert severity_for_gap(1000, 900)[0] == "medium"
    assert severity_for_gap(2000, 900)[0] == "medium"
    assert severity_for_gap(4000, 900)[0] == "high"
    # Score rises monotonically with the gap.
    assert severity_for_gap(4000, 900)[1] > severity_for_gap(1000, 900)[1]


def test_gap_finding_shape_and_stable_fingerprint() -> None:
    gap = TelemetryGap(asset=ASSET, silent_seconds=1800, never_seen=False)
    finding = gap_to_finding(gap, NOW, 900)
    assert finding["finding_type"] == "host_state_telemetry_gap"
    assert finding["asset_id"] == "host-1"
    assert finding["tenant_id"] == "tenant-a"
    assert finding["fingerprint"] == "host-state:telemetry-gap:host-1"
    # No speculative ATT&CK mapping for an ambiguous signal.
    assert finding["mitre_techniques"] == []
    assert finding["context"]["never_seen"] is False
    assert "30.0m" in finding["contributors"][0]["summary"]

    # Fingerprint is stable across sweeps so incidents correlate rather than pile up.
    later = gap_to_finding(
        TelemetryGap(asset=ASSET, silent_seconds=3600, never_seen=False), NOW, 900
    )
    assert later["fingerprint"] == finding["fingerprint"]
    assert later["finding_id"] != finding["finding_id"]


def _monitor(published: list, expected: list[ExpectedAsset], last_seen: dict) -> HeartbeatMonitor:
    monitor = HeartbeatMonitor(
        last_seen_provider=lambda: last_seen,
        publish=published.append,
        expected_loader=lambda _tenant: expected,
    )
    monitor.started_at = NOW - timedelta(hours=1)
    return monitor


def test_sweep_publishes_once_then_rearms(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "heartbeat_tenant_ids", "tenant-a")
    monkeypatch.setattr(settings, "stale_after_seconds", 900)
    published: list = []
    last_seen = {("tenant-a", "host-1"): NOW - timedelta(seconds=1800)}
    monitor = _monitor(published, [ASSET], last_seen)

    assert len(monitor.sweep(now=NOW)) == 1
    # A sustained gap must not re-alert on every sweep.
    assert monitor.sweep(now=NOW + timedelta(seconds=60)) == []
    assert len(published) == 1
    assert monitor.gaps_published == 1

    # Asset recovers -> monitor re-arms and alerts again on the next gap.
    recovered = NOW + timedelta(seconds=120)
    last_seen[("tenant-a", "host-1")] = recovered
    assert monitor.sweep(now=recovered) == []
    last_seen[("tenant-a", "host-1")] = recovered - timedelta(seconds=1800)
    assert len(monitor.sweep(now=recovered + timedelta(seconds=60))) == 1
    assert monitor.gaps_published == 2


def test_sweep_survives_registry_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    """A registry outage must not kill the monitor thread."""
    import httpx

    monkeypatch.setattr(settings, "heartbeat_tenant_ids", "tenant-a")

    def boom(_tenant: str) -> list[ExpectedAsset]:
        raise httpx.ConnectError("registry down")

    monitor = HeartbeatMonitor(
        last_seen_provider=dict, publish=lambda _f: None, expected_loader=boom
    )
    assert monitor.sweep(now=NOW) == []
    assert monitor.errors == 1
    assert "registry down" in (monitor.last_error or "")


def test_multiple_tenants_are_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "heartbeat_tenant_ids", "tenant-a, tenant-b")
    monkeypatch.setattr(settings, "stale_after_seconds", 900)
    published: list = []
    per_tenant = {
        "tenant-a": [ExpectedAsset("tenant-a", "host-a", "a")],
        "tenant-b": [ExpectedAsset("tenant-b", "host-b", "b")],
    }
    monitor = HeartbeatMonitor(
        last_seen_provider=dict,
        publish=published.append,
        expected_loader=lambda tenant: per_tenant[tenant],
    )
    monitor.started_at = NOW - timedelta(hours=1)
    monitor.sweep(now=NOW)
    assert {f["asset_id"] for f in published} == {"host-a", "host-b"}
