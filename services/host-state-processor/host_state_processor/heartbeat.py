"""Telemetry-gap detection: alert when an enrolled asset stops reporting.

A silent collector and a genuinely quiet host look identical on the wire, so
staleness is derived from the *enrolled* asset list in asset-registry rather than
from observed traffic alone. That way an agent that never starts at all is caught
too — the asset exists (enrollment happens at install), it just never reports.

Deliberately emits no MITRE technique. "Agent went quiet" is ambiguous (host
powered off, maintenance window, network partition, or genuine tampering), and
guessing T1562 here would pollute ATT&CK coverage analytics with speculative
mappings. Analysts triage the gap and attribute it themselves.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

import httpx
from black_onyx_contracts import Finding, FindingContributor, FindingWindow
from ulid import ULID

from host_state_processor.config import settings

logger = logging.getLogger(__name__)

MODEL_NAME = "host-state-heartbeat"
MODEL_VERSION = "1.0.0"
FEATURE_VERSION = "host-state.heartbeat.v1"
FINDING_TYPE = "host_state_telemetry_gap"

AssetKey = tuple[str, str]


@dataclass(frozen=True)
class ExpectedAsset:
    """An asset the registry says should be reporting."""

    tenant_id: str
    asset_id: str
    name: str
    service_id: str | None = None


@dataclass(frozen=True)
class TelemetryGap:
    asset: ExpectedAsset
    silent_seconds: float
    never_seen: bool


def severity_for_gap(silent_seconds: float, stale_after: float) -> tuple[str, float]:
    """Escalate with how long the asset has been silent.

    One threshold crossing is `medium`; sustained silence (4x) is `high`. Nothing
    here reaches `critical` on its own — correlation with other signals does that.
    """
    if stale_after <= 0:
        return "medium", 0.5
    ratio = silent_seconds / stale_after
    if ratio >= 4.0:
        return "high", 0.8
    if ratio >= 2.0:
        return "medium", 0.65
    return "medium", 0.5


def select_stale_assets(
    expected: Iterable[ExpectedAsset],
    last_seen: dict[AssetKey, datetime],
    now: datetime,
    stale_after_seconds: float,
    since: datetime,
) -> list[TelemetryGap]:
    """Return assets that should have reported by now but have not.

    `since` is when this processor started watching. An asset we have never seen
    is only considered stale once we have been watching longer than the staleness
    window — otherwise every restart would alert on the entire fleet at once.
    """
    cutoff = timedelta(seconds=stale_after_seconds)
    gaps: list[TelemetryGap] = []
    for asset in expected:
        key = (asset.tenant_id, asset.asset_id)
        seen_at = last_seen.get(key)
        never_seen = seen_at is None
        effective = seen_at if seen_at is not None else since
        silent = now - effective
        if silent > cutoff:
            gaps.append(
                TelemetryGap(
                    asset=asset,
                    silent_seconds=silent.total_seconds(),
                    never_seen=never_seen,
                )
            )
    return gaps


def gap_to_finding(gap: TelemetryGap, now: datetime, stale_after_seconds: float) -> dict[str, Any]:
    """Build a Finding for a telemetry gap, shaped like the rule findings."""
    severity, score = severity_for_gap(gap.silent_seconds, stale_after_seconds)
    minutes = round(gap.silent_seconds / 60.0, 1)
    if gap.never_seen:
        summary = (
            f"{gap.asset.name} is enrolled but has never reported host-state telemetry "
            f"({minutes}m since monitoring began)"
        )
    else:
        summary = f"{gap.asset.name} has not reported host-state telemetry for {minutes}m"

    finding = Finding(
        finding_id=str(ULID()),
        tenant_id=gap.asset.tenant_id,
        finding_type=FINDING_TYPE,
        asset_id=gap.asset.asset_id,
        service_id=gap.asset.service_id,
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
        raw_score=score,
        calibrated_score=score,
        severity_hint=severity,  # type: ignore[arg-type]
        window=FindingWindow(start=now - timedelta(seconds=gap.silent_seconds), end=now),
        contributors=[
            FindingContributor(
                type="telemetry_gap",
                contribution=score,
                summary=summary,
            )
        ],
        evidence_refs=[],
        context={
            "detector": "telemetry_gap",
            "silent_seconds": round(gap.silent_seconds, 1),
            "stale_after_seconds": stale_after_seconds,
            "never_seen": gap.never_seen,
            "asset_name": gap.asset.name,
        },
        # Stable so repeated gaps for one asset correlate into a single incident
        # rather than a new one per sweep.
        fingerprint=f"host-state:telemetry-gap:{gap.asset.asset_id}",
        category=["host_state", "telemetry_health"],
        occurred_at=now,
        mitre_techniques=[],
        mitre_confidence=0.0,
    )
    return finding.model_dump(mode="json")


def fetch_expected_assets(tenant_id: str) -> list[ExpectedAsset]:
    """Read active assets for a tenant from asset-registry (service-key auth)."""
    headers = {"X-Tenant-Id": tenant_id}
    if settings.asset_registry_service_key:
        headers["X-Service-Key"] = settings.asset_registry_service_key
    url = f"{settings.asset_registry_url.rstrip('/')}/api/v1/assets"
    with httpx.Client(timeout=settings.heartbeat_timeout_seconds) as client:
        response = client.get(url, headers=headers, params={"active": "true"})
        response.raise_for_status()
    body = response.json()
    if not isinstance(body, list):
        raise ValueError("asset-registry returned an invalid asset list")
    assets: list[ExpectedAsset] = []
    for item in body:
        if not isinstance(item, dict):
            continue
        asset_id = item.get("asset_id")
        if not asset_id:
            continue
        assets.append(
            ExpectedAsset(
                tenant_id=str(item.get("tenant_id") or tenant_id),
                asset_id=str(asset_id),
                name=str(item.get("name") or asset_id),
                service_id=item.get("service_id"),
            )
        )
    return assets


class HeartbeatMonitor:
    """Periodically compares enrolled assets against observed telemetry."""

    def __init__(
        self,
        last_seen_provider: Callable[[], dict[AssetKey, datetime]],
        publish: Callable[[dict[str, Any]], None],
        expected_loader: Callable[[str], list[ExpectedAsset]] | None = None,
    ) -> None:
        self._last_seen_provider = last_seen_provider
        self._publish = publish
        self._expected_loader = expected_loader or fetch_expected_assets
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Assets already alerted on, so a sustained gap emits once rather than
        # once per sweep. Cleared when the asset reports again (re-arm).
        self._alerted: set[AssetKey] = set()
        self.started_at = datetime.now(tz=timezone.utc)
        self.sweeps = 0
        self.gaps_published = 0
        self.errors = 0
        self.last_error: str | None = None

    def tenant_ids(self) -> list[str]:
        return [t.strip() for t in settings.heartbeat_tenant_ids.split(",") if t.strip()]

    def sweep(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Run one staleness pass and return the findings published."""
        moment = now or datetime.now(tz=timezone.utc)
        last_seen = self._last_seen_provider()
        published: list[dict[str, Any]] = []
        for tenant_id in self.tenant_ids():
            try:
                expected = self._expected_loader(tenant_id)
            except (httpx.HTTPError, ValueError) as exc:
                self.errors += 1
                self.last_error = f"expected-asset load failed for {tenant_id}: {exc}"
                logger.warning("heartbeat: %s", self.last_error)
                continue

            gaps = select_stale_assets(
                expected,
                last_seen,
                moment,
                settings.stale_after_seconds,
                self.started_at,
            )
            stale_keys = {(g.asset.tenant_id, g.asset.asset_id) for g in gaps}

            # Re-arm assets that recovered so a future gap alerts again.
            healthy = {
                (a.tenant_id, a.asset_id) for a in expected
            } - stale_keys
            self._alerted -= healthy

            for gap in gaps:
                key = (gap.asset.tenant_id, gap.asset.asset_id)
                if key in self._alerted:
                    continue
                finding = gap_to_finding(gap, moment, settings.stale_after_seconds)
                try:
                    self._publish(finding)
                except Exception as exc:  # noqa: BLE001
                    self.errors += 1
                    self.last_error = f"publish failed for {gap.asset.asset_id}: {exc}"
                    logger.exception("heartbeat publish failed")
                    continue
                self._alerted.add(key)
                self.gaps_published += 1
                published.append(finding)
        self.sweeps += 1
        return published

    def start(self) -> None:
        if not settings.enable_heartbeat:
            return
        self._thread = threading.Thread(
            target=self._run, name="host-state-heartbeat", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        # Wait one interval before the first sweep so a cold start has a chance
        # to observe traffic before judging anything stale.
        while not self._stop.wait(settings.heartbeat_interval_seconds):
            try:
                self.sweep()
            except Exception as exc:  # noqa: BLE001
                self.errors += 1
                self.last_error = str(exc)
                logger.exception("heartbeat sweep failed")
