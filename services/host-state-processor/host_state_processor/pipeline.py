from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from black_onyx_contracts import Finding, FindingContributor, FindingWindow
from ulid import ULID

from host_state_processor.config import settings
from host_state_processor.normalize import normalize_host_state_event
from host_state_processor.rules import run_rules

FEATURE_VERSION = "host-state.features.v1"
MODEL_NAME = "host-state-rules"
MODEL_VERSION = "1.0.0"


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(tz=timezone.utc)
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _severity_hint(severity: str | None, score: float) -> str:
    if severity in {"low", "medium", "high", "critical"}:
        return severity
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def detection_to_finding(
    event: dict[str, Any],
    detection: dict[str, Any],
) -> dict[str, Any]:
    """Build a Finding-shaped dict for a rule hit (Phase 1 without a model)."""
    occurred = _parse_iso(str(event.get("occurred_at") or ""))
    score = float(detection.get("score") or 0.0)
    score = max(0.0, min(1.0, score))
    severity = _severity_hint(detection.get("severity"), score)
    techniques = list(detection.get("mitre_techniques") or [])
    detector = str(detection.get("detector") or "host_state_rule")
    finding = Finding(
        finding_id=str(ULID()),
        tenant_id=str(event.get("tenant_id") or "default"),
        finding_type="host_state_rule",
        asset_id=str(event.get("asset_id") or "unknown"),
        service_id=event.get("service_id"),
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
        raw_score=score,
        calibrated_score=score,
        severity_hint=severity,  # type: ignore[arg-type]
        window=FindingWindow(start=occurred, end=occurred),
        contributors=[
            FindingContributor(
                type=detector,
                contribution=score,
                summary=f"host-state rule hit: {detector}",
            )
        ],
        evidence_refs=[],
        context={
            "detector": detector,
            "evidence": detection.get("evidence") or {},
            "event_type": event.get("event_type"),
            "hostname": event.get("hostname"),
            "os_family": event.get("os_family"),
        },
        fingerprint=f"host-state:{detector}:{event.get('asset_id')}",
        category=["host_state"],
        occurred_at=occurred,
        mitre_techniques=techniques,
        mitre_confidence=score,
    )
    return finding.model_dump(mode="json")


class HostStatePipeline:
    """Normalize host-state events, run rules, emit features (+ optional findings)."""

    def __init__(self) -> None:
        self.known_listening_ports: dict[tuple[str, str], set[int]] = {}
        self.processed = 0
        self.published = 0
        self.findings_published = 0
        self.errors = 0
        # Wall-clock arrival time per asset, read by the heartbeat monitor on a
        # separate thread. Deliberately *not* the event's occurred_at: telemetry
        # gaps are about when we last received data, and host clock skew (which
        # collectors/README.md warns about) would otherwise fake staleness.
        self._last_seen: dict[tuple[str, str], datetime] = {}
        self._last_seen_lock = threading.Lock()

    def last_seen_snapshot(self) -> dict[tuple[str, str], datetime]:
        with self._last_seen_lock:
            return dict(self._last_seen)

    def _mark_seen(self, key: tuple[str, str], moment: datetime) -> None:
        with self._last_seen_lock:
            self._last_seen[key] = moment

    def process_events(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        by_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
        detections_by_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
        findings: list[dict[str, Any]] = []

        for event in events:
            try:
                normalized = normalize_host_state_event(event)
                self.processed += 1
            except Exception:
                self.errors += 1
                continue

            asset_id = str(normalized.get("asset_id") or "unknown")
            tenant_id = str(normalized.get("tenant_id") or "default")
            key = (tenant_id, asset_id)
            self._mark_seen(key, datetime.now(tz=timezone.utc))
            known = self.known_listening_ports.setdefault(key, set())
            detections = run_rules(normalized, known_listening_ports=known)

            # Update known listening ports after novelty check.
            socket = normalized.get("socket") or {}
            if socket.get("local_port") is not None:
                state = str(socket.get("state") or "").lower()
                if not state or state in {"listen", "listening", "listenq"}:
                    try:
                        known.add(int(socket["local_port"]))
                    except (TypeError, ValueError):
                        pass

            by_asset.setdefault(key, []).append(normalized)
            if detections:
                detections_by_asset.setdefault(key, []).extend(detections)
                if settings.publish_findings:
                    for detection in detections:
                        findings.append(detection_to_finding(normalized, detection))
                        self.findings_published += 1

        features: list[dict[str, Any]] = []
        for (tenant_id, asset_id), process_events in by_asset.items():
            times = [_parse_iso(str(e.get("occurred_at") or "")) for e in process_events]
            window_start = min(times)
            window_end = max(times)
            service_id = next(
                (e.get("service_id") for e in process_events if e.get("service_id")),
                None,
            )
            record = {
                "event_type": "host_state.features",
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "service_id": service_id,
                "window_start": window_start.isoformat().replace("+00:00", "Z"),
                "window_end": window_end.isoformat().replace("+00:00", "Z"),
                "feature_version": FEATURE_VERSION,
                "process_events": process_events,
                "detections": detections_by_asset.get((tenant_id, asset_id), []),
                "event_count": len(process_events),
            }
            features.append(record)
            self.published += 1

        return features, findings
