from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from black_onyx_contracts import Finding, FindingContributor, FindingWindow
from ulid import ULID

from firewall_processor.config import settings
from firewall_processor.detectors import run_detectors
from firewall_processor.normalize import normalize_firewall_event

FEATURE_VERSION = "firewall.features.v1"
MODEL_NAME = "firewall-rules"
MODEL_VERSION = "1.0.0"


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(tz=timezone.utc)
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def detection_to_finding(detection: dict[str, Any]) -> dict[str, Any]:
    occurred = _parse_iso(str(detection.get("occurred_at") or ""))
    score = float(detection.get("score") or 0.0)
    score = max(0.0, min(1.0, score))
    severity = _severity_hint(detection.get("severity"), score)
    detector = str(detection.get("detector") or "firewall_rule")
    techniques = list(detection.get("mitre_techniques") or [])
    tactics = list(detection.get("mitre_tactics") or [])
    finding = Finding(
        finding_id=str(ULID()),
        tenant_id=str(detection.get("tenant_id") or "default"),
        finding_type="firewall_rule",
        asset_id=str(detection.get("asset_id") or "unknown"),
        service_id=detection.get("service_id"),
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
                summary=f"firewall rule hit: {detector}",
            )
        ],
        evidence_refs=[],
        context={
            "detector": detector,
            "evidence": detection.get("evidence") or {},
        },
        fingerprint=f"firewall:{detector}:{detection.get('asset_id')}:{detection.get('evidence', {}).get('src_ip') or detection.get('evidence', {}).get('rule_id')}",
        category=["firewall"],
        occurred_at=occurred,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        mitre_confidence=score,
    )
    return finding.model_dump(mode="json")


class FirewallPipeline:
    """Normalize firewall events, run detectors, emit features (+ findings)."""

    def __init__(self) -> None:
        self.processed = 0
        self.published = 0
        self.findings_published = 0
        self.errors = 0

    def process_events(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        normalized: list[dict[str, Any]] = []
        for event in events:
            try:
                normalized.append(normalize_firewall_event(event))
                self.processed += 1
            except Exception:
                self.errors += 1

        detections = run_detectors(normalized)
        findings: list[dict[str, Any]] = []
        if settings.publish_findings:
            for detection in detections:
                findings.append(detection_to_finding(detection))
                self.findings_published += 1

        by_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in normalized:
            key = (str(row.get("tenant_id") or "default"), str(row.get("asset_id") or "unknown"))
            by_asset.setdefault(key, []).append(row)

        detections_by_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for detection in detections:
            key = (
                str(detection.get("tenant_id") or "default"),
                str(detection.get("asset_id") or "unknown"),
            )
            detections_by_asset.setdefault(key, []).append(detection)

        features: list[dict[str, Any]] = []
        for (tenant_id, asset_id), rows in by_asset.items():
            times = [_parse_iso(str(e.get("occurred_at") or "")) for e in rows]
            window_start = min(times)
            window_end = max(times)
            deny_count = sum(1 for e in rows if e.get("is_deny"))
            record = {
                "event_type": "firewall.features",
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "window_start": window_start.isoformat().replace("+00:00", "Z"),
                "window_end": window_end.isoformat().replace("+00:00", "Z"),
                "feature_version": FEATURE_VERSION,
                "event_count": len(rows),
                "deny_count": deny_count,
                "events": rows,
                "detections": detections_by_asset.get((tenant_id, asset_id), []),
                "aggregates": {
                    "deny_count": deny_count,
                    "allow_count": len(rows) - deny_count,
                    "rule_changes": sum(
                        1
                        for e in rows
                        if e.get("event_type") in {"rule_add", "rule_delete", "rule_change"}
                    ),
                    "distinct_src": len({e.get("src_ip") for e in rows if e.get("src_ip")}),
                },
            }
            features.append(record)
            self.published += 1

        return features, findings
