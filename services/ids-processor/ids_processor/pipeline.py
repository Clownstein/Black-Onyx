from __future__ import annotations

import base64
import binascii
import logging
from datetime import datetime, timezone
from typing import Any

from black_onyx_contracts import Finding, FindingContributor, FindingWindow
from ulid import ULID

from ids_processor.config import settings
from ids_processor.minio_store import evidence_ref_for_pcap
from ids_processor.normalize import normalize_suricata_alert

try:
    from black_onyx_otel import inc_counter
except ImportError:  # pragma: no cover

    def inc_counter(name: str, amount: float = 1.0, **labels: str) -> None:
        return None


logger = logging.getLogger("ids-processor.pipeline")

FEATURE_VERSION = "ids.suricata.v1"
MODEL_NAME = "suricata-ids"
MODEL_VERSION = "1.0.0"
MAX_PCAP_BYTES = 16 * 1024 * 1024


def _pcap_bytes_from_alert(alert: dict[str, Any]) -> bytes | None:
    raw = alert.get("pcap_bytes")
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
        return data if len(data) <= MAX_PCAP_BYTES else None
    if isinstance(raw, str) and raw.strip():
        try:
            data = base64.b64decode(raw, validate=True)
            return data if len(data) <= MAX_PCAP_BYTES else None
        except (ValueError, binascii.Error):
            logger.debug("invalid pcap_bytes base64; skipping MinIO evidence")
            return None
    b64 = alert.get("pcap_b64")
    if isinstance(b64, str) and b64.strip():
        try:
            data = base64.b64decode(b64, validate=True)
            return data if len(data) <= MAX_PCAP_BYTES else None
        except (ValueError, binascii.Error):
            logger.debug("invalid pcap_b64 for alert; skipping MinIO evidence")
            return None
    return None


def _attach_pcap_evidence(finding: dict[str, Any], alert: dict[str, Any]) -> None:
    data = _pcap_bytes_from_alert(alert)
    if not data:
        return
    try:
        ref = evidence_ref_for_pcap(
            data,
            tenant_id=str(finding.get("tenant_id") or alert.get("tenant_id") or ""),
            asset_id=str(alert["asset_id"]),
            alert_id=alert.get("signature_id") or finding.get("finding_id"),
        )
        if ref is None:
            return
        refs = list(finding.get("evidence_refs") or [])
        refs.append(ref)
        finding["evidence_refs"] = refs
    except Exception:  # noqa: BLE001 soft-fail MinIO / evidence attach
        logger.exception("pcap evidence attach failed; continuing without evidence_ref")


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(tz=timezone.utc)
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def alert_to_finding(alert: dict[str, Any]) -> dict[str, Any]:
    occurred = _parse_iso(str(alert.get("occurred_at") or ""))
    score = float(alert.get("calibrated_score") or 0.55)
    score = max(0.0, min(1.0, score))
    severity = str(alert.get("severity_hint") or "medium")
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"
    sid = int(alert.get("signature_id") or 0)
    signature = str(alert.get("signature") or "suricata.alert")
    tenant_id = alert.get("tenant_id")
    asset_id = alert.get("asset_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("alert tenant_id is required")
    if not isinstance(asset_id, str) or not asset_id.strip():
        raise ValueError("alert asset_id is required")
    finding = Finding(
        finding_id=str(ULID()),
        tenant_id=tenant_id.strip(),
        finding_type="suricata_alert",
        asset_id=asset_id.strip(),
        service_id=alert.get("service_id"),
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
        raw_score=float(alert.get("suricata_severity") or 3),
        calibrated_score=score,
        severity_hint=severity,  # type: ignore[arg-type]
        window=FindingWindow(start=occurred, end=occurred),
        contributors=[
            FindingContributor(
                type="suricata_alert",
                contribution=score,
                summary=f"SID {sid}: {signature}",
            )
        ],
        evidence_refs=[],
        context={
            "signature_id": sid,
            "signature": signature,
            "community_id": alert.get("community_id"),
            "asset_id": alert.get("asset_id"),
            "sensor_id": alert.get("sensor_id"),
            "flow_id": alert.get("flow_id"),
            "category": alert.get("category"),
            "proto": alert.get("proto"),
            "src_port": alert.get("src_port"),
            "dest_port": alert.get("dest_port"),
            "suricata_severity": alert.get("suricata_severity"),
        },
        fingerprint=f"suricata:{sid}:{alert.get('asset_id')}:{alert.get('community_id') or alert.get('flow_id')}",
        category=["network", "ids", "suricata"],
        occurred_at=occurred,
        mitre_tactics=list(alert.get("mitre_tactics") or []),
        mitre_techniques=list(alert.get("mitre_techniques") or []),
        mitre_confidence=score,
    )
    return finding.model_dump(mode="json")


class IdsPipeline:
    """Normalize Suricata alerts and emit findings.network."""

    def __init__(self) -> None:
        self.processed = 0
        self.findings_published = 0
        self.errors = 0

    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for event in events:
            try:
                alert = normalize_suricata_alert(event)
                self.processed += 1
                inc_counter("ids_processor_events_total", 1.0, status="ok")
                if not settings.publish_findings:
                    continue
                if not alert.get("signature_id") and not alert.get("signature"):
                    continue
                finding = alert_to_finding(alert)
                _attach_pcap_evidence(finding, alert)
                findings.append(finding)
                self.findings_published += 1
                inc_counter("ids_processor_findings_total", 1.0, modality="suricata")
            except Exception:
                self.errors += 1
                inc_counter("ids_processor_events_total", 1.0, status="error")
        return findings
