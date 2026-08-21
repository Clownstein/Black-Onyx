"""SIEM outbound formatters (JSON + CEF)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _escape_cef(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("=", "\\=")
        .replace("|", "\\|")
    )


def _severity_cef(severity: str | None, score: float | None = None) -> int:
    key = str(severity or "").lower()
    if key == "critical":
        return 10
    if key == "high":
        return 8
    if key == "medium":
        return 5
    if key == "low":
        return 3
    if score is not None:
        return max(0, min(10, int(round(float(score) * 10))))
    return 5


def incident_to_json(incident: dict[str, Any]) -> dict[str, Any]:
    """Stable JSON export shape for SIEM / webhook consumers."""
    return {
        "format": "json",
        "exported_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "incident": {
            "incident_id": incident.get("incident_id") or incident.get("id"),
            "tenant_id": incident.get("tenant_id"),
            "title": incident.get("title") or incident.get("summary"),
            "status": incident.get("status"),
            "severity": incident.get("severity"),
            "risk_score": incident.get("risk_score") or incident.get("score"),
            "asset_ids": incident.get("asset_ids")
            or ([incident["asset_id"]] if incident.get("asset_id") else []),
            "service_ids": incident.get("service_ids") or incident.get("services") or [],
            "finding_ids": incident.get("finding_ids") or [],
            "mitre_techniques": incident.get("mitre_techniques") or [],
            "mitre_tactics": incident.get("mitre_tactics") or [],
            "created_at": incident.get("created_at") or incident.get("opened_at"),
            "updated_at": incident.get("updated_at"),
            "summary": incident.get("summary") or incident.get("description"),
        },
    }


def incident_to_cef(
    incident: dict[str, Any],
    *,
    device_vendor: str = "BlackOnyx",
    device_product: str = "integration-hub",
    device_version: str = "0.1.0",
) -> str:
    """Format an incident as a single CEF syslog-style line."""
    incident_id = incident.get("incident_id") or incident.get("id") or "unknown"
    severity = _severity_cef(
        incident.get("severity"),
        incident.get("risk_score") or incident.get("score"),
    )
    title = incident.get("title") or incident.get("summary") or "incident"
    signature = str(incident.get("signature_id") or "AA:INCIDENT")
    name = _escape_cef(title)[:512]
    extensions: list[str] = [
        f"externalId={_escape_cef(incident_id)}",
        f"msg={_escape_cef(incident.get('summary') or title)}",
    ]
    tenant = incident.get("tenant_id")
    if tenant:
        extensions.append(f"cs1Label=tenant_id")
        extensions.append(f"cs1={_escape_cef(tenant)}")
    assets = incident.get("asset_ids") or (
        [incident["asset_id"]] if incident.get("asset_id") else []
    )
    if assets:
        extensions.append(f"cs2Label=asset_ids")
        extensions.append(f"cs2={_escape_cef(','.join(str(a) for a in assets))}")
    techniques = incident.get("mitre_techniques") or []
    if techniques:
        extensions.append(f"cs3Label=mitre_techniques")
        extensions.append(f"cs3={_escape_cef(','.join(str(t) for t in techniques))}")
    status = incident.get("status")
    if status:
        extensions.append(f"cs4Label=status")
        extensions.append(f"cs4={_escape_cef(status)}")
    score = incident.get("risk_score") or incident.get("score")
    if score is not None:
        extensions.append(f"cn1Label=risk_score")
        extensions.append(f"cn1={_escape_cef(score)}")

    header = (
        f"CEF:0|{_escape_cef(device_vendor)}|{_escape_cef(device_product)}|"
        f"{_escape_cef(device_version)}|{_escape_cef(signature)}|{name}|{severity}"
    )
    return header + "|" + " ".join(extensions)


def format_siem_export(
    incident: dict[str, Any],
    *,
    fmt: str = "json",
    device_vendor: str = "BlackOnyx",
    device_product: str = "integration-hub",
    device_version: str = "0.1.0",
) -> dict[str, Any]:
    kind = (fmt or "json").strip().lower()
    if kind == "cef":
        line = incident_to_cef(
            incident,
            device_vendor=device_vendor,
            device_product=device_product,
            device_version=device_version,
        )
        return {"format": "cef", "cef": line, "lines": [line]}
    payload = incident_to_json(incident)
    return payload
