"""TheHive case adapter — create/update from incident payloads."""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy.orm import Session

from integration_hub.config import settings
from integration_hub.models import TheHiveDryRun


def incident_to_case_payload(incident: dict[str, Any]) -> dict[str, Any]:
    """Map Black Onyx incident → TheHive case-ish body (v5-compatible fields)."""
    title = str(incident.get("title") or f"Incident {incident.get('incident_id', 'unknown')}")
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    sev = severity_map.get(str(incident.get("severity") or "medium").lower(), 2)
    description_parts = [
        str(incident.get("summary") or ""),
        f"incident_id={incident.get('incident_id')}",
        f"risk_score={incident.get('risk_score')}",
        f"assets={','.join(incident.get('assets') or [])}",
        f"services={','.join(incident.get('services') or [])}",
    ]
    tags = list(incident.get("category") or [])
    tags.append("black-onyx")
    if incident.get("tenant_id"):
        tags.append(f"tenant:{incident['tenant_id']}")
    return {
        "title": title,
        "description": "\n".join(p for p in description_parts if p),
        "severity": sev,
        "tlp": 2,
        "pap": 2,
        "tags": tags,
        "customFields": {
            "incident_id": incident.get("incident_id"),
            "risk_score": incident.get("risk_score"),
        },
        "status": "New",
    }


def _configured() -> bool:
    return bool((settings.thehive_url or "").strip() and (settings.thehive_key or "").strip())


def create_or_update_case(
    db: Session,
    incident: dict[str, Any],
    *,
    case_id: str | None = None,
) -> dict[str, Any]:
    """Create or update a TheHive case. Dry-run when THEHIVE_URL/KEY unset."""
    payload = incident_to_case_payload(incident)
    tenant_id = str(incident.get("tenant_id") or "unknown")
    incident_id = str(incident.get("incident_id") or "unknown")
    operation = "update" if case_id else "create"

    if not _configured():
        row = TheHiveDryRun(
            tenant_id=tenant_id,
            incident_id=incident_id,
            operation=operation,
            payload={"case_id": case_id, "body": payload},
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return {
            "dry_run": True,
            "operation": operation,
            "stored_id": row.id,
            "case_id": case_id or f"dry-run-{row.id}",
            "payload": payload,
        }

    base = settings.thehive_url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {settings.thehive_key}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=15.0) as client:
        if case_id:
            url = f"{base}/api/v1/case/{case_id}"
            resp = client.patch(url, json=payload, headers=headers)
        else:
            url = f"{base}/api/v1/case"
            resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {
        "dry_run": False,
        "operation": operation,
        "case_id": data.get("_id") or data.get("id") or case_id,
        "response": data,
        "payload": payload,
    }
