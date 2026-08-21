"""Live / dry-run adapters for playbook containment and DFIR actions."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

import httpx

from integration_hub.config import settings

logger = logging.getLogger("integration-hub.adapters")


def validate_ip(payload: dict[str, Any], *, allow_non_public: bool = True) -> dict[str, Any]:
    raw = payload.get("ip")
    if not raw:
        raise ValueError("payload.ip is required")
    try:
        ip = ipaddress.ip_address(str(raw))
    except ValueError as exc:
        raise ValueError(f"invalid ip: {raw}") from exc
    if not allow_non_public and _is_rfc1918_or_mgmt(ip):
        raise ValueError(f"refusing to block non-public IP (RFC1918/mgmt): {raw}")
    return {"ok": True, "ip": str(ip)}


def _is_rfc1918_or_mgmt(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject RFC1918, loopback, link-local, and unspecified (not TEST-NET docs ranges)."""
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(
            ip in net
            for net in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )
    if isinstance(ip, ipaddress.IPv6Address):
        # Unique local addresses (fc00::/7)
        return ip.ipv4_mapped is None and (ip.packed[0] & 0xFE) == 0xFC
    return False


def validate_asset(payload: dict[str, Any]) -> dict[str, Any]:
    asset_id = payload.get("asset_id")
    if not asset_id or not str(asset_id).strip():
        raise ValueError("payload.asset_id is required")
    return {"ok": True, "asset_id": str(asset_id).strip()}


def format_incident_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    incident = payload.get("incident") or {}
    body = {
        "source": "black-onyx",
        "incident_id": incident.get("incident_id") or payload.get("incident_id"),
        "tenant_id": incident.get("tenant_id") or payload.get("tenant_id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
        "summary": incident.get("summary"),
        "assets": incident.get("assets") or [],
    }
    if payload.get("include_evidence"):
        body["evidence"] = incident.get("evidence") or []
    return {"ok": True, "body": body}


def pfsense_block_ip(payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    # Live and dry-run validation both reject RFC1918 / mgmt ranges (plan safety).
    validated = validate_ip(payload, allow_non_public=False)
    ip = validated["ip"]
    direction = str(payload.get("direction") or "both")
    ttl = int(payload.get("ttl_minutes") or 60)
    action_body = {
        "action": "block_ip",
        "ip": ip,
        "direction": direction,
        "ttl_minutes": ttl,
    }
    if dry_run:
        return {"ok": True, "dry_run": True, "would_send": action_body}
    url = (settings.pfsense_api_url or "").strip()
    if not url:
        return {
            "ok": True,
            "dry_run": False,
            "queued_external": True,
            "message": "PFSENSE_API_URL unset; block recorded for external fulfillment",
            "action": action_body,
        }
    headers = {"Content-Type": "application/json"}
    if settings.pfsense_api_key:
        headers["Authorization"] = f"Bearer {settings.pfsense_api_key}"
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url.rstrip("/") + "/api/v1/firewall/block", json=action_body, headers=headers)
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {"ok": True, "dry_run": False, "response": data, "action": action_body}


def edr_isolate_host(payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    validated = validate_asset(payload)
    asset_id = validated["asset_id"]
    action_body = {
        "action": "isolate_host",
        "asset_id": asset_id,
        "reason": payload.get("reason") or "incident response",
        "ttl_minutes": int(payload.get("ttl_minutes") or 120),
    }
    if dry_run:
        return {"ok": True, "dry_run": True, "would_send": action_body}
    url = (settings.edr_api_url or "").strip()
    if not url:
        return {
            "ok": True,
            "dry_run": False,
            "queued_external": True,
            "message": "EDR_API_URL unset; isolation recorded for external fulfillment",
            "action": action_body,
        }
    headers = {"Content-Type": "application/json"}
    if settings.edr_api_key:
        headers["Authorization"] = f"Bearer {settings.edr_api_key}"
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url.rstrip("/") + "/api/v1/hosts/isolate", json=action_body, headers=headers)
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {"ok": True, "dry_run": False, "response": data, "action": action_body}


def http_post(payload: dict[str, Any], *, dry_run: bool, body: dict[str, Any] | None = None) -> dict[str, Any]:
    url = str(payload.get("webhook_url") or "").strip()
    if not url:
        raise ValueError("payload.webhook_url is required for http.post")
    send_body = body if body is not None else dict(payload.get("body") or payload)
    if dry_run:
        return {"ok": True, "dry_run": True, "url": url, "would_send": send_body}
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url, json=send_body)
        resp.raise_for_status()
        data = resp.json() if resp.content and "application/json" in resp.headers.get("content-type", "") else {}
    return {"ok": True, "dry_run": False, "status_code": resp.status_code, "response": data}


def velociraptor_collect(
    *,
    asset_id: str,
    artifact: str,
    dry_run: bool,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Submit a Velociraptor artifact collection when configured; otherwise queue externally."""
    body = {
        "client_id": asset_id,
        "artifacts": [artifact],
        "detail": detail or {},
    }
    if dry_run:
        return {"ok": True, "dry_run": True, "status": "queued", "would_send": body}
    url = (settings.velociraptor_url or "").strip()
    if not url:
        return {
            "ok": True,
            "dry_run": False,
            "status": "queued",
            "queued_external": True,
            "message": "VELOCIRAPTOR_URL unset; collection recorded for operator fulfillment",
            "action": body,
        }
    headers = {"Content-Type": "application/json"}
    if settings.velociraptor_key:
        headers["Authorization"] = f"Bearer {settings.velociraptor_key}"
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            url.rstrip("/") + "/api/v1/CollectArtifact",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {"ok": True, "dry_run": False, "status": "submitted", "response": data}
