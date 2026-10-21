"""Containment adapters dry-run by default; live when URLs configured."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

import httpx

from response_orchestrator.config import settings
from response_orchestrator.wazuh_active_response import run_isolation, wazuh_agent_id

logger = logging.getLogger("response-orchestrator.adapters")


def _bounded_int(payload: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(payload.get(key) if payload.get(key) is not None else default)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"payload.{key} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"payload.{key} must be between {minimum} and {maximum}")
    return value


def validate_ip(payload: dict[str, Any], *, allow_non_public: bool = False) -> dict[str, Any]:
    raw = payload.get("ip") or payload.get("c2_ip")
    if not raw:
        raise ValueError("payload.ip is required")
    ip = ipaddress.ip_address(str(raw))
    if not allow_non_public and (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast
    ):
        raise ValueError(f"refusing non-public IP: {raw}")
    # Documentation / benchmark ranges are allowed for dry-run lab tests (TEST-NET, etc.)
    return {"ok": True, "ip": str(ip)}


def validate_asset(payload: dict[str, Any]) -> dict[str, Any]:
    asset_id = payload.get("asset_id")
    if not asset_id or not str(asset_id).strip():
        raise ValueError("payload.asset_id is required")
    normalized = str(asset_id).strip()
    if len(normalized) > 256:
        raise ValueError("payload.asset_id may not exceed 256 characters")
    return {"ok": True, "asset_id": normalized}


def validate_domain(payload: dict[str, Any]) -> dict[str, Any]:
    domain = payload.get("domain") or payload.get("c2_domain")
    if not domain or not str(domain).strip():
        raise ValueError("payload.domain is required")
    normalized = str(domain).strip().lower().rstrip(".")
    if len(normalized) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        normalized,
    ):
        raise ValueError("payload.domain must be a valid DNS name")
    return {"ok": True, "domain": normalized}


def block_ip(payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    validated = validate_ip(payload, allow_non_public=False)
    body = {
        "action": "block_ip",
        "ip": validated["ip"],
        "direction": payload.get("direction") or "both",
        "ttl_minutes": _bounded_int(payload, "ttl_minutes", 60, 1, 10_080),
    }
    if body["direction"] not in {"inbound", "outbound", "both"}:
        raise ValueError("payload.direction must be inbound, outbound, or both")
    if dry_run:
        return {"ok": True, "dry_run": True, "would_send": body}
    url = (settings.pfsense_api_url or "").strip()
    if not url:
        return {
            "ok": False,
            "dry_run": False,
            "queued_external": False,
            "error": "unconfigured",
            "message": "PFSENSE_API_URL unset; cannot block_ip in live mode",
            "action": body,
        }
    headers = {"Content-Type": "application/json"}
    if settings.pfsense_api_key:
        headers["Authorization"] = f"Bearer {settings.pfsense_api_key}"
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url.rstrip("/") + "/api/v1/firewall/block", json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {"ok": True, "dry_run": False, "response": data, "action": body}


def isolate_host(payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    validated = validate_asset(payload)
    body = {
        "action": "isolate_host",
        "asset_id": validated["asset_id"],
        "reason": payload.get("reason") or "incident response",
        "ttl_minutes": _bounded_int(payload, "ttl_minutes", 120, 1, 10_080),
    }
    provider = (settings.edr_provider or "").strip().lower()
    if provider not in {"", "wazuh"}:
        raise ValueError(f"unsupported EDR provider: {settings.edr_provider}")
    if provider == "wazuh":
        wazuh_agent_id(body["asset_id"])
    if dry_run:
        return {"ok": True, "dry_run": True, "would_send": body}
    if provider == "wazuh":
        if not settings.wazuh_api_url.strip() or not settings.wazuh_api_user or not settings.wazuh_api_password:
            return {
                "ok": False,
                "dry_run": False,
                "queued_external": False,
                "error": "unconfigured",
                "message": "Wazuh API URL/user/password unset; cannot isolate_host in live mode",
                "action": body,
            }
        verify: bool | str = settings.wazuh_api_ca_file.strip() or settings.wazuh_api_verify_tls
        return run_isolation(
            body,
            api_url=settings.wazuh_api_url,
            user=settings.wazuh_api_user,
            password=settings.wazuh_api_password,
            command=settings.wazuh_ar_command,
            command_windows=settings.wazuh_ar_command_windows,
            allow=settings.wazuh_isolation_allow,
            verify=verify,
        )
    url = (settings.edr_api_url or "").strip()
    if not url:
        return {
            "ok": False,
            "dry_run": False,
            "queued_external": False,
            "error": "unconfigured",
            "message": "EDR_API_URL unset; cannot isolate_host in live mode",
            "action": body,
        }
    headers = {"Content-Type": "application/json"}
    if settings.edr_api_key:
        headers["Authorization"] = f"Bearer {settings.edr_api_key}"
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url.rstrip("/") + "/api/v1/hosts/isolate", json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {"ok": True, "dry_run": False, "response": data, "action": body}


def capture_now(payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    asset_id = str(payload.get("asset_id") or payload.get("sensor_id") or "").strip()
    if not asset_id:
        raise ValueError("payload.asset_id or sensor_id required for capture_now")
    body = {
        "action": "capture_now",
        "asset_id": asset_id,
        "seconds": _bounded_int(payload, "seconds", 30, 1, 300),
        "filter": payload.get("filter") or {},
        "incident_id": payload.get("incident_id"),
    }
    if dry_run:
        return {"ok": True, "dry_run": True, "would_send": body}
    url = (settings.capture_api_url or "").strip()
    if not url:
        return {
            "ok": False,
            "dry_run": False,
            "queued_external": False,
            "error": "unconfigured",
            "message": "CAPTURE_API_URL unset; cannot capture_now in live mode",
            "action": body,
        }
    headers = {"Content-Type": "application/json"}
    if settings.capture_api_key:
        headers["Authorization"] = f"Bearer {settings.capture_api_key}"
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(url.rstrip("/") + "/api/v1/capture", json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    return {"ok": True, "dry_run": False, "response": data, "action": body}


def block_c2(payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    """Block C2 IP and/or domain (firewall + DNS RPZ)."""
    results: list[dict[str, Any]] = []
    if payload.get("ip") or payload.get("c2_ip"):
        results.append(block_ip(payload, dry_run=dry_run))
    domain_payload = dict(payload)
    if payload.get("domain") or payload.get("c2_domain"):
        validated = validate_domain(payload)
        body = {
            "action": "block_c2_domain",
            "domain": validated["domain"],
            "ttl_minutes": _bounded_int(payload, "ttl_minutes", 120, 1, 10_080),
        }
        if dry_run:
            results.append({"ok": True, "dry_run": True, "would_send": body})
        else:
            url = (settings.dns_rpz_url or "").strip()
            if not url:
                results.append(
                    {
                        "ok": False,
                        "dry_run": False,
                        "queued_external": False,
                        "error": "unconfigured",
                        "message": "DNS_RPZ_URL unset; cannot block_c2 domain in live mode",
                        "action": body,
                    }
                )
            else:
                headers = {"Content-Type": "application/json"}
                if settings.dns_rpz_key:
                    headers["Authorization"] = f"Bearer {settings.dns_rpz_key}"
                with httpx.Client(timeout=15.0) as client:
                    resp = client.post(
                        url.rstrip("/") + "/api/v1/rpz/block",
                        json=body,
                        headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json() if resp.content else {}
                results.append({"ok": True, "dry_run": False, "response": data, "action": body})
    if not results:
        raise ValueError("block_c2 requires ip and/or domain")
    ok = all(bool(step.get("ok")) for step in results)
    return {"ok": ok, "dry_run": dry_run, "steps": results}
