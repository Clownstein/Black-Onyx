"""Wazuh active-response client for approved host isolation."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import httpx

WAZUH_ASSET_PREFIX = "wazuh:"
_UNSAFE_REASON = re.compile(r"[^A-Za-z0-9 ._:/@-]+")


def wazuh_agent_id(asset_id: str) -> str:
    """Return the Wazuh agent id encoded in a `wazuh:{id}` asset id."""
    text = str(asset_id or "").strip()
    if not text.startswith(WAZUH_ASSET_PREFIX):
        raise ValueError("asset_id must be a Wazuh asset (wazuh:<agent_id>) when EDR_PROVIDER=wazuh")
    agent_id = text[len(WAZUH_ASSET_PREFIX):].strip()
    if not agent_id.isdigit() or len(agent_id) > 8:
        raise ValueError(f"invalid Wazuh agent id in asset_id: {asset_id}")
    return agent_id


def isolation_arguments(action_body: dict[str, Any], allow: str) -> list[str]:
    """Build active-response extra_args. Agent scripts split on commas and treat
    allow= entries as firewall exceptions, so reason text is reduced to a safe
    character set and every allow entry must be an IP address or CIDR."""
    reason = _UNSAFE_REASON.sub(" ", str(action_body.get("reason") or "")).strip()[:200]
    arguments = [f"ttl_minutes={int(action_body['ttl_minutes'])}", f"reason={reason}"]
    for entry in (item.strip() for item in (allow or "").split(",")):
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"WAZUH_ISOLATION_ALLOW entry is not an IP address or CIDR: {entry}") from exc
        arguments.append(f"allow={network.with_prefixlen if '/' in entry else network.network_address}")
    return arguments


def run_isolation(
    action_body: dict[str, Any],
    *,
    api_url: str,
    user: str,
    password: str,
    command: str,
    command_windows: str,
    allow: str,
    verify: bool | str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Authenticate to the Wazuh server API and dispatch the isolation command
    matching the agent's platform."""
    agent_id = wazuh_agent_id(action_body["asset_id"])
    base = api_url.strip().rstrip("/")
    with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False, verify=verify) as client:
        auth = client.post(f"{base}/security/user/authenticate", auth=(user, password))
        auth.raise_for_status()
        token = ((auth.json() or {}).get("data") or {}).get("token")
        if not token:
            raise RuntimeError("Wazuh API authentication returned no token")
        headers = {"Authorization": f"Bearer {token}"}
        agent = client.get(
            f"{base}/agents", params={"agents_list": agent_id, "select": "os.platform,status"}, headers=headers,
        )
        agent.raise_for_status()
        items = ((agent.json() or {}).get("data") or {}).get("affected_items") or []
        if not items:
            return {
                "ok": False,
                "dry_run": False,
                "error": "wazuh_agent_not_found",
                "message": f"Wazuh agent {agent_id} does not exist",
                "action": action_body,
            }
        platform = str(((items[0] or {}).get("os") or {}).get("platform") or "").lower()
        selected = command_windows if "windows" in platform else command
        resp = client.put(
            f"{base}/active-response",
            params={"agents_list": agent_id},
            json={"command": selected, "arguments": isolation_arguments(action_body, allow)},
            headers=headers,
        )
        resp.raise_for_status()
        data = (resp.json() or {}).get("data") or {}
    failed = data.get("failed_items") or []
    if failed or not data.get("total_affected_items"):
        return {
            "ok": False,
            "dry_run": False,
            "error": "wazuh_active_response_failed",
            "message": f"Wazuh did not dispatch isolation to agent {agent_id}",
            "response": data,
            "action": action_body,
        }
    return {"ok": True, "dry_run": False, "provider": "wazuh", "agent_id": agent_id, "command": selected,
            "response": data, "action": action_body}
