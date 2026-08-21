"""Threat intel observable matching via detection BFF; optional TIP sync publish."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient

_TYPE_MAP = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "email": "email",
    "cve": "cve",
}


def _to_tip_iocs(observables: list[dict[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for obs in observables:
        raw_type = (obs.get("type") or obs.get("ioc_type") or "").strip().lower()
        value = (obs.get("value") or obs.get("ioc_value") or "").strip()
        if not value:
            continue
        ioc_type = _TYPE_MAP.get(raw_type, raw_type or "domain")
        out.append({"ioc_type": ioc_type, "ioc_value": value})
    return out


async def ti_match(
    client: PlatformClient,
    *,
    observables: list[dict[str, str]],
    mode: Literal["exact", "semantic"] = "exact",
    publish: bool = False,
    confirm: bool = False,
    case_id: str = "",
) -> dict[str, Any]:
    if not observables:
        raise ValueError("observables list is required")

    path = "/api/v1/match" if mode == "exact" else "/api/v1/match/semantic"
    matches = await client.detection_post("ti", path, json={"observables": observables})

    if not publish:
        return {"mode": mode, "matches": matches, "published": False}

    tip_iocs = _to_tip_iocs(observables)
    if not tip_iocs:
        raise ValueError("publish requires observables with type/value (or ioc_type/ioc_value)")

    if not confirm:
        return {
            "mode": mode,
            "matches": matches,
            "draft": True,
            "action": "sync-indicators",
            "iocs": tip_iocs,
            "case_id": case_id or None,
            "published": False,
            "message": (
                "Publishing to TIP→threat-intel sync requires confirm=True "
                "and a case_id."
            ),
        }

    if not case_id.strip():
        raise ValueError("publish with confirm=True requires case_id")

    sync = await client.tip_post(
        "/api/v1/threat-intel/sync-indicators",
        json={"case_id": case_id.strip(), "iocs": tip_iocs, "info": "MCP ti_match publish"},
    )
    return {
        "mode": mode,
        "matches": matches,
        "published": True,
        "sync": sync,
        "iocs": tip_iocs,
        "case_id": case_id.strip(),
    }


def register_ti_match(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_ti_match")
    async def ti_match_tool(
        observables: list[dict[str, str]],
        mode: str = "exact",
        publish: bool = False,
        confirm: bool = False,
        case_id: str = "",
    ) -> dict[str, Any]:
        """Match observables via threat-intel-service. Publish sync only with confirm+case_id."""
        if mode not in {"exact", "semantic"}:
            raise ValueError("mode must be exact or semantic")
        return await ti_match(
            client,
            observables=observables,
            mode=mode,  # type: ignore[arg-type]
            publish=publish,
            confirm=confirm,
            case_id=case_id,
        )
