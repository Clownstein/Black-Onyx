"""Asset registry context via detection BFF."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def asset_context(
    client: PlatformClient,
    *,
    asset_id: str = "",
    hostname: str = "",
    ip_address: str = "",
    window_days: int = 7,
) -> dict[str, Any]:
    resolved_id = asset_id
    asset: dict[str, Any] | None = None

    if not resolved_id:
        assets_payload = await client.detection_get("assets", "/api/v1/assets")
        assets = assets_payload if isinstance(assets_payload, list) else assets_payload.get("items") or []
        needle_host = hostname.casefold()
        needle_ip = ip_address
        for row in assets:
            if hostname and str(row.get("name") or "").casefold() == needle_host:
                resolved_id = str(row.get("asset_id"))
                asset = row
                break
            if ip_address and str(row.get("ip_address") or row.get("ip") or "") == needle_ip:
                resolved_id = str(row.get("asset_id"))
                asset = row
                break
        if not resolved_id:
            raise ValueError("asset not found; provide asset_id or resolvable hostname/ip")

    if asset is None:
        asset = await client.detection_get("assets", f"/api/v1/assets/{resolved_id}")

    topology = await client.detection_get("assets", f"/api/v1/assets/{resolved_id}/topology")
    baseline = await client.detection_get(
        "assets",
        f"/api/v1/assets/{resolved_id}/baseline",
        params={"window_days": window_days},
    )

    incidents_payload = await client.detection_get("incident", "/api/v1/incidents")
    incidents = incidents_payload if isinstance(incidents_payload, list) else incidents_payload.get("items") or []
    related = [
        inc for inc in incidents
        if resolved_id in (inc.get("assets") or [])
    ]

    return {
        "asset_id": resolved_id,
        "asset": asset,
        "topology": topology,
        "baseline": baseline,
        "related_incidents": related[:20],
    }


def register_asset_context(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_asset_context")
    async def asset_context_tool(
        asset_id: str = "",
        hostname: str = "",
        ip_address: str = "",
        window_days: int = 7,
    ) -> dict[str, Any]:
        """Resolve an asset and return criticality, topology, baseline, and related incidents."""
        if not asset_id and not hostname and not ip_address:
            raise ValueError("Provide asset_id, hostname, or ip_address")
        return await asset_context(
            client,
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            window_days=window_days,
        )
