"""Connector health and recent detection pulse."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def connector_pulse(client: PlatformClient, *, limit: int = 20) -> dict[str, Any]:
    health = await client.tip_get("/api/v1/analytics/connectors/health")
    recent = await client.tip_get("/api/v1/connectors/detections/recent", params={"limit": limit})
    triage = await client.tip_get("/api/v1/triage", params={"limit": limit})
    return {
        "connectors_health": health,
        "recent_detections": recent,
        "triage_feed": triage,
        "markdown": _render_pulse(health, recent, triage),
    }


def _render_pulse(health: Any, recent: Any, triage: Any) -> str:
    lines = ["# Connector pulse", "", "## Connector health", str(health), "", "## Recent detections"]
    items = recent if isinstance(recent, list) else recent.get("items") if isinstance(recent, dict) else recent
    if not items:
        lines.append("_No recent detections._")
    else:
        for row in (items or [])[:10]:
            lines.append(f"- {row}")
    lines.extend(["", "## Triage feed"])
    triage_items = triage.get("items") if isinstance(triage, dict) else triage
    if not triage_items:
        lines.append("_Triage queue empty._")
    else:
        for row in (triage_items or [])[:10]:
            lines.append(f"- [{row.get('kind', 'item')}] {row.get('source', '')} — {row.get('id', '')}")
    return "\n".join(lines)


def register_connector_pulse(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_connector_pulse")
    async def connector_pulse_tool(limit: int = 20) -> dict[str, Any]:
        """Summarize connector health, recent detections, and triage backlog."""
        return await connector_pulse(client, limit=limit)
