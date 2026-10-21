"""Watchlist proposals and IOC decay summaries."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def watchlist_decay(
    client: PlatformClient,
    *,
    action: str = "summary",
    watchlist_id: str = "",
    watchlist_name: str = "",
    items: list[dict[str, str]] | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    if action == "summary":
        summary = await client.tip_get("/api/v1/decay/summary")
        stale = await client.tip_get("/api/v1/decay/stale")
        fresh = await client.tip_get("/api/v1/decay/fresh")
        return {"summary": summary, "stale": stale, "fresh": fresh}

    if action == "list_watchlists":
        return await client.tip_get("/api/v1/watchlists")

    if action == "propose_add":
        if not items:
            raise ValueError("items required for propose_add")
        proposal = {
            "watchlist_id": watchlist_id,
            "watchlist_name": watchlist_name,
            "items": items,
        }
        return {"draft": True, "proposal": proposal,
                "message": "Apply watchlist changes through the authenticated app review workflow; confirm is not authorization."}

    raise ValueError("action must be summary, list_watchlists, or propose_add")


def register_watchlist_decay(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_watchlist_decay")
    async def watchlist_decay_tool(
        action: str = "summary",
        watchlist_id: str = "",
        watchlist_name: str = "",
        items: list[dict[str, str]] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Summarize IOC decay or draft watchlist additions for app review."""
        return await watchlist_decay(
            client,
            action=action,
            watchlist_id=watchlist_id,
            watchlist_name=watchlist_name,
            items=items,
            confirm=confirm,
        )
