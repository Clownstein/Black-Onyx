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
        if not confirm:
            return {"draft": True, "proposal": proposal, "message": "Set confirm=True to add watchlist items."}
        if not watchlist_id:
            if not watchlist_name:
                raise ValueError("watchlist_id or watchlist_name required")
            created = await client.tip_post(
                "/api/v1/watchlists",
                json={"name": watchlist_name, "description": "Created by black-onyx-tools"},
            )
            watchlist_id = created.get("list_id") or created.get("watchlist_id") or ""
        if not watchlist_id:
            raise ValueError("Could not resolve watchlist_id")
        result = await client.tip_post(
            f"/api/v1/watchlists/{watchlist_id}/items",
            json={"items": items},
        )
        return {"proposal": proposal, "result": result, "watchlist_id": watchlist_id}

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
        """Summarize IOC decay or propose watchlist additions (mutations require confirm=True)."""
        return await watchlist_decay(
            client,
            action=action,
            watchlist_id=watchlist_id,
            watchlist_name=watchlist_name,
            items=items,
            confirm=confirm,
        )
