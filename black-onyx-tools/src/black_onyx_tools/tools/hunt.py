"""Detection hunt queries via incident-api BFF."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def hunt(
    client: PlatformClient,
    *,
    mode: Literal["search", "federated", "vector"],
    query: str,
    size: int = 50,
    limit: int = 25,
) -> dict[str, Any]:
    if mode == "search":
        return await client.detection_get(
            "incident",
            "/api/v1/hunt/search",
            params={"q": query, "size": size},
        )

    if mode == "federated":
        return await client.detection_post(
            "incident",
            "/api/v1/hunt/federated",
            json={"query": query},
        )

    return await client.detection_post(
        "incident",
        "/api/v1/hunt/vector",
        json={"text": query, "limit": limit},
    )


def register_hunt(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_hunt")
    async def hunt_tool(
        query: str,
        mode: str = "search",
        size: int = 50,
        limit: int = 25,
    ) -> dict[str, Any]:
        """Run OpenSearch, federated, or vector hunt through the detection BFF."""
        if mode not in {"search", "federated", "vector"}:
            raise ValueError("mode must be search, federated, or vector")
        return await hunt(client, mode=mode, query=query, size=size, limit=limit)  # type: ignore[arg-type]
