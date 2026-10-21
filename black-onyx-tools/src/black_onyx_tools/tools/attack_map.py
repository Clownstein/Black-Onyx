"""MITRE ATT&CK mapping and coverage analytics."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


def _normalize_technique_ids(raw: Any) -> list[str]:
    """TIP ``/attack/extract`` returns list[dict] with ``technique_id``; accept strings too."""
    if not raw:
        return []
    if isinstance(raw, dict):
        raw = raw.get("techniques") or raw.get("items") or []
    ids: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            ids.append(item.strip())
        elif isinstance(item, dict):
            tid = item.get("technique_id") or item.get("id") or item.get("technique")
            if isinstance(tid, str) and tid.strip():
                ids.append(tid.strip())
    return list(dict.fromkeys(ids))


async def attack_map(
    client: PlatformClient,
    *,
    text: str = "",
    technique_ids: list[str] | None = None,
    coverage_range: str = "30d",
    include_graph: bool = True,
) -> dict[str, Any]:
    extracted: list[str] = []
    if text:
        extract_payload = await client.tip_post("/api/v1/attack/extract", json={"text": text})
        extracted = _normalize_technique_ids(extract_payload.get("techniques") or extract_payload)

    techniques = list(dict.fromkeys([*(technique_ids or []), *extracted]))
    coverage = await client.tip_get("/api/v1/analytics/attack/coverage", params={"range": coverage_range})

    heatmap: dict[str, Any] = {}
    graph: dict[str, Any] = {}
    if techniques:
        heatmap = await client.tip_post("/api/v1/attack/heatmap", json=techniques)
        if include_graph:
            graph = await client.tip_post("/api/v1/graph/attack", json=techniques)

    return {
        "techniques": techniques,
        "coverage": coverage,
        "heatmap": heatmap,
        "graph": graph,
    }


def register_attack_map(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_attack_map")
    async def attack_map_tool(
        text: str = "",
        technique_ids: list[str] | None = None,
        coverage_range: str = "30d",
        include_graph: bool = True,
    ) -> dict[str, Any]:
        """Extract ATT&CK techniques from text and map org coverage."""
        if not text and not technique_ids:
            raise ValueError("Provide text and/or technique_ids")
        return await attack_map(
            client,
            text=text,
            technique_ids=technique_ids,
            coverage_range=coverage_range,
            include_graph=include_graph,
        )
