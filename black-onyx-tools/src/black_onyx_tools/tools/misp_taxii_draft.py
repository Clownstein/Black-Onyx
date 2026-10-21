"""MISP and TAXII publish drafts from case IOCs."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def misp_taxii_draft(
    client: PlatformClient,
    *,
    target: str,
    case_id: str = "",
    collection_id: str = "",
    iocs: list[dict[str, str]] | None = None,
    info: str = "",
    confirm: bool = False,
) -> dict[str, Any]:
    if target not in {"misp", "taxii"}:
        raise ValueError("target must be misp or taxii")

    resolved_iocs = iocs or []
    if case_id and not resolved_iocs:
        case = await client.tip_get(f"/api/v1/cases/{case_id}")
        for row in case.get("iocs") or []:
            if isinstance(row, dict):
                resolved_iocs.append({
                    "ioc_type": row.get("ioc_type") or row.get("type") or "unknown",
                    "ioc_value": row.get("ioc_value") or row.get("value") or "",
                })

    if not resolved_iocs:
        raise ValueError("Provide iocs or a case_id with attached IOCs")

    draft: dict[str, Any]
    if target == "misp":
        status = await client.tip_get("/api/v1/misp/status")
        draft = {
            "target": "misp",
            "case_id": case_id,
            "iocs": resolved_iocs,
            "info": info or f"Draft MISP event for case {case_id or 'manual'}",
            "status": status,
        }
        if not confirm:
            return {"draft": draft, "published": False, "message": "Set confirm=True to publish to MISP."}
        result = await client.tip_post(
            "/api/v1/misp/publish",
            json={"case_id": case_id or "manual", "iocs": resolved_iocs, "info": draft["info"]},
        )
        return {"draft": draft, "published": True, "result": result}

    collections = await client.tip_get("/api/v1/taxii/collections")
    draft = {
        "target": "taxii",
        "collection_id": collection_id,
        "iocs": resolved_iocs,
        "collections": collections,
    }
    if not confirm:
        return {"draft": draft, "published": False, "message": "Set confirm=True to publish to TAXII."}
    if not collection_id:
        raise ValueError("collection_id required for TAXII publish")
    result = await client.tip_post(
        "/api/v1/taxii/publish",
        json={"collection_id": collection_id, "iocs": resolved_iocs},
    )
    return {"draft": draft, "published": True, "result": result}


def register_misp_taxii_draft(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_misp_taxii_draft")
    async def misp_taxii_draft_tool(
        target: str,
        case_id: str = "",
        collection_id: str = "",
        iocs: list[dict[str, str]] | None = None,
        info: str = "",
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Draft or publish MISP events / TAXII packages from case IOCs (publish needs confirm=True)."""
        return await misp_taxii_draft(
            client,
            target=target,
            case_id=case_id,
            collection_id=collection_id,
            iocs=iocs,
            info=info,
            confirm=confirm,
        )
