"""IOC extraction and enrichment via Black Onyx TIP APIs."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


def _group_iocs(items: list[dict[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in items:
        ioc_type = item.get("ioc_type") or "unknown"
        value = item.get("ioc_value") or ""
        if not value:
            continue
        grouped.setdefault(ioc_type, []).append(value)
    return grouped


def _flat_iocs_for_stix(
    extracted: dict[str, list[str]],
    batch_items: list[dict[str, str]],
) -> list[dict[str, str]]:
    """TIP STIXExporter expects list[{ioc_type, ioc_value}], not a grouped dict."""
    if batch_items:
        return [
            {"ioc_type": item.get("ioc_type") or "unknown", "ioc_value": item["ioc_value"]}
            for item in batch_items
            if item.get("ioc_value")
        ]
    flat: list[dict[str, str]] = []
    for ioc_type, values in extracted.items():
        for value in values:
            if value:
                flat.append({"ioc_type": ioc_type, "ioc_value": value})
    return flat


async def ioc_enrich(
    client: PlatformClient,
    *,
    text: str | None = None,
    iocs: list[dict[str, str]] | None = None,
    providers: list[str] | None = None,
    export_stix: bool = False,
) -> dict[str, Any]:
    _ = providers  # reserved for future provider filtering; batch uses TIP defaults
    extracted: dict[str, list[str]] = {}
    if text:
        extract_payload = await client.tip_post(
            "/api/v1/ioc/extract",
            json={"text": text, "include_defanged": True},
        )
        extracted = extract_payload.get("iocs") or {}

    batch_items: list[dict[str, str]] = []
    if iocs:
        batch_items.extend(iocs)
    for ioc_type, values in extracted.items():
        for value in values:
            batch_items.append({"ioc_type": ioc_type, "ioc_value": value})

    if not batch_items:
        return {"extracted": extracted, "enrichment": {}, "stix": None}

    enrich_payload = await client.tip_post(
        "/api/v1/enrich/batch",
        json={"iocs": batch_items},
    )
    stix_bundle = None
    if export_stix:
        stix_iocs = _flat_iocs_for_stix(extracted, batch_items)
        stix_payload = await client.tip_post(
            "/api/v1/stix/export",
            json={"iocs": stix_iocs, "techniques": []},
        )
        stix_bundle = stix_payload.get("bundle")

    return {
        "extracted": extracted or _group_iocs(batch_items),
        "enrichment": enrich_payload.get("results") or enrich_payload,
        "stix": stix_bundle,
    }


def register_ioc_enrich(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_ioc_enrich")
    async def ioc_enrich_tool(
        text: str = "",
        iocs: list[dict[str, str]] | None = None,
        providers: list[str] | None = None,
        export_stix: bool = False,
    ) -> dict[str, Any]:
        """Extract IOCs from text and enrich them through configured providers."""
        if not text and not iocs:
            raise ValueError("Provide text and/or explicit iocs")
        return await ioc_enrich(
            client,
            text=text or None,
            iocs=iocs,
            providers=providers,
            export_stix=export_stix,
        )
