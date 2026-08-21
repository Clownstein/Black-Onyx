"""Certificate transparency lookups via crt.sh."""

from __future__ import annotations

from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def certificate_transparency(*, domain: str, limit: int = 25) -> dict[str, Any]:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain is required")

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=30.0)) as http:
        response = await http.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
        )
        response.raise_for_status()
        rows = response.json()

    if not isinstance(rows, list):
        rows = []

    certificates = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        certificates.append({
            "id": row.get("id"),
            "logged_at": row.get("entry_timestamp") or row.get("not_before"),
            "issuer": row.get("issuer_name"),
            "common_name": row.get("common_name") or row.get("name_value"),
            "name_value": row.get("name_value"),
        })

    return {
        "domain": domain,
        "total": len(rows),
        "returned": len(certificates),
        "certificates": certificates,
    }


def register_certificate_transparency(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="certificate_transparency")
    async def certificate_transparency_tool(domain: str, limit: int = 25) -> dict[str, Any]:
        """Query crt.sh for certificate transparency entries related to a domain."""
        _ = client
        return await certificate_transparency(domain=domain, limit=limit)
