"""Sigma and YARA rule drafting from IOC JSON."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def rule_draft(
    client: PlatformClient,
    *,
    rule_type: Literal["sigma", "yara"],
    iocs: dict[str, list[str]],
    title: str = "",
    description: str = "",
    level: str = "medium",
    rule_name: str = "black_onyx_rule",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    if not iocs:
        raise ValueError("iocs dict is required")

    if rule_type == "sigma":
        payload = await client.tip_post(
            "/api/v1/rules/sigma",
            json={
                "iocs": iocs,
                "title": title,
                "description": description,
                "level": level,
            },
        )
        return {"rule_type": "sigma", "rule": payload.get("rule"), "dry_run": True}

    payload = await client.tip_post(
        "/api/v1/rules/yara",
        json={
            "iocs": iocs,
            "rule_name": rule_name,
            "tags": tags or ["black_onyx"],
        },
    )
    return {"rule_type": "yara", "rule": payload.get("rule"), "dry_run": True}


def register_rule_draft(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_rule_draft")
    async def rule_draft_tool(
        rule_type: str,
        iocs: dict[str, list[str]],
        title: str = "",
        description: str = "",
        level: str = "medium",
        rule_name: str = "black_onyx_rule",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate Sigma or YARA rule drafts from IOC JSON (metadata only, no execution)."""
        if rule_type not in {"sigma", "yara"}:
            raise ValueError("rule_type must be sigma or yara")
        return await rule_draft(
            client,
            rule_type=rule_type,  # type: ignore[arg-type]
            iocs=iocs,
            title=title,
            description=description,
            level=level,
            rule_name=rule_name,
            tags=tags,
        )
