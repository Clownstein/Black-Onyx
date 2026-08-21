"""Human-gated response orchestrator drafts — never auto-approve."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def response_draft(
    client: PlatformClient,
    *,
    incident_id: str,
    playbook_id: str,
    action: str = "execute",
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    draft = {
        "incident_id": incident_id,
        "playbook_id": playbook_id,
        "action": action,
        "dry_run": True,
        "payload": {"response_mode": "suggest_only", "auto_execute": False},
        "message": "Draft only. Approval is never performed by this tool.",
    }
    if not confirm:
        return {"draft": draft, "submitted": False}

    # Even with confirm=True we only create a pending request — never approve.
    result = await client.detection_post(
        "response",
        "/api/v1/response/request",
        json={
            "incident_id": incident_id,
            "playbook_id": playbook_id,
            "action": action,
            "dry_run": True,
            "payload": {"response_mode": "suggest_only", "auto_execute": False},
        },
    )
    pending = await client.detection_get("response", "/api/v1/response/pending")
    return {
        "draft": draft,
        "submitted": True,
        "request": result,
        "pending_queue": pending,
        "approval_note": "Analyst must approve or reject in the response queue UI.",
    }


def register_response_draft(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_response_draft")
    async def response_draft_tool(
        incident_id: str,
        playbook_id: str,
        action: str = "execute",
        dry_run: bool = True,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Draft a response-orchestrator request (suggest-only). Never approves actions."""
        _ = dry_run  # always forced True inside response_draft
        return await response_draft(
            client,
            incident_id=incident_id,
            playbook_id=playbook_id,
            action=action,
            dry_run=True,
            confirm=confirm,
        )
