"""Incident investigation brief generator."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def incident_brief(client: PlatformClient, *, incident_id: str) -> dict[str, Any]:
    incident = await client.detection_get("incident", f"/api/v1/incidents/{incident_id}")
    timeline = await client.detection_get("incident", f"/api/v1/incidents/{incident_id}/timeline")

    finding_ids = list(dict.fromkeys(incident.get("finding_ids") or []))
    related_findings: list[dict[str, Any]] = []
    for fid in finding_ids[:25]:
        try:
            finding = await client.detection_get("incident", f"/api/v1/findings/{fid}")
            related_findings.append(finding)
        except Exception as exc:  # noqa: BLE001 — soft-fail per finding
            related_findings.append({"finding_id": fid, "error": str(exc)})

    markdown = _render_brief(incident, related_findings, timeline if isinstance(timeline, list) else [])
    return {
        "incident_id": incident_id,
        "incident": incident,
        "findings": related_findings,
        "timeline": timeline,
        "brief_markdown": markdown,
    }


def _render_brief(incident: dict[str, Any], findings: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> str:
    title = incident.get("title") or incident.get("incident_id") or "Incident"
    severity = incident.get("severity") or "unknown"
    status = incident.get("status") or "unknown"
    summary = incident.get("summary") or incident.get("description") or ""
    assets = incident.get("assets") or []
    services = incident.get("services") or []

    lines = [
        f"# Incident brief: {title}",
        "",
        f"- **ID:** {incident.get('incident_id', 'unknown')}",
        f"- **Severity:** {severity}",
        f"- **Status:** {status}",
        f"- **Assets:** {', '.join(map(str, assets)) or 'none'}",
        f"- **Services:** {', '.join(map(str, services)) or 'none'}",
        "",
        "## Summary",
        summary or "_No summary provided._",
        "",
        f"## Findings ({len(findings)})",
    ]
    if not findings:
        lines.append("_No correlated findings._")
    else:
        for finding in findings[:15]:
            fid = finding.get("finding_id") or finding.get("id") or "finding"
            if finding.get("error"):
                lines.append(f"- `{fid}` — error: {finding['error']}")
                continue
            model = finding.get("model_name") or finding.get("model") or "unknown"
            score = finding.get("calibrated_score") or finding.get("risk_score") or "n/a"
            lines.append(f"- `{fid}` — model `{model}`, score `{score}`")

    lines.extend(["", f"## Timeline ({len(timeline)})"])
    if not timeline:
        lines.append("_No timeline entries._")
    else:
        for entry in timeline[:20]:
            when = entry.get("created_at") or entry.get("occurred_at") or ""
            event_type = entry.get("event_type") or "event"
            detail = entry.get("summary") or entry.get("detail") or entry.get("refs") or {}
            lines.append(f"- `{when}` **{event_type}** — {detail}")

    return "\n".join(lines)


def register_incident_brief(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_incident_brief")
    async def incident_brief_tool(incident_id: str) -> dict[str, Any]:
        """Fetch incident, linked findings, and timeline; return InvestigationAssist markdown."""
        return await incident_brief(client, incident_id=incident_id)
