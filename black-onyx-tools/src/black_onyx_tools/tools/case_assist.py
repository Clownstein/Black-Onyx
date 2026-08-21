"""Investigation case assist — drafts, mutations, and triage promote with confirm gate."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient

PromoteKind = Literal["alert", "detection", "webhook", "detection_incident"]


def _require_confirm(confirm: bool, action: str) -> None:
    if not confirm:
        raise ValueError(f"Mutation '{action}' requires confirm=True")


def _promote_payload(
    *,
    title: str,
    description: str,
    priority: str,
    severity: str | None,
    tags: list[str] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"priority": priority or "high"}
    if title:
        payload["title"] = title
    if description:
        payload["description"] = description
    if severity:
        payload["severity"] = severity
    if tags:
        payload["tags"] = tags
    return payload


async def case_assist(
    client: PlatformClient,
    *,
    action: Literal[
        "get",
        "list",
        "create_draft",
        "update",
        "add_note",
        "add_point",
        "add_ioc",
        "delete",
        "promote",
    ],
    case_id: str | None = None,
    title: str = "",
    description: str = "",
    priority: str = "medium",
    status: str | None = None,
    note: str = "",
    collection: str = "",
    point_id: str = "",
    ioc_type: str = "",
    ioc_value: str = "",
    limit: int = 20,
    confirm: bool = False,
    promote_kind: PromoteKind | None = None,
    alert_id: str = "",
    detection_key: str = "",
    connector: str = "",
    event_id: str = "",
    incident_id: str = "",
    severity: str = "",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    if action == "list":
        return await client.tip_get("/api/v1/cases", params={"limit": limit})

    if action == "get":
        if not case_id:
            raise ValueError("case_id is required for get")
        return await client.tip_get(f"/api/v1/cases/{case_id}")

    if action == "create_draft":
        if confirm:
            _require_confirm(True, action)
            return await client.tip_post(
                "/api/v1/cases",
                json={
                    "title": title or "Untitled investigation",
                    "description": description,
                    "priority": priority,
                },
            )
        return {
            "draft": True,
            "action": "create_case",
            "payload": {
                "title": title or "Untitled investigation",
                "description": description,
                "priority": priority,
            },
            "message": "Set confirm=True to create the case.",
        }

    if action == "promote":
        return await _promote_triage(
            client,
            promote_kind=promote_kind,
            alert_id=alert_id,
            detection_key=detection_key,
            connector=connector,
            event_id=event_id,
            incident_id=incident_id,
            title=title,
            description=description,
            priority=priority if priority != "medium" else "high",
            severity=severity or None,
            tags=tags,
            confirm=confirm,
        )

    if not case_id:
        raise ValueError("case_id is required")

    if action == "update":
        updates = {k: v for k, v in {"status": status, "priority": priority, "description": description}.items() if v}
        if not confirm:
            return {"draft": True, "case_id": case_id, "updates": updates, "message": "Set confirm=True to apply."}
        _require_confirm(confirm, action)
        return await client.tip_patch(f"/api/v1/cases/{case_id}", json=updates)

    if action == "add_note":
        if not note:
            raise ValueError("note is required")
        if not confirm:
            return {"draft": True, "case_id": case_id, "note": note, "message": "Set confirm=True to add note."}
        _require_confirm(confirm, action)
        return await client.tip_post(f"/api/v1/cases/{case_id}/notes", json={"content": note})

    if action == "add_point":
        if not collection or not point_id:
            raise ValueError("collection and point_id are required")
        if not confirm:
            return {
                "draft": True,
                "case_id": case_id,
                "collection": collection,
                "point_id": point_id,
                "message": "Set confirm=True to attach evidence point.",
            }
        _require_confirm(confirm, action)
        return await client.tip_post(
            f"/api/v1/cases/{case_id}/points",
            json={"collection": collection, "point_id": point_id},
        )

    if action == "add_ioc":
        if not ioc_type or not ioc_value:
            raise ValueError("ioc_type and ioc_value are required")
        if not confirm:
            return {
                "draft": True,
                "case_id": case_id,
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "message": "Set confirm=True to attach IOC.",
            }
        _require_confirm(confirm, action)
        return await client.tip_post(
            f"/api/v1/cases/{case_id}/iocs",
            json={"ioc_type": ioc_type, "ioc_value": ioc_value},
        )

    if action == "delete":
        if not confirm:
            return {"draft": True, "case_id": case_id, "message": "Set confirm=True to delete case."}
        _require_confirm(confirm, action)
        return await client.tip_delete(f"/api/v1/cases/{case_id}")

    raise ValueError(f"Unknown action: {action}")


async def _promote_triage(
    client: PlatformClient,
    *,
    promote_kind: PromoteKind | None,
    alert_id: str,
    detection_key: str,
    connector: str,
    event_id: str,
    incident_id: str,
    title: str,
    description: str,
    priority: str,
    severity: str | None,
    tags: list[str] | None,
    confirm: bool,
) -> dict[str, Any]:
    if promote_kind not in {"alert", "detection", "webhook", "detection_incident"}:
        raise ValueError(
            "promote requires promote_kind: alert | detection | webhook | detection_incident",
        )

    base = _promote_payload(
        title=title,
        description=description,
        priority=priority,
        severity=severity,
        tags=tags,
    )

    if promote_kind == "alert":
        if not alert_id:
            raise ValueError("alert_id is required for promote_kind=alert")
        path = f"/api/v1/alerts/{alert_id}/promote"
        payload = base
    elif promote_kind == "detection":
        if not detection_key:
            raise ValueError("detection_key is required for promote_kind=detection")
        path = "/api/v1/detections/promote"
        payload = {**base, "detection_key": detection_key, "connector": connector}
    elif promote_kind == "webhook":
        if not event_id:
            raise ValueError("event_id is required for promote_kind=webhook")
        path = f"/api/v1/webhook-events/{event_id}/promote"
        payload = base
    else:
        if not incident_id:
            raise ValueError("incident_id is required for promote_kind=detection_incident")
        path = "/api/v1/detection-incidents/promote"
        payload = {**base, "incident_id": incident_id}

    if not confirm:
        return {
            "draft": True,
            "action": "promote",
            "promote_kind": promote_kind,
            "path": path,
            "payload": payload,
            "message": "Set confirm=True to promote into a TIP case.",
        }

    _require_confirm(confirm, "promote")
    return await client.tip_post(path, json=payload)


def register_case_assist(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_case_assist")
    async def case_assist_tool(
        action: str,
        case_id: str = "",
        title: str = "",
        description: str = "",
        priority: str = "medium",
        status: str = "",
        note: str = "",
        collection: str = "",
        point_id: str = "",
        ioc_type: str = "",
        ioc_value: str = "",
        limit: int = 20,
        confirm: bool = False,
        promote_kind: str = "",
        alert_id: str = "",
        detection_key: str = "",
        connector: str = "",
        event_id: str = "",
        incident_id: str = "",
        severity: str = "",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """List/inspect/mutate cases or promote triage items (mutations require confirm=True)."""
        return await case_assist(
            client,
            action=action,  # type: ignore[arg-type]
            case_id=case_id or None,
            title=title,
            description=description,
            priority=priority,
            status=status or None,
            note=note,
            collection=collection,
            point_id=point_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            limit=limit,
            confirm=confirm,
            promote_kind=promote_kind or None,  # type: ignore[arg-type]
            alert_id=alert_id,
            detection_key=detection_key,
            connector=connector,
            event_id=event_id,
            incident_id=incident_id,
            severity=severity,
            tags=tags,
        )
