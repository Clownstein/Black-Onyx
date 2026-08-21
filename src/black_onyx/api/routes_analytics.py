"""Operations analytics, triage feed, alert disposition/promote, and query API."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from black_onyx.auth.dependencies import current_principal, require_analyst
from black_onyx.auth.service import Principal
from black_onyx.threat.analytics import AnalyticsEngine
from black_onyx.threat.query_executor import QueryExecutor
from black_onyx.threat.watchlist_manager import DISPOSITIONS

logger = logging.getLogger(__name__)

analytics_router = APIRouter(tags=["analytics"])


def _get_service():
    from black_onyx.api.service import get_service
    return get_service()


def _safe_attr(service: Any, name: str) -> Any:
    try:
        return getattr(service, name)
    except Exception:
        logger.debug("analytics optional dependency %s unavailable", name, exc_info=True)
        return None


def _engine() -> AnalyticsEngine:
    service = _get_service()
    return AnalyticsEngine(
        watchlist_manager=service.watchlist_manager,
        case_manager=service.case_manager,
        connector_manager=_safe_attr(service, "connector_manager"),
        decay_manager=_safe_attr(service, "decay_manager"),
        feed_manager=_safe_attr(service, "feed_manager"),
        qdrant_store=_safe_attr(service, "qdrant_store"),
        detection_rules_manager=_safe_attr(service, "detection_rules_manager"),
        attack_mapper=_safe_attr(service, "attack_mapper"),
        playbook_manager=_safe_attr(service, "playbook_manager"),
        enrichment_manager=_safe_attr(service, "enrichment_manager"),
        webhook_manager=_safe_attr(service, "webhook_manager"),
        taxii_manager=_safe_attr(service, "taxii_manager"),
        asset_manager=_safe_attr(service, "asset_manager"),
    )


class AlertDispositionRequest(BaseModel):
    disposition: str = Field(min_length=1, max_length=64)
    note: str = Field(default="", max_length=10_000)
    suppress_item: bool = False
    lower_confidence: bool = False
    confidence_delta: float = Field(default=0.25, ge=0.0, le=1.0)
    misp_note: bool = False


class DetectionDispositionRequest(BaseModel):
    detection_key: str = Field(min_length=1, max_length=500)
    disposition: str = Field(min_length=1, max_length=64)
    note: str = Field(default="", max_length=10_000)
    connector: str = Field(default="", max_length=200)
    title: str = Field(default="", max_length=500)


class DetectionAckRequest(BaseModel):
    detection_key: str = Field(min_length=1, max_length=500)


class WebhookEventDispositionRequest(BaseModel):
    disposition: str = Field(min_length=1, max_length=64)
    note: str = Field(default="", max_length=10_000)


class AlertPromoteRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = Field(default=None, max_length=100_000)
    priority: str = Field(default="high", max_length=32)
    severity: Optional[str] = Field(default=None, max_length=32)
    assignee: Optional[str] = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=100)


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4_000)
    limit: int = Field(default=100, ge=1, le=5_000)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


@analytics_router.get("/api/v1/analytics/overview")
async def analytics_overview(
    range: str = Query(default="7d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    try:
        return _engine().overview(range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@analytics_router.get("/api/v1/analytics/timeseries")
async def analytics_timeseries(
    metric: str = Query(default="alerts"),
    group_by: str = Query(default="day"),
    range: str = Query(default="7d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    try:
        return _engine().timeseries(metric=metric, group_by=group_by, range_str=range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@analytics_router.get("/api/v1/analytics/distributions")
async def analytics_distributions(
    metric: str = Query(default="ioc_type"),
    range: str = Query(default="7d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    try:
        return _engine().distributions(metric=metric, range_str=range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@analytics_router.get("/api/v1/analytics/kpis")
async def analytics_kpis(
    metrics: str = Query(default="mtta,mttr,fpr"),
    range: str = Query(default="7d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    names = [m.strip() for m in metrics.split(",") if m.strip()]
    if not names:
        raise HTTPException(status_code=422, detail="metrics query parameter is required")
    try:
        return _engine().kpis(names, range_str=range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@analytics_router.get("/api/v1/analytics/attack/coverage")
async def analytics_attack_coverage(
    range: str = Query(default="30d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    try:
        return _engine().attack_coverage(range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@analytics_router.get("/api/v1/analytics/cti/impact")
async def analytics_cti_impact(
    range: str = Query(default="30d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    try:
        return _engine().cti_impact(range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@analytics_router.get("/api/v1/analytics/connectors/health")
async def analytics_connectors_health(
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    return _engine().connectors_health()


@analytics_router.get("/api/v1/analytics/playbooks")
async def analytics_playbooks(
    range: str = Query(default="30d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    try:
        return _engine().playbook_analytics(range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Saved analytic views (per-user + optional role defaults)
# ---------------------------------------------------------------------------


class AnalyticsViewRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    range: str = Field(default="30d", max_length=16)
    tab: str = Field(default="volume", max_length=32)
    role_default: Optional[Literal["admin", "analyst", "viewer"]] = None


def _auth_db():
    from black_onyx.auth.context import get_auth_service
    return get_auth_service().db


@analytics_router.get("/api/v1/analytics/views")
async def list_analytics_views(
    principal: Principal = Depends(current_principal),
) -> dict[str, Any]:
    rows = _auth_db()._conn.execute(
        """
        SELECT view_id, owner_user_id, name, range_key, tab_key, role_default, created_at, updated_at
        FROM analytics_views
        WHERE owner_user_id = ?
           OR role_default = ?
        ORDER BY
          CASE WHEN owner_user_id = ? THEN 0 ELSE 1 END,
          updated_at DESC
        """,
        (principal.user_id, principal.role, principal.user_id),
    ).fetchall()
    views = []
    for row in rows:
        views.append({
            "view_id": row["view_id"],
            "name": row["name"],
            "range": row["range_key"],
            "tab": row["tab_key"],
            "role_default": row["role_default"],
            "owned": row["owner_user_id"] == principal.user_id,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return {"views": views, "n": len(views)}


@analytics_router.post("/api/v1/analytics/views")
async def save_analytics_view(
    req: AnalyticsViewRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    role_default = req.role_default
    if role_default and principal.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only admins can publish role-default analytic views",
        )
    with _auth_db().transaction() as db:
        existing = db.execute(
            "SELECT view_id FROM analytics_views WHERE owner_user_id=? AND name=?",
            (principal.user_id, req.name.strip()),
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE analytics_views SET range_key=?, tab_key=?, role_default=?, updated_at=? "
                "WHERE view_id=?",
                (req.range, req.tab, role_default, now, existing["view_id"]),
            )
            view_id = existing["view_id"]
        else:
            view_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO analytics_views("
                "view_id, owner_user_id, name, range_key, tab_key, role_default, created_at, updated_at"
                ") VALUES (?,?,?,?,?,?,?,?)",
                (
                    view_id, principal.user_id, req.name.strip(), req.range, req.tab,
                    role_default, now, now,
                ),
            )
    return {
        "view_id": view_id,
        "name": req.name.strip(),
        "range": req.range,
        "tab": req.tab,
        "role_default": role_default,
        "owned": True,
    }


@analytics_router.delete("/api/v1/analytics/views/{view_id}")
async def delete_analytics_view(
    view_id: str,
    principal: Principal = Depends(require_analyst),
) -> dict[str, str]:
    with _auth_db().transaction() as db:
        row = db.execute(
            "SELECT view_id FROM analytics_views WHERE view_id=? AND owner_user_id=?",
            (view_id, principal.user_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="View not found")
        db.execute("DELETE FROM analytics_views WHERE view_id=?", (view_id,))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Triage feed
# ---------------------------------------------------------------------------


@analytics_router.get("/api/v1/triage")
async def triage_feed(
    limit: int = Query(default=50, ge=1, le=500),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    """Unified triage queue: watchlist alerts + connector detections + webhook events."""
    service = _get_service()
    now = datetime.now()
    items: list[dict[str, Any]] = []

    for alert in service.watchlist_manager.get_alerts(limit=limit, unacknowledged_only=False):
        triggered = alert.get("triggered_at") or ""
        age_seconds = None
        try:
            if triggered:
                age_seconds = max(0, (now - datetime.fromisoformat(triggered)).total_seconds())
        except ValueError:
            age_seconds = None
        items.append({
            "id": alert.get("alert_id"),
            "alert_id": alert.get("alert_id"),
            "kind": "watchlist_alert",
            "severity": "high" if not alert.get("acknowledged") else "medium",
            "source": alert.get("watchlist_name") or "watchlist",
            "title": f"Watchlist hit: {alert.get('ioc_value') or 'IOC'}",
            "ioc": f"{alert.get('ioc_type') or '?'}: {alert.get('ioc_value') or '—'}",
            "ioc_type": alert.get("ioc_type") or "",
            "ioc_value": alert.get("ioc_value") or "",
            "technique_ids": [],
            "age_seconds": age_seconds,
            "age": triggered,
            "triggered_at": triggered,
            "acknowledged": bool(alert.get("acknowledged")),
            "disposition": alert.get("disposition"),
            "promoted_case_id": alert.get("promoted_case_id"),
            "raw": alert,
        })

    try:
        detections = service.connector_manager.list_recent_detections(
            service.qdrant_store, limit=limit,
        )
    except Exception:
        logger.debug("triage detections unavailable", exc_info=True)
        detections = []

    for det in detections:
        indexed = det.get("indexed_at") or ""
        age_seconds = None
        try:
            if indexed:
                age_seconds = max(0, (now - datetime.fromisoformat(indexed)).total_seconds())
        except ValueError:
            age_seconds = None
        status = str(det.get("ioc_status") or "").lower()
        severity = "high" if "malicious" in status else ("medium" if status else "low")
        det_severity = str(det.get("severity") or "").lower() or severity
        detection_key = det.get("detection_key") or det.get("source_file") or ""
        items.append({
            "id": f"det:{det.get('connector')}:{detection_key or det.get('title')}",
            "detection_key": detection_key,
            "kind": "detection",
            "severity": det_severity,
            "source": det.get("connector") or "connector",
            "title": det.get("title") or det.get("source_file") or "Detection",
            "ioc_type": "",
            "ioc_value": "",
            "technique_ids": det.get("technique_ids") or [],
            "age_seconds": age_seconds,
            "triggered_at": det.get("event_time") or indexed,
            "event_time": det.get("event_time"),
            "indexed_at": indexed,
            "acknowledged": bool(det.get("acknowledged")),
            "disposition": det.get("disposition"),
            "promoted_case_id": det.get("promoted_case_id"),
            "raw": det,
        })

    try:
        webhook_events = service.webhook_manager.list_events(limit=limit)
    except Exception:
        logger.debug("triage webhook events unavailable", exc_info=True)
        webhook_events = []

    for event in webhook_events:
        created = event.get("created_at") or ""
        age_seconds = None
        try:
            if created:
                age_seconds = max(0, (now - datetime.fromisoformat(created)).total_seconds())
        except ValueError:
            age_seconds = None
        iocs = event.get("iocs") or {}
        first_type = ""
        first_value = ""
        for key, values in iocs.items():
            if values:
                first_type = key
                first_value = str(values[0])
                break
        items.append({
            "id": f"wh:{event.get('event_id')}",
            "event_id": event.get("event_id"),
            "kind": "webhook_event",
            "severity": "medium" if not event.get("acknowledged") else "low",
            "source": event.get("webhook_name") or event.get("source") or "webhook",
            "title": f"Webhook: {event.get('webhook_name') or 'event'} ({event.get('ioc_count') or 0} IOCs)",
            "ioc": f"{first_type}: {first_value}" if first_value else f"{event.get('ioc_count') or 0} indicators",
            "ioc_type": first_type,
            "ioc_value": first_value,
            "technique_ids": [],
            "age_seconds": age_seconds,
            "triggered_at": created,
            "acknowledged": bool(event.get("acknowledged")),
            "disposition": event.get("disposition"),
            "promoted_case_id": event.get("promoted_case_id"),
            "raw": event,
        })

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    items.sort(
        key=lambda x: (
            severity_rank.get(str(x.get("severity")), 9),
            -(x.get("age_seconds") or 0),
        ),
    )
    items = items[:limit]
    return {"items": items, "n": len(items)}


# ---------------------------------------------------------------------------
# Alert disposition / promote
# ---------------------------------------------------------------------------


@analytics_router.post("/api/v1/alerts/{alert_id}/disposition")
async def dispose_alert(
    alert_id: str,
    req: AlertDispositionRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    if req.disposition not in DISPOSITIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid disposition. Allowed: {', '.join(sorted(DISPOSITIONS))}",
        )
    mgr = _get_service().watchlist_manager
    if not mgr.get_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        updated = mgr.dispose_alert(
            alert_id,
            disposition=req.disposition,
            disposition_by=principal.user_id,
            disposition_note=req.note,
            suppress_item=req.suppress_item,
            lower_confidence=req.lower_confidence,
            confidence_delta=req.confidence_delta,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    misp_result: dict[str, Any] | None = None
    if req.misp_note and req.disposition == "false_positive":
        service = _get_service()
        misp = _safe_attr(service, "misp_manager")
        if misp and hasattr(misp, "publish_from_iocs"):
            try:
                ioc_type = str(updated.get("ioc_type") or "other")
                ioc_value = str(updated.get("ioc_value") or "")
                info = (
                    f"FP disposition note from Black Onyx alert {alert_id}. "
                    f"{req.note or 'Marked false_positive; consider sighting/comment in MISP.'}"
                )
                misp_result = misp.publish_from_iocs(
                    case_id=f"fp-{alert_id}",
                    iocs=[{"ioc_type": ioc_type, "ioc_value": ioc_value}] if ioc_value else [],
                    info=info,
                )
            except Exception as exc:
                logger.warning("MISP FP note failed: %s", exc)
                misp_result = {"error": str(exc)}
        else:
            misp_result = {"skipped": "MISP not configured"}
    return {"status": "ok", "alert": updated, "misp": misp_result}


@analytics_router.post("/api/v1/detections/disposition")
async def dispose_detection(
    req: DetectionDispositionRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    if req.disposition not in DISPOSITIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid disposition. Allowed: {', '.join(sorted(DISPOSITIONS))}",
        )
    mgr = _get_service().connector_manager
    try:
        updated = mgr.dispose_detection(
            req.detection_key,
            disposition=req.disposition,
            disposition_by=principal.user_id,
            disposition_note=req.note,
            connector=req.connector,
            title=req.title,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "ok", "detection": updated}


@analytics_router.post("/api/v1/detections/acknowledge")
async def acknowledge_detection(
    req: DetectionAckRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    updated = _get_service().connector_manager.acknowledge_detection(req.detection_key)
    return {"status": "ok", "detection": updated}


@analytics_router.post("/api/v1/webhook-events/{event_id}/disposition")
async def dispose_webhook_event(
    event_id: str,
    req: WebhookEventDispositionRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    if req.disposition not in DISPOSITIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid disposition. Allowed: {', '.join(sorted(DISPOSITIONS))}",
        )
    mgr = _get_service().webhook_manager
    if not mgr.get_event(event_id):
        raise HTTPException(status_code=404, detail="Webhook event not found")
    try:
        updated = mgr.dispose_event(
            event_id,
            disposition=req.disposition,
            disposition_by=principal.user_id,
            disposition_note=req.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "ok", "event": updated}


@analytics_router.post("/api/v1/webhook-events/{event_id}/acknowledge")
async def acknowledge_webhook_event(
    event_id: str,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    updated = _get_service().webhook_manager.acknowledge_event(event_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Webhook event not found")
    return {"status": "ok", "event": updated}


@analytics_router.post("/api/v1/alerts/{alert_id}/promote")
async def promote_alert(
    alert_id: str,
    req: AlertPromoteRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    service = _get_service()
    alert = service.watchlist_manager.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.get("promoted_case_id"):
        return {
            "status": "ok",
            "case_id": alert["promoted_case_id"],
            "alert": alert,
            "message": "Alert already promoted",
        }

    title = req.title or f"Alert: {alert.get('ioc_value') or alert_id}"
    description = req.description or (
        f"Promoted from watchlist alert {alert_id}. "
        f"IOC {alert.get('ioc_type')}={alert.get('ioc_value')} "
        f"(watchlist={alert.get('watchlist_name')})."
    )
    detected_at = alert.get("triggered_at") or datetime.now(timezone.utc).isoformat()
    case = service.case_manager.create_case(
        title=title,
        description=description,
        priority=req.priority,
        assignee=req.assignee or principal.user_id,
        tags=req.tags or ["promoted-alert"],
        severity=req.severity,
        detected_at=detected_at,
    )
    updated = service.watchlist_manager.set_promoted_case_id(alert_id, case.case_id)
    if updated is None:
        # Lost the race — discard the orphan case and return the winner's link.
        existing = service.watchlist_manager.get_alert(alert_id) or alert
        try:
            service.case_manager.delete_case(case.case_id)
        except Exception:
            logger.debug("orphan promote case cleanup failed", exc_info=True)
        return {
            "status": "ok",
            "case_id": existing.get("promoted_case_id"),
            "alert": existing,
            "message": "Alert already promoted",
        }
    if alert.get("ioc_type") and alert.get("ioc_value"):
        service.case_manager.add_ioc_to_case(
            case.case_id, str(alert["ioc_type"]), str(alert["ioc_value"]),
        )
    if alert.get("collection") and alert.get("point_id"):
        service.case_manager.add_point_to_case(
            case.case_id, str(alert["collection"]), str(alert["point_id"]),
        )
    service.case_manager.add_timeline_event(
        case.case_id,
        "alert_promoted",
        f"Created from alert {alert_id}",
        author=principal.user_id,
    )
    return {
        "status": "ok",
        "case_id": case.case_id,
        "case": case.__dict__,
        "alert": updated,
    }


class DetectionPromoteRequest(AlertPromoteRequest):
    detection_key: str = Field(min_length=1, max_length=500)
    connector: str = Field(default="", max_length=200)
    detection_title: str = Field(default="", max_length=500)


@analytics_router.post("/api/v1/detections/promote")
async def promote_detection(
    req: DetectionPromoteRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    service = _get_service()
    mgr = service.connector_manager
    existing = mgr.get_detection_disposition(req.detection_key)
    if existing and existing.get("promoted_case_id"):
        return {
            "status": "ok",
            "case_id": existing["promoted_case_id"],
            "detection": existing,
            "message": "Detection already promoted",
        }
    title = req.title or req.detection_title or f"Detection: {req.detection_key}"
    description = req.description or f"Promoted from connector detection {req.detection_key}."
    case = service.case_manager.create_case(
        title=title,
        description=description,
        priority=req.priority,
        assignee=req.assignee or principal.user_id,
        tags=req.tags or ["promoted-detection"],
        severity=req.severity,
    )
    try:
        updated = mgr.set_detection_promoted_case(req.detection_key, case.case_id)
    except LookupError as exc:
        try:
            service.case_manager.delete_case(case.case_id)
        except Exception:
            logger.debug("orphan promote case cleanup failed", exc_info=True)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if updated is None:
        existing = mgr.get_detection_disposition(req.detection_key) or {}
        try:
            service.case_manager.delete_case(case.case_id)
        except Exception:
            logger.debug("orphan promote case cleanup failed", exc_info=True)
        return {
            "status": "ok",
            "case_id": existing.get("promoted_case_id"),
            "detection": existing,
            "message": "Detection already promoted",
        }
    service.case_manager.add_timeline_event(
        case.case_id,
        "detection_promoted",
        f"Created from detection {req.detection_key} ({req.connector or 'connector'})",
        author=principal.user_id,
    )
    return {
        "status": "ok",
        "case_id": case.case_id,
        "case": case.__dict__,
        "detection": updated,
    }


@analytics_router.post("/api/v1/webhook-events/{event_id}/promote")
async def promote_webhook_event(
    event_id: str,
    req: AlertPromoteRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    service = _get_service()
    event = service.webhook_manager.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Webhook event not found")
    if event.get("promoted_case_id"):
        return {
            "status": "ok",
            "case_id": event["promoted_case_id"],
            "event": event,
            "message": "Webhook event already promoted",
        }
    title = req.title or f"Webhook: {event.get('source') or event_id}"
    description = req.description or (
        f"Promoted from webhook event {event_id} "
        f"(source={event.get('source')}, iocs={event.get('ioc_count')})."
    )
    case = service.case_manager.create_case(
        title=title,
        description=description,
        priority=req.priority,
        assignee=req.assignee or principal.user_id,
        tags=req.tags or ["promoted-webhook"],
        severity=req.severity,
        detected_at=event.get("created_at"),
    )
    updated = service.webhook_manager.set_event_promoted_case(event_id, case.case_id)
    if updated is None:
        existing = service.webhook_manager.get_event(event_id) or event
        try:
            service.case_manager.delete_case(case.case_id)
        except Exception:
            logger.debug("orphan promote case cleanup failed", exc_info=True)
        return {
            "status": "ok",
            "case_id": existing.get("promoted_case_id"),
            "event": existing,
            "message": "Webhook event already promoted",
        }
    iocs = event.get("iocs") or {}
    if isinstance(iocs, dict):
        for ioc_type, values in iocs.items():
            if not isinstance(values, list):
                continue
            for value in values[:20]:
                try:
                    service.case_manager.add_ioc_to_case(case.case_id, str(ioc_type), str(value))
                except Exception:
                    logger.debug("webhook promote IOC attach failed", exc_info=True)
    service.case_manager.add_timeline_event(
        case.case_id,
        "webhook_promoted",
        f"Created from webhook event {event_id}",
        author=principal.user_id,
    )
    return {
        "status": "ok",
        "case_id": case.case_id,
        "case": case.__dict__,
        "event": updated,
    }


class DetectionIncidentPromoteRequest(AlertPromoteRequest):
    incident_id: str = Field(min_length=1, max_length=128)
    incident_title: str = Field(default="", max_length=500)


@analytics_router.post("/api/v1/detection-incidents/promote")
async def promote_detection_incident(
    req: DetectionIncidentPromoteRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Promote a Postgres detection-spine incident into a TIP case (link via external_incident_id)."""
    service = _get_service()
    existing = service.case_manager.get_case_by_external_incident(req.incident_id)
    if existing:
        return {
            "status": "ok",
            "case_id": existing.case_id,
            "case": existing.__dict__,
            "message": "Incident already linked to a case",
        }
    title = req.title or req.incident_title or f"Detection incident {req.incident_id}"
    description = req.description or (
        f"Promoted from detection-spine incident {req.incident_id}. "
        "Incident SoR remains Postgres; this case holds TIP notes/IOCs."
    )
    case = service.case_manager.create_case(
        title=title,
        description=description,
        priority=req.priority,
        assignee=req.assignee or principal.user_id,
        tags=req.tags or ["promoted-detection-incident", "detection-spine"],
        severity=req.severity,
        external_incident_id=req.incident_id,
    )
    service.case_manager.add_timeline_event(
        case.case_id,
        "detection_incident_promoted",
        f"Linked to detection incident {req.incident_id}",
        author=principal.user_id,
    )
    return {
        "status": "ok",
        "case_id": case.case_id,
        "case": case.__dict__,
        "external_incident_id": req.incident_id,
    }


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


_EVIDENCE_MAX_POINTS = 400
_EVIDENCE_MAX_COLLECTIONS = 8


def _evidence_rows(service: Any, *, max_points: int = _EVIDENCE_MAX_POINTS) -> list[dict[str, Any]]:
    """Flatten Qdrant payloads into queryable evidence rows (hard-capped)."""
    store = getattr(service, "qdrant_store", None)
    if store is None:
        return []
    rows: list[dict[str, Any]] = []
    try:
        collections = store.list_collections() or []
    except Exception:
        logger.debug("evidence query: list_collections failed", exc_info=True)
        return []
    collections = collections[:_EVIDENCE_MAX_COLLECTIONS]
    per_collection = max(25, max_points // max(len(collections), 1))
    for coll in collections:
        name = coll.get("name") if isinstance(coll, dict) else str(coll)
        if not name:
            continue
        offset: Any = None
        remaining = min(per_collection, max_points - len(rows))
        while remaining > 0:
            try:
                points, offset = store.scroll(
                    name,
                    limit=min(50, remaining),
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )
            except Exception:
                logger.debug("evidence query: scroll failed for %s", name, exc_info=True)
                break
            for point in points or []:
                payload = getattr(point, "payload", None) or {}
                if not isinstance(payload, dict):
                    payload = {}
                text = (
                    payload.get("text")
                    or payload.get("content")
                    or payload.get("chunk")
                    or ""
                )
                rows.append({
                    "collection": name,
                    "point_id": str(getattr(point, "id", "")),
                    "source_file": payload.get("source_file") or payload.get("source") or "",
                    "payload_type": payload.get("payload_type") or payload.get("type") or "",
                    "text": str(text)[:2_000],
                    "indexed_at": payload.get("indexed_at") or payload.get("created_at") or "",
                    "title": payload.get("title") or payload.get("filename") or "",
                })
                if len(rows) >= max_points:
                    return rows
            remaining = min(per_collection, max_points - len(rows))
            if offset is None or not points:
                break
    return rows


def _query_has_bound(query: str) -> bool:
    """Evidence source requires a where/ago/limit constraint to avoid unbounded scroll."""
    stages = [s.strip().lower() for s in query.split("|")[1:] if s.strip()]
    for stage in stages:
        if stage.startswith("where ") or stage.startswith("limit "):
            return True
    return False


@analytics_router.post("/api/v1/query")
async def run_query(
    req: QueryRequest,
    user: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Run a KQL/SPL-subset filter against local operational metadata.

    Subset: ``source alerts|cases|assets|detections|evidence|webhooks`` then
    ``| where field==value``, ``| where field contains value``,
    ``| where field ago 7d``, ``| project a,b``, ``| limit N``.
    """
    service = _get_service()
    raw = req.query.strip()
    source_token = raw.split("|", 1)[0].strip().split()
    source_name = source_token[-1].lower() if source_token else ""
    if source_name == "evidence" and not _query_has_bound(raw):
        raise HTTPException(
            status_code=422,
            detail="evidence queries require a where or limit stage "
            "(e.g. `evidence | where indexed_at ago 7d | limit 50`)",
        )

    registry_assets: list[dict[str, Any]] = []
    if source_name == "assets":
        from black_onyx.api.routes_assets import (
            AssetRegistryUnavailable,
            _list_registry_assets,
        )

        try:
            registry_assets = await _list_registry_assets(user)
        except AssetRegistryUnavailable as exc:
            raise HTTPException(status_code=502, detail="Asset registry unavailable") from exc

    def _cases() -> list[dict[str, Any]]:
        return [c.__dict__ for c in service.case_manager.list_cases(limit=5_000)]

    def _detections() -> list[dict[str, Any]]:
        try:
            return service.connector_manager.list_recent_detections(
                service.qdrant_store, limit=500,
            )
        except Exception:
            return []

    def _webhooks() -> list[dict[str, Any]]:
        try:
            return service.webhook_manager.list_events(limit=1_000)
        except Exception:
            return []

    executor = QueryExecutor(
        alerts_loader=lambda: service.watchlist_manager.get_alerts(limit=5_000),
        cases_loader=_cases,
        assets_loader=lambda: registry_assets,
        detections_loader=_detections,
        evidence_loader=lambda: _evidence_rows(service),
        webhooks_loader=_webhooks,
    )
    try:
        return executor.execute(req.query, default_limit=min(req.limit, 500))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
