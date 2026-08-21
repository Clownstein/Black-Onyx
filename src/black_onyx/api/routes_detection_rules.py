"""Detection rules store API — Sigma/YARA create, validate, export, analytics."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from black_onyx.auth.dependencies import current_principal, require_analyst
from black_onyx.auth.service import Principal
from black_onyx.threat.detection_rules_manager import DetectionRulesManager

detection_rules_router = APIRouter(tags=["detection-rules"])


def _get_service():
    from black_onyx.api.service import get_service
    return get_service()


class RuleCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    rule_type: str = Field(min_length=1, max_length=16)
    content: str = Field(min_length=1, max_length=500_000)
    source: str = Field(default="authored", max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=100)
    status: str = Field(default="draft", max_length=32)


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    content: Optional[str] = Field(default=None, min_length=1, max_length=500_000)
    status: Optional[str] = Field(default=None, max_length=32)
    tags: Optional[list[str]] = Field(default=None, max_length=100)
    source: Optional[str] = Field(default=None, max_length=64)


class RuleValidateRequest(BaseModel):
    rule_type: str = Field(min_length=1, max_length=16)
    content: str = Field(min_length=1, max_length=500_000)


class RuleExportRequest(BaseModel):
    rule_ids: Optional[list[str]] = Field(default=None, max_length=5_000)
    status: Optional[str] = Field(default="approved", max_length=32)


@detection_rules_router.get("/api/v1/detection-rules")
async def list_rules(
    rule_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    rules = _get_service().detection_rules_manager.list_rules(
        rule_type=rule_type, status=status, limit=max(1, min(limit, 1000)),
    )
    return {"rules": rules, "n": len(rules)}


@detection_rules_router.post("/api/v1/detection-rules")
async def create_rule(
    req: RuleCreateRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return _get_service().detection_rules_manager.create_rule(
            name=req.name,
            rule_type=req.rule_type,
            content=req.content,
            author=principal.user_id,
            source=req.source,
            tags=req.tags,
            status=req.status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@detection_rules_router.post("/api/v1/detection-rules/validate")
async def validate_rule(
    req: RuleValidateRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    return DetectionRulesManager.validate_rule(req.rule_type, req.content)


@detection_rules_router.get("/api/v1/detection-rules/analytics")
async def rules_analytics(
    range: str = Query(default="30d", alias="range"),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    from black_onyx.threat.analytics import range_start
    try:
        since = range_start(range).isoformat()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _get_service().detection_rules_manager.analytics(since_iso=since)


@detection_rules_router.post("/api/v1/detection-rules/export")
async def export_rules(
    req: RuleExportRequest,
    _: Principal = Depends(require_analyst),
) -> Response:
    data = _get_service().detection_rules_manager.export_package(
        rule_ids=req.rule_ids, status=req.status,
    )
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="detection-rules.zip"'},
    )


@detection_rules_router.get("/api/v1/detection-rules/{rule_id}")
async def get_rule(
    rule_id: str,
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    rule = _get_service().detection_rules_manager.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


class RuleDryRunRequest(BaseModel):
    max_points: int = Field(default=400, ge=20, le=2_000)


@detection_rules_router.post("/api/v1/detection-rules/{rule_id}/dry-run")
async def dry_run_rule(
    rule_id: str,
    req: RuleDryRunRequest | None = None,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Evidence dry-run: string-match rule literals against ingested payloads (not live detection)."""
    service = _get_service()
    if not service.detection_rules_manager.get_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        return service.detection_rules_manager.dry_run_against_evidence(
            rule_id,
            service.qdrant_store,
            max_points=(req.max_points if req else 400),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@detection_rules_router.patch("/api/v1/detection-rules/{rule_id}")
async def update_rule(
    rule_id: str,
    req: RuleUpdateRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    if not _get_service().detection_rules_manager.get_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if updates.get("status") == "approved":
        updates["approved_by"] = principal.user_id
    try:
        return _get_service().detection_rules_manager.update_rule(rule_id, **updates)  # type: ignore[return-value]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@detection_rules_router.delete("/api/v1/detection-rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    _: Principal = Depends(require_analyst),
) -> dict[str, str]:
    if not _get_service().detection_rules_manager.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "ok"}
