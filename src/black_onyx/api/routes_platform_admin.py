"""Administrator settings inventory and deployment-revision control.

Routes (admin only):
  GET  /api/v1/admin/settings/inventory every setting with source metadata
  GET  /api/v1/admin/deployments revisions (optionally ?target=)
  POST /api/v1/admin/deployments create a draft revision
  GET  /api/v1/admin/deployments/{revision_id} one revision (refreshes apply state)
  POST /api/v1/admin/deployments/{revision_id}/approve approve the previewed draft
  POST /api/v1/admin/deployments/{revision_id}/reject reject a draft/approved revision
  POST /api/v1/admin/deployments/{revision_id}/apply hand an approved revision to the applier
  POST /api/v1/admin/deployments/rollback/{target} draft a rollback to the previous state
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from black_onyx.api.service import get_service
from black_onyx.auth.dependencies import require_admin
from black_onyx.auth.service import Principal

platform_admin_router = APIRouter(tags=["admin-platform"])


class DeploymentRevisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: Literal["compose", "helm"]
    env: dict[str, str | None] = Field(default_factory=dict, max_length=200)
    values: dict[str, Any] = Field(default_factory=dict, max_length=200)
    lab_exception_hours: int | None = Field(default=None, ge=1, le=72)


class DeploymentApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preview_digest: str = Field(min_length=64, max_length=64)


def _controller() -> Any:
    try:
        return get_service().deployment_controller
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _call(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    from black_onyx.ops.deploy_controller import DeploymentError

    try:
        return fn(*args, **kwargs).as_dict()
    except DeploymentError as exc:
        raise HTTPException(status_code=409 if "state" in str(exc) or "Only" in str(exc) else 422,
                            detail=str(exc)) from exc


@platform_admin_router.get("/api/v1/admin/settings/inventory")
async def settings_inventory(_: Principal = Depends(require_admin)) -> dict[str, Any]:
    service = get_service()
    items = service.settings_inventory()
    expired = [rev.revision_id for rev in service.deployment_controller.expired_exceptions()]
    return {
        "items": items,
        "total": len(items),
        "production": service.settings.security.production,
        "expired_exceptions": expired,
    }


@platform_admin_router.get("/api/v1/admin/deployments")
async def list_deployments(
    target: Literal["compose", "helm"] | None = None,
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    controller = _controller()
    revisions = controller.list(target)
    items = [
        controller.refresh(rev.revision_id).as_dict() if rev.status == "applying" else rev.as_dict()
        for rev in revisions
    ]
    return {"items": items, "handoff_configured": controller.handoff_dir is not None}


@platform_admin_router.post("/api/v1/admin/deployments", status_code=201)
async def create_deployment(
    body: DeploymentRevisionCreate,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    return _call(
        _controller().create_revision,
        body.target,
        env_changes=body.env,
        value_changes=body.values,
        actor=principal.user_id,
        lab_exception_hours=body.lab_exception_hours,
    )


@platform_admin_router.get("/api/v1/admin/deployments/{revision_id}")
async def get_deployment(revision_id: str, _: Principal = Depends(require_admin)) -> dict[str, Any]:
    return _call(_controller().refresh, revision_id)


@platform_admin_router.post("/api/v1/admin/deployments/{revision_id}/approve")
async def approve_deployment(
    revision_id: str,
    body: DeploymentApproval,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    return _call(
        _controller().approve, revision_id,
        approver=principal.user_id, preview_digest=body.preview_digest,
    )


@platform_admin_router.post("/api/v1/admin/deployments/{revision_id}/reject")
async def reject_deployment(revision_id: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    return _call(_controller().reject, revision_id, actor=principal.user_id)


@platform_admin_router.post("/api/v1/admin/deployments/{revision_id}/apply")
async def apply_deployment(revision_id: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    return _call(_controller().apply, revision_id, actor=principal.user_id)


@platform_admin_router.post("/api/v1/admin/deployments/rollback/{target}", status_code=201)
async def rollback_deployment(
    target: Literal["compose", "helm"],
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    return _call(_controller().rollback, target, actor=principal.user_id)
