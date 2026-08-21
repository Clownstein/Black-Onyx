"""Response request approval workflow."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from response_orchestrator.config import settings
from response_orchestrator.models import ResponseAudit, ResponseRequest
from response_orchestrator.playbooks import execute_playbook
from response_orchestrator.policy import classify_response_mode, may_auto_execute

try:
    from black_onyx_otel import inc_counter
except ImportError:

    def inc_counter(_name: str, _amount: float = 1.0, **_labels: str) -> None:
        return None


def _audit(
    db: Session,
    *,
    tenant_id: str,
    request_id: str,
    action: str,
    actor: str,
    detail: dict[str, Any] | None = None,
) -> None:
    db.add(
        ResponseAudit(
            tenant_id=tenant_id,
            request_id=request_id,
            action=action,
            actor=actor,
            detail=detail or {},
        )
    )


def create_request(
    db: Session,
    *,
    tenant_id: str,
    incident_id: str,
    playbook_id: str,
    action: str = "execute",
    dry_run: bool | None = None,
    payload: dict[str, Any] | None = None,
    actor: str,
) -> ResponseRequest:
    payload = dict(payload or {})
    signals = dict(payload.get("signals") or {})
    tenant_policy = dict(payload.get("tenant_policy") or {})
    mode = classify_response_mode(signals, tenant_policy)
    auto_ok = may_auto_execute(signals, tenant_policy)

    if dry_run is None:
        dry_run = bool(settings.dry_run_default)
    # Vector-only (or any non-multi-signal) path must remain human-gated:
    # force dry-run regardless of caller request.
    if not auto_ok:
        dry_run = True
        payload["response_mode"] = "suggest_only"
        payload["auto_execute"] = False
    else:
        payload["response_mode"] = mode
        payload["auto_execute"] = True

    request_id = f"resp-{uuid4().hex[:12]}"
    row = ResponseRequest(
        request_id=request_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        playbook_id=playbook_id,
        action=action,
        status="pending",
        dry_run=bool(dry_run),
        payload=payload,
    )
    db.add(row)
    # ResponseAudit has a composite foreign key to ResponseRequest. Without an
    # ORM relationship SQLAlchemy cannot infer the insert order, so persist the
    # parent before queuing its first audit record.
    db.flush()
    _audit(
        db,
        tenant_id=tenant_id,
        request_id=request_id,
        action="requested",
        actor=actor,
        detail={
            "playbook_id": playbook_id,
            "dry_run": row.dry_run,
            "approval_required": True,
            "response_mode": payload.get("response_mode"),
            "auto_execute": bool(payload.get("auto_execute")),
            "signals": signals,
        },
    )
    db.commit()
    db.refresh(row)
    return row


def approve_request(
    db: Session,
    *,
    request_id: str,
    actor: str,
    dry_run_override: bool | None = None,
    tenant_id: str | None = None,
    allow_live_override: bool = False,
) -> ResponseRequest:
    query = db.query(ResponseRequest).filter(ResponseRequest.request_id == request_id)
    if tenant_id:
        query = query.filter(ResponseRequest.tenant_id == tenant_id)
    row = query.one_or_none()
    if row is None:
        raise KeyError(request_id)
    if row.status not in {"pending", "rejected"}:
        raise ValueError(f"cannot approve status={row.status}")

    if dry_run_override is not None:
        if dry_run_override is False and not allow_live_override and bool(row.dry_run):
            raise PermissionError("live override requires elevated approver key")
        row.dry_run = dry_run_override

    row.status = "approved"
    row.approved_by = actor

    exec_payload = dict(row.payload or {})
    exec_payload.setdefault("incident_id", row.incident_id)
    exec_payload.setdefault("tenant_id", row.tenant_id)
    try:
        result = execute_playbook(
            row.playbook_id,
            exec_payload,
            dry_run=bool(row.dry_run),
            approved=True,
        )
        result["action"] = row.action
        if row.dry_run:
            result["message"] = "Dry-run: containment adapters simulated only"
            row.result = result
            row.status = "completed"
        else:
            steps_ok = True
            if isinstance(result.get("steps"), list):
                steps_ok = all(bool(s.get("ok", True)) for s in result["steps"] if isinstance(s, dict))
            elif result.get("ok") is False:
                steps_ok = False
            if not steps_ok:
                result["message"] = "Live execution failed or backends unconfigured"
                row.result = result
                row.status = "failed"
            else:
                result["message"] = "Playbook steps executed (live adapters when configured)"
                row.result = result
                row.status = "approved_live"
        _audit(
            db,
            tenant_id=row.tenant_id,
            request_id=row.request_id,
            action="approved",
            actor=actor,
            detail=result,
        )
        _audit(
            db,
            tenant_id=row.tenant_id,
            request_id=row.request_id,
            action="executed" if row.status != "failed" else "failed",
            actor=actor,
            detail={"status": row.status, "steps": len(result.get("steps") or [])},
        )
    except Exception as exc:  # noqa: BLE001
        row.status = "failed"
        row.result = {"executed": False, "error": str(exc), "playbook_id": row.playbook_id}
        _audit(
            db,
            tenant_id=row.tenant_id,
            request_id=row.request_id,
            action="failed",
            actor=actor,
            detail=row.result,
        )
        db.commit()
        db.refresh(row)
        inc_counter(
            "response_execution_total",
            status="failed",
            dry_run=str(bool(row.dry_run)).lower(),
        )
        return row

    db.commit()
    db.refresh(row)
    inc_counter(
        "response_execution_total",
        status="failed" if row.status == "failed" else "succeeded",
        dry_run=str(bool(row.dry_run)).lower(),
    )
    return row


def reject_request(
    db: Session,
    *,
    request_id: str,
    actor: str = "approver",
    tenant_id: str | None = None,
) -> ResponseRequest:
    query = db.query(ResponseRequest).filter(ResponseRequest.request_id == request_id)
    if tenant_id:
        query = query.filter(ResponseRequest.tenant_id == tenant_id)
    row = query.one_or_none()
    if row is None:
        raise KeyError(request_id)
    if row.status != "pending":
        raise ValueError(f"cannot reject status={row.status}")
    row.status = "rejected"
    _audit(
        db,
        tenant_id=row.tenant_id,
        request_id=row.request_id,
        action="rejected",
        actor=actor,
        detail={},
    )
    db.commit()
    db.refresh(row)
    return row


def get_request(
    db: Session,
    request_id: str,
    *,
    tenant_id: str | None = None,
) -> ResponseRequest | None:
    query = db.query(ResponseRequest).filter(ResponseRequest.request_id == request_id)
    if tenant_id:
        query = query.filter(ResponseRequest.tenant_id == tenant_id)
    row = query.one_or_none()
    if row is None:
        return None
    return row


def list_audit(db: Session, *, tenant_id: str | None = None, limit: int = 100) -> list[ResponseAudit]:
    q = db.query(ResponseAudit).order_by(ResponseAudit.id.desc())
    if tenant_id:
        q = q.filter(ResponseAudit.tenant_id == tenant_id)
    return list(q.limit(limit).all())


def list_pending(
    db: Session, *, tenant_id: str | None = None, limit: int = 100
) -> list[ResponseRequest]:
    q = db.query(ResponseRequest).filter(ResponseRequest.status == "pending")
    if tenant_id:
        q = q.filter(ResponseRequest.tenant_id == tenant_id)
    return list(q.order_by(ResponseRequest.id.desc()).limit(limit).all())
