"""Response request approval workflow."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import update
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
    signals_value = payload.get("signals")
    policy_value = payload.get("tenant_policy")
    signals = dict(signals_value) if isinstance(signals_value, dict) else {}
    tenant_policy = dict(policy_value) if isinstance(policy_value, dict) else {}
    mode = classify_response_mode(signals, tenant_policy)
    auto_eligible = may_auto_execute(signals, tenant_policy)

    if dry_run is None:
        dry_run = bool(settings.dry_run_default)
    # Signals and tenant_policy arrive in the request body and are therefore
    # evidence, not authorization. Every new request starts in dry-run mode;
    # only approve_request's separately authenticated approver key may make it
    # live. Preserve eligibility as informational metadata for reviewers.
    dry_run = True
    payload["response_mode"] = "suggest_only"
    payload["auto_execute"] = False
    payload["auto_eligible"] = bool(auto_eligible and mode == "gated_auto")

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
    if row.status != "pending":
        raise ValueError(f"cannot approve status={row.status}")

    if dry_run_override is False and not allow_live_override and bool(row.dry_run):
        raise PermissionError("live override requires elevated approver key")
    target_dry_run = row.dry_run if dry_run_override is None else dry_run_override
    # Claim before calling any external adapter. The compare-and-swap makes a
    # concurrent approval lose without repeating a live side effect.
    claimed = db.execute(
        update(ResponseRequest)
        .where(
            ResponseRequest.id == row.id,
            ResponseRequest.status == "pending",
        )
        .values(status="executing", approved_by=actor, dry_run=target_dry_run)
    ).rowcount
    if claimed != 1:
        db.rollback()
        raise ValueError("request has already been claimed")
    db.commit()
    db.refresh(row)

    exec_payload = dict(row.payload or {})
    exec_payload.setdefault("incident_id", row.incident_id)
    exec_payload.setdefault("tenant_id", row.tenant_id)
    raised = False
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
            final_status = "completed"
        else:
            def result_ok(value: Any) -> bool:
                if not isinstance(value, dict):
                    return True
                if value.get("ok") is False:
                    return False
                if isinstance(value.get("result"), dict) and not result_ok(value["result"]):
                    return False
                if isinstance(value.get("steps"), list):
                    return all(result_ok(step) for step in value["steps"] if isinstance(step, dict))
                return True

            steps_ok = result_ok(result)
            if not steps_ok:
                result["message"] = "Live execution failed or backends unconfigured"
                final_status = "failed"
            else:
                result["message"] = "Playbook steps executed (live adapters when configured)"
                final_status = "approved_live"
    except Exception as exc:  # noqa: BLE001
        raised = True
        final_status = "failed"
        result = {"executed": False, "error": str(exc), "playbook_id": row.playbook_id}

    # Reconciliation may have claimed an overlong execution while an adapter
    # was still running. Never overwrite the uncertain state or its audit.
    finalized = db.execute(
        update(ResponseRequest)
        .where(ResponseRequest.id == row.id, ResponseRequest.status == "executing")
        .values(status=final_status, result=result, updated_at=datetime.now(timezone.utc))
        .execution_options(synchronize_session=False)
    ).rowcount
    if finalized != 1:
        db.rollback()
        db.refresh(row)
        return row

    if not raised:
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
        action="failed" if final_status == "failed" else "executed",
        actor=actor,
        detail=result if raised else {"status": final_status, "steps": len(result.get("steps") or [])},
    )

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
    claimed = db.execute(
        update(ResponseRequest)
        .where(ResponseRequest.id == row.id, ResponseRequest.status == "pending")
        .values(status="rejected")
    ).rowcount
    if claimed != 1:
        db.rollback()
        raise ValueError("request has already been claimed")
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


def reconcile_stale_executions(
    db: Session, *, tenant_id: str, limit: int = 100,
) -> list[ResponseRequest]:
    """Surface timed-out executions for human reconciliation, never replaying adapters.

    A process can die after an external adapter accepts an action but before
    committing the result. Replaying in that state could perform it twice.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.execution_uncertain_after_seconds
    )
    stale = (
        db.query(ResponseRequest)
        .filter(
            ResponseRequest.tenant_id == tenant_id,
            ResponseRequest.status == "executing",
            ResponseRequest.updated_at < cutoff,
        )
        .order_by(ResponseRequest.id)
        .limit(limit)
        .all()
    )
    for row in stale:
        uncertainty = {
            "executed": None,
            "playbook_id": row.playbook_id,
            "message": "Execution outcome is unknown; verify external state before any new action",
        }
        claimed = db.execute(
            update(ResponseRequest)
            .where(
                ResponseRequest.id == row.id,
                ResponseRequest.tenant_id == tenant_id,
                ResponseRequest.status == "executing",
                ResponseRequest.updated_at < cutoff,
            )
            .values(
                status="execution_uncertain", result=uncertainty,
                updated_at=datetime.now(timezone.utc),
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        if claimed == 1:
            _audit(
                db, tenant_id=tenant_id, request_id=row.request_id,
                action="execution_uncertain", actor="response-orchestrator",
                detail={"message": uncertainty["message"]},
            )
    db.commit()
    return list_uncertain_executions(db, tenant_id=tenant_id, limit=limit)


def list_uncertain_executions(
    db: Session, *, tenant_id: str, limit: int = 100,
) -> list[ResponseRequest]:
    return list(
        db.query(ResponseRequest)
        .filter(
            ResponseRequest.tenant_id == tenant_id,
            ResponseRequest.status == "execution_uncertain",
        )
        .order_by(ResponseRequest.id.desc())
        .limit(limit)
        .all()
    )
