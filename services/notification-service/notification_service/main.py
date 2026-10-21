from contextlib import asynccontextmanager
from email.utils import parseaddr
from typing import Any, Literal

import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from black_onyx_contracts.incident import Incident

from notification_service.config import settings
from notification_service.db import engine, ensure_schema, get_db
from notification_service.delivery import (
    deliver_incident_webhook_once,
    deliver_webhook,
    enqueue_email,
    flush_email_outbox,
)
from notification_service.models import EmailOutbox
from notification_service.network import validate_public_https_url
from notification_service.request_limits import RequestBodyLimitMiddleware

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("notification-service")
except ImportError:
    pass


class NotificationTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(default="inc-test", min_length=1, max_length=128)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    title: str = Field(default="Test notification", min_length=1, max_length=512)
    severity: str = Field(default="high", min_length=1, max_length=32)
    summary: str = Field(default="Notification service connectivity test", max_length=8192)
    channels: list[Literal["webhook", "email"]] = Field(
        default_factory=lambda: ["webhook", "email"], max_length=2
    )
    email_to: str | None = Field(default=None, max_length=320)
    webhook_url: str | None = Field(default=None, max_length=2048)


class IncidentNotification(Incident):
    notify_email: str | None = Field(default=None, max_length=320)
    notification_policy: list[dict[str, Any]] = Field(default_factory=list, max_length=32)


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.notification_api_key
    if not expected:
        raise HTTPException(status_code=503, detail="notification API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def _require_tenant(x_tenant_id: str | None, body_tenant_id: str | None = None) -> str:
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(status_code=400, detail="X-Tenant-Id is required")
    tenant_id = x_tenant_id.strip()
    if body_tenant_id is not None and tenant_id != body_tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    return tenant_id


def _email_recipient(value: object) -> str:
    recipient = str(value or settings.default_email_to or "").strip()
    _, parsed = parseaddr(recipient)
    if not recipient or parsed != recipient or "." not in parsed.rpartition("@")[2]:
        raise HTTPException(
            status_code=422,
            detail="email recipient is required; provide email_to or configure NOTIFICATION_DEFAULT_EMAIL_TO",
        )
    return recipient


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Notification Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=1024 * 1024)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    with engine.connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    configured = bool(settings.notification_api_key)
    webhook_secure = not settings.notification_webhook_url or bool(
        settings.notification_webhook_secret
    )
    ready_now = configured and webhook_secure
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready_now else "not_ready",
        "webhook_configured": bool(settings.notification_webhook_url),
        "smtp_configured": bool(settings.smtp_host),
        "default_email_configured": bool(settings.default_email_to),
        "email_delivery_mode": "smtp" if settings.smtp_host else "unavailable",
        "api_key_configured": configured,
        "webhook_secret_configured": bool(settings.notification_webhook_secret),
    }


@app.post("/api/v1/notifications/test")
def test_notification(
    body: NotificationTestRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    tenant_id = _require_tenant(x_tenant_id, body.tenant_id)
    incident = {
        "incident_id": body.incident_id,
        "tenant_id": tenant_id,
        "title": body.title,
        "severity": body.severity,
        "summary": body.summary,
    }
    result: dict[str, Any] = {"incident": incident, "results": {}}
    if "webhook" in body.channels:
        result["results"]["webhook"] = deliver_webhook(incident, webhook_url=body.webhook_url)
    if "email" in body.channels:
        row = enqueue_email(db, incident, _email_recipient(body.email_to))
        result["results"]["email"] = {
            "queued": True,
            "outbox_id": row.id,
            "recipient": row.recipient,
            "status": row.status,
        }
    if not result["results"]:
        raise HTTPException(status_code=400, detail="no channels selected")
    return result


@app.post("/api/v1/notifications/incident")
def notify_incident(
    body: IncidentNotification,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    _require_tenant(x_tenant_id, body.tenant_id)
    incident = body.model_dump(mode="json")
    policies = body.notification_policy
    enabled = {
        row["channel"]: dict(row.get("config") or {})
        for row in policies
        if row.get("enabled") and row.get("channel") in {"email", "webhook"}
    }
    # With no tenant policy configured, keep the operator-level defaults for
    # installations that have not yet moved their settings into the tenant SoR.
    has_tenant_policy = bool(policies)
    email_config = enabled.get("email") if has_tenant_policy else {}
    webhook_config = enabled.get("webhook") if has_tenant_policy else {}
    email_to: str | None = None
    if email_config is not None or not has_tenant_policy:
        email_to = _email_recipient(
            (email_config or {}).get("email_to") or body.notify_email
        )
    webhook_url = (webhook_config or {}).get("webhook_url") or None
    webhook_secret = (webhook_config or {}).get("webhook_secret") or None
    webhook_requested = (
        webhook_config is not None
        if has_tenant_policy
        else bool(settings.notification_webhook_url)
    )
    if webhook_requested:
        # Resolve policy and validate every configured destination before
        # queuing email or making an outbound request.
        effective_webhook_url = webhook_url or settings.notification_webhook_url
        effective_webhook_secret = webhook_secret or settings.notification_webhook_secret
        if not isinstance(effective_webhook_url, str) or not effective_webhook_url.strip():
            raise HTTPException(status_code=422, detail="enabled webhook channel has no destination")
        if not isinstance(effective_webhook_secret, str) or not effective_webhook_secret.strip():
            raise HTTPException(status_code=422, detail="enabled webhook channel has no signing secret")
        try:
            validate_public_https_url(effective_webhook_url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="webhook destination is invalid") from exc
    webhook_result: dict[str, Any] | None = None
    email_result: dict[str, Any] | None = None
    if email_to is not None:
        row = enqueue_email(db, incident, email_to)
        email_result = {"outbox_id": row.id, "status": row.status, "recipient": row.recipient}
    if webhook_config is not None or not has_tenant_policy:
        webhook_result = deliver_incident_webhook_once(
            db,
            incident, webhook_url=webhook_url, webhook_secret=webhook_secret
        )
    return {
        "webhook": webhook_result or {"delivered": False, "reason": "disabled by tenant policy"},
        "email": email_result or {"queued": False, "reason": "disabled by tenant policy"},
    }


@app.get("/api/v1/notifications/outbox")
def list_outbox(
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    tenant_id = _require_tenant(x_tenant_id)
    rows = (
        db.query(EmailOutbox)
        .filter(EmailOutbox.tenant_id == tenant_id)
        .order_by(EmailOutbox.id.desc())
        .limit(100)
        .all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "recipient": r.recipient,
                "subject": r.subject,
                "status": r.status,
                "delivery_mode": r.delivery_mode,
                "attempt_count": r.attempt_count,
                "last_error": r.last_error,
                "retryable": r.retryable,
            }
            for r in rows
        ]
    }


@app.post("/api/v1/notifications/outbox/flush")
def flush_outbox(
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    """Deliver pending email outbox rows; missing SMTP fails retryably."""
    return flush_email_outbox(db, tenant_id=_require_tenant(x_tenant_id))


@app.post("/api/v1/notifications/outbox/{outbox_id}/retry")
def retry_outbox(
    outbox_id: int,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    tenant_id = _require_tenant(x_tenant_id)
    row = (
        db.query(EmailOutbox)
        .filter(EmailOutbox.id == outbox_id, EmailOutbox.tenant_id == tenant_id)
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="outbox entry not found")
    if row.status != "failed":
        raise HTTPException(status_code=409, detail="only failed outbox entries can be retried")
    row.status = "pending"
    row.delivery_mode = "queued"
    row.last_error = None
    row.retryable = False
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "status": row.status, "attempt_count": row.attempt_count}


def run() -> None:
    import uvicorn

    uvicorn.run("notification_service.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
