from contextlib import asynccontextmanager
from typing import Any

import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from notification_service.config import settings
from notification_service.db import engine, ensure_schema, get_db
from notification_service.delivery import deliver_webhook, enqueue_email, flush_email_outbox
from notification_service.models import EmailOutbox

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("notification-service")
except ImportError:
    pass


class NotificationTestRequest(BaseModel):
    incident_id: str = "inc-test"
    tenant_id: str = "tenant-acme"
    title: str = "Test notification"
    severity: str = "high"
    summary: str = "Notification service connectivity test"
    channels: list[str] = Field(default_factory=lambda: ["webhook", "email"])
    email_to: str = "ops@example.com"
    webhook_url: str | None = None


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.notification_api_key
    if not expected:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Notification Service", version="0.1.0", lifespan=lifespan)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    with engine.connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    return {
        "status": "ready",
        "webhook_configured": bool(settings.notification_webhook_url),
        "api_key_required": bool(settings.notification_api_key),
    }


@app.post("/api/v1/notifications/test")
def test_notification(
    body: NotificationTestRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    incident = {
        "incident_id": body.incident_id,
        "tenant_id": body.tenant_id,
        "title": body.title,
        "severity": body.severity,
        "summary": body.summary,
    }
    result: dict[str, Any] = {"incident": incident, "results": {}}
    if "webhook" in body.channels:
        result["results"]["webhook"] = deliver_webhook(incident, webhook_url=body.webhook_url)
    if "email" in body.channels:
        row = enqueue_email(db, incident, body.email_to)
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
    incident: dict[str, Any],
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    webhook = deliver_webhook(incident)
    email_to = str(incident.get("notify_email", "ops@example.com"))
    row = enqueue_email(db, incident, email_to)
    return {
        "webhook": webhook,
        "email": {"outbox_id": row.id, "status": row.status, "recipient": row.recipient},
    }


@app.get("/api/v1/notifications/outbox")
def list_outbox(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    rows = db.query(EmailOutbox).order_by(EmailOutbox.id.desc()).limit(100).all()
    return {
        "items": [
            {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "recipient": r.recipient,
                "subject": r.subject,
                "status": r.status,
            }
            for r in rows
        ]
    }


@app.post("/api/v1/notifications/outbox/flush")
def flush_outbox(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    """Deliver pending email outbox rows (SMTP if configured, else mark sent)."""
    return flush_email_outbox(db)


def run() -> None:
    import uvicorn

    uvicorn.run("notification_service.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
