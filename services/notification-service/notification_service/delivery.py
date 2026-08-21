from __future__ import annotations

import json
import hashlib
import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from notification_service.config import settings
from notification_service.formatters import format_email, format_slack_payload
from notification_service.models import EmailOutbox
from notification_service.signing import sign_payload


def deliver_webhook(incident: dict[str, Any], webhook_url: str | None = None) -> dict[str, Any]:
    url = webhook_url if webhook_url is not None else settings.notification_webhook_url
    if not url:
        return {"delivered": False, "reason": "NOTIFICATION_WEBHOOK_URL not configured"}

    payload = format_slack_payload(incident)
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Anomaly-Signature": sign_payload(settings.notification_webhook_secret, body),
    }
    attempts = 0
    last_error: str | None = None
    max_retries = max(1, settings.webhook_max_retries)
    for attempt in range(1, max_retries + 1):
        attempts = attempt
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.post(url, content=body, headers=headers)
                if response.status_code < 500:
                    response.raise_for_status()
                    return {
                        "delivered": True,
                        "attempts": attempts,
                        "status_code": response.status_code,
                    }
                last_error = f"HTTP {response.status_code}"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        if attempt < max_retries:
            time.sleep(settings.webhook_retry_backoff_seconds * attempt)
    return {"delivered": False, "attempts": attempts, "error": last_error}


def enqueue_email(db: Session, incident: dict[str, Any], recipient: str) -> EmailOutbox:
    subject, body = format_email(incident)
    identity = (
        f"{incident.get('tenant_id', '')}:{incident.get('incident_id', '')}:"
        f"{recipient}:{subject}"
    )
    notification_id = f"email-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"
    existing = (
        db.query(EmailOutbox)
        .filter(
            EmailOutbox.tenant_id == str(incident.get("tenant_id", "")),
            EmailOutbox.notification_id == notification_id,
        )
        .one_or_none()
    )
    if existing is not None:
        return existing
    row = EmailOutbox(
        notification_id=notification_id,
        tenant_id=str(incident.get("tenant_id", "")),
        recipient=recipient,
        subject=subject,
        body=body,
        status="pending",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _send_smtp(recipient: str, subject: str, body: str) -> dict[str, Any]:
    """Deliver via SMTP when configured; otherwise mark as logged locally."""
    host = settings.smtp_host
    if not host:
        return {"delivered": True, "mode": "outbox_only"}
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = recipient
    msg.set_content(body)
    with smtplib.SMTP(host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_starttls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(msg)
    return {"delivered": True, "mode": "smtp"}


def flush_email_outbox(db: Session, limit: int = 50) -> dict[str, Any]:
    """Process pending email outbox rows.

    With SMTP configured: status becomes ``sent`` or ``failed``.
    Without SMTP: status becomes ``logged`` (not claimed as delivered).
    """
    rows = (
        db.query(EmailOutbox)
        .filter(EmailOutbox.status == "pending")
        .order_by(EmailOutbox.id.asc())
        .limit(limit)
        .all()
    )
    sent = 0
    logged = 0
    failed = 0
    for row in rows:
        row.attempt_count += 1
        try:
            result = _send_smtp(row.recipient, row.subject, row.body)
            mode = str(result.get("mode") or "")
            if mode == "smtp" and result.get("delivered"):
                row.status = "sent"
                sent += 1
            elif mode == "outbox_only" and result.get("delivered"):
                row.status = "logged"
                logged += 1
            else:
                row.status = "failed"
                row.last_error = "SMTP delivery returned unsuccessful result"
                failed += 1
        except Exception as exc:  # noqa: BLE001
            row.status = "failed"
            row.last_error = str(exc)
            failed += 1
    db.commit()
    return {"processed": len(rows), "sent": sent, "logged": logged, "failed": failed}
