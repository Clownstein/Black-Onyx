from __future__ import annotations

import json
import hashlib
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from notification_service.config import settings
from notification_service.formatters import format_email, format_slack_payload
from notification_service.models import EmailOutbox, WebhookDelivery
from notification_service.network import request_public_https_sync, validate_public_https_url
from notification_service.signing import sign_payload


def deliver_webhook(
    incident: dict[str, Any], webhook_url: str | None = None,
    webhook_secret: str | None = None,
    delivery_id: str | None = None,
) -> dict[str, Any]:
    url = webhook_url if webhook_url is not None else settings.notification_webhook_url
    if not url:
        return {
            "delivered": False, "reason": "NOTIFICATION_WEBHOOK_URL not configured",
            "retryable": True,
        }
    secret = webhook_secret or settings.notification_webhook_secret
    if not secret:
        return {
            "delivered": False, "reason": "NOTIFICATION_WEBHOOK_SECRET not configured",
            "retryable": True,
        }
    try:
        url = validate_public_https_url(url)
    except ValueError as exc:
        return {"delivered": False, "reason": str(exc)}

    payload = format_slack_payload(incident)
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > 64 * 1024:
        return {"delivered": False, "reason": "webhook payload exceeds 65536 bytes", "retryable": False}
    headers = {
        "Content-Type": "application/json",
        "X-Black-Onyx-Signature": sign_payload(secret, body),
    }
    if delivery_id:
        headers["X-Black-Onyx-Delivery-Id"] = delivery_id
    attempts = 0
    last_error: str | None = None
    retryable = False
    max_retries = max(1, settings.webhook_max_retries)
    for attempt in range(1, max_retries + 1):
        attempts = attempt
        try:
            with httpx.Client(timeout=5.0, trust_env=False, follow_redirects=False) as client:
                response = request_public_https_sync(
                    client, "POST", url, max_bytes=16 * 1024,
                    headers=headers, content=body,
                )
                if response.status_code < 500:  # type: ignore[attr-defined]
                    response.raise_for_status()  # type: ignore[attr-defined]
                    return {
                        "delivered": True,
                        "attempts": attempts,
                        "status_code": response.status_code,  # type: ignore[attr-defined]
                        "retryable": False,
                    }
                last_error = f"HTTP {response.status_code}"  # type: ignore[attr-defined]
                retryable = True
        except httpx.HTTPStatusError as exc:
            last_error = f"HTTP {exc.response.status_code}"
            retryable = exc.response.status_code >= 500
        except Exception as exc:  # noqa: BLE001
            # Transport exception strings can include signed webhook query
            # parameters. Persist only the exception type, never the URL.
            last_error = type(exc).__name__
            retryable = not isinstance(exc, ValueError)
        if attempt < max_retries:
            time.sleep(settings.webhook_retry_backoff_seconds * attempt)
    return {
        "delivered": False,
        "attempts": attempts,
        "error": last_error,
        "retryable": retryable,
    }


def _webhook_delivery_id(incident: dict[str, Any]) -> str:
    identity = {
        key: incident.get(key)
        for key in (
            "tenant_id", "incident_id", "status", "severity", "title",
            "summary", "last_seen", "risk_score",
        )
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
    return "webhook-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:48]


def deliver_incident_webhook_once(
    db: Session,
    incident: dict[str, Any],
    *,
    webhook_url: str | None = None,
    webhook_secret: str | None = None,
) -> dict[str, Any]:
    """Record one outcome per tenant/event and reuse it on duplicate requests.

    Stale in-flight attempts and retryable failures may be reclaimed after the
    bounded HTTP retry window. The deterministic delivery header lets
    cooperating webhook receivers deduplicate the unavoidable crash window
    between remote acceptance and local outcome commit.
    """
    tenant_id = str(incident.get("tenant_id") or "")
    incident_id = str(incident.get("incident_id") or "")
    delivery_id = _webhook_delivery_id(incident)
    now = datetime.now(UTC)
    stale_before = now - timedelta(minutes=5)
    row = (
        db.query(WebhookDelivery)
        .filter(
            WebhookDelivery.tenant_id == tenant_id,
            WebhookDelivery.delivery_id == delivery_id,
        )
        .one_or_none()
    )
    claimed = False
    if row is None:
        row = WebhookDelivery(
            tenant_id=tenant_id,
            incident_id=incident_id,
            delivery_id=delivery_id,
            status="sending",
            attempt_count=1,
        )
        db.add(row)
        try:
            db.commit()
            claimed = True
        except IntegrityError:
            db.rollback()
            row = (
                db.query(WebhookDelivery)
                .filter(
                    WebhookDelivery.tenant_id == tenant_id,
                    WebhookDelivery.delivery_id == delivery_id,
                )
                .one_or_none()
            )
    if row is None:
        return {"delivered": False, "retryable": True, "error": "delivery claim unavailable"}

    if not claimed:
        if row.status == "delivered":
            try:
                previous = json.loads(row.result_json or "{}")
                return {**previous, "delivery_id": delivery_id, "replayed": True}
            except json.JSONDecodeError:
                return {"delivered": True, "delivery_id": delivery_id, "replayed": True}
        if row.status == "sending":
            result = db.execute(
                update(WebhookDelivery)
                .where(
                    WebhookDelivery.id == row.id,
                    WebhookDelivery.status == "sending",
                    WebhookDelivery.updated_at < stale_before,
                )
                .values(
                    attempt_count=WebhookDelivery.attempt_count + 1,
                    updated_at=now,
                )
            )
            db.commit()
            claimed = result.rowcount == 1
        elif row.status == "failed" and row.retryable:
            result = db.execute(
                update(WebhookDelivery)
                .where(
                    WebhookDelivery.id == row.id,
                    WebhookDelivery.status == "failed",
                    WebhookDelivery.retryable.is_(True),
                )
                .values(
                    status="sending",
                    attempt_count=WebhookDelivery.attempt_count + 1,
                    updated_at=now,
                )
            )
            db.commit()
            claimed = result.rowcount == 1
        else:
            try:
                previous = json.loads(row.result_json or "{}")
            except json.JSONDecodeError:
                previous = {"delivered": False, "error": "delivery outcome unavailable"}
            return {**previous, "delivery_id": delivery_id, "replayed": True}

    if not claimed:
        return {"delivered": False, "in_progress": True, "delivery_id": delivery_id}

    outcome = deliver_webhook(
        incident,
        webhook_url=webhook_url,
        webhook_secret=webhook_secret,
        delivery_id=delivery_id,
    )
    current = db.get(WebhookDelivery, row.id)
    if current is not None:
        current.status = "delivered" if outcome.get("delivered") else "failed"
        current.result_json = json.dumps(outcome, sort_keys=True, separators=(",", ":"))
        current.retryable = bool(outcome.get("retryable"))
        current.updated_at = datetime.now(UTC)
        db.add(current)
        db.commit()
    return {**outcome, "delivery_id": delivery_id, "replayed": False}


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
        delivery_mode="queued",
        retryable=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _send_smtp(recipient: str, subject: str, body: str) -> dict[str, Any]:
    """Deliver via configured SMTP, failing explicitly when unavailable."""
    host = settings.smtp_host
    if not host:
        return {"delivered": False, "mode": "smtp", "error": "SMTP is not configured"}
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


def flush_email_outbox(db: Session, *, tenant_id: str, limit: int = 50) -> dict[str, Any]:
    """Process pending email outbox rows.

    With SMTP configured: status becomes ``sent`` or ``failed``.
    Without SMTP: status becomes retryable ``failed``; queued mail is never
    consumed merely because it was written to application logs.
    """
    # Reclaim a crashed sender after its SMTP timeout plus generous headroom.
    # A crash after SMTP acceptance may yield a duplicate; SMTP is at-least-once.
    stale = datetime.now(UTC) - timedelta(minutes=5)
    db.execute(
        update(EmailOutbox)
        .where(EmailOutbox.tenant_id == tenant_id, EmailOutbox.status == "sending",
               EmailOutbox.updated_at < stale)
        .values(status="failed", retryable=True, last_error="sender lease expired")
    )
    retry_cutoff = datetime.now(UTC) - timedelta(seconds=settings.outbox_retry_seconds)
    db.execute(
        update(EmailOutbox)
        .where(EmailOutbox.tenant_id == tenant_id, EmailOutbox.status == "failed",
               EmailOutbox.retryable.is_(True),
               EmailOutbox.attempt_count < settings.outbox_max_attempts,
               EmailOutbox.updated_at < retry_cutoff)
        .values(status="pending")
    )
    db.commit()
    rows = (
        db.query(EmailOutbox)
        .filter(
            EmailOutbox.tenant_id == tenant_id,
            EmailOutbox.status == "pending",
        )
        .order_by(EmailOutbox.id.asc())
        .limit(limit)
        .all()
    )
    sent = 0
    failed = 0
    for row in rows:
        claimed = db.execute(
            update(EmailOutbox)
            .where(EmailOutbox.id == row.id, EmailOutbox.status == "pending")
            .values(status="sending", attempt_count=EmailOutbox.attempt_count + 1)
        ).rowcount
        db.commit()
        if claimed != 1:
            continue
        db.refresh(row)
        try:
            result = _send_smtp(row.recipient, row.subject, row.body)
            mode = str(result.get("mode") or "")
            if mode == "smtp" and result.get("delivered"):
                row.status = "sent"
                row.delivery_mode = "smtp"
                row.retryable = False
                row.last_error = None
                sent += 1
            else:
                row.status = "failed"
                row.delivery_mode = mode or "smtp"
                row.last_error = str(result.get("error") or "SMTP delivery returned unsuccessful result")
                row.retryable = True
                failed += 1
        except Exception as exc:  # noqa: BLE001
            row.status = "failed"
            row.delivery_mode = "smtp"
            row.last_error = str(exc)
            row.retryable = True
            failed += 1
        db.commit()
    return {"processed": sent + failed, "sent": sent, "failed": failed}
