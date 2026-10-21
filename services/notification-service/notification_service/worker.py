"""Owned SMTP outbox worker; retryable rows are claimed atomically."""
from __future__ import annotations

import logging
import time

from sqlalchemy import select

from notification_service.config import settings
from notification_service.db import SessionLocal, ensure_schema
from notification_service.delivery import flush_email_outbox
from notification_service.models import EmailOutbox

logger = logging.getLogger(__name__)


def run_once() -> dict[str, int]:
    if not settings.notification_api_key:
        raise RuntimeError("NOTIFICATION_API_KEY is required")
    totals = {"processed": 0, "sent": 0, "failed": 0}
    with SessionLocal() as db:
        tenants = db.scalars(
            select(EmailOutbox.tenant_id)
            .where(EmailOutbox.status.in_(("pending", "failed", "sending")))
            .distinct()
        ).all()
        for tenant_id in tenants:
            result = flush_email_outbox(db, tenant_id=tenant_id)
            for key in totals:
                totals[key] += result[key]
    return totals


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    ensure_schema()
    while True:
        try:
            result = run_once()
            if result["processed"]:
                logger.info("notification outbox: %s", result)
        except Exception:
            logger.exception("notification outbox worker cycle failed")
        time.sleep(max(1.0, settings.outbox_poll_seconds))


if __name__ == "__main__":
    main()
