"""Durable database-backed worker for queued training jobs."""

from __future__ import annotations

import argparse
import socket
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from training_orchestrator.config import settings
from training_orchestrator.db import SessionLocal
from training_orchestrator.models import TrainingJob
from training_orchestrator.schemas import TrainingJobCreate
from training_orchestrator.training import execute_training_job


def _now() -> datetime:
    return datetime.now(UTC)


def claim_next_job(db: Session, worker_id: str) -> TrainingJob | None:
    """Claim one queued or expired job while holding a row lock where supported."""
    now = _now()
    # An expired final attempt must become terminal rather than remaining a
    # permanently running row that no worker can claim.
    db.execute(
        update(TrainingJob)
        .where(
            TrainingJob.status == "running",
            TrainingJob.lease_expires_at < now,
            TrainingJob.attempt_count >= TrainingJob.max_attempts,
        )
        .values(status="failed", failure_reason="worker lease expired after final attempt",
                message="worker lease expired after final attempt", finished_at=now,
                claimed_by=None, lease_expires_at=None)
        .execution_options(synchronize_session=False)
    )
    db.commit()
    query = (
        select(TrainingJob)
        .where(
            TrainingJob.attempt_count < TrainingJob.max_attempts,
            or_(
                TrainingJob.status == "queued",
                (TrainingJob.status == "running") & (TrainingJob.lease_expires_at < now),
            ),
        )
        .order_by(TrainingJob.created_at.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    job = db.scalar(query)
    if job is None:
        return None
    job.status = "running"
    job.message = "claimed by training worker"
    job.claimed_by = worker_id
    job.attempt_count += 1
    job.started_at = job.started_at or now
    job.heartbeat_at = now
    lease_seconds = max(settings.worker_lease_seconds, settings.training_timeout_seconds * 2)
    job.lease_expires_at = now + timedelta(seconds=lease_seconds)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def run_claimed_job(db: Session, job: TrainingJob) -> TrainingJob:
    stopped = threading.Event()
    claim_owner = job.claimed_by
    claim_attempt = job.attempt_count
    heartbeat = threading.Thread(
        target=_renew_lease_until_stopped,
        args=(job.id, job.claimed_by or "", stopped),
        daemon=True,
    )
    heartbeat.start()
    try:
        request = TrainingJobCreate.model_validate(job.request_json)
        return execute_training_job(db, job, request)
    except Exception as exc:  # noqa: BLE001 - persist terminal worker failures
        db.rollback()
        status = "queued" if claim_attempt < job.max_attempts else "failed"
        db.execute(
            update(TrainingJob)
            .where(
                TrainingJob.id == job.id,
                TrainingJob.status == "running",
                TrainingJob.claimed_by == claim_owner,
                TrainingJob.attempt_count == claim_attempt,
            )
            .values(
                status=status, failure_reason=str(exc),
                message=f"worker attempt {claim_attempt} failed: {exc}",
                finished_at=_now() if status == "failed" else None,
                claimed_by=None, lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        db.commit()
        db.refresh(job)
        return job
    finally:
        stopped.set()
        heartbeat.join(timeout=max(1.0, settings.worker_heartbeat_seconds + 1.0))


def _renew_lease_until_stopped(job_id: str, worker_id: str, stopped: threading.Event) -> None:
    """Renew an active claim from an independent session until execution ends."""
    interval = max(1.0, min(settings.worker_heartbeat_seconds, settings.worker_lease_seconds / 3))
    while not stopped.wait(interval):
        now = _now()
        lease_seconds = max(settings.worker_lease_seconds, settings.training_timeout_seconds * 2)
        with SessionLocal() as heartbeat_db:
            heartbeat_db.execute(
                update(TrainingJob)
                .where(
                    TrainingJob.id == job_id,
                    TrainingJob.status == "running",
                    TrainingJob.claimed_by == worker_id,
                )
                .values(
                    heartbeat_at=now,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                )
            )
            heartbeat_db.commit()


def run_once(worker_id: str) -> bool:
    if not settings.artifact_signing_key.strip():
        raise RuntimeError("TRAINING_ORCHESTRATOR_ARTIFACT_SIGNING_KEY is required")
    with SessionLocal() as db:
        job = claim_next_job(db, worker_id)
        if job is None:
            return False
        run_claimed_job(db, job)
        return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--worker-id",
        default=f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}",
    )
    args = parser.parse_args(argv)
    if not settings.artifact_signing_key.strip():
        parser.error("TRAINING_ORCHESTRATOR_ARTIFACT_SIGNING_KEY is required")
    while True:
        worked = run_once(args.worker_id)
        if args.once:
            return 0
        if not worked:
            time.sleep(max(0.1, settings.worker_poll_seconds))


if __name__ == "__main__":
    raise SystemExit(main())
