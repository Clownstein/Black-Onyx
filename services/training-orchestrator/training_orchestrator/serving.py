"""Serving state: which signed package each alias must serve, and proof it does.

Promotion and rollback are two-phase:

1. write the desired alias → version/package signature row (committed so
   model-service replicas polling ``/serving/{model}/desired`` see it);
2. wait until every live replica reports that exact package loaded for the
   alias (or any replica reports a load error for it);
3. only then move the ``model_aliases`` row. On failure or timeout the
   desired row is restored, so replicas converge back to what they served.
"""
from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from training_orchestrator.config import settings
from training_orchestrator.models import ModelServingDesired, ModelServingInstance, ModelServingLease


class ServingConfirmationError(RuntimeError):
    """Replicas did not load the requested package; serving state was restored."""


class ServingLeaseError(RuntimeError):
    """Another promotion currently owns this tenant/model/alias transition."""


@dataclass(frozen=True)
class DesiredSnapshot:
    version: str
    package_signature: str
    generation: int


@contextmanager
def serving_lease(db: Session, tenant_id: str, model_name: str, alias: str) -> Iterator[None]:
    """Serialize alias changes across API workers with a bounded DB lease."""
    now = datetime.now(UTC)
    token = str(uuid.uuid4())
    duration = max(
        settings.serving_confirm_timeout_seconds,
        settings.serving_restore_timeout_seconds,
    ) + 60
    row = db.scalar(
        select(ModelServingLease).where(
            ModelServingLease.tenant_id == tenant_id,
            ModelServingLease.model_name == model_name,
            ModelServingLease.alias == alias,
        ).with_for_update()
    )
    if row is not None and _aware(row.expires_at) > now:
        raise ServingLeaseError(f"{model_name} {alias} already has a serving change in progress")
    if row is None:
        db.add(ModelServingLease(
            tenant_id=tenant_id,
            model_name=model_name,
            alias=alias,
            lease_token=token,
            expires_at=now + timedelta(seconds=duration),
        ))
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise ServingLeaseError(
                f"{model_name} {alias} already has a serving change in progress"
            ) from exc
    else:
        row.lease_token = token
        row.expires_at = now + timedelta(seconds=duration)
        db.commit()
    try:
        yield
    finally:
        db.execute(delete(ModelServingLease).where(ModelServingLease.lease_token == token))
        db.commit()


def package_signature(package_path: str | Path) -> str:
    signed = json.loads((Path(package_path) / "signature.json").read_text(encoding="utf-8"))
    return str(signed["signature"])


def _desired_row(db: Session, tenant_id: str, model_name: str, alias: str) -> ModelServingDesired | None:
    return db.scalar(
        select(ModelServingDesired).where(
            ModelServingDesired.tenant_id == tenant_id,
            ModelServingDesired.model_name == model_name,
            ModelServingDesired.alias == alias,
        )
    )


def desired_state(db: Session, tenant_id: str, model_name: str) -> dict[str, dict | None]:
    rows = db.scalars(
        select(ModelServingDesired).where(
            ModelServingDesired.tenant_id == tenant_id,
            ModelServingDesired.model_name == model_name,
        )
    ).all()
    return {
        row.alias: {
            "version": row.version,
            "signature": row.package_signature,
            "generation": row.generation,
            "removed": row.version is None,
        }
        for row in rows
    }


def set_desired(
    db: Session, tenant_id: str, model_name: str, alias: str, version: str, signature: str,
) -> tuple[DesiredSnapshot | None, int]:
    """Point ``alias`` at a package and return the previous desired snapshot."""
    row = _desired_row(db, tenant_id, model_name, alias)
    previous = (
        DesiredSnapshot(row.version, row.package_signature, row.generation)
        if row and row.version is not None and row.package_signature is not None
        else None
    )
    if row is None:
        row = ModelServingDesired(
            tenant_id=tenant_id, model_name=model_name, alias=alias,
            version=version, package_signature=signature, generation=1,
        )
    else:
        row.version, row.package_signature = version, signature
        row.generation += 1
    db.add(row)
    db.commit()
    return previous, row.generation


def restore_desired(
    db: Session, tenant_id: str, model_name: str, alias: str, previous: DesiredSnapshot | None,
    *, expected_generation: int,
) -> bool:
    row = _desired_row(db, tenant_id, model_name, alias)
    if row is None or row.generation != expected_generation:
        return False
    if previous is None:
        # Keep a generation-fenced removal tombstone so replicas can prove they
        # unloaded the package and stale reports cannot satisfy a later change.
        row.version, row.package_signature = None, None
        row.generation = expected_generation + 1
        db.add(row)
    else:
        row.version, row.package_signature = previous.version, previous.package_signature
        row.generation = expected_generation + 1
        db.add(row)
    db.commit()
    return True


def record_report(
    db: Session, tenant_id: str, model_name: str, instance_id: str,
    slots: dict[str, dict], errors: dict[str, str],
) -> None:
    """Upsert one replica's per-alias serving report."""
    now = datetime.now(UTC)
    for alias in set(slots) | set(errors) | {"champion"}:
        row = db.scalar(
            select(ModelServingInstance).where(
                ModelServingInstance.tenant_id == tenant_id,
                ModelServingInstance.model_name == model_name,
                ModelServingInstance.instance_id == instance_id,
                ModelServingInstance.alias == alias,
            )
        )
        if row is None:
            row = ModelServingInstance(
                tenant_id=tenant_id, model_name=model_name, instance_id=instance_id, alias=alias,
                reported_at=now,
            )
        slot = slots.get(alias) or {}
        generation = int(slot.get("generation", 0))
        if row.id is not None and generation < row.generation:
            # Delayed reports from an older poll cycle cannot roll back the
            # replica's durable observed state.
            continue
        row.version = slot.get("version")
        row.package_signature = slot.get("signature")
        row.generation = generation
        row.error = (errors.get(alias) or None) and str(errors[alias])[:2000]
        row.reported_at = now
        db.add(row)
    db.commit()


def live_instances(db: Session, tenant_id: str, model_name: str, alias: str) -> list[ModelServingInstance]:
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.serving_instance_ttl_seconds)
    rows = db.scalars(
        select(ModelServingInstance).where(
            ModelServingInstance.tenant_id == tenant_id,
            ModelServingInstance.model_name == model_name,
            ModelServingInstance.alias == alias,
        )
    ).all()
    return [row for row in rows if _aware(row.reported_at) >= cutoff]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def confirmation_status(
    db: Session, tenant_id: str, model_name: str, alias: str,
    version: str | None, signature: str | None,
    generation: int,
) -> tuple[bool | None, str]:
    """True when confirmed, False on a reported failure, None while pending."""
    db.expire_all()
    instances = live_instances(db, tenant_id, model_name, alias)
    current = [row for row in instances if row.generation == generation]
    failed = [row for row in current if row.error and (version is None or version in row.error)]
    if failed:
        return False, f"{failed[0].instance_id}: {failed[0].error}"
    serving = [
        row for row in current
        if row.version == version and row.package_signature == signature and not row.error
    ]
    if len(instances) >= settings.serving_min_instances and len(serving) == len(instances):
        return True, (
            f"{len(serving)} replica(s) confirmed {alias} unloaded at generation {generation}"
            if version is None else f"{len(serving)} replica(s) serving {version}"
        )
    return None, f"{len(serving)}/{max(len(instances), settings.serving_min_instances)} replicas at generation {generation} serving {version}"


def _restoration_confirmed(
    db: Session, tenant_id: str, model_name: str, alias: str, previous: DesiredSnapshot | None,
    generation: int,
) -> tuple[bool, str]:
    db.expire_all()
    instances = live_instances(db, tenant_id, model_name, alias)
    if len(instances) < settings.serving_min_instances:
        return False, f"only {len(instances)} live replica report(s) after restoration"
    if previous is None:
        unloaded = [row for row in instances if row.generation == generation and row.version is None and row.package_signature is None and not row.error]
        if len(unloaded) == len(instances):
            return True, f"{len(unloaded)} replica(s) confirmed the alias unloaded"
        return False, "replicas have not confirmed the alias is unloaded"
    serving = [
        row for row in instances
        if row.generation == generation and row.version == previous.version and row.package_signature == previous.package_signature and not row.error
    ]
    if len(serving) == len(instances):
        return True, f"{len(serving)} replica(s) restored {previous.version}"
    return False, f"{len(serving)}/{len(instances)} replica(s) restored {previous.version}"


def commit_serving_change(
    db: Session, tenant_id: str, model_name: str, alias: str, version: str, package_path: str,
    *, commit_alias: Callable[[], Any] | None = None,
) -> Any:
    """Run phases 1-2; raise ServingConfirmationError after restoring on failure."""
    signature = package_signature(package_path)
    environment = settings.environment.strip().casefold()
    confirmation_required = settings.serving_confirmation_required or environment in {
        "prod", "production", "staging",
    }
    if not confirmation_required:
        previous, generation = set_desired(db, tenant_id, model_name, alias, version, signature)
        try:
            committed = commit_alias() if commit_alias is not None else None
        except Exception:
            if not restore_desired(
                db, tenant_id, model_name, alias, previous, expected_generation=generation,
            ):
                raise ServingConfirmationError(
                    f"{model_name} {alias} desired generation changed during model-alias commit"
                )
            raise
        return committed if commit_alias is not None else "serving confirmation disabled; desired state recorded"
    previous, generation = set_desired(db, tenant_id, model_name, alias, version, signature)
    deadline = time.monotonic() + settings.serving_confirm_timeout_seconds
    detail = "no replica report"
    while True:
        confirmed, detail = confirmation_status(db, tenant_id, model_name, alias, version, signature, generation)
        if confirmed:
            try:
                return commit_alias() if commit_alias is not None else detail
            except Exception as commit_error:
                detail = f"model alias commit failed: {type(commit_error).__name__}"
                break
        if confirmed is False or time.monotonic() >= deadline:
            break
        time.sleep(settings.serving_confirm_poll_seconds)
    if not restore_desired(
        db, tenant_id, model_name, alias, previous, expected_generation=generation,
    ):
        raise ServingConfirmationError(
            f"{model_name} {alias} changed while {version} was pending; newer desired generation retained"
        )
    restore_deadline = time.monotonic() + settings.serving_restore_timeout_seconds
    restore_detail = "restoration has not yet been reported"
    while True:
        restored, restore_detail = _restoration_confirmed(
            db, tenant_id, model_name, alias, previous, generation + 1,
        )
        if restored:
            break
        if time.monotonic() >= restore_deadline:
            raise ServingConfirmationError(
                f"{model_name} {alias} failed to serve {version}; desired state was restored, "
                f"but replica rollback is not confirmed: {restore_detail}"
            )
        time.sleep(settings.serving_confirm_poll_seconds)
    raise ServingConfirmationError(
        f"{model_name} {alias} did not start serving {version}: {detail}; "
        f"replica rollback confirmed: {restore_detail}"
    )
