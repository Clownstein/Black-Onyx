import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from training_orchestrator.config import settings
from training_orchestrator.db import get_db
from training_orchestrator.drift import compute_drift_metrics
from training_orchestrator.models import DriftObservation, ModelAlias, ModelVersionHistory, TrainingJob
from training_orchestrator.schemas import (
    DriftMetricsResponse,
    DriftObservationCreate,
    PromoteRequest,
    PromoteResponse,
    RollbackResponse,
    TrainingJobCreate,
    TrainingJobResponse,
)
from training_orchestrator.serving import (
    ServingConfirmationError,
    ServingLeaseError,
    confirmation_status,
    desired_state,
    record_report,
)
from training_orchestrator.training import (
    SERVED_ALIASES,
    canonical_model_name,
    create_training_job,
    promote_version,
    rollback_champion,
)

def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="training API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


def _job_response(job: TrainingJob) -> TrainingJobResponse:
    manifest = None
    if job.dataset_manifest_json:
        manifest = json.loads(job.dataset_manifest_json)
    return TrainingJobResponse(
        job_id=job.id,
        tenant_id=job.tenant_id,
        model_name=job.model_name,
        status=job.status,
        version=job.version,
        message=job.message,
        package_path=job.package_path,
        dataset_manifest=manifest,
        synthetic_data=job.synthetic_data,
        attempt_count=job.attempt_count,
        max_attempts=job.max_attempts,
        claimed_by=job.claimed_by,
        lease_expires_at=job.lease_expires_at,
        heartbeat_at=job.heartbeat_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        failure_reason=job.failure_reason,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


@router.post("/models/{model_name}/training-jobs", response_model=TrainingJobResponse)
def start_training_job(
    model_name: str,
    body: TrainingJobCreate,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> TrainingJobResponse:
    if x_tenant_id != body.tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    try:
        job = create_training_job(db, model_name, body, idempotency_key=idempotency_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _job_response(job)


@router.get("/training-jobs", response_model=list[TrainingJobResponse])
def list_training_jobs(
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
    model_name: str | None = None,
    limit: int = 50,
) -> list[TrainingJobResponse]:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    query = select(TrainingJob).where(TrainingJob.tenant_id == x_tenant_id)
    if model_name:
        query = query.where(TrainingJob.model_name == model_name)
    rows = db.scalars(query.order_by(TrainingJob.created_at.desc()).limit(limit)).all()
    return [_job_response(row) for row in rows]


@router.get("/training-jobs/{job_id}", response_model=TrainingJobResponse)
def get_training_job(
    job_id: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> TrainingJobResponse:
    job = db.scalar(
        select(TrainingJob).where(
            TrainingJob.id == job_id,
            TrainingJob.tenant_id == x_tenant_id,
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="training job not found")
    return _job_response(job)


@router.post(
    "/models/{model_name}/versions/{version}/promote",
    response_model=PromoteResponse,
)
def promote_model_version(
    model_name: str,
    version: str,
    body: PromoteRequest,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> PromoteResponse:
    try:
        row, previous = promote_version(
            db, x_tenant_id, model_name, version, body.alias
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ServingConfirmationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ServingLeaseError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PromoteResponse(
        model_name=row.model_name,
        alias=row.alias,  # type: ignore[arg-type]
        version=row.version,
        previous_version=previous,
    )


@router.post("/models/{model_name}/versions/{version}/rollback", response_model=RollbackResponse)
def rollback_model(
    model_name: str,
    version: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> RollbackResponse:
    try:
        row = rollback_champion(
            db,
            x_tenant_id,
            model_name,
            expected_current_version=version,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ServingConfirmationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ServingLeaseError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RollbackResponse(
        model_name=row.model_name,
        alias="champion",
        version=row.version,
        previous_version=row.previous_version,
    )


@router.post("/models/{model_name}/drift/observations", status_code=201)
def record_drift_observation(
    model_name: str,
    body: DriftObservationCreate,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> dict:
    if x_tenant_id != body.tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    row = DriftObservation(
        tenant_id=body.tenant_id,
        model_name=model_name,
        observation=body.observed,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "observation_id": row.id,
        "tenant_id": row.tenant_id,
        "model_name": row.model_name,
        "observed_at": row.observed_at,
    }


@router.get("/models/{model_name}/versions")
def list_model_versions(
    model_name: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> dict:
    versions = list(
        db.scalars(
            select(ModelVersionHistory)
            .where(
                ModelVersionHistory.tenant_id == x_tenant_id,
                ModelVersionHistory.model_name == model_name,
            )
            .order_by(ModelVersionHistory.created_at.desc())
        ).all()
    )
    aliases = list(
        db.scalars(
            select(ModelAlias).where(
                ModelAlias.tenant_id == x_tenant_id,
                ModelAlias.model_name == model_name,
            )
        ).all()
    )
    aliases_by_version: dict[str, list[str]] = {}
    for alias in aliases:
        aliases_by_version.setdefault(alias.version, []).append(alias.alias)
    return {
        "tenant_id": x_tenant_id,
        "model_name": model_name,
        "items": [
            {
                "version": row.version,
                "aliases": sorted(aliases_by_version.get(row.version, [])),
                "created_at": row.created_at,
            }
            for row in versions
        ],
    }
@router.get("/models/{model_name}/drift", response_model=DriftMetricsResponse)
def get_drift(
    model_name: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> DriftMetricsResponse:
    rows = list(
        db.scalars(
            select(DriftObservation)
            .where(
                DriftObservation.tenant_id == x_tenant_id,
                DriftObservation.model_name == model_name,
            )
            .order_by(DriftObservation.observed_at.desc())
            .limit(200)
        ).all()
    )
    observed: dict = {}
    if rows:
        numeric: dict[str, list[float]] = {}
        flags: dict[str, bool] = {}
        calibration_probs: list[float] = []
        calibration_labels: list[int] = []
        for row in rows:
            for key, value in dict(row.observation or {}).items():
                if isinstance(value, bool):
                    flags[key] = flags.get(key, False) or value
                elif isinstance(value, (int, float)):
                    numeric.setdefault(key, []).append(float(value))
            observation = dict(row.observation or {})
            probs = observation.get("calibration_probs")
            labels = observation.get("calibration_labels")
            if isinstance(probs, list) and isinstance(labels, list) and len(probs) == len(labels):
                calibration_probs.extend(float(value) for value in probs)
                calibration_labels.extend(int(value) for value in labels)
        observed = {
            key: sum(values) / len(values)
            for key, values in numeric.items()
            if values
        }
        observed.update(flags)
        if calibration_probs:
            observed["calibration_probs"] = calibration_probs
            observed["calibration_labels"] = calibration_labels
    return DriftMetricsResponse(**compute_drift_metrics(model_name, observed))



# ── Serving state (polled by model-service replicas) ─────────────────────


def _served_model(model_name: str) -> str:
    name = canonical_model_name(model_name)
    if name is None:
        raise HTTPException(status_code=404, detail="unknown model")
    return name


class ServingSlotReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    version: str | None = None
    signature: str | None = None
    generation: int = Field(default=0, ge=0)


class ServingReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    slots: dict[str, ServingSlotReport] = Field(default_factory=dict, max_length=3)
    errors: dict[str, str] = Field(default_factory=dict, max_length=3)


@router.get("/serving/{model_name}/desired")
def get_serving_desired(
    model_name: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> dict:
    return {
        "tenant_id": x_tenant_id,
        "model_name": _served_model(model_name),
        "aliases": desired_state(db, x_tenant_id, _served_model(model_name)),
    }


@router.post("/serving/{model_name}/report", status_code=204)
def post_serving_report(
    model_name: str,
    body: ServingReport,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> Response:
    if set(body.slots) - SERVED_ALIASES or set(body.errors) - SERVED_ALIASES:
        raise HTTPException(status_code=422, detail="unknown serving alias")
    record_report(
        db, x_tenant_id, _served_model(model_name), body.instance_id,
        {alias: slot.model_dump() for alias, slot in body.slots.items()}, body.errors,
    )
    return Response(status_code=204)


@router.get("/serving/{model_name}")
def get_serving_status(
    model_name: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> dict:
    """Desired vs reported serving state per alias (for operators and the gateway)."""
    name = _served_model(model_name)
    desired = desired_state(db, x_tenant_id, name)
    out: dict[str, Any] = {}
    for alias, target in desired.items():
        if target is None:
            continue
        confirmed, detail = confirmation_status(
            db, x_tenant_id, name, alias, target["version"], target["signature"], target["generation"],
        )
        out[alias] = {**target, "confirmed": bool(confirmed), "detail": detail}
    return {"tenant_id": x_tenant_id, "model_name": name, "aliases": out}


@router.get("/models/{model_name}/versions/{version}/package")
def download_model_package(
    model_name: str,
    version: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
) -> Response:
    """Signed package tar for replicas; only versions with a verified package."""
    from black_onyx_model_package.serving import pack_package

    from training_orchestrator.training import _verify_version_package

    try:
        package_path = _verify_version_package(db, x_tenant_id, _served_model(model_name), version)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(content=pack_package(Path(package_path)), media_type="application/x-tar")
