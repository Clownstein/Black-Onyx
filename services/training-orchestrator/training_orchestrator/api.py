import json

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

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
from training_orchestrator.training import create_training_job, promote_version, rollback_champion

router = APIRouter(prefix="/api/v1")


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
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


@router.post("/models/{model_name}/training-jobs", response_model=TrainingJobResponse)
def start_training_job(
    model_name: str,
    body: TrainingJobCreate,
    db: Session = Depends(get_db),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> TrainingJobResponse:
    if x_tenant_id and x_tenant_id != body.tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    job = create_training_job(db, model_name, body)
    return _job_response(job)


@router.get("/training-jobs/{job_id}", response_model=TrainingJobResponse)
def get_training_job(
    job_id: str,
    db: Session = Depends(get_db),
    x_tenant_id: str = Header(default="tenant-acme", alias="X-Tenant-Id"),
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
    x_tenant_id: str = Header(default="tenant-acme", alias="X-Tenant-Id"),
) -> PromoteResponse:
    try:
        row, previous = promote_version(
            db, x_tenant_id, model_name, version, body.alias
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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
    x_tenant_id: str = Header(default="tenant-acme", alias="X-Tenant-Id"),
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
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict:
    if x_tenant_id and x_tenant_id != body.tenant_id:
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
    x_tenant_id: str = Header(default="tenant-acme", alias="X-Tenant-Id"),
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
    x_tenant_id: str = Header(default="tenant-acme", alias="X-Tenant-Id"),
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
        for row in rows:
            for key, value in dict(row.observation or {}).items():
                if isinstance(value, bool):
                    flags[key] = flags.get(key, False) or value
                elif isinstance(value, (int, float)):
                    numeric.setdefault(key, []).append(float(value))
        observed = {
            key: sum(values) / len(values)
            for key, values in numeric.items()
            if values
        }
        observed.update(flags)
    return DriftMetricsResponse(**compute_drift_metrics(model_name, observed))
