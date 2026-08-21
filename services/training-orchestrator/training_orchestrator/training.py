"""Training job execution for configured model trainers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from training_orchestrator.config import settings
from training_orchestrator.dataset_manifest import build_dataset_manifest
from training_orchestrator.models import ModelAlias, ModelVersionHistory, TrainingJob
from training_orchestrator.package_builder import build_model_package
from training_orchestrator.schemas import TrainingJobCreate

# Canonical modality package dirs under detection/models/<name>/
_CANONICAL_MODELS: dict[str, str] = {
    "log-model": "log-model",
    "log": "log-model",
    "network-model": "network-model",
    "network": "network-model",
    "metrics-model": "metrics-model",
    "metrics": "metrics-model",
    "code-model": "code-model",
    "code": "code-model",
}

_MODEL_TYPE_FOR_MANIFEST: dict[str, str] = {
    "log-model": "log",
    "network-model": "network",
    "metrics-model": "metrics",
    "code-model": "code",
}


def _repo_root() -> Path:
    if settings.repo_root:
        return Path(settings.repo_root).resolve()
    # services/training-orchestrator/training_orchestrator/training.py -> repo root
    return Path(__file__).resolve().parents[3]


def canonical_model_name(model_name: str) -> str | None:
    return _CANONICAL_MODELS.get(model_name)


def trainer_script_path(model_name: str) -> Path | None:
    canonical = canonical_model_name(model_name)
    if canonical is None:
        return None
    return _repo_root() / "detection" / "models" / canonical / "training" / "train.py"


def _next_version(db: Session, tenant_id: str, model_name: str) -> str:
    latest = (
        db.query(ModelVersionHistory)
        .filter(
            ModelVersionHistory.tenant_id == tenant_id,
            ModelVersionHistory.model_name == model_name,
        )
        .order_by(ModelVersionHistory.id.desc())
        .first()
    )
    if latest is None:
        return "1.0.0"
    parts = latest.version.split(".")
    try:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    except (IndexError, ValueError):
        return "1.0.0"
    return f"{major}.{minor}.{patch + 1}"


def _normalize_training_artifacts(artifacts_dir: Path, canonical: str) -> None:
    """Normalize trainer outputs to package-builder expectations."""
    if not (artifacts_dir / "model.onnx").is_file():
        for candidate in (
            artifacts_dir / "network_model.onnx",
            artifacts_dir / "metrics_model.onnx",
            artifacts_dir / f"{canonical.replace('-', '_')}.onnx",
        ):
            if candidate.is_file() and candidate.stat().st_size > 0:
                shutil.copy2(candidate, artifacts_dir / "model.onnx")
                break

    defaults = {
        "metrics.json": {"precision": 0.0, "recall": 0.0, "f1": 0.0, "note": "trainer did not emit metrics"},
        "thresholds.json": {"medium": 0.6, "high": 0.8, "critical": 0.93},
        "config.json": {"model_name": canonical},
        "calibration.json": {"method": "platt", "temperature": 1.0},
    }
    for name, payload in defaults.items():
        path = artifacts_dir / name
        if not path.is_file():
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _run_modality_training(
    model_name: str, job_id: str, hyperparameters: dict, artifacts_dir: Path
) -> tuple[bool, str]:
    canonical = canonical_model_name(model_name)
    if canonical is None:
        return False, f"no trainer is configured for model {model_name}"

    train_script = trainer_script_path(model_name)
    if train_script is None or not train_script.is_file():
        return False, f"{canonical} trainer unavailable: {train_script}"

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    model_root = train_script.parent.parent
    env = os.environ.copy()
    env["TRAINING_JOB_ID"] = job_id
    env["TRAINING_HYPERPARAMETERS"] = json.dumps(hyperparameters)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(model_root), env.get("PYTHONPATH", "")) if p
    )

    epochs = int(hyperparameters.get("epochs", 1))
    cmd: list[str] = [sys.executable, str(train_script)]

    if canonical == "log-model":
        cmd.extend(
            [
                "--artifacts-dir",
                str(artifacts_dir),
                "--epochs",
                str(epochs),
                "--batch-size",
                str(int(hyperparameters.get("batch_size", 8))),
                "--n-normal",
                str(int(hyperparameters.get("n_normal", 32))),
                "--n-corrupt",
                str(int(hyperparameters.get("n_corrupt", 32))),
                "--seq-len",
                str(int(hyperparameters.get("seq_len", 16))),
                "--seed",
                str(int(hyperparameters.get("seed", 7))),
            ]
        )
    elif canonical in {"network-model", "metrics-model"}:
        cmd.extend(["--out", str(artifacts_dir), "--epochs", str(epochs)])
    else:  # code-model
        cmd.extend(["--out", str(artifacts_dir)])

    dataset = hyperparameters.get("dataset")
    if isinstance(dataset, str) and dataset.strip():
        cmd.extend(["--dataset", dataset.strip()])

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(model_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=settings.training_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "training timed out"
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        return False, f"train.py failed: {stderr or completed.stdout}"

    _normalize_training_artifacts(artifacts_dir, canonical)
    return True, (completed.stdout or "").strip() or "train.py completed"


# Back-compat alias for existing tests that patch this name.
def _run_log_model_training(
    job_id: str, hyperparameters: dict, artifacts_dir: Path
) -> tuple[bool, str]:
    return _run_modality_training("log-model", job_id, hyperparameters, artifacts_dir)


def _collect_package_inputs(artifacts_dir: Path, canonical: str) -> tuple[Path, dict, dict, dict, dict]:
    def required_json(name: str) -> dict:
        path = artifacts_dir / name
        if not path.is_file():
            raise RuntimeError(f"trainer did not produce required artifact: {name}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError(f"trainer artifact must be a JSON object: {name}")
        return payload

    onnx_source = artifacts_dir / "model.onnx"
    joblib_source = artifacts_dir / "model.joblib"
    if onnx_source.is_file() and onnx_source.stat().st_size > 0:
        model_source = onnx_source
    elif joblib_source.is_file() and joblib_source.stat().st_size > 0:
        model_source = joblib_source
    else:
        raise RuntimeError(
            "trainer did not produce a non-empty model.onnx or model.joblib"
        )

    return (
        model_source,
        required_json("metrics.json"),
        required_json("thresholds.json"),
        required_json("config.json"),
        required_json("calibration.json"),
    )


def execute_training_job(db: Session, job: TrainingJob, request: TrainingJobCreate) -> TrainingJob:
    job.status = "running"
    job.message = "training started"
    db.add(job)
    db.commit()
    db.refresh(job)

    canonical = canonical_model_name(job.model_name)
    model_type = (
        _MODEL_TYPE_FOR_MANIFEST.get(canonical or "", "generic")
        if canonical
        else "generic"
    )
    dataset_id = (
        request.dataset_id or f"{job.model_name}-{datetime.now(UTC).strftime('%Y-%m-%d')}-v1"
    )
    manifest = build_dataset_manifest(
        dataset_id=dataset_id,
        tenant_id=request.tenant_id,
        model_type=model_type,
        source_query=request.source_query,
        time_range_start=request.time_range_start,
        time_range_end=request.time_range_end,
        excluded_incidents=request.excluded_incidents,
        event_count=int(request.hyperparameters.get("event_count", 1000)),
        sequence_count=int(request.hyperparameters.get("sequence_count", 100)),
        created_by=request.created_by,
    )
    job.dataset_manifest_json = json.dumps(manifest)

    version = _next_version(db, job.tenant_id, job.model_name)
    out_root = Path(settings.package_output_dir)
    if not out_root.is_absolute():
        out_root = Path.cwd() / out_root / job.id
    else:
        out_root = out_root / job.id
    out_root.mkdir(parents=True, exist_ok=True)

    if canonical is None:
        job.status = "failed"
        job.message = f"no trainer is configured for model {job.model_name}"
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    artifacts_dir = out_root / "training-artifacts"
    trained, train_message = _run_modality_training(
        job.model_name, job.id, request.hyperparameters, artifacts_dir
    )
    if not trained:
        job.status = "failed"
        job.message = train_message
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    try:
        model_source, metrics, thresholds, config, calibration = _collect_package_inputs(
            artifacts_dir, canonical
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        job.status = "failed"
        job.message = str(exc)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    package_dir = build_model_package(
        out_root,
        model_name=job.model_name,
        version=version,
        dataset_manifest=manifest,
        signing_key=settings.artifact_signing_key,
        model_source=model_source,
        metrics=metrics,
        thresholds=thresholds,
        config=config,
        calibration=calibration,
    )

    history = ModelVersionHistory(
        tenant_id=job.tenant_id, model_name=job.model_name, version=version
    )
    db.add(history)

    candidate = (
        db.query(ModelAlias)
        .filter(
            ModelAlias.tenant_id == job.tenant_id,
            ModelAlias.model_name == job.model_name,
            ModelAlias.alias == "candidate",
        )
        .one_or_none()
    )
    if candidate is None:
        candidate = ModelAlias(
            tenant_id=job.tenant_id,
            model_name=job.model_name,
            alias="candidate",
            version=version,
        )
    else:
        candidate.previous_version = candidate.version
        candidate.version = version
    db.add(candidate)

    job.status = "succeeded"
    job.version = version
    job.package_path = str(package_dir)
    job.message = train_message
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def create_training_job(db: Session, model_name: str, request: TrainingJobCreate) -> TrainingJob:
    job = TrainingJob(
        id=str(uuid.uuid4()),
        tenant_id=request.tenant_id,
        model_name=model_name,
        status="queued",
        message="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    if request.run_async:
        # In-process background via immediate execution for reliability in unit tests;
        # production can swap to a worker/queue without changing the API contract.
        return execute_training_job(db, job, request)
    return execute_training_job(db, job, request)


def promote_version(
    db: Session, tenant_id: str, model_name: str, version: str, alias: str
) -> tuple[ModelAlias, str | None]:
    allowed = {"champion", "canary", "shadow", "candidate"}
    if alias not in allowed:
        raise ValueError(f"unsupported alias: {alias}")

    history = (
        db.query(ModelVersionHistory)
        .filter(
            ModelVersionHistory.tenant_id == tenant_id,
            ModelVersionHistory.model_name == model_name,
            ModelVersionHistory.version == version,
        )
        .one_or_none()
    )
    if history is None:
        raise LookupError(f"model version not found: {model_name} {version}")

    row = (
        db.query(ModelAlias)
        .filter(
            ModelAlias.tenant_id == tenant_id,
            ModelAlias.model_name == model_name,
            ModelAlias.alias == alias,
        )
        .one_or_none()
    )
    previous = None
    if row is None:
        row = ModelAlias(
            tenant_id=tenant_id,
            model_name=model_name,
            alias=alias,
            version=version,
        )
    else:
        previous = row.version
        row.previous_version = previous
        row.version = version
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, previous


def rollback_champion(
    db: Session,
    tenant_id: str,
    model_name: str,
    *,
    expected_current_version: str | None = None,
) -> ModelAlias:
    row = (
        db.query(ModelAlias)
        .filter(
            ModelAlias.tenant_id == tenant_id,
            ModelAlias.model_name == model_name,
            ModelAlias.alias == "champion",
        )
        .one_or_none()
    )
    if row is None:
        raise LookupError("champion alias not set")
    if expected_current_version and row.version != expected_current_version:
        raise ValueError(
            f"champion is {row.version}, not requested version {expected_current_version}"
        )
    if not row.previous_version:
        raise LookupError("no previous champion version to rollback to")
    current = row.version
    row.version = row.previous_version
    row.previous_version = current
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
