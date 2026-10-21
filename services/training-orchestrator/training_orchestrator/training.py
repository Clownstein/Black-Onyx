"""Training job execution for configured model trainers."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from training_orchestrator.config import settings
from training_orchestrator.dataset_manifest import build_dataset_manifest, inspect_reviewed_dataset
from training_orchestrator.models import ModelAlias, ModelVersionHistory, TrainingJob
from training_orchestrator.package_builder import build_model_package, verify_model_package
from training_orchestrator.schemas import TrainingJobCreate
from training_orchestrator.serving import (
    ServingConfirmationError,
    commit_serving_change,
    serving_lease,
)

# Aliases a model service actually serves; "candidate" is a bookkeeping label.
SERVED_ALIASES = frozenset({"champion", "canary", "shadow"})

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
    if Path("/app/detection/models").is_dir():
        return Path("/app")
    # services/training-orchestrator/training_orchestrator/training.py -> repo root
    return Path(__file__).resolve().parents[3]


def canonical_model_name(model_name: str) -> str | None:
    return _CANONICAL_MODELS.get(model_name)


def trainer_script_path(model_name: str) -> Path | None:
    canonical = canonical_model_name(model_name)
    if canonical is None:
        return None
    return _repo_root() / "detection" / "models" / canonical / "training" / "train.py"


def reviewed_dataset_path(value: str) -> Path:
    roots = settings.allowed_dataset_root_list()
    if not roots:
        raise ValueError(
            "dataset_path is disabled until TRAINING_ORCHESTRATOR_ALLOWED_DATASET_ROOTS is configured"
        )
    source = Path(value)
    if source.is_symlink():
        raise ValueError("dataset_path cannot be a symlink")
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise ValueError("reviewed dataset is missing") from exc
    if not resolved.is_file():
        raise ValueError("dataset_path must be a regular file")
    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        raise ValueError("dataset_path is outside configured allowed roots")
    size = resolved.stat().st_size
    if size <= 0 or size > settings.max_dataset_bytes:
        raise ValueError("reviewed dataset is empty or exceeds the configured size limit")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


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


def _reserve_version(
    db: Session,
    tenant_id: str,
    model_name: str,
    *,
    job_id: str | None = None,
    claim_owner: str | None = None,
    claim_attempt: int | None = None,
) -> str | None:
    """Reserve a version through the database uniqueness constraint.

    A concurrent worker may read the same latest version. Only one insert can
    commit; the loser retries against the new committed history.

    For leased jobs the version row and the job's claim check commit in one
    transaction: a worker whose lease was reclaimed gets ``None`` and burns
    no version number.
    """
    for _ in range(20):
        version = _next_version(db, tenant_id, model_name)
        db.add(ModelVersionHistory(
            tenant_id=tenant_id, model_name=model_name, version=version,
        ))
        if claim_owner is not None:
            fenced = db.execute(
                update(TrainingJob)
                .where(
                    TrainingJob.id == job_id,
                    TrainingJob.status == "running",
                    TrainingJob.claimed_by == claim_owner,
                    TrainingJob.attempt_count == claim_attempt,
                )
                .values(version=version)
                .execution_options(synchronize_session=False)
            )
            if fenced.rowcount != 1:
                db.rollback()
                return None
        try:
            db.commit()
            return version
        except IntegrityError:
            db.rollback()
    raise RuntimeError("Could not reserve a unique model version")


def _normalize_training_artifacts(artifacts_dir: Path, canonical: str) -> None:
    """Normalize only equivalent model filenames; never invent evaluation artifacts."""
    if not (artifacts_dir / "model.onnx").is_file():
        for candidate in (
            artifacts_dir / "network_model.onnx",
            artifacts_dir / "metrics_model.onnx",
            artifacts_dir / f"{canonical.replace('-', '_')}.onnx",
        ):
            if candidate.is_file() and candidate.stat().st_size > 0:
                shutil.copy2(candidate, artifacts_dir / "model.onnx")
                break



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
        if not payload:
            raise RuntimeError(f"trainer artifact must not be empty: {name}")
        return payload

    onnx_source = artifacts_dir / "model.onnx"
    joblib_source = artifacts_dir / "model.joblib"
    # The code-model calibrator and feature schema belong to the sklearn
    # joblib scorer. Its optional encoder ONNX has different inputs and scores.
    if canonical == "code-model" and joblib_source.is_file() and joblib_source.stat().st_size > 0:
        model_source = joblib_source
    elif onnx_source.is_file() and onnx_source.stat().st_size > 0:
        model_source = onnx_source
    elif joblib_source.is_file() and joblib_source.stat().st_size > 0:
        model_source = joblib_source
    else:
        raise RuntimeError(
            "trainer did not produce a non-empty model.onnx or model.joblib"
        )

    inputs = (
        model_source,
        required_json("metrics.json"),
        required_json("thresholds.json"),
        required_json("config.json"),
        required_json("calibration.json"),
    )
    if canonical == "log-model":
        vocab_path = artifacts_dir / "vocab.json"
        if not vocab_path.is_file() or vocab_path.stat().st_size == 0:
            raise RuntimeError("trainer did not produce required artifact: vocab.json")
    return inputs


def execute_training_job(db: Session, job: TrainingJob, request: TrainingJobCreate) -> TrainingJob:
    claim_owner = job.claimed_by
    claim_attempt = job.attempt_count
    now = datetime.now(UTC)
    job.status = "running"
    job.message = "training started"
    job.started_at = job.started_at or now
    job.heartbeat_at = now
    job.failure_reason = None
    db.add(job)
    db.commit()
    db.refresh(job)

    canonical = canonical_model_name(job.model_name)
    dataset_path: Path | None = None
    dataset_hash: str | None = None
    if request.dataset_path and not request.demo_synthetic:
        try:
            dataset_path = reviewed_dataset_path(request.dataset_path)
            dataset_hash = _sha256_file(dataset_path)
        except ValueError as exc:
            message = str(exc)
            job.status = "failed"
            job.message = message
            job.failure_reason = message
            job.finished_at = datetime.now(UTC)
            db.add(job)
            db.commit()
            db.refresh(job)
            return job
    model_type = (
        _MODEL_TYPE_FOR_MANIFEST.get(canonical or "", "generic")
        if canonical
        else "generic"
    )
    dataset_id = (
        request.dataset_id or f"{job.model_name}-{datetime.now(UTC).strftime('%Y-%m-%d')}-v1"
    )
    try:
        dataset_summary = (
            inspect_reviewed_dataset(dataset_path, tenant_id=request.tenant_id, model_type=model_type)
            if dataset_path else None
        )
    except (OSError, ValueError) as exc:
        job.status = "failed"
        job.message = str(exc)
        job.failure_reason = job.message
        job.finished_at = datetime.now(UTC)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job
    manifest = build_dataset_manifest(
        dataset_id=dataset_id,
        tenant_id=request.tenant_id,
        model_type=model_type,
        source_query=request.source_query,
        time_range_start=request.time_range_start,
        time_range_end=request.time_range_end,
        excluded_incidents=request.excluded_incidents,
        event_count=dataset_summary["event_count"] if dataset_summary else 0,
        sequence_count=dataset_summary["sequence_count"] if dataset_summary else 0,
        created_by=request.created_by,
        content_hash=dataset_hash,
    )
    manifest["data_mode"] = "synthetic_demo" if request.demo_synthetic else "reviewed_dataset"
    manifest["dataset_path"] = str(dataset_path) if dataset_path else None
    manifest["dataset_reviewed"] = request.dataset_reviewed
    if dataset_summary:
        manifest["feature_schema"] = dataset_summary["feature_schema"]
    job.dataset_manifest_json = json.dumps(manifest)

    out_root = Path(settings.package_output_dir)
    if not out_root.is_absolute():
        out_root = Path.cwd() / out_root / job.id
    else:
        out_root = out_root / job.id
    out_root.mkdir(parents=True, exist_ok=True)

    if canonical is None:
        job.status = "failed"
        job.message = f"no trainer is configured for model {job.model_name}"
        job.failure_reason = job.message
        job.finished_at = datetime.now(UTC)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    artifacts_dir = out_root / "training-artifacts"
    hyperparameters = dict(request.hyperparameters)
    if dataset_path:
        hyperparameters["dataset"] = str(dataset_path)
    trained, train_message = _run_modality_training(
        job.model_name, job.id, hyperparameters, artifacts_dir
    )
    if not trained:
        job.status = "failed"
        job.message = train_message
        job.failure_reason = train_message
        job.finished_at = datetime.now(UTC)
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
        job.failure_reason = job.message
        job.finished_at = datetime.now(UTC)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    if claim_owner:
        # Do not allocate a version or assemble a package after another worker
        # has reclaimed this lease. The final CAS still protects the race after
        # this read.
        db.refresh(job)
        if (
            job.status != "running"
            or job.claimed_by != claim_owner
            or job.attempt_count != claim_attempt
        ):
            return job

    version = _reserve_version(
        db, job.tenant_id, job.model_name,
        job_id=job.id, claim_owner=claim_owner or None,
        claim_attempt=claim_attempt if claim_owner else None,
    )
    if version is None:
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
        vocab_source=artifacts_dir / "vocab.json" if canonical == "log-model" else None,
    )

    finished_at = datetime.now(UTC)
    if claim_owner:
        # A reclaimed lease fences the old worker from publishing its result.
        claimed = db.execute(
            update(TrainingJob)
            .where(
                TrainingJob.id == job.id,
                TrainingJob.status == "running",
                TrainingJob.claimed_by == claim_owner,
                TrainingJob.attempt_count == claim_attempt,
            )
            .values(
                status="succeeded", version=version, package_path=str(package_dir),
                message=train_message, finished_at=finished_at,
                heartbeat_at=finished_at, lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            db.rollback()
            shutil.rmtree(package_dir, ignore_errors=True)
            db.refresh(job)
            return job

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

    if not claim_owner:
        job.status = "succeeded"
        job.version = version
        job.package_path = str(package_dir)
        job.message = train_message
        job.finished_at = finished_at
        job.heartbeat_at = finished_at
        job.lease_expires_at = None
        db.add(job)
    db.commit()
    db.refresh(job)
    return job


def create_training_job(
    db: Session, model_name: str, request: TrainingJobCreate,
    *, idempotency_key: str | None = None,
) -> TrainingJob:
    if canonical_model_name(model_name) is None:
        raise ValueError(f"no trainer is configured for model {model_name}")
    if request.demo_synthetic and not settings.allow_synthetic_training:
        raise ValueError("synthetic training is disabled; configure a reviewed dataset_path")
    if not request.run_async and not settings.allow_synchronous_training:
        raise ValueError("synchronous training is disabled; submit an asynchronous job")
    if request.dataset_path and not request.demo_synthetic:
        request.dataset_path = str(reviewed_dataset_path(request.dataset_path))
    if idempotency_key:
        existing = db.scalar(select(TrainingJob).where(
            TrainingJob.tenant_id == request.tenant_id,
            TrainingJob.idempotency_key == idempotency_key,
        ))
        if existing is not None:
            if (existing.model_name != model_name
                    or existing.request_json != request.model_dump(mode="json")):
                raise ValueError("idempotency key was already used for a different training request")
            return existing
    job = TrainingJob(
        id=str(uuid.uuid4()),
        idempotency_key=idempotency_key,
        tenant_id=request.tenant_id,
        model_name=model_name,
        status="queued",
        message="queued",
        request_json=request.model_dump(mode="json"),
        synthetic_data=request.demo_synthetic,
        max_attempts=settings.worker_max_attempts,
    )
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if not idempotency_key:
            raise
        existing = db.scalar(select(TrainingJob).where(
            TrainingJob.tenant_id == request.tenant_id,
            TrainingJob.idempotency_key == idempotency_key,
        ))
        if existing is None:
            raise
        if existing.model_name != model_name or existing.request_json != request.model_dump(mode="json"):
            raise ValueError("idempotency key was already used for a different training request")
        return existing
    db.refresh(job)

    if request.run_async:
        return job
    return execute_training_job(db, job, request)


def _model_name_variants(model_name: str) -> list[str]:
    """All request spellings that refer to the same canonical model."""
    canonical = canonical_model_name(model_name)
    if canonical is None:
        return [model_name]
    return sorted(name for name, value in _CANONICAL_MODELS.items() if value == canonical)


def _verify_version_package(
    db: Session, tenant_id: str, model_name: str, version: str,
) -> str:
    """Require a completed, signed package for a version before alias changes."""
    history = (
        db.query(ModelVersionHistory)
        .filter(
            ModelVersionHistory.tenant_id == tenant_id,
            ModelVersionHistory.model_name.in_(_model_name_variants(model_name)),
            ModelVersionHistory.version == version,
        )
        .one_or_none()
    )
    if history is None:
        raise LookupError(f"model version not found: {model_name} {version}")

    completed = (
        db.query(TrainingJob)
        .filter(
            TrainingJob.tenant_id == tenant_id,
            TrainingJob.model_name.in_(_model_name_variants(model_name)),
            TrainingJob.version == version,
            TrainingJob.status == "succeeded",
        )
        .one_or_none()
    )
    if completed is None or not completed.package_path:
        raise ValueError("Model version has no completed package")
    package_path = Path(completed.package_path)
    verify_model_package(
        package_path,
        settings.artifact_signing_key,
        expected_model_name=canonical_model_name(model_name),
    )
    package_config = json.loads((package_path / "config.json").read_text(encoding="utf-8"))
    if not isinstance(package_config, dict) or package_config.get("model_version") != version:
        raise ValueError("Model package version does not match the requested version")
    return str(package_path)


def promote_version(
    db: Session, tenant_id: str, model_name: str, version: str, alias: str
) -> tuple[ModelAlias, str | None]:
    allowed = {"champion", "canary", "shadow", "candidate"}
    if alias not in allowed:
        raise ValueError(f"unsupported alias: {alias}")

    package_path = _verify_version_package(db, tenant_id, model_name, version)
    serving_model = canonical_model_name(model_name) or model_name

    def commit_alias() -> tuple[ModelAlias, str | None]:
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

    if alias in SERVED_ALIASES:
        with serving_lease(db, tenant_id, serving_model, alias):
            # Do not release the alias lease between replica confirmation and
            # the authoritative model_aliases commit.
            return commit_serving_change(
                db, tenant_id, serving_model, alias, version, package_path,
                commit_alias=commit_alias,
            )
    return commit_alias()


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
    serving_model = canonical_model_name(model_name) or model_name
    with serving_lease(db, tenant_id, serving_model, "champion"):
        db.refresh(row)
        if expected_current_version and row.version != expected_current_version:
            raise ValueError(
                f"champion is {row.version}, not requested version {expected_current_version}"
            )
        if not row.previous_version:
            raise LookupError("no previous champion version to rollback to")
        target_version = row.previous_version
        package_path = _verify_version_package(db, tenant_id, model_name, target_version)
        def commit_rollback() -> ModelAlias:
            current = row.version
            row.version = target_version
            row.previous_version = current
            db.add(row)
            db.commit()
            db.refresh(row)
            return row

        return commit_serving_change(
            db, tenant_id, serving_model, "champion", target_version, package_path,
            commit_alias=commit_rollback,
        )
