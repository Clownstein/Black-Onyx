import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from training_orchestrator import config
from training_orchestrator.dataset_manifest import build_dataset_manifest, inspect_reviewed_dataset
from training_orchestrator.db import Base, get_db
from training_orchestrator.main import app
from training_orchestrator.package_builder import PACKAGE_FILES, build_model_package, verify_model_package
from training_orchestrator import training
from training_orchestrator import worker
from training_orchestrator.models import ModelAlias, ModelVersionHistory, TrainingJob
from training_orchestrator.schemas import TrainingJobCreate
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

TEST_VOCAB = {"[PAD]": 0, "[CLS]": 1, "[SEP]": 2, "[MASK]": 3, "[UNK]": 4, "tpl-test": 5}


def test_model_versions_are_reserved_before_package_build() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    with Session() as first, Session() as second:
        one = training._reserve_version(first, "tenant-acme", "log-model")
        two = training._reserve_version(second, "tenant-acme", "log-model")
        assert (one, two) == ("1.0.0", "1.0.1")
        assert second.query(ModelVersionHistory).count() == 2


def test_signed_package_verification_detects_tampering(tmp_path: Path) -> None:
    source = tmp_path / "trained.onnx"
    source.write_bytes(b"trained-test-artifact")
    vocab = tmp_path / "vocab.json"
    vocab.write_text(json.dumps(TEST_VOCAB), encoding="utf-8")
    package = build_model_package(
        tmp_path, model_name="log-model", version="1.0.0",
        dataset_manifest={"feature_schema": {"features": ["events.template_id"]}},
        signing_key="test-signing-key", model_source=source,
        metrics={}, thresholds={}, config={"model_name": "log-model"}, calibration={},
        vocab_source=vocab,
    )
    assert verify_model_package(package, "test-signing-key") == "model.onnx"
    packaged_config = json.loads((package / "config.json").read_text(encoding="utf-8"))
    assert packaged_config["model_version"] == "1.0.0"
    (package / "model.onnx").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="failed verification"):
        verify_model_package(package, "test-signing-key")


@pytest.mark.parametrize(
    ("requested", "trainer"),
    [("log", "log-transformer"), ("network", "network-model"),
     ("metrics", "metrics-model"), ("code", "code-model")],
)
def test_supported_training_aliases_get_canonical_signed_identity(
    tmp_path: Path, requested: str, trainer: str,
) -> None:
    source = tmp_path / "trained.onnx"
    source.write_bytes(b"test-weights")
    vocab = tmp_path / "vocab.json"
    vocab.write_text(json.dumps(TEST_VOCAB), encoding="utf-8")
    package = build_model_package(
        tmp_path, model_name=requested, version="1.0.0",
        dataset_manifest={}, signing_key="test-signing-key", model_source=source,
        metrics={}, thresholds={}, config={"model_name": trainer}, calibration={},
        vocab_source=vocab if requested == "log" else None,
    )
    expected = "log-model" if requested == "log" else f"{requested}-model"
    assert json.loads((package / "config.json").read_text(encoding="utf-8"))["model_name"] == expected
    assert verify_model_package(package, "test-signing-key", expected_model_name=expected) == "model.onnx"


def test_log_package_requires_signed_vocabulary_and_rejects_extra_weights(tmp_path: Path) -> None:
    source = tmp_path / "trained.onnx"
    source.write_bytes(b"trained-test-artifact")
    with pytest.raises(ValueError, match="vocab.json"):
        build_model_package(
            tmp_path / "missing", model_name="log-model", version="1.0.0",
            dataset_manifest={}, signing_key="test-key", model_source=source,
            metrics={}, thresholds={}, config={"model_name": "log-model"}, calibration={},
        )
    vocab = tmp_path / "vocab.json"
    vocab.write_text(json.dumps(TEST_VOCAB), encoding="utf-8")
    package = build_model_package(
        tmp_path / "valid", model_name="log-model", version="1.0.0",
        dataset_manifest={}, signing_key="test-key", model_source=source,
        metrics={}, thresholds={}, config={"model_name": "log-model"}, calibration={},
        vocab_source=vocab,
    )
    (package / "model.pt").write_bytes(b"unsigned fallback")
    with pytest.raises(ValueError, match="unsigned files"):
        verify_model_package(package, "test-key")
    (package / "model.pt").unlink()
    (package / "vocab.json").write_text('{"[PAD]": 0}', encoding="utf-8")
    with pytest.raises(ValueError, match="failed verification"):
        verify_model_package(package, "test-key")


def test_reclaimed_worker_cannot_publish_candidate(tmp_path: Path, monkeypatch) -> None:
    engine = create_engine(
        "sqlite+pysqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(config.settings, "package_output_dir", str(tmp_path))
    monkeypatch.setattr(config.settings, "artifact_signing_key", "test-signing-key")
    request = TrainingJobCreate(
        tenant_id="tenant-acme", created_by="analyst@example.test",
        run_async=True, demo_synthetic=True,
    )
    with Session() as db:
        job = TrainingJob(
            id="stale-job", tenant_id="tenant-acme", model_name="log-model",
            status="running", request_json=request.model_dump(mode="json"),
            claimed_by="worker-a", attempt_count=1, max_attempts=3,
        )
        db.add(job)
        db.commit()
        source = tmp_path / "trained.onnx"
        source.write_bytes(b"test-only-artifact")

        def reclaim(_model, _job, _hyperparameters, _artifacts_dir):
            with Session() as other:
                other.query(TrainingJob).filter_by(id="stale-job").update(
                    {"claimed_by": "worker-b", "attempt_count": 2}
                )
                other.commit()
            return True, "trained"

        monkeypatch.setattr(training, "_run_modality_training", reclaim)
        monkeypatch.setattr(
            training, "_collect_package_inputs",
            lambda *_: (source, {}, {}, {}, {}),
        )
        result = training.execute_training_job(db, job, request)
        assert result.status == "running"
        assert result.claimed_by == "worker-b"
        assert db.query(ModelAlias).count() == 0


def test_reviewed_dataset_counts_and_schema_come_from_rows(tmp_path: Path) -> None:
    dataset = tmp_path / "reviewed.jsonl"
    rows = [
        {"tenant_id": "tenant-acme", "event_type": "logs.features",
         "events": [{"template_id": "one", "delta_ms": 0}, {"template_id": "two", "delta_ms": 4}]},
        {"tenant_id": "tenant-acme", "event_type": "logs.features",
         "events": [{"template_id": "three", "severity": "WARN"}]},
    ]
    dataset.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    summary = inspect_reviewed_dataset(dataset, tenant_id="tenant-acme", model_type="log")
    assert summary["event_count"] == 3
    assert summary["sequence_count"] == 2
    assert summary["feature_schema"]["features"] == [
        "events.delta_ms", "events.severity", "events.template_id",
    ]
    with pytest.raises(ValueError, match="tenant mismatch"):
        inspect_reviewed_dataset(dataset, tenant_id="other-tenant", model_type="log")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(config.settings, "package_output_dir", str(tmp_path / "packages"))
    monkeypatch.setattr(config.settings, "repo_root", str(tmp_path))
    monkeypatch.setattr(config.settings, "artifact_signing_key", "test-key")
    monkeypatch.setattr(config.settings, "api_key", "test-api-key")
    monkeypatch.setattr(config.settings, "allowed_dataset_roots", str(tmp_path))
    monkeypatch.setattr(config.settings, "allow_synthetic_training", True)
    monkeypatch.setattr(config.settings, "allow_synchronous_training", True)
    # Serving confirmation is exercised by the dedicated serving tests below.
    monkeypatch.setattr(config.settings, "serving_confirmation_required", False)

    def fake_trainer(model_name: str, _job_id: str, _hyperparameters: dict, artifacts_dir: Path):
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        (artifacts_dir / "model.onnx").write_bytes(b"test-only-onnx")
        if model_name == "log-model":
            (artifacts_dir / "vocab.json").write_text(json.dumps(TEST_VOCAB), encoding="utf-8")
        for name, payload in {
            "metrics.json": {"precision": 0.9, "recall": 0.8, "f1": 0.85},
            "thresholds.json": {"medium": 0.6, "high": 0.8, "critical": 0.93},
            "config.json": {"model_name": model_name, "model_version": "test"},
            "calibration.json": {"method": "platt", "temperature": 1.0},
        }.items():
            (artifacts_dir / name).write_text(json.dumps(payload), encoding="utf-8")
        return True, "test trainer completed"

    monkeypatch.setattr(training, "_run_modality_training", fake_trainer)
    monkeypatch.setattr(
        training,
        "_run_log_model_training",
        lambda job_id, hyperparameters, artifacts_dir: fake_trainer(
            "log-model", job_id, hyperparameters, artifacts_dir
        ),
    )

    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def _override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    with TestClient(
        app,
        headers={"X-API-Key": "test-api-key", "X-Tenant-Id": "tenant-acme"},
    ) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_unconfigured_api_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "api_key", "")
    monkeypatch.setattr(config.settings, "artifact_signing_key", "")
    with TestClient(app) as unconfigured:
        assert unconfigured.get("/health/ready").status_code == 503
        response = unconfigured.get("/api/v1/training-jobs/missing")
    assert response.status_code == 503


def test_training_routes_require_explicit_tenant_header(client: TestClient) -> None:
    response = client.get(
        "/api/v1/training-jobs/missing",
        headers={"X-API-Key": "test-api-key", "X-Tenant-Id": ""},
    )
    assert response.status_code == 422


def test_training_job_start_is_idempotent_and_list_is_tenant_scoped(client: TestClient) -> None:
    payload = {
        "tenant_id": "tenant-acme", "created_by": "analyst@example.test",
        "run_async": True, "demo_synthetic": True,
    }
    headers = {"Idempotency-Key": "stable-request-123"}
    first = client.post("/api/v1/models/log-model/training-jobs", json=payload, headers=headers)
    retried = client.post("/api/v1/models/log-model/training-jobs", json=payload, headers=headers)
    assert first.status_code == retried.status_code == 200
    assert first.json()["job_id"] == retried.json()["job_id"]
    conflict = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={**payload, "hyperparameters": {"changed": True}}, headers=headers,
    )
    assert conflict.status_code == 400
    listed = client.get("/api/v1/training-jobs?model_name=log-model")
    assert listed.status_code == 200
    assert [row["job_id"] for row in listed.json()] == [first.json()["job_id"]]
    assert listed.json()[0]["tenant_id"] == "tenant-acme"


def test_worker_refuses_missing_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "artifact_signing_key", "")
    with pytest.raises(RuntimeError, match="ARTIFACT_SIGNING_KEY"):
        worker.run_once("worker-without-key")


def test_training_job_promote_rollback_and_drift(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    create = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
            "demo_synthetic": True,
            "hyperparameters": {"event_count": 10},
        },
    )
    assert create.status_code == 200
    body = create.json()
    assert body["status"] == "succeeded"
    assert body["version"]
    assert body["dataset_manifest"]["model_type"] == "log"
    assert "content_hash" in body["dataset_manifest"]
    job_id = body["job_id"]

    fetched = client.get(f"/api/v1/training-jobs/{job_id}")
    assert fetched.status_code == 200
    assert fetched.json()["job_id"] == job_id

    version = body["version"]
    verified_identities: list[str | None] = []
    real_verify = training.verify_model_package

    def verify_identity(*args, **kwargs):
        verified_identities.append(kwargs.get("expected_model_name"))
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(training, "verify_model_package", verify_identity)
    promote = client.post(
        f"/api/v1/models/log-model/versions/{version}/promote",
        json={"alias": "champion"},
    )
    assert promote.status_code == 200, promote.json()
    assert promote.json()["alias"] == "champion"
    assert promote.json()["version"] == version
    assert verified_identities == ["log-model"]

    create2 = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
            "demo_synthetic": True,
        },
    )
    v2 = create2.json()["version"]
    client.post(f"/api/v1/models/log-model/versions/{v2}/promote", json={"alias": "champion"})

    stale = client.post(f"/api/v1/models/log-model/versions/not-current/rollback")
    assert stale.status_code == 409

    db_iterator = app.dependency_overrides[get_db]()
    db = next(db_iterator)
    try:
        first_job = db.query(TrainingJob).filter(TrainingJob.id == job_id).one()
        saved_package_path = first_job.package_path
        first_job.package_path = str(Path(saved_package_path).with_name("missing-package"))
        db.commit()
    finally:
        db_iterator.close()
    unavailable = client.post(f"/api/v1/models/log-model/versions/{v2}/rollback")
    assert unavailable.status_code == 409
    db_iterator = app.dependency_overrides[get_db]()
    db = next(db_iterator)
    try:
        champion = db.query(ModelAlias).filter(ModelAlias.alias == "champion").one()
        assert champion.version == v2
        first_job = db.query(TrainingJob).filter(TrainingJob.id == job_id).one()
        first_job.package_path = saved_package_path
        db.commit()
    finally:
        db_iterator.close()

    rollback = client.post(f"/api/v1/models/log-model/versions/{v2}/rollback")
    assert rollback.status_code == 200
    assert rollback.json()["version"] == version

    drift = client.get("/api/v1/models/log-model/drift")
    assert drift.status_code == 200
    payload = drift.json()
    assert "input_drift" in payload
    assert "unknown_template_rate" in payload["input_drift"]
    assert "output_drift" in payload
    assert "concept_drift" in payload

    observed = client.post(
        "/api/v1/models/log-model/drift/observations",
        headers={"X-Tenant-Id": "tenant-acme"},
        json={
            "tenant_id": "tenant-acme",
            "observed": {
                "unknown_template_rate": 0.4,
                "score_distribution_psi": 0.6,
            },
        },
    )
    assert observed.status_code == 201
    updated = client.get(
        "/api/v1/models/log-model/drift",
        headers={"X-Tenant-Id": "tenant-acme"},
    ).json()
    assert updated["input_drift"]["unknown_template_rate"] == 0.4
    assert updated["output_drift"]["score_distribution_psi"] == 0.6

    hidden = client.get(
        f"/api/v1/training-jobs/{job_id}",
        headers={"X-Tenant-Id": "tenant-other"},
    )
    assert hidden.status_code == 404

    history = client.get(
        "/api/v1/models/log-model/versions",
        headers={"X-Tenant-Id": "tenant-acme"},
    )
    assert history.status_code == 200
    assert {item["version"] for item in history.json()["items"]} >= {version, v2}


def test_promotion_rejects_signed_package_for_another_model(
    client: TestClient, tmp_path: Path,
) -> None:
    created = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "analyst@example.test",
              "run_async": False, "demo_synthetic": True},
    )
    assert created.status_code == 200, created.json()
    body = created.json()
    source = tmp_path / "other.onnx"
    source.write_bytes(b"signed-other-model")
    wrong_package = build_model_package(
        tmp_path, model_name="metrics-model", version=body["version"],
        dataset_manifest={}, signing_key="test-key", model_source=source,
        metrics={}, thresholds={}, config={"model_name": "metrics-model"}, calibration={},
    )
    db_iterator = app.dependency_overrides[get_db]()
    db = next(db_iterator)
    try:
        job = db.query(TrainingJob).filter(TrainingJob.id == body["job_id"]).one()
        job.package_path = str(wrong_package)
        db.commit()
    finally:
        db_iterator.close()
    response = client.post(
        f"/api/v1/models/log-model/versions/{body['version']}/promote",
        json={"alias": "champion"},
    )
    assert response.status_code == 400
    assert "identity mismatch" in response.json()["detail"]


def test_package_builder_writes_full_layout(tmp_path: Path) -> None:
    manifest = build_dataset_manifest(
        dataset_id="logs-test",
        tenant_id="tenant-acme",
        model_type="log",
        source_query="SELECT 1",
        time_range_start="2026-06-01T00:00:00Z",
        time_range_end="2026-07-15T00:00:00Z",
        created_by="test",
    )
    onnx = tmp_path / "trained.onnx"
    onnx.write_bytes(b"test-only-onnx")
    vocab = tmp_path / "vocab.json"
    vocab.write_text(json.dumps(TEST_VOCAB), encoding="utf-8")
    package = build_model_package(
        tmp_path,
        model_name="log-model",
        version="1.0.0",
        dataset_manifest=manifest,
        signing_key="test-key",
        model_source=onnx,
        metrics={"precision": 0.9, "recall": 0.8, "f1": 0.85},
        thresholds={"medium": 0.6, "high": 0.8, "critical": 0.93},
        config={"model_name": "log-model", "model_version": "1.0.0"},
        calibration={"method": "platt", "temperature": 1.0},
        vocab_source=vocab,
    )
    for name in PACKAGE_FILES:
        assert (package / name).exists()
    assert (package / "vocab.json").exists()
    signature = json.loads((package / "signature.json").read_text(encoding="utf-8"))
    assert signature["alg"] == "HMAC-SHA256"
    assert signature["signature"]


def test_training_job_fails_when_trainer_is_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        training,
        "_run_modality_training",
        lambda *_args, **_kwargs: (False, "log-model trainer unavailable"),
    )
    response = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
            "demo_synthetic": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "failed"
    assert response.json()["version"] is None
    assert response.json()["package_path"] is None


def test_trainer_paths_resolve_under_detection_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "repo_root", str(tmp_path))
    for name in ("log-model", "network-model", "metrics-model", "code-model"):
        script = tmp_path / "detection" / "models" / name / "training" / "train.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("# stub\n", encoding="utf-8")
        resolved = training.trainer_script_path(name)
        assert resolved is not None
        assert resolved.is_file()
        assert "detection" in resolved.parts
        assert resolved.name == "train.py"


def test_network_model_training_job_succeeds(client: TestClient) -> None:
    response = client.post(
        "/api/v1/models/network-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
            "demo_synthetic": True,
            "hyperparameters": {"epochs": 1},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "succeeded"
    assert body["dataset_manifest"]["model_type"] == "network"


def test_unknown_version_cannot_be_promoted(client: TestClient) -> None:
    response = client.post(
        "/api/v1/models/log-model/versions/9.9.9/promote",
        json={"alias": "champion"},
    )
    assert response.status_code == 404


def test_async_job_returns_queued_without_running_trainer(client: TestClient) -> None:
    response = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": True,
            "demo_synthetic": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "queued"
    assert body["attempt_count"] == 0
    assert body["synthetic_data"] is True
    assert body["version"] is None


def test_reviewed_dataset_or_explicit_demo_is_required(client: TestClient) -> None:
    response = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "analyst@example.test"},
    )
    assert response.status_code == 422
    unreviewed = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "dataset_path": "/datasets/reviewed.jsonl",
        },
    )
    assert unreviewed.status_code == 422
    assert "dataset_reviewed=true" in unreviewed.text


def test_reviewed_dataset_must_be_under_configured_root(client: TestClient, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-training.jsonl"
    outside.write_text('{"label": 1}\n', encoding="utf-8")
    response = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "dataset_path": str(outside),
            "dataset_reviewed": True,
        },
    )
    assert response.status_code == 400
    assert "outside configured allowed roots" in response.json()["detail"]


def test_unsupported_model_is_rejected_before_queueing(client: TestClient) -> None:
    response = client.post(
        "/api/v1/models/host-state-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "analyst@example.test", "demo_synthetic": True},
    )
    assert response.status_code == 400
    assert "no trainer is configured" in response.json()["detail"]


def test_missing_metrics_fail_instead_of_being_synthesized(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "model.onnx").write_bytes(b"model")
    with pytest.raises(RuntimeError, match="metrics.json"):
        training._collect_package_inputs(artifacts, "log-model")


def test_code_package_uses_weight_matching_its_calibrator(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "model.onnx").write_bytes(b"encoder")
    (artifacts / "model.joblib").write_bytes(b"sklearn")
    for name in ("metrics.json", "thresholds.json", "config.json", "calibration.json"):
        (artifacts / name).write_text('{"verified": true}', encoding="utf-8")
    source, *_ = training._collect_package_inputs(artifacts, "code-model")
    assert source.name == "model.joblib"


def test_worker_claims_and_completes_queued_job(client: TestClient) -> None:
    queued = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": True,
            "demo_synthetic": True,
        },
    ).json()
    db_factory = app.dependency_overrides[get_db]
    db_iter = db_factory()
    db = next(db_iter)
    try:
        claimed = worker.claim_next_job(db, "worker-test")
        assert claimed is not None
        assert claimed.id == queued["job_id"]
        assert claimed.attempt_count == 1
        assert claimed.claimed_by == "worker-test"
        assert worker.claim_next_job(db, "worker-other") is None
        completed = worker.run_claimed_job(db, claimed)
        assert completed.status == "succeeded"
        assert completed.finished_at is not None
    finally:
        db_iter.close()


def test_worker_recovers_an_expired_lease(client: TestClient) -> None:
    queued = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "analyst@example.test", "demo_synthetic": True},
    ).json()
    db_factory = app.dependency_overrides[get_db]
    db_iter = db_factory()
    db = next(db_iter)
    try:
        first = worker.claim_next_job(db, "worker-one")
        assert first is not None
        first.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.add(first)
        db.commit()
        recovered = worker.claim_next_job(db, "worker-two")
        assert recovered is not None
        assert recovered.id == queued["job_id"]
        assert recovered.claimed_by == "worker-two"
        assert recovered.attempt_count == 2
    finally:
        db_iter.close()


def test_worker_marks_exhausted_expired_lease_failed(client: TestClient) -> None:
    queued = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "analyst@example.test",
              "demo_synthetic": True},
    ).json()
    db_iter = app.dependency_overrides[get_db]()
    db = next(db_iter)
    try:
        job = worker.claim_next_job(db, "worker-final")
        assert job is not None
        job.max_attempts = job.attempt_count
        job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        assert worker.claim_next_job(db, "worker-next") is None
        db.refresh(job)
        assert job.id == queued["job_id"]
        assert job.status == "failed"
        assert "lease expired" in (job.failure_reason or "")
    finally:
        db_iter.close()


def test_worker_requeues_failure_until_attempt_limit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    client.post(
        "/api/v1/models/log-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "analyst@example.test", "demo_synthetic": True},
    )
    db_factory = app.dependency_overrides[get_db]
    db_iter = db_factory()
    db = next(db_iter)
    try:
        claimed = worker.claim_next_job(db, "worker-fail")
        assert claimed is not None
        claimed.max_attempts = 2
        db.commit()
        monkeypatch.setattr(worker, "execute_training_job", lambda *_args: (_ for _ in ()).throw(RuntimeError("trainer crashed")))
        first = worker.run_claimed_job(db, claimed)
        assert first.status == "queued"
        second_claim = worker.claim_next_job(db, "worker-fail-again")
        assert second_claim is not None
        final = worker.run_claimed_job(db, second_claim)
        assert final.status == "failed"
        assert final.failure_reason == "trainer crashed"
    finally:
        db_iter.close()


def test_synthetic_training_must_be_enabled(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config.settings, "allow_synthetic_training", False)
    response = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": True,
            "demo_synthetic": True,
        },
    )
    assert response.status_code == 400
    assert "synthetic training is disabled" in response.json()["detail"]


def test_synchronous_training_must_be_explicitly_enabled(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config.settings, "allow_synchronous_training", False)
    response = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
            "demo_synthetic": True,
        },
    )
    assert response.status_code == 400
    assert "synchronous training is disabled" in response.json()["detail"]



# ── Two-phase serving promotion ──────────────────────────────────────────


def _train(client: TestClient) -> str:
    body = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={"tenant_id": "tenant-acme", "created_by": "a@example.test", "run_async": False, "demo_synthetic": True},
    ).json()
    assert body["status"] == "succeeded", body
    return body["version"]


def _fast_confirmation(monkeypatch: pytest.MonkeyPatch, on_wait=None) -> None:
    from training_orchestrator import serving

    monkeypatch.setattr(config.settings, "serving_confirmation_required", True)
    monkeypatch.setattr(config.settings, "serving_confirm_timeout_seconds", 0.5)
    monkeypatch.setattr(config.settings, "serving_confirm_poll_seconds", 0.01)
    calls = {"n": 0}

    def fake_sleep(_seconds: float) -> None:
        calls["n"] += 1
        if on_wait is not None:
            on_wait()

    monkeypatch.setattr(serving.time, "sleep", fake_sleep)


def _replica_reports(slots: dict, errors: dict | None = None, instance: str = "replica-1") -> None:
    from training_orchestrator import serving

    db_iterator = app.dependency_overrides[get_db]()
    db = next(db_iterator)
    try:
        serving.record_report(db, "tenant-acme", "log-model", instance, slots, errors or {})
    finally:
        db_iterator.close()


def _desired(client: TestClient) -> dict:
    return client.get("/api/v1/serving/log-model/desired").json()["aliases"]


def test_promotion_commits_only_after_replicas_serve_the_package(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    version = _train(client)
    # A live replica that has not loaded anything yet.
    _replica_reports({})

    def replica_loads() -> None:
        target = _desired(client)["champion"]
        _replica_reports({"champion": {
            "version": target["version"], "signature": target["signature"],
            "generation": target["generation"],
        }})

    _fast_confirmation(monkeypatch, on_wait=replica_loads)
    promote = client.post(f"/api/v1/models/log-model/versions/{version}/promote", json={"alias": "champion"})
    assert promote.status_code == 200, promote.json()
    status = client.get("/api/v1/serving/log-model").json()["aliases"]["champion"]
    assert status["version"] == version and status["confirmed"] is True


def test_failed_replica_load_restores_serving_and_alias(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    v1 = _train(client)
    monkeypatch.setattr(config.settings, "serving_confirmation_required", False)
    assert client.post(f"/api/v1/models/log-model/versions/{v1}/promote", json={"alias": "champion"}).status_code == 200
    first = _desired(client)["champion"]
    v2 = _train(client)
    _replica_reports({"champion": {
        "version": v1, "signature": first["signature"], "generation": first["generation"],
    }})
    def report_transition() -> None:
        target = _desired(client)["champion"]
        if target["version"] == v2:
            _replica_reports(
                {"champion": {
                    "version": v1, "signature": first["signature"],
                    "generation": target["generation"],
                }},
                {"champion": f"{v2}: Model package signature mismatch"},
            )
        else:
            _replica_reports({"champion": {
                "version": target["version"], "signature": target["signature"],
                "generation": target["generation"],
            }})

    _fast_confirmation(monkeypatch, on_wait=report_transition)
    promote = client.post(f"/api/v1/models/log-model/versions/{v2}/promote", json={"alias": "champion"})
    assert promote.status_code == 502
    assert "replica rollback confirmed" in promote.json()["detail"]
    assert _desired(client)["champion"]["version"] == v1
    versions = client.get("/api/v1/models/log-model/versions").json()["items"]
    assert {row["version"]: row["aliases"] for row in versions}[v1] == ["champion"]


def test_stale_replica_generation_cannot_replace_fresh_confirmation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    v1 = _train(client)
    monkeypatch.setattr(config.settings, "serving_confirmation_required", False)
    assert client.post(f"/api/v1/models/log-model/versions/{v1}/promote", json={"alias": "champion"}).status_code == 200
    first = _desired(client)["champion"]
    v2 = _train(client)
    assert client.post(f"/api/v1/models/log-model/versions/{v2}/promote", json={"alias": "champion"}).status_code == 200
    current = _desired(client)["champion"]
    _replica_reports({"champion": {
        "version": v2, "signature": current["signature"], "generation": current["generation"],
    }})
    _replica_reports({"champion": {
        "version": v1, "signature": first["signature"], "generation": current["generation"] - 1,
    }})
    status = client.get("/api/v1/serving/log-model").json()["aliases"]["champion"]
    assert status["confirmed"] is True
    assert status["version"] == v2


def test_promotion_times_out_without_live_replicas(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    version = _train(client)
    def report_unloaded_after_rollback() -> None:
        target = _desired(client).get("canary")
        if target and target.get("removed"):
            _replica_reports({"canary": {
                "version": None, "signature": None, "generation": target["generation"],
            }}, instance="replica-canary")

    _fast_confirmation(monkeypatch, on_wait=report_unloaded_after_rollback)
    promote = client.post(f"/api/v1/models/log-model/versions/{version}/promote", json={"alias": "canary"})
    assert promote.status_code == 502
    assert _desired(client)["canary"]["removed"] is True


def test_package_download_is_the_signed_package(client: TestClient, tmp_path: Path) -> None:
    from black_onyx_model_package.serving import unpack_package

    version = _train(client)
    response = client.get(f"/api/v1/models/log-model/versions/{version}/package")
    assert response.status_code == 200
    unpack_package(response.content, tmp_path / "pkg")
    assert verify_model_package(tmp_path / "pkg", "test-key", expected_model_name="log-model") == "model.onnx"
    assert client.get("/api/v1/models/log-model/versions/9.9.9/package").status_code == 404


def test_serving_report_rejects_unknown_aliases(client: TestClient) -> None:
    bad = client.post("/api/v1/serving/log-model/report", json={"instance_id": "r1", "slots": {"candidate": {}}})
    assert bad.status_code == 422


def test_fenced_worker_does_not_burn_a_version(client: TestClient) -> None:
    db_iterator = app.dependency_overrides[get_db]()
    db = next(db_iterator)
    try:
        job = TrainingJob(
            id="job-fenced", tenant_id="tenant-acme", model_name="log-model", status="running",
            claimed_by="worker-new", attempt_count=2, request_json={},
        )
        db.add(job)
        db.commit()
        stale = training._reserve_version(
            db, "tenant-acme", "log-model", job_id="job-fenced", claim_owner="worker-old", claim_attempt=1,
        )
        assert stale is None
        assert db.query(ModelVersionHistory).count() == 0
        fresh = training._reserve_version(
            db, "tenant-acme", "log-model", job_id="job-fenced", claim_owner="worker-new", claim_attempt=2,
        )
        assert fresh == "1.0.0"
        db.refresh(job)
        assert job.version == "1.0.0"
    finally:
        db_iterator.close()
