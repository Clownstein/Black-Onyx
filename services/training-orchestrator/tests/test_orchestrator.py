import json
from pathlib import Path

import pytest
from training_orchestrator import config
from training_orchestrator.dataset_manifest import build_dataset_manifest
from training_orchestrator.db import Base, get_db
from training_orchestrator.main import app
from training_orchestrator.package_builder import PACKAGE_FILES, build_model_package
from training_orchestrator import training
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(config.settings, "package_output_dir", str(tmp_path / "packages"))
    monkeypatch.setattr(config.settings, "repo_root", str(tmp_path))
    monkeypatch.setattr(config.settings, "artifact_signing_key", "test-key")

    def fake_trainer(model_name: str, _job_id: str, _hyperparameters: dict, artifacts_dir: Path):
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        (artifacts_dir / "model.onnx").write_bytes(b"test-only-onnx")
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
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_training_job_promote_rollback_and_drift(client: TestClient) -> None:
    create = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
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
    promote = client.post(
        f"/api/v1/models/log-model/versions/{version}/promote",
        json={"alias": "champion"},
    )
    assert promote.status_code == 200
    assert promote.json()["alias"] == "champion"
    assert promote.json()["version"] == version

    create2 = client.post(
        "/api/v1/models/log-model/training-jobs",
        json={
            "tenant_id": "tenant-acme",
            "created_by": "analyst@example.test",
            "run_async": False,
        },
    )
    v2 = create2.json()["version"]
    client.post(f"/api/v1/models/log-model/versions/{v2}/promote", json={"alias": "champion"})

    stale = client.post(f"/api/v1/models/log-model/versions/not-current/rollback")
    assert stale.status_code == 409

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
    )
    for name in PACKAGE_FILES:
        assert (package / name).exists()
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
