"""Parity: expected detection Postgres databases exist in init SQL."""

from pathlib import Path

REQUIRED_DATABASES = {
    "incident_api",
    "asset_registry",
    "threat_intel",
    "integration_hub",
    "response_orchestrator",
    "notification_service",
    "training_orchestrator",
}

REQUIRED_TOPIC_FRAGMENTS = [
    "logs.raw",
    "findings.logs",
    "findings.embedding.dlq",
    "code.raw.dlq",
    "malware.submit",
    "malware.submit.dlq",
    "findings.correlation.dlq",
    "deployments.raw",
    "ingest.dlq",
]


def test_postgres_init_creates_required_databases():
    init = Path("deploy/detection/init/01-databases.sql")
    assert init.is_file(), "deploy/detection/init/01-databases.sql missing"
    text = init.read_text(encoding="utf-8")
    for name in REQUIRED_DATABASES:
        assert f"CREATE DATABASE {name}" in text, f"missing database {name}"


def test_platform_compose_bootstraps_kafka_topics():
    compose = Path("docker-compose.platform.yml")
    assert compose.is_file()
    text = compose.read_text(encoding="utf-8")
    for fragment in REQUIRED_TOPIC_FRAGMENTS:
        assert fragment in text, f"missing topic bootstrap for {fragment}"


def test_alembic_migrations_copied_per_service():
    root = Path("deploy/detection/migrations")
    assert root.is_dir()
    for name in (
        "incident-api",
        "asset-registry",
        "threat-intel-service",
        "integration-hub",
        "response-orchestrator",
        "notification-service",
        "training-orchestrator",
    ):
        d = root / name
        assert d.is_dir(), f"missing migrations for {name}"
        assert any(d.iterdir()), f"empty migrations for {name}"


def test_services_use_unique_package_names():
    services = Path("services")
    assert services.is_dir()
    for svc in services.iterdir():
        if not svc.is_dir():
            continue
        if svc.name.startswith("."):
            continue
        # Go gateway has no Python app package
        if svc.name == "ingestion-gateway":
            continue
        assert not (svc / "app").exists(), f"{svc.name} still has colliding package 'app'"
        pkg = svc.name.replace("-", "_")
        assert (svc / pkg).is_dir(), f"{svc.name} missing package dir {pkg}"


def test_compose_overrides_avoid_colliding_app_module():
    """Root detection apps include this file; uvicorn must use unique packages."""
    paths = [
        Path("deploy/detection/compose/docker-compose.apps.yml"),
        Path("detection/infrastructure/docker-compose/docker-compose.mtls.yml"),
        Path("docker-compose.detection-core.yml"),
        Path("docker-compose.detection-apps.yml"),
    ]
    for path in paths:
        assert path.is_file(), f"missing {path}"
        text = path.read_text(encoding="utf-8")
        assert "app.main:app" not in text, f"{path} still overrides with colliding app.main:app"


def test_detection_apps_use_blackonyx_container_names():
    apps = Path("deploy/detection/compose/docker-compose.apps.yml")
    text = apps.read_text(encoding="utf-8")
    assert "container_name: ap-" not in text
    assert "container_name: blackonyx-" in text


def test_model_dockerfiles_copy_from_detection_models():
    apps = Path("deploy/detection/compose/docker-compose.apps.yml").read_text(encoding="utf-8")
    assert "dockerfile: detection/models/log-model/Dockerfile" in apps
    assert "dockerfile: models/log-model/Dockerfile" not in apps
    for rel in (
        "detection/models/log-model/Dockerfile",
        "detection/models/network-model/Dockerfile",
        "detection/models/metrics-model/Dockerfile",
        "detection/models/code-model/Dockerfile",
    ):
        text = Path(rel).read_text(encoding="utf-8")
        assert "COPY detection/models/" in text
        assert "COPY models/" not in text


def test_legacy_infra_compose_is_absent():
    """Duplicate anomaly-platform entrypoints must not remain runnable or stubbed."""
    legacy = Path("detection/infrastructure/docker-compose/docker-compose.yml")
    assert not legacy.exists()
    assert not Path("detection/infrastructure/docker-compose/docker-compose.apps.yml").exists()


def test_active_compose_files_avoid_anomaly_platform_project_name():
    root = Path("detection/infrastructure/docker-compose")
    for path in root.glob("docker-compose*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "name: anomaly-platform" not in text, f"{path} still forces anomaly-platform project"
        assert "container_name: ap-" not in text, f"{path} still uses ap-* containers"


def test_k8s_namespaces_match_helm_values():
    ns = Path("detection/infrastructure/k8s/namespaces.yaml").read_text(encoding="utf-8")
    values = Path("deploy/detection/helm/black-onyx-detection/values.yaml").read_text(encoding="utf-8")
    for name in (
        "black-onyx-ingestion",
        "black-onyx-processing",
        "black-onyx-models",
        "black-onyx-application",
        "black-onyx-observability",
        "black-onyx-training",
    ):
        assert name in ns
        assert name in values
    assert "anomaly-ingestion" not in ns


def test_ci_runtime_smoke_proves_tenant_scoped_sor_round_trips():
    workflow = Path(".github/workflows/black-onyx-ci.yml").read_text(encoding="utf-8")
    smoke = Path("scripts/smoke_detection_infra.ps1").read_text(encoding="utf-8")

    assert "detection-runtime-smoke:" in workflow
    assert "INCIDENT_API_SERVICE_KEY: ci-runtime-incident-key" in workflow
    assert "ASSET_REGISTRY_SERVICE_KEY: ci-runtime-asset-key" in workflow
    assert "smoke_detection_infra.ps1 -RequireStack" in workflow
    assert "if: always()" in workflow
    assert "down -v --remove-orphans" in workflow

    for credential in ("API_KEYS", "INCIDENT_API_SERVICE_KEY", "ASSET_REGISTRY_SERVICE_KEY"):
        assert f'$env:{credential}' in smoke
    assert "API_KEYS (non-demo)" in smoke
    assert "Incident API write/read persistence: verified" in smoke
    assert "Asset registry write/read persistence: verified" in smoke
    assert "Kafka/Postgres event persistence: verified" in smoke
    assert "X-Tenant-Id':'default'" in smoke


def test_flow_processor_port_contract_is_consistent() -> None:
    service_guide = Path("services/AGENTS.md").read_text(encoding="utf-8")
    dockerfile = Path("services/flow-processor/Dockerfile").read_text(encoding="utf-8")
    config = Path("services/flow-processor/flow_processor/config.py").read_text(encoding="utf-8")

    assert "flow-processor` uses **8094**" in service_guide
    assert "config **8091**" not in service_guide
    assert "port: int = 8094" in config
    assert "EXPOSE 8094" in dockerfile
    assert '"--port", "8094"' in dockerfile
