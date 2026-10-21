"""Settings inventory and deployment-controller lifecycle."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from black_onyx.auth.database import StateDatabase
from black_onyx.config import Settings
from black_onyx.ops.deploy_controller import DeploymentController, DeploymentError
from black_onyx.settings_registry import (
    DEPLOYMENT_SETTINGS,
    HELM_SECRET_CONSUMERS,
    HELM_SECRET_KEYS,
    application_entries,
    deployment_entries,
    validate_deployment_value,
)

SIGNING_KEY = "k" * 40


@pytest.fixture
def controller(tmp_path, monkeypatch) -> DeploymentController:
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "a" * 48)
    monkeypatch.setenv("BLACK_ONYX_DEPLOY_SIGNING_KEY", SIGNING_KEY)
    return DeploymentController(StateDatabase(str(tmp_path / "state")), handoff_dir=tmp_path / "handoff")


# ── inventory ────────────────────────────────────────────────────────────


def test_application_sources_follow_precedence():
    settings = Settings(**{"chunking": {"chunk_size": 900}, "ingestion": {"batch_size": 7}})
    entries = {
        e.key: e for e in application_entries(
            settings,
            runtime_config={"chunking": {"chunk_size": 900}},
            yaml_config={"ingestion": {"batch_size": 7}},
            environ={"QDRANT_FEEDS__ENABLED": "true"},
        )
    }
    assert entries["chunking.chunk_size"].source == "runtime"
    assert entries["chunking.chunk_size"].desired == 900
    assert entries["ingestion.batch_size"].source == "config_file"
    assert entries["feeds.enabled"].source == "environment"
    assert entries["logging.level"].source == "default"
    assert entries["chunking.chunk_size"].restart_required is False
    assert entries["security.production"].restart_required is True
    assert entries["security.production"].editable is False


def test_secrets_are_never_returned():
    settings = Settings(**{"qdrant": {"api_key": "super-secret"}})
    entry = next(e for e in application_entries(settings, {}, {}, environ={}) if e.key == "qdrant.api_key")
    assert entry.secret is True
    assert entry.effective == {"configured": True}
    assert "super-secret" not in json.dumps(entry.as_dict())
    deployment = {e.key: e for e in deployment_entries({}, environ={"SECURITY_GATEWAY_KEY": "x" * 40})}
    assert deployment["SECURITY_GATEWAY_KEY"].effective == {"configured": True}


def test_deployment_secret_defaults_are_masked():
    entries = {e.key: e for e in deployment_entries({}, environ={})}
    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "SEARXNG_SECRET"):
        entry = entries[key]
        assert entry.secret is True
        assert entry.default is None
        assert entry.effective == {"configured": True}


def test_every_deployment_setting_names_a_consumer():
    for item in DEPLOYMENT_SETTINGS:
        assert item.consumers and item.category and item.description
    exposed = {entry.key for entry in deployment_entries({}, environ={})}
    assert {
        "SECURITY_RUNNER_MAX_JOBS_PER_SESSION",
        "SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES",
        "CODE_PROCESSOR_CODEQL_ENABLED",
        "CODE_PROCESSOR_CODEQL_RAM_MB",
        "CODE_PROCESSOR_MEMORY_LIMIT",
        "SECURITY_APPROVAL_DB",
        "SECURITY_AGENT_TOOL_HTTP_TIMEOUT",
        "SECURITY_DOCKER_SOCKET_GID",
        "OIDC_DISABLED",
        "ALLOW_DEMO_KEYS",
        "POSTGRES_PASSWORD",
        "PROCESSOR_API_KEY",
    } <= exposed


def test_helm_secret_consumers_cover_every_managed_key():
    assert set(HELM_SECRET_CONSUMERS) == set(HELM_SECRET_KEYS)
    assert all(namespaces and all(deployments for deployments in namespaces.values())
               for namespaces in HELM_SECRET_CONSUMERS.values())


def test_helm_handoff_scopes_secret_operations_to_signed_namespaces(controller):
    revision = SimpleNamespace(
        revision_id="rev-helm-secret-scope",
        target="helm",
        exception_expires_at=None,
    )
    bundle = controller._write_bundle(
        revision,
        {
            "env": {"TRAINING_API_KEY": "training-secret"},
            "values": {
                "namespaces.application": "ops-application",
                "namespaces.models": "ops-models",
                "namespaces.training": "ops-training",
            },
        },
        None,
        SIGNING_KEY,
    )
    operations = json.loads((bundle / "secret-operations.json").read_text(encoding="utf-8"))
    by_namespace = operations["namespaces"]
    assert by_namespace["ops-models"]["keys"]["trainingApiKey"] == {
        "op": "set", "value": "training-secret",
    }
    assert by_namespace["ops-training"]["keys"]["trainingApiKey"] == {
        "op": "set", "value": "training-secret",
    }
    assert "trainingApiKey" not in by_namespace["ops-application"]["keys"]
    assert "model-gateway" in by_namespace["ops-models"]["deployments"]
    assert "training-orchestrator" in by_namespace["ops-training"]["deployments"]


def test_compose_variables_are_present_in_admin_inventory():
    root = Path(__file__).resolve().parents[1]
    manifests = list(root.glob("docker-compose*.yml")) + list(
        (root / "deploy" / "detection" / "compose").glob("docker-compose*.yml")
    )
    referenced = {
        name
        for manifest in manifests
        for name in re.findall(r"\$\{([A-Z][A-Z0-9_]*)", manifest.read_text(encoding="utf-8"))
        if not name.startswith("QDRANT_")
    }
    assert referenced <= {item.name for item in DEPLOYMENT_SETTINGS}
    import runpy

    generator = runpy.run_path(str(root / "scripts" / "generate_compose_setting_inventory.py"))
    generated = root / "src" / "black_onyx" / "compose_setting_inventory.py"
    assert generated.read_text(encoding="utf-8") == generator["render"]()


def test_deployment_validation_rules():
    assert validate_deployment_value("ENABLE_BASH_TOOL", "maybe", production=False)
    assert validate_deployment_value("ENABLE_BASH_TOOL", "true", production=True)
    assert validate_deployment_value("ENABLE_BASH_TOOL", "true", production=False) is None
    assert validate_deployment_value("SECURITY_GATEWAY_KEY", "short", production=False)
    assert validate_deployment_value("SECURITY_SANDBOX_IMAGE", "ubuntu:latest", production=False)
    assert validate_deployment_value("SECURITY_RUNNER_MAX_JOBS_PER_SESSION", "0", production=False)
    assert validate_deployment_value("SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES", "many", production=False)
    assert validate_deployment_value("SECURITY_RUNNER_MAX_JOBS_PER_SESSION", "3", production=False) is None
    assert validate_deployment_value("CODE_PROCESSOR_CODEQL_ENABLED", "sometimes", production=False)
    assert validate_deployment_value("CODE_PROCESSOR_CODEQL_RAM_MB", "0", production=False)
    assert validate_deployment_value("SECURITY_DOCKER_SOCKET_GID", "invalid", production=False)
    assert validate_deployment_value("OIDC_DISABLED", "true", production=True)
    assert validate_deployment_value("ALLOW_DEMO_KEYS", "true", production=True)
    assert validate_deployment_value("NOT_MANAGED", "x", production=False)


# ── controller lifecycle ─────────────────────────────────────────────────


def _complete(controller: DeploymentController, revision_id: str, state: str = "applied") -> None:
    status = {"state": state, "health": {"ok": state == "applied"}}
    (controller.handoff_dir / revision_id / "status.json").write_text(json.dumps(status))
    controller.refresh(revision_id)


def _apply(controller, **kwargs):
    rev = controller.create_revision("compose", actor="admin-1", **kwargs)
    controller.approve(rev.revision_id, approver="admin-1", preview_digest=rev.preview_digest)
    controller.apply(rev.revision_id, actor="admin-1")
    return rev


def test_preview_masks_secrets_and_approval_binds_digest(controller):
    rev = controller.create_revision(
        "compose", env_changes={"SECURITY_GATEWAY_KEY": "s" * 40, "BLACK_ONYX_DETECTION_TENANT": "t1"},
        actor="admin-1",
    )
    assert "s" * 40 not in rev.rendered_preview
    assert "SECURITY_GATEWAY_KEY=<set>" in rev.rendered_preview
    with pytest.raises(DeploymentError):
        controller.approve(rev.revision_id, approver="admin-1", preview_digest="0" * 64)
    with pytest.raises(DeploymentError):
        controller.apply(rev.revision_id, actor="admin-1")  # not approved yet


def test_signed_bundle_and_activation(controller):
    rev = _apply(controller, env_changes={"BLACK_ONYX_DETECTION_TENANT": "t1"})
    bundle = controller.handoff_dir / rev.revision_id
    envelope = json.loads((bundle / "manifest.json").read_text())
    encoded = json.dumps(envelope["manifest"], sort_keys=True, separators=(",", ":"))
    assert hmac.compare_digest(
        envelope["signature"], hmac.new(SIGNING_KEY.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    )
    assert (bundle / "managed.env").read_text() == "BLACK_ONYX_DETECTION_TENANT=t1\n"
    assert controller.get(rev.revision_id).status == "applying"
    _complete(controller, rev.revision_id)
    assert controller.active("compose").revision_id == rev.revision_id
    assert controller.desired_env() == {"BLACK_ONYX_DETECTION_TENANT": "t1"}


def test_only_one_apply_in_flight(controller):
    _apply(controller, env_changes={"BLACK_ONYX_DETECTION_TENANT": "t1"})
    second = controller.create_revision("compose", env_changes={"LLM_MODEL_NAME": "m"}, actor="admin-1")
    controller.approve(second.revision_id, approver="admin-1", preview_digest=second.preview_digest)
    with pytest.raises(DeploymentError):
        controller.apply(second.revision_id, actor="admin-1")


def test_failed_apply_keeps_previous_active_and_rollback_restores(controller):
    first = _apply(controller, env_changes={"BLACK_ONYX_DETECTION_TENANT": "t1"})
    _complete(controller, first.revision_id)
    second = _apply(controller, env_changes={"BLACK_ONYX_DETECTION_TENANT": "t2"})
    _complete(controller, second.revision_id, "failed")
    assert controller.get(second.revision_id).status == "failed"
    assert controller.active("compose").revision_id == first.revision_id

    third = _apply(controller, env_changes={"BLACK_ONYX_DETECTION_TENANT": "t3", "LLM_MODEL_NAME": "m"})
    _complete(controller, third.revision_id)
    rollback = controller.rollback("compose", actor="admin-1")
    assert set(rollback.changed_keys) == {"env.BLACK_ONYX_DETECTION_TENANT", "env.LLM_MODEL_NAME"}
    controller.approve(rollback.revision_id, approver="admin-1", preview_digest=rollback.preview_digest)
    controller.apply(rollback.revision_id, actor="admin-1")
    _complete(controller, rollback.revision_id)
    assert controller.desired_env() == {"BLACK_ONYX_DETECTION_TENANT": "t1"}


def test_production_invariants_are_mandatory(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "a" * 48)
    prod = DeploymentController(StateDatabase(str(tmp_path / "p")), production=True, handoff_dir=tmp_path / "h")
    with pytest.raises(DeploymentError):
        prod.create_revision("compose", env_changes={"ENABLE_BASH_TOOL": "true"}, actor="a",
                             lab_exception_hours=4)
    with pytest.raises(DeploymentError):
        prod.create_revision("helm", value_changes={"security.allowDemoKeys": True}, actor="a")


def test_lab_exceptions_expire(controller, monkeypatch):
    with pytest.raises(DeploymentError):
        controller.create_revision("compose", env_changes={"ENABLE_BASH_TOOL": "true"}, actor="a")
    rev = controller.create_revision("compose", env_changes={"ENABLE_BASH_TOOL": "true"}, actor="a",
                                     lab_exception_hours=2)
    assert rev.exception_expires_at and "LAB EXCEPTION" in rev.rendered_preview
    controller.approve(rev.revision_id, approver="a", preview_digest=rev.preview_digest)
    from black_onyx.ops import deploy_controller as module
    from datetime import datetime, timedelta, timezone

    future = datetime.now(timezone.utc) + timedelta(hours=3)
    monkeypatch.setattr(module, "_now", lambda: future)
    with pytest.raises(DeploymentError):
        controller.apply(rev.revision_id, actor="a")


def test_helm_targets_only_chart_values_and_secret_keys(controller):
    with pytest.raises(DeploymentError):
        controller.create_revision("helm", env_changes={"ENABLE_BASH_TOOL": "false"}, actor="a")
    with pytest.raises(DeploymentError):
        controller.create_revision("helm", value_changes={"responseOrchestrator.nope": 1}, actor="a")
    with pytest.raises(DeploymentError):
        controller.create_revision("helm", value_changes={"responseOrchestrator.replicaCount": "two"}, actor="a")
    rev = controller.create_revision(
        "helm", value_changes={"responseOrchestrator.replicaCount": 2},
        env_changes={"TRAINING_API_KEY": "t" * 32}, actor="a",
    )
    controller.approve(rev.revision_id, approver="a", preview_digest=rev.preview_digest)
    controller.apply(rev.revision_id, actor="a")
    bundle = controller.handoff_dir / rev.revision_id
    assert "replicaCount: 2" in (bundle / "managed-values.yaml").read_text()
    assert json.loads((bundle / "secret-data.json").read_text()) == {"trainingApiKey": "t" * 32}


def test_applier_rejects_tampered_bundle(controller, tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "deploy_applier", Path(__file__).resolve().parents[1] / "scripts" / "deploy_applier.py"
    )
    applier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(applier)
    rev = _apply(controller, env_changes={"BLACK_ONYX_DETECTION_TENANT": "t1"})
    bundle = controller.handoff_dir / rev.revision_id
    assert applier.verify_bundle(bundle, SIGNING_KEY)["revision_id"] == rev.revision_id
    (bundle / "managed.env").write_text("ENABLE_BASH_TOOL=true\n")
    with pytest.raises(applier.ApplyError):
        applier.verify_bundle(bundle, SIGNING_KEY)
    with pytest.raises(applier.ApplyError):
        applier.verify_bundle(bundle, "x" * 40)
