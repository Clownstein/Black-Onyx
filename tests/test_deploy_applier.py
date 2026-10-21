"""Security regressions for signed deployment handoff execution."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import deploy_applier


def _signed_bundle(tmp_path: Path, key: str, **manifest_fields) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    bundle = tmp_path / "rev-test"
    bundle.mkdir()
    content = "revision data"
    (bundle / "managed.env").write_text(content, encoding="utf-8")
    manifest = {
        "manifest_version": deploy_applier.MANIFEST_VERSION,
        "policy_version": deploy_applier.POLICY_VERSION,
        "revision_id": bundle.name,
        "target": "compose",
        "files": {"managed.env": hashlib.sha256(content.encode()).hexdigest()},
        **manifest_fields,
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(key.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps({"manifest": manifest, "signature": signature}), encoding="utf-8",
    )
    return bundle


def test_signed_bundle_requires_current_policy_and_unexpired_exception(tmp_path: Path) -> None:
    key = "k" * 32
    bundle = _signed_bundle(tmp_path, key, policy_version=deploy_applier.POLICY_VERSION + 1)
    with pytest.raises(deploy_applier.ApplyError, match="policy version changed"):
        deploy_applier.verify_bundle(bundle, key)

    bundle = _signed_bundle(
        tmp_path / "next", key, exception_expires_at="2000-01-01T00:00:00+00:00",
    )
    manifest = deploy_applier.verify_bundle(bundle, key)
    with pytest.raises(deploy_applier.ApplyError, match="expired"):
        deploy_applier._assert_manifest_live(manifest)


def test_revision_ledger_survives_status_file_deletion(tmp_path: Path, monkeypatch) -> None:
    manifest = {"revision_id": "rev-once", "target": "compose"}
    monkeypatch.setattr(deploy_applier, "STATE_DIR", tmp_path)
    assert deploy_applier._claim_revision(manifest) is True
    (tmp_path / "rev-once-status.json").unlink(missing_ok=True)
    assert deploy_applier._claim_revision(manifest) is False
    assert (tmp_path / "consumed-revisions.json").is_file()


def test_compose_health_accepts_successful_one_shot_and_requires_expected_service(monkeypatch) -> None:
    output = "\n".join([
        json.dumps({"Service": "migration", "State": "exited", "Health": "", "ExitCode": 0}),
        json.dumps({"Service": "api", "State": "running", "Health": "healthy", "ExitCode": 0}),
    ])
    monkeypatch.setattr(deploy_applier, "_run", lambda *_args, **_kwargs: output)
    args = SimpleNamespace(health_timeout=1)
    result = deploy_applier.compose_health(
        args, Path("managed.env"), {
            "migration": {"labels": {"com.blackonyx.one-shot": "true"}},
            "api": {"healthcheck": {"test": ["CMD", "true"]}},
        },
    )
    assert result["ok"] is True

    monkeypatch.setattr(deploy_applier, "_run", lambda *_args, **_kwargs: "")
    result = deploy_applier.compose_health(args, Path("managed.env"), {"api": {}})
    assert result["ok"] is False


def test_subprocess_timeout_enters_standard_apply_error(monkeypatch) -> None:
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("docker", 1)

    monkeypatch.setattr(deploy_applier.subprocess, "run", timeout)
    with pytest.raises(deploy_applier.ApplyError, match="TimeoutExpired"):
        deploy_applier._run(["docker", "compose", "up"], timeout=1)


def test_signed_namespace_secret_operations_are_validated(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "secret-operations.json").write_text(json.dumps({
        "namespaces": {
            "app-ns": {
                "keys": {"serviceKey": {"op": "set", "value": "value"}},
                "deployments": ["incident-api"],
            },
        },
    }), encoding="utf-8")
    parsed = deploy_applier._read_secret_operations(bundle)
    assert parsed["app-ns"]["keys"]["serviceKey"]["value"] == "value"
    assert parsed["app-ns"]["deployments"] == ["incident-api"]

    (bundle / "secret-operations.json").write_text(json.dumps({
        "namespaces": {
            "../app-ns": {
                "keys": {"serviceKey": {"op": "delete"}},
                "deployments": ["incident-api"],
            },
        },
    }), encoding="utf-8")
    with pytest.raises(deploy_applier.ApplyError, match="namespace is invalid"):
        deploy_applier._read_secret_operations(bundle)


def test_rendered_secret_consumers_must_match_signed_namespace_map() -> None:
    operations = {
        "app-ns": {
            "keys": {"incidentApiServiceKey": {"op": "set", "value": "x"}},
            "deployments": ["incident-api"],
        },
    }
    rendered = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: incident-api
  namespace: app-ns
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: SERVICE_KEY
              valueFrom:
                secretKeyRef:
                  name: detection-secrets
                  key: incidentApiServiceKey
"""
    deploy_applier._validate_rendered_secret_targets(rendered, operations, "detection-secrets")

    with pytest.raises(deploy_applier.ApplyError, match="outside the signed consumer map"):
        deploy_applier._validate_rendered_secret_targets(
            rendered.replace("namespace: app-ns", "namespace: wrong-ns"),
            operations,
            "detection-secrets",
        )


@pytest.mark.parametrize("fail_upgrade", [False, True])
def test_helm_secret_rotation_preserves_unmanaged_keys_and_restores_all_namespaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_upgrade: bool,
) -> None:
    bundle = _signed_bundle(tmp_path, "k" * 32, target="helm")
    operations = {
        "namespaces": {
            "app-ns": {
                "keys": {"serviceKey": {"op": "set", "value": "new-app"}},
                "deployments": ["incident-api"],
            },
            "processing-ns": {
                "keys": {"oldKey": {"op": "delete"}},
                "deployments": ["correlation-engine"],
            },
        },
    }
    (bundle / "secret-operations.json").write_text(json.dumps(operations), encoding="utf-8")
    monkeypatch.setenv("BLACK_ONYX_DEPLOY_SIGNING_KEY", "k" * 32)
    monkeypatch.setattr(deploy_applier, "verify_bundle", lambda *_args: {})
    state = {
        "app-ns": {
            "serviceKey": base64.b64encode(b"old-app").decode(),
            "unmanaged": base64.b64encode(b"keep-app").decode(),
        },
        "processing-ns": {
            "oldKey": base64.b64encode(b"remove-me").decode(),
            "unmanaged": base64.b64encode(b"keep-processing").decode(),
        },
    }
    applied: list[dict] = []

    def fake_run(argv, *, input_text=None, timeout=900):
        if argv[:2] == ["helm", "template"]:
            return "---\n"
        if argv[:3] == ["kubectl", "-n", argv[2]] and "get" in argv:
            namespace = argv[2]
            if "secret" in argv:
                return json.dumps({"data": state[namespace]})
            if "deployments" in argv:
                return json.dumps({"items": [{"metadata": {"name": name}}
                                             for name in operations["namespaces"][namespace]["deployments"]]})
        if argv[:2] == ["kubectl", "apply"]:
            secret = json.loads(input_text)
            applied.append(secret)
            namespace = secret["metadata"]["namespace"]
            state[namespace] = {
                key: base64.b64encode(value.encode()).decode()
                for key, value in secret["stringData"].items()
            }
            return "secret updated"
        if argv[:2] == ["kubectl", "-n"] and "rollout" in argv:
            return "rollout ok"
        if argv[:2] == ["helm", "upgrade"]:
            if fail_upgrade:
                raise deploy_applier.ApplyError("upgrade failed")
            return "upgrade ok"
        if argv[:2] == ["helm", "status"]:
            return json.dumps({"info": {"status": "deployed"}, "version": 2})
        raise AssertionError(argv)

    monkeypatch.setattr(deploy_applier, "_run", fake_run)
    args = SimpleNamespace(
        file=[], release="black-onyx", namespace="release-ns", secret="detection-secrets",
        health_timeout=10,
    )
    if fail_upgrade:
        with pytest.raises(deploy_applier.ApplyError, match="upgrade failed"):
            deploy_applier.apply_helm(bundle, args)
        assert base64.b64decode(state["app-ns"]["serviceKey"]) == b"old-app"
        assert base64.b64decode(state["processing-ns"]["oldKey"]) == b"remove-me"
        assert base64.b64decode(state["app-ns"]["unmanaged"]) == b"keep-app"
        assert base64.b64decode(state["processing-ns"]["unmanaged"]) == b"keep-processing"
        assert len(applied) == 4
    else:
        result = deploy_applier.apply_helm(bundle, args)
        assert result["ok"] is True
        assert base64.b64decode(state["app-ns"]["serviceKey"]) == b"new-app"
        assert "oldKey" not in state["processing-ns"]
        assert base64.b64decode(state["app-ns"]["unmanaged"]) == b"keep-app"
        assert base64.b64decode(state["processing-ns"]["unmanaged"]) == b"keep-processing"
