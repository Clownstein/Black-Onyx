#!/usr/bin/env python3
"""Host-side applier for Black Onyx deployment-controller revisions.

Runs outside the TIP container, on a host (or CI runner) that holds Docker
Compose or Helm/kubectl credentials. It only acts on bundles whose manifest
signature verifies with ``BLACK_ONYX_DEPLOY_SIGNING_KEY`` and whose files
match the signed hashes, then writes ``status.json`` for the controller.

Compose:
    python scripts/deploy_applier.py compose --handoff-dir /srv/black-onyx/handoff \
        --env-file .env -f docker-compose.yml -f docker-compose.platform.yml \
        -f docker-compose.production.yml

Helm:
    python scripts/deploy_applier.py helm --handoff-dir /srv/black-onyx/handoff \
        --release black-onyx-detection --namespace black-onyx-application \
        --secret black-onyx-detection-secrets \
        -f deploy/detection/helm/black-onyx-detection/values.yaml \
        -f deploy/detection/helm/black-onyx-detection/values-prod.yaml

Add ``--watch`` to poll the handoff directory continuously.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "detection" / "helm" / "black-onyx-detection"
STATE_DIR = ROOT / "deploy" / "runtime"
MANIFEST_VERSION = 3
POLICY_VERSION = 2


class ApplyError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def verify_bundle(bundle: Path, signing_key: str) -> dict:
    """Return the manifest if its signature and file hashes verify."""
    envelope = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest = envelope.get("manifest")
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(signing_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(envelope.get("signature", ""))):
        raise ApplyError("Bundle signature does not verify")
    if manifest.get("revision_id") != bundle.name:
        raise ApplyError("Bundle directory does not match its manifest")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise ApplyError("Unsupported deployment handoff version; create a fresh approved preview")
    if manifest.get("policy_version") != POLICY_VERSION:
        raise ApplyError("Deployment policy version changed; create a fresh approved preview")
    for name, digest in manifest.get("files", {}).items():
        if "/" in name or "\\" in name or name.startswith("."):
            raise ApplyError(f"Unsafe bundle file name {name!r}")
        actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        if not hmac.compare_digest(actual, digest):
            raise ApplyError(f"{name} does not match its signed hash")
    return manifest


def _assert_manifest_live(manifest: dict) -> None:
    expiry = manifest.get("exception_expires_at")
    if expiry:
        try:
            expires_at = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ApplyError("Signed lab exception expiry is invalid") from exc
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise ApplyError("Signed lab exception has expired")


def _run(argv: list[str], *, input_text: str | None = None, timeout: int = 900) -> str:
    try:
        completed = subprocess.run(
            argv, input=input_text, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ApplyError(f"{' '.join(argv[:3])} failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise ApplyError(f"{' '.join(argv[:3])} failed: {completed.stderr.strip()[-2000:]}")
    return completed.stdout


# ── Compose ─────────────────────────────────────────────────────────────


def _compose_base(args: argparse.Namespace, managed_env: Path) -> list[str]:
    argv = ["docker", "compose"]
    for env_file in getattr(args, "env_file", None) or []:
        argv += ["--env-file", env_file]
    argv += ["--env-file", str(managed_env)]
    for compose_file in getattr(args, "file", None) or []:
        argv += ["-f", compose_file]
    return argv


def _compose_services(args: argparse.Namespace, managed_env: Path) -> dict[str, dict]:
    config = json.loads(_run(_compose_base(args, managed_env) + ["config", "--format", "json"]))
    services = config.get("services")
    if not isinstance(services, dict) or not services:
        raise ApplyError("Resolved Compose configuration contains no services")
    return services


def compose_health(args: argparse.Namespace, managed_env: Path, expected: dict[str, dict]) -> dict:
    deadline = time.monotonic() + args.health_timeout
    last: dict = {}
    while time.monotonic() < deadline:
        output = _run(_compose_base(args, managed_env) + ["ps", "--all", "--format", "json"])
        rows = [json.loads(line) for line in output.splitlines() if line.strip().startswith("{")]
        if not rows and output.strip().startswith("["):
            rows = json.loads(output)
        services = {}
        for row in rows:
            name = row.get("Service")
            if not name:
                continue
            services[name] = {
                "state": row.get("State"), "health": row.get("Health") or "",
                "exit_code": row.get("ExitCode"),
            }
        last = services
        unhealthy: dict[str, dict] = {}
        for name, config in expected.items():
            state = services.get(name)
            if state is None:
                unhealthy[name] = {"state": "missing", "health": ""}
                continue
            labels = config.get("labels") or {}
            one_shot = isinstance(labels, dict) and str(labels.get("com.blackonyx.one-shot", "")).lower() == "true"
            if one_shot and state["state"] == "exited" and str(state["exit_code"]) == "0":
                continue
            has_healthcheck = bool(config.get("healthcheck"))
            healthy = state["state"] == "running" and (
                not has_healthcheck or state["health"] == "healthy"
            )
            if not healthy:
                unhealthy[name] = state
        starting = {
            name for name, state in unhealthy.items()
            if state["health"] == "starting" or state["state"] == "running"
        }
        if not unhealthy:
            return {"ok": True, "services": services}
        if set(unhealthy) != starting and any(
            s["state"] in ("exited", "dead") or s["state"] == "missing" for s in unhealthy.values()
        ):
            return {"ok": False, "services": services}
        time.sleep(5)
    return {"ok": False, "services": last, "timeout": True}


def apply_compose(bundle: Path, args: argparse.Namespace) -> dict:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    live = STATE_DIR / "managed.env"
    backup = STATE_DIR / "managed.env.previous"
    if live.exists():
        shutil.copy2(live, backup)
    staged = STATE_DIR / "managed.env.staged"
    shutil.copy2(bundle / "managed.env", staged)
    os.chmod(staged, 0o600)
    _run(_compose_base(args, staged) + ["config", "--quiet"])
    expected = _compose_services(args, staged)
    os.replace(staged, live)
    try:
        _run(_compose_base(args, live) + ["up", "-d", "--wait", "--wait-timeout", str(args.health_timeout)])
        health = compose_health(args, live, expected)
        if not health["ok"]:
            raise ApplyError("Services did not become healthy")
        return health
    except ApplyError:
        if backup.exists():
            os.replace(backup, live)
        else:
            live.unlink(missing_ok=True)
            live.touch(mode=0o600)
        _run(_compose_base(args, live) + ["up", "-d"])
        raise


# ── Helm ────────────────────────────────────────────────────────────────


def _secret_data(args: argparse.Namespace, namespace: str | None = None) -> dict[str, str]:
    target_namespace = namespace or args.namespace
    output = _run(["kubectl", "-n", target_namespace, "get", "secret", args.secret, "-o", "json"])
    data = json.loads(output).get("data") or {}
    try:
        return {key: base64.b64decode(value, validate=True).decode() for key, value in data.items()}
    except (ValueError, UnicodeDecodeError) as exc:
        raise ApplyError(f"Secret {args.secret} in namespace {target_namespace} is invalid") from exc


def _put_secret(
    args: argparse.Namespace, data: dict[str, str], namespace: str | None = None,
) -> None:
    target_namespace = namespace or args.namespace
    manifest = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": args.secret, "namespace": target_namespace},
        "type": "Opaque", "stringData": data,
    }
    _run(["kubectl", "apply", "-f", "-"], input_text=json.dumps(manifest))


def _read_secret_operations(bundle: Path) -> dict[str, dict]:
    try:
        payload = json.loads((bundle / "secret-operations.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApplyError("Signed namespace secret operations are unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {"namespaces"} or not isinstance(payload["namespaces"], dict):
        raise ApplyError("Signed namespace secret operations are invalid")
    namespaces = payload["namespaces"]
    if not namespaces:
        raise ApplyError("Signed namespace secret operations are empty")
    normalized: dict[str, dict] = {}
    for namespace, entry in namespaces.items():
        if not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace):
            raise ApplyError("Signed secret namespace is invalid")
        if not isinstance(entry, dict) or set(entry) != {"keys", "deployments"}:
            raise ApplyError(f"Signed secret operations for namespace {namespace} are invalid")
        keys, deployments = entry["keys"], entry["deployments"]
        if not isinstance(keys, dict) or not keys or not isinstance(deployments, list) or not deployments:
            raise ApplyError(f"Signed secret operations for namespace {namespace} are empty")
        if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", name) for name in deployments):
            raise ApplyError(f"Signed secret consumer list for namespace {namespace} is invalid")
        for key, operation in keys.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", key) or not isinstance(operation, dict):
                raise ApplyError(f"Signed secret operation for namespace {namespace} is invalid")
            if operation.get("op") == "delete" and set(operation) == {"op"}:
                continue
            if operation.get("op") == "set" and set(operation) == {"op", "value"} and isinstance(operation["value"], str):
                continue
            raise ApplyError(f"Signed secret operation for namespace {namespace} is invalid")
        normalized[namespace] = {"keys": keys, "deployments": sorted(set(deployments))}
    return normalized


def _restart_secret_consumers(
    args: argparse.Namespace, namespace: str, deployments: list[str],
) -> list[str]:
    output = _run(["kubectl", "-n", namespace, "get", "deployments", "-o", "json"])
    body = json.loads(output)
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        raise ApplyError(f"Kubernetes returned an invalid Deployment list for namespace {namespace}")
    available = {
        str(item.get("metadata", {}).get("name"))
        for item in items if isinstance(item, dict) and isinstance(item.get("metadata"), dict)
    }
    restarted: list[str] = []
    for name in deployments:
        if name not in available:
            continue
        _run(["kubectl", "-n", namespace, "rollout", "restart", f"deployment/{name}"])
        _run(
            ["kubectl", "-n", namespace, "rollout", "status", f"deployment/{name}",
             f"--timeout={args.health_timeout}s"],
            timeout=args.health_timeout + 30,
        )
        restarted.append(name)
    return restarted


def _validate_rendered_secret_targets(
    rendered: str, operations: dict[str, dict], secret_name: str,
) -> None:
    """Require every rendered managed Secret reference to have an approved target."""
    try:
        import yaml

        documents = yaml.safe_load_all(rendered)
        managed_keys = {key for entry in operations.values() for key in entry["keys"]}
        for document in documents:
            if not isinstance(document, dict) or document.get("kind") not in {
                "Deployment", "StatefulSet", "DaemonSet", "Job",
            }:
                continue
            metadata = document.get("metadata") or {}
            namespace = metadata.get("namespace")
            name = metadata.get("name")
            pod_spec = (((document.get("spec") or {}).get("template") or {}).get("spec") or {})
            containers = [
                *pod_spec.get("containers", []), *pod_spec.get("initContainers", []),
            ]
            for container in containers:
                for env in container.get("env", []):
                    secret_ref = (((env.get("valueFrom") or {}).get("secretKeyRef")) or {})
                    key = secret_ref.get("key")
                    if key not in managed_keys:
                        continue
                    if secret_ref.get("name") != secret_name:
                        raise ApplyError(
                            f"Rendered managed key {key} uses a Secret other than {secret_name}"
                        )
                    approved = operations.get(namespace)
                    if (
                        approved is None or key not in approved["keys"]
                        or name not in approved["deployments"]
                    ):
                        raise ApplyError(
                            f"Rendered Secret reference {namespace}/{name}:{key} is outside the signed consumer map"
                        )
    except ApplyError:
        raise
    except Exception as exc:
        raise ApplyError("Could not validate rendered Helm Secret consumers") from exc


def apply_helm(bundle: Path, args: argparse.Namespace) -> dict:
    values_args: list[str] = []
    for values_file in [*args.file, str(bundle / "managed-values.yaml")]:
        values_args += ["-f", values_file]
    # Render the full release before touching credentials in the cluster.
    operations = _read_secret_operations(bundle)
    rendered = _run(["helm", "template", args.release, str(CHART), "--namespace", args.namespace, *values_args])
    _validate_rendered_secret_targets(rendered, operations, args.secret)
    previous = {namespace: _secret_data(args, namespace) for namespace in operations}
    updated: dict[str, dict[str, str]] = {}
    changed_deployments: dict[str, list[str]] = {}
    for namespace, entry in operations.items():
        data = dict(previous[namespace])
        changed_keys: set[str] = set()
        for key, operation in entry["keys"].items():
            if operation["op"] == "delete":
                if key in data:
                    data.pop(key)
                    changed_keys.add(key)
            elif data.get(key) != operation["value"]:
                data[key] = operation["value"]
                changed_keys.add(key)
        updated[namespace] = data
        if changed_keys:
            changed_deployments[namespace] = entry["deployments"]
    mutated: list[str] = []
    try:
        # Recheck the signed exception immediately before the first mutation.
        _assert_manifest_live(verify_bundle(bundle, os.environ["BLACK_ONYX_DEPLOY_SIGNING_KEY"]))
        for namespace in operations:
            if updated[namespace] == previous[namespace]:
                continue
            mutated.append(namespace)
            _put_secret(args, updated[namespace], namespace)
        for namespace, consumers in changed_deployments.items():
            _restart_secret_consumers(args, namespace, consumers)
        # --atomic restores the previous release if pods do not become ready.
        _run(["helm", "upgrade", "--install", args.release, str(CHART), "--namespace", args.namespace,
              "--atomic", "--wait", "--timeout", f"{args.health_timeout}s", *values_args],
             timeout=args.health_timeout + 120)
    except Exception as apply_error:
        rollback_errors: list[str] = []
        for namespace in reversed(mutated):
            try:
                _put_secret(args, previous[namespace], namespace)
            except Exception as rollback_error:
                rollback_errors.append(f"{namespace}: Secret restore failed ({rollback_error})")
        for namespace, consumers in changed_deployments.items():
            if namespace not in mutated:
                continue
            try:
                _restart_secret_consumers(args, namespace, consumers)
            except Exception as rollback_error:
                rollback_errors.append(f"{namespace}: consumer restart failed ({rollback_error})")
        if rollback_errors:
            raise ApplyError(
                f"Helm apply failed ({apply_error}); rollback incomplete: {'; '.join(rollback_errors)}"
            ) from apply_error
        if isinstance(apply_error, ApplyError):
            raise
        raise ApplyError(f"Helm apply failed: {type(apply_error).__name__}") from apply_error
    status = json.loads(_run(["helm", "status", args.release, "--namespace", args.namespace, "-o", "json"]))
    return {"ok": True, "release": status.get("info", {}).get("status"), "version": status.get("version")}


# ── Driver ──────────────────────────────────────────────────────────────


def process(bundle: Path, args: argparse.Namespace, signing_key: str) -> None:
    status_path = bundle / "status.json"
    if status_path.exists() or not (bundle / "manifest.json").exists():
        return
    try:
        manifest = verify_bundle(bundle, signing_key)
        _assert_manifest_live(manifest)
        if manifest.get("target") != args.target:
            return
        if not _claim_revision(manifest):
            raise ApplyError("This signed revision was already consumed; create a fresh approved preview")
        health = apply_compose(bundle, args) if args.target == "compose" else apply_helm(bundle, args)
        status = {"state": "applied", "health": health, "finished_at": _now()}
    except (ApplyError, OSError, ValueError) as exc:
        status = {"state": "failed", "error": str(exc), "finished_at": _now()}
    status_path.write_text(json.dumps(status, indent=2), encoding="utf-8")
    print(f"{bundle.name}: {status['state']}", file=sys.stderr)


def _claim_revision(manifest: dict) -> bool:
    """Durably consume a signed revision independently of its status file."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock = STATE_DIR / ".consumed-revisions.lock"
    ledger = STATE_DIR / "consumed-revisions.json"
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise ApplyError("Another deployment applier is updating the revision ledger") from exc
        try:
            consumed = json.loads(ledger.read_text(encoding="utf-8")) if ledger.exists() else {}
        except (OSError, json.JSONDecodeError) as exc:
            raise ApplyError("Consumed revision ledger is unreadable; refusing deployment") from exc
        if not isinstance(consumed, dict):
            raise ApplyError("Consumed revision ledger is invalid; refusing deployment")
        revision_id = str(manifest["revision_id"])
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if revision_id in consumed:
            return False
        consumed[revision_id] = digest
        temp = ledger.with_suffix(".json.tmp")
        temp.write_text(json.dumps(consumed, sort_keys=True), encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, ledger)
        return True
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", choices=("compose", "helm"))
    parser.add_argument("--handoff-dir", required=True)
    parser.add_argument("-f", "--file", action="append", default=[], help="Compose file or Helm values file")
    parser.add_argument("--env-file", action="append", help="Base Compose env file(s)")
    parser.add_argument("--release", default="black-onyx-detection")
    parser.add_argument("--namespace", default="black-onyx-application")
    parser.add_argument("--secret", default="black-onyx-detection-secrets")
    parser.add_argument("--health-timeout", type=int, default=300)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args(argv)
    signing_key = os.environ.get("BLACK_ONYX_DEPLOY_SIGNING_KEY", "")
    if len(signing_key) < 32:
        print("BLACK_ONYX_DEPLOY_SIGNING_KEY must be at least 32 characters", file=sys.stderr)
        return 2
    if args.target == "compose" and not args.file:
        parser.error("compose requires at least one -f compose file")
    handoff = Path(args.handoff_dir)
    while True:
        for bundle in sorted(p for p in handoff.iterdir() if p.is_dir()):
            process(bundle, args, signing_key)
        if not args.watch:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
