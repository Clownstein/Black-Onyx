"""Restricted deployment controller for Compose and Helm settings.

The TIP process never holds Docker or Kubernetes credentials. It manages
immutable *revisions* of the deployment settings it owns and hands approved
revisions to a host-side applier (``scripts/deploy_applier.py``) through a
signed bundle in ``BLACK_ONYX_DEPLOY_HANDOFF_DIR``:

    draft ──approve──▶ approved ──apply──▶ applying ──applier──▶ active | failed
                                                     (previous active → superseded)

* Every revision stores the full desired state (encrypted at rest) plus the
  keys it changed relative to its parent.
* Previews mask secrets; approval must quote the preview digest, so what an
  administrator saw is exactly what is applied.
* Production invariants (auth on, isolation on) are enforced on every
  revision. Non-production lab exceptions must carry an expiry and are
  refused at apply time once expired.
* Rollback creates a new draft from the last superseded revision; it goes
  through the same approval and health-checked apply path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from black_onyx.auth.database import StateDatabase
from black_onyx.crypto import derive_fernet, resolve_auth_secret
from black_onyx.settings_registry import (
    DEPLOYMENT_SETTINGS_BY_NAME,
    HELM_PRODUCTION_INVARIANTS,
    HELM_SECRET_CONSUMERS,
    HELM_SECRET_KEYS,
    validate_deployment_value,
)

Target = Literal["compose", "helm"]
MAX_EXCEPTION_HOURS = 72
DEPLOYMENT_MANIFEST_VERSION = 3
DEPLOYMENT_POLICY_VERSION = 2
ROOT = Path(__file__).resolve().parents[3]
HELM_CHART_VALUES = ROOT / "deploy" / "detection" / "helm" / "black-onyx-detection" / "values.yaml"


class DeploymentError(ValueError):
    """A revision is invalid or not in the right state for the operation."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            flat.update(_flatten(value, f"{path}."))
        else:
            flat[path] = value
    return flat


def _unflatten(flat: dict[str, Any]) -> dict[str, Any]:
    tree: dict[str, Any] = {}
    for path, value in sorted(flat.items()):
        node = tree
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return tree


def _merge_values(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_values(merged[key], value)
        else:
            merged[key] = value
    return merged


def chart_value_types() -> dict[str, type]:
    """Leaf value paths and their types from the chart's base values.yaml."""
    import yaml

    try:
        base = yaml.safe_load(HELM_CHART_VALUES.read_text(encoding="utf-8")) or {}
    except OSError:
        return {}
    return {path: type(value) for path, value in _flatten(base).items()}


@dataclass
class Revision:
    revision_id: str
    target: str
    parent_revision_id: str | None
    status: str
    changed_keys: list[str]
    rendered_preview: str
    preview_digest: str
    exception_expires_at: str | None
    created_by: str
    approved_by: str | None
    applied_at: str | None
    health: dict[str, Any] | None
    error: str | None
    created_at: str
    updated_at: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class DeploymentController:
    def __init__(
        self,
        database: StateDatabase,
        *,
        auth_secret_env: str = "BLACK_ONYX_AUTH_SECRET",
        production: bool = False,
        handoff_dir: str | Path | None = None,
    ) -> None:
        self.database = database
        self.production = production
        self._fernet = derive_fernet(resolve_auth_secret(auth_secret_env), "deployment-revisions")
        configured = handoff_dir or os.environ.get("BLACK_ONYX_DEPLOY_HANDOFF_DIR", "")
        self.handoff_dir = Path(configured) if configured else None

    # ── persistence ────────────────────────────────────────────────────

    def _row(self, revision_id: str) -> Any:
        row = self.database._conn.execute(
            "SELECT * FROM deployment_revisions WHERE revision_id=?", (revision_id,)
        ).fetchone()
        if row is None:
            raise DeploymentError("Unknown deployment revision")
        return row

    @staticmethod
    def _revision(row: Any) -> Revision:
        return Revision(
            revision_id=row["revision_id"], target=row["target"],
            parent_revision_id=row["parent_revision_id"], status=row["status"],
            changed_keys=json.loads(row["changed_keys"]),
            rendered_preview=row["rendered_preview"] or "",
            preview_digest=row["preview_digest"] or "",
            exception_expires_at=row["exception_expires_at"],
            created_by=row["created_by"], approved_by=row["approved_by"],
            applied_at=row["applied_at"],
            health=json.loads(row["health"]) if row["health"] else None,
            error=row["error"], created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def _values(self, row: Any) -> dict[str, Any]:
        return json.loads(self._fernet.decrypt(row["values_encrypted"].encode()).decode())

    def _set_status(self, revision_id: str, status: str, **fields: Any) -> None:
        assignments = ["status=?", "updated_at=?"]
        params: list[Any] = [status, _now().isoformat()]
        for column, value in fields.items():
            assignments.append(f"{column}=?")
            params.append(json.dumps(value) if column == "health" and value is not None else value)
        params.append(revision_id)
        with self.database.transaction() as db:
            db.execute(
                f"UPDATE deployment_revisions SET {', '.join(assignments)} WHERE revision_id=?",
                params,
            )

    def get(self, revision_id: str) -> Revision:
        return self._revision(self._row(revision_id))

    def list(self, target: str | None = None, limit: int = 50) -> list[Revision]:
        query = "SELECT * FROM deployment_revisions"
        params: list[Any] = []
        if target:
            query += " WHERE target=?"
            params.append(target)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 200)))
        return [self._revision(row) for row in self.database._conn.execute(query, params)]

    def active(self, target: str) -> Revision | None:
        row = self.database._conn.execute(
            "SELECT * FROM deployment_revisions WHERE target=? AND status='active' "
            "ORDER BY applied_at DESC LIMIT 1",
            (target,),
        ).fetchone()
        return self._revision(row) if row else None

    def desired_env(self, target: str = "compose") -> dict[str, str]:
        """Non-secret env values of the active revision (for the settings API)."""
        current = self.active(target)
        if current is None:
            return {}
        env = self._values(self._row(current.revision_id)).get("env", {})
        # Secret values never leave the controller; report only that one is set.
        return {
            name: (("<set>" if value else "") if DEPLOYMENT_SETTINGS_BY_NAME[name].secret else value)
            for name, value in env.items()
            if name in DEPLOYMENT_SETTINGS_BY_NAME
        }

    # ── validation and preview ─────────────────────────────────────────

    def _validate(self, target: str, values: dict[str, Any], exception: bool) -> list[str]:
        """Return invariant violations that a lab exception may cover; raise on hard errors."""
        waivable: list[str] = []
        for name, value in values.get("env", {}).items():
            if target == "helm" and name not in HELM_SECRET_KEYS:
                raise DeploymentError(f"{name} is not consumed by the detection Helm chart")
            error = validate_deployment_value(name, str(value), production=False)
            if error:
                raise DeploymentError(error)
            if validate_deployment_value(name, str(value), production=True):
                waivable.append(name)
        chart_types = chart_value_types() if target == "helm" else {}
        for path, value in values.get("values", {}).items():
            if target != "helm":
                raise DeploymentError("Chart values apply only to the helm target")
            expected = chart_types.get(path)
            if expected is None:
                raise DeploymentError(f"{path} is not a value of the detection chart")
            if expected is not type(None) and not isinstance(value, expected):
                if not (expected is float and isinstance(value, int)):
                    raise DeploymentError(f"{path} must be {expected.__name__}")
            if path in HELM_PRODUCTION_INVARIANTS and value != HELM_PRODUCTION_INVARIANTS[path]:
                waivable.append(path)
        if waivable and (self.production or not exception):
            raise DeploymentError(
                "Production security invariants cannot be changed: " + ", ".join(sorted(waivable))
                + ("" if self.production else " (isolated labs may request a time-limited exception)")
            )
        return waivable

    @staticmethod
    def _mask(name: str, value: Any) -> str:
        item = DEPLOYMENT_SETTINGS_BY_NAME.get(name)
        if item is not None and item.secret:
            return "<set>" if value else "<empty>"
        return json.dumps(value) if not isinstance(value, str) else value

    def _render(self, target: str, values: dict[str, Any], parent: dict[str, Any], changed: list[str]) -> str:
        lines = [f"# Black Onyx {target} deployment revision preview", "# Changes:"]
        parent_flat = {**{f"env.{k}": v for k, v in parent.get("env", {}).items()},
                       **{f"values.{k}": v for k, v in parent.get("values", {}).items()}}
        new_flat = {**{f"env.{k}": v for k, v in values.get("env", {}).items()},
                    **{f"values.{k}": v for k, v in values.get("values", {}).items()}}
        for key in changed:
            name = key.split(".", 1)[1]
            before = self._mask(name, parent_flat[key]) if key in parent_flat else "<unset>"
            after = self._mask(name, new_flat[key]) if key in new_flat else "<unset>"
            lines.append(f"#   {key}: {before} -> {after}")
        if target == "compose":
            lines.append("# managed.env")
            for name in sorted(values.get("env", {})):
                lines.append(f"{name}={self._mask(name, values['env'][name])}")
        else:
            import yaml

            lines.append("# managed-values.yaml")
            lines.append(yaml.safe_dump(_unflatten(values.get("values", {})), sort_keys=True).rstrip())
            lines.append("# secret stringData keys")
            for name in sorted(values.get("env", {})):
                lines.append(f"{HELM_SECRET_KEYS[name]}: {self._mask(name, values['env'][name])}")
        return "\n".join(lines)

    @staticmethod
    def _digest(values: dict[str, Any], preview: str) -> str:
        blob = json.dumps({"values": values, "preview": preview}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    # ── lifecycle ──────────────────────────────────────────────────────

    def create_revision(
        self,
        target: Target,
        *,
        env_changes: dict[str, str | None] | None = None,
        value_changes: dict[str, Any] | None = None,
        actor: str,
        lab_exception_hours: int | None = None,
        base_revision_id: str | None = None,
    ) -> Revision:
        if target not in ("compose", "helm"):
            raise DeploymentError("target must be compose or helm")
        base = self.get(base_revision_id) if base_revision_id else self.active(target)
        if base is not None and base.target != target:
            raise DeploymentError("Base revision belongs to another target")
        parent_values = self._values(self._row(base.revision_id)) if base else {"env": {}, "values": {}}
        values = {"env": dict(parent_values.get("env", {})), "values": dict(parent_values.get("values", {}))}
        for name, value in (env_changes or {}).items():
            if value is None:
                values["env"].pop(name, None)
            else:
                values["env"][name] = str(value)
        for path, value in (value_changes or {}).items():
            if value is None:
                values["values"].pop(path, None)
            else:
                values["values"][path] = value
        changed = sorted(
            {f"env.{k}" for k in set(values["env"]) | set(parent_values.get("env", {}))
             if values["env"].get(k) != parent_values.get("env", {}).get(k)}
            | {f"values.{k}" for k in set(values["values"]) | set(parent_values.get("values", {}))
               if values["values"].get(k) != parent_values.get("values", {}).get(k)}
        )
        if not changed and base_revision_id is None:
            raise DeploymentError("Revision does not change anything")
        exception_hours = lab_exception_hours or 0
        if exception_hours < 0 or exception_hours > MAX_EXCEPTION_HOURS:
            raise DeploymentError(f"Lab exceptions may last at most {MAX_EXCEPTION_HOURS} hours")
        waived = self._validate(target, values, exception=exception_hours > 0)
        expires = (_now() + timedelta(hours=exception_hours)).isoformat() if waived else None
        preview = self._render(target, values, parent_values, changed)
        if waived:
            preview += f"\n# LAB EXCEPTION until {expires}: {', '.join(sorted(waived))}"
        revision_id = f"rev-{_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"
        now = _now().isoformat()
        with self.database.transaction() as db:
            db.execute(
                """INSERT INTO deployment_revisions(
                       revision_id,target,parent_revision_id,status,values_encrypted,changed_keys,
                       rendered_preview,preview_digest,exception_expires_at,created_by,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (revision_id, target, base.revision_id if base else None, "draft",
                 self._fernet.encrypt(json.dumps(values, sort_keys=True).encode()).decode(),
                 json.dumps(changed), preview, self._digest(values, preview), expires, actor, now, now),
            )
            self._audit(db, actor, "deployment.revision.create", revision_id, {"changed": changed})
        return self.get(revision_id)

    def approve(self, revision_id: str, *, approver: str, preview_digest: str) -> Revision:
        revision = self.get(revision_id)
        if revision.status != "draft":
            raise DeploymentError("Only draft revisions can be approved")
        if not hmac.compare_digest(revision.preview_digest, preview_digest or ""):
            raise DeploymentError("Approval does not match the current preview")
        if os.environ.get("BLACK_ONYX_DEPLOY_TWO_PERSON", "").lower() in ("1", "true", "yes") \
                and approver == revision.created_by:
            raise DeploymentError("A different administrator must approve this revision")
        self._set_status(revision_id, "approved", approved_by=approver)
        with self.database.transaction() as db:
            self._audit(db, approver, "deployment.revision.approve", revision_id, {})
        return self.get(revision_id)

    def reject(self, revision_id: str, *, actor: str) -> Revision:
        revision = self.get(revision_id)
        if revision.status not in ("draft", "approved"):
            raise DeploymentError("Only draft or approved revisions can be rejected")
        self._set_status(revision_id, "rejected")
        with self.database.transaction() as db:
            self._audit(db, actor, "deployment.revision.reject", revision_id, {})
        return self.get(revision_id)

    def apply(self, revision_id: str, *, actor: str) -> Revision:
        revision = self.get(revision_id)
        if revision.status != "approved":
            raise DeploymentError("Only approved revisions can be applied")
        if revision.exception_expires_at and datetime.fromisoformat(revision.exception_expires_at) <= _now():
            raise DeploymentError("The lab exception on this revision has expired")
        if self.handoff_dir is None:
            raise DeploymentError("BLACK_ONYX_DEPLOY_HANDOFF_DIR is not configured")
        signing_key = os.environ.get("BLACK_ONYX_DEPLOY_SIGNING_KEY", "")
        if len(signing_key) < 32:
            raise DeploymentError("BLACK_ONYX_DEPLOY_SIGNING_KEY must be at least 32 characters")
        in_flight = self.database._conn.execute(
            "SELECT revision_id FROM deployment_revisions WHERE target=? AND status='applying'",
            (revision.target,),
        ).fetchone()
        if in_flight:
            raise DeploymentError(f"Revision {in_flight['revision_id']} is still applying")
        values = self._values(self._row(revision_id))
        previous = self.active(revision.target)
        bundle = self._write_bundle(revision, values, previous, signing_key)
        self._set_status(revision_id, "applying", error=None)
        with self.database.transaction() as db:
            self._audit(db, actor, "deployment.revision.apply", revision_id, {"bundle": str(bundle)})
        return self.get(revision_id)

    def _write_bundle(self, revision: Revision, values: dict[str, Any], previous: Revision | None,
                      signing_key: str) -> Path:
        assert self.handoff_dir is not None
        bundle = self.handoff_dir / revision.revision_id
        bundle.mkdir(parents=True, exist_ok=False)
        files: dict[str, str] = {}
        if revision.target == "compose":
            content = "".join(
                f"{name}={value}\n" for name, value in sorted(values.get("env", {}).items())
            )
            files["managed.env"] = content
        else:
            import yaml

            files["managed-values.yaml"] = yaml.safe_dump(_unflatten(values.get("values", {})), sort_keys=True)
            files["secret-data.json"] = json.dumps(
                {HELM_SECRET_KEYS[name]: value for name, value in sorted(values.get("env", {}).items())},
                sort_keys=True,
            )
            if set(HELM_SECRET_CONSUMERS) != set(HELM_SECRET_KEYS):
                raise DeploymentError("Helm secret consumer map does not cover every managed key")
            chart_values = yaml.safe_load(HELM_CHART_VALUES.read_text(encoding="utf-8")) or {}
            chart_values = _merge_values(chart_values, _unflatten(values.get("values", {})))
            namespaces = chart_values.get("namespaces") or {}
            namespace_operations: dict[str, dict[str, Any]] = {}
            env_values = values.get("env", {})
            for name, key in sorted(HELM_SECRET_KEYS.items()):
                operation = (
                    {"op": "set", "value": env_values[name]}
                    if name in env_values else {"op": "delete"}
                )
                for group, deployments in HELM_SECRET_CONSUMERS[name].items():
                    namespace = str(namespaces.get(group) or "")
                    if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace):
                        raise DeploymentError(f"Helm namespace {group} is missing or invalid")
                    entry = namespace_operations.setdefault(
                        namespace, {"keys": {}, "deployments": set()},
                    )
                    entry["keys"][key] = operation
                    entry["deployments"].update(deployments)
            normalized_operations = {
                namespace: {
                    "keys": entry["keys"],
                    "deployments": sorted(entry["deployments"]),
                }
                for namespace, entry in sorted(namespace_operations.items())
            }
            files["secret-operations.json"] = json.dumps(
                {"namespaces": normalized_operations}, sort_keys=True,
            )
        for name, content in files.items():
            path = bundle / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
        manifest = {
            "manifest_version": DEPLOYMENT_MANIFEST_VERSION,
            "policy_version": DEPLOYMENT_POLICY_VERSION,
            "revision_id": revision.revision_id,
            "target": revision.target,
            "previous_revision_id": previous.revision_id if previous else None,
            "files": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in files.items()},
            "created_at": _now().isoformat(),
            "exception_expires_at": revision.exception_expires_at,
        }
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(signing_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        (bundle / "manifest.json").write_text(
            json.dumps({"manifest": manifest, "signature": signature}, indent=2), encoding="utf-8",
        )
        return bundle

    def refresh(self, revision_id: str) -> Revision:
        """Fold the applier's status file into the revision state."""
        revision = self.get(revision_id)
        if revision.status != "applying" or self.handoff_dir is None:
            return revision
        status_path = self.handoff_dir / revision_id / "status.json"
        if not status_path.is_file():
            return revision
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return revision
        state = status.get("state")
        health = status.get("health") if isinstance(status.get("health"), dict) else None
        if state == "applied":
            previous = self.active(revision.target)
            if previous is not None:
                self._set_status(previous.revision_id, "superseded")
            self._set_status(revision_id, "active", applied_at=_now().isoformat(), health=health)
        elif state == "failed":
            self._set_status(
                revision_id, "failed", health=health,
                error=str(status.get("error") or "Applier reported failure")[:2000],
            )
        else:
            return revision
        with self.database.transaction() as db:
            self._audit(db, "deploy-applier", f"deployment.revision.{state}", revision_id,
                        {"health": health})
        return self.get(revision_id)

    def rollback(self, target: Target, *, actor: str) -> Revision:
        """Draft a revision restoring the last superseded state for ``target``."""
        row = self.database._conn.execute(
            "SELECT * FROM deployment_revisions WHERE target=? AND status='superseded' "
            "ORDER BY applied_at DESC LIMIT 1",
            (target,),
        ).fetchone()
        if row is None:
            raise DeploymentError("No earlier applied revision to roll back to")
        restore = self._values(row)
        current = self.active(target)
        current_values = self._values(self._row(current.revision_id)) if current else {"env": {}, "values": {}}
        env_changes: dict[str, str | None] = {
            name: None for name in current_values.get("env", {}) if name not in restore.get("env", {})
        }
        env_changes.update(restore.get("env", {}))
        value_changes: dict[str, Any] = {
            path: None for path in current_values.get("values", {}) if path not in restore.get("values", {})
        }
        value_changes.update(restore.get("values", {}))
        hours = None
        if row["exception_expires_at"]:
            remaining = datetime.fromisoformat(row["exception_expires_at"]) - _now()
            hours = max(1, int(remaining.total_seconds() // 3600)) if remaining.total_seconds() > 0 else None
        return self.create_revision(
            target, env_changes=env_changes, value_changes=value_changes, actor=actor,
            lab_exception_hours=hours, base_revision_id=current.revision_id if current else None,
        )

    def expired_exceptions(self) -> list[Revision]:
        now = _now().isoformat()
        rows = self.database._conn.execute(
            "SELECT * FROM deployment_revisions WHERE status='active' "
            "AND exception_expires_at IS NOT NULL AND exception_expires_at <= ?",
            (now,),
        ).fetchall()
        return [self._revision(row) for row in rows]

    @staticmethod
    def _audit(db: Any, actor: str, action: str, revision_id: str, detail: dict[str, Any]) -> None:
        db.execute(
            """INSERT INTO audit_events(event_id,actor_user_id,action,target_type,target_id,detail,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (os.urandom(16).hex(), None, action, "deployment_revision", revision_id,
             json.dumps({"actor": actor, **detail}), _now().isoformat()),
        )
