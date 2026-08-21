"""Load YAML playbooks and execute approved steps."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from response_orchestrator import adapters
from response_orchestrator.config import settings

_SKIP_ACTIONS = frozenset({"create_response_request"})

_ACTION_MAP = {
    "validate_ip": lambda p, dry_run=True: adapters.validate_ip(p),
    "validate_asset": lambda p, dry_run=True: adapters.validate_asset(p),
    "validate_domain": lambda p, dry_run=True: adapters.validate_domain(p),
    "block_ip": adapters.block_ip,
    "pfsense.block_ip": adapters.block_ip,
    "isolate_host": adapters.isolate_host,
    "edr.isolate_host": adapters.isolate_host,
    "capture_now": adapters.capture_now,
    "block_c2": adapters.block_c2,
}


def _default_playbooks_root() -> Path:
    configured = (settings.playbooks_dir or "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "playbooks"


def normalize_playbook_id(playbook_id: str) -> str:
    pid = playbook_id.strip().removesuffix(".yaml").removesuffix(".yml")
    if pid.startswith("packs/"):
        return pid
    if "/" not in pid:
        return f"packs/v1/{pid}"
    return pid


def playbook_path(playbook_id: str, root: Path | None = None) -> Path:
    root = root or _default_playbooks_root()
    rel = normalize_playbook_id(playbook_id)
    path = root / f"{rel}.yaml"
    if not path.is_file():
        alt = root / f"{rel}.yml"
        if alt.is_file():
            return alt
    return path


def _builtin_playbook(playbook_id: str) -> dict[str, Any]:
    short = normalize_playbook_id(playbook_id).rsplit("/", 1)[-1]
    builtins: dict[str, dict[str, Any]] = {
        "block-ip-pfsense": {
            "id": "block-ip-pfsense",
            "approval": {"required": True},
            "dry_run": {"default": True},
            "steps": [
                {"id": "validate", "action": "validate_ip"},
                {"id": "apply", "action": "block_ip", "when": "approved"},
            ],
        },
        "isolate-host": {
            "id": "isolate-host",
            "approval": {"required": True},
            "dry_run": {"default": True},
            "steps": [
                {"id": "validate", "action": "validate_asset"},
                {"id": "isolate", "action": "isolate_host", "when": "approved"},
            ],
        },
        "isolate-host-edr": {
            "id": "isolate-host-edr",
            "approval": {"required": True},
            "dry_run": {"default": True},
            "steps": [
                {"id": "validate", "action": "validate_asset"},
                {"id": "isolate", "action": "isolate_host", "when": "approved"},
            ],
        },
        "capture-now": {
            "id": "capture-now",
            "approval": {"required": True},
            "dry_run": {"default": True},
            "steps": [
                {"id": "validate", "action": "validate_asset"},
                {"id": "capture", "action": "capture_now", "when": "approved"},
            ],
        },
        "block-c2": {
            "id": "block-c2",
            "approval": {"required": True},
            "dry_run": {"default": True},
            "steps": [
                {"id": "block", "action": "block_c2", "when": "approved"},
            ],
        },
    }
    if short not in builtins:
        raise FileNotFoundError(f"playbook not found: {playbook_id}")
    return builtins[short]


def load_playbook(playbook_id: str, root: Path | None = None) -> dict[str, Any]:
    path = playbook_path(playbook_id, root=root)
    if not path.is_file():
        return _builtin_playbook(playbook_id)
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"playbook {playbook_id} is not a mapping")
    return data


def list_playbooks(root: Path | None = None) -> list[dict[str, Any]]:
    root = root or _default_playbooks_root()
    packs = root / "packs" / "v1"
    found: list[dict[str, Any]] = []
    if packs.is_dir():
        for path in sorted(packs.glob("*.yaml")) + sorted(packs.glob("*.yml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            if isinstance(data, dict):
                found.append(
                    {
                        "id": data.get("id") or path.stem,
                        "name": data.get("name") or path.stem,
                        "approval_required": bool((data.get("approval") or {}).get("required", True)),
                        "dry_run_default": bool((data.get("dry_run") or {}).get("default", True)),
                    }
                )
    # Ensure built-ins appear even if YAML missing.
    for pid in ("block-ip-pfsense", "isolate-host", "capture-now", "block-c2"):
        if not any(p["id"] == pid or p["id"].endswith(pid) for p in found):
            pb = _builtin_playbook(pid)
            found.append(
                {
                    "id": pb["id"],
                    "name": pb["id"],
                    "approval_required": True,
                    "dry_run_default": True,
                }
            )
    return found


def run_action(action: str, payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    handler = _ACTION_MAP.get(action)
    if handler is None:
        raise ValueError(f"unknown playbook action: {action}")
    return handler(payload, dry_run=dry_run)


def execute_playbook(
    playbook_id: str,
    payload: dict[str, Any],
    *,
    dry_run: bool,
    approved: bool = True,
) -> dict[str, Any]:
    playbook = load_playbook(playbook_id)
    approval = playbook.get("approval") or {}
    if approval.get("required", True) and not approved:
        raise PermissionError("playbook requires approval")
    steps = list(playbook.get("steps") or [])
    step_results: list[dict[str, Any]] = []
    working = dict(payload)

    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "")
        step_id = str(step.get("id") or action)
        when = step.get("when")
        if when == "approved" and not approved:
            step_results.append({"id": step_id, "action": action, "skipped": True, "reason": "not_approved"})
            continue
        if action in _SKIP_ACTIONS:
            step_results.append({"id": step_id, "action": action, "skipped": True, "reason": "workflow"})
            continue
        result = run_action(action, working, dry_run=dry_run)
        step_results.append({"id": step_id, "action": action, "result": result})

    return {
        "executed": True,
        "dry_run": dry_run,
        "playbook_id": normalize_playbook_id(playbook_id),
        "playbook_name": playbook.get("name") or playbook.get("id"),
        "approval_required": bool(approval.get("required", True)),
        "steps": step_results,
    }
