"""Load and execute declarative playbook packs under playbooks/packs/v1."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from integration_hub import adapters
from integration_hub.config import settings

# Actions that are bookkeeping / already handled by the response workflow.
_SKIP_ACTIONS = frozenset({"create_response_request"})


def _default_playbooks_root() -> Path:
    configured = (settings.playbooks_dir or "").strip()
    if configured:
        return Path(configured)
    # services/integration-hub/app/playbooks.py → repo root / playbooks
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


def load_playbook(playbook_id: str, root: Path | None = None) -> dict[str, Any]:
    path = playbook_path(playbook_id, root=root)
    if not path.is_file():
        # Minimal built-in fallback so approvals still execute known actions.
        return _builtin_playbook(playbook_id)
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"playbook {playbook_id} is not a mapping")
    return data


def _builtin_playbook(playbook_id: str) -> dict[str, Any]:
    pid = normalize_playbook_id(playbook_id)
    short = pid.rsplit("/", 1)[-1]
    builtins: dict[str, dict[str, Any]] = {
        "block-ip-pfsense": {
            "id": "block-ip-pfsense",
            "steps": [
                {"id": "validate", "action": "validate_ip"},
                {"id": "apply_block", "action": "pfsense.block_ip", "when": "approved"},
            ],
        },
        "notify-webhook": {
            "id": "notify-webhook",
            "steps": [
                {"id": "build_payload", "action": "format_incident_webhook"},
                {"id": "deliver", "action": "http.post"},
            ],
        },
        "isolate-host-edr": {
            "id": "isolate-host-edr",
            "steps": [
                {"id": "validate", "action": "validate_asset"},
                {"id": "isolate", "action": "edr.isolate_host", "when": "approved"},
            ],
        },
        "isolate-host": {
            "id": "isolate-host",
            "steps": [
                {"id": "validate", "action": "validate_asset"},
                {"id": "isolate", "action": "edr.isolate_host", "when": "approved"},
            ],
        },
    }
    if short not in builtins:
        raise FileNotFoundError(f"playbook not found: {playbook_id}")
    return builtins[short]


def run_action(action: str, payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    if action == "validate_ip":
        return adapters.validate_ip(payload)
    if action == "validate_asset":
        return adapters.validate_asset(payload)
    if action == "format_incident_webhook":
        return adapters.format_incident_webhook(payload)
    if action == "pfsense.block_ip":
        return adapters.pfsense_block_ip(payload, dry_run=dry_run)
    if action == "edr.isolate_host":
        return adapters.edr_isolate_host(payload, dry_run=dry_run)
    if action == "http.post":
        formatted = payload.get("_formatted_body")
        body = formatted if isinstance(formatted, dict) else None
        return adapters.http_post(payload, dry_run=dry_run, body=body)
    raise ValueError(f"unknown playbook action: {action}")


def execute_playbook(
    playbook_id: str,
    payload: dict[str, Any],
    *,
    dry_run: bool,
    approved: bool = True,
) -> dict[str, Any]:
    """Run playbook steps after approval. Returns structured result for audit."""
    playbook = load_playbook(playbook_id)
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
        skip_live = bool(step.get("dry_run_skips_live")) and dry_run
        # still invoke adapters with dry_run=True so would_send is recorded
        result = run_action(action, working, dry_run=dry_run or skip_live)
        if action == "format_incident_webhook" and isinstance(result.get("body"), dict):
            working["_formatted_body"] = result["body"]
        step_results.append({"id": step_id, "action": action, "result": result})

    return {
        "executed": True,
        "dry_run": dry_run,
        "playbook_id": normalize_playbook_id(playbook_id),
        "playbook_name": playbook.get("name") or playbook.get("id"),
        "steps": step_results,
    }
