from __future__ import annotations

from pathlib import Path

from integration_hub.playbooks import execute_playbook, load_playbook, normalize_playbook_id


def test_normalize_playbook_id() -> None:
    assert normalize_playbook_id("block-ip-pfsense") == "packs/v1/block-ip-pfsense"
    assert normalize_playbook_id("packs/v1/notify-webhook.yaml") == "packs/v1/notify-webhook"


def test_load_pack_yaml_from_repo() -> None:
    root = Path(__file__).resolve().parents[3] / "playbooks"
    pb = load_playbook("packs/v1/block-ip-pfsense", root=root)
    assert pb["id"] == "block-ip-pfsense"
    assert any(s.get("action") == "pfsense.block_ip" for s in pb["steps"])


def test_execute_notify_webhook_dry_run() -> None:
    result = execute_playbook(
        "packs/v1/notify-webhook",
        {
            "webhook_url": "https://hooks.example.test/x",
            "incident": {"incident_id": "inc-1", "title": "t", "severity": "low"},
        },
        dry_run=True,
    )
    assert result["executed"] is True
    deliver = next(s for s in result["steps"] if s["action"] == "http.post")
    assert deliver["result"]["dry_run"] is True
    assert deliver["result"]["url"] == "https://hooks.example.test/x"
