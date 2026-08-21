"""Unit tests for offline Sigma-like matcher."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from run_sigma_match import load_rules, match_event, run_match  # noqa: E402

RULES_DIR = ROOT / "rules"


@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES_DIR)


def test_load_curated_rules(rules) -> None:
    ids = {r.get("id") for r in rules}
    assert "aa-proc-powershell-encoded" in ids
    assert "aa-failed-logon-burst" in ids
    assert "aa-rare-scheduled-task" in ids


def test_encoded_powershell_matches(rules) -> None:
    rule = next(r for r in rules if r.get("id") == "aa-proc-powershell-encoded")
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA",
        "asset_id": "host-1",
        "tenant_id": "t1",
        "occurred_at": "2024-06-01T12:00:00Z",
    }
    hit = match_event(event, rule)
    assert hit is not None
    assert hit["finding_type"] == "sigma_rule"
    assert "T1059.001" in hit["mitre_techniques"]


def test_failed_logon_burst(rules) -> None:
    rule = next(r for r in rules if r.get("id") == "aa-failed-logon-burst")
    events = [
        {
            "EventID": 4625,
            "TargetUserName": "alice",
            "asset_id": "dc-1",
            "tenant_id": "t1",
            "occurred_at": f"2024-06-01T12:00:{i:02d}Z",
        }
        for i in range(6)
    ]
    findings = run_match(events, [rule])
    assert findings
    assert findings[0]["evidence"]["burst_count"] >= 5


def test_cli_smoke(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    events_path = tmp_path / "events.json"
    events_path.write_text(
        json.dumps(
            [
                {
                    "EventID": 1,
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "pwsh -EncodedCommand AAA=",
                    "asset_id": "host-2",
                    "tenant_id": "t1",
                    "occurred_at": "2024-06-01T12:00:00Z",
                }
            ]
        ),
        encoding="utf-8",
    )
    from run_sigma_match import main

    assert main(["--events", str(events_path), "--rules", str(RULES_DIR)]) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert isinstance(payload, list)
    assert payload
    assert payload[0]["rule_id"] == "aa-proc-powershell-encoded"
