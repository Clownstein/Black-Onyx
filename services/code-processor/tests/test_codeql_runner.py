from __future__ import annotations

import json
from pathlib import Path

from code_processor.codeql_runner import _sarif_findings, run_codeql
from code_processor.config import settings


def test_codeql_disabled_is_explicit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "codeql_enabled", False)
    findings, capability = run_codeql(tmp_path)
    assert findings == []
    assert capability == {"status": "disabled", "finding_count": 0}


def test_codeql_analysis_uses_bounded_ram(tmp_path: Path, monkeypatch) -> None:
    from code_processor import codeql_runner

    source = tmp_path / "sample.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str], _timeout: int) -> None:
        commands.append(command)
        if "analyze" in command:
            output = next(item.split("=", 1)[1] for item in command if item.startswith("--output="))
            Path(output).write_text('{"runs": []}', encoding="utf-8")

    monkeypatch.setattr(settings, "codeql_enabled", True)
    monkeypatch.setattr(settings, "codeql_cli_path", str(tmp_path / "codeql"))
    (tmp_path / "codeql").write_text("", encoding="utf-8")
    monkeypatch.setattr(settings, "codeql_ram_mb", 1024)
    monkeypatch.setattr(codeql_runner, "_run", fake_run)

    findings, status = run_codeql(tmp_path)

    assert findings == []
    analyze = next(command for command in commands if "analyze" in command)
    assert "--ram=1024" in analyze
    assert status["status"] == "ready"


def test_codeql_sarif_normalizes_finding_shape(tmp_path: Path) -> None:
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps({
        "runs": [{
            "tool": {"driver": {"rules": [{"id": "py/sql-injection", "properties": {"tags": ["security"]}}]}},
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "Uncontrolled query"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "api.py"},
                    "region": {"startLine": 12, "endLine": 13},
                }}],
            }],
        }],
    }), encoding="utf-8")
    assert _sarif_findings(sarif) == [{
        "scanner": "codeql",
        "rule_id": "py/sql-injection",
        "severity": "error",
        "message": "Uncontrolled query",
        "path": "api.py",
        "start_line": 12,
        "end_line": 13,
        "metadata": {"tags": ["security"]},
    }]
