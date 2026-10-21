import os
from pathlib import Path

import pytest

from code_processor.scanners import (
    run_configured_semgrep,
    run_heuristic_scan,
    scanner_findings_structure,
)


@pytest.mark.skipif(os.name == "nt", reason="Semgrep does not publish a Windows CLI")
def test_semgrep_cli_normalizes_repository_rule_finding(tmp_path: Path, monkeypatch):
    risky = tmp_path / "risky.py"
    risky.write_text("def bad(value):\n    return eval(value)\n", encoding="utf-8")
    monkeypatch.setenv("SEMGREP_PROFILE_CONFIGS", "profiles/owasp-asvs")
    findings = run_configured_semgrep([risky])
    finding = next(item for item in findings if item["rule_id"] == "owasp-asvs-eval-use")
    assert finding["scanner"] == "semgrep"
    assert finding["severity"] == "ERROR"
    assert finding["path"].endswith("risky.py")
    assert finding["start_line"] == 2


def test_run_heuristic_scanner(tmp_path: Path):
    risky = tmp_path / "risky.py"
    risky.write_text(
        "import pickle\n"
        "def bad(cmd, data):\n"
        "    subprocess.call(cmd, shell=True)\n"
        "    eval(data)\n"
        "    return pickle.loads(data)\n",
        encoding="utf-8",
    )
    findings = run_heuristic_scan([tmp_path])
    rule_ids = {f["rule_id"] for f in findings}
    assert "heuristic.shell-true" in rule_ids
    assert "heuristic.eval-call" in rule_ids
    assert "heuristic.pickle-loads" in rule_ids
    by_rule = {f["rule_id"]: f for f in findings if f.get("scanner") == "heuristic"}
    assert "T1059" in by_rule["heuristic.shell-true"]["mitre_techniques"]
    assert "T1059.006" in by_rule["heuristic.eval-call"]["mitre_techniques"]
    assert "T1059.006" in by_rule["heuristic.pickle-loads"]["mitre_techniques"]

    structured = scanner_findings_structure(findings, semgrep_available=False)
    assert structured["scanners"]["semgrep"]["status"] == "unavailable"
    assert len(structured["scanner_findings"]) >= 3

    from code_processor.cwe_normalize import enrich_scanner_findings

    enriched = enrich_scanner_findings(findings)
    by_cwe = {f["rule_id"]: f.get("cwe_id") for f in enriched if f.get("scanner") == "heuristic"}
    assert by_cwe["heuristic.shell-true"] == "CWE-78"
    assert by_cwe["heuristic.eval-call"] == "CWE-95"
    assert by_cwe["heuristic.pickle-loads"] == "CWE-502"


def test_run_heuristic_scanner_clean_file(tmp_path: Path):
    clean = tmp_path / "clean.py"
    clean.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    findings = run_heuristic_scan([tmp_path])
    # Heuristics should not fire on clean arithmetic.
    assert not any(f.get("scanner") == "heuristic" for f in findings)
