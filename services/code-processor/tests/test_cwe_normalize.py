from code_processor.cwe_normalize import (
    attach_cwe_to_finding,
    collect_cwe_ids,
    cwe_contributors,
    cwe_for_rule_id,
    enrich_scanner_findings,
    normalize_cwe_id,
)


def test_normalize_cwe_id():
    assert normalize_cwe_id("CWE-89") == "CWE-89"
    assert normalize_cwe_id("cwe_79") == "CWE-79"
    assert normalize_cwe_id("22") == "CWE-22"
    assert normalize_cwe_id("see CWE-798 in message") == "CWE-798"
    assert normalize_cwe_id("") is None
    assert normalize_cwe_id(None) is None


def test_cwe_for_common_rules():
    assert cwe_for_rule_id("sql-injection") == "CWE-89"
    assert cwe_for_rule_id("python.lang.security.audit.sqli.raw-query") == "CWE-89"
    assert cwe_for_rule_id("javascript.browser.security.xss.dangerously-set") == "CWE-79"
    assert cwe_for_rule_id("path-traversal") == "CWE-22"
    assert cwe_for_rule_id("command-injection") == "CWE-78"
    assert cwe_for_rule_id("hardcoded-secret") == "CWE-798"
    assert cwe_for_rule_id("insecure-deserialization") == "CWE-502"
    assert cwe_for_rule_id("ssrf") == "CWE-918"
    assert cwe_for_rule_id("heuristic.shell-true") == "CWE-78"
    assert cwe_for_rule_id("heuristic.eval-call") == "CWE-95"
    assert cwe_for_rule_id("heuristic.pickle-loads") == "CWE-502"
    assert cwe_for_rule_id("totally-unknown-rule") is None


def test_attach_and_contributors():
    findings = enrich_scanner_findings(
        [
            {
                "scanner": "heuristic",
                "rule_id": "heuristic.shell-true",
                "severity": "high",
                "message": "Matched heuristic.shell-true",
                "path": "a.py",
                "start_line": 1,
                "end_line": 1,
            },
            {
                "scanner": "semgrep",
                "rule_id": "python.lang.security.audit.sql-injection.avoid-sql",
                "severity": "high",
                "message": "Possible SQL injection",
                "path": "db.py",
                "start_line": 10,
                "end_line": 12,
            },
        ]
    )
    assert findings[0]["cwe_id"] == "CWE-78"
    assert findings[1]["cwe_id"] == "CWE-89"
    assert collect_cwe_ids(findings) == ["CWE-78", "CWE-89"]
    contrib = cwe_contributors(findings)
    assert len(contrib) == 2
    assert contrib[0]["type"] == "cwe"
    assert contrib[0]["cwe_id"] == "CWE-78"

    already = attach_cwe_to_finding({"rule_id": "x", "cwe_id": "cwe-22"})
    assert already["cwe_id"] == "CWE-22"
