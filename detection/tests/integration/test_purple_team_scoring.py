from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "purple-team" / "score_purple_team.py"
SPEC = importlib.util.spec_from_file_location("purple_team_scorer", SCRIPT)
assert SPEC and SPEC.loader
scorer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scorer)


EXPECTED = {
    "techniques": [
        {"technique_id": "T1000", "name": "one", "expected_finding_types": ["alpha", "alpha-alt"]},
        {"technique_id": "T2000", "name": "two", "expected_finding_types": ["beta"]},
    ]
}
START = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
END = datetime(2026, 8, 11, 13, 0, tzinfo=UTC)


def finding(kind: str, *, tenant: str = "tenant-purple", timestamp: str = "2026-08-11T12:15:00Z") -> dict[str, str]:
    return {"tenant_id": tenant, "finding_type": kind, "occurred_at": timestamp}


def test_score_accepts_any_expected_finding_type_per_technique() -> None:
    report = scorer.score(EXPECTED, [finding("alpha-alt"), finding("beta")], tenant_id="tenant-purple", window_start=START, window_end=END)

    assert report["passed"] is True
    assert report["missing_techniques"] == []


def test_score_reports_missing_techniques() -> None:
    report = scorer.score(EXPECTED, [finding("alpha")], tenant_id="tenant-purple", window_start=START, window_end=END)

    assert report["passed"] is False
    assert report["missing_techniques"] == ["T2000"]


def test_score_rejects_findings_from_another_tenant() -> None:
    with pytest.raises(scorer.InputError, match="outside tenant"):
        scorer.score(EXPECTED, [finding("alpha", tenant="other")], tenant_id="tenant-purple", window_start=START, window_end=END)


def test_score_ignores_findings_outside_the_time_window() -> None:
    report = scorer.score(EXPECTED, [finding("alpha", timestamp="2026-08-11T11:59:59Z")], tenant_id="tenant-purple", window_start=START, window_end=END)

    assert report["findings_in_window"] == 0
    assert report["missing_techniques"] == ["T1000", "T2000"]


def test_findings_rejects_malformed_export() -> None:
    with pytest.raises(scorer.InputError, match="items array"):
        scorer._findings({"findings": []})


def test_load_json_rejects_non_utf8_input(tmp_path: Path) -> None:
    capture = tmp_path / "findings.json"
    capture.write_bytes(b"\xff\xfe")

    with pytest.raises(scorer.InputError, match="valid UTF-8"):
        scorer._load_json(capture)


def test_load_json_enforces_byte_limit_while_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = tmp_path / "findings.json"
    capture.write_bytes(b"[] ")
    monkeypatch.setattr(scorer, "MAX_JSON_BYTES", 2)

    with pytest.raises(scorer.InputError, match="byte limit"):
        scorer._load_json(capture)


def test_score_rejects_duplicate_techniques() -> None:
    duplicated = {
        "techniques": [
            {"technique_id": "T1000", "expected_finding_types": ["alpha"]},
            {"technique_id": "T1000", "expected_finding_types": ["beta"]},
        ]
    }
    with pytest.raises(scorer.InputError, match="duplicate technique_id"):
        scorer.score(
            duplicated,
            [finding("alpha")],
            tenant_id="tenant-purple",
            window_start=START,
            window_end=END,
        )


def test_score_rejects_findings_without_a_type() -> None:
    row = finding("alpha")
    del row["finding_type"]
    with pytest.raises(scorer.InputError, match="finding_type"):
        scorer.score(
            EXPECTED,
            [row],
            tenant_id="tenant-purple",
            window_start=START,
            window_end=END,
        )


def test_cli_writes_machine_readable_report(tmp_path: Path) -> None:
    expected_path = tmp_path / "expected.json"
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.json"
    expected_path.write_text(json.dumps({"tenant_hint": "tenant-purple", **EXPECTED}), encoding="utf-8")
    findings_path.write_text(json.dumps([finding("alpha"), finding("beta")]), encoding="utf-8")

    result = scorer.main(
        [
            "--expected-map",
            str(expected_path),
            "--findings",
            str(findings_path),
            "--window-start",
            START.isoformat(),
            "--window-end",
            END.isoformat(),
            "--report",
            str(report_path),
        ]
    )

    assert result == 0
    assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is True


@pytest.mark.parametrize("input_name", ["expected.json", "findings.json"])
def test_cli_refuses_to_overwrite_scoring_inputs(tmp_path: Path, input_name: str) -> None:
    expected_path = tmp_path / "expected.json"
    findings_path = tmp_path / "findings.json"
    expected_path.write_text(json.dumps({"tenant_hint": "tenant-purple", **EXPECTED}), encoding="utf-8")
    findings_path.write_text(json.dumps([finding("alpha"), finding("beta")]), encoding="utf-8")
    original = (tmp_path / input_name).read_bytes()

    result = scorer.main(
        [
            "--expected-map",
            str(expected_path),
            "--findings",
            str(findings_path),
            "--window-start",
            START.isoformat(),
            "--window-end",
            END.isoformat(),
            "--report",
            str(tmp_path / input_name),
        ]
    )

    assert result == 2
    assert (tmp_path / input_name).read_bytes() == original


def test_cli_reports_output_publication_failure(tmp_path: Path) -> None:
    expected_path = tmp_path / "expected.json"
    findings_path = tmp_path / "findings.json"
    expected_path.write_text(json.dumps({"tenant_hint": "tenant-purple", **EXPECTED}), encoding="utf-8")
    findings_path.write_text(json.dumps([finding("alpha"), finding("beta")]), encoding="utf-8")

    result = scorer.main(
        [
            "--expected-map",
            str(expected_path),
            "--findings",
            str(findings_path),
            "--window-start",
            START.isoformat(),
            "--window-end",
            END.isoformat(),
            "--report",
            str(tmp_path),
        ]
    )

    assert result == 2
