#!/usr/bin/env python3
"""Score an operator-exported purple-team findings capture offline.

This deliberately does not contact endpoints or invoke adversary-emulation
software. Operators export findings from an isolated lab after an Atomic Red
Team or Caldera exercise, then use this tool to produce an auditable result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 100 * 1024 * 1024


class InputError(ValueError):
    """Raised for an invalid findings capture or scoring invocation."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise InputError(f"invalid RFC 3339 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise InputError(f"timestamp must include a timezone: {value}")
    return parsed.astimezone(UTC)


def _load_json(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise InputError(f"JSON input exceeds {MAX_JSON_BYTES} byte limit: {path}")
        return json.loads(raw.decode("utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"JSON input is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path}: {exc.msg}") from exc
    except OSError as exc:
        raise InputError(f"unable to read {path}: {exc}") from exc


def _paths_alias(left: Path, right: Path) -> bool:
    """Return true when output would replace one of the scorer inputs."""
    try:
        return left.samefile(right)
    except (FileNotFoundError, OSError):
        return left.resolve(strict=False) == right.resolve(strict=False)


def _write_report(path: Path, report: dict[str, Any]) -> None:
    """Publish a complete report atomically in the destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("items"), list):
        rows = payload["items"]
    else:
        raise InputError("findings JSON must be an array or an object with an items array")
    if not all(isinstance(row, dict) for row in rows):
        raise InputError("every findings item must be an object")
    return rows


def _finding_time(row: dict[str, Any]) -> datetime:
    candidates: list[Any] = [
        row.get("occurred_at"),
        row.get("timestamp"),
        row.get("created_at"),
        row.get("observed_at"),
    ]
    window = row.get("window")
    if isinstance(window, dict):
        candidates.append(window.get("start"))
    for value in candidates:
        if isinstance(value, str) and value:
            return _parse_time(value)
    raise InputError("each finding needs occurred_at, timestamp, created_at, observed_at, or window.start")


def score(
    expected: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    tenant_id: str,
    window_start: datetime,
    window_end: datetime,
) -> dict[str, Any]:
    if window_end < window_start:
        raise InputError("window end must not precede window start")
    techniques = expected.get("techniques")
    if not isinstance(techniques, list) or not techniques:
        raise InputError("expected map needs a non-empty techniques array")

    seen_techniques: set[str] = set()
    for technique in techniques:
        if not isinstance(technique, dict):
            raise InputError("each expected technique must be an object")
        technique_id = technique.get("technique_id")
        expected_types = technique.get("expected_finding_types")
        if not isinstance(technique_id, str) or not technique_id.strip():
            raise InputError("each technique needs a non-empty technique_id")
        if technique_id in seen_techniques:
            raise InputError(f"duplicate technique_id: {technique_id}")
        seen_techniques.add(technique_id)
        if not isinstance(expected_types, list) or not expected_types or not all(
            isinstance(item, str) and item for item in expected_types
        ):
            raise InputError("techniques need a non-empty expected_finding_types string array")

    observed_types: set[str] = set()
    in_window = 0
    wrong_tenant = 0
    for row in findings:
        if str(row.get("tenant_id") or "") != tenant_id:
            wrong_tenant += 1
            continue
        timestamp = _finding_time(row)
        finding_type = row.get("finding_type")
        if not isinstance(finding_type, str) or not finding_type:
            raise InputError("each finding needs a non-empty finding_type")
        if window_start <= timestamp <= window_end:
            in_window += 1
            observed_types.add(finding_type)

    if wrong_tenant:
        raise InputError(f"findings capture contains {wrong_tenant} row(s) outside tenant {tenant_id!r}")

    coverage: list[dict[str, Any]] = []
    for technique in techniques:
        technique_id = technique.get("technique_id")
        expected_types = technique.get("expected_finding_types")
        matched = sorted(set(expected_types) & observed_types)
        coverage.append(
            {
                "technique_id": technique_id,
                "name": technique.get("name", technique_id),
                "expected_finding_types": expected_types,
                "matched_finding_types": matched,
                "passed": bool(matched),
            }
        )

    failed = [item["technique_id"] for item in coverage if not item["passed"]]
    return {
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "window": {"start": window_start.isoformat(), "end": window_end.isoformat()},
        "findings_in_window": in_window,
        "observed_finding_types": sorted(observed_types),
        "techniques": coverage,
        "passed": not failed,
        "missing_techniques": failed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a time-bounded purple-team findings export offline")
    here = Path(__file__).resolve().parent
    parser.add_argument("--expected-map", type=Path, default=here / "expected_findings.json")
    parser.add_argument("--findings", required=True, type=Path, help="JSON array or incident-api {items: [...]} export")
    parser.add_argument("--tenant", help="Lab tenant; defaults to expected-map tenant_hint")
    parser.add_argument("--window-start", required=True, help="RFC 3339 inclusive start")
    parser.add_argument("--window-end", required=True, help="RFC 3339 inclusive end")
    parser.add_argument("--report", required=True, type=Path, help="Output JSON report path")
    args = parser.parse_args(argv)
    try:
        if _paths_alias(args.report, args.expected_map) or _paths_alias(args.report, args.findings):
            raise InputError("report path must not overwrite the expected map or findings export")
        expected = _load_json(args.expected_map)
        if not isinstance(expected, dict):
            raise InputError("expected map must be a JSON object")
        tenant = args.tenant or expected.get("tenant_hint")
        if not isinstance(tenant, str) or not tenant:
            raise InputError("--tenant is required when expected-map has no tenant_hint")
        report = score(
            expected,
            _findings(_load_json(args.findings)),
            tenant_id=tenant,
            window_start=_parse_time(args.window_start),
            window_end=_parse_time(args.window_end),
        )
    except InputError as exc:
        print(f"purple-team scoring input error: {exc}", file=sys.stderr)
        return 2

    try:
        _write_report(args.report, report)
    except OSError as exc:
        print(f"purple-team report write error: {exc}", file=sys.stderr)
        return 2
    print(f"Purple-team report: {args.report}")
    if not report["passed"]:
        print("Missing expected coverage: " + ", ".join(report["missing_techniques"]), file=sys.stderr)
        return 1
    print("Purple-team expected coverage satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
