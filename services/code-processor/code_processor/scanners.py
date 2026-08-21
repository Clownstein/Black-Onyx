from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from code_processor.config import settings
from code_processor.codeql_runner import run_codeql

# Heuristic patterns used when the semgrep binary is unavailable.
# Each row: (pattern, rule_id, severity, mitre_tactics, mitre_techniques)
_HEURISTICS: list[tuple[str, str, str, list[str], list[str]]] = [
    (r"shell\s*=\s*True", "heuristic.shell-true", "high", ["TA0002"], ["T1059"]),
    (r"\beval\s*\(", "heuristic.eval-call", "high", ["TA0002"], ["T1059.006"]),
    (r"pickle\.loads\s*\(", "heuristic.pickle-loads", "high", ["TA0002"], ["T1059.006"]),
]


def run_configured_semgrep(paths: list[str] | list[Path]) -> list[dict[str, Any]]:
    """Run the configured Semgrep CLI and fail clearly when unavailable."""
    path_objs = [Path(p) for p in paths]
    if not path_objs:
        return []
    if shutil.which("semgrep") is None:
        raise RuntimeError("semgrep binary is unavailable")
    return _run_semgrep_cli(path_objs)


def run_heuristic_scan(paths: list[str] | list[Path]) -> list[dict[str, Any]]:
    """Run the explicit rule-based heuristic scanner capability."""
    return _regex_heuristics([Path(path) for path in paths])


def _repo_semgrep_rules_dir() -> Path:
    configured = os.environ.get("CODE_PROCESSOR_SEMGREP_RULES_DIR", "").strip()
    if configured:
        return Path(configured)
    installed = Path("/opt/black-onyx/scanners/semgrep/rules")
    if installed.is_dir():
        return installed
    return Path(__file__).resolve().parents[3] / "detection" / "scanners" / "semgrep" / "rules"


def _profile_config_dirs() -> list[str]:
    """Resolve ``SEMGREP_PROFILE_CONFIGS`` into absolute rule directories.

    The env var is a comma-separated list of paths relative to
    ``scanners/semgrep/rules/`` (e.g. ``profiles/owasp-asvs,profiles/pci-dss``).
    Only entries that exist on disk are returned.
    """
    raw = os.environ.get("SEMGREP_PROFILE_CONFIGS", "").strip()
    if not raw:
        return []
    rules_root = _repo_semgrep_rules_dir()
    resolved: list[str] = []
    for entry in raw.split(","):
        rel = entry.strip()
        if not rel:
            continue
        candidate = (rules_root / rel).resolve()
        if candidate.exists() and str(candidate) not in resolved:
            resolved.append(str(candidate))
    return resolved


def _semgrep_config() -> str:
    configured = os.environ.get("SEMGREP_CONFIG", "").strip()
    if configured:
        return configured
    repo_rules = _repo_semgrep_rules_dir()
    if repo_rules.is_dir() and any(repo_rules.glob("*.y*ml")):
        return str(repo_rules)
    return "auto"


def _semgrep_configs() -> list[str]:
    """Return the ordered list of Semgrep ``--config`` values to apply.

    Honors ``SEMGREP_PROFILE_CONFIGS`` (multiple profile packs) when set and at
    least one directory exists; otherwise falls back to the single
    ``SEMGREP_CONFIG`` / repo-rules / ``auto`` behavior.
    """
    profile_dirs = _profile_config_dirs()
    if profile_dirs:
        return profile_dirs
    return [_semgrep_config()]


def _run_semgrep_cli(paths: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    configs = _semgrep_configs()
    config_args: list[str] = []
    for cfg in configs:
        config_args.extend(["--config", cfg])
    for target in paths:
        if not target.exists():
            continue
        try:
            proc = subprocess.run(
                [
                    "semgrep",
                    *config_args,
                    "--json",
                    "--quiet",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"semgrep timed out scanning {target}") from exc
        except OSError as exc:
            raise RuntimeError(f"semgrep failed to start: {exc}") from exc
        if proc.returncode not in {0, 1}:
            raise RuntimeError(
                f"semgrep failed for {target}: {(proc.stderr or '').strip() or proc.returncode}"
            )
        if not proc.stdout.strip():
            continue
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"semgrep returned invalid JSON for {target}") from exc
        for item in payload.get("results") or []:
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") if isinstance(extra, dict) else None
            findings.append(
                {
                    "scanner": "semgrep",
                    "rule_id": item.get("check_id"),
                    "severity": extra.get("severity") if isinstance(extra, dict) else "info",
                    "message": (extra.get("message") if isinstance(extra, dict) else None) or "",
                    "path": item.get("path"),
                    "start_line": (item.get("start") or {}).get("line"),
                    "end_line": (item.get("end") or {}).get("line"),
                    "metadata": dict(metadata) if isinstance(metadata, dict) else {},
                }
            )
    return findings


def _regex_heuristics(paths: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.py")))
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, rule_id, severity, tactics, techniques in _HEURISTICS:
                if re.search(pattern, line):
                    findings.append(
                        {
                            "scanner": "heuristic",
                            "rule_id": rule_id,
                            "severity": severity,
                            "message": f"Matched {rule_id}",
                            "path": str(file_path),
                            "start_line": lineno,
                            "end_line": lineno,
                            "mitre_tactics": list(tactics),
                            "mitre_techniques": list(techniques),
                        }
                    )
    return findings


def scanner_findings_structure(
    findings: list[dict[str, Any]],
    *,
    semgrep_available: bool | None = None,
) -> dict[str, Any]:
    available = (
        shutil.which("semgrep") is not None if semgrep_available is None else semgrep_available
    )
    return {
        "scanner_findings": findings,
        "scanners": {
            "semgrep": {
                "available": available,
                "finding_count": len([f for f in findings if f.get("scanner") == "semgrep"]),
                "status": "ok" if available else "unavailable",
            },
            "heuristic": {
                "finding_count": len([f for f in findings if f.get("scanner") == "heuristic"]),
            },
        },
    }


def scan_path_or_noop(target_dir: Path) -> dict[str, Any]:
    codeql_findings: list[dict[str, Any]] = []
    try:
        codeql_findings, codeql_status = run_codeql(target_dir)
    except RuntimeError as exc:
        codeql_status = {"status": "failed", "finding_count": 0, "reason": str(exc)}
    try:
        if not settings.semgrep_enabled:
            raise RuntimeError("semgrep is disabled")
        findings = run_configured_semgrep([target_dir])
        findings.extend(codeql_findings)
        result = scanner_findings_structure(findings, semgrep_available=True)
        result["scanners"]["codeql"] = codeql_status
        result["capability"] = {
            "status": "ready",
            "capability": "semgrep",
            "reason": "configured_cli",
        }
        return result
    except RuntimeError as exc:
        if settings.heuristic_enabled:
            findings = run_heuristic_scan([target_dir])
            findings.extend(codeql_findings)
            result = scanner_findings_structure(findings, semgrep_available=False)
            result["capability"] = {
                "status": "degraded",
                "capability": "semgrep",
                "reason": f"{exc}; independent heuristic scanner enabled",
            }
            result["scanners"]["codeql"] = codeql_status
            return result
        result = scanner_findings_structure(codeql_findings, semgrep_available=False)
        result["scanners"]["codeql"] = codeql_status
        result["capability"] = {
            "status": "degraded",
            "capability": "semgrep",
            "reason": str(exc),
        }
        return result
