from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from code_processor.config import settings

_LANGUAGES: dict[str, tuple[set[str], str]] = {
    "python": ({".py"}, "codeql/python-queries:codeql-suites/python-security-and-quality.qls"),
    "javascript-typescript": (
        {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
        "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
    ),
    "go": ({".go"}, "codeql/go-queries:codeql-suites/go-security-and-quality.qls"),
}


def _source_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _detect_languages(root: Path) -> list[tuple[str, str]]:
    suffixes = {path.suffix.lower() for path in root.rglob("*") if path.is_file()}
    return [(language, suite) for language, (extensions, suite) in _LANGUAGES.items() if suffixes & extensions]


def _run(command: list[str], timeout: int) -> None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "CODEQL_THREADS": str(settings.codeql_threads)},
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("CodeQL scan timed out") from exc
    except OSError as exc:
        raise RuntimeError(f"CodeQL failed to start: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[-2000:]
        raise RuntimeError(f"CodeQL failed: {detail or result.returncode}")


def _sarif_findings(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = []
    for run in payload.get("runs") or []:
        rules = {
            str(rule.get("id")): rule
            for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
            if isinstance(rule, dict)
        }
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "codeql.unknown")
            location = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            region = location.get("region") or {}
            uri = (location.get("artifactLocation") or {}).get("uri")
            properties = result.get("properties") or {}
            rule = rules.get(rule_id) or {}
            findings.append({
                "scanner": "codeql",
                "rule_id": rule_id,
                "severity": properties.get("security-severity") or result.get("level") or "warning",
                "message": (result.get("message") or {}).get("text") or "",
                "path": uri,
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine") or region.get("startLine"),
                "metadata": rule.get("properties") or properties,
            })
    return findings


def run_codeql(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not settings.codeql_enabled:
        return [], {"status": "disabled", "finding_count": 0}
    cli = Path(settings.codeql_cli_path)
    if not cli.is_file() and shutil.which(settings.codeql_cli_path) is None:
        raise RuntimeError("CodeQL is enabled but the configured CLI is unavailable")
    if _source_size(root) > settings.codeql_max_source_bytes:
        raise RuntimeError("CodeQL source size limit exceeded")
    languages = _detect_languages(root)
    if not languages:
        return [], {"status": "unsupported_language", "finding_count": 0}

    executable = str(cli if cli.is_file() else settings.codeql_cli_path)
    findings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="black-onyx-codeql-") as temporary:
        work = Path(temporary)
        for language, suite in languages:
            database = work / f"db-{language}"
            sarif = work / f"{language}.sarif"
            _run([
                executable, "database", "create", str(database),
                f"--language={language}", f"--source-root={root}", "--overwrite",
                f"--threads={settings.codeql_threads}",
            ], settings.codeql_timeout_seconds)
            _run([
                executable, "database", "analyze", str(database), suite,
                "--format=sarif-latest", f"--output={sarif}",
                f"--threads={settings.codeql_threads}",
                f"--ram={settings.codeql_ram_mb}",
            ], settings.codeql_timeout_seconds)
            findings.extend(_sarif_findings(sarif))
    return findings, {
        "status": "ready",
        "finding_count": len(findings),
        "languages": [language for language, _ in languages],
    }
