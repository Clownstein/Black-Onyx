"""Invoke Antares CLI via subprocess (never import antares into this service)."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from code_enrichment_worker.config import settings

logger = logging.getLogger(__name__)


def _pythonpath_for_cli() -> str:
    src = Path(settings.antares_cli_src)
    existing = os.environ.get("PYTHONPATH", "")
    parts = [str(src)]
    if existing:
        parts.append(existing)
    return os.pathsep.join(parts)


def _antares_base_cmd() -> list[str]:
    """Prefer installed ``antares``; else ``python -m antares_cli`` with PYTHONPATH."""
    which = shutil.which("antares")
    if which:
        return [which]
    return ["python", "-m", "antares_cli"]


def run_antares(
    args: list[str],
    *,
    stdin_payload: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Run an Antares CLI command and parse JSON stdout when possible."""
    cmd = [*_antares_base_cmd(), *args]
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath_for_cli()
    if settings.antares_endpoint:
        env["ANTARES_ENDPOINT"] = settings.antares_endpoint
    if settings.antares_api_key:
        env["ANTARES_API_KEY"] = settings.antares_api_key

    stdin_text = None
    if stdin_payload is not None:
        stdin_text = json.dumps(stdin_payload)

    logger.info("antares invoke: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout if timeout is not None else settings.antares_timeout_seconds,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "exit_code": 127,
            "error": f"antares binary/python missing: {exc}",
            "stdout": "",
            "stderr": str(exc),
            "data": None,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "exit_code": 124,
            "error": "antares timed out",
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "data": None,
        }

    data: Any = None
    stdout = proc.stdout or ""
    if stdout.strip():
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            data = None

    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "error": None if proc.returncode == 0 else (proc.stderr or "antares failed"),
        "stdout": stdout,
        "stderr": proc.stderr or "",
        "data": data,
    }


def run_plan(target: str) -> dict[str, Any]:
    """``antares plan PATH --format json`` — local CWE selection without model inference."""
    return run_antares(["plan", target, "--format", "json"])


def run_tool_query(target: str, cwe_ids: list[str]) -> dict[str, Any]:
    """``antares tool query --stdin`` with explicit CWEs."""
    payload = {
        "target": target,
        "cwe_ids": cwe_ids,
        "tool_budget": settings.antares_tool_budget,
    }
    if settings.antares_endpoint:
        payload["endpoint"] = settings.antares_endpoint
    if settings.antares_api_key:
        payload["api_key"] = settings.antares_api_key
    return run_antares(["tool", "query", "--stdin"], stdin_payload=payload)


def run_tool_sweep(target: str, *, max_cwes: int = 20) -> dict[str, Any]:
    """``antares tool sweep --stdin`` multi-CWE selection + investigation."""
    payload: dict[str, Any] = {
        "target": target,
        "workers": 2,
        "selection": {"scope": "owasp", "cwe_level": "base", "max_cwes": max_cwes},
        "tool_budget": settings.antares_tool_budget,
    }
    if settings.antares_endpoint:
        payload["endpoint"] = settings.antares_endpoint
    if settings.antares_api_key:
        payload["api_key"] = settings.antares_api_key
    return run_antares(["tool", "sweep", "--stdin"], stdin_payload=payload)
