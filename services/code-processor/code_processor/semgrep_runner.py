"""Compatibility exports; prefer ``code_processor.scanners``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from code_processor.scanners import (
    run_configured_semgrep,
    run_heuristic_scan,
    scan_path_or_noop,
    scanner_findings_structure,
)


def run_semgrep(target_dir: Path) -> list[dict[str, Any]]:
    return run_configured_semgrep([target_dir])


__all__ = [
    "run_semgrep",
    "run_heuristic_scan",
    "scan_path_or_noop",
    "scanner_findings_structure",
]
