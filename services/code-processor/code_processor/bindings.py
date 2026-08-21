"""Load profile scanner/detector binding maps from repo ``profiles/bindings/``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


def _bindings_root() -> Path:
    return Path(__file__).resolve().parents[3] / "detection" / "profiles" / "bindings"


@lru_cache(maxsize=1)
def load_scanner_map() -> dict[str, list[str]]:
    path = _bindings_root() / "scanner_map.yaml"
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    scanners = raw.get("scanners") or {}
    out: dict[str, list[str]] = {}
    for key, checks in scanners.items():
        if isinstance(checks, list):
            out[str(key)] = [str(c) for c in checks if c]
    return out


@lru_cache(maxsize=1)
def load_detector_map() -> dict[str, list[str]]:
    path = _bindings_root() / "detector_map.yaml"
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    detectors = raw.get("detectors") or {}
    out: dict[str, list[str]] = {}
    for key, checks in detectors.items():
        if isinstance(checks, list):
            out[str(key)] = [str(c) for c in checks if c]
    return out


def check_ids_for_scanners(scanner_keys: list[str]) -> list[str]:
    """Resolve check_ids for scanner pack keys (e.g. ``owasp-asvs``, ``secrets-scan``)."""
    smap = load_scanner_map()
    ordered: list[str] = []
    seen: set[str] = set()
    for key in scanner_keys:
        for cid in smap.get(key) or []:
            if cid not in seen:
                seen.add(cid)
                ordered.append(cid)
    return ordered


def profile_keys_from_findings(scanner_findings: list[dict[str, Any]]) -> list[str]:
    """Infer scanner_map keys from Semgrep rule_ids / metadata profile tags."""
    keys: list[str] = []
    seen: set[str] = set()
    for finding in scanner_findings:
        meta = finding.get("metadata") or {}
        profile = meta.get("profile") if isinstance(meta, dict) else None
        if isinstance(profile, str) and profile.strip() and profile not in seen:
            seen.add(profile)
            keys.append(profile.strip())
        rule_id = str(finding.get("rule_id") or "")
        # Semgrep check_ids often look like ``owasp-asvs-eval-use`` or path-prefixed.
        for pack in load_scanner_map():
            if pack in rule_id and pack not in seen:
                seen.add(pack)
                keys.append(pack)
    return keys


def compliance_from_scanner_findings(
    scanner_findings: list[dict[str, Any]],
    *,
    pack_ids: list[str] | None = None,
) -> dict[str, Any] | None:
    """Build compliance block from scanner hits via ``scanner_map.yaml``."""
    keys = profile_keys_from_findings(scanner_findings)
    check_ids = check_ids_for_scanners(keys)
    packs = list(pack_ids or [])
    for key in keys:
        if key not in packs:
            packs.append(key)
    if not check_ids and not packs:
        return None
    return {
        "profile_pack_ids": packs,
        "check_ids": check_ids,
        "surfaces": ["code", "webapp"],
        "automation": "auto",
    }
