"""Load and merge security profile packs from the repo ``profiles/`` tree."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
AUTOMATION_RANK = {"manual": 0, "hybrid": 1, "auto": 2}


def _repo_profiles_root() -> Path:
    """Resolve the security profiles directory without assuming a fixed depth.

    Prefer ``SECURITY_PROFILES_ROOT`` (set in the container image). Otherwise walk
    ancestors of this file looking for a ``profiles/`` directory, then fall back
    to cwd-relative locations and the in-image copy at ``/app/profiles``.
    """
    env_root = (os.environ.get("SECURITY_PROFILES_ROOT") or "").strip()
    if env_root:
        env_path = Path(env_root)
        if env_path.is_dir():
            return env_path

    def _looks_like_data_root(path: Path) -> bool:
        # Distinguish the pack data tree from this Python package, which is
        # also named ``profiles`` (app/profiles) and shadows it in the walk.
        return path.is_dir() and ((path / "packs").is_dir() or (path / "presets.yaml").is_file())

    here = Path(__file__).resolve()
    candidates: list[Path] = []
    for parent in here.parents:
        candidates.append(parent / "profiles")
        candidates.append(parent / "detection" / "profiles")
    candidates.extend(
        [
            Path.cwd() / "profiles",
            Path.cwd().parent / "profiles",
            Path("/app/profiles"),
        ]
    )
    for c in candidates:
        if _looks_like_data_root(c):
            return c
    return candidates[0] if candidates else Path("/app/profiles")


@dataclass
class Check:
    check_id: str
    title: str
    surfaces: list[str]
    automation: str
    severity_default: str = "medium"
    mitre_techniques: list[str] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)
    bindings: dict[str, Any] = field(default_factory=dict)
    pack_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "surfaces": list(self.surfaces),
            "automation": self.automation,
            "severity_default": self.severity_default,
            "mitre_techniques": list(self.mitre_techniques),
            "evidence_types": list(self.evidence_types),
            "bindings": dict(self.bindings),
            "pack_ids": list(self.pack_ids),
        }


@dataclass
class Pack:
    pack_id: str
    kind: str
    version: str
    title: str
    description: str = ""
    extends_surfaces: list[str] = field(default_factory=list)
    recommended_backbone: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "kind": self.kind,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "extends_surfaces": list(self.extends_surfaces),
            "recommended_backbone": list(self.recommended_backbone),
            "checks": [c.to_dict() for c in self.checks],
            "check_count": len(self.checks),
        }


@dataclass
class ResolvedProfile:
    selected_packs: list[str]
    checks: list[Check]
    detectors: set[str] = field(default_factory=set)
    scanners: set[str] = field(default_factory=set)
    surfaces: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_packs": list(self.selected_packs),
            "checks": [c.to_dict() for c in self.checks],
            "detectors": sorted(self.detectors),
            "scanners": sorted(self.scanners),
            "surfaces": sorted(self.surfaces),
            "auto_count": sum(1 for c in self.checks if c.automation == "auto"),
            "manual_count": sum(1 for c in self.checks if c.automation == "manual"),
            "hybrid_count": sum(1 for c in self.checks if c.automation == "hybrid"),
        }


def _parse_check(raw: dict[str, Any], pack_id: str) -> Check:
    return Check(
        check_id=str(raw["check_id"]),
        title=str(raw["title"]),
        surfaces=[str(s) for s in (raw.get("surfaces") or [])],
        automation=str(raw.get("automation") or "manual"),
        severity_default=str(raw.get("severity_default") or "medium"),
        mitre_techniques=[str(t) for t in (raw.get("mitre_techniques") or [])],
        evidence_types=[str(e) for e in (raw.get("evidence_types") or [])],
        bindings=dict(raw.get("bindings") or {}),
        pack_ids=[pack_id],
    )


def _parse_pack(raw: dict[str, Any]) -> Pack:
    pack_id = str(raw["pack_id"])
    return Pack(
        pack_id=pack_id,
        kind=str(raw.get("kind") or "framework"),
        version=str(raw.get("version") or "1.0"),
        title=str(raw.get("title") or pack_id),
        description=str(raw.get("description") or ""),
        extends_surfaces=[str(s) for s in (raw.get("extends_surfaces") or [])],
        recommended_backbone=[str(p) for p in (raw.get("recommended_backbone") or [])],
        checks=[_parse_check(c, pack_id) for c in (raw.get("checks") or [])],
    )


@lru_cache(maxsize=1)
def load_all_packs(profiles_root: str | None = None) -> dict[str, Pack]:
    root = Path(profiles_root) if profiles_root else _repo_profiles_root()
    packs: dict[str, Pack] = {}
    for sub in ("packs/frameworks", "packs/industries", "packs/certification", "surfaces"):
        d = root / sub
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict) or "pack_id" not in data:
                continue
            pack = _parse_pack(data)
            packs[pack.pack_id] = pack
    return packs


def load_presets(profiles_root: str | None = None) -> list[dict[str, Any]]:
    root = Path(profiles_root) if profiles_root else _repo_profiles_root()
    path = root / "presets.yaml"
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(data.get("presets") or [])


def _merge_check(existing: Check, incoming: Check) -> Check:
    sev = existing.severity_default
    if SEVERITY_RANK.get(incoming.severity_default, 0) > SEVERITY_RANK.get(sev, 0):
        sev = incoming.severity_default
    auto = existing.automation
    if AUTOMATION_RANK.get(incoming.automation, 0) > AUTOMATION_RANK.get(auto, 0):
        auto = incoming.automation
    surfaces = sorted(set(existing.surfaces) | set(incoming.surfaces))
    mitre = sorted(set(existing.mitre_techniques) | set(incoming.mitre_techniques))
    evidence = sorted(set(existing.evidence_types) | set(incoming.evidence_types))
    bindings = dict(existing.bindings)
    for key, val in incoming.bindings.items():
        if isinstance(val, list):
            bindings[key] = sorted(set(list(bindings.get(key) or []) + list(val)))
        else:
            bindings[key] = val
    pack_ids = sorted(set(existing.pack_ids) | set(incoming.pack_ids))
    return Check(
        check_id=existing.check_id,
        title=existing.title or incoming.title,
        surfaces=surfaces,
        automation=auto,
        severity_default=sev,
        mitre_techniques=mitre,
        evidence_types=evidence,
        bindings=bindings,
        pack_ids=pack_ids,
    )


def merge_packs(
    pack_ids: list[str],
    *,
    enabled_surfaces: list[str] | None = None,
    profiles_root: str | None = None,
) -> ResolvedProfile:
    """Union packs with strictest-wins severity/automation; industry additive."""
    catalog = load_all_packs(profiles_root)
    by_id: dict[str, Check] = {}
    selected: list[str] = []
    for pid in pack_ids:
        pack = catalog.get(pid)
        if pack is None:
            continue
        selected.append(pid)
        for chk in pack.checks:
            if enabled_surfaces and not (set(chk.surfaces) & set(enabled_surfaces)):
                continue
            if chk.check_id in by_id:
                by_id[chk.check_id] = _merge_check(by_id[chk.check_id], chk)
            else:
                by_id[chk.check_id] = Check(
                    check_id=chk.check_id,
                    title=chk.title,
                    surfaces=list(chk.surfaces),
                    automation=chk.automation,
                    severity_default=chk.severity_default,
                    mitre_techniques=list(chk.mitre_techniques),
                    evidence_types=list(chk.evidence_types),
                    bindings=dict(chk.bindings),
                    pack_ids=list(chk.pack_ids),
                )

    detectors: set[str] = set()
    scanners: set[str] = set()
    surfaces: set[str] = set()
    for chk in by_id.values():
        surfaces.update(chk.surfaces)
        detectors.update(chk.bindings.get("detectors") or [])
        scanners.update(chk.bindings.get("scanners") or [])

    checks = sorted(by_id.values(), key=lambda c: c.check_id)
    return ResolvedProfile(
        selected_packs=selected,
        checks=checks,
        detectors=detectors,
        scanners=scanners,
        surfaces=surfaces,
    )


def semgrep_dirs_for_scanners(scanners: set[str] | list[str]) -> list[str]:
    """Map scanner ids to relative Semgrep rule directories under scanners/semgrep/rules/profiles/."""
    mapping = {
        "owasp-asvs": "profiles/owasp-asvs",
        "pci-dss": "profiles/pci-dss",
        "cis-appsec": "profiles/cis-appsec",
        "saas-tenant": "profiles/saas-tenant",
        "secrets-scan": "profiles/secrets-scan",
        "owasp-injection": "profiles/owasp-asvs",
    }
    out: list[str] = []
    for s in scanners:
        rel = mapping.get(s)
        if rel and rel not in out:
            out.append(rel)
    return out
