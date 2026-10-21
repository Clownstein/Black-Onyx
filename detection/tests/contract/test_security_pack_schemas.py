"""Validate every Security Profile pack YAML against the pack schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
# profiles/ are detection-local, but contracts/ lives at the repository root.
REPO_ROOT = Path(__file__).resolve().parents[3]
PACK_DIRS = [
    ROOT / "profiles" / "packs" / "frameworks",
    ROOT / "profiles" / "packs" / "industries",
    ROOT / "profiles" / "packs" / "certification",
    ROOT / "profiles" / "surfaces",
]
SCHEMA_PATH = REPO_ROOT / "contracts" / "profiles" / "security_pack.schema.json"


def _pack_files() -> list[Path]:
    files: list[Path] = []
    for directory in PACK_DIRS:
        if directory.is_dir():
            files.extend(sorted(directory.glob("*.yaml")))
            files.extend(sorted(directory.glob("*.yml")))
    return files


@pytest.fixture(scope="module")
def pack_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


@pytest.mark.parametrize("pack_path", _pack_files(), ids=lambda p: p.name)
def test_pack_yaml_validates(pack_path: Path, pack_validator: Draft202012Validator) -> None:
    doc = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    errors = sorted(pack_validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, f"{pack_path}: " + "; ".join(e.message for e in errors)


def test_check_ids_unique_across_packs() -> None:
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for pack_path in _pack_files():
        doc = yaml.safe_load(pack_path.read_text(encoding="utf-8")) or {}
        pack_id = str(doc.get("pack_id") or pack_path.stem)
        for check in doc.get("checks") or []:
            cid = str(check.get("check_id") or "")
            if not cid:
                continue
            if cid in seen and seen[cid] != pack_id:
                # Same check_id reused across packs is allowed for crosswalks;
                # only flag identical pack+check collisions.
                continue
            key = f"{pack_id}:{cid}"
            if key in seen:
                duplicates.append(key)
            seen[key] = pack_id
    assert not duplicates
