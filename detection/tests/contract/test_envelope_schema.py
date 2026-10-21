from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

# contracts/ lives at the repository root, not under detection/.
REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "contracts" / "common" / "event_envelope.schema.json"
EXAMPLE_PATH = REPO_ROOT / "contracts" / "common" / "examples" / "valid_envelope.json"


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_valid_envelope_matches_schema() -> None:
    schema = _load_json(SCHEMA_PATH)
    example = _load_json(EXAMPLE_PATH)
    jsonschema.validate(instance=example, schema=schema)


def test_missing_tenant_id_rejected() -> None:
    schema = _load_json(SCHEMA_PATH)
    example = _load_json(EXAMPLE_PATH)
    invalid = dict(example)
    invalid.pop("tenant_id", None)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid, schema=schema)
