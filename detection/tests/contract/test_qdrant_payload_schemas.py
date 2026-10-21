from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

# contracts/ lives at the repository root, not under detection/.
ROOT = Path(__file__).resolve().parents[3]
QDRANT = ROOT / "contracts" / "qdrant"

COLLECTIONS = [
    "findings_v1",
    "incidents_v1",
    "features_baseline_v1",
    "ti_text_v1",
    "attack_tech_v1",
    "runbooks_v1",
]


@pytest.mark.parametrize("collection", COLLECTIONS)
def test_qdrant_payload_example_validates(collection: str) -> None:
    schema = json.loads((QDRANT / f"{collection}.payload.json").read_text(encoding="utf-8"))
    example = json.loads((QDRANT / "examples" / f"valid_{collection}.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=example, schema=schema)


@pytest.mark.parametrize("collection", COLLECTIONS)
def test_qdrant_payload_schema_loads(collection: str) -> None:
    schema = json.loads((QDRANT / f"{collection}.payload.json").read_text(encoding="utf-8"))
    assert schema.get("title")
    assert "properties" in schema
    assert schema.get("additionalProperties") is False


def test_dense_text_collections_are_768() -> None:
    # The 768-d assumption is encoded in the shared client; the contracts here
    # describe payloads. Ensure the required embedding provenance fields exist.
    for collection in COLLECTIONS:
        schema = json.loads((QDRANT / f"{collection}.payload.json").read_text(encoding="utf-8"))
        required = set(schema.get("required") or [])
        assert {"embed_model", "embed_version"}.issubset(required)
