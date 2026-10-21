from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from black_onyx_contracts import EventEnvelope, load_envelope_schema, validate_envelope_dict

# contracts/ lives at the repository root, not under detection/.
ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "contracts" / "common" / "event_envelope.schema.json"
EXAMPLE_PATH = ROOT / "contracts" / "common" / "examples" / "valid_envelope.json"


@pytest.fixture(scope="module")
def schema() -> dict:
    return load_envelope_schema()


@pytest.fixture(scope="module")
def sample() -> dict:
    with EXAMPLE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_schema_file_exists() -> None:
    assert SCHEMA_PATH.is_file()


def test_sample_matches_json_schema(schema: dict, sample: dict) -> None:
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(sample)


def test_sample_matches_pydantic(sample: dict) -> None:
    envelope = validate_envelope_dict(sample)
    assert isinstance(envelope, EventEnvelope)
    assert envelope.tenant_id == "tenant-acme"
    assert envelope.event_id == "01J3T5C0RB6GCYKAT1BFRX7A3Q"


def test_rejects_bad_event_id(sample: dict) -> None:
    bad = deepcopy(sample)
    bad["event_id"] = "not-a-ulid"
    with pytest.raises(Exception):
        validate_envelope_dict(bad)


def test_rejects_unsupported_major_version(sample: dict) -> None:
    bad = deepcopy(sample)
    bad["schema_version"] = "2.0"
    with pytest.raises(Exception):
        validate_envelope_dict(bad)
