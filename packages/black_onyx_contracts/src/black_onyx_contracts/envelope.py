"""Common event envelope Pydantic models and JSON Schema helpers."""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from ulid import ULID

ULID_PATTERN = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
SCHEMA_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")
EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")

SUPPORTED_MAJOR_SCHEMA_VERSION = 1


_SCHEMA_RELPATH = Path("contracts") / "common" / "event_envelope.schema.json"


def _repo_contracts_root() -> Path:
    """Locate contracts/common relative to this package or the monorepo root.

    Walks up from both the installed module and the working directory, because
    `contracts/` sits at the repository root while callers run from anywhere in
    the monorepo (e.g. `detection/`) and the package may be installed into a
    venv, where its own parents point into site-packages rather than the repo.
    """
    here = Path(__file__).resolve()
    roots = [here, *here.parents, Path.cwd().resolve(), *Path.cwd().resolve().parents]
    seen: set[Path] = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        candidate = root / _SCHEMA_RELPATH
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "event_envelope.schema.json not found; run from the monorepo root or install with contracts present"
    )


class SourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str = Field(min_length=1, max_length=256)
    source_type: str = Field(min_length=1, max_length=128)


class AssetRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=256)
    service_id: str | None = Field(default=None, max_length=256)
    environment: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=128)


class TraceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str | None = Field(default=None, max_length=128)
    span_id: str | None = Field(default=None, max_length=128)


class EventEnvelope(BaseModel):
    """Common envelope required on every platform event."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    event_id: str
    event_type: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str | None = Field(default=None, max_length=128)
    occurred_at: datetime
    ingested_at: datetime
    source: SourceRef
    asset: AssetRef
    trace: TraceRef | None = None
    labels: dict[str, str] | None = None
    extensions: dict[str, Any] | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema_version(cls, value: str) -> str:
        if not SCHEMA_VERSION_PATTERN.match(value):
            raise ValueError("schema_version must be major.minor")
        major = int(value.split(".", 1)[0])
        if major != SUPPORTED_MAJOR_SCHEMA_VERSION:
            raise ValueError(f"unsupported major schema version: {major}")
        return value

    @field_validator("event_id")
    @classmethod
    def _event_id(cls, value: str) -> str:
        if not ULID_PATTERN.match(value):
            raise ValueError("event_id must be a ULID")
        # Ensure Crockford alphabet parses as a ULID
        ULID.from_str(value)
        return value

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, value: str) -> str:
        if not EVENT_TYPE_PATTERN.match(value):
            raise ValueError("event_type must match [a-z][a-z0-9_.-]*")
        return value


@lru_cache(maxsize=1)
def load_envelope_schema() -> dict[str, Any]:
    path = _repo_contracts_root()
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_envelope_dict(payload: dict[str, Any]) -> EventEnvelope:
    """Validate via Pydantic (canonical). JSON Schema is exercised in contract tests."""
    return EventEnvelope.model_validate(payload)
