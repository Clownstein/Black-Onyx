"""Threat intelligence indicator and match models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ObservableType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "file_hash",
    "email",
    "ja3",
    "cve",
]
TlpLevel = Literal["white", "green", "amber", "red", "clear"]


class ThreatIntelIndicator(BaseModel):
    model_config = ConfigDict(extra="allow")

    indicator_id: str = Field(min_length=1)
    tenant_id: str | None = None
    observable_type: ObservableType
    observable_value: str = Field(min_length=1)
    pattern: str | None = None
    source: str = Field(min_length=1)
    confidence: int = Field(ge=0, le=100)
    tlp: TlpLevel | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    labels: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    external_refs: list[dict[str, Any]] = Field(default_factory=list)
    raw_stix: dict[str, Any] | None = None


class ThreatIntelMatch(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    value: str
    confidence: int = Field(ge=0, le=100)
    source: str
    tlp: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)


class ThreatIntelMatchResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    matches: list[ThreatIntelMatch] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    tlp: str | None = None
