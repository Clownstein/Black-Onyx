"""Suricata EVE alert models (contracts/network/suricata_alert.schema.json)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class SuricataAlertDetail(BaseModel):
    """Nested Suricata ``alert`` object."""

    model_config = ConfigDict(extra="allow")

    action: str | None = None
    gid: int | None = None
    signature_id: int
    rev: int | None = None
    signature: str = Field(min_length=1)
    category: str | None = None
    severity: int = Field(ge=1, le=4)
    metadata: dict[str, Any] | None = None


class SuricataAlert(BaseModel):
    """Suricata EVE alert record for IDS ingest / ids-processor."""

    model_config = ConfigDict(extra="allow")

    event_type: Literal["suricata.alert"] = "suricata.alert"
    timestamp: str | None = None
    flow_id: int | str | None = None
    community_id: str | None = None
    src_ip_hash: str | None = None
    dest_ip_hash: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    proto: str | None = None
    sensor_id: str | None = None
    asset_id: str | None = None
    alert: SuricataAlertDetail
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
