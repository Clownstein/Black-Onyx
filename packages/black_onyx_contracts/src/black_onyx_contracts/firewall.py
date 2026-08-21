"""Firewall event models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

FirewallEventType = Literal["firewall.traffic", "firewall.rule_change"]
FirewallAction = Literal[
    "allow",
    "deny",
    "drop",
    "reject",
    "rule_add",
    "rule_delete",
    "rule_modify",
]


class FirewallEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_type: FirewallEventType
    tenant_id: str = Field(min_length=1)
    asset_id: str | None = None
    occurred_at: datetime
    vendor: str | None = None
    action: FirewallAction
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    rule_id: str | None = None
    interface: str | None = None
    message: str | None = None
    raw: dict[str, Any] | None = None
