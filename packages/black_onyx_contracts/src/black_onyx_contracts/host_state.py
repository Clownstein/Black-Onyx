"""Host-state modality models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

HostStateEventType = Literal[
    "host_state.process_snapshot",
    "host_state.process_event",
    "host_state.socket_snapshot",
    "host_state.autorun_snapshot",
    "host_state.user_session",
]
OsFamily = Literal["linux", "windows", "darwin", "unknown"]


class HostProcess(BaseModel):
    """Process block for host-state events (parent fields used by rules)."""

    model_config = ConfigDict(extra="allow")

    pid: int | None = None
    ppid: int | None = None
    name: str | None = None
    path: str | None = None
    cmdline: str | None = None
    user: str | None = None
    parent_name: str | None = None
    parent_path: str | None = None
    hashes: dict[str, str] | None = None
    action: Literal["create", "terminate", "open"] | None = None


class HostStateEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_type: HostStateEventType
    tenant_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    service_id: str | None = None
    occurred_at: datetime
    hostname: str | None = None
    os_family: OsFamily | None = None
    process: HostProcess | dict[str, Any] | None = None
    socket: dict[str, Any] | None = None
    autorun: dict[str, Any] | None = None
    session: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None


class HostStateFeatures(BaseModel):
    """Feature record published to host-state.features."""

    model_config = ConfigDict(extra="allow")

    event_type: str = "host_state.features"
    tenant_id: str
    asset_id: str
    service_id: str | None = None
    window_start: datetime
    window_end: datetime
    feature_version: str = "host-state.features.v1"
    process_events: list[dict[str, Any]] = Field(default_factory=list)
    detections: list[dict[str, Any]] = Field(default_factory=list)
    event_count: int = 0
