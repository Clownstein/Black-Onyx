"""Log raw event payload models (platform section 5.3)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LogResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    process_name: str | None = Field(default=None, max_length=256)
    container_id: str | None = Field(default=None, max_length=256)


class LogRawEvent(BaseModel):
    """Domain fields for a raw log event (paired with the common envelope)."""

    model_config = ConfigDict(extra="forbid")

    event_type: Literal["log.raw"] = "log.raw"
    severity: str = Field(min_length=1, max_length=64)
    facility: str | None = Field(default=None, max_length=128)
    logger: str | None = Field(default=None, max_length=256)
    message: str = Field(min_length=1)
    structured: dict[str, Any] = Field(default_factory=dict)
    resource: LogResource | None = None
