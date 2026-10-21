"""Sandbox schemas Pydantic models for execution requests and results.

Merged from model-tools/sandbox/schemas.py. These models are used by the
runner service and the sandbox client to validate requests and responses.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ExecutionRequest(BaseModel):
    """Request to execute a command in the sandbox."""
    model_config = ConfigDict(extra="forbid", strict=True)

    session: str = Field(pattern=r"^[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    tool: str = Field(min_length=1, max_length=64)
    command: str = Field(min_length=1, max_length=100_000)
    timeout: int = Field(ge=1, le=300, default=30)
    environment: dict[str, str] = Field(default_factory=dict, max_length=4)
    network_profile: Literal["offline", "public", "lab"] = "offline"
    destinations: list[str] = Field(default_factory=list, max_length=100)


class ExecutionResult(BaseModel):
    """Result of a sandbox execution."""
    model_config = ConfigDict(extra="forbid")

    status: Literal["success", "error", "timeout"] = "success"
    output: str = Field(default="", max_length=50_000)
    returncode: int = 0
    duration_s: float = 0.0
    tool: str = ""
    session: str = ""


class FileReadRequest(BaseModel):
    """Request to read a file from the sandbox workspace."""
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    offset: int = Field(ge=1, default=1)
    limit: int = Field(ge=1, le=10_000, default=2000)


class FileWriteRequest(BaseModel):
    """Request to write a file to the sandbox workspace."""
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(min_length=0, max_length=10_485_760)  # 10 MB


class FileListRequest(BaseModel):
    """Request to list files in the sandbox workspace."""
    model_config = ConfigDict(extra="forbid")

    path: str = Field(default=".", max_length=1024)


class ToolDefinition(BaseModel):
    """Definition of a sandbox tool."""
    model_config = ConfigDict(extra="allow")

    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    category: str = ""
    tier: str = "read"
    parameters: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Health check response."""
    model_config = ConfigDict(extra="forbid")

    status: str = "ok"
    version: str = ""
    sandbox_image: str = ""
    active_sessions: int = 0
