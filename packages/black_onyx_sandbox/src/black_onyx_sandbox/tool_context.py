"""Sandbox tool context execution context passed to tool handlers.

Merged from model-tools/sandbox/tool_context.py. Provides a ToolContext
that gives tool handlers access to the workspace, session, principal,
and approved tools without exposing the full runner state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolContext:
    """Execution context for a sandbox tool invocation.

    Encapsulates the workspace, session identity, principal, and
    approved tools so that tool handlers don't need direct access to
    the runner or gateway internals.
    """

    workspace: Path
    session: str
    principal: str
    approved_tools: set[str] = field(default_factory=set)
    network_profile: str = "offline"
    destinations: list[str] = field(default_factory=list)
    timeout: int = 30
    environment: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_approved(self, tool_name: str) -> bool:
        """Check if a tool is in the approved set."""
        return tool_name in self.approved_tools

    def workspace_path(self, relative_path: str) -> Path:
        """Resolve a path relative to the workspace (with traversal protection)."""
        from black_onyx_sandbox.security import resolve_workspace_path
        return resolve_workspace_path(self.workspace, relative_path)

    def read_file(self, relative_path: str, *, offset: int = 0, limit: int = 2000) -> str:
        """Read a file from the workspace."""
        from black_onyx_sandbox.filesystem import safe_read
        return safe_read(self.workspace, relative_path, offset=offset, limit=limit)

    def write_file(self, relative_path: str, content: str) -> Path:
        """Write a file to the workspace."""
        from black_onyx_sandbox.filesystem import safe_write
        return safe_write(self.workspace, relative_path, content)

    def list_files(self, relative_path: str = ".") -> list[dict]:
        """List files in a directory."""
        from black_onyx_sandbox.filesystem import safe_list
        return safe_list(self.workspace, relative_path)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict for logging (excludes sensitive data)."""
        return {
            "session": self.session,
            "principal": self.principal,
            "network_profile": self.network_profile,
            "timeout": self.timeout,
            "approved_tools": sorted(self.approved_tools),
            "workspace": str(self.workspace),
        }
