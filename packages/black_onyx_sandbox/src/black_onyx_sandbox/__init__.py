"""Sandbox execution engine merged from model-tools/sandbox/.

Provides SandboxExecutor, SSRF/target validation, workspace path resolution,
session isolation, archive validation, quotas, Landlock/bwrap confinement
helpers, safe IO, tool context, session locking, Firecracker microVM support,
runner client, and Pydantic schemas for the security tooling backend.

The Docker-owning runner service lives in services/security-runner/; this
package is the shared client-side library that builds commands, validates
targets, and enforces quotas before dispatching to the runner over HTTP.
"""
from black_onyx_sandbox.executor import SandboxExecutor, ExecutionResult
from black_onyx_sandbox.security import (
    validate_target,
    resolve_workspace_path,
    redact_command_for_audit,
)

__all__ = [
    "SandboxExecutor",
    "ExecutionResult",
    "validate_target",
    "resolve_workspace_path",
    "redact_command_for_audit",
]
