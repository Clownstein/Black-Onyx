"""Sandboxed command execution engine.

Merged from model-tools/sandbox/executor.py, adapted to dispatch to the
security-runner service over HTTP (runner mode) or run locally (subprocess
mode for development). Docker and Firecracker modes are delegated to the
runner service which owns the Docker socket.

Modes:
  - 'runner' (default): authenticated HTTP call to services/security-runner/
  - 'subprocess': local child process with resource limits (dev only,
    requires ALLOW_UNSANDBOXED_SUBPROCESS=true)
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import httpx

from black_onyx_sandbox.security import redact_command_for_audit

logger = logging.getLogger(__name__)

try:
    import resource  # Unix only; used for subprocess limits
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

DEFAULT_TIMEOUT_S = 30
DEFAULT_MAX_OUTPUT_CHARS = 50_000
DEFAULT_MAX_CPU_S = 60
DEFAULT_MAX_MEMORY_MB = 1024
DEFAULT_MAX_PROCESSES = 50


@dataclass
class ExecutionResult:
    """Result of a sandboxed command execution."""

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False
    duration_s: float = 0.0
    command: str = ""
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "success" if self.success else "error",
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 3),
            "timed_out": self.timed_out,
            "error": self.error,
            "command": redact_command_for_audit(self.command) if self.command else "",
        }


class SandboxExecutor:
    """Execute commands in an isolated sandbox environment.

    Args:
        mode: Execution mode 'runner' (default) or 'subprocess' (dev).
        workspace: Working directory for command execution.
        timeout_s: Maximum execution time in seconds.
        max_output_chars: Maximum combined stdout+stderr output size.
        max_memory_mb: Maximum memory usage in MB (subprocess mode).
        max_cpu_s: Maximum CPU time in seconds (subprocess mode).
        max_processes: Maximum number of child processes (subprocess mode).
        runner_url: URL of the security-runner service (runner mode).
        runner_token: Bearer token for the security-runner (runner mode).
    """

    def __init__(
        self,
        mode: str = "runner",
        workspace: Optional[str] = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        max_memory_mb: int = DEFAULT_MAX_MEMORY_MB,
        max_cpu_s: int = DEFAULT_MAX_CPU_S,
        max_processes: int = DEFAULT_MAX_PROCESSES,
        runner_url: Optional[str] = None,
        runner_token: Optional[str] = None,
        env_vars: Optional[dict[str, str]] = None,
    ) -> None:
        if mode not in {"runner", "subprocess"}:
            raise ValueError(f"Unknown sandbox mode: {mode!r} (use 'runner' or 'subprocess')")
        if mode == "subprocess" and not _allow_unsandboxed_subprocess():
            raise ValueError(
                "subprocess mode requires ALLOW_UNSANDBOXED_SUBPROCESS=true "
                "and is for development only"
            )
        self.mode = mode
        self.workspace = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="sandbox_"))
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s
        self.max_output_chars = max_output_chars
        self.max_memory_mb = max_memory_mb
        self.max_cpu_s = max_cpu_s
        self.max_processes = max_processes
        self.runner_url = runner_url or os.environ.get(
            "SECURITY_RUNNER_URL", "http://security-runner:8080"
        )
        self.runner_token = runner_token or os.environ.get("SECURITY_RUNNER_TOKEN", "")
        self.env_vars = env_vars or {}
        self.env_vars.setdefault("TERM", "xterm")
        self.env_vars.setdefault("COLUMNS", "120")
        self.env_vars.setdefault("LINES", "40")
        self._cancel_event: Optional[asyncio.Event] = None
        logger.info(
            "SandboxExecutor initialized: mode=%s, workspace=%s, timeout=%ss",
            mode, self.workspace, timeout_s,
        )

    def with_workspace(self, workspace: str) -> "SandboxExecutor":
        """Clone this executor with a different workspace."""
        clone = SandboxExecutor(
            mode=self.mode,
            workspace=workspace,
            timeout_s=self.timeout_s,
            max_output_chars=self.max_output_chars,
            max_memory_mb=self.max_memory_mb,
            max_cpu_s=self.max_cpu_s,
            max_processes=self.max_processes,
            runner_url=self.runner_url,
            runner_token=self.runner_token,
            env_vars=dict(self.env_vars),
        )
        clone._cancel_event = self._cancel_event
        return clone

    def bind_cancel_event(self, event: asyncio.Event) -> None:
        """Bind an asyncio.Event used to cancel in-flight executions."""
        self._cancel_event = event

    def cancel(self) -> None:
        """Trigger the cancel event if bound."""
        if self._cancel_event is not None:
            self._cancel_event.set()

    async def execute(
        self,
        command: str,
        *,
        timeout: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
    ) -> ExecutionResult:
        """Execute a command. Dispatches to runner or subprocess based on mode."""
        effective_timeout = min(timeout or self.timeout_s, 300)
        if self.mode == "runner":
            return await self._execute_runner(
                command, timeout=effective_timeout, env=env
            )
        return await self._execute_subprocess(
            command, timeout=effective_timeout, env=env
        )

    async def _execute_runner(
        self,
        command: str,
        *,
        timeout: int,
        env: Optional[dict[str, str]],
    ) -> ExecutionResult:
        """Dispatch execution to the security-runner service over HTTP."""
        session_hash = _session_hash(self.runner_token or "anonymous")
        session = f"{session_hash}/default"
        env_items = list((env or {}).items())[:4]  # runner allows max 4 env vars
        payload: dict[str, Any] = {
            "session": session,
            "tool": "Bash",
            "command": command,
            "timeout": timeout,
            "environment": dict(env_items),
            "network_profile": "offline",
        }
        headers = {}
        if self.runner_token:
            headers["Authorization"] = f"Bearer {self.runner_token}"
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=timeout + 30.0, trust_env=False) as client:
                response = await client.post(
                    f"{self.runner_url.rstrip('/')}/execute",
                    json=payload,
                    headers=headers,
                )
            duration = time.monotonic() - started
            if response.status_code != 200:
                detail = response.text[:500]
                return ExecutionResult(
                    command=command,
                    returncode=1,
                    duration_s=duration,
                    error=f"Runner returned {response.status_code}: {detail}",
                )
            data = response.json()
            output = data.get("output", "")[: self.max_output_chars]
            return ExecutionResult(
                stdout=output,
                stderr="",
                returncode=data.get("returncode", 1),
                timed_out=data.get("timed_out", False),
                duration_s=data.get("duration_s", duration),
                command=command,
            )
        except httpx.HTTPError as exc:
            return ExecutionResult(
                command=command,
                returncode=1,
                duration_s=time.monotonic() - started,
                error=f"Runner unavailable: {type(exc).__name__}",
            )

    async def _execute_subprocess(
        self,
        command: str,
        *,
        timeout: int,
        env: Optional[dict[str, str]],
    ) -> ExecutionResult:
        """Execute locally as a child process with resource limits (dev only)."""
        started = time.monotonic()
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.workspace),
            env={**os.environ, **self.env_vars, **(env or {})},
            preexec_fn=_subprocess_limits if resource is not None else None,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            duration = time.monotonic() - started
            out = stdout.decode("utf-8", errors="replace")[: self.max_output_chars]
            err = stderr.decode("utf-8", errors="replace")[: self.max_output_chars]
            return ExecutionResult(
                stdout=out,
                stderr=err,
                returncode=proc.returncode or 0,
                duration_s=duration,
                command=command,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ExecutionResult(
                command=command,
                returncode=1,
                timed_out=True,
                duration_s=time.monotonic() - started,
                error=f"Execution timed out after {timeout}s",
            )


def _allow_unsandboxed_subprocess() -> bool:
    return (os.environ.get("ALLOW_UNSANDBOXED_SUBPROCESS") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _subprocess_limits() -> None:  # pragma: no cover - Unix only
    """Set resource limits on the child process (subprocess mode, Unix)."""
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_CPU, (DEFAULT_MAX_CPU_S, DEFAULT_MAX_CPU_S))
    resource.setrlimit(
        resource.RLIMIT_AS, (DEFAULT_MAX_MEMORY_MB * 1024 * 1024,) * 2
    )
    resource.setrlimit(resource.RLIMIT_NPROC, (DEFAULT_MAX_PROCESSES, DEFAULT_MAX_PROCESSES))


def _session_hash(token: str) -> str:
    """Derive a stable session hash from a bearer token (principal isolation)."""
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()
