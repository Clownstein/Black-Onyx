"""Sandbox quotas enforce resource limits per session and principal.

Merged from model-tools/sandbox/quota.py. Tracks execution time, output
size, and concurrent sessions to prevent resource exhaustion.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from threading import RLock


@dataclass
class QuotaUsage:
    """Current quota usage for a session."""
    executions: int = 0
    total_output_bytes: int = 0
    total_time_seconds: float = 0.0
    last_execution: float = 0.0


class QuotaManager:
    """Track and enforce quotas per session."""

    def __init__(
        self,
        *,
        max_executions: int = 100,
        max_output_bytes: int = 50 * 1024 * 1024,
        max_concurrent: int = 4,
    ) -> None:
        self.max_executions = max_executions
        self.max_output_bytes = max_output_bytes
        self.max_concurrent = max_concurrent
        self._usage: dict[str, QuotaUsage] = {}
        self._active: dict[str, int] = {}
        self._lock = RLock()

    def check(self, session: str) -> None:
        """Check if a session can start a new execution. Raises if quota exceeded."""
        with self._lock:
            usage = self._usage.get(session, QuotaUsage())
            if usage.executions >= self.max_executions:
                raise RuntimeError(f"Execution quota exceeded for session {session}")
            if usage.total_output_bytes >= self.max_output_bytes:
                raise RuntimeError(f"Output quota exceeded for session {session}")
            if self._active.get(session, 0) >= self.max_concurrent:
                raise RuntimeError(f"Concurrent execution limit reached for session {session}")

    def acquire(self, session: str) -> None:
        """Mark an execution as started."""
        with self._lock:
            self.check(session)
            self._active[session] = self._active.get(session, 0) + 1
            if session not in self._usage:
                self._usage[session] = QuotaUsage()

    def release(self, session: str, *, output_bytes: int, duration: float) -> None:
        """Mark an execution as completed and record usage."""
        with self._lock:
            self._active[session] = max(0, self._active.get(session, 0) - 1)
            usage = self._usage.get(session, QuotaUsage())
            usage.executions += 1
            usage.total_output_bytes += output_bytes
            usage.total_time_seconds += duration
            usage.last_execution = time.time()
            self._usage[session] = usage

    def usage(self, session: str) -> QuotaUsage:
        """Get current quota usage for a session."""
        with self._lock:
            return self._usage.get(session, QuotaUsage())

    def reset(self, session: str) -> None:
        """Reset quota for a session (e.g. after cleanup)."""
        with self._lock:
            self._usage.pop(session, None)
            self._active.pop(session, None)

    def active_count(self, session: str) -> int:
        """Get the number of active executions for a session."""
        with self._lock:
            return self._active.get(session, 0)
