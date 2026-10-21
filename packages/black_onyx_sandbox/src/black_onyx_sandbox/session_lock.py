"""Sandbox session locking prevent concurrent modifications to a session.

Merged from model-tools/sandbox/session_lock.py. Uses file-based locks to
prevent race conditions when multiple tool executions target the same
session workspace.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

LOCK_TIMEOUT_SECONDS = 30
LOCK_POLL_INTERVAL = 0.1


class SessionLock:
    """File-based lock for a session workspace.

    Uses an atomic create-and-exclusive-open pattern to prevent concurrent
    modifications. On non-POSIX systems, falls back to a directory-based lock.
    """

    def __init__(self, workspace: Path, *, timeout: float = LOCK_TIMEOUT_SECONDS) -> None:
        self._workspace = workspace
        self._lock_path = workspace / ".lock"
        self._timeout = timeout
        self._fd: Any = None
        self._acquired = False

    def acquire(self) -> bool:
        """Acquire the lock. Returns True if acquired, False on timeout."""
        deadline = time.time() + self._timeout
        self._workspace.mkdir(parents=True, exist_ok=True)
        while time.time() < deadline:
            try:
                if os.name == "posix":
                    import fcntl
                    self._fd = open(self._lock_path, "w")
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._fd.write(str(os.getpid()))
                    self._fd.flush()
                else:
                    # Directory-based lock on non-POSIX
                    if self._lock_path.exists():
                        time.sleep(LOCK_POLL_INTERVAL)
                        continue
                    self._lock_path.mkdir()
                self._acquired = True
                return True
            except (OSError, IOError):
                if self._fd:
                    self._fd.close()
                    self._fd = None
                time.sleep(LOCK_POLL_INTERVAL)
        logger.warning("Session lock timeout for %s", self._workspace)
        return False

    def release(self) -> None:
        """Release the lock."""
        if not self._acquired:
            return
        try:
            if os.name == "posix" and self._fd:
                import fcntl
                fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
                self._fd.close()
            else:
                if self._lock_path.exists():
                    self._lock_path.rmdir()
        except (OSError, IOError) as exc:
            logger.warning("Failed to release session lock: %s", exc)
        finally:
            self._fd = None
            self._acquired = False

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()

    @property
    def is_acquired(self) -> bool:
        return self._acquired
