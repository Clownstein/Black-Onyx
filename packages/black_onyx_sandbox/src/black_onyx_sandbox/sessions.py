"""Sandbox session management workspace isolation and lifecycle.

Merged from model-tools/sandbox/sessions.py. Each session is an isolated
directory under the sessions root, identified by a sha256(principal)/session_id
path. Sessions are created on demand and cleaned up after a TTL.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Session path pattern: sha256(principal)/session_id
SESSION_PATH_PATTERN = r"^[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
SESSION_TTL_SECONDS = 3600  # 1 hour
MAX_SESSIONS_PER_PRINCIPAL = 10


def session_path(sessions_root: Path, principal: str, session_id: str) -> Path:
    """Compute the workspace path for a session.

    Args:
        sessions_root: Root directory for all sessions.
        principal: The principal identity (user_id or token prefix).
        session_id: The session identifier.

    Returns:
        The resolved workspace path.

    Raises:
        ValueError: If session_id contains path traversal characters.
    """
    if not session_id or "/" in session_id or "\\" in session_id:
        raise ValueError(f"Invalid session_id: {session_id}")
    if session_id in {".", ".."}:
        raise ValueError(f"Invalid session_id: {session_id}")
    principal_hash = hashlib.sha256(principal.encode()).hexdigest()
    return sessions_root / principal_hash / session_id


def create_session(sessions_root: Path, principal: str, session_id: str) -> Path:
    """Create a new session workspace directory.

    Returns the path to the created directory. If the directory already
    exists, it is returned as-is (idempotent).
    """
    path = session_path(sessions_root, principal, session_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_session_path(sessions_root: Path, session: str) -> Path:
    """Validate a full session path string (principal_hash/session_id).

    Returns the resolved path if valid. Raises ValueError if the path
    contains traversal characters or doesn't match the expected pattern.
    """
    import re

    if not re.match(SESSION_PATH_PATTERN, session):
        raise ValueError(f"Invalid session path: {session}")
    parts = session.split("/")
    resolved = sessions_root / parts[0] / parts[1]
    # Verify no symlink escape
    if resolved.is_symlink():
        raise ValueError(f"Session path is a symlink: {resolved}")
    return resolved


def cleanup_expired_sessions(sessions_root: Path, ttl: int = SESSION_TTL_SECONDS) -> int:
    """Remove session directories older than ttl seconds.

    Returns the number of sessions removed.
    """
    if not sessions_root.is_dir():
        return 0
    now = time.time()
    removed = 0
    for principal_dir in sessions_root.iterdir():
        if not principal_dir.is_dir():
            continue
        for session_dir in principal_dir.iterdir():
            if not session_dir.is_dir():
                continue
            mtime = session_dir.stat().st_mtime
            if now - mtime > ttl:
                shutil.rmtree(session_dir, ignore_errors=True)
                removed += 1
    return removed


def count_sessions(sessions_root: Path, principal: str) -> int:
    """Count active sessions for a principal."""
    principal_hash = hashlib.sha256(principal.encode()).hexdigest()
    principal_dir = sessions_root / principal_hash
    if not principal_dir.is_dir():
        return 0
    return sum(1 for d in principal_dir.iterdir() if d.is_dir())
