"""Sandbox filesystem operations safe file IO within workspace boundaries.

Merged from model-tools/sandbox/filesystem.py. All operations are confined
to the session workspace; path traversal attempts are rejected.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from black_onyx_sandbox.security import resolve_workspace_path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_LIST_ENTRIES = 1000


def safe_read(workspace: Path, relative_path: str, *, offset: int = 0, limit: int = 2000) -> str:
    """Read a file from the workspace safely.

    Args:
        workspace: The session workspace root.
        relative_path: Path relative to the workspace.
        offset: Line number to start reading from (1-based).
        limit: Maximum number of lines to read.

    Returns:
        The file content as a string.

    Raises:
        PermissionError: If the path escapes the workspace.
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file exceeds MAX_FILE_SIZE.
    """
    path = resolve_workspace_path(workspace, relative_path)
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {relative_path}")
    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {path.stat().st_size} > {MAX_FILE_SIZE}")
    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    start = max(0, offset - 1)
    end = start + limit
    return "\n".join(lines[start:end])


def safe_write(workspace: Path, relative_path: str, content: str) -> Path:
    """Write content to a file in the workspace safely.

    Returns the path to the written file.
    """
    path = resolve_workspace_path(workspace, relative_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(content) > MAX_FILE_SIZE:
        raise ValueError(f"Content too large: {len(content)} > {MAX_FILE_SIZE}")
    path.write_text(content, encoding="utf-8")
    return path


def safe_list(workspace: Path, relative_path: str = ".") -> list[dict]:
    """List files in a directory within the workspace.

    Returns a list of {name, type, size} dicts.
    """
    path = resolve_workspace_path(workspace, relative_path)
    if not path.is_dir():
        raise FileNotFoundError(f"Not a directory: {relative_path}")
    entries = []
    for entry in sorted(path.iterdir())[:MAX_LIST_ENTRIES]:
        entries.append({
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size": entry.stat().st_size if entry.is_file() else 0,
        })
    return entries


def safe_delete(workspace: Path, relative_path: str) -> bool:
    """Delete a file or directory within the workspace.

    Returns True if the deletion succeeded.
    """
    path = resolve_workspace_path(workspace, relative_path)
    if not path.exists():
        return False
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    return True


def safe_copy(workspace: Path, src: str, dst: str) -> Path:
    """Copy a file within the workspace."""
    src_path = resolve_workspace_path(workspace, src)
    dst_path = resolve_workspace_path(workspace, dst)
    if not src_path.is_file():
        raise FileNotFoundError(f"Source not found: {src}")
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, dst_path)
    return dst_path


def safe_move(workspace: Path, src: str, dst: str) -> Path:
    """Move a file within the workspace."""
    src_path = resolve_workspace_path(workspace, src)
    dst_path = resolve_workspace_path(workspace, dst)
    if not src_path.exists():
        raise FileNotFoundError(f"Source not found: {src}")
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src_path), str(dst_path))
    return dst_path
