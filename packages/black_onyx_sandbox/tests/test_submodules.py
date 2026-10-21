"""Tests for black_onyx_sandbox submodules sessions, filesystem, quota, archives, schemas, safe_io, tool_context."""

from __future__ import annotations

from pathlib import Path

import pytest

from black_onyx_sandbox.sessions import (
    create_session,
    session_path,
    validate_session_path,
    count_sessions,
    cleanup_expired_sessions,
)
from black_onyx_sandbox.filesystem import (
    safe_read,
    safe_write,
    safe_list,
    safe_delete,
)
from black_onyx_sandbox.quota import QuotaManager, QuotaUsage
from black_onyx_sandbox.schemas import (
    ExecutionRequest,
    ExecutionResult,
    FileReadRequest,
    FileWriteRequest,
)
from black_onyx_sandbox.safe_io import (
    strip_ansi,
    strip_control_chars,
    sanitize_output,
    sanitize_filename,
    truncate_lines,
)
from black_onyx_sandbox.tool_context import ToolContext
from black_onyx_sandbox.session_lock import SessionLock


# ── Sessions ─────────────────────────────────────────────────────────────


def test_session_path_creates_valid_path(tmp_path: Path) -> None:
    """session_path returns a path under the sessions root."""
    path = session_path(tmp_path, "user-123", "session-1")
    assert path.parent.parent == tmp_path
    assert "session-1" in path.name


def test_session_path_rejects_traversal(tmp_path: Path) -> None:
    """session_path rejects session_ids with path separators."""
    with pytest.raises(ValueError, match="Invalid session_id"):
        session_path(tmp_path, "user", "../escape")


def test_create_session_creates_directory(tmp_path: Path) -> None:
    """create_session creates the workspace directory."""
    path = create_session(tmp_path, "user-123", "session-1")
    assert path.is_dir()


def test_create_session_idempotent(tmp_path: Path) -> None:
    """create_session is idempotent calling twice doesn't fail."""
    p1 = create_session(tmp_path, "user", "s1")
    p2 = create_session(tmp_path, "user", "s1")
    assert p1 == p2


def test_validate_session_path_valid(tmp_path: Path) -> None:
    """validate_session_path accepts a valid sha256/session_id path."""
    import hashlib
    principal_hash = hashlib.sha256(b"user").hexdigest()
    session = f"{principal_hash}/session-1"
    result = validate_session_path(tmp_path, session)
    assert result.parent.parent == tmp_path


def test_validate_session_path_rejects_invalid(tmp_path: Path) -> None:
    """validate_session_path rejects malformed paths."""
    with pytest.raises(ValueError, match="Invalid session path"):
        validate_session_path(tmp_path, "not-a-hash/session")
    with pytest.raises(ValueError, match="Invalid session path"):
        validate_session_path(tmp_path, "short/session")


def test_count_sessions(tmp_path: Path) -> None:
    """count_sessions counts active sessions for a principal."""
    assert count_sessions(tmp_path, "user") == 0
    create_session(tmp_path, "user", "s1")
    create_session(tmp_path, "user", "s2")
    assert count_sessions(tmp_path, "user") == 2


def test_cleanup_expired_sessions(tmp_path: Path) -> None:
    """cleanup_expired_sessions removes old session directories."""
    import os
    import time
    s = create_session(tmp_path, "user", "old-session")
    # Set mtime to 2 hours ago
    old_time = time.time() - 7200
    os.utime(s, (old_time, old_time))
    removed = cleanup_expired_sessions(tmp_path, ttl=3600)
    assert removed == 1
    assert not s.exists()


# ── Filesystem ────────────────────────────────────────────────────────────


def test_safe_write_and_read(tmp_path: Path) -> None:
    """safe_write then safe_read round-trips content."""
    safe_write(tmp_path, "test.txt", "hello world")
    content = safe_read(tmp_path, "test.txt")
    assert content == "hello world"


def test_safe_read_with_offset_and_limit(tmp_path: Path) -> None:
    """safe_read supports offset and limit."""
    safe_write(tmp_path, "lines.txt", "line1\nline2\nline3\nline4\nline5")
    content = safe_read(tmp_path, "lines.txt", offset=2, limit=2)
    assert "line2" in content
    assert "line3" in content
    assert "line4" not in content


def test_safe_list(tmp_path: Path) -> None:
    """safe_list returns directory entries."""
    safe_write(tmp_path, "file1.txt", "a")
    safe_write(tmp_path, "file2.txt", "b")
    (tmp_path / "subdir").mkdir()
    entries = safe_list(tmp_path)
    names = [e["name"] for e in entries]
    assert "file1.txt" in names
    assert "file2.txt" in names
    assert "subdir" in names


def test_safe_delete(tmp_path: Path) -> None:
    """safe_delete removes files."""
    safe_write(tmp_path, "to_delete.txt", "content")
    assert safe_delete(tmp_path, "to_delete.txt") is True
    assert not (tmp_path / "to_delete.txt").exists()


def test_safe_delete_nonexistent(tmp_path: Path) -> None:
    """safe_delete returns False for nonexistent files."""
    assert safe_delete(tmp_path, "nonexistent.txt") is False


def test_safe_read_nonexistent_raises(tmp_path: Path) -> None:
    """safe_read raises FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        safe_read(tmp_path, "missing.txt")


# ── Quota ─────────────────────────────────────────────────────────────────


def test_quota_acquire_and_release() -> None:
    """QuotaManager tracks executions."""
    qm = QuotaManager(max_executions=5, max_output_bytes=1024, max_concurrent=2)
    qm.acquire("session-1")
    assert qm.active_count("session-1") == 1
    qm.release("session-1", output_bytes=100, duration=1.0)
    assert qm.active_count("session-1") == 0
    usage = qm.usage("session-1")
    assert usage.executions == 1
    assert usage.total_output_bytes == 100


def test_quota_exceeds_executions() -> None:
    """QuotaManager raises when execution limit is exceeded."""
    qm = QuotaManager(max_executions=2)
    qm.acquire("s1")
    qm.release("s1", output_bytes=10, duration=1.0)
    qm.acquire("s1")
    qm.release("s1", output_bytes=10, duration=1.0)
    with pytest.raises(RuntimeError, match="Execution quota"):
        qm.acquire("s1")


def test_quota_exceeds_output() -> None:
    """QuotaManager raises when output limit is exceeded."""
    qm = QuotaManager(max_output_bytes=100)
    qm.acquire("s1")
    qm.release("s1", output_bytes=100, duration=1.0)
    with pytest.raises(RuntimeError, match="Output quota"):
        qm.acquire("s1")


def test_quota_concurrent_limit() -> None:
    """QuotaManager enforces concurrent execution limit."""
    qm = QuotaManager(max_concurrent=1)
    qm.acquire("s1")
    with pytest.raises(RuntimeError, match="Concurrent"):
        qm.acquire("s1")


def test_quota_reset() -> None:
    """reset clears quota for a session."""
    qm = QuotaManager()
    qm.acquire("s1")
    qm.release("s1", output_bytes=50, duration=1.0)
    assert qm.usage("s1").executions == 1
    qm.reset("s1")
    assert qm.usage("s1").executions == 0


# ── Schemas ──────────────────────────────────────────────────────────────


def test_execution_request_valid() -> None:
    """ExecutionRequest accepts a valid request."""
    import hashlib
    principal_hash = hashlib.sha256(b"user").hexdigest()
    req = ExecutionRequest(
        session=f"{principal_hash}/session-1",
        tool="nmap_scan",
        command="nmap 127.0.0.1",
        timeout=30,
    )
    assert req.tool == "nmap_scan"
    assert req.network_profile == "offline"


def test_execution_request_rejects_invalid_session() -> None:
    """ExecutionRequest rejects an invalid session path."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ExecutionRequest(
            session="invalid/session",
            tool="test",
            command="echo hi",
        )


def test_execution_result_defaults() -> None:
    """ExecutionResult has correct defaults."""
    result = ExecutionResult()
    assert result.status == "success"
    assert result.returncode == 0
    assert result.output == ""


def test_file_read_request_defaults() -> None:
    """FileReadRequest has correct defaults."""
    req = FileReadRequest(path="test.txt")
    assert req.offset == 1
    assert req.limit == 2000


def test_file_write_request_valid() -> None:
    """FileWriteRequest accepts valid content."""
    req = FileWriteRequest(path="test.txt", content="hello")
    assert req.content == "hello"


# ── Safe IO ──────────────────────────────────────────────────────────────


def test_strip_ansi() -> None:
    """strip_ansi removes ANSI escape sequences."""
    text = "\x1b[31mred text\x1b[0m"
    assert strip_ansi(text) == "red text"


def test_strip_control_chars() -> None:
    """strip_control_chars removes non-printable characters."""
    text = "hello\x00\x01\x02world"
    assert strip_control_chars(text) == "helloworld"


def test_sanitize_output_truncates() -> None:
    """sanitize_output truncates long output."""
    long_text = "x" * 100
    result = sanitize_output(long_text, max_chars=50)
    assert "[truncated]" in result
    assert len(result) < len(long_text)


def test_sanitize_filename() -> None:
    """sanitize_filename removes path separators and traversal."""
    assert sanitize_filename("../etc/passwd") == "__etc_passwd"
    assert sanitize_filename("normal.txt") == "normal.txt"


def test_truncate_lines() -> None:
    """truncate_lines limits the number of lines."""
    text = "\n".join(f"line{i}" for i in range(100))
    result = truncate_lines(text, max_lines=10)
    assert "truncated" in result


# ── ToolContext ──────────────────────────────────────────────────────────


def test_tool_context_is_approved(tmp_path: Path) -> None:
    """ToolContext.is_approved checks the approved set."""
    ctx = ToolContext(
        workspace=tmp_path,
        session="test",
        principal="user",
        approved_tools={"sec_nmap_scan"},
    )
    assert ctx.is_approved("sec_nmap_scan") is True
    assert ctx.is_approved("sec_Bash") is False


def test_tool_context_read_write(tmp_path: Path) -> None:
    """ToolContext can read and write files in the workspace."""
    ctx = ToolContext(workspace=tmp_path, session="test", principal="user")
    ctx.write_file("test.txt", "hello")
    assert ctx.read_file("test.txt") == "hello"


def test_tool_context_list_files(tmp_path: Path) -> None:
    """ToolContext can list files in the workspace."""
    ctx = ToolContext(workspace=tmp_path, session="test", principal="user")
    ctx.write_file("a.txt", "a")
    ctx.write_file("b.txt", "b")
    entries = ctx.list_files()
    names = [e["name"] for e in entries]
    assert "a.txt" in names
    assert "b.txt" in names


def test_tool_context_to_dict(tmp_path: Path) -> None:
    """ToolContext.to_dict serializes safely."""
    ctx = ToolContext(
        workspace=tmp_path,
        session="test",
        principal="user",
        approved_tools={"sec_Bash", "sec_nmap_scan"},
    )
    d = ctx.to_dict()
    assert d["session"] == "test"
    assert d["principal"] == "user"
    assert sorted(d["approved_tools"]) == ["sec_Bash", "sec_nmap_scan"]


# ── SessionLock ─────────────────────────────────────────────────────────


def test_session_lock_acquire_release(tmp_path: Path) -> None:
    """SessionLock can acquire and release."""
    lock = SessionLock(tmp_path, timeout=5)
    assert lock.acquire() is True
    assert lock.is_acquired is True
    lock.release()
    assert lock.is_acquired is False


def test_session_lock_context_manager(tmp_path: Path) -> None:
    """SessionLock works as a context manager."""
    lock = SessionLock(tmp_path, timeout=5)
    with lock as acquired:
        assert acquired is True
        assert lock.is_acquired is True
    assert lock.is_acquired is False
