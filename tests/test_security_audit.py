"""Tests for the security audit logger."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from black_onyx.audit.security_audit import SecurityAuditLogger, redact


# ── Redaction tests ──────────────────────────────────────────────────────


def test_redact_sk_token() -> None:
    """OpenAI-style API keys are redacted."""
    assert redact("sk-abcdefghijklmnopqrstuvwxyz123") == "[REDACTED]"


def test_redact_hex_string() -> None:
    """64+ char hex strings are redacted."""
    assert redact("a" * 64) == "[REDACTED]"


def test_redact_pem_block() -> None:
    """PEM private key blocks are redacted."""
    pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    assert redact(pem) == "[REDACTED]"


def test_redact_secret_key_in_dict() -> None:
    """Dict keys matching the secret pattern are redacted."""
    result = redact({"api_key": "secret123", "name": "test"})
    assert result["api_key"] == "[REDACTED]"
    assert result["name"] == "test"


def test_redact_password_key() -> None:
    """The 'password' key is redacted."""
    result = redact({"password": "hunter2"})
    assert result["password"] == "[REDACTED]"


def test_redact_authorization_key() -> None:
    """The 'authorization' key is redacted."""
    result = redact({"authorization": "Bearer abc"})
    assert result["authorization"] == "[REDACTED]"


def test_redact_command_secret() -> None:
    """Command-line secret flags are redacted."""
    result = redact("--password=hunter2 --token=abc123")
    assert "[REDACTED]" in result


def test_redact_preserves_non_secret_keys() -> None:
    """Non-secret keys keep their values."""
    result = redact({"target": "10.0.0.1", "port": "80"})
    assert result == {"target": "10.0.0.1", "port": "80"}


def test_redact_truncates_long_strings() -> None:
    """Long strings are truncated to max_chars."""
    long_str = "x" * 10000
    result = redact(long_str, max_chars=100)
    assert len(result) <= 100


def test_redact_list() -> None:
    """List values are recursively redacted."""
    result = redact(["sk-abcdefghijklmnopqrstuvwxyz123", "safe"])
    assert result[0] == "[REDACTED]"
    assert result[1] == "safe"


def test_redact_nested_dict() -> None:
    """Nested dicts are recursively redacted."""
    result = redact({"outer": {"api_key": "secret", "safe": "ok"}})
    assert result["outer"]["api_key"] == "[REDACTED]"
    assert result["outer"]["safe"] == "ok"


# ── Audit logger tests ───────────────────────────────────────────────────


def test_audit_log_tool_call(tmp_path: Path) -> None:
    """log_tool_call writes a JSONL event with tool, args, and principal."""
    log_path = tmp_path / "audit.jsonl"
    audit = SecurityAuditLogger(path=str(log_path))
    audit.log_tool_call("sec_nmap_scan", {"target": "10.0.0.1"}, "user-123")
    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event"] == "security.tool.call"
    assert entry["tool"] == "sec_nmap_scan"
    assert entry["args"]["target"] == "10.0.0.1"
    assert entry["principal"] == "user-123"
    assert "timestamp" in entry
    assert "request_id" in entry


def test_audit_log_tool_result(tmp_path: Path) -> None:
    """log_tool_result writes a JSONL event with status and duration."""
    log_path = tmp_path / "audit.jsonl"
    audit = SecurityAuditLogger(path=str(log_path))
    audit.log_tool_result("sec_nmap_scan", "success", 1.5)
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["event"] == "security.tool.result"
    assert entry["status"] == "success"
    assert entry["duration_s"] == 1.5


def test_audit_log_denial(tmp_path: Path) -> None:
    """log_denial writes a JSONL event with the denial reason."""
    log_path = tmp_path / "audit.jsonl"
    audit = SecurityAuditLogger(path=str(log_path))
    audit.log_denial("sec_Bash", "tier destructive", "user-456")
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["event"] == "security.tool.denied"
    assert entry["tool"] == "sec_Bash"
    assert entry["reason"] == "tier destructive"


def test_audit_log_agent_run(tmp_path: Path) -> None:
    """log_agent_run writes a JSONL event with a truncated message preview."""
    log_path = tmp_path / "audit.jsonl"
    audit = SecurityAuditLogger(path=str(log_path))
    long_message = "x" * 500
    audit.log_agent_run(long_message, 5, "user-789")
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["event"] == "security.agent.run"
    assert entry["rounds"] == 5
    assert len(entry["message_preview"]) == 200


def test_audit_redacts_secrets_in_args(tmp_path: Path) -> None:
    """Secrets in tool args are redacted before logging."""
    log_path = tmp_path / "audit.jsonl"
    audit = SecurityAuditLogger(path=str(log_path))
    audit.log_tool_call(
        "sec_aes_encrypt",
        {"data": "plaintext", "key": "a" * 64},
        "user-123",
    )
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["args"]["key"] == "[REDACTED]"
    assert entry["args"]["data"] == "plaintext"


def test_audit_creates_parent_directory(tmp_path: Path) -> None:
    """The logger creates parent directories if they don't exist."""
    log_path = tmp_path / "subdir" / "deep" / "audit.jsonl"
    audit = SecurityAuditLogger(path=str(log_path))
    audit.log("test.event")
    assert log_path.exists()
