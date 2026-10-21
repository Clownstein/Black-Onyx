"""Tests for the black_onyx_sandbox package SSRF validation, path resolution, redaction."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from black_onyx_sandbox.security import (
    TargetBlockedError,
    bound_hex_data,
    quote_shell_args,
    redact_command_for_audit,
    resolve_workspace_path,
    validate_eth_address,
    validate_target,
    validate_url,
)


# ── SSRF / target validation ─────────────────────────────────────────────


def test_validate_target_rejects_empty() -> None:
    with pytest.raises(TargetBlockedError, match="Empty target"):
        validate_target("")


def test_validate_target_rejects_localhost() -> None:
    with pytest.raises(TargetBlockedError, match="Blocked hostname"):
        validate_target("localhost")


def test_validate_target_rejects_docker_services() -> None:
    for service in ("qdrant", "postgres", "redpanda", "redis", "web"):
        with pytest.raises(TargetBlockedError, match="Blocked hostname"):
            validate_target(service)


def test_validate_target_rejects_metadata_endpoint() -> None:
    with pytest.raises(TargetBlockedError, match="Blocked hostname"):
        validate_target("metadata.google.internal")


def test_validate_target_rejects_ambiguous_numeric() -> None:
    with pytest.raises(TargetBlockedError, match="Ambiguous numeric"):
        validate_target("10.1")


def test_validate_url_rejects_non_http() -> None:
    with pytest.raises(TargetBlockedError, match="Unsupported URL scheme"):
        validate_url("ftp://example.com/file")


def test_validate_url_rejects_credentials() -> None:
    with pytest.raises(TargetBlockedError, match="URL must not contain credentials"):
        validate_url("http://user:pass@example.com/")


def test_validate_url_rejects_fragment() -> None:
    with pytest.raises(TargetBlockedError, match="fragment"):
        validate_url("http://example.com/#section")


# ── Workspace path resolution ─────────────────────────────────────────────


def test_resolve_workspace_path_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="escapes workspace"):
        resolve_workspace_path(tmp_path, "../../etc/passwd")


def test_resolve_workspace_path_rejects_absolute(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="escapes workspace"):
        resolve_workspace_path(tmp_path, "/etc/passwd")


def test_resolve_workspace_path_accepts_relative(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "file.txt").write_text("ok")
    result = resolve_workspace_path(tmp_path, "subdir/file.txt")
    assert result.is_file()
    assert result.read_text() == "ok"


# ── Command redaction ─────────────────────────────────────────────────────


def test_redact_command_strips_password_flag() -> None:
    result = redact_command_for_audit("--password=hunter2 --target=10.0.0.1")
    assert "[REDACTED]" in result
    assert "hunter2" not in result
    assert "10.0.0.1" in result


def test_redact_command_strips_private_key_flag() -> None:
    result = redact_command_for_audit("--private-key=abc123 --port=22")
    assert "[REDACTED]" in result
    assert "abc123" not in result


def test_redact_command_strips_cast_private_key_env() -> None:
    result = redact_command_for_audit("CAST_PRIVATE_KEY=0xabc123 cast send")
    assert "[REDACTED]" in result
    assert "0xabc123" not in result


def test_redact_command_strips_long_hex() -> None:
    result = redact_command_for_audit("key=" + "a" * 64)
    assert "[REDACTED]" in result


# ── Shell quoting ─────────────────────────────────────────────────────────


def test_quote_shell_args_simple() -> None:
    assert quote_shell_args(["nmap", "10.0.0.1"]) == "nmap 10.0.0.1"


def test_quote_shell_args_with_spaces() -> None:
    assert "'hello world'" in quote_shell_args(["echo", "hello world"])


def test_quote_shell_args_with_special_chars() -> None:
    result = quote_shell_args(["echo", "a; rm -rf /"])
    # The semicolon should be inside single quotes, preventing injection
    assert "'a; rm -rf /'" in result


# ── Ethereum address validation ───────────────────────────────────────────


def test_validate_eth_address_valid() -> None:
    assert validate_eth_address("0x" + "a" * 40) is True


def test_validate_eth_address_invalid_short() -> None:
    assert validate_eth_address("0x" + "a" * 39) is False


def test_validate_eth_address_invalid_no_prefix() -> None:
    assert validate_eth_address("a" * 40) is False


def test_validate_eth_address_empty() -> None:
    assert validate_eth_address("") is False


# ── Hex data bounding ─────────────────────────────────────────────────────


def test_bound_hex_data_short() -> None:
    assert bound_hex_data("abcd") == "abcd"


def test_bound_hex_data_strips_prefix() -> None:
    assert bound_hex_data("0xabcd") == "abcd"


def test_bound_hex_data_rejects_too_long() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        bound_hex_data("a" * 100_001, max_chars=100_000)
