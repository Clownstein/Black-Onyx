"""Tests for the unified tool tier policy."""

from __future__ import annotations

import os

from black_onyx.mcp.tool_policy import (
    ToolTier,
    approval_denial_message,
    get_tool_tier,
    is_tool_approved,
    normalize_approved_tools,
)


def test_platform_tool_tiers() -> None:
    """Black Onyx platform tools have correct tiers."""
    assert get_tool_tier("black_onyx_evidence_search") == ToolTier.READ
    assert get_tool_tier("black_onyx_response_draft") == ToolTier.DESTRUCTIVE
    assert get_tool_tier("black_onyx_case_assist") == ToolTier.WORKSPACE_WRITE
    assert get_tool_tier("black_onyx_connector_pulse") == ToolTier.NETWORK


def test_security_tool_tiers() -> None:
    """Security tools have correct tiers."""
    assert get_tool_tier("sec_decode_hex") == ToolTier.READ
    assert get_tool_tier("sec_Bash") == ToolTier.DESTRUCTIVE
    assert get_tool_tier("sec_nmap_scan") == ToolTier.NETWORK
    assert get_tool_tier("sec_cast_send") == ToolTier.TRANSACTION
    assert get_tool_tier("sec_tcpdump_capture") == ToolTier.PRIVILEGED_CAPTURE
    assert get_tool_tier("sec_decompile") == ToolTier.LAB
    assert get_tool_tier("sec_Write") == ToolTier.WORKSPACE_WRITE


def test_unknown_tool_fails_closed() -> None:
    """An unknown tool defaults to DESTRUCTIVE (fail-closed)."""
    assert get_tool_tier("unknown_tool") == ToolTier.DESTRUCTIVE
    assert get_tool_tier("totally_new_tool_xyz") == ToolTier.DESTRUCTIVE


def test_read_tier_auto_approved() -> None:
    """Read-tier tools are auto-approved under the 'required' policy."""
    assert is_tool_approved("sec_decode_hex", tool_approval="required") is True
    assert is_tool_approved("black_onyx_evidence_search", tool_approval="required") is True


def test_non_read_tier_requires_approval() -> None:
    """Non-read tier tools require explicit approved_tools under 'required'."""
    assert is_tool_approved("sec_Bash", tool_approval="required") is False
    assert is_tool_approved("sec_nmap_scan", tool_approval="required") is False


def test_security_tool_name_list_is_not_authorization() -> None:
    """Security executors require request-bound approval, never a name list."""
    assert is_tool_approved(
        "sec_Bash", tool_approval="required", approved_tools=["sec_Bash"]
    ) is False
    assert is_tool_approved(
        "sec_nmap_scan", tool_approval="required", approved_tools=["sec_nmap_scan", "other"]
    ) is False


def test_auto_policy_approves_everything() -> None:
    """The 'auto' policy approves every tool (trusted labs only)."""
    assert is_tool_approved("sec_Bash", tool_approval="auto") is True
    assert is_tool_approved("sec_hydra_brute", tool_approval="auto") is True


def test_unknown_policy_fails_closed() -> None:
    """An unknown approval mode fails closed."""
    assert is_tool_approved("sec_decode_hex", tool_approval="bogus") is False


def test_normalize_approved_tools() -> None:
    """normalize_approved_tools strips whitespace and filters empties."""
    result = normalize_approved_tools(["  sec_Bash  ", "", " sec_nmap_scan "])
    assert result == {"sec_Bash", "sec_nmap_scan"}


def test_normalize_approved_tools_none() -> None:
    """normalize_approved_tools with None returns an empty set."""
    assert normalize_approved_tools(None) == set()
    assert normalize_approved_tools([]) == set()


def test_approval_denial_message() -> None:
    """The denial message includes the tool name and tier."""
    msg = approval_denial_message("sec_Bash")
    assert "sec_Bash" in msg
    assert "destructive" in msg
    assert "approval_id" in msg


def test_sqlmap_exploit_mode_elevates_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    """sqlmap_scan elevates to DESTRUCTIVE when SQLMAP_EXPLOIT_MODE=true."""
    monkeypatch.setenv("SQLMAP_EXPLOIT_MODE", "true")
    assert get_tool_tier("sec_sqlmap_scan") == ToolTier.DESTRUCTIVE


def test_sqlmap_default_tier_is_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    """sqlmap_scan defaults to LAB when SQLMAP_EXPLOIT_MODE is not set."""
    monkeypatch.delenv("SQLMAP_EXPLOIT_MODE", raising=False)
    assert get_tool_tier("sec_sqlmap_scan") == ToolTier.LAB


def test_all_63_tools_have_tiers() -> None:
    """Every tool in the registry has an explicit tier (no accidental unknowns)."""
    from black_onyx.mcp.tool_policy import TOOL_TIERS
    # 18 platform + 45 security = 63
    assert len(TOOL_TIERS) == 63
    # All values are valid ToolTier enums
    for tier in TOOL_TIERS.values():
        assert isinstance(tier, ToolTier)


def test_response_draft_never_auto_approvable() -> None:
    """response_draft is DESTRUCTIVE never auto-approved under 'required'."""
    assert get_tool_tier("black_onyx_response_draft") == ToolTier.DESTRUCTIVE
    assert is_tool_approved("black_onyx_response_draft", tool_approval="required") is False
