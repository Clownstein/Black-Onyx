from __future__ import annotations

from types import SimpleNamespace

from pydantic import ValidationError
import pytest

from black_onyx.mcp.tool_settings import (
    McpToolPolicy,
    McpToolsConfig,
    apply_mcp_runtime,
    filter_tool_catalog,
    host_on_allowlist,
    mcp_tool_policy,
    preview_on_allowlist,
    tool_group,
)


def test_default_policy_enables_platform_and_disables_security() -> None:
    cfg = SimpleNamespace(tools={}, lab_profile_id="anvil")
    platform = mcp_tool_policy(cfg, "black_onyx_evidence_search")
    assert platform.enabled is True
    assert platform.allow_public is False
    security = mcp_tool_policy(cfg, "sec_nmap_scan")
    assert security.enabled is False


def test_filter_catalog_requires_explicit_selection() -> None:
    catalog = [
        {"type": "function", "function": {"name": "black_onyx_hunt", "description": "hunt"}},
        {"type": "function", "function": {"name": "sec_nmap_scan", "description": "nmap"}},
    ]
    cfg = SimpleNamespace(
        tools={"sec_nmap_scan": McpToolPolicy(enabled=True)},
        lab_profile_id="anvil",
    )
    assert filter_tool_catalog(catalog, cfg, None) == []
    assert filter_tool_catalog(catalog, cfg, []) == []
    selected = filter_tool_catalog(catalog, cfg, ["black_onyx_hunt", "sec_nmap_scan"])
    assert [item["function"]["name"] for item in selected] == ["black_onyx_hunt", "sec_nmap_scan"]
    disabled = filter_tool_catalog(
        catalog,
        SimpleNamespace(tools={"sec_nmap_scan": McpToolPolicy(enabled=False)}, lab_profile_id="anvil"),
        ["sec_nmap_scan"],
    )
    assert disabled == []


def test_apply_runtime_injects_lab_scope_from_policy() -> None:
    cfg = SimpleNamespace(
        tools={"sec_nmap_scan": McpToolPolicy(enabled=True, allow_private=True, network_profile="lab")},
        lab_profile_id="anvil",
    )
    merged, error = apply_mcp_runtime(
        cfg,
        "sec_nmap_scan",
        {"target": "10.88.0.2", "ports": "all", "approval_id": "forged", "network_profile": "public"},
        ["sec_nmap_scan"],
    )
    assert error is None
    assert merged is not None
    assert merged["network_profile"] == "lab"
    assert merged["lab_profile_id"] == "anvil"
    assert "approval_id" not in merged
    assert merged["target"] == "10.88.0.2"


def test_apply_runtime_blocks_unselected_and_public_when_disabled() -> None:
    cfg = SimpleNamespace(
        tools={"sec_nmap_scan": McpToolPolicy(enabled=True, allow_public=False, network_profile="public")},
        lab_profile_id="anvil",
    )
    skipped, skip_error = apply_mcp_runtime(cfg, "sec_nmap_scan", {"target": "10.88.0.2"}, None)
    assert skipped is None
    assert skip_error is not None
    merged, error = apply_mcp_runtime(cfg, "sec_nmap_scan", {}, ["sec_nmap_scan"])
    assert merged is None
    assert error is not None
    assert "Public" in error


def test_apply_runtime_blocks_private_when_allow_private_false() -> None:
    cfg = SimpleNamespace(
        tools={"sec_nmap_scan": McpToolPolicy(enabled=True, allow_private=False, network_profile="lab")},
        lab_profile_id="anvil",
    )
    merged, error = apply_mcp_runtime(cfg, "sec_nmap_scan", {"target": "10.88.0.2"}, ["sec_nmap_scan"])
    assert merged is None
    assert error is not None
    assert "Private" in error


def test_mcp_tools_config_rejects_oversized_tool_keys() -> None:
    with pytest.raises(ValidationError):
        McpToolsConfig(tools={"x" * 81: McpToolPolicy()})


def test_chat_allowlist_normalizes_and_matches() -> None:
    cfg = McpToolsConfig(allowed_targets=["10.88.0.2", "Example.COM.", "10.88.1.0/24"])
    assert cfg.allowed_targets == ["10.88.0.2", "example.com", "10.88.1.0/24"]
    assert host_on_allowlist("10.88.0.2", cfg.allowed_targets)
    assert host_on_allowlist("example.com", cfg.allowed_targets)
    assert host_on_allowlist("10.88.1.9", cfg.allowed_targets)
    assert not host_on_allowlist("45.82.66.225", cfg.allowed_targets)
    assert preview_on_allowlist(
        cfg,
        ["scan.example.com"],
        {"scan.example.com": ["10.88.0.2"]},
    )
    assert not preview_on_allowlist(cfg, ["45.82.66.225"], {"45.82.66.225": ["45.82.66.225"]})
    with pytest.raises(ValidationError):
        McpToolsConfig(allowed_targets=["10.0.0.0/8"])


def test_tool_group_for_security_names() -> None:
    assert tool_group("black_onyx_hunt") == "platform"
    assert tool_group("sec_nmap_scan") == "security"
    assert tool_group("sec_Bash") == "sandbox"
