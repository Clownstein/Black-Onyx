"""Tests for MCP tool registry validation."""

from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from black_onyx.auth.service import Principal, Role
from black_onyx.mcp.registry import execute_tool, load_tool_catalog, validate_tool_call


def test_tool_catalog_loads() -> None:
    catalog = load_tool_catalog()
    assert len(catalog) == 63
    names = [(item.get("function") or {}).get("name") for item in catalog]
    assert len(set(names)) == 63
    assert "black_onyx_evidence_search" in names
    assert len([name for name in names if isinstance(name, str) and name.startswith("sec_")]) == 45
    assert "sec_approve_tool" not in names


def test_security_tool_name_list_cannot_replace_request_approval() -> None:
    analyst = Principal("u2", "analyst@test", "Analyst", Role.ANALYST)
    err = validate_tool_call(
        "sec_hydra_brute",
        {"target": "10.0.0.5", "service": "ssh"},
        principal=analyst,
        approved_tools=["sec_hydra_brute"],
    )
    assert "approval_id" in (err or "")


@pytest.mark.asyncio
async def test_network_scanner_without_allowlist_cannot_execute() -> None:
    analyst = Principal("u2", "analyst@test", "Analyst", Role.ANALYST)
    client = AsyncMock()
    result = await execute_tool(
        client,
        name="sec_nmap_scan",
        arguments={"target": "10.88.0.2", "ports": "80"},
        principal=analyst,
        approved_tools=["sec_nmap_scan"],
    )
    assert "approval_id" in str(result.get("error") or "")
    client.tip_post.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_scanner_mints_approval_for_allowlisted_target() -> None:
    analyst = Principal("u2", "analyst@test", "Analyst", Role.ANALYST)
    client = AsyncMock()

    async def tip_post(path: str, json=None):
        if path.endswith("/preview"):
            return {
                "arguments": {"target": "10.88.0.2", "ports": "80"},
                "session_id": "embedded-chat",
                "timeout": 60,
                "network_profile": "lab",
                "destinations": ["10.88.0.2"],
                "ports": [80],
                "lab_profile_id": "anvil",
                "resolved_targets": {"10.88.0.2": ["10.88.0.2"]},
                "preview_hash": "abc",
            }
        if path.endswith("/approve"):
            return {"approval_id": "minted-1"}
        return {"status": "success", "output": "80/tcp open"}

    client.tip_post.side_effect = tip_post
    result = await execute_tool(
        client,
        name="sec_nmap_scan",
        arguments={"target": "10.88.0.2", "ports": "80", "network_profile": "lab"},
        principal=analyst,
        mcp_cfg=SimpleNamespace(allowed_targets=["10.88.0.0/24"]),
    )
    assert result["status"] == "success"
    paths = [call.args[0] for call in client.tip_post.await_args_list]
    assert paths[-1] == "/api/v1/security/tools/nmap_scan"
    assert client.tip_post.await_args.kwargs["json"]["approval_id"] == "minted-1"


@pytest.mark.asyncio
async def test_security_execution_forwards_approval_as_transport_metadata() -> None:
    analyst = Principal("u2", "analyst@test", "Analyst", Role.ANALYST)
    client = AsyncMock()
    client.tip_post.return_value = {"status": "success"}
    await execute_tool(
        client,
        name="sec_nmap_scan",
        arguments={
            "target": "10.88.0.2",
            "ports": "80,443",
            "approval_id": "approval-1",
            "network_profile": "lab",
            "lab_profile_id": "owned-lab",
            "destinations": ["10.88.0.2"],
            "scope_ports": [80, 443],
            "resolved_targets": {"10.88.0.2": ["10.88.0.2"]},
        },
        principal=analyst,
        approved_tools=["sec_nmap_scan"],
    )
    client.tip_post.assert_awaited_once_with(
        "/api/v1/security/tools/nmap_scan",
        json={
            "arguments": {"target": "10.88.0.2", "ports": "80,443"},
            "session_id": "embedded-chat",
            "timeout": 60,
            "network_profile": "lab",
            "destinations": ["10.88.0.2"],
            "ports": [80, 443],
            "approval_id": "approval-1",
            "lab_profile_id": "owned-lab",
            "resolved_targets": {"10.88.0.2": ["10.88.0.2"]},
        },
    )


def test_viewer_blocked_from_mutating_case_assist() -> None:
    viewer = Principal("u1", "viewer@test", "Viewer", Role.VIEWER)
    err = validate_tool_call(
        "black_onyx_case_assist",
        {"action": "create_draft", "title": "x"},
        principal=viewer,
    )
    assert err is not None


def test_viewer_may_list_cases() -> None:
    viewer = Principal("u1", "viewer@test", "Viewer", Role.VIEWER)
    err = validate_tool_call(
        "black_onyx_case_assist",
        {"action": "list"},
        principal=viewer,
    )
    assert err is None


def test_response_draft_never_approves() -> None:
    analyst = Principal("u2", "analyst@test", "Analyst", Role.ANALYST)
    err = validate_tool_call(
        "black_onyx_response_draft",
        {"incident_id": "inc-1", "approve": True},
        principal=analyst,
    )
    assert "never approves" in (err or "")
