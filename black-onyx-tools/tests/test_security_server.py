"""Security MCP server tests for executors and approval lifecycle controls."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.tools.sec_tools import (
    SECURITY_CONTROL_CATALOG,
    SECURITY_TOOL_CATALOG,
    approve_security_tool,
    execute_security_tool,
    preview_security_tool,
    public_security_tool_schema,
    register_security_tools,
    resume_security_agent_run,
    security_agent_run_status,
)


DATASETS = Path(__file__).resolve().parents[1] / "datasets" / "tool_use"


@pytest.fixture
def mock_client() -> PlatformClient:
    client = AsyncMock(spec=PlatformClient)
    return client


def test_security_tool_catalog_has_45_tools() -> None:
    """The catalog contains exactly 45 security tools."""
    assert len(SECURITY_TOOL_CATALOG) == 45


def test_security_tool_categories() -> None:
    """Tools span the 5 categories: sandbox, security, binary, crypto, web3."""
    sandbox = {"Bash", "Read", "Write", "Edit", "Grep", "Glob", "ListFiles"}
    security = {"nmap_scan", "sqlmap_scan", "nikto_scan", "whois_lookup", "shodan_search",
                "gobuster_dir", "hydra_brute", "tcpdump_capture", "port_scan"}
    binary = {"checksec", "decompile", "decompile_function", "disassemble",
              "disassemble_binary", "extract_strings", "run_binary", "file_info",
              "search_gadgets", "cyclic_pattern"}
    crypto = {"aes_encrypt", "aes_decrypt", "decode_hex", "decode_base64",
              "encode_base64", "hash_data", "extract_iocs", "compute_threat_score",
              "add_ioc_to_case", "generate_yara_rule", "analyze_pcap"}
    web3 = {"cast_call", "cast_send", "cast_keccak", "compile_contracts",
            "analyze_contract", "get_contract_storage", "check_solved", "submit_solution"}

    catalog_names = set(SECURITY_TOOL_CATALOG.keys())
    assert sandbox <= catalog_names, f"Missing sandbox tools: {sandbox - catalog_names}"
    assert security <= catalog_names, f"Missing security tools: {security - catalog_names}"
    assert binary <= catalog_names, f"Missing binary tools: {binary - catalog_names}"
    assert crypto <= catalog_names, f"Missing crypto tools: {crypto - catalog_names}"
    assert web3 <= catalog_names, f"Missing web3 tools: {web3 - catalog_names}"
    # Total: 7 + 9 + 10 + 11 + 8 = 45
    assert len(sandbox | security | binary | crypto | web3) == 45


def test_each_tool_has_description_and_schema() -> None:
    """Each tool entry has a non-empty description and a valid JSON schema."""
    for name, (description, schema) in SECURITY_TOOL_CATALOG.items():
        assert isinstance(description, str) and description, f"{name}: empty description"
        assert isinstance(schema, dict), f"{name}: schema is not a dict"
        assert schema.get("type") == "object", f"{name}: schema type != object"
        assert "properties" in schema, f"{name}: missing properties"
        if "required" in schema:
            for req in schema["required"]:
                assert req in schema["properties"], f"{name}: required '{req}' not in properties"


def test_security_tools_json_matches_catalog() -> None:
    """The exported security_tools.json matches the in-code catalog."""
    json_path = DATASETS / "security_tools.json"
    assert json_path.exists(), "security_tools.json not found"
    tools = json.loads(json_path.read_text(encoding="utf-8"))
    expected = [
        {
            "type": "function",
            "function": {
                "name": f"sec_{name}",
                "description": description,
                "parameters": (
                    public_security_tool_schema(name)
                    if name in SECURITY_TOOL_CATALOG
                    else schema
                ),
            },
        }
        for name, (description, schema) in sorted(
            {**SECURITY_TOOL_CATALOG, **SECURITY_CONTROL_CATALOG}.items()
        )
    ]
    assert tools == expected


def test_tools_json_contains_sec_entries() -> None:
    """The main tools.json contains all executors and lifecycle controls."""
    tools = json.loads((DATASETS / "tools.json").read_text(encoding="utf-8"))
    sec_names = {
        t["function"]["name"]
        for t in tools
        if t.get("function", {}).get("name", "").startswith("sec_")
    }
    assert len(sec_names) == 49
    expected = {
        f"sec_{name}"
        for name in {**SECURITY_TOOL_CATALOG, **SECURITY_CONTROL_CATALOG}
    }
    assert sec_names == expected, f"Mismatch: {sec_names ^ expected}"


@pytest.mark.asyncio
async def test_execute_security_tool_dispatches_to_bff(mock_client: PlatformClient) -> None:
    """execute_security_tool calls the BFF /api/v1/security/tools/{name} endpoint."""
    mock_client.tip_post = AsyncMock(return_value={"status": "success", "output": "done"})
    result = await execute_security_tool(
        mock_client, tool_name="nmap_scan", target="127.0.0.1"
    )
    assert result["status"] == "success"
    mock_client.tip_post.assert_awaited_once_with(
        "/api/v1/security/tools/nmap_scan",
        json={
            "arguments": {"target": "127.0.0.1"},
            "session_id": "mcp-security",
            "timeout": 60,
            "network_profile": "offline",
            "destinations": [],
                "ports": [],
        },
    )


@pytest.mark.asyncio
async def test_execute_security_tool_unknown_name(mock_client: PlatformClient) -> None:
    """Unknown tool names return an error dict (fail closed)."""
    result = await execute_security_tool(mock_client, tool_name="nonexistent")
    assert result.get("error"), "Expected error for unknown tool"


@pytest.mark.asyncio
async def test_execute_security_tool_missing_name(mock_client: PlatformClient) -> None:
    """A missing tool_name returns an error (fail closed)."""
    result = await execute_security_tool(mock_client)
    assert result.get("error"), "Expected error for missing tool_name"


@pytest.mark.asyncio
async def test_execute_security_tool_none_client() -> None:
    """A None client raises AttributeError (caller must supply a client)."""
    with pytest.raises(AttributeError):
        await execute_security_tool(None, tool_name="nmap_scan")


def test_register_security_tools_registers_executors_and_controls() -> None:
    """Every executor and explicit approval/run control is registered."""
    import asyncio

    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("test-security-server")
    register_security_tools(mcp, AsyncMock(spec=PlatformClient))
    tools = asyncio.run(mcp.list_tools())
    tool_names = {t.name for t in tools}
    expected = {
        f"sec_{name}"
        for name in {**SECURITY_TOOL_CATALOG, **SECURITY_CONTROL_CATALOG}
    }
    assert tool_names == expected, f"Registered {len(tool_names)} tools; missing: {expected - tool_names}"


@pytest.mark.asyncio
async def test_security_approval_lifecycle_uses_exact_bff_envelopes(
    mock_client: PlatformClient,
) -> None:
    preview = {
        "tool": "Write",
        "tier": "write",
        "arguments": {"path": "notes.txt", "content": "reviewed"},
        "session_id": "mcp-security",
        "timeout": 60,
        "network_profile": "offline",
        "destinations": [],
        "ports": [],
        "lab_profile_id": None,
        "resolved_targets": {},
        "preview_hash": "a" * 64,
    }
    mock_client.tip_post = AsyncMock(side_effect=[preview, {"approval_id": "approval-1"}])
    result = await preview_security_tool(
        mock_client,
        tool_name="Write",
        arguments={"path": "notes.txt", "content": "reviewed"},
    )
    approved = await approve_security_tool(
        mock_client, tool_name="Write", preview=result
    )
    assert approved == {"approval_id": "approval-1"}
    assert mock_client.tip_post.await_args_list[0].args == (
        "/api/v1/security/tools/Write/preview",
    )
    approval_body = mock_client.tip_post.await_args_list[1].kwargs["json"]
    assert approval_body["preview_hash"] == "a" * 64
    assert "tier" not in approval_body and "tool" not in approval_body


@pytest.mark.asyncio
async def test_agent_status_resume_and_deny_are_explicit(
    mock_client: PlatformClient,
) -> None:
    mock_client.tip_get = AsyncMock(return_value={"status": "pending_approval"})
    mock_client.tip_post = AsyncMock(return_value={"status": "completed"})
    assert (await security_agent_run_status(mock_client, run_id="run-1"))["status"] == "pending_approval"
    await resume_security_agent_run(
        mock_client, run_id="run-1", approval_id="approval-1"
    )
    mock_client.tip_post.assert_awaited_with(
        "/api/v1/security/agent/runs/run-1/resume",
        json={"deny": False, "approval_id": "approval-1"},
    )
    await resume_security_agent_run(mock_client, run_id="run-2", deny=True)
    mock_client.tip_post.assert_awaited_with(
        "/api/v1/security/agent/runs/run-2/resume", json={"deny": True}
    )
    with pytest.raises(ValueError):
        await resume_security_agent_run(mock_client, run_id="run-3")


def test_security_server_module_exports() -> None:
    """The security_server module exports create_app and main with port 8203."""
    from black_onyx_tools.servers.security_server import DEFAULT_PORT, create_app, main

    assert DEFAULT_PORT == 8203
    assert callable(create_app)
    assert callable(main)
