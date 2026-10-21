"""Tests for in-process MCP tool orchestrator."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from black_onyx.auth.service import Principal, Role
from black_onyx.llm.base import ChatMessage, ChatResponse
from black_onyx.llm.mcp_orchestrator import McpToolOrchestrator
from black_onyx.mcp.tool_settings import McpToolPolicy


@pytest.mark.asyncio
async def test_mcp_orchestrator_runs_tool_then_final_answer() -> None:
    settings = SimpleNamespace(
        mcp_tools=SimpleNamespace(max_tool_rounds=2),
        llm=SimpleNamespace(
            provider="local",
            rag=SimpleNamespace(system_prompt="Analyst system prompt."),
            openai_compatible=SimpleNamespace(thinking_level=None),
        ),
    )
    service = SimpleNamespace(settings=settings)
    principal = Principal("u1", "a@test", "A", Role.ANALYST)
    llm = MagicMock()
    llm._default_max_tokens = 1024
    llm.chat.side_effect = [
        ChatResponse(text=json.dumps({
            "tool": "black_onyx_evidence_search",
            "args": {"query": "lateral movement"},
        })),
        ChatResponse(text=json.dumps({"final": True, "answer": "Found one hit."})),
    ]

    app = MagicMock()
    orch = McpToolOrchestrator(
        service=service,
        app=app,
        llm=llm,
        principal=principal,
        provider_name="local",
        selected_tools=["black_onyx_evidence_search"],
    )

    with patch("black_onyx.mcp.session_client.SessionPlatformClient") as client_cls, patch(
        "black_onyx.llm.mcp_orchestrator.execute_tool",
        new=AsyncMock(return_value={"citations": [{"point_id": "1", "collection": "all-knowledge", "score": 0.9, "snippet": "hit"}]}),
    ) as execute_tool:
        client_cls.return_value.__aenter__.return_value = MagicMock()
        events = [event async for event in orch.run("find lateral movement evidence")]

    execute_tool.assert_awaited_once()
    assert ("tool", {"name": "black_onyx_evidence_search", "args": {"query": "lateral movement"}, "status": "running"}) in [
        (kind, payload) for kind, payload in events if kind == "tool" and payload.get("status") == "running"
    ]
    tokens = "".join(data for kind, data in events if kind == "token")
    assert "Found one hit." in tokens


@pytest.mark.asyncio
async def test_mcp_orchestrator_does_not_ask_for_approval_id() -> None:
    settings = SimpleNamespace(
        mcp_tools=SimpleNamespace(
            max_tool_rounds=3,
            lab_profile_id="anvil",
            tools={"sec_nmap_scan": McpToolPolicy(
                enabled=True, allow_private=True, allow_public=False,
                network_profile="lab", timeout_seconds=60,
            )},
        ),
        llm=SimpleNamespace(
            provider="local",
            rag=SimpleNamespace(system_prompt="Analyst system prompt."),
            openai_compatible=SimpleNamespace(thinking_level=None),
        ),
    )
    service = SimpleNamespace(settings=settings)
    principal = Principal("u1", "a@test", "A", Role.ANALYST)
    llm = MagicMock()
    llm._default_max_tokens = 1024
    llm.chat.side_effect = [
        ChatResponse(text=json.dumps({
            "tool": "sec_nmap_scan",
            "args": {"target": "10.88.0.2", "ports": "80"},
        })),
        ChatResponse(text="should not run"),
    ]
    orch = McpToolOrchestrator(
        service=service,
        app=MagicMock(),
        llm=llm,
        principal=principal,
        provider_name="local",
        selected_tools=["sec_nmap_scan"],
    )
    denial = (
        "Tool 'sec_nmap_scan' requires a matching, unused approval_id from "
        "an exact human-reviewed server preview."
    )
    with patch("black_onyx.mcp.session_client.SessionPlatformClient") as client_cls, patch(
        "black_onyx.llm.mcp_orchestrator.execute_tool",
        new=AsyncMock(return_value={"error": denial, "tool": "sec_nmap_scan"}),
    ):
        client_cls.return_value.__aenter__.return_value = MagicMock()
        events = [event async for event in orch.run("scan the lab host")]

    tokens = "".join(data for kind, data in events if kind == "token")
    assert "Preview" in tokens
    assert "allowlist" in tokens
    assert "approval_id" not in tokens
    assert llm.chat.call_count == 2
    assert "should not run" in tokens
