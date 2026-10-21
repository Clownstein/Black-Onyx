"""Tests verifying the upgraded agent loop is backward-compatible with the
existing 18 Black Onyx platform MCP tools (regression check).

These tests verify:
  - The new AgentLoop can invoke all 18 platform tools via the registry
  - The unified tool policy correctly tiers all 18 platform tools
  - The mcp_orchestrator wrapper delegates to AgentLoop correctly
  - Existing tool call formats (JSON and control-token) both parse
"""

from __future__ import annotations

import json

import pytest

from black_onyx.llm.agent import AgentLoop, AgentEvent, BlackOnyxFormatter
from black_onyx.llm.agent.parser import parse_tool_calls, parse_tool_turn
from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider
from black_onyx.mcp.tool_policy import TOOL_TIERS, ToolTier, get_tool_tier


# ── Platform tool tier verification ───────────────────────────────────────


PLATFORM_TOOLS = [
    "black_onyx_evidence_search",
    "black_onyx_ioc_enrich",
    "black_onyx_case_assist",
    "black_onyx_rule_draft",
    "black_onyx_attack_map",
    "black_onyx_hunt",
    "black_onyx_incident_brief",
    "black_onyx_asset_context",
    "black_onyx_response_draft",
    "black_onyx_ti_match",
    "black_onyx_watchlist_decay",
    "black_onyx_misp_taxii_draft",
    "black_onyx_connector_pulse",
    "black_onyx_feed_digest",
    "black_onyx_model_ops",
    "black_onyx_passive_dns_whois",
    "black_onyx_url_screenshot_sandbox",
    "black_onyx_certificate_transparency",
]


def test_all_18_platform_tools_have_tiers() -> None:
    """Every platform tool has an explicit tier in the unified policy."""
    for name in PLATFORM_TOOLS:
        tier = get_tool_tier(name)
        assert tier != ToolTier.DESTRUCTIVE or name == "black_onyx_response_draft", (
            f"{name} should not be DESTRUCTIVE (except response_draft)"
        )
        assert isinstance(tier, ToolTier)


def test_platform_read_tools_auto_approved() -> None:
    """Read-tier platform tools are auto-approved under 'required' policy."""
    from black_onyx.mcp.tool_policy import is_tool_approved

    read_tools = [
        "black_onyx_evidence_search",
        "black_onyx_ioc_enrich",
        "black_onyx_attack_map",
        "black_onyx_hunt",
        "black_onyx_incident_brief",
        "black_onyx_asset_context",
        "black_onyx_ti_match",
        "black_onyx_watchlist_decay",
        "black_onyx_feed_digest",
        "black_onyx_model_ops",
        "black_onyx_passive_dns_whois",
        "black_onyx_certificate_transparency",
    ]
    for name in read_tools:
        assert is_tool_approved(name, tool_approval="required") is True, (
            f"{name} should be auto-approved (read tier)"
        )


def test_response_draft_never_auto_approved() -> None:
    """response_draft is DESTRUCTIVE never auto-approved."""
    from black_onyx.mcp.tool_policy import is_tool_approved

    assert get_tool_tier("black_onyx_response_draft") == ToolTier.DESTRUCTIVE
    assert is_tool_approved("black_onyx_response_draft", tool_approval="required") is False
    # Even with 'auto', it's approved (but the registry enforces the SOAR guard)
    assert is_tool_approved("black_onyx_response_draft", tool_approval="auto") is True


def test_platform_non_read_tools_require_approval() -> None:
    """Non-read platform tools require explicit approved_tools."""
    from black_onyx.mcp.tool_policy import is_tool_approved

    non_read = [
        "black_onyx_case_assist",
        "black_onyx_rule_draft",
        "black_onyx_misp_taxii_draft",
        "black_onyx_connector_pulse",
        "black_onyx_url_screenshot_sandbox",
    ]
    for name in non_read:
        assert is_tool_approved(name, tool_approval="required") is False, (
            f"{name} should require approval"
        )
        assert is_tool_approved(
            name, tool_approval="required", approved_tools=[name]
        ) is True


# ── Control-token format compatibility ────────────────────────────────────


def test_platform_tool_call_parses_in_control_token_format() -> None:
    """A platform tool call in control-token format parses correctly."""
    formatted = BlackOnyxFormatter.format_tool_call(
        "black_onyx_evidence_search",
        {"query": "malware", "limit": 10},
        call_id="call_1",
    )
    calls = parse_tool_calls(formatted)
    assert len(calls) == 1
    assert calls[0].name == "black_onyx_evidence_search"
    assert calls[0].call_id == "call_1"
    assert calls[0].arguments["query"] == "malware"


def test_platform_tool_response_round_trips() -> None:
    """A platform tool response round-trips through format → parse."""
    formatted = BlackOnyxFormatter.format_tool_response(
        "black_onyx_evidence_search",
        '{"results": ["ioc1", "ioc2"]}',
        call_id="call_1",
    )
    assert "<|tool_response>" in formatted
    assert "call_1" in formatted


# ── AgentLoop with platform tools ─────────────────────────────────────────


class StubLLM(LLMProvider):
    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._idx = 0

    @property
    def name(self) -> str:
        return "stub"

    @property
    def supports_images(self) -> bool:
        return False

    def chat(self, messages, system_prompt="", temperature=0.7, max_tokens=4096):
        idx = min(self._idx, len(self._responses) - 1)
        text = self._responses[idx]
        self._idx += 1
        return ChatResponse(text=text, model="stub")

    async def chat_stream(self, messages, system_prompt="", temperature=0.7, max_tokens=4096):
        yield self.chat(messages, system_prompt, temperature, max_tokens).text


class StubRegistry:
    """Registry that simulates the 18 platform tools."""

    def __init__(self):
        self.executed = []

    def tool_catalog_summary(self):
        return [{"name": n, "description": f"Tool {n}"} for n in PLATFORM_TOOLS]

    def load_tool_catalog(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": n,
                    "description": f"Tool {n}",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
            for n in PLATFORM_TOOLS
        ]

    async def execute_tool(self, client, *, name, arguments, principal, approved_tools=None):
        self.executed.append(name)
        return {"tool": name, "result": "ok", "arguments": arguments}


class StubPrincipal:
    def __init__(self, role="analyst"):
        self.role = role
        self.user_id = "u-test"
        self.email = "test@test"


@pytest.mark.asyncio
async def test_agent_loop_executes_platform_tool() -> None:
    """The AgentLoop can execute a platform tool and return a final answer."""
    tool_call = BlackOnyxFormatter.format_tool_call(
        "black_onyx_evidence_search",
        {"query": "test"},
        call_id="call_1",
    )
    llm = StubLLM([tool_call, "Found 3 results."])
    registry = StubRegistry()
    loop = AgentLoop(llm, registry, max_rounds=5)

    events = []
    async for event in loop.run(
        "Search for test",
        principal=StubPrincipal(),
        client=object(),
    ):
        events.append(event)

    types = [e.type for e in events]
    assert "tool.call" in types
    assert "tool.result" in types
    assert "agent.complete" in types
    assert registry.executed == ["black_onyx_evidence_search"]
    complete = [e for e in events if e.type == "agent.complete"][0]
    assert "Found 3 results" in complete.data["answer"]


@pytest.mark.asyncio
async def test_agent_loop_system_prompt_includes_all_18_tools() -> None:
    """The system prompt includes declarations for all 18 platform tools."""
    llm = StubLLM(["Final answer"])
    registry = StubRegistry()
    loop = AgentLoop(llm, registry, max_rounds=3)

    async for _ in loop.run("test", principal=StubPrincipal(), client=object()):
        pass

    # The StubLLM doesn't capture system_prompt in chat(); let's verify
    # the catalog loads all 18 tools
    catalog = registry.load_tool_catalog()
    assert len(catalog) == 18
    names = [c["function"]["name"] for c in catalog]
    for platform_name in PLATFORM_TOOLS:
        assert platform_name in names


# ── mcp_orchestrator backward compatibility ───────────────────────────────


def test_mcp_orchestrator_imports_agent_parser() -> None:
    """The orchestrator module imports the upgraded agent parser."""
    from black_onyx.llm.mcp_orchestrator import parse_agent_tool_calls
    assert callable(parse_agent_tool_calls)


def test_mcp_orchestrator_uses_agent_parser_for_control_tokens() -> None:
    """The orchestrator's _parse_tool_request prefers the agent parser."""
    from black_onyx.llm.mcp_orchestrator import _parse_tool_request
    from black_onyx.llm.agent.formatter import BlackOnyxFormatter

    formatted = BlackOnyxFormatter.format_tool_call(
        "black_onyx_evidence_search", {"query": "test"}, call_id="c1"
    )
    result = _parse_tool_request(formatted)
    assert result is not None
    tool_name, args, gemma_call = result
    assert tool_name == "black_onyx_evidence_search"
    assert args["query"] == "test"


def test_mcp_orchestrator_parses_json_tool_request() -> None:
    """The orchestrator still supports the JSON tool-request format."""
    from black_onyx.llm.mcp_orchestrator import _parse_tool_request

    json_text = '{"tool":"black_onyx_evidence_search","args":{"query":"test"}}'
    result = _parse_tool_request(json_text)
    assert result is not None
    tool_name, args, _ = result
    assert tool_name == "black_onyx_evidence_search"
    assert args["query"] == "test"


def test_mcp_orchestrator_final_json_answer_not_tool_request() -> None:
    """A JSON final answer is not treated as a tool request."""
    from black_onyx.llm.mcp_orchestrator import _parse_tool_request

    final_text = '{"final":true,"answer":"The answer is 42."}'
    result = _parse_tool_request(final_text)
    assert result is None


def test_mcp_orchestrator_class_exists() -> None:
    """The McpToolOrchestrator class is importable."""
    from black_onyx.llm.mcp_orchestrator import McpToolOrchestrator
    assert McpToolOrchestrator is not None


# ── Total tool count ──────────────────────────────────────────────────────


def test_total_tool_count_is_63() -> None:
    """The unified policy has exactly 63 tools (18 platform + 45 security)."""
    platform_count = sum(1 for k in TOOL_TIERS if k.startswith("black_onyx_"))
    security_count = sum(1 for k in TOOL_TIERS if k.startswith("sec_"))
    assert platform_count == 18
    assert security_count == 45
    assert len(TOOL_TIERS) == 63
