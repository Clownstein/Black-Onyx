"""Tests for the multi-turn AgentLoop.

Uses a mock LLM provider and a mock tool registry to verify:
  - Single-round (no tool calls) → immediate final answer
  - Multi-round (tool call → result → final answer)
  - Max rounds exhaustion → forced final answer
  - Tool result truncation
  - History compaction
  - System prompt includes tool declarations and safety rules
"""

from __future__ import annotations

import pytest

from black_onyx.llm.agent.formatter import BlackOnyxFormatter
from black_onyx.llm.agent.loop import (
    AgentEvent,
    AgentLoop,
    MAX_TOOL_RESULT_CHARS,
    MAX_TOOL_CONTEXT_TOKENS,
)
from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider


# ── Mock LLM ─────────────────────────────────────────────────────────────


class MockLLM(LLMProvider):
    """Returns pre-programmed responses in sequence."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._calls = 0
        self._last_messages: list[ChatMessage] | None = None
        self._last_system_prompt: str = ""

    @property
    def name(self) -> str:
        return "mock"

    @property
    def supports_images(self) -> bool:
        return False

    def chat(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        self._last_messages = list(messages)
        self._last_system_prompt = system_prompt
        idx = min(self._calls, len(self._responses) - 1)
        text = self._responses[idx]
        self._calls += 1
        return ChatResponse(text=text, model="mock")

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        yield self.chat(messages, system_prompt, temperature, max_tokens).text


# ── Mock registry ─────────────────────────────────────────────────────────


class MockRegistry:
    """Minimal registry that returns canned tool results."""

    def __init__(self, results: dict[str, str] | None = None) -> None:
        self._results = results or {}
        self._executed: list[tuple[str, dict]] = []

    def tool_catalog_summary(self) -> list[dict[str, str]]:
        return [{"name": "sec_decode_hex", "description": "Decode hex", "category": "crypto"}]

    def load_tool_catalog(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "sec_decode_hex",
                    "description": "Decode hex to ASCII",
                    "parameters": {
                        "type": "object",
                        "properties": {"data": {"type": "string"}},
                        "required": ["data"],
                    },
                },
            }
        ]

    async def execute_tool(
        self, client, *, name, arguments, principal, approved_tools=None
    ) -> dict:
        self._executed.append((name, arguments))
        return {"output": self._results.get(name, f"result for {name}")}


class MockPrincipal:
    def __init__(self, role="analyst"):
        self.role = role
        self.user_id = "u-test"
        self.email = "test@test"


# ── Tests ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_single_round_no_tool_calls() -> None:
    """When the LLM returns plain text (no tool calls), the loop completes in one round."""
    llm = MockLLM(["The answer is 42."])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry, max_rounds=5)

    events = []
    async for event in loop.run("What is the answer?", principal=MockPrincipal(), client=object()):
        events.append(event)

    types = [e.type for e in events]
    assert "message.delta" in types
    assert "agent.complete" in types
    assert "tool.call" not in types
    complete = [e for e in events if e.type == "agent.complete"][0]
    assert complete.data["answer"] == "The answer is 42."
    assert complete.data["rounds"] == 1


@pytest.mark.asyncio
async def test_multi_round_with_tool_call() -> None:
    """A tool call followed by a final answer takes 2 rounds."""
    tool_call = BlackOnyxFormatter.format_tool_call(
        "sec_decode_hex", {"data": "48656c6c6f"}, call_id="call_1"
    )
    llm = MockLLM([tool_call, "The decoded value is: Hello"])
    registry = MockRegistry(results={"sec_decode_hex": "Hello"})
    loop = AgentLoop(llm, registry, max_rounds=5)

    events = []
    async for event in loop.run("Decode 48656c6c6f", principal=MockPrincipal(), client=object()):
        events.append(event)

    types = [e.type for e in events]
    assert "tool.call" in types
    assert "tool.result" in types
    assert "agent.complete" in types
    complete = [e for e in events if e.type == "agent.complete"][0]
    assert complete.data["rounds"] == 2
    assert "Hello" in complete.data["answer"]
    # The tool was executed with the right arguments
    assert len(registry._executed) == 1
    assert registry._executed[0][0] == "sec_decode_hex"
    assert registry._executed[0][1]["data"] == "48656c6c6f"


@pytest.mark.asyncio
async def test_max_rounds_exhaustion() -> None:
    """When max_rounds is exhausted, a forced final answer is emitted."""
    tool_call = BlackOnyxFormatter.format_tool_call("sec_decode_hex", {"data": "ab"})
    # Always return a tool call never a final answer
    llm = MockLLM([tool_call, tool_call, "Forced final answer"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry, max_rounds=2)

    events = []
    async for event in loop.run("Keep calling tools", principal=MockPrincipal(), client=object()):
        events.append(event)

    complete = [e for e in events if e.type == "agent.complete"][0]
    assert complete.data["rounds"] == 2
    assert "Forced final answer" in complete.data["answer"]


@pytest.mark.asyncio
async def test_tool_result_truncation() -> None:
    """Tool results longer than MAX_TOOL_RESULT_CHARS are truncated."""
    long_result = "x" * (MAX_TOOL_RESULT_CHARS + 1000)
    tool_call = BlackOnyxFormatter.format_tool_call("sec_decode_hex", {"data": "ab"})
    llm = MockLLM([tool_call, "Final answer"])
    registry = MockRegistry(results={"sec_decode_hex": long_result})
    loop = AgentLoop(llm, registry, max_rounds=5)

    events = []
    async for event in loop.run("Run tool", principal=MockPrincipal(), client=object()):
        events.append(event)

    # The second LLM call should have received a truncated tool response
    # Check the messages sent to the LLM in the second call
    second_call_messages = llm._last_messages
    # The last message should contain the truncated result
    last_msg = second_call_messages[-1].content
    assert "...[truncated]" in last_msg
    assert len(last_msg) < len(long_result)


@pytest.mark.asyncio
async def test_system_prompt_includes_tool_declarations() -> None:
    """The system prompt contains tool declarations and safety rules."""
    llm = MockLLM(["Final answer"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry, max_rounds=5)

    async for _ in loop.run("test", principal=MockPrincipal(), client=object()):
        pass

    sys_prompt = llm._last_system_prompt
    assert "sec_decode_hex" in sys_prompt
    assert "UNTRUSTED" in sys_prompt
    assert "SOAR" in sys_prompt


@pytest.mark.asyncio
async def test_conversation_history_stripped_of_thoughts() -> None:
    """Prior conversation history has thought blocks stripped."""
    from black_onyx.llm.agent.parser import strip_thoughts

    llm = MockLLM(["Final answer"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry, max_rounds=5)

    history = [
        ChatMessage(role="user", content="<|channel>thought secret thinking<channel|>Hello"),
        ChatMessage(role="assistant", content="<|channel>thought inner<channel|>Hi there"),
    ]

    async for _ in loop.run(
        "next message",
        conversation_history=history,
        principal=MockPrincipal(),
        client=object(),
    ):
        pass

    # The first message in the LLM's input should not contain thought blocks
    first_msg = llm._last_messages[0].content
    assert "<|channel>thought" not in first_msg
    assert "Hello" in first_msg


@pytest.mark.asyncio
async def test_multiple_tool_calls_in_one_turn() -> None:
    """Multiple tool calls in a single LLM turn are all executed."""
    call1 = BlackOnyxFormatter.format_tool_call("sec_decode_hex", {"data": "ab"}, call_id="c1")
    call2 = BlackOnyxFormatter.format_tool_call("sec_decode_hex", {"data": "cd"}, call_id="c2")
    llm = MockLLM([call1 + call2, "Done"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry, max_rounds=5)

    events = []
    async for event in loop.run("Decode both", principal=MockPrincipal(), client=object()):
        events.append(event)

    tool_calls = [e for e in events if e.type == "tool.call"]
    assert len(tool_calls) == 2
    assert tool_calls[0].data["call_id"] == "c1"
    assert tool_calls[1].data["call_id"] == "c2"
    assert len(registry._executed) == 2


@pytest.mark.asyncio
async def test_no_client_no_principal_returns_error_result() -> None:
    """Without a client/principal, tool execution returns an error dict."""
    tool_call = BlackOnyxFormatter.format_tool_call("sec_decode_hex", {"data": "ab"})
    llm = MockLLM([tool_call, "Final answer"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry, max_rounds=5)

    events = []
    async for event in loop.run("Run tool"):
        events.append(event)

    tool_results = [e for e in events if e.type == "tool.result"]
    assert len(tool_results) == 1
    assert "error" in tool_results[0].data["result"]


def test_estimate_tokens() -> None:
    """Token estimation uses chars/4 heuristic."""
    assert AgentLoop._estimate_tokens("abcd") == 1
    assert AgentLoop._estimate_tokens("") == 0
    assert AgentLoop._estimate_tokens("a" * 100) == 25


def test_compact_history_preserves_short_history() -> None:
    """Short history is not compacted."""
    llm = MockLLM(["answer"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry)
    messages = [ChatMessage(role="user", content="short")]
    assert loop._compact_history(messages) is messages


def test_compact_history_truncates_long_history() -> None:
    """History exceeding the token budget is truncated to system + last 6."""
    llm = MockLLM(["answer"])
    registry = MockRegistry()
    loop = AgentLoop(llm, registry)
    # Create 20 messages that exceed MAX_TOOL_CONTEXT_TOKENS (25000 tokens)
    # 20 messages × 6000 chars / 4 = 30000 tokens > 25000
    messages = [ChatMessage(role="user", content="x" * 6000) for _ in range(20)]
    compacted = loop._compact_history(messages)
    # Should keep first + last 6 = 7 messages
    assert len(compacted) == 7
