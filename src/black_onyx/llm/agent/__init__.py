"""Agent loop, parser, and formatter merged from model-tools.

Provides the upgraded multi-turn agent loop with Black Onyx control-token
parsing, round-trippable formatting, and tiered tool approval. Uses Black
Onyx's LLMProvider abstraction (6 providers) instead of the OpenAI
Responses API.
"""
from black_onyx.llm.agent.formatter import BlackOnyxFormatter
from black_onyx.llm.agent.loop import AgentEvent, AgentLoop
from black_onyx.llm.agent.parser import (
    ParsedToolCall,
    ParsedToolTurn,
    parse_tool_call,
    parse_tool_calls,
    parse_tool_turn,
    strip_control_blocks,
    strip_thoughts,
)

__all__ = [
    "AgentLoop",
    "AgentEvent",
    "BlackOnyxFormatter",
    "ParsedToolCall",
    "ParsedToolTurn",
    "parse_tool_call",
    "parse_tool_calls",
    "parse_tool_turn",
    "strip_control_blocks",
    "strip_thoughts",
]
