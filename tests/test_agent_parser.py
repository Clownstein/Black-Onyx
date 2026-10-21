"""Tests for the upgraded Black Onyx control-token parser."""

from __future__ import annotations

from black_onyx.llm.agent.parser import (
    ParsedToolCall,
    ParsedToolTurn,
    parse_tool_call,
    parse_tool_calls,
    parse_tool_turn,
    strip_control_blocks,
    strip_thoughts,
)


def test_parse_basic_tool_call() -> None:
    """A single tool call with one string argument parses correctly."""
    text = '<|tool_call>call:sec_nmap_scan:call_1{target:<|"|>127.0.0.1<|"|>}<tool_call|>'
    calls = parse_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].name == "sec_nmap_scan"
    assert calls[0].call_id == "call_1"
    assert calls[0].arguments == {"target": "127.0.0.1"}


def test_parse_tool_call_without_call_id() -> None:
    """A tool call without an explicit call_id gets a default."""
    text = '<|tool_call>call:sec_decode_hex{data:<|"|>48656c6c6f<|"|>}<tool_call|>'
    calls = parse_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].name == "sec_decode_hex"
    assert calls[0].arguments == {"data": "48656c6c6f"}
    assert calls[0].call_id == "call_sec_decode_hex"


def test_parse_multiple_tool_calls() -> None:
    """Multiple tool calls in one turn all parse."""
    text = (
        '<|tool_call>call:a{x:1}<tool_call|> some text '
        '<|tool_call>call:b{y:2}<tool_call|>'
    )
    calls = parse_tool_calls(text)
    assert len(calls) == 2
    assert calls[0].name == "a"
    assert calls[1].name == "b"


def test_parse_nested_object() -> None:
    """Nested objects in arguments parse correctly."""
    text = '<|tool_call>call:tool{params:{inner:<|"|>value<|"|>,num:42}}<tool_call|>'
    calls = parse_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].name == "tool"
    assert "params" in calls[0].arguments


def test_parse_plain_text_no_tool_calls() -> None:
    """Plain text with no tool calls yields an empty list."""
    calls = parse_tool_calls("This is a plain answer with no tools.")
    assert calls == []


def test_parse_tool_turn_with_tool_calls() -> None:
    """A turn with tool calls has final_answer=None and the calls listed."""
    text = 'Let me search... <|tool_call>call:sec_nmap_scan{target:<|"|>10.0.0.1<|"|>}<tool_call|>'
    turn = parse_tool_turn(text)
    assert turn.final_answer is None
    assert len(turn.tool_calls) == 1
    assert turn.tool_calls[0].name == "sec_nmap_scan"


def test_parse_tool_turn_plain_text() -> None:
    """A turn with plain text has final_answer set and no tool calls."""
    turn = parse_tool_turn("This is a plain answer with no tools.")
    assert turn.final_answer == "This is a plain answer with no tools."
    assert not turn.tool_calls


def test_strip_control_blocks() -> None:
    """strip_control_blocks removes all control token blocks."""
    text = (
        '<|channel>thought thinking<channel|>'
        '<|tool_call>call:x<tool_call|>'
        '<|tool_response>response:x{...}<tool_response|>'
        'remaining text'
    )
    stripped = strip_control_blocks(text)
    assert stripped == "remaining text"


def test_strip_thoughts_preserves_tool_calls() -> None:
    """strip_thoughts removes only thought blocks, keeping tool calls."""
    text = '<|channel>thought thinking<channel|><|tool_call>call:x<tool_call|>'
    stripped = strip_thoughts(text)
    assert "<|tool_call>" in stripped
    assert "<|channel>thought" not in stripped


def test_parse_empty_string() -> None:
    """An empty string yields no calls and an empty final answer."""
    calls = parse_tool_calls("")
    assert calls == []
    turn = parse_tool_turn("")
    assert turn.final_answer is None
    assert not turn.tool_calls


def test_parse_integer_argument() -> None:
    """Integer arguments parse to int values."""
    text = '<|tool_call>call:tool{count:42}<tool_call|>'
    calls = parse_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].arguments.get("count") == "42"


def test_parse_boolean_argument() -> None:
    """Boolean arguments parse to bool values."""
    text = '<|tool_call>call:tool{flag:true}<tool_call|>'
    calls = parse_tool_calls(text)
    assert len(calls) == 1
