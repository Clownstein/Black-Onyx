"""Tests for the Black Onyx control-token formatter."""

from __future__ import annotations

import pytest

from black_onyx.llm.agent.formatter import BlackOnyxFormatter
from black_onyx.llm.agent.parser import parse_tool_calls


def test_format_tool_call_round_trips() -> None:
    """A formatted tool call parses back to the same name and arguments."""
    formatted = BlackOnyxFormatter.format_tool_call(
        "sec_decode_hex", {"data": "48656c6c6f"}, call_id="call_2"
    )
    parsed = parse_tool_calls(formatted)
    assert len(parsed) == 1
    assert parsed[0].name == "sec_decode_hex"
    assert parsed[0].call_id == "call_2"
    assert parsed[0].arguments == {"data": "48656c6c6f"}


def test_format_tool_call_default_call_id() -> None:
    """A tool call without call_id gets a default of call_<name>."""
    formatted = BlackOnyxFormatter.format_tool_call("sec_nmap_scan", {"target": "10.0.0.1"})
    parsed = parse_tool_calls(formatted)
    assert len(parsed) == 1
    assert parsed[0].call_id == "call_sec_nmap_scan"


def test_format_tool_call_invalid_name() -> None:
    """An invalid tool name raises ValueError."""
    with pytest.raises(ValueError, match="Invalid tool name"):
        BlackOnyxFormatter.format_tool_call("123bad", {})


def test_format_tool_call_invalid_call_id() -> None:
    """An invalid call_id raises ValueError."""
    with pytest.raises(ValueError, match="Invalid call_id"):
        BlackOnyxFormatter.format_tool_call("valid_name", {}, call_id="bad call id!")


def test_format_tool_response_string() -> None:
    """A tool response with a string body formats correctly."""
    formatted = BlackOnyxFormatter.format_tool_response(
        "sec_nmap_scan", "scan complete", call_id="call_1"
    )
    assert "<|tool_response>" in formatted
    assert "<tool_response|>" in formatted
    assert "call_1" in formatted


def test_format_tool_response_dict() -> None:
    """A tool response with a dict body formats correctly."""
    formatted = BlackOnyxFormatter.format_tool_response(
        "sec_decode_hex", {"output": "Hello"}, call_id="call_2"
    )
    assert "<|tool_response>" in formatted


def test_format_declaration() -> None:
    """A tool declaration includes name, description, and parameters."""
    formatted = BlackOnyxFormatter.format_declaration(
        "sec_nmap_scan",
        "Run nmap against a target.",
        {"type": "object", "properties": {"target": {"type": "string"}}},
    )
    assert "<|tool>declaration:sec_nmap_scan" in formatted
    assert "<tool|>" in formatted
    assert "Run nmap against a target." in formatted


def test_format_declaration_invalid_name() -> None:
    """An invalid tool name in a declaration raises ValueError."""
    with pytest.raises(ValueError, match="Invalid tool name"):
        BlackOnyxFormatter.format_declaration("bad name", "", {})


def test_format_value_string() -> None:
    """A string value is wrapped in string delimiters."""
    result = BlackOnyxFormatter.format_value("hello")
    assert '<|"|>' in result
    assert "hello" in result


def test_format_value_integer() -> None:
    """An integer value is rendered as a bare number."""
    assert BlackOnyxFormatter.format_value(42) == "42"


def test_format_value_boolean() -> None:
    """A boolean value is rendered as lowercase true/false."""
    assert BlackOnyxFormatter.format_value(True) == "true"
    assert BlackOnyxFormatter.format_value(False) == "false"


def test_format_value_none() -> None:
    """None is rendered as null."""
    assert BlackOnyxFormatter.format_value(None) == "null"


def test_format_value_list() -> None:
    """A list is rendered as a bracket-enclosed comma-separated sequence."""
    result = BlackOnyxFormatter.format_value(["a", "b"])
    assert result.startswith("[")
    assert result.endswith("]")


def test_format_value_dict() -> None:
    """A dict is rendered as a brace-enclosed key:value sequence."""
    result = BlackOnyxFormatter.format_value({"key": "value"})
    assert result.startswith("{")
    assert result.endswith("}")


def test_escape_string_delimiter() -> None:
    """The string delimiter inside a value is escaped."""
    escaped = BlackOnyxFormatter.escape_string('before<|"|>after')
    assert '<|\\"|>' in escaped


def test_format_thought() -> None:
    """A thought block is wrapped in the thought channel tokens."""
    formatted = BlackOnyxFormatter.format_thought("thinking about this")
    assert "<|channel>thought" in formatted
    assert "<channel|>" in formatted
    assert "thinking about this" in formatted
