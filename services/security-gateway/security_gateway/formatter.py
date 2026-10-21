"""Black Onyx control-token formatter.

Merged from model-tools/agent/formatter.py. Serializes tool calls, responses,
and declarations with proper string escaping round-trippable with the
recursive descent parser in parser.py.
"""
from __future__ import annotations

import json
import re
from typing import Any

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_CALL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# String delimiter used by the Black Onyx token format
_STRING_DELIM = '<|"|>'
# Escaped form of the delimiter inside strings
_STRING_DELIM_ESCAPED = '<|\\"|>'


class BlackOnyxFormatter:
    """Format tool calls, responses, and declarations as Black Onyx control tokens."""

    @staticmethod
    def escape_string(value: str) -> str:
        """Escape the string delimiter inside a value."""
        return (value or "").replace(_STRING_DELIM, _STRING_DELIM_ESCAPED)

    @staticmethod
    def format_value(value: Any) -> str:
        """Serialize a Python value into the token format."""
        if isinstance(value, str):
            return f"{_STRING_DELIM}{BlackOnyxFormatter.escape_string(value)}{_STRING_DELIM}"
        if isinstance(value, bool):
            return str(value).lower()
        if value is None:
            return "null"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "[" + ",".join(BlackOnyxFormatter.format_value(v) for v in value) + "]"
        if isinstance(value, dict):
            parts = [f"{k}:{BlackOnyxFormatter.format_value(v)}" for k, v in value.items()]
            return "{" + ",".join(parts) + "}"
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def format_tool_call(name: str, arguments: dict[str, Any], *, call_id: str = "") -> str:
        """Format a tool call: `<|tool_call>call:name:call_id{args}<tool_call|>`."""
        if not _NAME_RE.match(name):
            raise ValueError(f"Invalid tool name: {name!r}")
        cid = call_id or f"call_{name}"
        if not _CALL_ID_RE.match(cid):
            raise ValueError(f"Invalid call_id: {cid!r}")
        parts = [f"{k}:{BlackOnyxFormatter.format_value(v)}" for k, v in arguments.items()]
        args_blob = "{" + ",".join(parts) + "}"
        return f"<|tool_call>call:{name}:{cid}{args_blob}<tool_call|>"

    @staticmethod
    def format_tool_response(name: str, content: str | dict[str, Any], *, call_id: str = "") -> str:
        """Format a tool response: `<|tool_response>response:name{...}<tool_response|>`."""
        header = f"response:{call_id or name}"
        if isinstance(content, str):
            body = content
        else:
            body = json.dumps(content, ensure_ascii=False)
        escaped = BlackOnyxFormatter.escape_string(body)
        return (
            f"<|tool_response>{header}{{status:{_STRING_DELIM}success{_STRING_DELIM},"
            f"output:{_STRING_DELIM}{escaped}{_STRING_DELIM}}}"
            f"<tool_response|>"
        )

    @staticmethod
    def format_declaration(name: str, description: str, parameters: dict[str, Any]) -> str:
        """Format a tool declaration: `<|tool>declaration:name{...}<tool|>`."""
        if not _NAME_RE.match(name):
            raise ValueError(f"Invalid tool name: {name!r}")
        header_parts = [f"description:{_STRING_DELIM}{description}{_STRING_DELIM}"]
        if parameters:
            header_parts.append(f"parameters:{BlackOnyxFormatter.format_value(parameters)}")
        body = "{" + ",".join(header_parts) + "}"
        return f"<|tool>declaration:{name}{body}<tool|>"

    @staticmethod
    def format_thought(content: str) -> str:
        """Format a thought block: `<|channel>thought ... <channel|>`."""
        return f"<|channel>thought\n{content}\n<channel|>"
