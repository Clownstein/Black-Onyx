"""Black Onyx control-token parser (recursive descent).

Merged from model-tools/agent/parser.py. Handles nested objects, escaped
delimiters, multiple calls per turn, optional call_id, and strips residual
control tokens from final text.

Token grammar:
  Tool call:      <|tool_call>call:name:call_id{args}<tool_call|>
  Tool response:  <|tool_response>response:name{...}<tool_response|>
  Thought:        <|channel>thought ... <channel|>
  String delimiter: <|"|>...<|"|> (escaped as <|\\"|> inside strings)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

_TOOL_CALL_BLOCK = re.compile(r"<\|tool_call>(.*?)<tool_call\|>", re.DOTALL)
_TOOL_RESPONSE_BLOCK = re.compile(r"<\|tool_response>(.*?)<tool_response\|>", re.DOTALL)
_THOUGHT_BLOCK = re.compile(r"<\|channel>thought.*?<channel\|>", re.DOTALL)
_STRING = re.compile(r"<\|\"?\|>(.*?)<\|\"?\|>", re.DOTALL)
_TOOL_INNER = re.compile(r"^call:([^{\s]+)(\{.*\})\s*$", re.DOTALL)


@dataclass
class ParsedToolCall:
    """A single parsed tool call."""
    name: str
    call_id: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedToolTurn:
    """The result of parsing one assistant turn."""
    final_answer: str | None = None
    tool_calls: list[ParsedToolCall] = field(default_factory=list)
    cleaned_text: str = ""


def strip_control_blocks(text: str) -> str:
    """Remove thought/tool control tokens before persisting assistant turns."""
    value = text or ""
    value = _THOUGHT_BLOCK.sub("", value)
    value = _TOOL_CALL_BLOCK.sub("", value)
    value = _TOOL_RESPONSE_BLOCK.sub("", value)
    return value.strip()


def strip_thoughts(text: str) -> str:
    """Remove only thought blocks (keep tool calls for multi-turn context)."""
    return _THOUGHT_BLOCK.sub("", text or "")


def _decode_strings(raw: str) -> str:
    """Convert <|"|>string<|"|> delimiters to JSON-quoted strings."""
    return _STRING.sub(lambda m: json.dumps(m.group(1))[1:-1], raw)


def _parse_args(raw_args: str) -> dict[str, Any]:
    """Parse Gemma `{key:value,...}` argument blobs into a JSON-like dict.

    Handles:
    - Already-valid JSON (including URLs with ``://``)
    - <|"|> delimited strings
    - Bare (unquoted) keys
    - Unquoted string values
    - Nested objects and arrays
    """
    body = (raw_args or "").strip()
    if not body.startswith("{") or not body.endswith("}"):
        return {}
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    inner = body[1:-1].strip()
    if not inner:
        return {}

    decoded = _decode_strings(inner)
    # Quote bare keys and unquoted string values heuristically.
    normalized = re.sub(
        r"([,{]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:",
        r'\1"\2":',
        "{" + decoded + "}",
    )
    normalized = re.sub(
        r':\s*([^",\{\[\]\}][^,\}\]]*?)(?=[,\}])',
        lambda m: f":{json.dumps(m.group(1).strip())}",
        normalized,
    )
    try:
        parsed = json.loads(normalized)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def parse_tool_call(block: str) -> ParsedToolCall | None:
    """Parse one `<|tool_call>call:name:call_id{args}<tool_call|>` payload."""
    payload = (block or "").strip()
    match = _TOOL_INNER.match(payload)
    if not match:
        return None
    name = match.group(1).strip()
    # Strip optional :call_id suffix from the name
    if ":" in name:
        name, call_id = name.split(":", 1)
        call_id = call_id.strip()
    else:
        call_id = ""
    args = _parse_args(match.group(2))
    call_id = str(args.pop("call_id", "") or args.pop("id", "") or call_id or f"call_{name}")
    return ParsedToolCall(name=name, call_id=call_id, arguments=args)


def parse_tool_calls(text: str) -> list[ParsedToolCall]:
    """Extract all tool calls from a text block."""
    calls: list[ParsedToolCall] = []
    for block in _TOOL_CALL_BLOCK.findall(text or ""):
        parsed = parse_tool_call(block)
        if parsed:
            calls.append(parsed)
    return calls


def parse_tool_turn(text: str) -> ParsedToolTurn:
    """Parse an assistant turn that may contain tool calls or plain text.

    If tool calls are found, final_answer is None (the loop continues).
    Otherwise, the cleaned text becomes the final answer.
    """
    raw = text or ""
    tool_calls = parse_tool_calls(raw)
    cleaned = strip_control_blocks(raw)
    if tool_calls:
        return ParsedToolTurn(final_answer=None, tool_calls=tool_calls, cleaned_text=cleaned)
    answer = cleaned.strip()
    return ParsedToolTurn(
        final_answer=answer or None,
        tool_calls=[],
        cleaned_text=cleaned,
    )
