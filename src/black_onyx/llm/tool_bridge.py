"""Bridge Gemma 4 native tool tokens and the platform JSON tool protocol."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# Gemma 4 control tokens (see docs/BLACK_ONYX_5B_INTEGRATION.md).
_GEMMA_TOOL_CALL_BLOCK = re.compile(r"<\|tool_call>(.*?)<tool_call\|>", re.DOTALL)
_GEMMA_TOOL_RESPONSE_BLOCK = re.compile(r"<\|tool_response>(.*?)<tool_response\|>", re.DOTALL)
_GEMMA_THOUGHT_BLOCK = re.compile(r"<\|channel>thought.*?<channel\|>", re.DOTALL)
_GEMMA_STRING = re.compile(r"<\|\"?\|>(.*?)<\|\"?\|>", re.DOTALL)
_GEMMA_TOOL_INNER = re.compile(r"^call:([^{\s]+)(\{.*\})\s*$", re.DOTALL)

# Web-search orchestrator tool names (MCP tools are not executed in that loop).
_WEB_TOOL_ALIASES: dict[str, str] = {
    "web_search": "web_search",
    "scrape_url": "scrape_url",
    "firecrawl_scrape": "scrape_url",
}


@dataclass
class ParsedToolCall:
    name: str
    call_id: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedToolTurn:
    final_answer: str | None = None
    tool_calls: list[ParsedToolCall] = field(default_factory=list)
    cleaned_text: str = ""


def strip_gemma_control_blocks(text: str) -> str:
    """Remove Gemma thought/tool control tokens before persisting assistant turns."""
    value = text or ""
    value = _GEMMA_THOUGHT_BLOCK.sub("", value)
    value = _GEMMA_TOOL_CALL_BLOCK.sub("", value)
    value = _GEMMA_TOOL_RESPONSE_BLOCK.sub("", value)
    return value.strip()


def _decode_gemma_strings(raw: str) -> str:
    return _GEMMA_STRING.sub(lambda match: json.dumps(match.group(1))[1:-1], raw)


def _parse_gemma_args(raw_args: str) -> dict[str, Any]:
    """Parse Gemma `{key:value,...}` argument blobs into a JSON-like dict."""
    body = (raw_args or "").strip()
    if not body.startswith("{") or not body.endswith("}"):
        return {}
    inner = body[1:-1].strip()
    if not inner:
        return {}

    decoded = _decode_gemma_strings(inner)
    # Quote bare keys and unquoted string values heuristically.
    normalized = re.sub(
        r"([,{]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:",
        r'\1"\2":',
        "{" + decoded + "}",
    )
    normalized = re.sub(
        r':\s*([^",\{\[\]\}][^,\}\]]*?)(?=[,\}])',
        lambda match: f":{json.dumps(match.group(1).strip())}",
        normalized,
    )
    try:
        parsed = json.loads(normalized)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def parse_gemma_tool_call(block: str) -> ParsedToolCall | None:
    """Parse one Gemma `<|tool_call>call:name{args}<tool_call|>` payload."""
    payload = (block or "").strip()
    match = _GEMMA_TOOL_INNER.match(payload)
    if not match:
        return None
    name = match.group(1).strip()
    args = _parse_gemma_args(match.group(2))
    call_id = str(args.pop("call_id", "") or args.pop("id", "") or f"call_{name}")
    return ParsedToolCall(name=name, call_id=call_id, arguments=args)


def parse_gemma_tool_calls(text: str) -> list[ParsedToolCall]:
    calls: list[ParsedToolCall] = []
    for block in _GEMMA_TOOL_CALL_BLOCK.findall(text or ""):
        parsed = parse_gemma_tool_call(block)
        if parsed:
            calls.append(parsed)
    return calls


def format_gemma_tool_response(name: str, content: str, *, call_id: str = "") -> str:
    """Format a tool result for Gemma-native multi-turn prompts."""
    header = f"call:{call_id or name}"
    body = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
    return f"<|tool_response>{header}{{{body}}}<tool_response|>"


def gemma_tool_to_json_protocol(call: ParsedToolCall) -> dict[str, Any] | None:
    """Map a Gemma tool call onto the web-search orchestrator JSON contract."""
    tool = _WEB_TOOL_ALIASES.get(call.name, call.name)
    if tool == "web_search":
        query = str(call.arguments.get("query") or call.arguments.get("q") or "").strip()
        if not query:
            return None
        return {"tool": "web_search", "args": {"query": query}}
    if tool == "scrape_url":
        url = str(call.arguments.get("url") or call.arguments.get("link") or "").strip()
        if not url:
            return None
        return {"tool": "scrape_url", "args": {"url": url}}
    return None


def parse_tool_turn(text: str) -> ParsedToolTurn:
    """Parse an assistant turn that may contain Gemma tool calls or plain text."""
    raw = text or ""
    tool_calls = parse_gemma_tool_calls(raw)
    cleaned = strip_gemma_control_blocks(raw)
    if tool_calls:
        return ParsedToolTurn(final_answer=None, tool_calls=tool_calls, cleaned_text=cleaned)
    answer = cleaned.strip()
    return ParsedToolTurn(
        final_answer=answer or None,
        tool_calls=[],
        cleaned_text=cleaned,
    )


def _gemma_literal(value: Any) -> str:
    if isinstance(value, str):
        return f'<|"|>{value}<|"|>'
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "null"
    return json.dumps(value, ensure_ascii=False)


def openai_tool_call_to_gemma(name: str, arguments: dict[str, Any] | str, *, call_id: str = "") -> str:
    """Convert an OpenAI-style tool call into Gemma 4 native syntax for fine-tuning."""
    if isinstance(arguments, str):
        try:
            args_obj = json.loads(arguments)
        except json.JSONDecodeError:
            args_obj = {"raw": arguments}
    else:
        args_obj = dict(arguments or {})

    parts = [f"{key}:{_gemma_literal(value)}" for key, value in args_obj.items()]
    args_blob = "{" + ",".join(parts) + "}"
    _ = call_id or f"call_{name}"
    return f"<|tool_call>call:{name}{args_blob}<tool_call|>"


def openai_tools_to_gemma_declarations(tools: list[dict[str, Any]]) -> str:
    """Convert OpenAI-style tool schemas into Gemma 4 `<|tool>…<tool|>` declarations."""
    blocks: list[str] = []
    for item in tools:
        if item.get("type") != "function":
            continue
        fn = item.get("function") or {}
        name = str(fn.get("name") or "").strip()
        if not name:
            continue
        description = str(fn.get("description") or "").strip()
        parameters = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {}
        props = parameters.get("properties") if isinstance(parameters.get("properties"), dict) else {}
        required = parameters.get("required") if isinstance(parameters.get("required"), list) else []

        param_parts: list[str] = []
        for key, schema in props.items():
            if not isinstance(schema, dict):
                continue
            ptype = schema.get("type") or "string"
            pdesc = str(schema.get("description") or "").strip()
            fields = [f"type:{_gemma_literal(ptype)}"]
            if pdesc:
                fields.append(f"description:{_gemma_literal(pdesc)}")
            if "default" in schema:
                fields.append(f"default:{_gemma_literal(schema['default'])}")
            if key in required:
                fields.append("required:true")
            param_parts.append(f"{key}:{{{','.join(fields)}}}")

        header_parts = [f"description:{_gemma_literal(description)}"] if description else []
        if param_parts:
            header_parts.append("parameters:{" + ",".join(param_parts) + "}")
        body = "{" + ",".join(header_parts) + "}" if header_parts else "{}"
        blocks.append(f"<|tool>{name}{body}<tool|>")
    return "\n".join(blocks)


def effective_system_prompt(
    base: str,
    llm_config: Any,
    provider_name: str,
    *,
    purpose: str | None = None,
) -> str:
    """Append optional purpose and provider-specific system instructions."""
    parts = [base.strip()] if (base or "").strip() else []
    if purpose == "investigation":
        parts.append(
            "Produce suggest-only investigation notes in Markdown. "
            "Do not instruct automatic containment, playbook execution, or case closure. "
            "Mark hypotheses as hypotheses. Reference incident fields literally when present."
        )
    if provider_name == "openai_compatible":
        level = getattr(getattr(llm_config, "openai_compatible", None), "thinking_level", None)
        if level and str(level).upper() == "LOW":
            parts.append(
                "Use LOW thinking depth: keep internal reasoning brief and prioritize concise answers."
            )
    return "\n\n".join(parts)
