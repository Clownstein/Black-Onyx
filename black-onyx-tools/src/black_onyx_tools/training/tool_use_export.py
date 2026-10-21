"""Export tool-use datasets for OpenAI, Hugging Face, and Gemma 4 trainers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from black_onyx_tools.training.tool_use_dataset import ToolUseExample, iter_openai_rows


def write_jsonl(path: Path, rows: Iterator[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def export_openai_finetune(examples: list[ToolUseExample], out_path: Path) -> int:
    return write_jsonl(out_path, iter_openai_rows(examples))


def export_gemma_native(examples: list[ToolUseExample], out_path: Path) -> int:
    def _rows() -> Iterator[dict[str, Any]]:
        for row in examples:
            if row.format != "gemma4_native":
                continue
            yield {"messages": row.messages}

    return write_jsonl(out_path, _rows())


def _gemma_literal(value: Any) -> str:
    if isinstance(value, str):
        return f'<|"|>{value}<|"|>'
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "null"
    return json.dumps(value, ensure_ascii=False)


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


def export_gemma_declarations(tools: list[dict[str, Any]], out_path: Path) -> int:
    """Write a Gemma `<|tool>` declaration block file from tools.json."""
    text = openai_tools_to_gemma_declarations(tools)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text + ("\n" if text else ""), encoding="utf-8")
    return len([line for line in text.splitlines() if line.strip()])


def export_hf_sft(
    examples: list[ToolUseExample],
    out_path: Path,
    *,
    template: str = "openai",
) -> int:
    """Export chat rows for TRL/HF SFT (`messages` column JSONL)."""

    def _rows() -> Iterator[dict[str, Any]]:
        for row in examples:
            if template == "gemma" and row.format == "gemma4_native":
                yield {"messages": row.messages}
            elif template != "gemma":
                payload = {"messages": row.messages}
                if row.tools:
                    payload["tools"] = row.tools
                yield payload

    return write_jsonl(out_path, _rows())
