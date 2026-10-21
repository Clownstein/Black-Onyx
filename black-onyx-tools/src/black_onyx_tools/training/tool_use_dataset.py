"""Load and validate Black Onyx MCP tool-use fine-tune datasets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

DEFAULT_DATASET_DIR = Path(__file__).resolve().parents[3] / "datasets" / "tool_use"


@dataclass
class DatasetIssue:
    example_id: str
    message: str


@dataclass
class ToolUseExample:
    id: str
    tool: str
    tags: list[str]
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] = field(default_factory=list)
    format: str = "openai"


def load_tools(catalog_path: Path | None = None) -> list[dict[str, Any]]:
    path = catalog_path or (DEFAULT_DATASET_DIR / "tools.json")
    return json.loads(path.read_text(encoding="utf-8"))


def load_examples(
    examples_path: Path | None = None,
    *,
    fmt: str = "openai",
) -> list[ToolUseExample]:
    if fmt == "gemma":
        path = examples_path or (DEFAULT_DATASET_DIR / "examples_gemma.jsonl")
    else:
        path = examples_path or (DEFAULT_DATASET_DIR / "examples.jsonl")
    rows: list[ToolUseExample] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        rows.append(
            ToolUseExample(
                id=str(raw.get("id") or ""),
                tool=str(raw.get("tool") or ""),
                tags=list(raw.get("tags") or []),
                messages=list(raw.get("messages") or []),
                tools=list(raw.get("tools") or []),
                format=str(raw.get("format") or fmt),
            )
        )
    return rows


def iter_openai_rows(examples: list[ToolUseExample]) -> Iterator[dict[str, Any]]:
    for row in examples:
        payload: dict[str, Any] = {"messages": row.messages}
        if row.tools:
            payload["tools"] = row.tools
        yield payload


def validate_examples(
    examples: list[ToolUseExample],
    tools: list[dict[str, Any]] | None = None,
    *,
    require_full_coverage: bool = True,
) -> list[DatasetIssue]:
    catalog = tools if tools is not None else load_tools()
    known = {item["function"]["name"] for item in catalog if item.get("type") == "function"}
    issues: list[DatasetIssue] = []

    for row in examples:
        if not row.id:
            issues.append(DatasetIssue(example_id="?", message="Missing example id"))
        if row.tool and row.tool not in known and not row.tool.startswith("web_"):
            issues.append(DatasetIssue(row.id, f"Unknown primary tool: {row.tool}"))

        roles = [msg.get("role") for msg in row.messages]
        if "user" not in roles:
            issues.append(DatasetIssue(row.id, "Missing user turn"))
        if "assistant" not in roles:
            issues.append(DatasetIssue(row.id, "Missing assistant turn"))

        for msg in row.messages:
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                for call in msg["tool_calls"]:
                    fn = (call.get("function") or {})
                    name = fn.get("name")
                    if name and name not in known:
                        issues.append(DatasetIssue(row.id, f"Unknown tool call: {name}"))
            if row.format == "gemma4_native" and msg.get("role") == "assistant":
                content = str(msg.get("content") or "")
                if "<|tool_call>" in content and "<tool_call|>" not in content:
                    issues.append(DatasetIssue(row.id, "Malformed Gemma tool_call block"))

    covered = {row.tool for row in examples if row.tool in known}
    if require_full_coverage:
        missing = sorted(known - covered)
        for name in missing:
            issues.append(DatasetIssue(example_id="*", message=f"No primary example for tool: {name}"))

    return issues


def split_examples(
    examples: list[ToolUseExample],
    *,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> tuple[list[ToolUseExample], list[ToolUseExample]]:
    import random

    rows = list(examples)
    rng = random.Random(seed)
    rng.shuffle(rows)
    if len(rows) <= 1:
        return rows, []
    val_count = max(1, int(len(rows) * val_ratio))
    val = rows[:val_count]
    train = rows[val_count:]
    return train, val
