#!/usr/bin/env python3
"""Offline log investigation via configured TIP LLM (not Kafka hot path).

Exports a log window JSON file and asks the platform LLM for suggest-only
investigation notes. Intended for LogTinyLLM-style offline analysis using
Black Onyx 12B or any configured provider.

Usage:
    uv run python detection/scripts/offline/log_investigation_llm.py --input logs.jsonl
    uv run python detection/scripts/offline/log_investigation_llm.py --input logs.jsonl --config config.black-onyx-12b.example.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

INVESTIGATION_PROMPT = """You are assisting a SOC analyst with offline log review.
Produce suggest-only investigation notes in Markdown.
Do not instruct automatic containment, playbook execution, or case closure.
Mark hypotheses as hypotheses. Reference log fields literally when present.

Log window (JSONL events):
"""


def load_events(path: Path, max_events: int) -> list[dict]:
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if isinstance(row, dict):
            events.append(row)
        if len(events) >= max_events:
            break
    if not events:
        raise SystemExit(f"No events found in {path}")
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline log investigation LLM helper")
    parser.add_argument("--input", type=Path, required=True, help="JSONL log window export")
    parser.add_argument("--config", type=str, default=None, help="Optional config.yaml path")
    parser.add_argument("--max-events", type=int, default=200)
    args = parser.parse_args()

    from black_onyx.config import get_settings
    from black_onyx.llm.base import ChatMessage
    from black_onyx.llm.factory import create_provider

    if args.config:
        get_settings.cache_clear()
    settings = get_settings(config_path=args.config)
    provider = create_provider(
        settings.llm.provider,
        settings.llm,
        settings.get_all_api_keys(),
    )

    events = load_events(args.input, args.max_events)
    payload = INVESTIGATION_PROMPT + json.dumps(events, indent=2)[:120000]
    from black_onyx.llm.tool_bridge import effective_system_prompt

    system_prompt = effective_system_prompt(
        settings.llm.rag.system_prompt,
        settings.llm,
        settings.llm.provider,
        purpose="investigation",
    )
    response = provider.chat(
        messages=[ChatMessage(role="user", content=payload)],
        system_prompt=system_prompt,
        temperature=0.2,
    )
    print(response.text)
    if response.reasoning:
        print("\n--- reasoning (not for automation) ---\n", response.reasoning, file=sys.stderr)


if __name__ == "__main__":
    main()
