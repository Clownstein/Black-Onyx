"""Tests for offline log investigation helper."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "detection" / "scripts" / "offline" / "log_investigation_llm.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("log_investigation_llm", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_load_events_respects_max(tmp_path: Path) -> None:
    mod = _load_mod()
    path = tmp_path / "logs.jsonl"
    path.write_text(
        '{"msg":"a"}\n{"msg":"b"}\n{"msg":"c"}\n',
        encoding="utf-8",
    )
    events = mod.load_events(path, max_events=2)
    assert len(events) == 2
    assert events[0]["msg"] == "a"


def test_investigation_prompt_is_suggest_only() -> None:
    mod = _load_mod()
    assert "suggest-only" in mod.INVESTIGATION_PROMPT.lower()
    assert "containment" in mod.INVESTIGATION_PROMPT.lower()
