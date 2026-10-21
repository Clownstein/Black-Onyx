"""Tests for MCP tool-use training helpers."""

import json
from pathlib import Path

import pytest

from black_onyx_tools.training.tool_use_dataset import load_examples, load_tools, validate_examples
from black_onyx_tools.training.tool_use_export import (
    export_gemma_declarations,
    export_hf_sft,
    export_openai_finetune,
)
from black_onyx_tools.training.tool_use_train import _validate_checkpoint_indexes
from black_onyx_tools.training.tool_use_train import train_tool_use_lora


def test_openai_dataset_validates() -> None:
    examples = load_examples(fmt="openai")
    tools = load_tools()
    issues = validate_examples(examples, tools, require_full_coverage=True)
    assert not issues, issues


def test_export_openai_and_hf(tmp_path: Path) -> None:
    examples = load_examples(fmt="openai")[:5]
    n1 = export_openai_finetune(examples, tmp_path / "train.jsonl")
    n2 = export_hf_sft(examples, tmp_path / "train_hf.jsonl")
    assert n1 == 5
    assert n2 == 5
    assert (tmp_path / "train.jsonl").read_text(encoding="utf-8").count("\n") == 5


def test_export_gemma_declarations(tmp_path: Path) -> None:
    tools = load_tools()
    n = export_gemma_declarations(tools, tmp_path / "decl.txt")
    text = (tmp_path / "decl.txt").read_text(encoding="utf-8")
    assert n == 67  # 18 platform + 45 executors + 4 lifecycle controls
    assert "<|tool>black_onyx_evidence_search{" in text
    assert text.count("<tool|>") == 67


def test_train_dry_run_without_hf(tmp_path: Path) -> None:
    examples = load_examples(fmt="openai")[:3]
    train_file = tmp_path / "train_hf.jsonl"
    export_hf_sft(examples, train_file)
    result = train_tool_use_lora(
        train_file=train_file,
        output_dir=tmp_path / "out",
        base_model="google/gemma-2-2b-it",
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["train_rows"] == 3


@pytest.mark.parametrize(
    "shard",
    ["../outside.safetensors", r"..\outside.safetensors", "C:\\outside.safetensors", "/outside.safetensors"],
)
def test_checkpoint_index_rejects_paths_outside_model(shard: str, tmp_path: Path) -> None:
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"weight": shard}}), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="escapes model directory"):
        _validate_checkpoint_indexes(tmp_path)


def test_checkpoint_index_accepts_relative_shard(tmp_path: Path) -> None:
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"weight": "model-00001-of-00002.safetensors"}}),
        encoding="utf-8",
    )

    _validate_checkpoint_indexes(tmp_path)
