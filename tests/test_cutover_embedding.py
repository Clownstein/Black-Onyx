"""Tests for embedding collection cutover helper."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cutover_embedding_collection.py"


def _load_cutover():
    spec = importlib.util.spec_from_file_location("cutover_embedding_collection", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_patch_yaml_updates_collection_fields() -> None:
    mod = _load_cutover()
    src = """
ingestion:
  collection_name: all-knowledge
llm:
  rag:
    collections: ["all-knowledge", "other"]
"""
    out = mod._patch_yaml_text(src, "all-knowledge-qwen3")
    assert 'collection_name: "all-knowledge-qwen3"' in out
    assert 'collections: ["all-knowledge-qwen3"]' in out


def test_apply_cutover_writes_backup(tmp_path: Path) -> None:
    mod = _load_cutover()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        'ingestion:\n  collection_name: "all-knowledge"\nllm:\n  rag:\n    collections: ["all-knowledge"]\n',
        encoding="utf-8",
    )
    result = mod.apply_cutover(cfg, "all-knowledge-qwen3", dry_run=False)
    assert result["applied"] is True
    assert "all-knowledge-qwen3" in cfg.read_text(encoding="utf-8")
    assert Path(str(result["backup"])).is_file()
