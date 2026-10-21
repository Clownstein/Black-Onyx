"""Unit tests for TIP reindex helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reindex_tip_collections.py"


def _load_reindex():
    spec = importlib.util.spec_from_file_location("reindex_tip_collections", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_point_vector_dict_preserves_clip() -> None:
    mod = _load_reindex()
    point = SimpleNamespace(vector={"text": [0.1], "clip": [0.9, 0.8]})
    out = mod._point_vector_dict(point, [0.2, 0.3])
    assert out["text"] == [0.2, 0.3]
    assert out["clip"] == [0.9, 0.8]


def test_point_vector_dict_text_only() -> None:
    mod = _load_reindex()
    point = SimpleNamespace(vector=[0.1, 0.2])
    out = mod._point_vector_dict(point, [0.5])
    assert out == {"text": [0.5]}
