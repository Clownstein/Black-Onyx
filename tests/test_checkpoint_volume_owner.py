from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fix_checkpoint_volume_owner.py"
SPEC = importlib.util.spec_from_file_location("fix_checkpoint_volume_owner", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_owner_repair_changes_only_entries_inside_checkpoint_tree(tmp_path, monkeypatch) -> None:
    root = tmp_path / "checkpoints"
    nested = root / "legacy-backups"
    nested.mkdir(parents=True)
    file_path = nested / "state.sqlite"
    file_path.write_bytes(b"preserve this data")
    original = file_path.read_bytes()
    changed: list[tuple[Path, int, int, bool]] = []

    monkeypatch.setattr(
        MODULE.os,
        "chown",
        lambda path, uid, gid, *, follow_symlinks: changed.append(
            (Path(path), uid, gid, follow_symlinks)
        ),
        raising=False,
    )

    assert MODULE.fix_checkpoint_volume_owner(root) == 3
    assert {path for path, _, _, _ in changed} == {root, nested, file_path}
    assert all((uid, gid, nofollow) == (10001, 10001, False) for _, uid, gid, nofollow in changed)
    assert file_path.read_bytes() == original


def test_owner_repair_refuses_symlinks_before_changing_anything(tmp_path, monkeypatch) -> None:
    root = tmp_path / "checkpoints"
    root.mkdir()
    outside = tmp_path / "outside.sqlite"
    outside.write_bytes(b"outside")
    try:
        (root / "external.sqlite").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not available on this Windows host")
    changed: list[Path] = []
    monkeypatch.setattr(
        MODULE.os,
        "chown",
        lambda path, *_args, **_kwargs: changed.append(Path(path)),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="symlink"):
        MODULE.fix_checkpoint_volume_owner(root)
    assert changed == []
    assert outside.read_bytes() == b"outside"
