from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from black_onyx.ops.backup_manager import BackupManager


def _sqlite(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE state (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def test_requested_qdrant_failure_does_not_publish_partial_backup(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _sqlite(state / "tip.sqlite")

    class BrokenQdrant:
        def list_collections(self):
            return [{"name": "all-knowledge"}]

        def create_and_download_snapshot(self, _name, _destination):
            raise RuntimeError("snapshot failed")

    manager = BackupManager(state, qdrant_store=BrokenQdrant())
    with pytest.raises(RuntimeError, match="snapshot failed"):
        manager.create_backup(include_qdrant=True, label="broken")
    assert list(manager.backups_dir.glob("*.zip")) == []
    assert list(manager.backups_dir.glob("*.partial")) == []


def test_archive_validation_rejects_traversal_and_symlinks(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../outside.sqlite", b"bad")
        archive.writestr("manifest.json", json.dumps({"format_version": 2}))
    with pytest.raises(RuntimeError, match="Unsafe path"):
        BackupManager.validate_backup_file(traversal)

    symlink = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("sqlite/link.sqlite")
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(symlink, "w") as archive:
        archive.writestr(info, "../../outside")
        archive.writestr("manifest.json", json.dumps({"format_version": 2}))
    with pytest.raises(RuntimeError, match="symlinks"):
        BackupManager.validate_backup_file(symlink)


def test_manifest_checksums_are_required_and_verified(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _sqlite(state / "tip.sqlite")
    manager = BackupManager(state)
    result = manager.create_backup(include_qdrant=False, label="verified")
    manifest = BackupManager.validate_backup_file(result["path"])
    assert manifest["format_version"] == 2
    assert manifest["sqlite"][0]["sha256"]

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(result["path"], "r") as source, zipfile.ZipFile(tampered, "w") as output:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename.endswith(".sqlite"):
                data += b"tamper"
            output.writestr(info, data)
    with pytest.raises(RuntimeError, match="size mismatch|checksum mismatch"):
        BackupManager.validate_backup_file(tampered)


def test_backup_id_cannot_escape_backup_directory(tmp_path: Path) -> None:
    manager = BackupManager(tmp_path)
    with pytest.raises(ValueError, match="Invalid backup id"):
        manager.backup_path("../outside")


def test_qdrant_restore_fails_when_snapshot_backend_is_unavailable(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _sqlite(state / "tip.sqlite")

    class SnapshotQdrant:
        def list_collections(self):
            return [{"name": "all-knowledge"}]

        def create_and_download_snapshot(self, name, destination):
            destination.write_bytes(b"snapshot")
            return {"collection": name}

    created = BackupManager(state, qdrant_store=SnapshotQdrant()).create_backup()
    with pytest.raises(RuntimeError, match="Qdrant is unavailable"):
        BackupManager(state, qdrant_store=None).restore_backup(created["backup_id"])
