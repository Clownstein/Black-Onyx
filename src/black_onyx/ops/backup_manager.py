"""Create and restore application state backups (SQLite + Qdrant snapshots)."""

from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
SQLITE_DIR = "sqlite"
QDRANT_DIR = "qdrant"
EXTRA_FILES = ("sla_policy.json",)
FORMAT_VERSION = 2
MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
_BACKUP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")


def _utcnow_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = Path(normalized)
    return bool(
        normalized
        and not normalized.startswith("/")
        and not path.is_absolute()
        and not path.drive
        and ".." not in path.parts
    )


def _safe_inventory_name(name: str) -> bool:
    path = Path(name)
    return bool(name and path.name == name and not path.is_absolute() and not path.drive)


def _validate_archive(archive: Path) -> dict[str, Any]:
    """Validate archive structure, expansion bounds, manifest, and checksums."""
    with zipfile.ZipFile(archive, "r") as zf:
        infos = zf.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
            raise RuntimeError("Backup archive has an invalid member count")
        names: set[str] = set()
        expanded = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name in names:
                raise RuntimeError(f"Duplicate archive member: {name}")
            names.add(name)
            if not _safe_member_name(name):
                raise RuntimeError(f"Unsafe path in archive: {name}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"Archive symlinks are not allowed: {name}")
            expanded += info.file_size
            if expanded > MAX_EXPANDED_BYTES:
                raise RuntimeError("Backup expanded size limit exceeded")
            if info.file_size and info.compress_size == 0:
                raise RuntimeError(f"Invalid compressed member: {name}")
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise RuntimeError(f"Unsafe compression ratio: {name}")
        if MANIFEST_NAME not in names:
            raise RuntimeError("Backup manifest is missing")
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("Backup manifest is invalid") from exc
        if manifest.get("format_version") != FORMAT_VERSION:
            raise RuntimeError("Unsupported backup format version")
        inventory = list(manifest.get("sqlite") or []) + list(manifest.get("extra_files") or [])
        inventory += list(manifest.get("qdrant") or [])
        declared: set[str] = {MANIFEST_NAME}
        for item in inventory:
            if not isinstance(item, dict):
                raise RuntimeError("Backup manifest inventory is invalid")
            member = str(item.get("path") or "")
            checksum = str(item.get("sha256") or "")
            item_name = str(item.get("name") or item.get("collection") or "")
            if not _safe_member_name(member) or member not in names:
                raise RuntimeError(f"Manifest member is missing: {member}")
            local_items = list(manifest.get("sqlite") or []) + list(manifest.get("extra_files") or [])
            if item in local_items and (
                not _safe_inventory_name(item_name) or Path(member).name != item_name
            ):
                raise RuntimeError(f"Manifest inventory name is invalid: {item_name}")
            if len(checksum) != 64:
                raise RuntimeError(f"Manifest checksum is invalid: {member}")
            if item.get("bytes") != zf.getinfo(member).file_size:
                raise RuntimeError(f"Manifest size mismatch: {member}")
            if hashlib.sha256(zf.read(member)).hexdigest() != checksum:
                raise RuntimeError(f"Backup checksum mismatch: {member}")
            declared.add(member)
        file_names = {i.filename.replace("\\", "/") for i in infos if not i.is_dir()}
        if file_names != declared:
            raise RuntimeError("Backup contains undeclared files")
        return manifest


def _verified_sqlite_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
        result = destination_db.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"Integrity verification failed for {source.name}")
    finally:
        destination_db.close()
        source_db.close()


def _restore_sqlite_into(live: Path, staged: Path) -> None:
    """Copy staged SQLite into the live path via the backup API (safe with WAL)."""
    live.parent.mkdir(parents=True, exist_ok=True)
    source_db = sqlite3.connect(f"file:{staged}?mode=ro", uri=True)
    destination_db = sqlite3.connect(live)
    try:
        source_db.backup(destination_db)
        result = destination_db.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"Integrity verification failed restoring {live.name}")
        destination_db.commit()
    finally:
        destination_db.close()
        source_db.close()


class BackupManager:
    """Admin backup/restore over ``storage.state_dir`` and Qdrant collections."""

    def __init__(self, state_dir: str | Path, qdrant_store: Any | None = None) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir = self.state_dir / "backups"
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.qdrant = qdrant_store

    def list_state_inventory(self) -> dict[str, Any]:
        sqlite_files = sorted(
            p for p in self.state_dir.glob("*.sqlite")
            if p.is_file()
        )
        extras = [name for name in EXTRA_FILES if (self.state_dir / name).is_file()]
        collections: list[dict[str, Any]] = []
        if self.qdrant is not None:
            try:
                collections = self.qdrant.list_collections() or []
            except Exception:
                logger.debug("backup inventory: list_collections failed", exc_info=True)
        return {
            "state_dir": str(self.state_dir),
            "sqlite": [
                {"name": p.name, "bytes": p.stat().st_size}
                for p in sqlite_files
            ],
            "extra_files": extras,
            "qdrant_collections": [
                {
                    "name": c.get("name"),
                    "points_count": c.get("points_count", 0),
                }
                for c in collections
            ],
            "backups_dir": str(self.backups_dir),
        }

    @staticmethod
    def validate_backup_file(path: str | Path) -> dict[str, Any]:
        return _validate_archive(Path(path))

    def _archive_path(self, backup_id: str) -> Path:
        if not _BACKUP_ID_RE.fullmatch(backup_id):
            raise ValueError("Invalid backup id")
        return self.backups_dir / f"{backup_id}.zip"

    def list_backups(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for path in sorted(self.backups_dir.glob("*.zip"), reverse=True):
            meta: dict[str, Any] = {
                "backup_id": path.stem,
                "filename": path.name,
                "bytes": path.stat().st_size,
                "created_at": datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc,
                ).isoformat(),
            }
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    if MANIFEST_NAME in zf.namelist():
                        manifest = json.loads(zf.read(MANIFEST_NAME))
                        meta["manifest"] = {
                            "created_at": manifest.get("created_at"),
                            "sqlite": manifest.get("sqlite", []),
                            "qdrant": manifest.get("qdrant", []),
                            "include_qdrant": manifest.get("include_qdrant"),
                        }
            except Exception:
                logger.debug("backup list: manifest read failed for %s", path, exc_info=True)
            items.append(meta)
        return items

    def create_backup(
        self,
        *,
        include_qdrant: bool = True,
        label: str = "",
    ) -> dict[str, Any]:
        stamp = _utcnow_stamp()
        backup_id = f"{stamp}{('-' + label.strip()) if label.strip() else ''}"
        # Sanitize label for filesystem
        backup_id = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in backup_id)
        work = self.backups_dir / f".work-{backup_id}"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        sqlite_out = work / SQLITE_DIR
        qdrant_out = work / QDRANT_DIR
        sqlite_out.mkdir()
        qdrant_out.mkdir()

        archive = self.backups_dir / f"{backup_id}.zip"
        partial = archive.with_suffix(".zip.partial")
        try:
            sqlite_meta: list[dict[str, Any]] = []
            for source in sorted(self.state_dir.glob("*.sqlite")):
                if not source.is_file():
                    continue
                destination = sqlite_out / source.name
                _verified_sqlite_copy(source, sqlite_out / source.name)
                sqlite_meta.append({
                    "name": source.name,
                    "path": f"{SQLITE_DIR}/{source.name}",
                    "bytes": destination.stat().st_size,
                    "sha256": _sha256(destination),
                })

            extras_meta: list[dict[str, Any]] = []
            for name in EXTRA_FILES:
                src = self.state_dir / name
                if src.is_file():
                    destination = work / name
                    shutil.copy2(src, destination)
                    extras_meta.append({
                        "name": name, "path": name, "bytes": destination.stat().st_size,
                        "sha256": _sha256(destination),
                    })

            qdrant_meta: list[dict[str, Any]] = []
            if include_qdrant:
                if self.qdrant is None:
                    raise RuntimeError("Qdrant is unavailable for the requested backup")
                collections = self.qdrant.list_collections() or []
                for col in collections:
                    name = col.get("name")
                    if not name:
                        continue
                    filename = f"{hashlib.sha256(str(name).encode()).hexdigest()[:24]}.snapshot"
                    dest = qdrant_out / filename
                    info = self.qdrant.create_and_download_snapshot(name, dest)
                    qdrant_meta.append({
                        **(info if isinstance(info, dict) else {}),
                        "collection": name,
                        "path": f"{QDRANT_DIR}/{filename}",
                        "bytes": dest.stat().st_size,
                        "sha256": _sha256(dest),
                    })

            manifest = {
                "backup_id": backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "include_qdrant": include_qdrant,
                "sqlite": sqlite_meta,
                "extra_files": extras_meta,
                "qdrant": qdrant_meta,
                "format_version": FORMAT_VERSION,
            }
            (work / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for path in work.rglob("*"):
                    if path.is_file():
                        zf.write(path, path.relative_to(work).as_posix())
            _validate_archive(partial)
            os.replace(partial, archive)
        except Exception:
            partial.unlink(missing_ok=True)
            archive.unlink(missing_ok=True)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)

        return {
            "backup_id": backup_id,
            "filename": archive.name,
            "path": str(archive),
            "bytes": archive.stat().st_size,
            "manifest": manifest,
        }

    def restore_backup(
        self,
        backup_id: str,
        *,
        include_qdrant: bool = True,
        include_sqlite: bool = True,
    ) -> dict[str, Any]:
        archive = self._archive_path(backup_id)
        if not archive.is_file():
            raise FileNotFoundError(f"Backup not found: {backup_id}")

        work = self.backups_dir / f".restore-{backup_id}"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        try:
            manifest = _validate_archive(archive)
            with zipfile.ZipFile(archive, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    target = work / info.filename.replace("\\", "/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as source, target.open("wb") as destination:
                        shutil.copyfileobj(source, destination)

            for item in manifest.get("sqlite") or []:
                staged = work / item["path"]
                connection = sqlite3.connect(f"file:{staged}?mode=ro", uri=True)
                try:
                    result = connection.execute("PRAGMA integrity_check").fetchone()
                    if not result or result[0] != "ok":
                        raise RuntimeError(f"Staged SQLite integrity failed: {item['name']}")
                finally:
                    connection.close()
            if include_qdrant and self.qdrant is None and manifest.get("qdrant"):
                raise RuntimeError("Qdrant is unavailable for the requested restore")
            restored_sqlite: list[str] = []
            if include_sqlite:
                for item in manifest.get("sqlite") or []:
                    staged = work / item["path"]
                    live = self.state_dir / item["name"]
                    _restore_sqlite_into(live, staged)
                    restored_sqlite.append(item["name"])
                for item in manifest.get("extra_files") or []:
                    shutil.copy2(work / item["path"], self.state_dir / item["name"])

            restored_qdrant: list[dict[str, Any]] = []
            if include_qdrant:
                for item in manifest.get("qdrant") or []:
                    snap = work / item["path"]
                    collection = item["collection"]
                    info = self.qdrant.upload_and_recover_snapshot(collection, snap)
                    restored_qdrant.append(info)

            return {
                "backup_id": backup_id,
                "restored_sqlite": restored_sqlite,
                "restored_qdrant": restored_qdrant,
                "manifest": {
                    "created_at": manifest.get("created_at"),
                    "sqlite": manifest.get("sqlite", []),
                },
                "restart_recommended": True,
                "message": (
                    "Restore applied via SQLite backup API and Qdrant snapshot upload. "
                    "Restart the web container so in-memory managers reopen fresh connections."
                ),
            }
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def delete_backup(self, backup_id: str) -> bool:
        archive = self._archive_path(backup_id)
        if not archive.is_file():
            return False
        archive.unlink()
        return True

    def backup_path(self, backup_id: str) -> Path | None:
        archive = self._archive_path(backup_id)
        return archive if archive.is_file() else None
