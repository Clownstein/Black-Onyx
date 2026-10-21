"""Create and restore application state backups (SQLite + Qdrant snapshots)."""

from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
SQLITE_DIR = "sqlite"
POSTGRES_DIR = "postgres"
QDRANT_DIR = "qdrant"
EXTRA_FILES = ("sla_policy.json",)
FORMAT_VERSION = 3
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


def _remove_work_directory(work: Path, backups_dir: Path) -> None:
    if work.is_symlink() or work.resolve().parent != backups_dir.resolve():
        raise RuntimeError("Unsafe backup work directory")
    shutil.rmtree(work, ignore_errors=True)


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
        if manifest.get("format_version") not in (2, FORMAT_VERSION):
            raise RuntimeError("Unsupported backup format version")
        inventory = list(manifest.get("sqlite") or []) + list(manifest.get("extra_files") or [])
        inventory += list(manifest.get("qdrant") or [])
        inventory += list(manifest.get("postgres") or [])
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


def _libpq_target(database_url: str) -> tuple[str, dict[str, str]]:
    """Return a password-free libpq URL plus the subprocess environment.

    The password travels in PGPASSWORD so it never appears in the process
    list (argv is world-readable inside the container).
    """
    url = database_url.strip()
    for prefix in (
        "postgresql+psycopg://",
        "postgresql+psycopg2://",
        "postgres+psycopg://",
        "postgres+psycopg2://",
    ):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix) :]
            break
    parts = urlsplit(url)
    env = dict(os.environ)
    if parts.password is not None:
        env["PGPASSWORD"] = unquote(parts.password)
        user = quote(unquote(parts.username or ""), safe="")
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = f"{user}@{host}" if user else host
        if parts.port:
            netloc += f":{parts.port}"
        url = urlunsplit(parts._replace(netloc=netloc))
    return url, env


def _pg_dump(database_url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    target, env = _libpq_target(database_url)
    result = subprocess.run(
        ["pg_dump", "--format=custom", "--no-owner", "--dbname", target, "-f", str(destination)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "pg_dump failed")


def _pg_restore(database_url: str, dump_path: Path) -> None:
    if not dump_path.is_file():
        raise FileNotFoundError(f"Postgres dump missing: {dump_path}")
    target, env = _libpq_target(database_url)
    result = subprocess.run(
        ["pg_restore", "--clean", "--if-exists", "--no-owner", "--dbname", target, str(dump_path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    # pg_restore returns 1 for non-fatal warnings (e.g. role ownership notices).
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "pg_restore failed")


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
        postgres_urls = {
            name: url
            for name, url in (
                ("black_onyx", os.environ.get("BLACK_ONYX_DATABASE_URL")),
                ("security_gateway", os.environ.get("SECURITY_GATEWAY_DATABASE_URL")),
            )
            if url
        }
        return {
            "state_dir": str(self.state_dir),
            "sqlite": [
                {"name": p.name, "bytes": p.stat().st_size}
                for p in sqlite_files
            ],
            "postgres": [{"name": name, "configured": True} for name in postgres_urls],
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
            _remove_work_directory(work, self.backups_dir)
        work.mkdir(parents=True)
        sqlite_out = work / SQLITE_DIR
        postgres_out = work / POSTGRES_DIR
        qdrant_out = work / QDRANT_DIR
        sqlite_out.mkdir()
        postgres_out.mkdir()
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

            postgres_meta: list[dict[str, Any]] = []
            for label, url in (
                ("black_onyx", os.environ.get("BLACK_ONYX_DATABASE_URL")),
                ("security_gateway", os.environ.get("SECURITY_GATEWAY_DATABASE_URL")),
            ):
                if not url:
                    continue
                dump_path = postgres_out / f"{label}.dump"
                _pg_dump(url.strip(), dump_path)
                postgres_meta.append({
                    "name": label,
                    "path": f"{POSTGRES_DIR}/{label}.dump",
                    "bytes": dump_path.stat().st_size,
                    "sha256": _sha256(dump_path),
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
                "postgres": postgres_meta,
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
            _remove_work_directory(work, self.backups_dir)

        result = {
            "backup_id": backup_id,
            "filename": archive.name,
            "path": str(archive),
            "bytes": archive.stat().st_size,
            "manifest": manifest,
        }
        result["pruned"] = self.prune_backups(keep_backup_id=backup_id)
        return result

    @staticmethod
    def retention_count() -> int:
        """Backups to keep (BLACK_ONYX_BACKUP_RETENTION, default 7; 0 keeps all)."""
        raw = os.environ.get("BLACK_ONYX_BACKUP_RETENTION", "7").strip()
        try:
            return max(0, int(raw))
        except ValueError:
            logger.warning("Invalid BLACK_ONYX_BACKUP_RETENTION=%r; keeping all backups", raw)
            return 0

    def prune_backups(self, *, keep_backup_id: str | None = None) -> list[str]:
        """Delete the oldest archives beyond the retention count."""
        keep = self.retention_count()
        if keep == 0:
            return []
        archives = sorted(
            self.backups_dir.glob("*.zip"), key=lambda path: path.stat().st_mtime, reverse=True,
        )
        removed: list[str] = []
        for path in archives[keep:]:
            if path.stem == keep_backup_id:
                continue
            try:
                path.unlink()
                removed.append(path.stem)
            except OSError:
                logger.warning("Could not prune backup %s", path.name)
        return removed

    def restore_backup(
        self,
        backup_id: str,
        *,
        include_qdrant: bool = True,
        include_sqlite: bool = True,
        include_postgres: bool = True,
    ) -> dict[str, Any]:
        archive = self._archive_path(backup_id)
        if not archive.is_file():
            raise FileNotFoundError(f"Backup not found: {backup_id}")

        work = self.backups_dir / f".restore-{backup_id}"
        if work.exists():
            raise RuntimeError(f"Restore recovery directory already exists: {work}")
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
            postgres_urls = {
                "black_onyx": (os.environ.get("BLACK_ONYX_DATABASE_URL") or "").strip(),
                "security_gateway": (os.environ.get("SECURITY_GATEWAY_DATABASE_URL") or "").strip(),
            }
            if include_postgres:
                for item in manifest.get("postgres") or []:
                    name = str(item.get("name") or "")
                    if name and not postgres_urls.get(name):
                        raise RuntimeError(
                            f"Postgres dump {name} is present but its database URL is not configured"
                        )
            # Save the current state before changing either store. Restore
            # Qdrant first, so a failed vector upload never exposes the new
            # SQLite state with old vectors. Roll back both on later failure.
            rollback_dir = work / "rollback"
            rollback_dir.mkdir()
            old_sqlite: dict[str, Path | None] = {}
            old_extras: dict[str, Path | None] = {}
            old_qdrant: dict[str, Path] = {}
            old_postgres: dict[str, Path] = {}
            if include_sqlite:
                for item in manifest.get("sqlite") or []:
                    live = self.state_dir / item["name"]
                    saved = rollback_dir / item["name"]
                    if live.is_file():
                        _verified_sqlite_copy(live, saved)
                        old_sqlite[item["name"]] = saved
                    else:
                        old_sqlite[item["name"]] = None
                for item in manifest.get("extra_files") or []:
                    live = self.state_dir / item["name"]
                    saved = rollback_dir / f"extra-{item['name']}"
                    if live.is_file():
                        shutil.copy2(live, saved)
                        old_extras[item["name"]] = saved
                    else:
                        old_extras[item["name"]] = None
            if include_qdrant:
                for item in manifest.get("qdrant") or []:
                    collection = item["collection"]
                    saved = rollback_dir / f"{hashlib.sha256(collection.encode()).hexdigest()}.snapshot"
                    self.qdrant.create_and_download_snapshot(collection, saved)
                    old_qdrant[collection] = saved
            if include_postgres:
                for item in manifest.get("postgres") or []:
                    name = str(item.get("name") or "")
                    url = postgres_urls.get(name) or ""
                    if not name or not url:
                        continue
                    saved = rollback_dir / f"{name}.dump"
                    _pg_dump(url, saved)
                    old_postgres[name] = saved

            restored_sqlite: list[str] = []
            restored_postgres: list[str] = []
            restored_qdrant: list[dict[str, Any]] = []
            changed_qdrant: list[str] = []
            changed_sqlite: list[str] = []
            changed_extras: list[str] = []
            changed_postgres: list[str] = []
            try:
                if include_qdrant:
                    for item in manifest.get("qdrant") or []:
                        collection = item["collection"]
                        # Include the in-progress collection in rollback even
                        # if the upload fails after partially applying it.
                        changed_qdrant.append(collection)
                        info = self.qdrant.upload_and_recover_snapshot(collection, work / item["path"])
                        restored_qdrant.append(info)
                if include_postgres:
                    for item in manifest.get("postgres") or []:
                        name = str(item.get("name") or "")
                        url = postgres_urls.get(name) or ""
                        if not name or not url:
                            continue
                        changed_postgres.append(name)
                        _pg_restore(url, work / item["path"])
                        restored_postgres.append(name)
                if include_sqlite:
                    for item in manifest.get("sqlite") or []:
                        name = item["name"]
                        changed_sqlite.append(name)
                        _restore_sqlite_into(self.state_dir / name, work / item["path"])
                        restored_sqlite.append(name)
                    for item in manifest.get("extra_files") or []:
                        name = item["name"]
                        changed_extras.append(name)
                        shutil.copy2(work / item["path"], self.state_dir / name)
            except Exception as exc:
                recovery_errors: list[str] = []
                for name in reversed(changed_extras):
                    try:
                        previous = old_extras[name]
                        if previous is None:
                            (self.state_dir / name).unlink(missing_ok=True)
                        else:
                            shutil.copy2(previous, self.state_dir / name)
                    except Exception as rollback_exc:
                        recovery_errors.append(f"extra {name}: {rollback_exc}")
                for name in reversed(changed_sqlite):
                    try:
                        previous = old_sqlite[name]
                        if previous is None:
                            (self.state_dir / name).unlink(missing_ok=True)
                        else:
                            _restore_sqlite_into(self.state_dir / name, previous)
                    except Exception as rollback_exc:
                        recovery_errors.append(f"SQLite {name}: {rollback_exc}")
                for name in reversed(changed_postgres):
                    try:
                        previous = old_postgres.get(name)
                        url = postgres_urls.get(name) or ""
                        if previous is not None and url:
                            _pg_restore(url, previous)
                    except Exception as rollback_exc:
                        recovery_errors.append(f"Postgres {name}: {rollback_exc}")
                for name in reversed(changed_qdrant):
                    try:
                        self.qdrant.upload_and_recover_snapshot(name, old_qdrant[name])
                    except Exception as rollback_exc:
                        recovery_errors.append(f"Qdrant {name}: {rollback_exc}")
                if recovery_errors:
                    # Keep the staged files for operator recovery.
                    raise RuntimeError(
                        f"Restore failed and rollback is incomplete; recovery files: {work}; "
                        + "; ".join(recovery_errors)
                    ) from exc
                raise

            return {
                "backup_id": backup_id,
                "restored_sqlite": restored_sqlite,
                "restored_postgres": restored_postgres,
                "restored_qdrant": restored_qdrant,
                "manifest": {
                    "created_at": manifest.get("created_at"),
                    "sqlite": manifest.get("sqlite", []),
                    "postgres": manifest.get("postgres", []),
                },
                "restart_recommended": True,
                "message": (
                    "Restore applied via Postgres pg_restore, SQLite backup API, and Qdrant snapshot upload. "
                    "Restart the web and security-gateway containers so in-memory managers reopen fresh connections."
                ),
            }
        finally:
            if not locals().get("recovery_errors"):
                _remove_work_directory(work, self.backups_dir)

    def delete_backup(self, backup_id: str) -> bool:
        archive = self._archive_path(backup_id)
        if not archive.is_file():
            return False
        archive.unlink()
        return True

    def backup_path(self, backup_id: str) -> Path | None:
        archive = self._archive_path(backup_id)
        return archive if archive.is_file() else None
