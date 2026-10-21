"""Admin backup/restore endpoints for SQLite state and Qdrant collections."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from black_onyx.auth.dependencies import require_admin
from black_onyx.auth.service import Principal
from black_onyx.ops.backup_manager import BackupManager

logger = logging.getLogger(__name__)
MAX_BACKUP_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024

backup_router = APIRouter(prefix="/api/v1/admin/backup", tags=["backup"])


def _get_service():
    from black_onyx.api.service import get_service
    return get_service()


def _manager() -> BackupManager:
    service = _get_service()
    qdrant = None
    try:
        qdrant = service.qdrant_store
    except Exception:
        logger.debug("backup: qdrant unavailable", exc_info=True)
    return BackupManager(service.settings.storage.state_dir, qdrant_store=qdrant)


class BackupCreateRequest(BaseModel):
    include_qdrant: bool = True
    label: str = Field(default="", max_length=64)


class BackupRestoreRequest(BaseModel):
    backup_id: str = Field(min_length=1, max_length=200)
    include_qdrant: bool = True
    include_sqlite: bool = True


@backup_router.get("/inventory")
async def backup_inventory(_: Principal = Depends(require_admin)) -> dict[str, Any]:
    return _manager().list_state_inventory()


@backup_router.get("")
async def list_backups(_: Principal = Depends(require_admin)) -> dict[str, Any]:
    items = _manager().list_backups()
    return {"backups": items, "n": len(items)}


@backup_router.post("/create")
async def create_backup(
    req: BackupCreateRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    try:
        result = _manager().create_backup(
            include_qdrant=req.include_qdrant,
            label=req.label,
        )
    except Exception as exc:
        logger.exception("backup create failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(
        principal, "backup.create", "backup", result["backup_id"],
        detail={"bytes": result.get("bytes"), "include_qdrant": req.include_qdrant},
    )
    return result


@backup_router.post("/restore")
async def restore_backup(
    req: BackupRestoreRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    try:
        result = _manager().restore_backup(
            req.backup_id,
            include_qdrant=req.include_qdrant,
            include_sqlite=req.include_sqlite,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("backup restore failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(
        principal, "backup.restore", "backup", req.backup_id,
        detail={
            "sqlite": result.get("restored_sqlite"),
            "qdrant": [r.get("collection") for r in result.get("restored_qdrant") or []],
        },
    )
    return result


@backup_router.get("/{backup_id}/download")
async def download_backup(
    backup_id: str,
    _: Principal = Depends(require_admin),
) -> FileResponse:
    try:
        path = _manager().backup_path(backup_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Backup not found") from exc
    if path is None:
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(
        path,
        media_type="application/zip",
        filename=path.name,
    )


@backup_router.delete("/{backup_id}")
async def delete_backup(
    backup_id: str,
    principal: Principal = Depends(require_admin),
) -> dict[str, str]:
    try:
        deleted = _manager().delete_backup(backup_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Backup not found") from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="Backup not found")
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(principal, "backup.delete", "backup", backup_id)
    return {"status": "ok", "backup_id": backup_id}


@backup_router.post("/upload")
async def upload_backup(
    principal: Principal = Depends(require_admin),
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """Upload an external backup zip into the backups directory."""
    filename = Path(file.filename or "upload.zip").name
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=422, detail="Backup upload must be a .zip file")
    # Strip path components
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in filename)
    if not safe.lower().endswith(".zip"):
        safe = f"{safe}.zip"
    manager = _manager()
    dest = manager.backups_dir / safe
    if dest.exists():
        raise HTTPException(status_code=409, detail="A backup with this filename already exists")
    temporary = manager.backups_dir / f".upload-{principal.user_id}-{safe}.partial"
    size = 0
    try:
        with temporary.open("xb") as output:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_BACKUP_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Backup exceeds 2 GiB limit")
                output.write(chunk)
        manager.validate_backup_file(temporary)
        temporary.replace(dest)
    except HTTPException:
        temporary.unlink(missing_ok=True)
        raise
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail="A backup upload is already in progress") from exc
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=f"Invalid backup archive: {exc}") from exc
    finally:
        await file.close()
    from black_onyx.auth.context import get_auth_service
    get_auth_service().audit(
        principal, "backup.upload", "backup", dest.stem,
        detail={"bytes": size, "filename": safe},
    )
    return {"backup_id": dest.stem, "filename": safe, "bytes": size}
