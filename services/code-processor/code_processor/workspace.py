from __future__ import annotations

import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any

from code_processor.diff_parse import parse_unified_diff

_MAX_FILES = 10_000
_MAX_FILE_BYTES = 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_DIFF_BYTES = 8 * 1024 * 1024


def _safe_path(root: Path, value: object) -> Path:
    text = str(value).replace("\\", "/")
    relative = Path(text)
    if (
        not text
        or "\x00" in text
        or PureWindowsPath(str(value)).drive
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"unsafe code workspace path: {value}")
    destination = (root / relative).resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"code workspace path escapes root: {value}") from exc
    return destination


def materialize_patch_workspace(patch_payload: dict[str, Any]) -> tempfile.TemporaryDirectory[str]:
    """
    Materialize bounded, path-confined files from a patch payload.
    Expected payload shapes:
      {"files": {"path.py": "content"}}
      {"diff": "unified diff text"}  # reconstructs from added lines
    """
    tmp = tempfile.TemporaryDirectory(prefix="code-processor-")
    root = Path(tmp.name)

    files = patch_payload.get("files")
    if isinstance(files, dict) and files:
        if len(files) > _MAX_FILES:
            tmp.cleanup()
            raise ValueError("files must contain between 1 and 10000 entries")
        total_bytes = 0
        for rel, content in files.items():
            encoded = str(content).encode("utf-8")
            if len(encoded) > _MAX_FILE_BYTES:
                tmp.cleanup()
                raise ValueError(f"code workspace file is too large: {rel}")
            total_bytes += len(encoded)
            if total_bytes > _MAX_TOTAL_BYTES:
                tmp.cleanup()
                raise ValueError("code workspace exceeds total byte limit")
            path = _safe_path(root, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(content), encoding="utf-8")
        return tmp

    diff = patch_payload.get("diff") or patch_payload.get("patch") or ""
    if not str(diff).strip():
        tmp.cleanup()
        raise ValueError("files or diff is required")
    if len(str(diff).encode("utf-8")) > _MAX_DIFF_BYTES:
        tmp.cleanup()
        raise ValueError("diff exceeds byte limit")
    parsed = parse_unified_diff(str(diff))
    if len(parsed) > _MAX_FILES:
        tmp.cleanup()
        raise ValueError("diff contains too many files")
    for file_diff in parsed:
        path = _safe_path(root, file_diff["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        # Prefer added lines as the post-image simulation.
        body = "\n".join(file_diff["added"])
        if body:
            if len(body.encode("utf-8")) > _MAX_FILE_BYTES:
                tmp.cleanup()
                raise ValueError(f"diff file is too large: {file_diff['path']}")
            path.write_text(body + "\n", encoding="utf-8")
    return tmp
