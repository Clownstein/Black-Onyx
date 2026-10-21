"""Read-only repo snapshot helpers for enrichment."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from typing import Any


_SKIP_DIR_NAMES = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}
_MAX_SNAPSHOT_FILES = 10_000
_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
_MAX_INLINE_FILE_BYTES = 1024 * 1024
_MAX_DIFF_BYTES = 8 * 1024 * 1024


@contextmanager
def snapshot_repo(
    request: dict[str, Any], *, allowed_repo_roots: list[Path] | None = None
) -> Iterator[Path]:
    """Materialize a temporary read-only-ish workspace from request fields.

    Supported inputs (first match wins):
    - ``repo_path`` / ``target``: copy tree (filtered)
    - ``files``: dict path → source text
    - ``diff`` / ``patch``: write added lines as files (best-effort)
    """
    with tempfile.TemporaryDirectory(prefix="code-enrich-") as tmp:
        root = Path(tmp)
        repo_path = request.get("repo_path") or request.get("target")
        files = request.get("files")
        diff_text = request.get("diff") or request.get("patch") or request.get("diff_text")

        if isinstance(repo_path, str) and repo_path.strip():
            source = _validate_repo_source(Path(repo_path), allowed_repo_roots or [])
            _copy_tree_filtered(source, root)
        elif isinstance(files, dict) and files:
            if len(files) > _MAX_SNAPSHOT_FILES:
                raise ValueError("too many inline files")
            total_bytes = 0
            for rel, content in files.items():
                encoded = str(content).encode("utf-8")
                if len(encoded) > _MAX_INLINE_FILE_BYTES:
                    raise ValueError(f"inline file is too large: {rel}")
                total_bytes += len(encoded)
                if total_bytes > _MAX_SNAPSHOT_BYTES:
                    raise ValueError("inline snapshot is too large")
                dest = _safe_destination(root, str(rel))
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(str(content), encoding="utf-8", errors="ignore")
        elif isinstance(diff_text, str) and diff_text.strip():
            if len(diff_text.encode("utf-8")) > _MAX_DIFF_BYTES:
                raise ValueError("diff snapshot is too large")
            _materialize_diff(diff_text, root)
        else:
            raise ValueError("repo_path, files, or diff is required")

        # Best-effort strip write bits (Windows may ignore).
        for path in root.rglob("*"):
            try:
                mode = path.stat().st_mode
                path.chmod(mode & ~0o222)
            except OSError:
                pass

        yield root


def _safe_destination(root: Path, relative: str) -> Path:
    normalized = relative.replace("\\", "/")
    candidate_path = Path(normalized)
    if (
        not normalized
        or "\x00" in normalized
        or PureWindowsPath(relative).drive
        or candidate_path.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate_path.parts)
    ):
        raise ValueError(f"unsafe snapshot path: {relative}")
    candidate = (root / candidate_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"snapshot path escapes workspace: {relative}") from exc
    return candidate


def _validate_repo_source(source: Path, allowed_roots: list[Path]) -> Path:
    if not allowed_roots:
        raise ValueError("repo_path ingestion is disabled until allowed_repo_roots is configured")
    if source.is_symlink():
        raise ValueError("repo_path cannot be a symlink")
    resolved = source.resolve(strict=True)
    if not any(resolved == root or resolved.is_relative_to(root) for root in allowed_roots):
        raise ValueError("repo_path is outside configured allowed roots")
    return resolved


def _copy_tree_filtered(src: Path, dest: Path) -> None:
    paths = [src] if src.is_file() else src.rglob("*")
    file_count = 0
    total_bytes = 0
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"symlinks are not allowed in snapshots: {path}")
        if path.is_file() and not any(part in _SKIP_DIR_NAMES for part in path.parts):
            file_count += 1
            total_bytes += path.stat().st_size
            if file_count > _MAX_SNAPSHOT_FILES or total_bytes > _MAX_SNAPSHOT_BYTES:
                raise ValueError("repository snapshot exceeds file or byte limit")

    def _ignore(_directory: str, names: list[str]) -> set[str]:
        return {n for n in names if n in _SKIP_DIR_NAMES}

    if src.is_file():
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / src.name)
        return
    shutil.copytree(src, dest, dirs_exist_ok=True, ignore=_ignore)


def _materialize_diff(diff_text: str, root: Path) -> None:
    current: Path | None = None
    lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            if current is not None and lines:
                current.parent.mkdir(parents=True, exist_ok=True)
                current.write_text("\n".join(lines) + "\n", encoding="utf-8")
            path_token = line[4:].strip()
            if path_token.startswith("b/"):
                path_token = path_token[2:]
            if path_token == "/dev/null":
                current = None
                lines = []
            else:
                current = _safe_destination(root, path_token)
                lines = []
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
        elif line.startswith(" ") and not line.startswith("\\"):
            lines.append(line[1:])
    if current is not None and lines:
        current.parent.mkdir(parents=True, exist_ok=True)
        current.write_text("\n".join(lines) + "\n", encoding="utf-8")
