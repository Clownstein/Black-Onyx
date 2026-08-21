"""Read-only repo snapshot helpers for enrichment."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
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


@contextmanager
def snapshot_repo(request: dict[str, Any]) -> Iterator[Path]:
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

        if isinstance(repo_path, str) and repo_path.strip() and Path(repo_path).exists():
            _copy_tree_filtered(Path(repo_path), root)
        elif isinstance(files, dict) and files:
            for rel, content in files.items():
                dest = root / str(rel)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(str(content), encoding="utf-8", errors="ignore")
        elif isinstance(diff_text, str) and diff_text.strip():
            _materialize_diff(diff_text, root)
        else:
            # Empty workspace — plan may still run but will find nothing.
            (root / "README.enrichment").write_text(
                "empty enrichment snapshot\n", encoding="utf-8"
            )

        # Best-effort strip write bits (Windows may ignore).
        for path in root.rglob("*"):
            try:
                mode = path.stat().st_mode
                path.chmod(mode & ~0o222)
            except OSError:
                pass

        yield root


def _copy_tree_filtered(src: Path, dest: Path) -> None:
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
                current = root / path_token
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
