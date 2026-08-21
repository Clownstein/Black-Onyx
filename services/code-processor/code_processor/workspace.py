from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from code_processor.diff_parse import parse_unified_diff


def materialize_patch_workspace(patch_payload: dict[str, Any]) -> tempfile.TemporaryDirectory[str]:
    """
    Simulate a git clone by writing files from a patch payload into a temp directory.
    Expected payload shapes:
      {"files": {"path.py": "content"}}
      {"diff": "unified diff text"}  # reconstructs from added lines
    """
    tmp = tempfile.TemporaryDirectory(prefix="code-processor-")
    root = Path(tmp.name)

    files = patch_payload.get("files")
    if isinstance(files, dict):
        for rel, content in files.items():
            path = root / str(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(content), encoding="utf-8")
        return tmp

    diff = patch_payload.get("diff") or patch_payload.get("patch") or ""
    for file_diff in parse_unified_diff(str(diff)):
        path = root / str(file_diff["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        # Prefer added lines as the post-image simulation.
        body = "\n".join(file_diff["added"])
        if body:
            path.write_text(body + "\n", encoding="utf-8")
    return tmp
