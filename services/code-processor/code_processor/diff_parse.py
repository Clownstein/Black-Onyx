from __future__ import annotations

from typing import Any


def parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    """Parse a unified diff into changed files with added/removed lines.

    Each entry:
      ``{path, added_lines, removed_lines, added, removed, hunks}``
    ``added``/``removed`` are aliases of the ``*_lines`` lists for compatibility.
    """
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            path = parts[-1][2:] if len(parts) >= 4 else "unknown"
            current = {
                "path": path,
                "added_lines": [],
                "removed_lines": [],
                "added": [],
                "removed": [],
                "hunks": 0,
            }
            files.append(current)
            continue
        if line.startswith("+++ b/"):
            if current is not None:
                current["path"] = line[6:]
            continue
        if current is None:
            continue
        if line.startswith("@@"):
            current["hunks"] += 1
            continue
        if line.startswith("+") and not line.startswith("+++"):
            text = line[1:]
            current["added_lines"].append(text)
            current["added"].append(text)
        elif line.startswith("-") and not line.startswith("---"):
            text = line[1:]
            current["removed_lines"].append(text)
            current["removed"].append(text)
    return files
