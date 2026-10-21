"""Set the checkpoint volume owner to the non-root application identity.

Compose runs this one-shot helper with only CAP_CHOWN and the checkpoint volume
mounted. Existing files are retained; the helper changes ownership metadata
only so the UID 10001 web/CLI process can migrate and use old named volumes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

CHECKPOINT_ROOT = Path("/app/.checkpoints")
APP_UID = 10001
APP_GID = 10001


def checkpoint_paths(root: Path) -> list[Path]:
    """Return the volume tree while refusing symlinks that could escape it."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Checkpoint mount must be a real directory")

    paths = [root]
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(current)
        children = [parent / name for name in (*directories, *files)]
        links = [path for path in children if path.is_symlink()]
        if links:
            raise RuntimeError("Checkpoint mount contains a symlink")
        paths.extend(children)
    return paths


def fix_checkpoint_volume_owner(root: Path = CHECKPOINT_ROOT) -> int:
    """Change ownership of existing volume entries; return the entry count."""
    paths = checkpoint_paths(root)
    for path in paths:
        os.chown(path, APP_UID, APP_GID, follow_symlinks=False)
    return len(paths)


def main() -> int:
    try:
        count = fix_checkpoint_volume_owner()
    except (OSError, RuntimeError) as exc:
        print(f"checkpoint ownership repair failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(f"checkpoint ownership verified for {count} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
