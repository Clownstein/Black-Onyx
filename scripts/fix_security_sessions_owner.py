"""Set the Security Lab sessions bind mount owner to the sandbox identity.

Compose runs this one-shot helper with only CAP_CHOWN and the host sessions
directory mounted at /workspace. The security-runner process is UID 10001 and
cannot create session directories on a host path owned by the compose user.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SESSIONS_ROOT = Path("/workspace")
APP_UID = 10001
APP_GID = 10001


def session_paths(root: Path) -> list[Path]:
    """Return the mount tree while refusing symlinks that could escape it."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Sessions mount must be a real directory")

    paths = [root]
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(current)
        children = [parent / name for name in (*directories, *files)]
        links = [path for path in children if path.is_symlink()]
        if links:
            raise RuntimeError("Sessions mount contains a symlink")
        paths.extend(children)
    return paths


def fix_security_sessions_owner(root: Path = SESSIONS_ROOT) -> int:
    """Change ownership of existing mount entries; return the entry count."""
    paths = session_paths(root)
    for path in paths:
        os.chown(path, APP_UID, APP_GID, follow_symlinks=False)
    return len(paths)


def main() -> int:
    try:
        count = fix_security_sessions_owner()
    except (OSError, RuntimeError) as exc:
        print(f"sessions ownership repair failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(f"sessions ownership verified for {count} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
