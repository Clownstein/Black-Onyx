"""Recursive glob executed inside the sandbox (passed to ``python3 -c``).

Kept as a module so it is testable; ``SOURCE`` is the text sent as argv.
Results are listed relative to the workspace and never escape it.
"""
from __future__ import annotations

import inspect
import sys


def main(argv: list[str]) -> int:
    import pathlib

    base = pathlib.Path.cwd().resolve()
    root = (base / argv[1]).resolve()
    if root != base and base not in root.parents:
        print("path escapes workspace", file=sys.stderr)
        return 2
    limit = int(argv[3])
    count = 0
    for match in sorted(root.glob(argv[2])):
        resolved = match.resolve()
        if resolved != base and base not in resolved.parents:
            continue
        print(resolved.relative_to(base).as_posix())
        count += 1
        if count >= limit:
            print("...[truncated]")
            break
    return 0


SOURCE = inspect.getsource(main) + "\nimport sys\nraise SystemExit(main(sys.argv))\n"
