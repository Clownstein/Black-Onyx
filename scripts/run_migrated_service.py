#!/usr/bin/env python3
"""Run Alembic before replacing this process with a service's Uvicorn server."""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: run_migrated_service.py MODULE:APP PORT")
    module, port_text = sys.argv[1:]
    port = int(port_text)
    if not module or not 1 <= port <= 65535:
        raise SystemExit("invalid service module or port")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True)
    os.execv(
        sys.executable,
        [sys.executable, "-m", "uvicorn", module, "--host", "0.0.0.0", "--port", str(port)],
    )


if __name__ == "__main__":
    main()
