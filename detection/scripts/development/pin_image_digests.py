#!/usr/bin/env python3
"""Resolve and print image@sha256 digests for pins in image-pins.yaml (requires Docker)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

PINS = Path(__file__).resolve().parents[2] / "infrastructure/docker-compose/image-pins.yaml"


def main() -> int:
    data = yaml.safe_load(PINS.read_text(encoding="utf-8"))
    images = [v for k, v in data.items() if isinstance(v, str) and ":" in v]
    failed = 0
    for image in images:
        print(f"pull {image}", file=sys.stderr)
        r = subprocess.run(["docker", "pull", image], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL {image}: {r.stderr.strip()}", file=sys.stderr)
            failed += 1
            continue
        insp = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        digest = (insp.stdout or "").strip()
        print(f"{image} => {digest or 'NO_DIGEST'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
