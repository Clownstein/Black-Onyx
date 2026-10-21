#!/usr/bin/env python3
"""Clean up checkpoints and temporary files.

Usage:
    python scripts/clean.py [--checkpoints] [--temp] [--all]
"""

import argparse
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def clean_checkpoints() -> int:
    """Remove the .checkpoints/ directory."""
    cp_dir = PROJECT_ROOT / ".checkpoints"
    if cp_dir.exists():
        shutil.rmtree(cp_dir)
        print(f"Removed: {cp_dir}")
        return 0
    print(f"Not found: {cp_dir}")
    return 0


def clean_temp() -> int:
    """Remove temporary image extraction directories."""
    import tempfile
    tmp_base = Path(tempfile.gettempdir()) / "black_onyx_images"
    if tmp_base.exists():
        shutil.rmtree(tmp_base)
        print(f"Removed: {tmp_base}")
        return 0
    print(f"Not found: {tmp_base}")
    return 0


def clean_pycache() -> int:
    """Remove all __pycache__ directories."""
    count = 0
    for p in PROJECT_ROOT.rglob("__pycache__"):
        shutil.rmtree(p)
        count += 1
    print(f"Removed {count} __pycache__ directories")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean up Black Onyx temporary files")
    parser.add_argument("--checkpoints", action="store_true", help="Remove checkpoints")
    parser.add_argument("--temp", action="store_true", help="Remove temporary image files")
    parser.add_argument("--pycache", action="store_true", help="Remove __pycache__ directories")
    parser.add_argument("--all", action="store_true", help="Remove everything")
    args = parser.parse_args()

    if args.all:
        args.checkpoints = True
        args.temp = True
        args.pycache = True

    if not any([args.checkpoints, args.temp, args.pycache]):
        parser.print_help()
        return 1

    rc = 0
    if args.checkpoints:
        rc |= clean_checkpoints()
    if args.temp:
        rc |= clean_temp()
    if args.pycache:
        rc |= clean_pycache()

    return rc


if __name__ == "__main__":
    sys.exit(main())
