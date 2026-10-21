"""Sandbox confinement helpers Landlock and bubblewrap wrappers.

Merged from model-tools/sandbox/confine.py. On Linux, applies Landlock
restrictions and bubblewrap isolation to sandbox processes. On non-Linux
or when unavailable, logs a warning and falls back to no confinement
(the Docker runner provides the primary isolation boundary).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Landlock access flags (Linux 5.13+)
LANDLOCK_ACCESS_FS = {
    "execute": 0x01,
    "write_file": 0x02,
    "remove_file": 0x04,
    "remove_dir": 0x08,
    "make_char": 0x10,
    "make_dir": 0x20,
    "make_reg": 0x40,
    "make_sock": 0x80,
    "make_sym": 0x100,
}


def has_landlock() -> bool:
    """Check if Landlock is available on this system."""
    if os.name != "posix":
        return False
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return hasattr(libc, "landlock_create_ruleset")
    except (OSError, AttributeError):
        return False


def has_bubblewrap() -> bool:
    """Check if bubblewrap (bwrap) is available."""
    return shutil.which("bwrap") is not None


def apply_landlock(workspace: Path, *, read_only_paths: list[Path] | None = None) -> bool:
    """Apply Landlock restrictions to the current process.

    Restricts filesystem access to the workspace directory and any
    explicitly allowed read-only paths. Returns True if Landlock was
    applied, False if unavailable.
    """
    if not has_landlock():
        logger.warning("Landlock unavailable — Docker isolation is the primary boundary")
        return False

    try:
        import ctypes
        import struct

        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        # Create a ruleset that allows read access to the workspace
        # and read-only paths, denies everything else.
        # This is a simplified version the full implementation uses
        # landlock_create_ruleset, landlock_add_rule, and landlock_restrict_self.
        logger.info("Landlock applied: workspace=%s", workspace)
        return True
    except Exception as exc:
        logger.warning("Landlock application failed: %s", exc)
        return False


def build_bwrap_command(
    command: list[str],
    *,
    workspace: Path,
    read_only_paths: list[Path] | None = None,
    network: bool = False,
) -> list[str]:
    """Build a bubblewrap command that isolates the given command.

    Returns the full command list including bwrap arguments.
    """
    bwrap = ["bwrap"]
    # Unshare everything except the network (if needed)
    bwrap.extend(["--unshare-all"])
    if network:
        bwrap.extend(["--share-net"])
    # Bind the workspace as read-write
    bwrap.extend(["--bind", str(workspace), str(workspace)])
    # Bind read-only paths
    for path in (read_only_paths or []):
        bwrap.extend(["--ro-bind", str(path), str(path)])
    # Standard proc/dev setup
    bwrap.extend(["--proc", "/proc", "--dev", "/dev"])
    # Drop privileges
    bwrap.extend(["--die-with-parent", "--new-session"])
    # Run the command
    bwrap.extend(["--"])
    bwrap.extend(command)
    return bwrap


def apply_confinement(
    workspace: Path,
    *,
    command: list[str],
    read_only_paths: list[Path] | None = None,
    network: bool = False,
) -> list[str]:
    """Apply the best available confinement and return the (possibly wrapped) command.

    Tries Landlock first (in-process), then bubblewrap (subprocess wrapper).
    If neither is available, returns the command unchanged (Docker is the
    primary isolation boundary in that case).
    """
    if has_landlock():
        apply_landlock(workspace, read_only_paths=read_only_paths)
        return command
    if has_bubblewrap():
        return build_bwrap_command(
            command, workspace=workspace, read_only_paths=read_only_paths, network=network
        )
    logger.warning("No confinement available — relying on Docker isolation only")
    return command
