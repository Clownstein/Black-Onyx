"""Sandbox archive validation safe extraction of uploaded archives.

Merged from model-tools/sandbox/archives.py. Prevents zip bombs, path
traversal via symlinks, and decompression bombs.
"""

from __future__ import annotations

import logging
import os
import tarfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_ARCHIVE_ENTRIES = 10_000
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_COMPRESSION_RATIO = 100


def _is_path_safe(path: str, extract_to: Path) -> bool:
    """Check if a path is safe to extract (no traversal, no absolute paths)."""
    if not path:
        return False
    if path.startswith("/") or path.startswith("\\"):
        return False
    if ".." in Path(path).parts:
        return False
    resolved = (extract_to / path).resolve()
    try:
        resolved.relative_to(extract_to.resolve())
    except ValueError:
        return False
    return True


def validate_zip(path: Path, extract_to: Path) -> list[str]:
    """Validate a zip archive before extraction.

    Returns a list of safe entry names. Raises ValueError if the archive
    is unsafe (zip bomb, traversal, too many entries).
    """
    if not path.is_file():
        raise FileNotFoundError(f"Archive not found: {path}")
    safe_entries: list[str] = []
    total_uncompressed = 0
    compressed_size = path.stat().st_size

    with zipfile.ZipFile(path, "r") as zf:
        if len(zf.namelist()) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Too many entries: {len(zf.namelist())} > {MAX_ARCHIVE_ENTRIES}")
        for info in zf.infolist():
            if not _is_path_safe(info.filename, extract_to):
                raise ValueError(f"Unsafe path in archive: {info.filename}")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                raise ValueError(f"Uncompressed size exceeds limit: {total_uncompressed}")
            if compressed_size > 0:
                ratio = total_uncompressed / compressed_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise ValueError(f"Compression ratio too high: {ratio:.1f}")
            safe_entries.append(info.filename)

    return safe_entries


def validate_tar(path: Path, extract_to: Path) -> list[str]:
    """Validate a tar archive before extraction."""
    if not path.is_file():
        raise FileNotFoundError(f"Archive not found: {path}")
    safe_entries: list[str] = []
    total_uncompressed = 0
    compressed_size = path.stat().st_size

    with tarfile.open(path, "r:*") as tf:
        members = tf.getmembers()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Too many entries: {len(members)} > {MAX_ARCHIVE_ENTRIES}")
        for member in members:
            if not _is_path_safe(member.name, extract_to):
                raise ValueError(f"Unsafe path in archive: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"Symlink/link in archive: {member.name}")
            total_uncompressed += member.size
            if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                raise ValueError(f"Uncompressed size exceeds limit: {total_uncompressed}")
            safe_entries.append(member.name)

    return safe_entries


def safe_extract_zip(path: Path, extract_to: Path) -> list[str]:
    """Validate and extract a zip archive safely."""
    safe_entries = validate_zip(path, extract_to)
    extract_to.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "r") as zf:
        zf.extractall(extract_to)
    return safe_entries


def safe_extract_tar(path: Path, extract_to: Path) -> list[str]:
    """Validate and extract a tar archive safely.

    `filter="data"` is not redundant with `validate_tar`. Validation opens the
    archive, and extraction opens it a second time, so the checks describe an
    archive that may no longer be the one being unpacked. The filter enforces
    the same invariants no traversal, no links, no device nodes, no setuid
    member by member as they are written.

    It is also the difference between safe and exploitable on the runtime this
    ships on. The filter only defaults to "data" from Python 3.14; this package
    supports 3.12, and every service image pins python:3.12, where an unfiltered
    `extractall` is still `fully_trusted`.
    """
    safe_entries = validate_tar(path, extract_to)
    extract_to.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "r:*") as tf:
        tf.extractall(extract_to, filter="data")
    return safe_entries


# Single-suffix names. The compressed tar forms are handled separately because
# `Path.suffix` returns only the last component: ".tar.gz" could never match a
# `suffix ==` test, so .tar.gz / .tar.bz2 / .tar.xz uploads were reported as
# "not an archive" and skipped the validators entirely.
_TAR_SUFFIXES = {".tar", ".tgz", ".tbz2", ".txz", ".tbz"}
_TAR_COMPRESSION_SUFFIXES = {".gz", ".bz2", ".xz", ".zst", ".lzma"}


def detect_archive_type(path: Path) -> str | None:
    """Detect the archive type from the file extension."""
    suffixes = [suffix.lower() for suffix in path.suffixes]
    suffix = suffixes[-1] if suffixes else ""
    if suffix == ".zip":
        return "zip"
    if suffix in _TAR_SUFFIXES:
        return "tar"
    if (
        suffix in _TAR_COMPRESSION_SUFFIXES
        and len(suffixes) >= 2
        and suffixes[-2] == ".tar"
    ):
        return "tar"
    return None
