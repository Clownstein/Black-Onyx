"""Archive validation and extraction guards.

`archives.py` had no tests. It is the code that unpacks attacker-supplied
archives malware samples, uploaded evidence so its failure modes are
traversal, symlink escape, and decompression bombs.

The tar extraction test matters most on the runtime this actually ships on:
`tarfile.extractall` only defaults to the `data` filter from Python 3.14, and
every service image pins python:3.12, where an unfiltered call is still
`fully_trusted`. A test that passes on a 3.14 developer machine and an image
that runs 3.12 is exactly the gap these cover.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from black_onyx_sandbox import archives
from black_onyx_sandbox.archives import (
    MAX_ARCHIVE_ENTRIES,
    detect_archive_type,
    safe_extract_tar,
    safe_extract_zip,
    validate_tar,
    validate_zip,
)


def write_tar(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with tarfile.open(path, "w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def write_zip(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return path


# ── Happy path ────────────────────────────────────────────────────────────


def test_safe_tar_extracts_its_members(tmp_path: Path) -> None:
    archive = write_tar(tmp_path / "ok.tar", [("a.txt", b"one"), ("dir/b.txt", b"two")])
    out = tmp_path / "out"

    entries = safe_extract_tar(archive, out)

    assert sorted(entries) == ["a.txt", "dir/b.txt"]
    assert (out / "a.txt").read_bytes() == b"one"
    assert (out / "dir" / "b.txt").read_bytes() == b"two"


def test_safe_zip_extracts_its_members(tmp_path: Path) -> None:
    archive = write_zip(tmp_path / "ok.zip", [("a.txt", b"one"), ("dir/b.txt", b"two")])
    out = tmp_path / "out"

    entries = safe_extract_zip(archive, out)

    assert sorted(entries) == ["a.txt", "dir/b.txt"]
    assert (out / "dir" / "b.txt").read_bytes() == b"two"


# ── Path traversal ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    ["../escaped.txt", "dir/../../escaped.txt", "/abs.txt", "\\abs.txt", ""],
)
def test_validate_tar_rejects_unsafe_paths(tmp_path: Path, name: str) -> None:
    archive = write_tar(tmp_path / "evil.tar", [(name, b"x")] if name else [])
    if not name:
        # An empty member name cannot be written; assert the predicate directly.
        from black_onyx_sandbox.archives import _is_path_safe

        assert _is_path_safe("", tmp_path) is False
        return
    with pytest.raises(ValueError, match="Unsafe path"):
        validate_tar(archive, tmp_path / "out")


@pytest.mark.parametrize("name", ["../escaped.txt", "dir/../../escaped.txt"])
def test_validate_zip_rejects_traversal(tmp_path: Path, name: str) -> None:
    archive = write_zip(tmp_path / "evil.zip", [(name, b"x")])
    with pytest.raises(ValueError, match="Unsafe path"):
        validate_zip(archive, tmp_path / "out")


def test_tar_traversal_never_writes_outside_the_destination(tmp_path: Path) -> None:
    """The end-to-end guarantee, independent of which check catches it."""
    archive = write_tar(tmp_path / "evil.tar", [("../escaped.txt", b"pwned")])
    out = tmp_path / "out"

    with pytest.raises(ValueError):
        safe_extract_tar(archive, out)

    assert not (tmp_path / "escaped.txt").exists()


def test_extraction_applies_the_data_filter_not_just_pre_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`safe_extract_tar` must filter at extraction, not only pre-validate.

    `validate_tar` and `extractall` open the archive separately, so validation
    describes an archive that may no longer be the one unpacked. The filter is
    what closes that window and it is not the default on python:3.12, which
    is what every service image pins, so an unfiltered call there is
    `fully_trusted` even though it looks safe on a 3.14 developer machine.
    """
    seen: list[object] = []
    real = tarfile.TarFile.extractall

    def spy(self, path=".", members=None, *, numeric_owner=False, filter=None):
        seen.append(filter)
        return real(self, path, members, numeric_owner=numeric_owner, filter=filter)

    monkeypatch.setattr(tarfile.TarFile, "extractall", spy)

    archive = write_tar(tmp_path / "ok.tar", [("a.txt", b"one")])
    safe_extract_tar(archive, tmp_path / "out")

    assert seen == ["data"], "safe_extract_tar must pass filter='data' explicitly"


def test_the_data_filter_blocks_traversal_at_extraction_time(tmp_path: Path) -> None:
    """The behaviour the filter buys, asserted against tarfile itself."""
    archive = write_tar(tmp_path / "evil.tar", [("../escaped.txt", b"pwned")])
    out = tmp_path / "out"
    out.mkdir()

    with tarfile.open(archive) as tf:
        with pytest.raises(tarfile.OutsideDestinationError):
            tf.extractall(out, filter="data")

    assert not (tmp_path / "escaped.txt").exists()


# ── Links ─────────────────────────────────────────────────────────────────


def test_validate_tar_rejects_symlink_members(tmp_path: Path) -> None:
    archive = tmp_path / "link.tar"
    with tarfile.open(archive, "w") as tf:
        info = tarfile.TarInfo("evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)

    with pytest.raises(ValueError, match="Symlink/link"):
        validate_tar(archive, tmp_path / "out")


def test_validate_tar_rejects_hardlink_members(tmp_path: Path) -> None:
    archive = tmp_path / "link.tar"
    with tarfile.open(archive, "w") as tf:
        payload = tarfile.TarInfo("a.txt")
        payload.size = 1
        tf.addfile(payload, io.BytesIO(b"x"))
        info = tarfile.TarInfo("evil")
        info.type = tarfile.LNKTYPE
        info.linkname = "a.txt"
        tf.addfile(info)

    with pytest.raises(ValueError, match="Symlink/link"):
        validate_tar(archive, tmp_path / "out")


# ── Resource bounds ───────────────────────────────────────────────────────


def test_validate_tar_rejects_too_many_entries(tmp_path: Path) -> None:
    archive = write_tar(
        tmp_path / "many.tar",
        [(f"f{i}.txt", b"") for i in range(MAX_ARCHIVE_ENTRIES + 1)],
    )
    with pytest.raises(ValueError, match="Too many entries"):
        validate_tar(archive, tmp_path / "out")


def test_validate_tar_rejects_decompression_bomb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declared sizes are summed from the headers and refused past the cap.

    The cap is lowered rather than the archive inflated. A truncated header
    claiming 100 MB is not a usable fixture `getmembers` seeks past the
    declared data and raises ReadError before the size check runs and writing
    a real 100 MB member would spend a second per run to reach the same branch.
    """
    monkeypatch.setattr(archives, "MAX_UNCOMPRESSED_SIZE", 8)
    archive = write_tar(
        tmp_path / "bomb.tar", [("a", b"12345"), ("b", b"67890")]
    )

    with pytest.raises(ValueError, match="Uncompressed size exceeds limit"):
        validate_tar(archive, tmp_path / "out")


def test_validate_tar_accepts_an_archive_at_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The boundary is inclusive, so a file exactly at the cap still extracts."""
    monkeypatch.setattr(archives, "MAX_UNCOMPRESSED_SIZE", 10)
    archive = write_tar(tmp_path / "ok.tar", [("a", b"1234567890")])

    assert validate_tar(archive, tmp_path / "out") == ["a"]


def test_validate_zip_rejects_high_compression_ratio(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros", b"\0" * (2 * 1024 * 1024))

    with pytest.raises(ValueError, match="Compression ratio too high"):
        validate_zip(archive, tmp_path / "out")


def test_missing_archive_raises_file_not_found(tmp_path: Path) -> None:
    for validate in (validate_tar, validate_zip):
        with pytest.raises(FileNotFoundError):
            validate(tmp_path / "nope", tmp_path / "out")


# ── Type detection ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("x.zip", "zip"),
        ("x.ZIP", "zip"),
        ("x.tar", "tar"),
        ("x.tgz", "tar"),
        # Path.suffix returns only the last component, so these compound forms
        # silently fell through to None and skipped validation entirely.
        ("x.tar.gz", "tar"),
        ("x.tar.bz2", "tar"),
        ("x.tar.xz", "tar"),
        ("sample.2024.tar.gz", "tar"),
        ("notatar.gz", None),
        ("x.txz", "tar"),
        ("x.exe", None),
        ("x", None),
    ],
)
def test_detect_archive_type(name: str, expected: str | None) -> None:
    assert detect_archive_type(Path(name)) == expected
