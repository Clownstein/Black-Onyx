"""Replace Jackson artifacts shaded inside the CodeQL bundle's jars with a patched release.

CodeQL's own fat jars (codeql.jar, extractor jars, ...) embed jackson-core/databind/annotations
at a version older than the patched one. For every embedded artifact, drop *all* of its old
entries (classes, multi-release copies, services, pom metadata) and copy the complete payload of
the patched jar, so no stale or missing class survives. Scanners read the embedded
``META-INF/maven/.../pom.properties``, which comes from the same replacement payload.

Usage: patch_jackson.py CODEQL_ROOT JACKSON_CORE.jar JACKSON_DATABIND.jar JACKSON_ANNOTATIONS.jar
"""

from __future__ import annotations

import os
import re
import sys
import zipfile
from pathlib import Path

ARTIFACT_PACKAGES = {
    "jackson-core": "com/fasterxml/jackson/core/",
    "jackson-databind": "com/fasterxml/jackson/databind/",
    "jackson-annotations": "com/fasterxml/jackson/annotation/",
}
SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")
# Per-jar housekeeping that is not part of the shaded library payload.
NOT_PAYLOAD = re.compile(r"^META-INF/(MANIFEST\.MF|LICENSE.*|NOTICE.*|.*module-info\.class)$|"
                         r"^META-INF/versions/\d+/module-info\.class$|^module-info\.class$")
MULTI_RELEASE = re.compile(r"^META-INF/versions/\d+/")
SKIPPED: list[Path] = []


def _pom_dir(artifact: str) -> str:
    return f"META-INF/maven/com.fasterxml.jackson.core/{artifact}/"


def owned_by(artifact: str, name: str) -> bool:
    """True if the archive entry belongs to the artifact's shaded payload."""
    if NOT_PAYLOAD.match(name):
        return False
    bare = MULTI_RELEASE.sub("", name)
    return bare.startswith(ARTIFACT_PACKAGES[artifact]) or name.startswith(_pom_dir(artifact))


def load_payloads(jars: dict[str, Path]) -> dict[str, dict[str, bytes]]:
    payloads: dict[str, dict[str, bytes]] = {}
    for artifact, path in jars.items():
        with zipfile.ZipFile(path) as archive:
            files = {
                i.filename: archive.read(i.filename)
                for i in archive.infolist()
                if not i.is_dir() and not NOT_PAYLOAD.match(i.filename)
            }
        if not any(n.startswith(_pom_dir(artifact)) for n in files):
            raise SystemExit(f"{path}: missing pom metadata for {artifact}")
        payloads[artifact] = files
    return payloads


def patch_jar(path: Path, payloads: dict[str, dict[str, bytes]]) -> bool:
    try:
        source = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return False
    with source:
        names = source.namelist()
        embedded = [a for a in ARTIFACT_PACKAGES if any(n.startswith(_pom_dir(a)) for n in names)]
        if "jackson-databind" not in embedded:
            return False
        if "com/fasterxml/jackson/databind/ObjectMapper.class" not in names:
            # Relocated (shaded) copy: classes live under another package, so replacing the pom
            # metadata alone would misreport the version. Leave the jar untouched and say so.
            print(f"SKIPPED {path}: jackson is relocated, not patched")
            SKIPPED.append(path)
            return False
        if any(n.startswith("META-INF/") and n.endswith(SIGNATURE_SUFFIXES) for n in names):
            raise SystemExit(f"{path}: signed jar, refusing to rewrite")

        added: dict[str, bytes] = {}
        for artifact in embedded:
            added.update(payloads[artifact])
        temporary = path.with_suffix(path.suffix + ".patched")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as target:
            for info in source.infolist():
                name = info.filename
                if name in added or any(owned_by(a, name) for a in embedded):
                    continue
                target.writestr(info, b"" if info.is_dir() else source.read(name),
                                compress_type=zipfile.ZIP_DEFLATED)
            for name, data in sorted(added.items()):
                target.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)

    with zipfile.ZipFile(temporary) as result:
        final = set(result.namelist())
    for artifact in embedded:
        expected = set(payloads[artifact])
        stale = {n for n in final if owned_by(artifact, n)} - expected
        missing = expected - final
        if stale or missing:
            temporary.unlink()
            raise SystemExit(f"{path}: {artifact} payload mismatch "
                             f"(stale={sorted(stale)[:5]}, missing={sorted(missing)[:5]})")
    os.replace(temporary, path)
    print(f"patched {path} ({', '.join(embedded)}; {len(added)} entries)")
    return True


def main() -> None:
    root = Path(sys.argv[1])
    jars = dict(zip(ARTIFACT_PACKAGES, map(Path, sys.argv[2:5]), strict=True))
    payloads = load_payloads(jars)
    patched = sum(patch_jar(path, payloads) for path in sorted(root.rglob("*.jar")))
    if not patched:
        raise SystemExit("no jar embedding jackson-databind found; bundle layout changed")
    print(f"patched {patched} jar(s), skipped {len(SKIPPED)} relocated")
    if SKIPPED and os.environ.get("JACKSON_FAIL_ON_RELOCATED") == "1":
        raise SystemExit("relocated jackson copies remain: " + ", ".join(map(str, SKIPPED)))


if __name__ == "__main__":
    main()
