"""Run inside a just-built toolbox image before it is tagged or published."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path


manifest = json.loads(Path("/usr/share/blackonyx/toolbox-manifest.json").read_text())
missing_bins = [name for name in manifest["binary_requirements"] if shutil.which(name) is None]
missing_modules = [
    name for name in manifest["python_requirements"]
    if importlib.util.find_spec(name) is None
]
if missing_bins or missing_modules:
    raise SystemExit(json.dumps({"missing_bins": missing_bins, "missing_modules": missing_modules}))

for helper_name in manifest.get("trusted_helpers", []):
    helper = Path("/usr/share/blackonyx") / helper_name
    if helper.parent != Path("/usr/share/blackonyx") or helper.is_symlink() or not helper.is_file():
        raise SystemExit(f"missing trusted helper: {helper_name}")
    if os.access(helper, os.W_OK):
        raise SystemExit(f"trusted helper is writable: {helper_name}")

for name, spec in manifest["wordlists"].items():
    path = Path("/usr/share/blackonyx/wordlists") / name
    if path.is_symlink() or not path.is_file() or len(path.read_text().splitlines()) > spec["maximum_lines"]:
        raise SystemExit(f"invalid bounded wordlist: {name}")
    if os.access(path, os.W_OK):
        raise SystemExit(f"wordlist is writable: {name}")

if os.getuid() != 10001:
    raise SystemExit("toolbox must run as uid 10001")
print(json.dumps({"status": "ok", "binaries": len(manifest["binary_requirements"]), "modules": len(manifest["python_requirements"])}))
