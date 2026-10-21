#!/usr/bin/env python3
"""Prove the final code-model image serves a signed artifact over HTTP."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "blackonyx-code-model:ci"
SIGNING_KEY = "code-model-image-smoke-only"


def docker(*args: str) -> str:
    try:
        result = subprocess.run(
            ["docker", *args], cwd=ROOT, check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Docker {args[0]} failed:\n{exc.stderr[-4000:]}") from exc
    return result.stdout.strip()


GENERATE = r'''
import joblib
import numpy as np
from pathlib import Path
from sklearn.dummy import DummyClassifier
from black_onyx_model_package import build_model_package
from code_model.features import FEATURE_NAMES

root = Path("/output")
source = root / "trained.joblib"
model = DummyClassifier(strategy="prior")
model.fit(
    np.array([[0.0] * len(FEATURE_NAMES), [1.0] * len(FEATURE_NAMES)]),
    np.array([0, 1]),
)
joblib.dump({"model": model, "version": "smoke-v1", "feature_names": FEATURE_NAMES}, source)
build_model_package(
    root, model_name="code-model", version="smoke-v1",
    dataset_manifest={"feature_schema": {"features": FEATURE_NAMES}},
    signing_key="code-model-image-smoke-only", metrics={"f1": 0.5},
    thresholds={"high": 0.8}, config={"model_name": "code-model"},
    calibration={}, model_source=source,
)
print("signed test package built")
'''


CHECK = r'''
import json
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:8103"
for _ in range(60):
    try:
        with urllib.request.urlopen(base + "/health/live", timeout=1) as response:
            assert response.status == 200
            break
    except urllib.error.URLError:
        time.sleep(0.25)
else:
    raise AssertionError("Code-model HTTP server did not start")
with urllib.request.urlopen(base + "/health/ready", timeout=3) as response:
    assert response.status == 200 and json.load(response)["artifact_loaded"] is True
request = urllib.request.Request(
    base + "/v1/predict", method="POST",
    headers={"Content-Type": "application/json"},
    data=json.dumps({"diff_text": "+eval(x)", "files_changed": ["src/x.py"]}).encode(),
)
with urllib.request.urlopen(request, timeout=10) as response:
    prediction = json.load(response)
assert prediction["model_version"] == "smoke-v1", prediction
assert 0 <= prediction["risk_score"] <= 1
print("signed package ready and prediction served over HTTP")
'''


def main() -> None:
    workspace = Path(tempfile.mkdtemp(prefix=".code-model-image-smoke-", dir=ROOT))
    workspace.chmod(0o777)
    container = f"blackonyx-code-model-smoke-{uuid.uuid4().hex[:10]}"
    try:
        print(docker(
            "run", "--rm", "--network", "none", "-v", f"{workspace}:/output",
            "--entrypoint", "/usr/local/bin/python", IMAGE, "-c", GENERATE,
        ))
        docker(
            "run", "-d", "--name", container, "--network", "none",
            "-v", f"{workspace / 'model-package'}:/app/artifacts:ro",
            "-e", f"CODE_MODEL_ARTIFACT_SIGNING_KEY={SIGNING_KEY}", IMAGE,
        )
        print(docker("exec", container, "/usr/local/bin/python", "-c", CHECK))
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
        resolved = workspace.resolve()
        if not resolved.is_relative_to(ROOT.resolve()) or resolved == ROOT.resolve():
            raise RuntimeError("Unsafe code-model smoke cleanup path")
        if os.name == "posix":
            docker(
                "run", "--rm", "--user", "0", "-v", f"{resolved}:/output",
                "--entrypoint", "/usr/local/bin/python", IMAGE, "-c",
                "import os,sys; uid,gid=map(int,sys.argv[1:3]); "
                "[(os.chown(os.path.join(root,name),uid,gid)) "
                "for root,dirs,files in os.walk('/output') for name in dirs+files]; "
                "os.chown('/output',uid,gid)",
                str(os.getuid()), str(os.getgid()),
            )
        shutil.rmtree(resolved)


if __name__ == "__main__":
    main()
