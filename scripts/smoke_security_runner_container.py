#!/usr/bin/env python3
"""Exercise the security runner against a real local Docker daemon.

This is deliberately separate from unit tests: it proves the socket mount,
workspace ownership, nested container options, and cleanup actually work.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER_IMAGE = "blackonyx-security-runner:container-smoke"
SANDBOX_IMAGE = "python:3.12.14-slim"


def docker(*args: str) -> str:
    try:
        result = subprocess.run(
            ["docker", *args], check=True, text=True, capture_output=True, cwd=ROOT,
            # Docker output is UTF-8; the Windows default codepage cannot decode it.
            encoding="utf-8", errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Docker command failed: {args[0]}\n{exc.stderr[-4000:]}") from exc
    return result.stdout.strip()


def sandbox_container_ids() -> set[str]:
    return set(docker("ps", "-a", "--filter", "label=black-onyx.runner=true", "--format", "{{.ID}}").splitlines())


SMOKE = r'''
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
import time

token, session = sys.argv[1:3]
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
def post(path, body, *, authorized=True):
    request = urllib.request.Request(
        "http://127.0.0.1:8080" + path,
        data=json.dumps(body).encode(),
        headers=headers if authorized else {"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)

workspace = Path("/workspace", session)
for _ in range(40):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=1):
            break
    except urllib.error.URLError:
        time.sleep(0.25)
else:
    raise AssertionError("Runner did not start")
assert post("/workspace", {"session": session})[0] == 200
workspace.joinpath("hello.txt").write_text("runner-live-smoke\n")
base = {"session": session, "tool": "Read", "timeout": 15}
assert post("/execute", {**base, "argv": ["/bin/cat", str(workspace / "hello.txt")]}, authorized=False)[0] == 401
status, read = post("/execute", {**base, "argv": ["/bin/cat", str(workspace / "hello.txt")]})
assert status == 200 and read["status"] == "success" and read["output"] == "runner-live-smoke\n", read
_, write = post("/execute", {**base, "argv": ["/bin/sh", "-c", f"echo bypass > {workspace / 'blocked.txt'}"]})
assert write["status"] == "error" and not (workspace / "blocked.txt").exists(), write
_, network = post("/execute", {**base, "argv": ["python3", "-c", "import socket; s=socket.socket(); s.settimeout(1); print(s.connect_ex(('1.1.1.1',80)))"]})
assert network["output"].strip() == "101", network
status, denied_egress = post("/execute", {
    **base, "tool": "nmap_scan", "argv": ["nmap", "93.184.216.34"],
    "network_profile": "public", "destinations": ["93.184.216.34"],
})
assert status == 503 and "per-job" in denied_egress["detail"].lower(), denied_egress
_, stdin = post("/execute", {"session": session, "tool": "Bash", "argv": ["python3", "-c", "import sys; print(sys.stdin.read().strip())"], "stdin": "runner-stdin", "timeout": 15})
assert stdin["status"] == "success" and stdin["output"].strip() == "runner-stdin", stdin
assert not [path for path in workspace.iterdir() if path.name.startswith(".stdin-")]
print("authenticated execution, read-only mount, offline network, egress rejection, stdin and cleanup passed")
'''


def main() -> None:
    docker("build", "-f", "services/security-runner/Dockerfile", "-t", RUNNER_IMAGE, ".")
    docker("pull", SANDBOX_IMAGE)
    sandbox_id = docker(
        "image", "inspect", SANDBOX_IMAGE, "--format", "{{index .RepoDigests 0}}",
    )
    if "@sha256:" not in sandbox_id:
        raise RuntimeError("Sandbox smoke image did not resolve to a repository digest")
    before = sandbox_container_ids()
    workspace = Path(tempfile.mkdtemp(prefix=".runner-smoke-", dir=ROOT))
    workspace.chmod(0o777)
    container = f"blackonyx-runner-smoke-{uuid.uuid4().hex[:10]}"
    token = uuid.uuid4().hex + uuid.uuid4().hex
    session = uuid.uuid4().hex + uuid.uuid4().hex + "/work"
    socket_gid = os.environ.get("SECURITY_DOCKER_SOCKET_GID")
    if socket_gid is None:
        socket_gid = str(os.stat("/var/run/docker.sock").st_gid) if os.name == "posix" else "0"
    try:
        docker(
            "run", "-d", "--name", container, "--network", "none",
            "--group-add", socket_gid,
            "-v", f"{workspace}:/workspace",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-e", f"SECURITY_RUNNER_TOKEN={token}",
            "-e", f"SECURITY_SANDBOX_IMAGE={sandbox_id}",
            "-e", "SECURITY_EGRESS_NETWORK=blackonyx_sandbox_egress",
            "-e", "SESSIONS_ROOT=/workspace", RUNNER_IMAGE,
        )
        print(docker("exec", container, "/usr/local/bin/python", "-c", SMOKE, token, session))
        assert sandbox_container_ids() == before, "Runner left a sandbox container behind"
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
        resolved = workspace.resolve()
        if not resolved.is_relative_to(ROOT.resolve()) or resolved == ROOT.resolve():
            raise RuntimeError("Unsafe runner smoke cleanup path")
        if os.name == "posix":
            owner = f"{os.getuid()}:{os.getgid()}"
            docker(
                "run", "--rm", "--user", "0", "-v", f"{resolved}:/workspace",
                SANDBOX_IMAGE, "sh", "-c", f"chown -R {owner} /workspace",
            )
        shutil.rmtree(resolved)


if __name__ == "__main__":
    main()
