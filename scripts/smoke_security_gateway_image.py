#!/usr/bin/env python3
"""Exercise the final gateway image, HTTP startup, and durable approvals."""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "blackonyx-security-gateway:ci"
CONTAINER = f"blackonyx-gateway-smoke-{uuid.uuid4().hex[:10]}"
VOLUME = f"{CONTAINER}-state"


def docker(*args: str) -> str:
    try:
        result = subprocess.run(
            ["docker", *args], cwd=ROOT, check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Docker {args[0]} failed:\n{exc.stderr[-4000:]}") from exc
    return result.stdout.strip()


CHECK_HEALTH = r'''
import time
import urllib.error
import urllib.request

for _ in range(60):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/health/", timeout=1) as response:
            assert response.status == 200
            print("gateway HTTP health passed")
            break
    except urllib.error.URLError:
        time.sleep(0.25)
else:
    raise AssertionError("Gateway did not start")
'''

APPROVE = r'''
from security_gateway.approvals import approve
print(approve("smoke-actor", "Bash", {"arguments": {"x": 1}}, "smoke-admin"))
'''

CONSUME = r'''
import sys
from security_gateway.approvals import consume

body = {"arguments": {"x": 1}}
assert consume(sys.argv[1], "smoke-actor", "Bash", body)
assert not consume(sys.argv[1], "smoke-actor", "Bash", body)
print("durable single-use approval passed")
'''


def start() -> None:
    docker(
        "run", "-d", "--name", CONTAINER, "--network", "none",
        "-v", f"{VOLUME}:/app/state",
        "-e", "SECURITY_APPROVAL_DB=/app/state/approvals.db",
        "-e", "SECURITY_GATEWAY_KEY=container-smoke-only-signing-key-32-bytes",
        IMAGE,
    )


def main() -> None:
    try:
        start()
        print(docker("exec", CONTAINER, "/usr/local/bin/python", "-c", CHECK_HEALTH))
        approval_id = docker("exec", CONTAINER, "/usr/local/bin/python", "-c", APPROVE)
        docker("rm", "-f", CONTAINER)
        start()
        print(docker("exec", CONTAINER, "/usr/local/bin/python", "-c", CONSUME, approval_id))
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, text=True)
        subprocess.run(["docker", "volume", "rm", VOLUME], capture_output=True, text=True)


if __name__ == "__main__":
    main()
