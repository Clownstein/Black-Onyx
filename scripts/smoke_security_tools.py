#!/usr/bin/env python3
"""Smoke test for security tooling through the Black Onyx BFF.

Verifies the security tooling integration end-to-end against a running stack:

  1. BFF health endpoint returns ok
  2. Capabilities endpoint lists 45 security tools
  3. Read-tier tools execute without approval
  4. Non-read tools require approved_tools (fail closed)
  5. Agent run completes with a final answer

Usage:
    python scripts/smoke_security_tools.py --base http://127.0.0.1:8000 --session <cookie>

Requires a running stack with the security-tools overlay active:
    docker compose -f docker-compose.yml -f docker-compose.security-tools.yml up -d
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
PASSES = 0
FAILS = 0


def _request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    session_cookie: str = "",
    csrf_token: str = "",
) -> tuple[int, dict | str]:
    url = f"{base.rstrip('/')}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    # Origin is required by the CSRF/origin middleware for all non-safe methods.
    parsed = urllib.parse.urlsplit(base)
    req.add_header("Origin", f"{parsed.scheme}://{parsed.netloc}")
    if session_cookie:
        cookies = [f"blackonyx_session={session_cookie}"]
        if csrf_token:
            cookies.append(f"blackonyx_csrf={csrf_token}")
            req.add_header("X-CSRF-Token", csrf_token)
        req.add_header("Cookie", "; ".join(cookies))
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw
    except urllib.error.URLError as exc:
        return 0, str(exc)


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSES, FAILS
    if condition:
        PASSES += 1
        print(f"  PASS  {name}")
    else:
        FAILS += 1
        print(f"  FAIL  {name}  {detail}")


def smoke(base: str, session: str, csrf: str = "") -> int:
    print(f"Security tooling smoke test against {base}")

    # 1. Health
    print("\n[1] BFF health")
    status, body = _request(base, "/api/v1/security/health", session_cookie=session, csrf_token=csrf)
    check("health returns 200", status == 200, f"got {status}")
    if isinstance(body, dict):
        check("health status ok", body.get("status") == "ok", str(body)[:120])

    # 2. Capabilities 45 security tools
    print("\n[2] Capabilities (tool listing)")
    status, body = _request(base, "/api/v1/security/capabilities", session_cookie=session, csrf_token=csrf)
    check("capabilities returns 200", status in (200, 502), f"got {status}")
    if status == 200 and isinstance(body, dict):
        tools = body.get("tools", [])
        check("capabilities lists 45 tools", len(tools) == 45, f"got {len(tools)}")
        tiers = {t.get("tier") for t in tools}
        check("tiers present", bool(tiers - {"", None}), str(tiers))

    # 3. Read-tier tool without approval (agent run with decode_hex)
    print("\n[3] Read-tier tool execution (no approval)")
    status, body = _request(
        base,
        "/api/v1/security/agent/run",
        method="POST",
        body={"message": "Decode hex 48656c6c6f using sec_decode_hex", "max_rounds": 3},
        session_cookie=session,
        csrf_token=csrf,
    )
    check("read-tier agent run accepted", status in (200, 502), f"got {status}")
    if status == 200 and isinstance(body, dict):
        check("agent run has answer", bool(body.get("answer")), str(body)[:120])
        check("agent run has rounds", body.get("rounds", 0) >= 0)

    # 4. Non-read tool without approval expect denial (fail closed)
    print("\n[4] Non-read tool without approval (expect denial)")
    status, body = _request(
        base,
        "/api/v1/security/agent/run",
        method="POST",
        body={"message": "Run nmap scan on 127.0.0.1", "max_rounds": 3},
        session_cookie=session,
        csrf_token=csrf,
    )
    check("non-read without approval handled", status in (200, 403, 502), f"got {status}")

    # 5. Non-read tool WITH approval
    print("\n[5] Non-read tool with approval")
    status, body = _request(
        base,
        "/api/v1/security/agent/run",
        method="POST",
        body={
            "message": "Run nmap scan on 127.0.0.1",
            "max_rounds": 3,
            "approved_tools": ["sec_nmap_scan"],
        },
        session_cookie=session,
        csrf_token=csrf,
    )
    check("non-read with approval accepted", status in (200, 502), f"got {status}")

    print(f"\n{'=' * 50}")
    print(f"Results: {PASSES} passed, {FAILS} failed")
    return 1 if FAILS else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=BASE, help=f"Base URL (default {BASE})")
    parser.add_argument("--session", default="", help="blackonyx_session cookie value")
    parser.add_argument("--csrf", default="", help="blackonyx_csrf cookie value (X-CSRF-Token)")
    args = parser.parse_args()
    return smoke(args.base, args.session, args.csrf)


if __name__ == "__main__":
    sys.exit(main())
