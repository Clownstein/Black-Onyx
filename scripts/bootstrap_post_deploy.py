#!/usr/bin/env python3
"""Post-deploy configuration and authenticated smoke checks for bootstrap.

Logs in as the bootstrapped administrator (credentials from the environment,
never argv), points MISP sync at the compose ``misp`` service when
``MISP_API_KEY`` is set, and verifies the surfaces a first launch depends on:

  * TIP API health
  * collector install guide (osquery / Wazuh / Suricata) and package files
  * Security Lab tool matrix proxied from security-gateway ``/health/tools``
  * MISP sync configuration

Exit status is non-zero when any required check fails.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any


class TipClient:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.headers = {"Content-Type": "application/json", "Origin": self.base}
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def call(self, method: str, path: str, body: Any = None, timeout: float = 30) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
        with self.opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None

    def wait_healthy(self, seconds: int) -> None:
        deadline = time.monotonic() + seconds
        while True:
            try:
                self.call("GET", "/api/v1/health", timeout=5)
                return
            except (urllib.error.URLError, OSError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(3)

    def login(self, email: str, password: str) -> None:
        result = self.call("POST", "/api/v1/auth/login", {"email": email, "password": password})
        if not isinstance(result, dict) or not result.get("csrf_token"):
            raise RuntimeError("login did not return a CSRF token (MFA-enforced admin?)")
        self.headers["X-CSRF-Token"] = result["csrf_token"]


def check_collectors(tip: TipClient) -> list[str]:
    problems: list[str] = []
    guide = tip.call("GET", "/api/v1/collectors/guide")
    ids = {g.get("id") for g in guide.get("guides", [])}
    for expected in ("osquery_shipper", "wazuh", "suricata"):
        if expected not in ids:
            problems.append(f"collector guide missing {expected}")
    for package in guide.get("packages", []):
        if not package.get("available"):
            problems.append(f"collector package {package.get('os')} is incomplete")
    print(f"  gateway URL for agents: {guide.get('gateway_url')}")
    print(f"  Wazuh manager address: {guide.get('wazuh_manager')}")
    return problems


def check_security_tools(tip: TipClient) -> list[str]:
    matrix = tip.call("GET", "/api/v1/security/capabilities")
    tools = matrix.get("tools") or []
    if not tools:
        return ["security-gateway returned no tools"]
    enabled = [t["name"] for t in tools if t.get("status") == "enabled"]
    print(f"  security tools: {len(enabled)}/{len(tools)} enabled")
    return [] if enabled else ["no security tools are enabled (check egress/capture verification)"]


def configure_misp(tip: TipClient, url: str) -> list[str]:
    if not (os.environ.get("MISP_API_KEY") or "").strip():
        return ["MISP_API_KEY is unset; MISP sync not configured"]
    tip.call("PUT", "/api/v1/misp/configure", {"url": url, "enabled": True})
    print(f"  MISP sync configured for {url}")
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tip-url", default=os.environ.get("BLACK_ONYX_URL") or "http://127.0.0.1:8000")
    parser.add_argument("--misp-url", default="http://misp")
    parser.add_argument("--wait-seconds", type=int, default=180)
    args = parser.parse_args()

    email = os.environ.get("BLACK_ONYX_ADMIN_EMAIL", "")
    password = os.environ.get("BLACK_ONYX_ADMIN_PASSWORD", "")
    if not email or not password:
        print("FAIL: BLACK_ONYX_ADMIN_EMAIL / BLACK_ONYX_ADMIN_PASSWORD must be set", file=sys.stderr)
        return 1

    tip = TipClient(args.tip_url)
    failures: list[str] = []
    try:
        tip.wait_healthy(args.wait_seconds)
        print("ok   TIP API health")
        tip.login(email, password)
        print("ok   admin login")
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        print(f"FAIL TIP unavailable: {exc}", file=sys.stderr)
        return 1

    for name, check in (
        ("collector install guides", lambda: check_collectors(tip)),
        ("security tools", lambda: check_security_tools(tip)),
        ("MISP sync", lambda: configure_misp(tip, args.misp_url)),
    ):
        try:
            problems = check()
        except urllib.error.HTTPError as exc:
            problems = [f"HTTP {exc.code} from {exc.url}"]
        except (urllib.error.URLError, OSError, KeyError, TypeError, ValueError) as exc:
            problems = [str(exc)]
        if problems:
            failures.extend(f"{name}: {p}" for p in problems)
            print(f"FAIL {name}: {'; '.join(problems)}", file=sys.stderr)
        else:
            print(f"ok   {name}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
