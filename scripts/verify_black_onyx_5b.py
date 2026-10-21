#!/usr/bin/env python3
"""Verify Black Onyx 5B / OpenAI-compatible LLM deployment checklist."""

from __future__ import annotations

import argparse
import json
import os
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description="Black Onyx 5B integration verification")
    parser.add_argument("--base-url", default=os.environ.get("BLACK_ONYX_BASE_URL", "http://127.0.0.1:8100"))
    parser.add_argument("--vllm-url", default=os.environ.get("VLLM_BASE_URL", "http://127.0.0.1:8081/v1"))
    parser.add_argument("--model", default=os.environ.get("BLACK_ONYX_5B_MODEL", "Black-Onyx-5B:Q8_0"))
    parser.add_argument("--cookie", default="", help="Optional session cookie for authenticated TIP checks")
    parser.add_argument("--csrf", default="", help="Optional CSRF token header value")
    parser.add_argument("--probe-stream", action="store_true", help="POST /api/v1/chat/stream and check SSE events")
    args = parser.parse_args()

    results: dict[str, object] = {"checks": []}

    def record(name: str, ok: bool, detail: str = "") -> None:
        results["checks"].append({"name": name, "ok": ok, "detail": detail})

    try:
        models = httpx.get(f"{args.vllm_url.rstrip('/')}/models", timeout=10.0)
        record("vllm_models", models.status_code == 200, models.text[:200])
    except Exception as exc:
        record("vllm_models", False, str(exc))

    headers: dict[str, str] = {}
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.csrf:
        headers["X-CSRF-Token"] = args.csrf

    try:
        health = httpx.get(f"{args.base_url.rstrip('/')}/api/v1/health", timeout=10.0, headers=headers)
        record("tip_health", health.status_code == 200, health.text[:120])
    except Exception as exc:
        record("tip_health", False, str(exc))

    if args.cookie:
        try:
            llm_test = httpx.get(
                f"{args.base_url.rstrip('/')}/api/v1/llm/test",
                timeout=30.0,
                headers=headers,
            )
            record("tip_llm_test", llm_test.status_code == 200, llm_test.text[:200])
        except Exception as exc:
            record("tip_llm_test", False, str(exc))
    else:
        record("tip_llm_test", False, "skipped — pass --cookie for authenticated llm/test")

    if args.probe_stream:
        if not args.cookie:
            record("tip_chat_stream", False, "skipped — --probe-stream requires --cookie")
        else:
            try:
                stream_headers = {
                    **headers,
                    "Accept": "text/event-stream",
                    "Content-Type": "application/json",
                }
                tokens = 0
                reasoning = 0
                with httpx.stream(
                    "POST",
                    f"{args.base_url.rstrip('/')}/api/v1/chat/stream",
                    headers=stream_headers,
                    json={
                        "message": "Reply with exactly: OK",
                        "use_rag": False,
                        "use_web_search": False,
                        "use_mcp_tools": False,
                    },
                    timeout=60.0,
                ) as response:
                    ok_status = response.status_code == 200
                    for line in response.iter_lines():
                        if line.startswith("event: token"):
                            tokens += 1
                        elif line.startswith("event: reasoning"):
                            reasoning += 1
                record(
                    "tip_chat_stream",
                    ok_status and tokens > 0,
                    f"status_ok={ok_status} token_events={tokens} reasoning_events={reasoning}",
                )
            except Exception as exc:
                record("tip_chat_stream", False, str(exc))

    results["model"] = args.model
    print(json.dumps(results, indent=2))
    required = [c for c in results["checks"] if c["name"] in {"vllm_models", "tip_health"}]
    if args.cookie:
        required.extend(c for c in results["checks"] if c["name"] == "tip_llm_test")
    if args.probe_stream and args.cookie:
        required.extend(c for c in results["checks"] if c["name"] == "tip_chat_stream")
    ok = all(item["ok"] for item in required)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
