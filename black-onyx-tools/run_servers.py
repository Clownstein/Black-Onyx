"""Launch tip/detection/ops MCP servers as subprocesses.

Default transport is **stdio** (what Cursor MCP expects).

Optional HTTP for local debugging only:

  $env:BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS = "true"
  $env:BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN = "<random-16+-chars>"
  python run_servers.py --http

Binds tip:8200 detection:8201 ops:8202 on 127.0.0.1 with bearer token auth.
Cursor should keep using stdio entrypoints (`black-onyx-*-mcp`).
"""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time

SERVERS = {
    "tip": {
        "module": "black_onyx_tools.servers.tip_server",
        "port": 8200,
    },
    "detection": {
        "module": "black_onyx_tools.servers.detection_server",
        "port": 8201,
    },
    "ops": {
        "module": "black_onyx_tools.servers.ops_server",
        "port": 8202,
    },
}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Launch Black Onyx MCP servers")
    parser.add_argument(
        "--http",
        action="store_true",
        help=(
            "Use SSE HTTP on tip:8200 detection:8201 ops:8202 (requires "
            "BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS=true and HTTP_TOKEN)"
        ),
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=None,
        help="Override MCP transport (default: stdio, or sse when --http)",
    )
    args = parser.parse_args(argv)

    transport = args.transport
    if transport is None:
        transport = "sse" if args.http else "stdio"

    if transport != "stdio":
        os.environ.setdefault("BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS", "true")
        if not (os.environ.get("BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN") or "").strip():
            generated = secrets.token_urlsafe(24)
            os.environ["BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN"] = generated
            print(
                f"Generated BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN={generated}\n"
                "Clients must send Authorization: Bearer <token> "
                "(or X-MCP-HTTP-Token).",
                file=sys.stderr,
            )

    processes: list[subprocess.Popen[bytes]] = []
    for name, config in SERVERS.items():
        env = os.environ.copy()
        env["BLACK_ONYX_TOOLS_MCP_TRANSPORT"] = transport
        if transport != "stdio":
            env["BLACK_ONYX_TOOLS_MCP_PORT"] = str(config["port"])
            print(f"Starting {name} MCP server ({transport} on 127.0.0.1:{config['port']})...")
        else:
            env.pop("BLACK_ONYX_TOOLS_MCP_PORT", None)
            print(f"Starting {name} MCP server (stdio; reserved debug port {config['port']})...")
        proc = subprocess.Popen([sys.executable, "-m", config["module"]], env=env)
        processes.append(proc)
        time.sleep(0.5)

    print("All MCP servers started.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down MCP servers...")
        for proc in processes:
            proc.terminate()
        for proc in processes:
            proc.wait()
        print("Done.")


if __name__ == "__main__":
    main()
