"""FastMCP factory helpers and transport selection."""

from __future__ import annotations

import os
import secrets
from typing import Callable

from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def create_fastmcp(name: str, *, port: int = 8000) -> FastMCP:
    """Create a FastMCP server instance (host/port used only for HTTP transports)."""
    return FastMCP(name, host="127.0.0.1", port=port)


def _truthy(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


class _BearerTokenMiddleware(BaseHTTPMiddleware):
    """Require Bearer / X-MCP-HTTP-Token for all HTTP MCP requests."""

    def __init__(self, app: Callable, expected_token: str) -> None:
        super().__init__(app)
        self._expected = expected_token

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = (request.headers.get("x-mcp-http-token") or "").strip()
        auth = (request.headers.get("authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip() or supplied
        if not supplied or not secrets.compare_digest(supplied, self._expected):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)


def run_mcp(mcp: FastMCP, *, default_port: int) -> None:
    """Run FastMCP with stdio (default) or optional HTTP transport from env.

    Env:
      BLACK_ONYX_TOOLS_MCP_TRANSPORT = stdio | sse | streamable-http (default stdio)
      BLACK_ONYX_TOOLS_MCP_PORT = override listen port for HTTP transports
      BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS = must be true for non-stdio
      BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN = required bearer token (>=16 chars) for HTTP
    """
    transport = (os.environ.get("BLACK_ONYX_TOOLS_MCP_TRANSPORT") or "stdio").strip().lower()
    if transport in {"", "stdio"}:
        mcp.run(transport="stdio")
        return
    if transport not in {"sse", "streamable-http"}:
        raise SystemExit(
            f"Unsupported BLACK_ONYX_TOOLS_MCP_TRANSPORT={transport!r}; "
            "use stdio, sse, or streamable-http",
        )
    if not _truthy("BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS"):
        raise SystemExit(
            "HTTP MCP transport requires BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS=true. "
            "Prefer stdio for Cursor. HTTP is local-debug only.",
        )
    token = (os.environ.get("BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN") or "").strip()
    if len(token) < 16:
        raise SystemExit(
            "HTTP MCP transport requires BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN "
            "(at least 16 characters). Send it as Authorization: Bearer <token> "
            "or X-MCP-HTTP-Token.",
        )

    port = int(os.environ.get("BLACK_ONYX_TOOLS_MCP_PORT") or default_port)
    mcp.settings.port = port
    mcp.settings.host = "127.0.0.1"

    if transport == "sse":
        app = mcp.sse_app()
    else:
        app = mcp.streamable_http_app()
    app.add_middleware(_BearerTokenMiddleware, expected_token=token)

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
