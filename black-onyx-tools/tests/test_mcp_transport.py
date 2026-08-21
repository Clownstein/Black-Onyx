"""Transport selection / HTTP gate tests."""

from __future__ import annotations

import pytest
from mcp.server.fastmcp import FastMCP

from black_onyx_tools.mcp_app import run_mcp


def test_http_transport_requires_dangerous_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLACK_ONYX_TOOLS_MCP_TRANSPORT", "sse")
    monkeypatch.delenv("BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS", raising=False)
    monkeypatch.setenv("BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN", "x" * 16)
    with pytest.raises(SystemExit, match="HTTP_DANGEROUS"):
        run_mcp(FastMCP("t"), default_port=8200)


def test_http_transport_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BLACK_ONYX_TOOLS_MCP_TRANSPORT", "sse")
    monkeypatch.setenv("BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS", "true")
    monkeypatch.delenv("BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="HTTP_TOKEN"):
        run_mcp(FastMCP("t"), default_port=8200)
