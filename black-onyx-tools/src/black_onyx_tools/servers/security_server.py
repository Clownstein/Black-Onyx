"""Security MCP server 45 executors plus 4 approval/run controls.

Tools are named sec_<tool> and dispatch through the Black Onyx BFF
(/api/v1/security/*) to the security-gateway service. Default transport
is stdio (what Cursor MCP expects).
"""

from __future__ import annotations

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import get_settings
from black_onyx_tools.mcp_app import create_fastmcp, run_mcp
from black_onyx_tools.tools.sec_tools import register_security_tools

DEFAULT_PORT = 8203


def create_app():
    settings = get_settings()
    client = PlatformClient(settings)
    mcp = create_fastmcp("black-onyx-security", port=DEFAULT_PORT)
    register_security_tools(mcp, client)
    return mcp


def main() -> None:
    run_mcp(create_app(), default_port=DEFAULT_PORT)


if __name__ == "__main__":
    main()
