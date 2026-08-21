"""Request headers for Black Onyx MCP service authentication."""

from black_onyx_tools.config import Settings


def headers(settings: Settings, *, json_content: bool = True) -> dict[str, str]:
    """Return auth headers for platform API calls.

    Omit Content-Type when posting multipart so httpx can set the boundary.
    """
    out: dict[str, str] = {
        "X-Tenant-Id": settings.default_tenant_id,
    }
    if json_content:
        out["Content-Type"] = "application/json"
    if settings.mcp_service_key:
        out["X-MCP-Service-Key"] = settings.mcp_service_key
    return out
