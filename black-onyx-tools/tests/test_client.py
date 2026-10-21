"""PlatformClient HTTP tests with respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import Settings


@pytest.mark.asyncio
async def test_tip_get_success(settings: Settings) -> None:
    with respx.mock(base_url=settings.base_url) as router:
        route = router.get("/api/v1/cases").mock(return_value=httpx.Response(200, json={"cases": []}))
        async with PlatformClient(settings) as client:
            payload = await client.tip_get("/api/v1/cases")
        assert payload == {"cases": []}
        assert route.called


@pytest.mark.asyncio
async def test_tip_post_raises_with_body(settings: Settings) -> None:
    with respx.mock(base_url=settings.base_url) as router:
        router.post("/api/v1/search").mock(
            return_value=httpx.Response(422, text='{"detail":"bad query"}'),
        )
        async with PlatformClient(settings) as client:
            with pytest.raises(httpx.HTTPStatusError) as exc:
                await client.tip_post("/api/v1/search", json={"query": "", "collection": "x"})
        assert "422" in str(exc.value)
        assert "bad query" in str(exc.value)


@pytest.mark.asyncio
async def test_detection_path_prefix(settings: Settings) -> None:
    with respx.mock(base_url=settings.base_url) as router:
        route = router.get("/api/v1/detection/incident/api/v1/hunt/search").mock(
            return_value=httpx.Response(200, json={"hits": [], "total": 0}),
        )
        async with PlatformClient(settings) as client:
            payload = await client.detection_get("incident", "/api/v1/hunt/search", params={"q": "x"})
        assert payload["total"] == 0
        assert route.called


@pytest.mark.asyncio
async def test_auth_headers(settings: Settings) -> None:
    with respx.mock(base_url=settings.base_url) as router:
        route = router.get("/api/v1/health").mock(return_value=httpx.Response(200, json={"ok": True}))
        async with PlatformClient(settings) as client:
            await client.tip_get("/api/v1/health")
        request = route.calls.last.request
        assert request.headers["X-MCP-Service-Key"] == "test-key"
        assert request.headers["X-Tenant-Id"] == "tenant-test"


def test_platform_client_requires_service_key(settings: Settings) -> None:
    settings.mcp_service_key = ""
    with pytest.raises(ValueError, match="BLACK_ONYX_MCP_SERVICE_KEY"):
        PlatformClient(settings)


@pytest.mark.asyncio
async def test_tip_post_multipart(settings: Settings) -> None:
    with respx.mock(base_url=settings.base_url) as router:
        route = router.post("/api/v1/search/image").mock(
            return_value=httpx.Response(200, json={"results": [], "total": 0}),
        )
        async with PlatformClient(settings) as client:
            payload = await client.tip_post_multipart(
                "/api/v1/search/image",
                files={"image": ("x.png", b"png", "image/png")},
                data={"collection": "all-knowledge", "limit": "5"},
            )
        assert payload["total"] == 0
        assert route.called
        # Multipart must not force application/json
        assert "multipart/form-data" in route.calls.last.request.headers["content-type"]
