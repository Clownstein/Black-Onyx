"""PlatformClient-compatible adapter for in-TIP MCP tool execution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
from fastapi import FastAPI

from black_onyx.auth.internal import INTERNAL_TOOL_HEADER, internal_tool_context
from black_onyx.auth.service import Principal


class SessionPlatformClient:
    """Call TIP/detection BFF routes in-process as the chat session principal."""

    def __init__(self, app: FastAPI, principal: Principal) -> None:
        self.settings = SimpleNamespace(
            mcp_service_key="",
            default_tenant_id="",
            allow_sandbox=False,
        )
        self._app = app
        self._principal = principal
        self._transport = httpx.ASGITransport(app=app)
        self._client = httpx.AsyncClient(
            transport=self._transport,
            base_url="http://testserver",
            timeout=320.0,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> SessionPlatformClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.is_success:
            return
        raise httpx.HTTPStatusError(
            f"{response.status_code} {response.reason_phrase}: {response.text}",
            request=response.request,
            response=response,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        files: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        headers = {INTERNAL_TOOL_HEADER: "1"}
        async with internal_tool_context(self._principal):
            response = await self._client.request(
                method,
                path,
                json=json,
                files=files,
                data=data,
                headers=headers,
            )
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def tip_get(self, path: str, **kwargs: Any) -> Any:
        return await self._request("GET", path, json=kwargs.get("json"))

    async def tip_post(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        return await self._request("POST", path, json=json)

    async def tip_post_multipart(
        self,
        path: str,
        *,
        files: dict[str, Any],
        data: dict[str, Any] | None = None,
    ) -> Any:
        return await self._request("POST", path, files=files, data=data or {})

    async def tip_patch(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        return await self._request("PATCH", path, json=json)

    async def tip_delete(self, path: str, **kwargs: Any) -> Any:
        return await self._request("DELETE", path)

    @staticmethod
    def _detection_path(service: str, path: str) -> str:
        if not path.startswith("/"):
            path = f"/{path}"
        return f"/api/v1/detection/{service}{path}"

    async def detection_get(self, service: str, path: str, **kwargs: Any) -> Any:
        return await self._request("GET", self._detection_path(service, path))

    async def detection_post(self, service: str, path: str, json: Any = None, **kwargs: Any) -> Any:
        return await self._request("POST", self._detection_path(service, path), json=json)
