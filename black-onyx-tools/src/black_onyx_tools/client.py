"""Async HTTP client for Black Onyx TIP and detection BFF routes."""

from __future__ import annotations

from typing import Any

import httpx

from black_onyx_tools.auth import headers
from black_onyx_tools.config import Settings


class PlatformClient:
    """Thin httpx wrapper over Black Onyx platform APIs."""

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        if not (settings.mcp_service_key or "").strip():
            raise ValueError(
                "BLACK_ONYX_MCP_SERVICE_KEY is required for PlatformClient "
                "(set it in the MCP process environment).",
            )
        self.settings = settings
        self._owns_client = client is None
        # Auth headers only — omit Content-Type so JSON (`json=`) and multipart
        # (`files=`) each set the correct type per request.
        self._client = client or httpx.AsyncClient(
            base_url=settings.base_url.rstrip("/"),
            timeout=settings.timeout,
            headers=headers(settings, json_content=False),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> PlatformClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.is_success:
            return
        body = response.text
        raise httpx.HTTPStatusError(
            f"{response.status_code} {response.reason_phrase}: {body}",
            request=response.request,
            response=response,
        )

    @staticmethod
    def _detection_path(service: str, path: str) -> str:
        if not path.startswith("/"):
            path = f"/{path}"
        return f"/api/v1/detection/{service}{path}"

    async def tip_get(self, path: str, **kwargs: Any) -> Any:
        response = await self._client.get(path, **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def tip_post(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        response = await self._client.post(path, json=json, **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def tip_post_multipart(
        self,
        path: str,
        *,
        files: dict[str, Any],
        data: dict[str, Any] | None = None,
    ) -> Any:
        """POST multipart/form-data (e.g. image search). Omits JSON Content-Type."""
        response = await self._client.post(
            path,
            files=files,
            data=data or {},
        )
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def tip_patch(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        response = await self._client.patch(path, json=json, **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def tip_delete(self, path: str, **kwargs: Any) -> Any:
        response = await self._client.delete(path, **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def detection_get(self, service: str, path: str, **kwargs: Any) -> Any:
        response = await self._client.get(self._detection_path(service, path), **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()

    async def detection_post(self, service: str, path: str, json: Any = None, **kwargs: Any) -> Any:
        response = await self._client.post(self._detection_path(service, path), json=json, **kwargs)
        self._raise_for_status(response)
        if not response.content:
            return {}
        return response.json()
