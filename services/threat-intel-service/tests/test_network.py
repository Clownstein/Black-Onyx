from __future__ import annotations

import httpx
import pytest

from threat_intel_service.network import request_json_bounded, validate_public_https_url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/feed.json",
        "https://127.0.0.1/feed.json",
        "https://169.254.169.254/latest/meta-data",
        "https://user:password@example.com/feed.json",
    ],
)
def test_feed_url_rejects_unsafe_destinations(url: str) -> None:
    with pytest.raises(ValueError):
        validate_public_https_url(url, resolve_dns=False)


@pytest.mark.asyncio
async def test_feed_response_is_stream_bounded() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"items":"' + (b"x" * 100) + b'"}')

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="byte limit"):
            await request_json_bounded(
                client,
                "GET",
                "https://feed.example/data.json",
                max_bytes=32,
            )
