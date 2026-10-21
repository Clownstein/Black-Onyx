"""Decoded streamed bodies must not be decompressed a second time."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_streamed_gzip_body_is_not_decoded_twice(monkeypatch):
    import httpx

    from black_onyx.net.safe_url import request_public_https

    body = b"<?xml version='1.0'?><rss><channel><title>ok</title></channel></rss>"

    class FakeResponse:
        status_code = 200
        is_redirect = False
        headers = httpx.Headers({
            "content-type": "application/rss+xml",
            "content-encoding": "gzip",
            "content-length": "12",
        })

        async def aiter_bytes(self):
            yield body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class FakeClient:
        def stream(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", ("93.184.216.34", 443))],
    )
    response = await request_public_https(
        FakeClient(),
        "GET",
        "https://feeds.example.com/rss",
        max_bytes=1024,
        purpose="Feed URL",
    )
    assert response.content == body
    assert response.headers.get("content-encoding") is None
