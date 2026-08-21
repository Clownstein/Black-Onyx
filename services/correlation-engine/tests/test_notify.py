from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from correlation_engine.engine import CorrelationEngine


def _incident(**overrides: Any) -> dict[str, Any]:
    base = {
        "tenant_id": "tenant-a",
        "incident_id": "inc-1",
        "title": "t",
        "status": "open",
        "severity": "high",
        "risk_score": 0.9,
        "category": [],
        "first_seen": "2026-07-26T20:00:00+00:00",
        "last_seen": "2026-07-26T20:01:00+00:00",
        "assets": [],
        "services": [],
        "finding_ids": [],
        "summary": "",
        "models": [],
        "suppress_notification": False,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_publish_notifies_when_not_suppressed() -> None:
    posts: list[str] = []

    class FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(self, url: str, **kwargs: Any) -> MagicMock:
            posts.append(url)
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            return resp

    with patch("correlation_engine.engine.httpx.AsyncClient", FakeClient):
        await CorrelationEngine().publish_incident(_incident())

    assert any("/api/v1/incidents" in u for u in posts)
    assert any("/api/v1/notifications/incident" in u for u in posts)


@pytest.mark.asyncio
async def test_publish_skips_notify_when_suppressed() -> None:
    posts: list[str] = []

    class FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(self, url: str, **kwargs: Any) -> MagicMock:
            posts.append(url)
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            return resp

    with patch("correlation_engine.engine.httpx.AsyncClient", FakeClient):
        await CorrelationEngine().publish_incident(_incident(suppress_notification=True))

    assert any("/api/v1/incidents" in u for u in posts)
    assert not any("notifications" in u for u in posts)


@pytest.mark.asyncio
async def test_notify_soft_fails() -> None:
    class FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(self, url: str, **kwargs: Any) -> MagicMock:
            if "notifications" in url:
                raise ConnectionError("down")
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            return resp

    with patch("correlation_engine.engine.httpx.AsyncClient", FakeClient):
        await CorrelationEngine().publish_incident(_incident(incident_id="inc-3"))
