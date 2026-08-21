"""P1 detection tool tests with mocked PlatformClient."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.tools.asset_context import asset_context
from black_onyx_tools.tools.hunt import hunt
from black_onyx_tools.tools.incident_brief import incident_brief
from black_onyx_tools.tools.response_draft import response_draft
from black_onyx_tools.tools.ti_match import ti_match


@pytest.fixture
def mock_client() -> PlatformClient:
    return AsyncMock(spec=PlatformClient)


@pytest.mark.asyncio
async def test_hunt_search(mock_client: PlatformClient) -> None:
    mock_client.detection_get = AsyncMock(return_value={"hits": [{"id": "f1"}], "total": 1})
    result = await hunt(mock_client, mode="search", query="powershell")
    assert result["total"] == 1


@pytest.mark.asyncio
async def test_incident_brief_markdown(mock_client: PlatformClient) -> None:
    mock_client.detection_get = AsyncMock(
        side_effect=[
            {
                "incident_id": "inc-1",
                "title": "Test",
                "severity": "high",
                "status": "open",
                "finding_ids": ["f1"],
            },
            [{"event_type": "created", "created_at": "2026-01-01T00:00:00Z"}],
            {"finding_id": "f1", "model_name": "log-model", "calibrated_score": 0.8},
        ],
    )
    result = await incident_brief(mock_client, incident_id="inc-1")
    assert "Incident brief" in result["brief_markdown"]
    assert result["incident"]["incident_id"] == "inc-1"
    assert result["findings"][0]["finding_id"] == "f1"
    mock_client.detection_get.assert_any_await("incident", "/api/v1/findings/f1")


@pytest.mark.asyncio
async def test_asset_context_by_id(mock_client: PlatformClient) -> None:
    mock_client.detection_get = AsyncMock(
        side_effect=[
            {"asset_id": "a1", "name": "host1"},
            {"nodes": []},
            {"baseline": {}},
            {"items": []},
        ],
    )
    result = await asset_context(mock_client, asset_id="a1")
    assert result["asset_id"] == "a1"


@pytest.mark.asyncio
async def test_response_draft_never_approves(mock_client: PlatformClient) -> None:
    draft = await response_draft(
        mock_client,
        incident_id="inc-1",
        playbook_id="isolate-host",
        confirm=False,
    )
    assert draft["submitted"] is False
    mock_client.detection_post.assert_not_called()


@pytest.mark.asyncio
async def test_response_draft_submit_pending_only(mock_client: PlatformClient) -> None:
    mock_client.detection_post = AsyncMock(return_value={"request_id": "r1", "status": "pending"})
    mock_client.detection_get = AsyncMock(return_value={"items": [{"request_id": "r1"}]})
    result = await response_draft(
        mock_client,
        incident_id="inc-1",
        playbook_id="isolate-host",
        confirm=True,
    )
    assert result["submitted"] is True
    assert "approval_note" in result
    assert mock_client.detection_post.await_count == 1


@pytest.mark.asyncio
async def test_ti_match_exact(mock_client: PlatformClient) -> None:
    mock_client.detection_post = AsyncMock(return_value={"matches": [{"value": "1.2.3.4"}]})
    result = await ti_match(
        mock_client,
        observables=[{"type": "ipv4", "value": "1.2.3.4"}],
        mode="exact",
    )
    assert result["matches"]["matches"][0]["value"] == "1.2.3.4"
    assert result["published"] is False


@pytest.mark.asyncio
async def test_ti_match_publish_requires_confirm(mock_client: PlatformClient) -> None:
    mock_client.detection_post = AsyncMock(return_value={"matches": []})
    result = await ti_match(
        mock_client,
        observables=[{"type": "domain", "value": "evil.example"}],
        publish=True,
        confirm=False,
    )
    assert result["draft"] is True
    assert result["published"] is False
    mock_client.tip_post.assert_not_called()


@pytest.mark.asyncio
async def test_ti_match_publish_with_confirm(mock_client: PlatformClient) -> None:
    mock_client.detection_post = AsyncMock(return_value={"matches": []})
    mock_client.tip_post = AsyncMock(return_value={"status": "ok", "iocs": 1})
    result = await ti_match(
        mock_client,
        observables=[{"type": "ipv4", "value": "1.2.3.4"}],
        publish=True,
        confirm=True,
        case_id="case-1",
    )
    assert result["published"] is True
    mock_client.tip_post.assert_awaited_once()
    args, kwargs = mock_client.tip_post.await_args
    assert args[0] == "/api/v1/threat-intel/sync-indicators"
    assert kwargs["json"]["case_id"] == "case-1"
    assert kwargs["json"]["iocs"][0]["ioc_type"] == "ip"
