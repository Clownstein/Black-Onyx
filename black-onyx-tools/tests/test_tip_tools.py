"""P0 TIP tool tests with mocked PlatformClient."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.tools.attack_map import attack_map
from black_onyx_tools.tools.case_assist import case_assist
from black_onyx_tools.tools.evidence_search import evidence_search
from black_onyx_tools.tools.ioc_enrich import ioc_enrich
from black_onyx_tools.tools.rule_draft import rule_draft


@pytest.fixture
def mock_client() -> PlatformClient:
    client = AsyncMock(spec=PlatformClient)
    return client


@pytest.mark.asyncio
async def test_evidence_search(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(
        return_value={
            "query": "ransomware",
            "total": 1,
            "results": [{"id": "p1", "score": 0.9, "payload": {"text": "ransom note"}, "collection": "all-knowledge"}],
        },
    )
    result = await evidence_search(mock_client, query="ransomware")
    assert result["total"] == 1
    assert result["mode"] == "text"
    assert result["citations"][0]["point_id"] == "p1"


@pytest.mark.asyncio
async def test_evidence_search_image(mock_client: PlatformClient, tmp_path) -> None:
    image = tmp_path / "shot.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    mock_client.tip_post_multipart = AsyncMock(
        return_value={
            "total": 1,
            "results": [{"id": "img1", "score": 0.7, "payload": {"title": "phish"}, "collection": "all-knowledge"}],
        },
    )
    result = await evidence_search(mock_client, image_path=str(image))
    assert result["mode"] == "image"
    assert result["enabled"] is True
    assert result["citations"][0]["point_id"] == "img1"
    mock_client.tip_post_multipart.assert_awaited_once()


@pytest.mark.asyncio
async def test_evidence_search_image_soft_fails_without_clip(mock_client: PlatformClient, tmp_path) -> None:
    import httpx

    image = tmp_path / "shot.jpg"
    image.write_bytes(b"jpeg-bytes")
    request = httpx.Request("POST", "http://testserver/api/v1/search/image")
    response = httpx.Response(400, text='{"detail":"CLIP model not available. Install image dependencies."}', request=request)
    mock_client.tip_post_multipart = AsyncMock(
        side_effect=httpx.HTTPStatusError("400", request=request, response=response),
    )
    result = await evidence_search(mock_client, image_path=str(image))
    assert result["enabled"] is False
    assert "CLIP" in result["message"]



@pytest.mark.asyncio
async def test_ioc_enrich_extract_and_batch(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(
        side_effect=[
            {"iocs": {"domain": ["evil.example"]}, "total_count": 1},
            {"results": {"evil.example": [{"provider": "otx", "score": 1}]}},
        ],
    )
    result = await ioc_enrich(mock_client, text="evil.example")
    assert "domain" in result["extracted"]
    assert mock_client.tip_post.await_count == 2


@pytest.mark.asyncio
async def test_ioc_enrich_stix_sends_flat_list(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(
        side_effect=[
            {"iocs": {"domain": ["evil.example"]}, "total_count": 1},
            {"results": {}},
            {"bundle": {"type": "bundle", "objects": []}},
        ],
    )
    result = await ioc_enrich(mock_client, text="evil.example", export_stix=True)
    assert result["stix"]["type"] == "bundle"
    stix_call = mock_client.tip_post.await_args_list[2]
    assert stix_call.args[0] == "/api/v1/stix/export"
    iocs = stix_call.kwargs["json"]["iocs"]
    assert isinstance(iocs, list)
    assert iocs[0] == {"ioc_type": "domain", "ioc_value": "evil.example"}


@pytest.mark.asyncio
async def test_case_assist_create_draft_requires_confirm(mock_client: PlatformClient) -> None:
    result = await case_assist(mock_client, action="create_draft", title="T1", confirm=False)
    assert result["draft"] is True
    mock_client.tip_post.assert_not_called()


@pytest.mark.asyncio
async def test_case_assist_create_with_confirm(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(return_value={"case_id": "c1", "title": "T1"})
    result = await case_assist(mock_client, action="create_draft", title="T1", confirm=True)
    assert result["case_id"] == "c1"


@pytest.mark.asyncio
async def test_case_assist_promote_draft(mock_client: PlatformClient) -> None:
    result = await case_assist(
        mock_client,
        action="promote",
        promote_kind="alert",
        alert_id="a1",
        confirm=False,
    )
    assert result["draft"] is True
    assert result["path"] == "/api/v1/alerts/a1/promote"
    mock_client.tip_post.assert_not_called()


@pytest.mark.asyncio
async def test_case_assist_promote_detection_confirm(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(return_value={"status": "ok", "case_id": "c9"})
    result = await case_assist(
        mock_client,
        action="promote",
        promote_kind="detection",
        detection_key="det-1",
        connector="splunk",
        title="Promoted",
        confirm=True,
    )
    assert result["case_id"] == "c9"
    mock_client.tip_post.assert_awaited_once()
    args, kwargs = mock_client.tip_post.await_args
    assert args[0] == "/api/v1/detections/promote"
    assert kwargs["json"]["detection_key"] == "det-1"


@pytest.mark.asyncio
async def test_rule_draft_sigma(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(return_value={"rule": "title: test"})
    result = await rule_draft(mock_client, rule_type="sigma", iocs={"ip": ["1.2.3.4"]})
    assert result["rule_type"] == "sigma"
    assert "title" in result["rule"]


@pytest.mark.asyncio
async def test_attack_map(mock_client: PlatformClient) -> None:
    mock_client.tip_post = AsyncMock(
        side_effect=[
            {"techniques": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter"}]},
            {"tactics": []},
            {"nodes": [], "edges": []},
        ],
    )
    mock_client.tip_get = AsyncMock(return_value={"coverage": {"T1059": 1}})
    result = await attack_map(mock_client, text="T1059 powershell")
    assert result["techniques"] == ["T1059"]
    heatmap_call = mock_client.tip_post.await_args_list[1]
    assert heatmap_call.kwargs["json"] == ["T1059"]