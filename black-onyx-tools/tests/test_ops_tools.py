"""P2 ops tool tests with mocked PlatformClient / external HTTP."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from black_onyx_tools.client import PlatformClient
from black_onyx_tools.config import Settings
from black_onyx_tools.tools.certificate_transparency import certificate_transparency
from black_onyx_tools.tools.connector_pulse import connector_pulse
from black_onyx_tools.tools.feed_digest import feed_digest
from black_onyx_tools.tools.misp_taxii_draft import misp_taxii_draft
from black_onyx_tools.tools.model_ops import model_ops
from black_onyx_tools.tools.passive_dns_whois import passive_dns_whois
from black_onyx_tools.tools.url_screenshot_sandbox import assert_public_http_url, url_screenshot_sandbox
from black_onyx_tools.tools.watchlist_decay import watchlist_decay


@pytest.fixture
def mock_client() -> PlatformClient:
    return AsyncMock(spec=PlatformClient)


@pytest.mark.asyncio
async def test_watchlist_decay_summary(mock_client: PlatformClient) -> None:
    mock_client.tip_get = AsyncMock(
        side_effect=[
            {"tracked": 10},
            {"items": []},
            {"items": []},
        ],
    )
    result = await watchlist_decay(mock_client, action="summary")
    assert "summary" in result


@pytest.mark.asyncio
async def test_misp_taxii_draft_requires_confirm(mock_client: PlatformClient) -> None:
    mock_client.tip_get = AsyncMock(return_value={"configured": False})
    result = await misp_taxii_draft(
        mock_client,
        target="misp",
        iocs=[{"ioc_type": "domain", "ioc_value": "evil.example"}],
        confirm=False,
    )
    assert result["published"] is False


@pytest.mark.asyncio
async def test_connector_pulse(mock_client: PlatformClient) -> None:
    mock_client.tip_get = AsyncMock(
        side_effect=[
            {"healthy": 2},
            [{"connector": "splunk"}],
            {"items": [{"kind": "watchlist_alert", "id": "a1", "source": "wl"}]},
        ],
    )
    result = await connector_pulse(mock_client)
    assert "markdown" in result


@pytest.mark.asyncio
async def test_feed_digest_list(mock_client: PlatformClient) -> None:
    mock_client.tip_get = AsyncMock(return_value={"feeds": [{"name": "rss-1"}]})
    result = await feed_digest(mock_client)
    assert "rss-1" in result["digest_markdown"]


@pytest.mark.asyncio
async def test_model_ops_read_only(mock_client: PlatformClient) -> None:
    mock_client.detection_get = AsyncMock(
        side_effect=[
            {"status": "ready", "models": {"log-model": "http://x"}},
            {"status": "ready"},
            {"models": []},
        ],
    )
    result = await model_ops(mock_client)
    assert result["read_only"] is True
    assert result["models_ready"]["status"] == "ready"
    mock_client.detection_get.assert_any_await("models", "/health/ready")
    mock_client.detection_get.assert_any_await("training", "/health/ready")


@pytest.mark.asyncio
async def test_model_ops_with_job_id(mock_client: PlatformClient) -> None:
    mock_client.detection_get = AsyncMock(
        side_effect=[
            {"status": "ready"},
            {"status": "ready"},
            {"models": []},
            {"job_id": "j1", "status": "succeeded"},
        ],
    )
    result = await model_ops(mock_client, job_id="j1")
    assert result["training_job"]["job_id"] == "j1"
    mock_client.detection_get.assert_any_await("training", "/api/v1/training-jobs/j1")


@pytest.mark.asyncio
async def test_passive_dns_whois_soft_fail_whois() -> None:
    class FakeAnswer:
        def to_text(self) -> str:
            return "93.184.216.34"

    async def fake_to_thread(func, *args, **kwargs):
        if getattr(func, "__name__", "") == "resolve":
            return [FakeAnswer()]
        raise RuntimeError("whois unavailable")

    with patch("black_onyx_tools.tools.passive_dns_whois.asyncio.to_thread", side_effect=fake_to_thread):
        result = await passive_dns_whois(domain="example.com", query_types=["A"])

    assert result["domain"] == "example.com"
    assert result["dns"]["A"] == ["93.184.216.34"]
    assert result["whois_error"] == "whois unavailable"


@pytest.mark.asyncio
async def test_url_screenshot_sandbox_disabled(settings: Settings) -> None:
    result = await url_screenshot_sandbox(settings, url="https://example.com")
    assert result["enabled"] is False


@pytest.mark.asyncio
async def test_url_screenshot_sandbox_enabled(settings: Settings) -> None:
    settings.tools_allow_sandbox = True
    with respx.mock:
        respx.get("https://example.com").mock(return_value=httpx.Response(200, text="hello"))
        result = await url_screenshot_sandbox(settings, url="https://example.com")
    assert result["enabled"] is True
    assert result["sha256"]
    # Soft-fail without Playwright installed
    assert result["screenshot"] is not None
    assert result["screenshot"].get("available") is False or "sha256" in result["screenshot"]


@pytest.mark.asyncio
async def test_url_screenshot_sandbox_blocks_private(settings: Settings) -> None:
    settings.tools_allow_sandbox = True
    with pytest.raises(ValueError, match="blocked|private|http"):
        await url_screenshot_sandbox(settings, url="http://127.0.0.1/")
    with pytest.raises(ValueError, match="blocked|private"):
        assert_public_http_url("http://localhost/admin")
    with pytest.raises(ValueError, match="http/https"):
        assert_public_http_url("file:///etc/passwd")
    with pytest.raises(ValueError, match="blocked|private"):
        assert_public_http_url("http://169.254.169.254/latest/meta-data/")


@pytest.mark.asyncio
async def test_certificate_transparency() -> None:
    with respx.mock:
        respx.get("https://crt.sh/").mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 1, "issuer_name": "Let's Encrypt", "name_value": "example.com"}],
            ),
        )
        result = await certificate_transparency(domain="example.com", limit=5)
    assert result["returned"] == 1
