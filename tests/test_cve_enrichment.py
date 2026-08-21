"""Unit tests for CVE enrichment providers (NVD, EPSS, CISA KEV)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from black_onyx.enrichment.factory import create_enrichment_provider
from black_onyx.enrichment.manager import EnrichmentManager
from black_onyx.enrichment.providers.epss import EPSSProvider
from black_onyx.enrichment.providers.kev import KEVProvider
from black_onyx.enrichment.providers.nvd import NVDProvider


class TestClassifyCVE:
    def test_classify_cve(self):
        assert EnrichmentManager.classify_ioc_type("CVE-2021-44228") == "cve"
        assert EnrichmentManager.classify_ioc_type("cve-2024-12345") == "cve"
        assert EnrichmentManager.classify_ioc_type("CVE-2017-0144") == "cve"

    def test_classify_rejects_short_cve_suffix(self):
        assert EnrichmentManager.classify_ioc_type("CVE-2021-123") == "unknown"

    def test_classify_non_cve_unchanged(self):
        assert EnrichmentManager.classify_ioc_type("1.2.3.4") == "ip"
        assert EnrichmentManager.classify_ioc_type("example.com") == "domain"


class TestFactoryCVEProviders:
    def test_create_nvd_epss_kev(self):
        nvd = create_enrichment_provider("nvd", {"NVD_API_KEY": "test-key"})
        epss = create_enrichment_provider("epss")
        kev = create_enrichment_provider("kev")
        assert isinstance(nvd, NVDProvider)
        assert isinstance(epss, EPSSProvider)
        assert isinstance(kev, KEVProvider)
        assert nvd.supported_ioc_types == ["cve"]
        assert epss.supported_ioc_types == ["cve"]
        assert kev.supported_ioc_types == ["cve"]
        assert nvd._api_key == "test-key"


class TestEPSSProvider:
    @pytest.mark.asyncio
    async def test_epss_enrich_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.97521",
                    "percentile": "0.99989",
                    "date": "2024-06-01",
                }
            ],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("black_onyx.enrichment.providers.epss.httpx.AsyncClient", return_value=mock_client):
            result = await EPSSProvider().enrich("cve", "CVE-2021-44228")

        assert result.error is None
        assert result.provider == "epss"
        assert result.confidence == pytest.approx(0.97521)
        assert result.raw_data["epss"] == pytest.approx(0.97521)
        assert result.raw_data["percentile"] == pytest.approx(0.99989)
        assert any(t.startswith("epss:") for t in result.tags)
        mock_client.get.assert_awaited_once()
        call_kwargs = mock_client.get.await_args
        assert call_kwargs.args[0] == "https://api.first.org/data/v1/epss"
        assert call_kwargs.kwargs["params"]["cve"] == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_epss_not_found(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"status": "OK", "data": []}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("black_onyx.enrichment.providers.epss.httpx.AsyncClient", return_value=mock_client):
            result = await EPSSProvider().enrich("cve", "CVE-2099-0001")

        assert result.error is None
        assert result.confidence == 0.0
        assert "not_found" in result.tags

    @pytest.mark.asyncio
    async def test_epss_unsupported_type(self):
        result = await EPSSProvider().enrich("ip", "1.2.3.4")
        assert result.error is not None
        assert "Unsupported" in result.error


class TestKEVProvider:
    @pytest.mark.asyncio
    async def test_kev_in_memory_hit_without_network(self):
        import time

        provider = KEVProvider()
        provider._cache = {
            "CVE-2021-44228": {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "knownRansomwareCampaignUse": "Known",
            }
        }
        provider._cache_fetched_at = time.monotonic()

        with patch("black_onyx.enrichment.providers.kev.httpx.AsyncClient") as mock_httpx:
            result = await provider.enrich("cve", "CVE-2021-44228")
            mock_httpx.assert_not_called()

        assert result.error is None
        assert result.malicious is True
        assert result.confidence == 1.0
        assert result.raw_data["in_kev"] is True
        assert "in_kev" in result.tags
        assert any(t.startswith("vendor:Apache") for t in result.tags)

    @pytest.mark.asyncio
    async def test_kev_in_memory_miss_without_network(self):
        provider = KEVProvider()
        import time

        provider._cache = {"CVE-2021-44228": {"cveID": "CVE-2021-44228"}}
        provider._cache_fetched_at = time.monotonic()

        with patch("black_onyx.enrichment.providers.kev.httpx.AsyncClient") as mock_httpx:
            result = await provider.enrich("cve", "CVE-2099-0001")
            mock_httpx.assert_not_called()

        assert result.malicious is False
        assert result.confidence == 0.0
        assert "not_in_kev" in result.tags
        assert result.raw_data["in_kev"] is False

    @pytest.mark.asyncio
    async def test_kev_fetches_and_indexes_feed(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2023-12345",
                    "vendorProject": "Example",
                    "product": "Widget",
                    "dateAdded": "2023-01-01",
                }
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        provider = KEVProvider()
        with patch("black_onyx.enrichment.providers.kev.httpx.AsyncClient", return_value=mock_client):
            result = await provider.enrich("cve", "cve-2023-12345")

        assert result.malicious is True
        assert result.raw_data["cveID"] == "CVE-2023-12345"
        assert "CVE-2023-12345" in provider._cache


class TestNVDProvider:
    @pytest.mark.asyncio
    async def test_nvd_enrich_with_cvss(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [
                            {
                                "description": [
                                    {"lang": "en", "value": "CWE-502"}
                                ]
                            }
                        ],
                    }
                }
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("black_onyx.enrichment.providers.nvd.httpx.AsyncClient", return_value=mock_client):
            result = await NVDProvider(api_key="k").enrich("cve", "CVE-2021-44228")

        assert result.error is None
        assert result.raw_data["cvss"] == 10.0
        assert result.confidence == pytest.approx(1.0)
        assert "severity:critical" in result.tags
        assert "CWE-502" in result.tags
        headers = mock_client.get.await_args.kwargs["headers"]
        assert headers["apiKey"] == "k"

    @pytest.mark.asyncio
    async def test_nvd_not_found(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("black_onyx.enrichment.providers.nvd.httpx.AsyncClient", return_value=mock_client):
            result = await NVDProvider().enrich("cve", "CVE-2099-0001")

        assert "not_found" in result.tags
        assert result.malicious is False


class TestEnrichmentManagerLoopBinding:
    """EnrichmentManager is a process-wide singleton reached from two different
    event loops: the FastAPI loop (interactive /enrich requests) and the
    short-lived loops asyncio.run() creates for playbook triggers fired from
    ingestion worker threads.

    asyncio.Semaphore binds itself to a loop the first time it suspends a
    waiter and then raises "is bound to a different event loop" everywhere
    else, so a single semaphore built in __init__ worked right up until more
    than max_concurrent enrichments contended — and from then on permanently
    failed for whichever loop had not claimed it, including breaking the
    interactive endpoint because a background ingestion claimed it first.
    """

    @staticmethod
    def _slow_provider():
        from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

        class SlowProvider(EnrichmentProvider):
            @property
            def name(self) -> str:
                return "slow"

            @property
            def supported_ioc_types(self) -> list[str]:
                return ["ip"]

            async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
                import asyncio
                await asyncio.sleep(0.01)
                return EnrichmentResult(provider="slow", ioc_type=ioc_type, ioc_value=ioc_value)

        return SlowProvider()

    def test_survives_enrichment_from_several_event_loops(self):
        import asyncio

        manager = EnrichmentManager(providers=[self._slow_provider()], max_concurrent=2)
        # More IOCs than max_concurrent, so the semaphore genuinely contends
        # and would bind to a loop under the old implementation.
        iocs = [("ip", f"203.0.113.{i}") for i in range(8)]

        for _ in range(3):
            results = asyncio.run(manager.enrich_batch(iocs))
            assert len(results) == len(iocs)

    def test_concurrency_cap_is_still_enforced(self):
        import asyncio

        from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

        peak = {"current": 0, "max": 0}

        class TrackingProvider(EnrichmentProvider):
            @property
            def name(self) -> str:
                return "tracking"

            @property
            def supported_ioc_types(self) -> list[str]:
                return ["ip"]

            async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
                peak["current"] += 1
                peak["max"] = max(peak["max"], peak["current"])
                await asyncio.sleep(0.02)
                peak["current"] -= 1
                return EnrichmentResult(provider="tracking", ioc_type=ioc_type, ioc_value=ioc_value)

        manager = EnrichmentManager(providers=[TrackingProvider()], max_concurrent=3)
        asyncio.run(manager.enrich_batch([("ip", f"203.0.113.{i}") for i in range(12)]))
        assert peak["max"] <= 3

    def test_per_loop_semaphores_do_not_accumulate(self):
        """Weak keys, so an entry disappears with its short-lived loop rather
        than leaking one per ingestion for the life of the process."""
        import asyncio
        import gc

        manager = EnrichmentManager(providers=[self._slow_provider()], max_concurrent=2)
        for _ in range(20):
            asyncio.run(manager.enrich_batch([("ip", "203.0.113.1")]))
        gc.collect()
        assert len(manager._semaphores) <= 2
