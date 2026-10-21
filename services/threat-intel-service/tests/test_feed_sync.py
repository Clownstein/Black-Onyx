from __future__ import annotations

import json

import httpx
import pytest

from threat_intel_service.ingest.misp import sync_misp
from threat_intel_service.ingest.taxii import sync_taxii
from threat_intel_service.models import FeedCheckpoint, FeedHealth
from threat_intel_service.store import match_observables


@pytest.mark.asyncio
async def test_taxii_sync_paginates_and_checkpoints(db_session) -> None:
    object_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/collections/"):
            return httpx.Response(
                200,
                json={"collections": [{"id": "collection-a"}], "more": False},
            )
        object_requests.append(request)
        if request.url.params.get("next") == "page-2":
            return httpx.Response(
                200,
                json={
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--two",
                            "pattern": "[domain-name:value = 'second.example']",
                        }
                    ],
                    "more": False,
                },
            )
        return httpx.Response(
            200,
            json={
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--one",
                        "pattern": "[domain-name:value = 'first.example']",
                    }
                ],
                "more": True,
                "next": "page-2",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await sync_taxii(
            db_session,
            base_url="https://taxii.example/api/",
            client=client,
        )

    assert result["status"] == "ready"
    assert result["pages"] == 2
    assert result["upserted"] == 2
    assert object_requests[1].url.params["next"] == "page-2"
    checkpoint = db_session.get(FeedCheckpoint, "taxii:collection-a")
    assert checkpoint is not None
    assert checkpoint.cursor
    assert db_session.get(FeedHealth, "taxii").last_status == "ok"


@pytest.mark.asyncio
async def test_misp_sync_uses_checkpoint_and_deduplicates(db_session) -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "id": "123",
                            "type": "domain",
                            "value": "misp.example",
                            "timestamp": "1720000000",
                            "confidence": "85",
                        }
                    ]
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        first = await sync_misp(
            db_session,
            base_url="https://misp.example/",
            api_key="secret",
            client=client,
        )
        second = await sync_misp(
            db_session,
            base_url="https://misp.example/",
            api_key="secret",
            client=client,
        )

    assert first["status"] == "ready"
    assert second["status"] == "ready"
    assert bodies[1]["timestamp"] == "1720000000"
    hits = match_observables(
        db_session, [{"type": "domain", "value": "misp.example"}]
    )
    assert len(hits) == 1
    assert hits[0].confidence == 85
