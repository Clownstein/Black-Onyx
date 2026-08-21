from __future__ import annotations

from typing import Any

import httpx
import pytest

from correlation_engine.config import settings
from correlation_engine.engine import CorrelationEngine
from correlation_engine.main import _handle_finding_message, build_dlq_envelope, commit_offsets_for
from correlation_engine.store import MemoryBucketStore


class FakeConsumer:
    def __init__(self) -> None:
        self.committed: list[dict[Any, int]] = []

    async def commit(self, offsets: dict[Any, int]) -> None:
        self.committed.append(offsets)


class FakeDlqProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    async def send_and_wait(self, topic: str, value: dict[str, Any]) -> None:
        self.sent.append((topic, value))


class FakeMsg:
    def __init__(self, offset: int = 0) -> None:
        self.offset = offset
        self.topic = "findings.logs"
        self.partition = 0


def test_build_dlq_envelope() -> None:
    payload = {"tenant_id": "t1", "finding_id": "f-1"}
    envelope = build_dlq_envelope(payload, ValueError("bad finding"))
    assert envelope == {"error": "bad finding", "payload": payload}


def test_commit_offsets_for() -> None:
    offsets = commit_offsets_for(FakeMsg(offset=3))
    assert list(offsets.values()) == [4]


@pytest.mark.asyncio
async def test_handle_message_commits_on_duplicate() -> None:
    engine = CorrelationEngine(store=MemoryBucketStore())
    consumer = FakeConsumer()
    dlq = FakeDlqProducer()
    payload = {
        "finding_id": "f-dup",
        "finding_type": "log_anomaly",
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "calibrated_score": 0.5,
        "model_name": "log-model",
        "contributors": [],
        "context": {},
        "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:15:00Z"},
    }
    first = engine.ingest_finding(payload)
    assert first is not None
    engine.mark_publish_ok(first)

    await _handle_finding_message(consumer, dlq, engine, payload, FakeMsg(offset=3))

    assert len(consumer.committed) == 1
    assert list(consumer.committed[0].values()) == [4]
    assert dlq.sent == []


@pytest.mark.asyncio
async def test_handle_message_publishes_dlq_on_publish_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = CorrelationEngine(store=MemoryBucketStore())
    consumer = FakeConsumer()
    dlq = FakeDlqProducer()
    payload = {
        "finding_id": "f-fail",
        "finding_type": "log_anomaly",
        "tenant_id": "tenant-a",
        "asset_id": "host-1",
        "calibrated_score": 0.9,
        "model_name": "log-model",
        "contributors": [{"type": "template", "contribution": 0.8, "template_id": "auth"}],
        "context": {},
        "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:15:00Z"},
    }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise httpx.HTTPError("boom")

    monkeypatch.setattr("correlation_engine.engine.httpx.AsyncClient", FakeClient)

    await _handle_finding_message(consumer, dlq, engine, payload, FakeMsg(offset=7))

    assert len(consumer.committed) == 1
    assert list(consumer.committed[0].values()) == [8]
    assert len(dlq.sent) == 1
    topic, envelope = dlq.sent[0]
    assert topic == settings.topic_dlq
    assert envelope["payload"] == payload
    assert "boom" in envelope["error"]
