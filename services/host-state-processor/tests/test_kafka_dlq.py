from __future__ import annotations

from typing import Any

from host_state_processor.config import settings
from host_state_processor.kafka_io import HostStateConsumer


class FakeProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, topic: str, value: dict[str, Any], **_kwargs: Any) -> None:
        self.sent.append((topic, value))

    def flush(self) -> None:
        return None


class BoomPipeline:
    def process_events(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        raise ValueError("bad host-state event")

    def last_seen_snapshot(self) -> dict[str, Any]:
        return {}


class OkPipeline:
    def process_events(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return ([{"feature": True, "events": events}], [{"finding": True}])

    def last_seen_snapshot(self) -> dict[str, Any]:
        return {}


def test_handle_message_publishes_to_dlq_on_failure() -> None:
    consumer = HostStateConsumer(pipeline=BoomPipeline())  # type: ignore[arg-type]
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "payload": {"broken": True}}

    consumer._handle_message(payload)

    assert len(producer.sent) == 1
    topic, envelope = producer.sent[0]
    assert topic == settings.topic_dlq
    assert envelope["error"] == "bad host-state event"
    assert envelope["payload"] == payload


def test_handle_message_publishes_features_and_findings_on_success() -> None:
    consumer = HostStateConsumer(pipeline=OkPipeline())  # type: ignore[arg-type]
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "payload": {"ok": True}}

    consumer._handle_message(payload)

    topics = [topic for topic, _ in producer.sent]
    assert settings.topic_features in topics
    assert settings.topic_findings in topics
    assert settings.topic_dlq not in topics
