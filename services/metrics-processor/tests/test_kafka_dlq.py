from __future__ import annotations

from typing import Any

from metrics_processor.config import settings
from metrics_processor.kafka_io import MetricsConsumer


class FakeProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, topic: str, value: dict[str, Any], **_kwargs: Any) -> None:
        self.sent.append((topic, value))

    def flush(self) -> None:
        return None


class BoomPipeline:
    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise ValueError("bad metrics event")


class OkPipeline:
    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"feature_version": "metrics.features.v1", "events": events}]


def test_handle_message_publishes_to_dlq_on_failure() -> None:
    consumer = MetricsConsumer(pipeline=BoomPipeline())  # type: ignore[arg-type]
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "payload": {"broken": True}}

    consumer._handle_message(payload)

    assert len(producer.sent) == 1
    topic, envelope = producer.sent[0]
    assert topic == settings.topic_dlq
    assert envelope["error"] == "bad metrics event"
    assert envelope["payload"] == payload


def test_handle_message_publishes_features_on_success() -> None:
    consumer = MetricsConsumer(pipeline=OkPipeline())  # type: ignore[arg-type]
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "payload": {"ok": True}}

    consumer._handle_message(payload)

    assert len(producer.sent) == 1
    topic, feature = producer.sent[0]
    assert topic == settings.topic_features
    assert feature["feature_version"] == "metrics.features.v1"
