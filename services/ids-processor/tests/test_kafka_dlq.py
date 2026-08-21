from __future__ import annotations

from typing import Any

from ids_processor.config import settings
from ids_processor.kafka_io import IdsConsumer


class FakeProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, topic: str, value: dict[str, Any], **_kwargs: Any) -> None:
        self.sent.append((topic, value))

    def flush(self) -> None:
        return None


class BoomPipeline:
    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise ValueError("bad suricata event")


class OkPipeline:
    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"finding_type": "suricata_alert", "events": events}]


def test_handle_message_publishes_to_dlq_on_failure() -> None:
    consumer = IdsConsumer(pipeline=BoomPipeline())  # type: ignore[arg-type]
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "payload": {"broken": True}}

    consumer._handle_message(payload)

    assert len(producer.sent) == 1
    topic, envelope = producer.sent[0]
    assert topic == settings.topic_dlq
    assert envelope["error"] == "bad suricata event"
    assert envelope["payload"] == payload


def test_handle_message_publishes_findings_on_success() -> None:
    consumer = IdsConsumer(pipeline=OkPipeline())  # type: ignore[arg-type]
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "payload": {"ok": True}}

    consumer._handle_message(payload)

    assert len(producer.sent) == 1
    topic, finding = producer.sent[0]
    assert topic == settings.topic_findings
    assert finding["finding_type"] == "suricata_alert"
