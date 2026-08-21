from __future__ import annotations

from typing import Any
from unittest.mock import patch

from embedding_worker.config import settings
from embedding_worker.kafka_io import EmbeddingConsumer


class FakeProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, topic: str, value: dict[str, Any], **_kwargs: Any) -> None:
        self.sent.append((topic, value))

    def flush(self) -> None:
        return None


def test_degraded_result_publishes_to_dlq() -> None:
    consumer = EmbeddingConsumer()
    producer = FakeProducer()
    consumer._producer = producer  # type: ignore[assignment]
    payload = {"tenant_id": "t1", "finding_id": "f-1"}

    with patch(
        "embedding_worker.kafka_io.process_finding",
        return_value={"status": "degraded", "reason": "qdrant down", "capability": "vector_storage"},
    ):
        consumer._handle_message(payload)

    assert len(producer.sent) == 1
    topic, envelope = producer.sent[0]
    assert topic == settings.topic_dlq
    assert envelope["error"] == "qdrant down"
    assert envelope["payload"] == payload
