from __future__ import annotations

import json
import logging
import threading
from typing import Any

from kafka import KafkaConsumer, KafkaProducer

from embedding_worker.config import settings
from embedding_worker.worker import process_finding

logger = logging.getLogger(__name__)


class EmbeddingConsumer:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.ready = False
        self.last_error: str | None = None
        self.processed = 0
        self.upserted = 0
        self.errors = 0
        self._consumer: KafkaConsumer | None = None
        self._producer: KafkaProducer | None = None

    def start(self) -> None:
        if settings.enable_kafka:
            self._thread = threading.Thread(
                target=self._run_kafka, name="embedding-kafka", daemon=True
            )
            self._thread.start()
        else:
            self.ready = True

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._consumer is not None:
            self._consumer.close()
        if self._producer is not None:
            self._producer.close()

    def _topics(self) -> list[str]:
        return [t.strip() for t in settings.finding_topics.split(",") if t.strip()]

    def _publish_dlq(self, payload: dict[str, Any], error: str) -> None:
        if self._producer is None:
            return
        self._producer.send(
            settings.topic_dlq,
            {"error": error, "payload": payload},
        )
        self._producer.flush()

    def _handle_message(self, payload: dict[str, Any]) -> None:
        try:
            result = process_finding(payload)
            self.processed += 1
            if result.get("status") == "upserted":
                self.upserted += 1
            elif result.get("status") == "degraded":
                self.errors += 1
                reason = str(result.get("reason") or "degraded")
                self.last_error = reason
                logger.warning(
                    "embedding degraded for finding %s: %s",
                    payload.get("finding_id"),
                    result.get("reason"),
                )
                self._publish_dlq(payload, reason)
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            self.last_error = str(exc)
            logger.exception("embedding upsert failed")
            self._publish_dlq(payload, str(exc))

    def _run_kafka(self) -> None:
        try:
            brokers = [b.strip() for b in settings.kafka_brokers.split(",") if b.strip()]
            self._consumer = KafkaConsumer(
                *self._topics(),
                bootstrap_servers=brokers,
                group_id=settings.consumer_group,
                enable_auto_commit=True,
                auto_offset_reset="earliest",
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
            self._producer = KafkaProducer(
                bootstrap_servers=brokers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            self.ready = True
            while not self._stop.is_set():
                polled = self._consumer.poll(timeout_ms=500)
                for _tp, messages in polled.items():
                    for msg in messages:
                        if not isinstance(msg.value, dict):
                            continue
                        self._handle_message(msg.value)
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            self.ready = False
            logger.exception("embedding kafka consumer failed")
