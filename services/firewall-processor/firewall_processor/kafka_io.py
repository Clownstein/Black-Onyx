from __future__ import annotations

import json
import logging
import threading
from typing import Any

from kafka import KafkaConsumer, KafkaProducer

from firewall_processor.config import settings
from firewall_processor.pipeline import FirewallPipeline

logger = logging.getLogger(__name__)


class FirewallConsumer:
    def __init__(self, pipeline: FirewallPipeline | None = None) -> None:
        self.pipeline = pipeline or FirewallPipeline()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.ready = False
        self.last_error: str | None = None
        self._consumer: KafkaConsumer | None = None
        self._producer: KafkaProducer | None = None

    def start(self) -> None:
        if not settings.enable_kafka:
            self.ready = True
            return
        self._thread = threading.Thread(
            target=self._run, name="firewall-consumer", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._consumer is not None:
            self._consumer.close()
        if self._producer is not None:
            self._producer.close()

    def _publish_dlq(self, payload: dict[str, Any], exc: Exception) -> None:
        if self._producer is None:
            return
        self._producer.send(
            settings.topic_dlq,
            {"error": str(exc), "payload": payload},
        )
        self._producer.flush()

    def _handle_message(self, event: dict[str, Any]) -> None:
        try:
            features, findings = self.pipeline.process_events([event])
            if self._producer is None:
                return
            for feature in features:
                self._producer.send(settings.topic_features, feature)
            if settings.publish_findings:
                for finding in findings:
                    self._producer.send(settings.topic_findings, finding)
            if features or findings:
                self._producer.flush()
        except Exception as exc:  # noqa: BLE001 - keep consumer alive on bad messages
            self.last_error = str(exc)
            logger.exception("failed to process firewall message; sending to DLQ")
            self._publish_dlq(event, exc)

    def _run(self) -> None:
        try:
            brokers = [b.strip() for b in settings.kafka_brokers.split(",") if b.strip()]
            self._consumer = KafkaConsumer(
                settings.topic_raw,
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
            logger.exception("firewall consumer failed")

    def process_batch(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return self.pipeline.process_events(events)
