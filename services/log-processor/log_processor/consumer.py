"""aiokafka consumer/producer loop for log processing."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from log_processor.config import settings
from log_processor.processor import LogProcessor

logger = logging.getLogger(__name__)


class LogProcessorWorker:
    def __init__(self) -> None:
        self.processor = LogProcessor()
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._ready = False
        self._last_error: str | None = None
        self._seen_keys: set[str] = set()

    @property
    def ready(self) -> bool:
        return self._ready and not self._stop.is_set()

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name="log-processor-worker")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await asyncio.wait([self._task], timeout=10)

    async def _run(self) -> None:
        brokers = [b.strip() for b in settings.kafka_brokers.split(",") if b.strip()]
        while not self._stop.is_set():
            consumer: AIOKafkaConsumer | None = None
            producer: AIOKafkaProducer | None = None
            try:
                consumer = AIOKafkaConsumer(
                    settings.topic_raw,
                    bootstrap_servers=brokers,
                    group_id=settings.group_id,
                    enable_auto_commit=True,
                    auto_offset_reset="earliest",
                    value_deserializer=lambda v: v.decode("utf-8"),
                )
                producer = AIOKafkaProducer(
                    bootstrap_servers=brokers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                )
                await consumer.start()
                await producer.start()
                self._ready = True
                self._last_error = None
                logger.info("consuming %s", settings.topic_raw)
                async for message in consumer:
                    if self._stop.is_set():
                        break
                    await self._handle(message.value, producer)
            except Exception as exc:  # noqa: BLE001
                self._ready = False
                self._last_error = str(exc)
                logger.exception("worker loop error: %s", exc)
                await asyncio.sleep(2)
            finally:
                self._ready = False
                if consumer is not None:
                    await consumer.stop()
                if producer is not None:
                    await producer.stop()

    async def _handle(self, raw: str, producer: AIOKafkaProducer) -> None:
        try:
            payload: dict[str, Any] = json.loads(raw)
            sequences = self.processor.process_payload(payload)
            for sequence in sequences:
                key = sequence.idempotency_key
                if key in self._seen_keys:
                    continue
                self._seen_keys.add(key)
                await producer.send_and_wait(
                    settings.topic_features,
                    sequence.model_dump(mode="json"),
                    key=key.encode("utf-8"),
                )
            # Bound memory for idempotency cache
            if len(self._seen_keys) > 50_000:
                self._seen_keys = set(list(self._seen_keys)[-10_000:])
        except Exception as exc:  # noqa: BLE001
            logger.exception("failed to process message: %s", exc)
            await producer.send_and_wait(
                settings.topic_dlq,
                {
                    "error": str(exc),
                    "raw": raw[:4096],
                    "processor_version": settings.processor_version,
                },
            )
