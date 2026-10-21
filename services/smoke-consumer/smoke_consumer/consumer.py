from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from kafka import KafkaConsumer

from black_onyx_contracts import EventEnvelope
from smoke_consumer.config import settings
from smoke_consumer.db import upsert_event

logger = logging.getLogger(__name__)


class SmokeConsumer:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._task: asyncio.Task[None] | None = None
        self._ready = False
        self._last_error: str | None = None
        self.processed = 0
        self.inserted = 0

    @property
    def ready(self) -> bool:
        return self._ready and not self._stop.is_set()

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="smoke-consumer")

    async def stop(self) -> None:
        self._stop.set()
        self._ready = False
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self._consume_until_error)
            except Exception as exc:  # noqa: BLE001 - keep consumer alive
                self._ready = False
                self._last_error = str(exc)
                logger.exception("consumer loop error: %s", exc)
                if self._stop.wait(timeout=2):
                    break

    def _consume_until_error(self) -> None:
        consumer = KafkaConsumer(
            settings.topic,
            bootstrap_servers=[
                b.strip() for b in settings.kafka_bootstrap_servers.split(",") if b.strip()
            ],
            group_id=settings.group_id,
            enable_auto_commit=True,
            auto_offset_reset="earliest",
            value_deserializer=lambda v: v.decode("utf-8"),
            consumer_timeout_ms=int(settings.consumer_poll_seconds * 1000),
        )
        try:
            self._ready = True
            self._last_error = None
            logger.info(
                "consuming %s from %s",
                settings.topic,
                settings.kafka_bootstrap_servers,
            )
            while not self._stop.is_set():
                for message in consumer:
                    self._handle(message.value)
                    if self._stop.is_set():
                        break
        finally:
            consumer.close()
            self._ready = False

    def _handle(self, raw: str) -> None:
        payload: dict[str, Any] = json.loads(raw)
        envelope = EventEnvelope.model_validate(payload)
        inserted = upsert_event(
            tenant_id=envelope.tenant_id,
            event_id=envelope.event_id,
            event_type=envelope.event_type,
            payload=payload,
        )
        self.processed += 1
        if inserted:
            self.inserted += 1
            logger.info("stored event %s for tenant %s", envelope.event_id, envelope.tenant_id)
