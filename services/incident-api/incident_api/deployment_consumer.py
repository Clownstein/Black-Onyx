"""Persist deployment envelopes accepted by the ingestion gateway."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from incident_api.config import settings
from incident_api.db import create_session
from incident_api.deployment_store import persist_deployment
from incident_api.schemas import DeploymentEventCreate

logger = logging.getLogger(__name__)


def _deployment_from_envelope(envelope: dict[str, Any]) -> tuple[str, DeploymentEventCreate]:
    payload = envelope.get("payload")
    source = payload if isinstance(payload, dict) else envelope
    tenant_id = str(envelope.get("tenant_id") or source.get("tenant_id") or "").strip()
    if not tenant_id:
        raise ValueError("deployment event is missing tenant_id")
    deployed_at = (
        source.get("completed_at")
        or source.get("deployed_at")
        or envelope.get("timestamp")
        or datetime.now(UTC)
    )
    body = DeploymentEventCreate(
        deployment_id=source.get("deployment_id"),
        service_id=source.get("service_id"),
        environment=source.get("environment"),
        commit_sha=source.get("commit_sha") or source.get("commit"),
        version=source.get("version"),
        status=source.get("status") or "succeeded",
        deployed_at=deployed_at,
        payload=dict(source),
    )
    return tenant_id, body


def _persist(envelope: dict[str, Any]) -> None:
    tenant_id, body = _deployment_from_envelope(envelope)
    with create_session() as db:
        persist_deployment(
            db,
            tenant_id=tenant_id,
            body=body,
            actor="system:deployment-consumer",
        )


class DeploymentConsumer:
    def __init__(self) -> None:
        self.task: asyncio.Task[None] | None = None
        self.ready = False
        self.processed = 0
        self.errors = 0
        self.last_error: str | None = None
        self._consumer: AIOKafkaConsumer | None = None
        self._producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        if not settings.deployment_consumer_enabled:
            self.ready = True
            return
        self.task = asyncio.create_task(self._run(), name="deployment-consumer")

    async def stop(self) -> None:
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

    async def _publish_dlq(self, envelope: Any, exc: Exception) -> None:
        if self._producer is None:
            return
        payload = {
            "status": "rejected",
            "capability": "deployment_event_persistence",
            "reason": str(exc),
            "failed_at": datetime.now(UTC).isoformat(),
            "event": envelope if isinstance(envelope, dict) else {"raw": str(envelope)},
        }
        await self._producer.send_and_wait(
            settings.deployment_dlq_topic,
            json.dumps(payload).encode("utf-8"),
        )

    async def _run(self) -> None:
        brokers = [
            broker.strip()
            for broker in settings.kafka_brokers.split(",")
            if broker.strip()
        ]
        self._consumer = AIOKafkaConsumer(
            settings.deployment_topic,
            bootstrap_servers=brokers,
            group_id=settings.deployment_consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
        )
        self._producer = AIOKafkaProducer(bootstrap_servers=brokers)
        try:
            await self._consumer.start()
            await self._producer.start()
            self.ready = True
            async for message in self._consumer:
                try:
                    if not isinstance(message.value, dict):
                        raise ValueError("deployment event must be a JSON object")
                    await asyncio.to_thread(_persist, message.value)
                    self.processed += 1
                except Exception as exc:  # noqa: BLE001 - route bad events to DLQ
                    self.errors += 1
                    self.last_error = str(exc)
                    logger.exception("deployment event persistence failed")
                    await self._publish_dlq(message.value, exc)
                await self._consumer.commit()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            self.ready = False
            logger.exception("deployment consumer failed")
        finally:
            if self._consumer is not None:
                await self._consumer.stop()
            if self._producer is not None:
                await self._producer.stop()


deployment_consumer = DeploymentConsumer()
