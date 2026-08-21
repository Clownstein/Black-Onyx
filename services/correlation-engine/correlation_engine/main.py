from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import TopicPartition
from fastapi import FastAPI

from correlation_engine.config import settings
from correlation_engine.engine import CorrelationEngine

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("correlation-engine")
except ImportError:
    pass

logger = logging.getLogger("correlation-engine")
logging.basicConfig(level=logging.INFO)

engine = CorrelationEngine()
_consumer_task: asyncio.Task[None] | None = None


def build_dlq_envelope(payload: dict[str, Any], exc: Exception) -> dict[str, Any]:
    return {"error": str(exc), "payload": payload}


def commit_offsets_for(msg: Any) -> dict[TopicPartition, int]:
    tp = TopicPartition(msg.topic, msg.partition)
    return {tp: msg.offset + 1}


async def _publish_dlq(producer: AIOKafkaProducer, payload: dict[str, Any], exc: Exception) -> None:
    await producer.send_and_wait(
        settings.topic_dlq,
        build_dlq_envelope(payload, exc),
    )


async def _handle_finding_message(
    consumer: AIOKafkaConsumer,
    dlq_producer: AIOKafkaProducer,
    correlation_engine: CorrelationEngine,
    payload: dict[str, Any],
    msg: Any,
) -> None:
    try:
        incident = correlation_engine.ingest_finding(payload)
        if incident is not None:
            await correlation_engine.publish_incident(incident)
        await consumer.commit(commit_offsets_for(msg))
    except Exception as exc:
        logger.exception("failed to correlate finding; sending to DLQ")
        await _publish_dlq(dlq_producer, payload, exc)
        # Park poison: commit after DLQ so redelivery does not flood the DLQ.
        await consumer.commit(commit_offsets_for(msg))


async def _consume_loop() -> None:
    topics = [t.strip() for t in settings.finding_topics.split(",") if t.strip()]
    consumer = AIOKafkaConsumer(
        *topics,
        bootstrap_servers=settings.kafka_brokers,
        group_id=settings.group_id,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )
    dlq_producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_brokers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    await consumer.start()
    await dlq_producer.start()
    try:
        async for msg in consumer:
            payload: dict[str, Any] = msg.value
            await _handle_finding_message(consumer, dlq_producer, engine, payload, msg)
    finally:
        await dlq_producer.stop()
        await consumer.stop()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _consumer_task
    _consumer_task = asyncio.create_task(_consume_loop())
    yield
    if _consumer_task:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Correlation Engine", version="0.1.0", lifespan=lifespan)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    topics = [t.strip() for t in settings.finding_topics.split(",") if t.strip()]
    return {
        "status": "ready",
        "topics": topics,
        "window_minutes": settings.initial_window_minutes,
    }


@app.post("/v1/correlate")
async def correlate(finding: dict[str, Any]) -> dict[str, Any]:
    """Synchronous correlate endpoint for tests and golden scenarios."""
    incident = engine.ingest_finding(finding)
    if incident is None:
        return {"status": "duplicate"}
    return {"status": "ok", "incident": incident}


def run() -> None:
    import uvicorn

    uvicorn.run("correlation_engine.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
