from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import TopicPartition
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status

from correlation_engine.config import settings
from correlation_engine.asset_criticality import resolve_asset_criticality
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
_consumer_running = False
_consumer_error: str | None = None


async def _ingest_finding(payload: dict[str, Any]) -> dict[str, Any] | None:
    tenant_id = str(payload.get("tenant_id") or "").strip()
    asset_id = str(payload.get("asset_id") or "").strip()
    if tenant_id and asset_id:
        criticality = await resolve_asset_criticality(tenant_id, asset_id)
        if criticality is not None:
            return engine.ingest_finding(payload, asset_criticality=criticality)
    return engine.ingest_finding(payload)


def build_dlq_envelope(payload: Any, exc: Exception) -> dict[str, Any]:
    valid_payload = payload if isinstance(payload, dict) else {}
    return {
        "error": str(exc),
        "payload": valid_payload if isinstance(payload, dict) else None,
        "raw_value_base64": base64.b64encode(payload).decode("ascii") if isinstance(payload, bytes) else None,
        "raw_value_sha256": hashlib.sha256(payload).hexdigest() if isinstance(payload, bytes) else None,
        "raw_value_bytes": len(payload) if isinstance(payload, bytes) else None,
    }


def commit_offsets_for(msg: Any) -> dict[TopicPartition, int]:
    tp = TopicPartition(msg.topic, msg.partition)
    return {tp: msg.offset + 1}


async def _publish_dlq(producer: AIOKafkaProducer, payload: Any, exc: Exception) -> None:
    await producer.send_and_wait(
        settings.topic_dlq,
        build_dlq_envelope(payload, exc),
    )


async def _handle_finding_message(
    consumer: AIOKafkaConsumer,
    dlq_producer: AIOKafkaProducer,
    correlation_engine: CorrelationEngine,
    raw_value: Any,
    msg: Any,
) -> None:
    try:
        payload = json.loads(raw_value.decode("utf-8")) if isinstance(raw_value, bytes) else raw_value
        if not isinstance(payload, dict):
            raise ValueError("finding message must be a JSON object")
    except Exception as exc:  # poison bytes still reach durable DLQ
        logger.warning("invalid finding message; sending to DLQ")
        await _publish_dlq(dlq_producer, raw_value, exc)
        await consumer.commit(commit_offsets_for(msg))
        return

    try:
        # Persistence is the durable finding path for every canonical topic,
        # including direct host-state/firewall/IDS/malware findings.
        await correlation_engine.persist_finding(payload)
        tenant_id = str(payload.get("tenant_id") or "").strip()
        asset_id = str(payload.get("asset_id") or "").strip()
        criticality = await resolve_asset_criticality(tenant_id, asset_id) if tenant_id and asset_id else None
        incident = (
            correlation_engine.ingest_finding(payload, asset_criticality=criticality)
            if criticality is not None else correlation_engine.ingest_finding(payload)
        )
        if incident is not None:
            await correlation_engine.publish_incident(incident)
        await consumer.commit(commit_offsets_for(msg))
    except Exception as exc:
        logger.exception("failed to correlate finding; sending to DLQ")
        await _publish_dlq(dlq_producer, payload, exc)
        # Park poison: commit after DLQ so redelivery does not flood the DLQ.
        await consumer.commit(commit_offsets_for(msg))


async def _consume_loop() -> None:
    global _consumer_running, _consumer_error
    topics = [t.strip() for t in settings.finding_topics.split(",") if t.strip()]
    consumer = AIOKafkaConsumer(
        *topics,
        bootstrap_servers=settings.kafka_brokers,
        group_id=settings.group_id,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    dlq_producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_brokers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    consumer_started = False
    producer_started = False
    try:
        await consumer.start()
        consumer_started = True
        await dlq_producer.start()
        producer_started = True
        _consumer_running = True
        _consumer_error = None
        async for msg in consumer:
            await _handle_finding_message(consumer, dlq_producer, engine, msg.value, msg)
    finally:
        _consumer_running = False
        if producer_started:
            await dlq_producer.stop()
        if consumer_started:
            await consumer.stop()


async def _consume_supervisor() -> None:
    global _consumer_error
    delay = 1.0
    while True:
        try:
            await _consume_loop()
            raise RuntimeError("Kafka consumer loop stopped unexpectedly")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep consumer supervision alive
            _consumer_error = type(exc).__name__
            logger.exception("correlation consumer failed; retrying in %.1fs", delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)
        else:
            delay = 1.0


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _consumer_task
    _consumer_task = asyncio.create_task(_consume_supervisor())
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
def ready(response: Response) -> dict[str, object]:
    topics = [t.strip() for t in settings.finding_topics.split(",") if t.strip()]
    healthy = _consumer_running
    body: dict[str, object] = {
        "status": "ready" if healthy else "not_ready",
        "topics": topics,
        "window_minutes": settings.initial_window_minutes,
        "consumer_running": _consumer_running,
    }
    if _consumer_error:
        body["consumer_error"] = _consumer_error
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return body


def require_sync_access(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> str:
    """Fail closed: disabled by default, keyed, and tenant-bound."""
    if not settings.sync_endpoint_enabled:
        raise HTTPException(status_code=404, detail="Not found")
    expected = settings.api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="correlation API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id is required")
    return x_tenant_id


@app.post("/v1/correlate")
async def correlate(finding: dict[str, Any], tenant_id: str = Depends(require_sync_access)) -> dict[str, Any]:
    """Synchronous correlate endpoint for tests and golden scenarios."""
    if finding.get("tenant_id", tenant_id) != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_id does not match X-Tenant-Id")
    finding = {**finding, "tenant_id": tenant_id}
    incident = await _ingest_finding(finding)
    if incident is None:
        return {"status": "duplicate"}
    return {"status": "ok", "incident": incident}


def run() -> None:
    import uvicorn

    uvicorn.run("correlation_engine.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
