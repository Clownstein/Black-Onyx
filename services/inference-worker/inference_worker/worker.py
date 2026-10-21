"""Async Kafka consume → predict → publish findings loop."""

from __future__ import annotations

import json
import base64
import hashlib
import logging
import asyncio
from typing import Any

import httpx
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import TopicPartition

from inference_worker.adapters import adapt_features, direct_predict_body
from inference_worker.config import settings
from inference_worker.findings import build_finding, normalize_code_finding

logger = logging.getLogger("inference-worker")


class InferenceWorker:
    def __init__(self) -> None:
        self._consumer: AIOKafkaConsumer | None = None
        self._producer: AIOKafkaProducer | None = None
        self.processed = 0
        self.published = 0
        self.scored_unpublished = 0
        self.dlq_count = 0
        self.errors = 0
        self.ready = False
        self.last_error: str | None = None

    async def start(self) -> None:
        topics = settings.consume_topics()
        self._consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=settings.kafka_brokers,
            group_id=settings.group_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        self._producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_brokers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        consumer_started = False
        try:
            await self._consumer.start()
            consumer_started = True
            await self._producer.start()
        except Exception:
            if consumer_started:
                await self._consumer.stop()
            self._consumer = None
            self._producer = None
            raise
        self.ready = True
        logger.info("inference-worker consuming topics=%s (manual commit)", topics)

    async def stop(self) -> None:
        self.ready = False
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None

    def dlq_topic_for(self, topic: str) -> str:
        return f"{topic}{settings.dlq_suffix}"

    async def run_forever(self) -> None:
        if self._consumer is None:
            await self.start()
        assert self._consumer is not None
        async for msg in self._consumer:
            topic = msg.topic
            payload = msg.value
            partition = TopicPartition(msg.topic, msg.partition)
            try:
                if isinstance(payload, bytes):
                    payload = json.loads(payload.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("message value must be a JSON object")
                finding = await self.process_message(topic, payload)
                if finding is not None:
                    if settings.publish_findings_for(topic):
                        out_topic = settings.findings_topic_for(topic)
                        if out_topic is None:
                            raise ValueError(f"no findings topic for {topic}")
                        await self.publish_finding(out_topic, finding)
                    else:
                        # Score-only route (host-state): processor owns golden findings.
                        self.scored_unpublished += 1
                        logger.debug(
                            "scored %s without publishing findings (publish_findings=false)",
                            topic,
                        )
            except Exception as exc:  # noqa: BLE001 - keep the consumer alive
                self.errors += 1
                self.last_error = type(exc).__name__
                logger.exception("failed to process message from %s; sending to DLQ", topic)
                dlq_payload = payload if isinstance(payload, dict) else self._raw_value(payload)
                await self._park_and_ack(partition, msg.offset, topic, dlq_payload, exc)
            else:
                await self._commit_with_retry(partition, msg.offset + 1)

    async def _park_and_ack(
        self, partition: TopicPartition, offset: int, topic: str, payload: Any, exc: Exception,
    ) -> None:
        assert self._consumer is not None
        self._consumer.pause(partition)
        delay = 1.0
        try:
            while True:
                try:
                    await self.publish_dlq(
                        topic, payload, exc,
                        message_id=f"{topic}:{partition.partition}:{offset}",
                    )
                    await self._consumer.commit({partition: offset + 1})
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.last_error = "DLQ delivery or offset acknowledgement failed"
                    logger.exception("DLQ delivery/ack failed for %s; retrying in %.1fs", topic, delay)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30.0)
        finally:
            self._consumer.resume(partition)

    async def _commit_with_retry(self, partition: TopicPartition, offset: int) -> None:
        assert self._consumer is not None
        self._consumer.pause(partition)
        delay = 1.0
        try:
            while True:
                try:
                    await self._consumer.commit({partition: offset})
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.last_error = "output acknowledged but Kafka offset commit failed"
                    logger.exception("offset commit failed for %s; retrying in %.1fs", partition, delay)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30.0)
        finally:
            self._consumer.resume(partition)

    @staticmethod
    def _raw_value(value: Any) -> dict[str, Any]:
        if isinstance(value, bytes):
            return {
                "raw_value_base64": base64.b64encode(value).decode("ascii"),
                "raw_value_sha256": hashlib.sha256(value).hexdigest(),
                "raw_value_bytes": len(value),
            }
        return {"raw_value": str(value)[:4096]}

    async def publish_dlq(
        self, source_topic: str, payload: Any, exc: Exception, *, message_id: str = "",
    ) -> None:
        if self._producer is None:
            raise RuntimeError("producer not started")
        dlq_topic = self.dlq_topic_for(source_topic)
        envelope = {
            "source_topic": source_topic,
            "message_id": message_id,
            "error": type(exc).__name__,
            "payload": payload,
        }
        await self._producer.send_and_wait(
            dlq_topic,
            value=envelope,
            key=message_id.encode("utf-8") if message_id else None,
        )
        self.dlq_count += 1

    async def process_message(self, topic: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        self.processed += 1

        if topic == settings.code_findings_topic:
            # Prefer scoring code.features; advisory topic is normalized but skipped
            # when the same fingerprint was already emitted from code.features path
            # (stable finding ids make Kafka/API upserts idempotent).
            return normalize_code_finding(payload)

        model_name = settings.model_name_for(topic)
        if model_name is None:
            raise ValueError(f"unmapped feature topic: {topic}")

        return await self.score_feature(model_name, payload)

    async def score_feature(self, model_name: str, feature_msg: dict[str, Any]) -> dict[str, Any]:
        gateway_body = adapt_features(model_name, feature_msg)
        predict_response = await self.call_predict(gateway_body)
        return build_finding(
            model_name,
            feature_msg,
            predict_response,
            predict_body=gateway_body,
        )

    async def call_predict(self, gateway_body: dict[str, Any]) -> dict[str, Any]:
        model_name = str(gateway_body["model_name"])
        timeout = settings.request_timeout_seconds

        if settings.uses_model_gateway(model_name):
            url = f"{settings.model_gateway_url.rstrip('/')}/v1/predict"
            payload = gateway_body
            headers = {"X-API-Key": settings.model_gateway_api_key}
        else:
            url = f"{settings.direct_model_url(model_name).rstrip('/')}/v1/predict"
            payload = direct_predict_body(gateway_body)
            headers = {}

        async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return {"result": data, "model_name": model_name}
            return data

    async def publish_finding(self, topic: str, finding: dict[str, Any]) -> None:
        if self._producer is None:
            raise RuntimeError("producer not started")
        if not str(finding.get("tenant_id") or "").strip():
            raise ValueError("finding.tenant_id is required")
        if not str(finding.get("asset_id") or "").strip():
            raise ValueError("finding.asset_id is required")
        key = str(finding.get("finding_id") or "").encode("utf-8") or None
        await self._producer.send_and_wait(topic, value=finding, key=key)
        self.published += 1

    async def persist_finding(self, finding: dict[str, Any]) -> None:
        """Best-effort upsert into incident-api so UI/search see Kafka findings."""
        if not settings.persist_findings:
            return
        tenant_id = str(finding["tenant_id"])
        url = settings.incident_api_url.rstrip("/") + "/api/v1/findings"
        window = finding.get("window") or {}
        body = {
            "finding_id": finding.get("finding_id"),
            "finding_type": finding.get("finding_type") or "anomaly",
            "asset_id": finding["asset_id"],
            "service_id": finding.get("service_id"),
            "model_name": finding.get("model_name") or "",
            "model_version": finding.get("model_version"),
            "feature_version": finding.get("feature_version"),
            "raw_score": float(finding.get("raw_score") or 0.0),
            "calibrated_score": float(finding.get("calibrated_score") or 0.0),
            "severity_hint": finding.get("severity_hint"),
            "window": {
                "start": window.get("start"),
                "end": window.get("end"),
            },
            "contributors": list(finding.get("contributors") or []),
            "evidence_refs": list(finding.get("evidence_refs") or []),
            "context": dict(finding.get("context") or {}),
            "fingerprint": finding.get("fingerprint"),
            "category": list(finding.get("category") or []),
            "schema_version": str(finding.get("schema_version") or "1.0"),
        }
        if body["window"]["start"] is None or body["window"]["end"] is None:
            logger.warning("skip persist finding %s: missing window", finding.get("finding_id"))
            return
        headers = {"X-Tenant-Id": tenant_id}
        if settings.incident_api_service_key:
            headers["X-Service-Key"] = settings.incident_api_service_key
        try:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                resp = await client.post(url, json=body, headers=headers)
                resp.raise_for_status()
        except Exception:  # noqa: BLE001 - Kafka publish already succeeded
            logger.exception(
                "failed to persist finding %s to incident-api",
                finding.get("finding_id"),
            )
