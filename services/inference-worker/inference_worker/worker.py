"""Async Kafka consume → predict → publish findings loop."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

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
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )
        self._producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_brokers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        await self._consumer.start()
        await self._producer.start()
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
            try:
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
                await self._consumer.commit()
            except Exception as exc:  # noqa: BLE001 - keep the consumer alive
                self.errors += 1
                self.last_error = str(exc)
                logger.exception("failed to process message from %s; sending to DLQ", topic)
                try:
                    await self.publish_dlq(topic, payload if isinstance(payload, dict) else {"raw": payload}, exc)
                    await self._consumer.commit()
                except Exception:  # noqa: BLE001
                    logger.exception("DLQ publish/commit failed for %s", topic)

    async def publish_dlq(self, source_topic: str, payload: Any, exc: Exception) -> None:
        if self._producer is None:
            raise RuntimeError("producer not started")
        dlq_topic = self.dlq_topic_for(source_topic)
        envelope = {
            "source_topic": source_topic,
            "error": str(exc),
            "payload": payload,
        }
        await self._producer.send_and_wait(dlq_topic, value=envelope)
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

        if settings.use_model_gateway:
            url = f"{settings.model_gateway_url.rstrip('/')}/v1/predict"
            payload = gateway_body
        else:
            url = f"{settings.direct_model_url(model_name).rstrip('/')}/v1/predict"
            payload = direct_predict_body(gateway_body)

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return {"result": data, "model_name": model_name}
            return data

    async def publish_finding(self, topic: str, finding: dict[str, Any]) -> None:
        if self._producer is None:
            raise RuntimeError("producer not started")
        key = str(finding.get("finding_id") or "").encode("utf-8") or None
        await self._producer.send_and_wait(topic, value=finding, key=key)
        self.published += 1
        await self.persist_finding(finding)

    async def persist_finding(self, finding: dict[str, Any]) -> None:
        """Best-effort upsert into incident-api so UI/search see Kafka findings."""
        if not settings.persist_findings:
            return
        tenant_id = str(finding.get("tenant_id") or "default")
        url = settings.incident_api_url.rstrip("/") + "/api/v1/findings"
        window = finding.get("window") or {}
        body = {
            "finding_id": finding.get("finding_id"),
            "finding_type": finding.get("finding_type") or "anomaly",
            "asset_id": finding.get("asset_id") or "unknown",
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
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
                resp = await client.post(url, json=body, headers=headers)
                resp.raise_for_status()
        except Exception:  # noqa: BLE001 - Kafka publish already succeeded
            logger.exception(
                "failed to persist finding %s to incident-api",
                finding.get("finding_id"),
            )
