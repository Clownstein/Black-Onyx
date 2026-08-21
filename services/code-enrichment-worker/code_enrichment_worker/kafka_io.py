from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from kafka import KafkaConsumer, KafkaProducer

from code_enrichment_worker.config import settings
from code_enrichment_worker.enrich import enrich_code
from code_enrichment_worker.incident_client import fetch_high_risk_code_findings

logger = logging.getLogger(__name__)


class EnrichmentConsumer:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._poll_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.ready = False
        self.last_error: str | None = None
        self.processed = 0
        self.errors = 0
        self._consumer: KafkaConsumer | None = None
        self._producer: KafkaProducer | None = None

    def start(self) -> None:
        if settings.enable_kafka:
            self._thread = threading.Thread(
                target=self._run_kafka, name="code-enrich-kafka", daemon=True
            )
            self._thread.start()
        else:
            self.ready = True
        if settings.poll_findings:
            self._poll_thread = threading.Thread(
                target=self._run_poll, name="code-enrich-poll", daemon=True
            )
            self._poll_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5)
        if self._consumer is not None:
            self._consumer.close()
        if self._producer is not None:
            self._producer.close()

    def _run_kafka(self) -> None:
        try:
            brokers = [b.strip() for b in settings.kafka_brokers.split(",") if b.strip()]
            self._consumer = KafkaConsumer(
                settings.topic_enrichment,
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
                        try:
                            enrich_code(msg.value)
                            self.processed += 1
                        except Exception as exc:  # noqa: BLE001
                            self.errors += 1
                            self.last_error = str(exc)
                            logger.exception("enrichment failed")
                            if self._producer is not None:
                                self._producer.send(
                                    settings.topic_dlq,
                                    {"error": str(exc), "payload": msg.value},
                                )
                                self._producer.flush()
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            self.ready = False
            logger.exception("enrichment kafka consumer failed")

    def _run_poll(self) -> None:
        while not self._stop.is_set():
            try:
                items = fetch_high_risk_code_findings(
                    tenant_id=settings.poll_tenant_id,
                    min_score=settings.poll_min_score,
                )
                for item in items:
                    ctx = item.get("context") or {}
                    if isinstance(ctx, dict) and (ctx.get("code_enrichment") or {}).get("status"):
                        continue
                    payload: dict[str, Any] = {
                        "tenant_id": item.get("tenant_id") or settings.poll_tenant_id,
                        "finding_id": item.get("finding_id"),
                        "finding": item,
                        "asset_id": item.get("asset_id"),
                        "service_id": item.get("service_id"),
                        "calibrated_score": item.get("calibrated_score"),
                        "severity_hint": item.get("severity_hint"),
                    }
                    # Prefer nested payload files/diff if present
                    nested = item.get("payload") if isinstance(item.get("payload"), dict) else {}
                    for key in ("files", "diff", "patch", "repo_path", "cwe_ids"):
                        if key in nested:
                            payload[key] = nested[key]
                        if key in ctx:
                            payload[key] = ctx[key]
                    try:
                        enrich_code(payload)
                        self.processed += 1
                    except Exception as exc:  # noqa: BLE001
                        self.errors += 1
                        self.last_error = str(exc)
                        logger.exception("poll enrichment failed")
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)
                logger.exception("findings poll loop error")
            self._stop.wait(settings.poll_interval_seconds)
