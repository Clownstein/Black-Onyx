"""Parse raw log events into feature sequences."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from black_onyx_contracts import LogFeatureEvent, LogFeatureSequence, LogRawEvent
from ulid import ULID

from log_processor.config import settings
from log_processor.sequencer import SequenceBuilder
from log_processor.templates import TemplateExtractor


def _validate_raw_log_fields(message: str, severity: str, payload: dict[str, Any]) -> None:
    """Validate domain log fields when present (envelope validated separately upstream)."""
    domain = {
        "event_type": "log.raw",
        "severity": severity,
        "message": message,
        "facility": payload.get("facility"),
        "logger": payload.get("logger"),
        "structured": payload.get("structured") or {},
        "resource": payload.get("resource"),
    }
    nested = payload.get("payload")
    if isinstance(nested, dict):
        domain["facility"] = nested.get("facility", domain["facility"])
        domain["logger"] = nested.get("logger", domain["logger"])
        domain["structured"] = nested.get("structured") or domain["structured"]
        domain["resource"] = nested.get("resource", domain["resource"])
    LogRawEvent.model_validate(domain)


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt
    return datetime.now(UTC)


def extract_message_and_severity(payload: dict[str, Any]) -> tuple[str, str]:
    nested = payload.get("payload")
    if isinstance(nested, dict):
        message = nested.get("message") or payload.get("message") or ""
        severity = nested.get("severity") or payload.get("severity") or "INFO"
    else:
        message = payload.get("message") or ""
        severity = payload.get("severity") or "INFO"
    if isinstance(message, dict):
        message = str(message.get("text") or message)
    return str(message), str(severity).upper()


class LogProcessor:
    def __init__(self) -> None:
        self.templates = TemplateExtractor()
        self.sequences = SequenceBuilder(
            max_length=settings.max_sequence_length,
            stride=settings.sequence_stride,
            min_length=settings.min_sequence_length,
            max_duration_seconds=settings.max_duration_seconds,
            inactivity_timeout_seconds=settings.inactivity_timeout_seconds,
            processor_version=settings.processor_version,
            feature_version=settings.feature_version,
        )
        self.processed = 0
        self.published = 0

    def process_payload(self, payload: dict[str, Any]) -> list[LogFeatureSequence]:
        message, severity = extract_message_and_severity(payload)
        if not message.strip():
            raise ValueError("log message is empty")

        # Accept envelope-shaped payloads and reject incomplete identity metadata.
        event_id = str(payload.get("event_id") or ULID())
        tenant_id = str(payload.get("tenant_id") or "").strip()
        asset = payload.get("asset") or {}
        asset_id = str(asset.get("asset_id") or payload.get("asset_id") or "").strip()
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not asset_id:
            raise ValueError("asset.asset_id or asset_id is required")
        service_id = asset.get("service_id") or payload.get("service_id")
        if service_id is not None:
            service_id = str(service_id)
        logger_name = None
        nested = payload.get("payload")
        if isinstance(nested, dict):
            logger_name = nested.get("logger")
        logger_name = logger_name or payload.get("logger")

        if not payload.get("occurred_at"):
            raise ValueError("occurred_at is required")
        occurred_at = _parse_datetime(payload["occurred_at"])
        tmpl = self.templates.extract(message)

        feature_event = LogFeatureEvent(
            event_id=event_id,
            template_id=tmpl.template_id,
            severity=severity,
            logger=str(logger_name) if logger_name else None,
            occurred_at=occurred_at,
            delta_ms=0,
            parameter_categories=[],
            is_novel_template=tmpl.is_novel,
        )

        _validate_raw_log_fields(message, severity, payload)

        emitted = self.sequences.add_event(
            tenant_id=tenant_id,
            asset_id=asset_id,
            service_id=service_id,
            event=feature_event,
            now=occurred_at,
        )
        self.processed += 1
        self.published += len(emitted)
        return emitted
