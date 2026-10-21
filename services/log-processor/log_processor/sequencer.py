"""Sequence windowing keyed by service:asset."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from black_onyx_contracts import LogFeatureEvent, LogFeatureSequence
from ulid import ULID


@dataclass
class _Buffer:
    events: list[LogFeatureEvent] = field(default_factory=list)
    last_seen: datetime | None = None


class SequenceBuilder:
    def __init__(
        self,
        *,
        max_length: int = 128,
        stride: int = 32,
        min_length: int = 4,
        max_duration_seconds: int = 900,
        inactivity_timeout_seconds: int = 300,
        processor_version: str = "1.0.0",
        feature_version: str = "1.0",
    ) -> None:
        self.max_length = max_length
        self.stride = stride
        self.min_length = min_length
        self.max_duration = timedelta(seconds=max_duration_seconds)
        self.inactivity_timeout = timedelta(seconds=inactivity_timeout_seconds)
        self.processor_version = processor_version
        self.feature_version = feature_version
        self._buffers: dict[str, _Buffer] = {}

    def sequence_key(self, service_id: str | None, asset_id: str) -> str:
        service = service_id or "unknown-service"
        return f"{service}:{asset_id}"

    def add_event(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        service_id: str | None,
        event: LogFeatureEvent,
        now: datetime | None = None,
    ) -> list[LogFeatureSequence]:
        key = self.sequence_key(service_id, asset_id)
        buffer_key = f"{tenant_id}:{key}"
        clock = now or datetime.now(UTC)
        emitted: list[LogFeatureSequence] = []

        buf = self._buffers.get(buffer_key)
        if buf is None:
            buf = _Buffer()
            self._buffers[buffer_key] = buf
        else:
            emitted.extend(
                self._maybe_close(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    service_id=service_id,
                    sequence_key=key,
                    buffer_key=buffer_key,
                    buf=buf,
                    reason_time=clock,
                )
            )
            buf = self._buffers.setdefault(buffer_key, _Buffer())

        if buf.events:
            prev = buf.events[-1].occurred_at
            delta = int((event.occurred_at - prev).total_seconds() * 1000)
            event = event.model_copy(update={"delta_ms": max(delta, 0)})

        buf.events.append(event)
        buf.last_seen = clock

        while len(buf.events) >= self.max_length:
            window = buf.events[: self.max_length]
            if self._duration(window) > self.max_duration:
                # Emit up to max duration cutoff, then slide.
                cutoff_idx = self._index_within_duration(window)
                window = window[:cutoff_idx]
                if len(window) >= self.min_length:
                    emitted.append(
                        self._to_sequence(
                            tenant_id=tenant_id,
                            asset_id=asset_id,
                            service_id=service_id,
                            sequence_key=key,
                            events=window,
                        )
                    )
                buf.events = buf.events[self.stride :]
                continue

            emitted.append(
                self._to_sequence(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    service_id=service_id,
                    sequence_key=key,
                    events=window,
                )
            )
            buf.events = buf.events[self.stride :]

        # Duration-based flush even before max length.
        if buf.events and self._duration(buf.events) > self.max_duration:
            cutoff_idx = self._index_within_duration(buf.events)
            window = buf.events[:cutoff_idx]
            if len(window) >= self.min_length:
                emitted.append(
                    self._to_sequence(
                        tenant_id=tenant_id,
                        asset_id=asset_id,
                        service_id=service_id,
                        sequence_key=key,
                        events=window,
                    )
                )
            buf.events = buf.events[max(self.stride, cutoff_idx) :]

        return emitted

    def flush_inactive(self, now: datetime | None = None) -> list[LogFeatureSequence]:
        clock = now or datetime.now(UTC)
        emitted: list[LogFeatureSequence] = []
        for buffer_key in list(self._buffers):
            tenant_id, sequence_key = buffer_key.split(":", 1)
            service_id, asset_id = self._split_sequence_key(sequence_key)
            buf = self._buffers[buffer_key]
            emitted.extend(
                self._maybe_close(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    service_id=service_id,
                    sequence_key=sequence_key,
                    buffer_key=buffer_key,
                    buf=buf,
                    reason_time=clock,
                    force_inactive=True,
                )
            )
        return emitted

    def _maybe_close(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        service_id: str | None,
        sequence_key: str,
        buffer_key: str,
        buf: _Buffer,
        reason_time: datetime,
        force_inactive: bool = False,
    ) -> list[LogFeatureSequence]:
        if not buf.events or buf.last_seen is None:
            return []
        inactive = reason_time - buf.last_seen >= self.inactivity_timeout
        if not (force_inactive and inactive) and not inactive:
            return []
        emitted: list[LogFeatureSequence] = []
        if len(buf.events) >= self.min_length:
            emitted.append(
                self._to_sequence(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    service_id=service_id,
                    sequence_key=sequence_key,
                    events=list(buf.events),
                )
            )
        del self._buffers[buffer_key]
        return emitted

    def _to_sequence(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        service_id: str | None,
        sequence_key: str,
        events: list[LogFeatureEvent],
    ) -> LogFeatureSequence:
        sequence_id = str(ULID())
        last_event_id = events[-1].event_id
        idempotency_key = f"{tenant_id}:{last_event_id}:{self.processor_version}"
        return LogFeatureSequence(
            sequence_id=sequence_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            service_id=service_id,
            sequence_key=sequence_key,
            feature_version=self.feature_version,
            processor_version=self.processor_version,
            window_start=events[0].occurred_at,
            window_end=events[-1].occurred_at,
            events=events,
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _duration(events: list[LogFeatureEvent]) -> timedelta:
        return events[-1].occurred_at - events[0].occurred_at

    def _index_within_duration(self, events: list[LogFeatureEvent]) -> int:
        start = events[0].occurred_at
        for idx, event in enumerate(events):
            if event.occurred_at - start > self.max_duration:
                return max(idx, 1)
        return len(events)

    @staticmethod
    def _split_sequence_key(sequence_key: str) -> tuple[str | None, str]:
        if ":" not in sequence_key:
            return None, sequence_key
        service_id, asset_id = sequence_key.split(":", 1)
        return service_id, asset_id
