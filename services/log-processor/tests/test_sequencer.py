from datetime import UTC, datetime, timedelta

from black_onyx_contracts import LogFeatureEvent

from log_processor.sequencer import SequenceBuilder


def _ulidish(idx: int) -> str:
    return f"01JTEST{idx:019d}"[:26]


def _event(idx: int, start: datetime) -> LogFeatureEvent:
    return LogFeatureEvent(
        event_id=_ulidish(idx),
        template_id=f"tpl-auth-{idx % 3}",
        severity="INFO",
        occurred_at=start + timedelta(seconds=idx),
    )


def test_emits_on_max_length_with_stride() -> None:
    builder = SequenceBuilder(max_length=8, stride=4, min_length=4)
    start = datetime(2026, 7, 26, 20, 0, tzinfo=UTC)
    emitted = []
    for i in range(12):
        emitted.extend(
            builder.add_event(
                tenant_id="tenant-a",
                asset_id="host-1",
                service_id="payments-api",
                event=_event(i, start),
            )
        )
    assert len(emitted) >= 1
    assert all(len(seq.events) == 8 for seq in emitted)
    assert all(seq.sequence_key == "payments-api:host-1" for seq in emitted)
    assert all(
        seq.idempotency_key.endswith(":1.0.0") and seq.idempotency_key.startswith("tenant-a:")
        for seq in emitted
    )


def test_flush_inactive_emits_short_window() -> None:
    builder = SequenceBuilder(
        max_length=128,
        stride=32,
        min_length=4,
        inactivity_timeout_seconds=60,
    )
    start = datetime(2026, 7, 26, 20, 0, tzinfo=UTC)
    for i in range(5):
        builder.add_event(
            tenant_id="tenant-a",
            asset_id="host-1",
            service_id="auth",
            event=_event(i, start),
            now=start + timedelta(seconds=i),
        )
    emitted = builder.flush_inactive(now=start + timedelta(seconds=400))
    assert len(emitted) == 1
    assert len(emitted[0].events) == 5
