from datetime import datetime, timedelta, timezone

from threat_intel_service.store import expire_stale, list_feed_health, match_observables, record_feed_health, upsert_indicator


def test_upsert_dedupes_on_type_value_source(db_session) -> None:
    first = upsert_indicator(
        db_session,
        {
            "indicator_id": "ind-1",
            "observable_type": "ipv4",
            "observable_value": "203.0.113.50",
            "source": "taxii-demo",
            "confidence": 80,
            "tlp": "amber",
        },
    )
    second = upsert_indicator(
        db_session,
        {
            "indicator_id": "ind-2",
            "observable_type": "ipv4",
            "observable_value": "203.0.113.50",
            "source": "taxii-demo",
            "confidence": 95,
            "tlp": "red",
            "campaigns": ["demo"],
        },
    )
    db_session.commit()
    assert first.indicator_id == second.indicator_id == "ind-1"
    assert second.confidence == 95
    assert second.tlp == "red"
    assert second.campaigns == ["demo"]


def test_match_and_expire(db_session) -> None:
    now = datetime.now(timezone.utc)
    upsert_indicator(
        db_session,
        {
            "indicator_id": "ind-live",
            "observable_type": "domain",
            "observable_value": "evil.example",
            "source": "stix-upload",
            "confidence": 90,
            "valid_until": now + timedelta(hours=1),
        },
    )
    upsert_indicator(
        db_session,
        {
            "indicator_id": "ind-stale",
            "observable_type": "domain",
            "observable_value": "old.example",
            "source": "stix-upload",
            "confidence": 90,
            "valid_until": now - timedelta(hours=1),
        },
    )
    db_session.commit()

    hits = match_observables(
        db_session,
        [
            {"type": "domain", "value": "evil.example"},
            {"type": "domain", "value": "old.example"},
        ],
        now=now,
    )
    assert [h.indicator_id for h in hits] == ["ind-live"]

    deleted = expire_stale(db_session, now=now)
    db_session.commit()
    assert deleted == 1
    assert match_observables(db_session, [{"type": "domain", "value": "old.example"}], now=now) == []


def test_feed_health(db_session) -> None:
    record_feed_health(db_session, "cisa-kev", status="ok", indicator_count=3)
    db_session.commit()
    health = list_feed_health(db_session)
    assert health[0]["feed_name"] == "cisa-kev"
    assert health[0]["last_status"] == "ok"
    assert health[0]["indicator_count"] == 3
