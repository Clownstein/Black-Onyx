from log_processor.masking import mask_message


def test_masks_ip_uuid_email_and_long_numbers() -> None:
    raw = (
        "user alice@example.com from 10.0.4.21 uuid "
        "550e8400-e29b-41d4-a716-446655440000 ref 1234567890"
    )
    masked = mask_message(raw)
    assert "<IP>" in masked
    assert "<UUID>" in masked
    assert "<EMAIL>" in masked
    assert "<NUM>" in masked
    assert "10.0.4.21" not in masked
    assert "alice@example.com" not in masked
    assert "550e8400-e29b-41d4-a716-446655440000" not in masked
    assert "1234567890" not in masked


def test_leaves_short_numbers() -> None:
    assert mask_message("retry count 42") == "retry count 42"
