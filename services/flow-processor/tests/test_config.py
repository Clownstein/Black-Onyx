from flow_processor.config import Settings


def test_default_port_is_unique_from_model_gateway() -> None:
    """Standalone flow-processor must not bind model-gateway's default port."""
    default_port = Settings.model_fields["port"].default
    assert default_port == 8094
    assert default_port != 8091
