"""Detection connector factory — creates connector instances from configuration."""

from __future__ import annotations

from typing import Any

from black_onyx.connectors.base import DetectionConnector


def create_detection_connector(
    connector_type: str,
    name: str,
    config: dict[str, Any],
    secrets: dict[str, str] | None = None,
) -> DetectionConnector:
    """Create a detection connector instance from configuration.

    Args:
        connector_type: "generic_rest", "microsoft_defender", or "crowdstrike_falcon".
        name: The user-chosen connector instance name.
        config: Connector configuration (base_url, auth, pagination, field_map, ...).
        secrets: Resolved credential values (api_key/bearer_token/client_id/client_secret) —
                 already-resolved values, never env-var names; the manager resolves
                 `credential_env` before calling this factory.

    Returns:
        DetectionConnector instance.

    Raises:
        ValueError: If the connector type is unknown.
    """
    resolved_secrets = secrets or {}

    if connector_type == "generic_rest":
        from black_onyx.connectors.generic_rest import GenericRestConnector
        return GenericRestConnector(name=name, config=config, secrets=resolved_secrets)

    elif connector_type == "microsoft_defender":
        from black_onyx.connectors.microsoft_defender import MicrosoftDefenderConnector
        return MicrosoftDefenderConnector(name=name, config=config, secrets=resolved_secrets)

    elif connector_type == "crowdstrike_falcon":
        from black_onyx.connectors.crowdstrike_falcon import CrowdStrikeFalconConnector
        return CrowdStrikeFalconConnector(name=name, config=config, secrets=resolved_secrets)

    else:
        raise ValueError(
            f"Unknown connector type: '{connector_type}'. "
            f"Supported: generic_rest, microsoft_defender, crowdstrike_falcon"
        )
