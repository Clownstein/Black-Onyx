"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from black_onyx_tools.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        base_url="http://testserver",
        mcp_service_key="test-key",
        default_tenant_id="tenant-test",
        tools_allow_sandbox=False,
    )
