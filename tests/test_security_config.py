"""Tests for SecurityToolsConfig validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from black_onyx.config import SecurityToolsConfig, Settings


def test_security_tools_config_defaults() -> None:
    """Default config is disabled with safe defaults."""
    cfg = SecurityToolsConfig()
    assert cfg.enabled is False
    assert cfg.gateway_url == "http://security-gateway:8000"
    assert cfg.runner_url == "http://security-runner:8080"
    assert cfg.gateway_key_env == "SECURITY_GATEWAY_KEY"
    assert cfg.runner_token_env == "SECURITY_RUNNER_TOKEN"
    assert cfg.sandbox_image == ""
    assert cfg.enable_bash is False
    assert cfg.enable_hydra is False
    assert cfg.enable_tcpdump is False
    assert cfg.enable_cast_send is False
    assert cfg.sqlmap_exploit_mode is False
    assert cfg.tool_approval == "required"
    assert cfg.allow_public_targets is False
    assert cfg.allow_private_targets is False
    assert cfg.allowed_targets == []
    assert cfg.max_tool_rounds == 15
    assert cfg.audit_log_enabled is True


def test_security_tools_config_enabled_with_image() -> None:
    """Config can be enabled with a digest-pinned sandbox image."""
    cfg = SecurityToolsConfig(
        enabled=True,
        sandbox_image="sha256:" + "a" * 64,
    )
    assert cfg.enabled is True
    assert cfg.sandbox_image.startswith("sha256:")


def test_security_tools_config_tool_approval_auto() -> None:
    """tool_approval='auto' is accepted (trusted labs only)."""
    cfg = SecurityToolsConfig(tool_approval="auto")
    assert cfg.tool_approval == "auto"


def test_security_tools_config_tool_approval_invalid() -> None:
    """An invalid tool_approval value is rejected."""
    with pytest.raises(ValidationError):
        SecurityToolsConfig(tool_approval="bogus")


def test_security_tools_config_max_tool_rounds_minimum() -> None:
    """max_tool_rounds must be at least 1."""
    with pytest.raises(ValidationError, match="max_tool_rounds"):
        SecurityToolsConfig(max_tool_rounds=0)


def test_security_tools_config_max_tool_rounds_maximum() -> None:
    """max_tool_rounds cannot exceed 20."""
    with pytest.raises(ValidationError, match="max_tool_rounds"):
        SecurityToolsConfig(max_tool_rounds=21)


def test_security_tools_config_max_tool_rounds_boundary() -> None:
    """max_tool_rounds=1 and =20 are valid boundaries."""
    assert SecurityToolsConfig(max_tool_rounds=1).max_tool_rounds == 1
    assert SecurityToolsConfig(max_tool_rounds=20).max_tool_rounds == 20


def test_security_tools_config_allowed_targets() -> None:
    """allowed_targets can be set to a list of targets."""
    cfg = SecurityToolsConfig(allowed_targets=["10.0.0.1", "example.com"])
    assert cfg.allowed_targets == ["10.0.0.1", "example.com"]


def test_security_tools_config_enable_gates() -> None:
    """Per-tool gates can be individually enabled."""
    cfg = SecurityToolsConfig(
        enable_bash=True,
        enable_hydra=True,
        enable_tcpdump=True,
        enable_cast_send=True,
        sqlmap_exploit_mode=True,
    )
    assert cfg.enable_bash is True
    assert cfg.enable_hydra is True
    assert cfg.enable_tcpdump is True
    assert cfg.enable_cast_send is True
    assert cfg.sqlmap_exploit_mode is True


def test_settings_includes_security_tools() -> None:
    """The root Settings includes a security_tools field with defaults."""
    settings = Settings()
    assert hasattr(settings, "security_tools")
    assert isinstance(settings.security_tools, SecurityToolsConfig)
    assert settings.security_tools.enabled is False


def test_settings_security_tools_independent() -> None:
    """Each Settings instance gets an independent SecurityToolsConfig (not shared)."""
    s1 = Settings()
    s2 = Settings()
    assert s1.security_tools is not s2.security_tools


def test_security_tools_config_custom_urls() -> None:
    """Gateway and runner URLs can be customized."""
    cfg = SecurityToolsConfig(
        gateway_url="http://my-gateway:9000",
        runner_url="http://my-runner:9001",
    )
    assert cfg.gateway_url == "http://my-gateway:9000"
    assert cfg.runner_url == "http://my-runner:9001"


def test_security_tools_config_custom_env_names() -> None:
    """Secret env variable names can be customized."""
    cfg = SecurityToolsConfig(
        gateway_key_env="MY_GATEWAY_KEY",
        runner_token_env="MY_RUNNER_TOKEN",
    )
    assert cfg.gateway_key_env == "MY_GATEWAY_KEY"
    assert cfg.runner_token_env == "MY_RUNNER_TOKEN"
