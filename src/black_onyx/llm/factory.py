"""LLM factory creates provider instances from configuration."""

from __future__ import annotations

import logging
from typing import Any, get_args
from urllib.parse import urlparse

from black_onyx.config import LLMProviderName
from black_onyx.llm.base import LLMProvider

logger = logging.getLogger(__name__)

ALLOWED_LLM_PROVIDERS: tuple[LLMProviderName, ...] = get_args(LLMProviderName)


def migrate_openai_provider_settings(llm_config: Any) -> bool:
    """Move api.openai.com openai_compatible configs onto the openai provider.

    Returns True when the config object was mutated.
    """
    changed = False
    compat = getattr(llm_config, "openai_compatible", None)
    openai = getattr(llm_config, "openai", None)
    if compat is None or openai is None:
        return False
    host = (urlparse(getattr(compat, "base_url", "") or "").hostname or "").lower()
    if host == "api.openai.com":
        openai.model = compat.model
        openai.temperature = compat.temperature
        openai.max_tokens = compat.max_tokens
        if getattr(compat, "api_key_env", None):
            openai.api_key_env = compat.api_key_env
        compat.base_url = "http://localhost:1234/v1"
        compat.model = "local-model"
        if getattr(llm_config, "provider", None) == "openai_compatible":
            llm_config.provider = "openai"
        changed = True
    return changed


def _openrouter_headers(config: Any) -> dict[str, str]:
    headers = {"X-Title": str(getattr(config, "app_name", "") or "Black Onyx")}
    site_url = str(getattr(config, "site_url", "") or "").strip()
    if site_url:
        headers["HTTP-Referer"] = site_url
    return headers


def create_provider(
    provider_type: str,
    config: Any,
    api_keys: dict[str, str] | None = None,
) -> LLMProvider:
    """Create an LLM provider instance from configuration."""
    keys = api_keys or {}

    if provider_type == "local":
        from black_onyx.llm.providers.ollama import OllamaProvider
        return OllamaProvider(
            base_url=config.local.base_url,
            model=config.local.model,
            temperature=config.local.temperature,
            max_tokens=config.local.max_tokens,
        )

    if provider_type == "openai":
        from black_onyx.llm.providers.openai import OpenAIProvider
        api_key = keys.get(config.openai.api_key_env, "")
        return OpenAIProvider(
            api_key=api_key,
            model=config.openai.model,
            temperature=config.openai.temperature,
            max_tokens=config.openai.max_tokens,
        )

    if provider_type == "openai_compatible":
        from black_onyx.llm.providers.openai_compat import OpenAICompatibleProvider
        api_key = keys.get(config.openai_compatible.api_key_env, "")
        return OpenAICompatibleProvider(
            base_url=config.openai_compatible.base_url,
            api_key=api_key,
            model=config.openai_compatible.model,
            temperature=config.openai_compatible.temperature,
            max_tokens=config.openai_compatible.max_tokens,
        )

    if provider_type == "openrouter":
        from black_onyx.llm.providers.openai_compat import OpenAICompatibleProvider
        api_key = keys.get(config.openrouter.api_key_env, "")
        return OpenAICompatibleProvider(
            base_url=config.openrouter.base_url,
            api_key=api_key,
            model=config.openrouter.model,
            temperature=config.openrouter.temperature,
            max_tokens=config.openrouter.max_tokens,
            extra_headers=_openrouter_headers(config.openrouter),
            provider_name="openrouter",
        )

    if provider_type == "claude":
        from black_onyx.llm.providers.claude import ClaudeProvider
        api_key = keys.get(config.claude.api_key_env, "")
        return ClaudeProvider(
            api_key=api_key,
            model=config.claude.model,
            temperature=config.claude.temperature,
            max_tokens=config.claude.max_tokens,
        )

    if provider_type == "gemini":
        from black_onyx.llm.providers.gemini import GeminiProvider
        api_key = keys.get(config.gemini.api_key_env, "")
        return GeminiProvider(
            api_key=api_key,
            model=config.gemini.model,
            temperature=config.gemini.temperature,
            max_tokens=config.gemini.max_tokens,
        )

    raise ValueError(
        f"Unknown LLM provider type: '{provider_type}'. "
        f"Supported: {', '.join(ALLOWED_LLM_PROVIDERS)}"
    )


def list_available_providers() -> list[str]:
    """List all available provider types."""
    return list(ALLOWED_LLM_PROVIDERS)


def _provider_label(provider_type: str, config: Any) -> str:
    if provider_type == "local":
        return f"Local (Ollama) — {config.local.model}"
    if provider_type == "openai":
        return f"OpenAI — {config.openai.model}"
    if provider_type == "openai_compatible":
        custom = (getattr(config.openai_compatible, "display_name", "") or "").strip()
        if custom:
            return custom
        model = config.openai_compatible.model
        if "black-onyx" in model.lower():
            return f"Black Onyx 5B — {model}"
        return f"OpenAI-compatible — {model}"
    if provider_type == "openrouter":
        return f"OpenRouter — {config.openrouter.model}"
    if provider_type == "claude":
        return f"Claude — {config.claude.model}"
    if provider_type == "gemini":
        return f"Gemini — {config.gemini.model}"
    return provider_type


def describe_llm_providers(config: Any) -> dict[str, Any]:
    """Return provider ids with human-readable labels and active model names."""
    details: dict[str, dict[str, str]] = {}
    for provider_type in ALLOWED_LLM_PROVIDERS:
        details[provider_type] = {
            "label": _provider_label(provider_type, config),
            "model": _provider_model(provider_type, config),
        }
    return {
        "providers": list(ALLOWED_LLM_PROVIDERS),
        "active": getattr(config, "provider", "local"),
        "details": details,
    }


def _provider_model(provider_type: str, config: Any) -> str:
    mapping = {
        "local": config.local.model,
        "openai": config.openai.model,
        "openai_compatible": config.openai_compatible.model,
        "openrouter": config.openrouter.model,
        "claude": config.claude.model,
        "gemini": config.gemini.model,
    }
    return str(mapping.get(provider_type, ""))
