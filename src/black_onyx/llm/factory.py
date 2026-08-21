"""LLM factory — creates provider instances from configuration."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from black_onyx.llm.base import LLMProvider

logger = logging.getLogger(__name__)

ALLOWED_LLM_PROVIDERS = (
    "local",
    "openai",
    "openai_compatible",
    "claude",
    "gemini",
    "llama_cpp",
)


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

    elif provider_type == "openai":
        from black_onyx.llm.providers.openai import OpenAIProvider
        api_key = keys.get(config.openai.api_key_env, "")
        return OpenAIProvider(
            api_key=api_key,
            model=config.openai.model,
            temperature=config.openai.temperature,
            max_tokens=config.openai.max_tokens,
        )

    elif provider_type == "openai_compatible":
        from black_onyx.llm.providers.openai_compat import OpenAICompatibleProvider
        api_key = keys.get(config.openai_compatible.api_key_env, "")
        return OpenAICompatibleProvider(
            base_url=config.openai_compatible.base_url,
            api_key=api_key,
            model=config.openai_compatible.model,
            temperature=config.openai_compatible.temperature,
            max_tokens=config.openai_compatible.max_tokens,
        )

    elif provider_type == "claude":
        from black_onyx.llm.providers.claude import ClaudeProvider
        api_key = keys.get(config.claude.api_key_env, "")
        return ClaudeProvider(
            api_key=api_key,
            model=config.claude.model,
            temperature=config.claude.temperature,
            max_tokens=config.claude.max_tokens,
        )

    elif provider_type == "gemini":
        from black_onyx.llm.providers.gemini import GeminiProvider
        api_key = keys.get(config.gemini.api_key_env, "")
        return GeminiProvider(
            api_key=api_key,
            model=config.gemini.model,
            temperature=config.gemini.temperature,
            max_tokens=config.gemini.max_tokens,
        )

    elif provider_type == "llama_cpp":
        from black_onyx.llm.providers.llama_cpp import LlamaCppProvider
        return LlamaCppProvider(
            model_path=config.llama_cpp.model_path,
            n_ctx=config.llama_cpp.n_ctx,
            n_gpu_layers=config.llama_cpp.n_gpu_layers,
            temperature=config.llama_cpp.temperature,
            max_tokens=config.llama_cpp.max_tokens,
        )

    else:
        raise ValueError(
            f"Unknown LLM provider type: '{provider_type}'. "
            f"Supported: {', '.join(ALLOWED_LLM_PROVIDERS)}"
        )


def list_available_providers() -> list[str]:
    """List all available provider types."""
    return list(ALLOWED_LLM_PROVIDERS)
