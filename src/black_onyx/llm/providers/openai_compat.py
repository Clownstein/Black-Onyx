"""OpenAI-compatible LLM provider — Chat Completions only (LM Studio, vLLM, OpenRouter, etc.)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider

logger = logging.getLogger(__name__)

# Official OpenAI hosts must use OpenAIProvider (Responses API), not this class.
OPENAI_HOSTS = frozenset({"api.openai.com"})


class OpenAICompatibleProvider(LLMProvider):
    """LLM provider using Chat Completions against an OpenAI-compatible base URL.

    Works with LM Studio, vLLM, OpenRouter, Together AI, and similar servers.
    Pointing base_url at api.openai.com is rejected — use the openai provider.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:1234/v1",
        api_key: str = "",
        model: str = "gpt-4o",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> None:
        host = (urlparse(base_url).hostname or "").lower()
        if host in OPENAI_HOSTS:
            raise ValueError(
                "api.openai.com requires the 'openai' provider (Responses API). "
                "Use openai_compatible only for Chat Completions endpoints."
            )
        self._base_url = base_url
        self._api_key = api_key or "not-needed"
        self._model = model
        self._default_temperature = temperature
        self._default_max_tokens = max_tokens
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(base_url=self._base_url, api_key=self._api_key)
        return self._client

    @property
    def name(self) -> str:
        return "openai_compatible"

    @property
    def supports_images(self) -> bool:
        return True

    def _build_messages(
        self,
        messages: list[ChatMessage],
        system_prompt: str,
    ) -> list[dict[str, Any]]:
        api_messages: list[dict[str, Any]] = []
        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})
        for msg in messages:
            if msg.images:
                content: list[dict[str, Any]] = [{"type": "text", "text": msg.content}]
                for img in msg.images:
                    b64, media_type = self.encode_image_to_base64(img)
                    content.append({
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{media_type};base64,{b64}",
                            "detail": "auto",
                        },
                    })
                api_messages.append({"role": msg.role, "content": content})
            else:
                api_messages.append({"role": msg.role, "content": msg.content})
        return api_messages

    def chat(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens
        try:
            client = self._get_client()
            api_messages = self._build_messages(messages, system_prompt)
            response = client.chat.completions.create(
                model=self._model,
                messages=api_messages,
                temperature=temp,
                max_tokens=tokens,
            )
            text = response.choices[0].message.content or ""
            usage = {}
            if response.usage:
                usage = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }
            return ChatResponse(text=text, model=self._model, usage=usage, raw=response)
        except Exception as e:
            logger.error(f"OpenAI-compatible chat error: {e}")
            return ChatResponse(text=f"Error: {e}", model=self._model)

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens
        try:
            client = self._get_client()
            api_messages = self._build_messages(messages, system_prompt)
            stream = client.chat.completions.create(
                model=self._model,
                messages=api_messages,
                temperature=temp,
                max_tokens=tokens,
                stream=True,
            )
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content is not None:
                    yield chunk.choices[0].delta.content
                await asyncio.sleep(0)
        except Exception as e:
            logger.error(f"OpenAI-compatible stream error: {e}")
            yield f"Error: {e}"

    def test_connection(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1,
            )
            return {"status": "ok", "provider": self.name, "model": self._model}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}
