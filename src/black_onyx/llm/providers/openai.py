"""Official OpenAI LLM provider — Responses API only."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider

logger = logging.getLogger(__name__)

OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider(LLMProvider):
    """LLM provider for OpenAI's Responses API.

    Reasoning models and the GPT-5 family expect Responses (`max_output_tokens`,
    `instructions`) rather than Chat Completions. Self-hosted OpenAI-compatible
    servers belong in OpenAICompatibleProvider instead.
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "gpt-4o",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        base_url: str = OPENAI_BASE_URL,
    ) -> None:
        self._base_url = base_url.rstrip("/") or OPENAI_BASE_URL
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
        return "openai"

    @property
    def supports_images(self) -> bool:
        return True

    def _build_responses_input(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for msg in messages:
            if msg.images and msg.role != "assistant":
                content: list[dict[str, Any]] = [{"type": "input_text", "text": msg.content}]
                for img in msg.images:
                    b64, media_type = self.encode_image_to_base64(img)
                    content.append({
                        "type": "input_image",
                        "image_url": f"data:{media_type};base64,{b64}",
                        "detail": "auto",
                    })
                items.append({"role": msg.role, "content": content})
            else:
                items.append({"role": msg.role, "content": msg.content})
        return items

    def _responses_kwargs(
        self,
        system_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "temperature": temperature,
            "max_output_tokens": max_tokens,
        }
        if system_prompt:
            kwargs["instructions"] = system_prompt
        return kwargs

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
            response = client.responses.create(
                model=self._model,
                input=self._build_responses_input(messages),
                **self._responses_kwargs(system_prompt, temp, tokens),
            )
            usage = {}
            if response.usage:
                usage = {
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.total_tokens,
                }
            return ChatResponse(
                text=response.output_text or "",
                model=self._model,
                usage=usage,
                raw=response,
            )
        except Exception as e:
            logger.error(f"OpenAI Responses chat error: {e}")
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
            events = client.responses.create(
                model=self._model,
                input=self._build_responses_input(messages),
                stream=True,
                **self._responses_kwargs(system_prompt, temp, tokens),
            )
            for event in events:
                if event.type == "response.output_text.delta":
                    yield event.delta
                elif event.type == "error":
                    message = getattr(event, "message", "") or "unknown stream error"
                    logger.error(f"OpenAI Responses stream error: {message}")
                    yield f"Error: {message}"
                await asyncio.sleep(0)
        except Exception as e:
            logger.error(f"OpenAI Responses stream error: {e}")
            yield f"Error: {e}"

    def test_connection(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            client.responses.create(
                model=self._model,
                input="test",
                max_output_tokens=16,
            )
            return {"status": "ok", "provider": self.name, "model": self._model}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}
