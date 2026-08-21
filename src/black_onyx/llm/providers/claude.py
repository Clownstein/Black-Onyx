"""Anthropic Claude LLM provider — using the official anthropic Python SDK."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider

logger = logging.getLogger(__name__)


class ClaudeProvider(LLMProvider):
    """LLM provider using Anthropic's Claude API.

    Key difference from OpenAI: the system prompt is a top-level parameter,
    NOT a message in the messages array. Vision images use a different
    content block format (type: "image" with source.type: "base64").
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "claude-sonnet-4-20250514",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._default_temperature = temperature
        self._default_max_tokens = max_tokens
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-load the Anthropic client."""
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    @property
    def name(self) -> str:
        return "claude"

    @property
    def supports_images(self) -> bool:
        return True

    def _build_messages(
        self,
        messages: list[ChatMessage],
    ) -> list[dict[str, Any]]:
        """Build the Claude messages array (without system prompt).

        System prompt is passed separately as a top-level parameter.
        """
        api_messages: list[dict[str, Any]] = []

        for msg in messages:
            if msg.images:
                # Build content array with image and text blocks
                content: list[dict[str, Any]] = []
                for img in msg.images:
                    b64, media_type = self.encode_image_to_base64(img)
                    content.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": b64,
                        },
                    })
                content.append({"type": "text", "text": msg.content})
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
        """Send a non-streaming chat request to Claude."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        try:
            client = self._get_client()
            api_messages = self._build_messages(messages)

            kwargs: dict[str, Any] = {
                "model": self._model,
                "max_tokens": tokens,
                "messages": api_messages,
                "temperature": temp,
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            message = client.messages.create(**kwargs)

            # Extract text from content blocks
            text_parts: list[str] = []
            for block in message.content:
                if block.type == "text":
                    text_parts.append(block.text)
            text = "".join(text_parts)

            usage = {}
            if message.usage:
                usage = {
                    "input_tokens": message.usage.input_tokens,
                    "output_tokens": message.usage.output_tokens,
                }
            return ChatResponse(text=text, model=self._model, usage=usage, raw=message)
        except Exception as e:
            logger.error(f"Claude chat error: {e}")
            return ChatResponse(text=f"Error: {e}", model=self._model)

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Stream chat tokens from Claude using messages.stream()."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        try:
            client = self._get_client()
            api_messages = self._build_messages(messages)

            kwargs: dict[str, Any] = {
                "model": self._model,
                "max_tokens": tokens,
                "messages": api_messages,
                "temperature": temp,
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            # Use the sync streaming API wrapped in async
            with client.messages.stream(**kwargs) as stream:
                for text in stream.text_stream:
                    yield text
                    await asyncio.sleep(0)  # Yield control to event loop
        except Exception as e:
            logger.error(f"Claude stream error: {e}")
            yield f"Error: {e}"

    def test_connection(self) -> dict[str, Any]:
        """Test the Claude API connection."""
        try:
            client = self._get_client()
            client.messages.create(
                model=self._model,
                max_tokens=1,
                messages=[{"role": "user", "content": "test"}],
            )
            return {"status": "ok", "provider": self.name, "model": self._model}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}
