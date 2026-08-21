"""Google Gemini LLM provider — using the google-genai SDK."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider

logger = logging.getLogger(__name__)


class GeminiProvider(LLMProvider):
    """LLM provider using Google's Gemini API via the google-genai SDK.

    Uses the new google-genai package (NOT the deprecated google-generativeai).
    Vision images are sent via types.Part.from_bytes().
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "gemini-2.5-flash",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._default_temperature = temperature
        self._default_max_tokens = max_tokens
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-load the google-genai client."""
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self._api_key)
        return self._client

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def supports_images(self) -> bool:
        return True

    def _build_contents(
        self,
        messages: list[ChatMessage],
        system_prompt: str,
    ) -> list[Any]:
        """Build the Gemini contents list from chat messages.

        Gemini uses a different format: system instructions are passed
        separately, and messages are converted to a contents list.
        """
        from google.genai import types

        contents: list[Any] = []

        for msg in messages:
            if msg.images:
                # Build content with image parts and text
                parts: list[Any] = []
                for img in msg.images:
                    import os
                    import base64
                    if os.path.isfile(img):
                        with open(img, "rb") as f:
                            data = f.read()
                        import mimetypes
                        mime_type, _ = mimetypes.guess_type(img)
                        parts.append(types.Part.from_bytes(data=data, mime_type=mime_type or "image/png"))
                    else:
                        # Assume base64-encoded
                        data = base64.b64decode(img)
                        parts.append(types.Part.from_bytes(data=data, mime_type="image/png"))
                parts.append(msg.content)
                contents.append(parts)
            else:
                contents.append(msg.content)

        return contents

    def chat(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        """Send a non-streaming chat request to Gemini."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        try:
            from google.genai import types
            client = self._get_client()
            contents = self._build_contents(messages, system_prompt)

            config = types.GenerateContentConfig(
                temperature=temp,
                max_output_tokens=tokens,
            )
            if system_prompt:
                config.system_instruction = system_prompt

            response = client.models.generate_content(
                model=self._model,
                contents=contents,
                config=config,
            )
            text = response.text or ""
            return ChatResponse(text=text, model=self._model, raw=response)
        except Exception as e:
            logger.error(f"Gemini chat error: {e}")
            return ChatResponse(text=f"Error: {e}", model=self._model)

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Stream chat tokens from Gemini."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        try:
            from google.genai import types
            client = self._get_client()
            contents = self._build_contents(messages, system_prompt)

            config = types.GenerateContentConfig(
                temperature=temp,
                max_output_tokens=tokens,
            )
            if system_prompt:
                config.system_instruction = system_prompt

            for chunk in client.models.generate_content_stream(
                model=self._model,
                contents=contents,
                config=config,
            ):
                if chunk.text:
                    yield chunk.text
                await asyncio.sleep(0)
        except Exception as e:
            logger.error(f"Gemini stream error: {e}")
            yield f"Error: {e}"

    def test_connection(self) -> dict[str, Any]:
        """Test the Gemini API connection."""
        try:
            client = self._get_client()
            client.models.generate_content(
                model=self._model,
                contents="test",
            )
            return {"status": "ok", "provider": self.name, "model": self._model}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}
