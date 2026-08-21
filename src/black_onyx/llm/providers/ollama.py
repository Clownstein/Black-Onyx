"""Ollama LLM provider — local model via Ollama REST API."""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

import httpx

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """LLM provider using Ollama's REST API.

    Calls POST /api/chat for completions and GET /api/tags for model listing.
    Streaming uses newline-delimited JSON (NDJSON).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._default_temperature = temperature
        self._default_max_tokens = max_tokens

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def supports_images(self) -> bool:
        return True  # Ollama supports vision models (llava, etc.)

    def _build_request(
        self,
        messages: list[ChatMessage],
        system_prompt: str,
        temperature: float,
        max_tokens: int,
        stream: bool,
    ) -> dict[str, Any]:
        """Build the Ollama API request body."""
        api_messages: list[dict[str, Any]] = []

        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})

        for msg in messages:
            api_msg: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.images:
                # Encode images to base64
                encoded_images = []
                for img in msg.images:
                    b64, _ = self.encode_image_to_base64(img)
                    encoded_images.append(b64)
                api_msg["images"] = encoded_images
            api_messages.append(api_msg)

        return {
            "model": self._model,
            "messages": api_messages,
            "stream": stream,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

    def chat(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        """Send a non-streaming chat request to Ollama."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        body = self._build_request(messages, system_prompt, temp, tokens, stream=False)

        try:
            with httpx.Client(timeout=120.0) as client:
                resp = client.post(f"{self._base_url}/api/chat", json=body)
                resp.raise_for_status()
                data = resp.json()

            text = data.get("message", {}).get("content", "")
            usage = {
                "prompt_eval_count": data.get("prompt_eval_count", 0),
                "eval_count": data.get("eval_count", 0),
                "total_duration": data.get("total_duration", 0),
            }
            return ChatResponse(text=text, model=self._model, usage=usage, raw=data)
        except Exception as e:
            logger.error(f"Ollama chat error: {e}")
            return ChatResponse(text=f"Error: {e}", model=self._model)

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Stream chat tokens from Ollama via NDJSON."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        body = self._build_request(messages, system_prompt, temp, tokens, stream=True)

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream("POST", f"{self._base_url}/api/chat", json=body) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            content = data.get("message", {}).get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Ollama stream error: {e}")
            yield f"Error: {e}"

    def test_connection(self) -> dict[str, Any]:
        """Test Ollama connection by listing models."""
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                return {"status": "ok", "provider": self.name, "models": model_names}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}

    def list_models(self) -> list[str]:
        """List available Ollama models."""
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
                models = resp.json().get("models", [])
                return [m.get("name", "") for m in models]
        except Exception:
            return []
