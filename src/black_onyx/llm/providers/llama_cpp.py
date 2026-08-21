"""llama.cpp LLM provider — local model via llama-cpp-python."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider

logger = logging.getLogger(__name__)


class LlamaCppProvider(LLMProvider):
    """LLM provider using llama-cpp-python for local GGUF models.

    Loads a .gguf model file and runs inference locally. Supports GPU
    offloading via n_gpu_layers.
    """

    def __init__(
        self,
        model_path: str = "",
        n_ctx: int = 4096,
        n_gpu_layers: int = 0,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> None:
        self._model_path = model_path
        self._n_ctx = n_ctx
        self._n_gpu_layers = n_gpu_layers
        self._default_temperature = temperature
        self._default_max_tokens = max_tokens
        self._llm: Any = None

    def _get_llm(self) -> Any:
        """Lazy-load the llama.cpp model."""
        if self._llm is None:
            if not self._model_path:
                raise ValueError("llama_cpp model_path is not configured")
            from llama_cpp import Llama
            logger.info(f"Loading llama.cpp model: {self._model_path}")
            self._llm = Llama(
                model_path=self._model_path,
                n_ctx=self._n_ctx,
                n_gpu_layers=self._n_gpu_layers,
                verbose=False,
            )
            logger.info("llama.cpp model loaded")
        return self._llm

    @property
    def name(self) -> str:
        return "llama_cpp"

    @property
    def supports_images(self) -> bool:
        return False  # Standard llama.cpp doesn't support vision

    def _build_messages(
        self,
        messages: list[ChatMessage],
        system_prompt: str,
    ) -> list[dict[str, str]]:
        """Build the messages array for llama.cpp's chat API."""
        api_messages: list[dict[str, str]] = []
        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})
        for msg in messages:
            api_messages.append({"role": msg.role, "content": msg.content})
        return api_messages

    def chat(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        """Send a non-streaming chat request to llama.cpp."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        try:
            llm = self._get_llm()
            api_messages = self._build_messages(messages, system_prompt)
            response = llm.create_chat_completion(
                messages=api_messages,
                temperature=temp,
                max_tokens=tokens,
            )
            text = response["choices"][0]["message"]["content"]
            usage = response.get("usage", {})
            return ChatResponse(text=text, model="llama-cpp", usage=usage, raw=response)
        except Exception as e:
            logger.error(f"llama.cpp chat error: {e}")
            return ChatResponse(text=f"Error: {e}", model="llama-cpp")

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Stream chat tokens from llama.cpp."""
        temp = temperature if temperature is not None else self._default_temperature
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        try:
            llm = self._get_llm()
            api_messages = self._build_messages(messages, system_prompt)
            stream = llm.create_chat_completion(
                messages=api_messages,
                temperature=temp,
                max_tokens=tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk["choices"][0].get("delta", {})
                content = delta.get("content", "")
                if content:
                    yield content
                await asyncio.sleep(0)
        except Exception as e:
            logger.error(f"llama.cpp stream error: {e}")
            yield f"Error: {e}"

    def test_connection(self) -> dict[str, Any]:
        """Test the llama.cpp model loading."""
        try:
            self._get_llm()
            return {"status": "ok", "provider": self.name, "model_path": self._model_path}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}
