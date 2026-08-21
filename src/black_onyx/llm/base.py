"""LLM provider abstraction — base classes, data structures, and common types."""

from __future__ import annotations

import base64
import logging
import mimetypes
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """A single message in a chat conversation.

    Attributes:
        role: Message role — "system", "user", or "assistant".
        content: Text content of the message.
        images: Optional list of image file paths or base64-encoded strings.
    """

    role: str
    content: str
    images: Optional[list[str]] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict for JSON serialization."""
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.images:
            d["images"] = self.images
        return d


@dataclass
class ChatResponse:
    """Response from a chat completion.

    Attributes:
        text: The full response text.
        model: Model name that generated the response.
        usage: Usage statistics dict (e.g. {"prompt_tokens": 100, "completion_tokens": 50}).
        raw: Raw response object from the provider SDK.
    """

    text: str
    model: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    raw: Any = None


@dataclass
class RetrievedChunk:
    """A retrieved chunk from RAG search.

    Attributes:
        id: Point ID in Qdrant.
        score: Similarity score.
        payload: Qdrant payload dict.
        collection: Source collection name.
    """

    id: Any
    score: float
    payload: dict[str, Any]
    collection: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict for JSON serialization."""
        return {
            "id": str(self.id),
            "score": self.score,
            "payload": self.payload,
            "collection": self.collection,
        }


class LLMProvider(ABC):
    """Abstract base class for LLM providers.

    All providers must implement chat() and chat_stream() methods.
    Providers that support vision/image input should set supports_images=True.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g. 'ollama', 'claude', 'gemini')."""

    @property
    @abstractmethod
    def supports_images(self) -> bool:
        """Whether this provider supports image input."""

    @abstractmethod
    def chat(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        """Send a chat completion request (non-streaming).

        Args:
            messages: List of ChatMessage objects.
            system_prompt: System prompt (handled differently per provider).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            ChatResponse with the full response text.
        """

    @abstractmethod
    def chat_stream(
        self,
        messages: list[ChatMessage],
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Send a chat completion request with streaming.

        Args:
            messages: List of ChatMessage objects.
            system_prompt: System prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.

        Yields:
            Text chunks as they are generated.
        """

    def test_connection(self) -> dict[str, Any]:
        """Test the provider connection.

        Returns:
            Dict with "status" ("ok" or "error") and optional "error" message.
        """
        return {"status": "ok", "provider": self.name}

    @staticmethod
    def encode_image_to_base64(image_path_or_data: str) -> tuple[str, str]:
        """Encode an image to base64 with media type detection.

        Args:
            image_path_or_data: File path or base64-encoded string.

        Returns:
            Tuple of (base64_data, media_type).
        """
        # If it's already base64, return as-is
        try:
            import os
            if os.path.isfile(image_path_or_data):
                with open(image_path_or_data, "rb") as f:
                    data = f.read()
                b64 = base64.b64encode(data).decode("utf-8")
                mime_type, _ = mimetypes.guess_type(image_path_or_data)
                media_type = mime_type or "image/png"
                return b64, media_type
        except OSError as exc:
            logger.debug("Image path could not be read: %s", type(exc).__name__)

        # Assume it's already base64-encoded
        return image_path_or_data, "image/png"
