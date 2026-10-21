"""Text embedding backends SentenceTransformers (in-process) or Ollama HTTP."""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from black_onyx.config import EmbeddingConfig

logger = logging.getLogger(__name__)

DEFAULT_QUERY_INSTRUCT = (
    "Given a threat-intel search query, retrieve relevant passages that answer the query"
)
DEFAULT_RAG_QUERY_INSTRUCT = (
    "Given an analyst question, retrieve relevant evidence passages from the knowledge base"
)


def format_query(text: str, instruct: str) -> str:
    """Format Qwen3-style instruct-aware query text."""
    instruct = (instruct or "").strip()
    if not instruct:
        return text
    return f"Instruct: {instruct}\nQuery: {text}"


@runtime_checkable
class EmbeddingBackend(Protocol):
    """Common interface for text embedding backends."""

    @property
    def model_name(self) -> str: ...

    @property
    def is_loaded(self) -> bool: ...

    def encode(self, texts: list[str], batch_size: int = 32) -> list[list[float]]: ...

    def encode_single(self, text: str) -> list[float]: ...

    def get_embedding_dim(self) -> int: ...


class SentenceTransformerEmbedding:
    """Lazy-loaded SentenceTransformer text embedder."""

    def __init__(self, model_name: str = "all-mpnet-base-v2", device: str = "cpu") -> None:
        self._model_name = model_name
        self._device = device
        self._model: Any = None
        self._embedding_dim: int | None = None
        self._query_instruct = DEFAULT_QUERY_INSTRUCT
        self._rag_query_instruct = DEFAULT_RAG_QUERY_INSTRUCT

    @property
    def model(self) -> Any:
        if self._model is None:
            logger.info("Loading embedding model: %s on %s", self._model_name, self._device)
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self._model_name, device=self._device)
            logger.info("Embedding model loaded successfully")
        return self._model

    def encode(self, texts: list[str], batch_size: int = 32) -> list[list[float]]:
        if not texts:
            return []
        import numpy as np

        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        if isinstance(embeddings, np.ndarray):
            return embeddings.tolist()
        return [list(e) for e in embeddings]

    def encode_single(self, text: str) -> list[float]:
        result = self.encode([text])
        return result[0] if result else []

    def encode_document(self, text: str) -> list[float]:
        return self.encode_single(text)

    def encode_query(self, text: str, instruct: str | None = None) -> list[float]:
        formatted = format_query(text, instruct or self._query_instruct)
        return self.encode_single(formatted)

    def encode_rag_query(self, text: str) -> list[float]:
        return self.encode_query(text, self._rag_query_instruct)

    def encode_search_query(self, text: str) -> list[float]:
        return self.encode_query(text, self._query_instruct)

    def get_embedding_dim(self) -> int:
        if self._embedding_dim is None:
            vec = self.encode_single("test")
            self._embedding_dim = len(vec)
        return self._embedding_dim

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def backend(self) -> str:
        return "sentence_transformers"


class OllamaEmbedding:
    """Ollama HTTP embedding backend for Qwen3-Embedding-4B and similar models."""

    def __init__(
        self,
        model_name: str,
        ollama_base_url: str = "http://localhost:11434",
        dimensions: int | None = None,
        query_instruct: str = DEFAULT_QUERY_INSTRUCT,
        rag_query_instruct: str = DEFAULT_RAG_QUERY_INSTRUCT,
    ) -> None:
        from black_onyx.core.ollama_embed import OllamaEmbedClient

        self._query_instruct = query_instruct
        self._rag_query_instruct = rag_query_instruct
        self._client = OllamaEmbedClient(
            base_url=ollama_base_url,
            model_name=model_name,
            dimensions=dimensions,
        )

    def encode(self, texts: list[str], batch_size: int = 32) -> list[list[float]]:
        return self._client.encode(texts, batch_size=batch_size)

    def encode_single(self, text: str) -> list[float]:
        return self._client.encode_single(text)

    def encode_document(self, text: str) -> list[float]:
        return self.encode_single(text)

    def encode_query(self, text: str, instruct: str | None = None) -> list[float]:
        formatted = format_query(text, instruct or self._query_instruct)
        return self.encode_single(formatted)

    def encode_rag_query(self, text: str) -> list[float]:
        return self.encode_query(text, self._rag_query_instruct)

    def encode_search_query(self, text: str) -> list[float]:
        return self.encode_query(text, self._query_instruct)

    def get_embedding_dim(self) -> int:
        return self._client.get_embedding_dim()

    def test_connection(self) -> dict[str, Any]:
        return self._client.test_connection()

    @property
    def model_name(self) -> str:
        return self._client.model_name

    @property
    def is_loaded(self) -> bool:
        return self._client.is_loaded

    @property
    def backend(self) -> str:
        return "ollama"


def create_embedding_model(
    config: EmbeddingConfig,
    device: str = "cpu",
) -> SentenceTransformerEmbedding | OllamaEmbedding:
    """Factory: build the configured embedding backend."""
    if config.backend == "ollama":
        return OllamaEmbedding(
            model_name=config.model_name,
            ollama_base_url=config.ollama_base_url,
            dimensions=config.dimensions,
            query_instruct=config.query_instruct,
            rag_query_instruct=config.rag_query_instruct,
        )
    return SentenceTransformerEmbedding(
        model_name=config.model_name,
        device=device,
    )


# Backward-compatible alias
EmbeddingModel = SentenceTransformerEmbedding
