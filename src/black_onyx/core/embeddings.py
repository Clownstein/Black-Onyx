"""Embedding model wrapper — lazy-loaded SentenceTransformer."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class EmbeddingModel:
    """Lazy-loaded text embedding model using SentenceTransformer.

    The model is not loaded until first use, allowing the application
    to start quickly and only load the model when needed.
    """

    def __init__(self, model_name: str = "all-mpnet-base-v2", device: str = "cpu") -> None:
        """Store configuration without loading the model.

        Args:
            model_name: HuggingFace model name for SentenceTransformer.
            device: Torch device string ('cuda', 'cpu', 'mps').
        """
        self._model_name = model_name
        self._device = device
        self._model: Any = None
        self._embedding_dim: int | None = None

    @property
    def model(self) -> Any:
        """Lazy-load the SentenceTransformer model on first access."""
        if self._model is None:
            logger.info(f"Loading embedding model: {self._model_name} on {self._device}")
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name, device=self._device)
            logger.info("Embedding model loaded successfully")
        return self._model

    def encode(self, texts: list[str], batch_size: int = 32) -> list[list[float]]:
        """Encode a list of texts into embedding vectors.

        Args:
            texts: List of text strings to embed.
            batch_size: Batch size for encoding.

        Returns:
            List of embedding vectors (each a list of floats).
        """
        if not texts:
            return []
        import numpy as np
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        # Convert numpy.ndarray to list[list[float]] for Qdrant compatibility
        if isinstance(embeddings, np.ndarray):
            return embeddings.tolist()
        # Fallback: if it's already a list of tensors or lists
        return [list(e) for e in embeddings]

    def encode_single(self, text: str) -> list[float]:
        """Encode a single text string into an embedding vector.

        Args:
            text: Text string to embed.

        Returns:
            Embedding vector as a list of floats.
        """
        result = self.encode([text])
        return result[0] if result else []

    def get_embedding_dim(self) -> int:
        """Get the embedding dimension (loads model if needed).

        Returns:
            Integer embedding dimension.
        """
        if self._embedding_dim is None:
            # Encode a short test string to determine dimension
            vec = self.encode_single("test")
            self._embedding_dim = len(vec)
        return self._embedding_dim

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def is_loaded(self) -> bool:
        return self._model is not None
