"""SecureBERT embeddings backed only by the configured real model."""

from __future__ import annotations

import logging

from embedding_worker.config import settings

logger = logging.getLogger(__name__)

DENSE_SIZE = 768


class EmbeddingUnavailableError(RuntimeError):
    """Raised when the configured real embedding model cannot serve."""


class Embedder:
    """Lazily load SecureBERT and fail honestly when it is unavailable."""

    def __init__(self) -> None:
        self._model = None
        self._model_failed = False
        self.last_error: str | None = None

    def _load_model(self):
        if self._model is not None or self._model_failed:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(settings.embed_model)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SecureBERT unavailable: %s", exc)
            self._model_failed = True
            self._model = None
            self.last_error = str(exc)
        return self._model

    def embed(self, text: str) -> list[float]:
        text = text or ""
        model = self._load_model()
        if model is None:
            raise EmbeddingUnavailableError(
                self.last_error or "embedding model is unavailable"
            )
        vector = model.encode(text, normalize_embeddings=True)
        return [float(x) for x in list(vector)]

    def available(self) -> bool:
        """Return whether the configured model can be loaded."""

        return self._load_model() is not None


embedder = Embedder()
