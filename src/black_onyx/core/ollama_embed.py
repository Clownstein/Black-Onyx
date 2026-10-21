"""Ollama embedding client POST /api/embed for Qwen3 and other embed models."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
HEALTH_TIMEOUT = 10.0
MAX_RETRIES = 3
RETRY_BACKOFF_S = 0.5


class OllamaEmbedClient:
    """HTTP client for Ollama's embedding API."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_name: str = "hf.co/Qwen/Qwen3-Embedding-4B-GGUF:Q4_K_M",
        dimensions: int | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model_name = model_name
        self._dimensions = dimensions
        self._timeout = timeout
        self._embedding_dim: int | None = dimensions

    @property
    def model_name(self) -> str:
        return self._model_name

    def _embed_url(self) -> str:
        return f"{self._base_url}/api/embed"

    def _build_payload(self, texts: list[str]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model_name,
            "input": texts if len(texts) > 1 else texts[0],
        }
        if self._dimensions is not None:
            payload["dimensions"] = self._dimensions
        return payload

    def encode(self, texts: list[str], batch_size: int = 32) -> list[list[float]]:
        """Encode texts via Ollama embed API, batching large lists."""
        if not texts:
            return []
        all_embeddings: list[list[float]] = []
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            all_embeddings.extend(self._embed_batch(batch))
        return all_embeddings

    def _embed_batch(self, texts: list[str]) -> list[list[float]]:
        payload = self._build_payload(texts)
        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.post(self._embed_url(), json=payload)
                    response.raise_for_status()
                    data = response.json()
                break
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt + 1 >= MAX_RETRIES:
                    logger.error("Ollama embed request failed after %s attempts: %s", MAX_RETRIES, exc)
                    raise RuntimeError(f"Ollama embed failed: {exc}") from exc
                sleep_s = RETRY_BACKOFF_S * (2**attempt)
                logger.warning(
                    "Ollama embed attempt %s/%s failed; retrying in %.1fs: %s",
                    attempt + 1,
                    MAX_RETRIES,
                    sleep_s,
                    exc,
                )
                time.sleep(sleep_s)
        else:
            raise RuntimeError(f"Ollama embed failed: {last_exc}") from last_exc

        embeddings = data.get("embeddings")
        if embeddings is None and "embedding" in data:
            embeddings = [data["embedding"]]
        if not embeddings:
            raise RuntimeError("Ollama embed response missing embeddings")

        if len(embeddings) != len(texts):
            raise RuntimeError(
                f"Ollama returned {len(embeddings)} embeddings for {len(texts)} inputs"
            )

        result = [[float(v) for v in vec] for vec in embeddings]
        if self._embedding_dim is None and result:
            self._embedding_dim = len(result[0])
        return result

    def encode_single(self, text: str) -> list[float]:
        vectors = self.encode([text])
        return vectors[0] if vectors else []

    def get_embedding_dim(self) -> int:
        if self._embedding_dim is not None:
            return self._embedding_dim
        vec = self.encode_single("test")
        if not vec:
            raise RuntimeError("Failed to probe Ollama embedding dimension")
        self._embedding_dim = len(vec)
        return self._embedding_dim

    def test_connection(self) -> dict[str, Any]:
        """Probe Ollama embed endpoint readiness."""
        try:
            dim = self.get_embedding_dim()
            return {
                "status": "ok",
                "backend": "ollama",
                "model": self._model_name,
                "dimensions": dim,
            }
        except Exception as exc:
            return {
                "status": "error",
                "backend": "ollama",
                "model": self._model_name,
                "error": str(exc),
            }

    @property
    def is_loaded(self) -> bool:
        return True
