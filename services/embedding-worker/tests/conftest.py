from __future__ import annotations

import pytest

from embedding_worker.embed import DENSE_SIZE, embedder


class FakeEmbeddingModel:
    """Small test-only stand-in for SentenceTransformer."""

    def encode(self, text: str, *, normalize_embeddings: bool) -> list[float]:
        assert normalize_embeddings is True
        value = min(len(text), 1000) / 1000.0
        return [1.0 - value, value, *([0.0] * (DENSE_SIZE - 2))]


@pytest.fixture
def fake_embedding_model(monkeypatch: pytest.MonkeyPatch) -> FakeEmbeddingModel:
    model = FakeEmbeddingModel()
    monkeypatch.setattr(embedder, "_model", model)
    monkeypatch.setattr(embedder, "_model_failed", False)
    monkeypatch.setattr(embedder, "last_error", None)
    return model
