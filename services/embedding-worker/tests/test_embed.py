import pytest

from embedding_worker.embed import DENSE_SIZE, Embedder, EmbeddingUnavailableError


def test_embed_uses_injected_model(fake_embedding_model):
    subject = Embedder()
    subject._model = fake_embedding_model
    vector = subject.embed("new external peer beaconing from checkout")
    assert len(vector) == DENSE_SIZE
    assert vector[1] > 0


def test_embed_fails_closed_when_model_load_fails(monkeypatch):
    subject = Embedder()
    monkeypatch.setattr(subject, "_load_model", lambda: None)
    subject.last_error = "model missing"
    with pytest.raises(EmbeddingUnavailableError, match="model missing"):
        subject.embed("text")
