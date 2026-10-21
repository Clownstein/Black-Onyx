"""Tests for embedding backends (Ollama mock + instruct formatting)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from black_onyx.config import EmbeddingConfig
from black_onyx.core.embeddings import (
    OllamaEmbedding,
    SentenceTransformerEmbedding,
    create_embedding_model,
    format_query,
)


class TestFormatQuery:
    def test_instruct_prefix(self):
        text = format_query("Cobalt Strike C2", "Given a threat-intel search query")
        assert text.startswith("Instruct: Given a threat-intel search query\nQuery: ")
        assert "Cobalt Strike C2" in text

    def test_empty_instruct_returns_plain(self):
        assert format_query("hello", "") == "hello"


class TestOllamaEmbedding:
    @patch("black_onyx.core.ollama_embed.httpx.Client")
    def test_encode_batch(self, mock_client_cls: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "embeddings": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
        }
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        embedder = OllamaEmbedding(
            model_name="test-model",
            ollama_base_url="http://localhost:11434",
            dimensions=3,
        )
        vectors = embedder.encode(["doc one", "doc two"])
        assert len(vectors) == 2
        assert vectors[0] == [0.1, 0.2, 0.3]

    @patch("black_onyx.core.ollama_embed.time.sleep")
    @patch("black_onyx.core.ollama_embed.httpx.Client")
    def test_retries_on_transient_failure(self, mock_client_cls: MagicMock, mock_sleep: MagicMock) -> None:
        import httpx

        mock_response = MagicMock()
        mock_response.json.return_value = {"embeddings": [[1.0, 2.0]]}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.side_effect = [
            httpx.ConnectError("connection refused"),
            mock_response,
        ]
        mock_client_cls.return_value = mock_client

        from black_onyx.core.ollama_embed import OllamaEmbedClient

        client = OllamaEmbedClient(model_name="test-model", dimensions=2)
        vec = client.encode_single("hello")
        assert vec == [1.0, 2.0]
        assert mock_client.post.call_count == 2
        mock_sleep.assert_called_once()

    @patch("black_onyx.core.ollama_embed.httpx.Client")
    def test_encode_search_query_uses_instruct(self, mock_client_cls: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"embeddings": [[1.0, 2.0]]}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        embedder = OllamaEmbedding(
            model_name="test-model",
            query_instruct="search task",
        )
        embedder.encode_search_query("beaconing")
        call_payload = mock_client.post.call_args.kwargs["json"]
        assert call_payload["input"].startswith("Instruct: search task\nQuery: beaconing")

    @patch("black_onyx.core.ollama_embed.httpx.Client")
    def test_encode_document_plain(self, mock_client_cls: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"embeddings": [[1.0]]}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        embedder = OllamaEmbedding(model_name="test-model")
        embedder.encode_document("plain chunk text")
        call_payload = mock_client.post.call_args.kwargs["json"]
        assert call_payload["input"] == "plain chunk text"


class TestCreateEmbeddingModel:
    def test_sentence_transformers_default(self):
        config = EmbeddingConfig()
        model = create_embedding_model(config, device="cpu")
        assert isinstance(model, SentenceTransformerEmbedding)

    def test_ollama_backend(self):
        config = EmbeddingConfig(
            backend="ollama",
            model_name="dengcao/Qwen3-Embedding-4B:Q4_K_M",
            dimensions=2560,
        )
        model = create_embedding_model(config, device="cpu")
        assert isinstance(model, OllamaEmbedding)
