"""Tests for OpenAI-compatible provider reasoning stream support."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from black_onyx.llm.base import ChatMessage
from black_onyx.llm.providers.openai_compat import OpenAICompatibleProvider, _delta_reasoning


class TestDeltaReasoning:
    def test_reads_reasoning_attr(self):
        delta = SimpleNamespace(reasoning="think step", content=None)
        assert _delta_reasoning(delta) == "think step"

    def test_reads_reasoning_content_attr(self):
        delta = SimpleNamespace(reasoning_content="alt field", content=None)
        assert _delta_reasoning(delta) == "alt field"


class TestOpenAICompatibleStream:
    @pytest.mark.asyncio
    async def test_yields_reasoning_and_content(self):
        chunk_reason = SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace(reasoning="plan", content=None))],
        )
        chunk_token = SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace(reasoning=None, content="Hello"))],
        )

        mock_stream = iter([chunk_reason, chunk_token])
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_stream

        provider = OpenAICompatibleProvider(base_url="http://127.0.0.1:8000/v1")
        with patch.object(provider, "_get_client", return_value=mock_client):
            parts = []
            async for part in provider.chat_stream(
                messages=[ChatMessage(role="user", content="hi")],
            ):
                parts.append(part)

        assert ("reasoning", "plan") in parts
        assert ("content", "Hello") in parts
