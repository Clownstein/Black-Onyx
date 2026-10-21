"""Tests for the LLM provider abstraction and chat sessions."""

import pytest

from black_onyx.llm.base import ChatMessage, ChatResponse
from black_onyx.llm.factory import create_provider, describe_llm_providers, list_available_providers
from black_onyx.llm.session import ChatSessionManager


class TestChatMessage:
    def test_creation(self):
        msg = ChatMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"
        assert msg.images is None

    def test_with_images(self):
        msg = ChatMessage(role="user", content="What's in this image?", images=["/path/to/img.png"])
        assert msg.images == ["/path/to/img.png"]

    def test_to_dict(self):
        msg = ChatMessage(role="assistant", content="Response")
        d = msg.to_dict()
        assert d["role"] == "assistant"
        assert d["content"] == "Response"


class TestChatResponse:
    def test_creation(self):
        resp = ChatResponse(text="Hello!", model="test-model")
        assert resp.text == "Hello!"
        assert resp.model == "test-model"


class TestProviderFactory:
    def test_list_providers(self):
        providers = list_available_providers()
        assert "local" in providers
        assert "openai" in providers
        assert "openai_compatible" in providers
        assert "claude" in providers
        assert "gemini" in providers
        assert "openrouter" in providers
        assert "llama_cpp" not in providers

    def test_describe_providers_black_onyx_label(self):
        from black_onyx.config import LLMConfig, OpenAICompatibleConfig

        payload = describe_llm_providers(
            LLMConfig(
                provider="openai_compatible",
                openai_compatible=OpenAICompatibleConfig(
                    model="black-onyx-5b",
                    display_name="Black Onyx 5B",
                ),
            )
        )
        assert payload["active"] == "openai_compatible"
        assert payload["details"]["openai_compatible"]["label"] == "Black Onyx 5B"
        assert payload["details"]["openai_compatible"]["model"] == "black-onyx-5b"

    def test_migrate_openai_host_from_compatible(self):
        from black_onyx.config import LLMConfig, OpenAICompatibleConfig
        from black_onyx.llm.factory import migrate_openai_provider_settings
        config = LLMConfig(
            provider="openai_compatible",
            openai_compatible=OpenAICompatibleConfig(
                base_url="https://api.openai.com/v1",
                model="gpt-4o-mini",
            ),
        )
        assert migrate_openai_provider_settings(config) is True
        assert config.provider == "openai"
        assert config.openai.model == "gpt-4o-mini"
        assert "localhost" in config.openai_compatible.base_url

    def test_compatible_rejects_openai_host(self):
        from black_onyx.llm.providers.openai_compat import OpenAICompatibleProvider
        with pytest.raises(ValueError, match="Responses API"):
            OpenAICompatibleProvider(base_url="https://api.openai.com/v1")

    def test_create_openrouter_provider(self):
        from black_onyx.config import LLMConfig, OpenRouterConfig
        from black_onyx.llm.providers.openai_compat import OpenAICompatibleProvider

        config = LLMConfig(
            openrouter=OpenRouterConfig(
                model="openai/gpt-4o-mini",
                site_url="https://sec.dw.style",
                app_name="Black Onyx",
            ),
        )
        provider = create_provider(
            "openrouter",
            config,
            api_keys={"OPENROUTER_API_KEY": "sk-or-test"},
        )
        assert isinstance(provider, OpenAICompatibleProvider)
        assert provider.name == "openrouter"
        assert provider._model == "openai/gpt-4o-mini"
        assert provider._base_url == "https://openrouter.ai/api/v1"
        assert provider._extra_headers["X-Title"] == "Black Onyx"
        assert provider._extra_headers["HTTP-Referer"] == "https://sec.dw.style"

    def test_describe_providers_includes_openrouter(self):
        from black_onyx.config import LLMConfig, OpenRouterConfig

        payload = describe_llm_providers(
            LLMConfig(
                provider="openrouter",
                openrouter=OpenRouterConfig(model="anthropic/claude-sonnet-4.5"),
            )
        )
        assert payload["active"] == "openrouter"
        assert payload["details"]["openrouter"]["label"] == "OpenRouter — anthropic/claude-sonnet-4.5"
        assert payload["details"]["openrouter"]["model"] == "anthropic/claude-sonnet-4.5"

    def test_create_ollama_provider(self):
        from black_onyx.config import LLMConfig
        config = LLMConfig()
        provider = create_provider("local", config)
        assert provider.name == "ollama"
        assert provider.supports_images is True

    def test_create_unknown_provider(self):
        from black_onyx.config import LLMConfig
        config = LLMConfig()
        with pytest.raises(ValueError):
            create_provider("unknown_provider", config)

    def test_embedded_llama_cpp_provider_is_not_advertised(self):
        from black_onyx.config import LLMConfig

        with pytest.raises(ValueError, match="Unknown LLM provider type"):
            create_provider("llama_cpp", LLMConfig())


class TestChatSessionManager:
    def test_in_memory_sessions(self):
        mgr = ChatSessionManager(persist_dir=None)
        session_id = mgr.create_session(title="Test")
        assert session_id is not None

        mgr.add_message(session_id, "user", "Hello")
        mgr.add_message(session_id, "assistant", "Hi there!")

        messages = mgr.get_messages(session_id)
        assert len(messages) == 2
        assert messages[0].role == "user"
        assert messages[0].content == "Hello"
        assert messages[1].role == "assistant"

    def test_list_sessions(self):
        mgr = ChatSessionManager(persist_dir=None)
        mgr.create_session(title="Session 1")
        mgr.create_session(title="Session 2")
        sessions = mgr.list_sessions()
        assert len(sessions) == 2

    def test_delete_session(self):
        mgr = ChatSessionManager(persist_dir=None)
        session_id = mgr.create_session(title="To Delete")
        mgr.add_message(session_id, "user", "test")
        mgr.delete_session(session_id)
        messages = mgr.get_messages(session_id)
        assert len(messages) == 0

    def test_persistent_sessions(self, tmp_path):
        mgr1 = ChatSessionManager(persist_dir=str(tmp_path / "sessions"))
        session_id = mgr1.create_session(title="Persistent")
        mgr1.add_message(session_id, "user", "Hello")
        mgr1.add_message(session_id, "assistant", "Hi there")
        mgr1.close()

        # Create a new manager pointing to the same directory
        mgr2 = ChatSessionManager(persist_dir=str(tmp_path / "sessions"))
        messages = mgr2.get_messages(session_id)
        assert len(messages) == 2
        assert messages[0].content == "Hello"
        assert messages[1].role == "assistant"
        mgr2.close()
