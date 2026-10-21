"""Tests for configuration and device detection."""

from pathlib import Path

from black_onyx.config import SecurityConfig, Settings


class TestAllowsOrigin:
    """Origin rejection surfaced on POST /auth/login as a bare 403 that looked
    exactly like a broken sign-in, so both dev footguns below are regressions
    worth pinning: loopback spelling, and the Vite dev server's own port."""

    def test_dev_accepts_every_loopback_spelling(self):
        for named in ("http://127.0.0.1:8100", "http://localhost:8100"):
            config = SecurityConfig(external_url=named)
            for origin in ("http://127.0.0.1:8100", "http://localhost:8100", "http://[::1]:8100"):
                assert config.allows_origin(origin), f"{named} should allow {origin}"

    def test_dev_accepts_the_vite_dev_server_port(self):
        """`npm run dev` proxies /api through its own port, so the browser
        origin is never the API's own origin."""
        config = SecurityConfig(external_url="http://127.0.0.1:8100")
        assert config.allows_origin("http://localhost:5173")
        assert config.allows_origin("http://127.0.0.1:5199")

    def test_dev_still_rejects_remote_origins(self):
        """The dev allowance is loopback-only, not open season."""
        config = SecurityConfig(external_url="http://127.0.0.1:8100")
        assert not config.allows_origin("https://evil.example.com")
        assert not config.allows_origin("http://192.168.1.5:5173")
        assert not config.allows_origin(None)
        assert not config.allows_origin("")

    def test_explicit_allowed_origins_are_kept(self):
        config = SecurityConfig(
            external_url="http://127.0.0.1:8100",
            allowed_origins=["http://192.168.1.5:5173"],
        )
        assert config.allows_origin("http://192.168.1.5:5173")

    def test_production_is_exact_match_only(self):
        real_host = SecurityConfig(
            external_url="https://tip.example.com", production=True, secure_cookies=True,
        )
        assert real_host.allows_origin("https://tip.example.com")
        assert not real_host.allows_origin("https://www.tip.example.com")
        assert not real_host.allows_origin("http://localhost:5173")

        loopback = SecurityConfig(
            external_url="https://127.0.0.1:8100", production=True, secure_cookies=True,
        )
        assert loopback.allows_origin("https://127.0.0.1:8100")
        assert not loopback.allows_origin("https://localhost:8100")
        assert not loopback.allows_origin("https://127.0.0.1:5173")


class TestConfig:
    def test_default_settings(self, monkeypatch, tmp_path):
        """Test that default settings load correctly."""
        # Settings has a relative yaml_file source. Keep this library-default
        # assertion independent of an operator's checked-out config.yaml.
        monkeypatch.chdir(tmp_path)
        # Compose injects QDRANT_QDRANT__HOST=qdrant; clear so defaults are real defaults.
        monkeypatch.delenv("QDRANT_QDRANT__HOST", raising=False)
        monkeypatch.delenv("QDRANT_QDRANT__PORT", raising=False)
        from black_onyx.config import get_settings
        get_settings.cache_clear()
        settings = Settings()
        assert settings.qdrant.host == "localhost"
        assert settings.qdrant.port == 6333
        assert settings.embedding.model_name == "all-mpnet-base-v2"
        assert settings.embedding.backend == "sentence_transformers"
        assert settings.embedding.dimensions is None
        assert settings.chunking.chunk_size == 2048
        assert settings.chunking.chunk_overlap == 200
        assert settings.llm.provider == "local"
        get_settings.cache_clear()

    def test_yaml_config_loading(self, tmp_path: Path, monkeypatch):
        """Test loading configuration from a YAML file."""
        monkeypatch.delenv("QDRANT_QDRANT__HOST", raising=False)
        monkeypatch.delenv("QDRANT_QDRANT__PORT", raising=False)
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text("""
qdrant:
  host: "remote-host"
  port: 7333
embedding:
  model_name: "custom-model"
chunking:
  chunk_size: 1024
""")
        from black_onyx.config import get_settings
        get_settings.cache_clear()
        settings = get_settings(config_path=str(config_file))
        assert settings.qdrant.host == "remote-host"
        assert settings.qdrant.port == 7333
        assert settings.embedding.model_name == "custom-model"
        assert settings.chunking.chunk_size == 1024
        # Clear cache for other tests
        get_settings.cache_clear()

    def test_ollama_embedding_yaml(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("QDRANT_QDRANT__HOST", raising=False)
        config_file = tmp_path / "ollama_config.yaml"
        config_file.write_text("""
embedding:
  backend: ollama
  model_name: "dengcao/Qwen3-Embedding-4B:Q4_K_M"
  ollama_base_url: "http://127.0.0.1:11434"
  dimensions: 2560
""")
        from black_onyx.config import get_settings
        get_settings.cache_clear()
        settings = get_settings(config_path=str(config_file))
        assert settings.embedding.backend == "ollama"
        assert settings.embedding.dimensions == 2560
        assert settings.embedding.ollama_base_url == "http://127.0.0.1:11434"
        get_settings.cache_clear()

    def test_env_var_override(self, monkeypatch):
        """Test environment variable overrides."""
        monkeypatch.setenv("QDRANT_QDRANT__HOST", "env-host")
        monkeypatch.setenv("QDRANT_QDRANT__PORT", "9999")
        from black_onyx.config import get_settings
        get_settings.cache_clear()
        settings = get_settings()
        assert settings.qdrant.host == "env-host"
        assert settings.qdrant.port == 9999
        get_settings.cache_clear()
        monkeypatch.undo()

    def test_secret_str(self):
        """Test that API keys are stored as SecretStr."""
        from black_onyx.config import QdrantConfig
        # Test the model default independently of the developer's ignored .env.
        assert QdrantConfig().api_key is None

    def test_resolve_device(self):
        """Test device resolution."""
        settings = Settings()
        # 'auto' should resolve to an actual device
        device = settings.resolve_device("auto")
        assert device in ("cuda", "mps", "cpu")
        # Non-auto should return as-is
        assert settings.resolve_device("cpu") == "cpu"


class TestDeviceDetection:
    def test_get_device(self):
        """Test device detection returns a valid device string."""
        from black_onyx.core.device import get_device
        device = get_device()
        assert device in ("cuda", "mps", "cpu")

    def test_get_device_caching(self):
        """Test that device detection is cached."""
        from black_onyx.core.device import get_device
        d1 = get_device()
        d2 = get_device()
        assert d1 == d2

    def test_get_device_info(self):
        """Test device info dict."""
        from black_onyx.core.device import get_device_info
        info = get_device_info()
        assert "device" in info
        assert info["device"] in ("cuda", "mps", "cpu")


class TestClassifierFlagSync:
    def test_enable_classifier_mirrors_classifier_enabled(self):
        settings = Settings(
            ingestion={"enable_classifier": True},
            classifier={"enabled": False, "model_name": "demo"},
        )
        assert settings.classifier.enabled is True
        assert settings.ingestion.enable_classifier is True

    def test_classifier_enabled_mirrors_ingest_flag(self):
        settings = Settings(
            ingestion={"enable_classifier": False},
            classifier={"enabled": True, "model_name": "demo"},
        )
        assert settings.ingestion.enable_classifier is True
        assert settings.classifier.enabled is True
