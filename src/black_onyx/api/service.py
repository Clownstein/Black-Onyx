"""Service layer — shared application state and component management."""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Optional

from black_onyx.config import Settings, get_settings
from black_onyx.core.device import get_device_info
from black_onyx.auth.database import StateDatabase
from black_onyx.runtime_settings import RuntimeSettingsStore, apply_secret_environment, deep_merge

logger = logging.getLogger(__name__)


class AppService:
    """Singleton service holding shared application state.

    Lazily initializes all components (embedding model, NER, classifier,
    Qdrant store, OCR, CLIP, LLM provider, RAG engine, chat sessions).
    Components are created on first access to keep startup fast.
    """

    _instance: Optional["AppService"] = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls) -> "AppService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._base_settings: Settings = get_settings()
        self._deployment_secret_environment = {
            name: os.environ.get(name) for name in (
                self._base_settings.llm.openai.api_key_env,
                self._base_settings.llm.openai_compatible.api_key_env,
                self._base_settings.llm.claude.api_key_env,
                self._base_settings.llm.gemini.api_key_env,
                self._base_settings.web_search.firecrawl_api_key_env,
            )
        }
        self._settings_store = RuntimeSettingsStore(
            StateDatabase(self._base_settings.storage.state_dir), self._base_settings.security
        )
        runtime_config, runtime_secrets = self._settings_store.load()
        self._settings: Settings = Settings(**deep_merge(
            self._base_settings.model_dump(mode="python"), runtime_config
        ))
        from black_onyx.llm.factory import migrate_openai_provider_settings
        if migrate_openai_provider_settings(self._settings.llm):
            try:
                self._settings_store.save(
                    {"llm": self._settings.llm.model_dump(mode="python")},
                    runtime_secrets,
                )
            except Exception:
                logger.exception("Failed to persist migrated OpenAI provider settings")
        apply_secret_environment(self._settings, runtime_secrets, self._deployment_secret_environment)
        self._embedding_model: Any = None
        self._ner_model: Any = None
        self._classifier: Any = None
        self._qdrant_store: Any = None
        self._ocr_engine: Any = None
        self._clip_model: Any = None
        self._llm_providers: dict[str, Any] = {}
        self._rag_engines: dict[str, Any] = {}
        self._session_manager: Any = None
        self._ingestor: Any = None
        self._enrichment_manager: Any = None
        self._attack_mapper: Any = None
        self._case_manager: Any = None
        self._watchlist_manager: Any = None
        self._asset_manager: Any = None
        self._detection_rules_manager: Any = None
        self._annotation_manager: Any = None
        self._decay_manager: Any = None
        self._site_credential_store: Any = None
        self._report_generator: Any = None
        self._feed_manager: Any = None
        self._connector_manager: Any = None
        self._webhook_manager: Any = None
        self._misp_manager: Any = None
        self._taxii_manager: Any = None
        self._playbook_manager: Any = None
        self._playbook_runner: Any = None
        self._active_jobs: dict[str, dict[str, Any]] = {}
        self._initialized = True

    @property
    def settings(self) -> Settings:
        return self._settings

    def reload_settings(self, config_path: str | None = None) -> None:
        """Reload settings from a config file."""
        get_settings.cache_clear()
        self._base_settings = get_settings(config_path=config_path)
        runtime_config, runtime_secrets = self._settings_store.load()
        self._settings = Settings(**deep_merge(
            self._base_settings.model_dump(mode="python"), runtime_config
        ))
        from black_onyx.llm.factory import migrate_openai_provider_settings
        if migrate_openai_provider_settings(self._settings.llm):
            runtime_config = dict(runtime_config)
            runtime_config["llm"] = self._settings.llm.model_dump(mode="python")
            self._settings_store.save(runtime_config, {}, actor_user_id="system")
        apply_secret_environment(self._settings, runtime_secrets, self._deployment_secret_environment)
        self._reset_components()

    def update_runtime_settings(
        self,
        config: dict[str, Any],
        secret_updates: dict[str, str | None],
        actor_user_id: str,
    ) -> None:
        """Validate, persist, and immediately activate administrator settings."""
        merged = deep_merge(self._base_settings.model_dump(mode="python"), config)
        # Clearing the Qdrant key must also drop any value inherited from env/base,
        # otherwise local HTTP Qdrant is contacted with HTTPS (api_key forces TLS).
        if secret_updates.get("qdrant_api_key") == "":
            merged.setdefault("qdrant", {})["api_key"] = None
        candidate = Settings(**merged)
        from black_onyx.llm.factory import migrate_openai_provider_settings
        migrate_openai_provider_settings(candidate.llm)
        # Persist migrated LLM settings so disk matches runtime after OpenAI split.
        persist_config = dict(config)
        persist_config["llm"] = candidate.llm.model_dump(mode="python")
        secrets = self._settings_store.save(persist_config, secret_updates, actor_user_id)
        self._settings = candidate
        apply_secret_environment(self._settings, secrets, self._deployment_secret_environment)
        if secret_updates.get("qdrant_api_key") == "":
            self._settings.qdrant.api_key = None
        self._reset_components()
        # _reset_components stopped the old pollers; bring them back up under
        # the new settings, otherwise saving anything on the Settings page
        # silently disables feed and connector polling until the next restart.
        self.start_background_schedulers()

    def runtime_secret_status(self) -> dict[str, bool]:
        _, secrets = self._settings_store.load()
        return {
            "openai_api_key": bool(secrets.get("openai_api_key") or self._settings.get_api_key(self._settings.llm.openai.api_key_env)),
            "claude_api_key": bool(secrets.get("claude_api_key") or self._settings.get_api_key(self._settings.llm.claude.api_key_env)),
            "gemini_api_key": bool(secrets.get("gemini_api_key") or self._settings.get_api_key(self._settings.llm.gemini.api_key_env)),
            "qdrant_api_key": bool(secrets.get("qdrant_api_key") or self._settings.qdrant.api_key),
            "firecrawl_api_key": bool(
                secrets.get("firecrawl_api_key")
                or self._settings.get_api_key(self._settings.web_search.firecrawl_api_key_env)
            ),
            "virustotal_api_key": bool(secrets.get("virustotal_api_key") or self._settings.get_api_key("VIRUSTOTAL_API_KEY")),
            "abuseipdb_api_key": bool(secrets.get("abuseipdb_api_key") or self._settings.get_api_key("ABUSEIPDB_API_KEY")),
            "shodan_api_key": bool(secrets.get("shodan_api_key") or self._settings.get_api_key("SHODAN_API_KEY")),
            "otx_api_key": bool(secrets.get("otx_api_key") or self._settings.get_api_key("OTX_API_KEY")),
            "misp_api_key": bool(secrets.get("misp_api_key") or self._settings.get_api_key("MISP_API_KEY")),
        }

    def _collection_vector_sizes(self) -> tuple[int, int]:
        from black_onyx.core.collections import default_clip_vector_size, default_text_vector_size

        text_dim = default_text_vector_size(self._settings.embedding.model_name)
        clip_dim = default_clip_vector_size(self._settings.clip.model_name)
        if self._embedding_model is not None:
            try:
                text_dim = self._embedding_model.get_embedding_dim()
            except Exception:
                logger.debug("Using default text vector size", exc_info=True)
        if self._clip_model is not None:
            try:
                clip_dim = self._clip_model.get_embedding_dim()
            except Exception:
                logger.debug("Using default CLIP vector size", exc_info=True)
        return text_dim, clip_dim

    def ensure_collection(self, name: str) -> None:
        """Create a collection if missing using the app's embedding layout."""
        from black_onyx.core.collections import COLLECTION_NAME_RE

        if not COLLECTION_NAME_RE.match(name):
            raise ValueError(f"Invalid collection name: {name}")
        text_dim, clip_dim = self._collection_vector_sizes()
        self.qdrant_store.ensure_collection(
            collection_name=name,
            text_vector_size=text_dim,
            clip_vector_size=clip_dim,
            use_multivector=self._settings.image.use_multivector,
        )

    def ensure_default_collections(self) -> list[str]:
        """Ensure premade collections exist: all-knowledge, web-search, and per-feed."""
        from black_onyx.core.collections import feed_collection_name

        names = [
            self._settings.ingestion.collection_name or "all-knowledge",
            self._settings.web_search.collection or "web-search",
            "all-knowledge",
            "web-search",
        ]
        created: list[str] = []
        seen: set[str] = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            self.ensure_collection(name)
            created.append(name)

        feed_names: list[str] = []
        try:
            if self.feed_manager is not None:
                for feed in self.feed_manager.list_feeds():
                    feed_names.append(feed.get("name") or "")
        except Exception:
            logger.debug("Unable to list feeds while ensuring collections", exc_info=True)
        for feed_cfg in self._settings.feeds.feeds:
            feed_names.append(str(feed_cfg.get("name") or ""))
        for feed_name in feed_names:
            if not feed_name:
                continue
            coll = feed_collection_name(feed_name)
            if coll in seen:
                continue
            seen.add(coll)
            self.ensure_collection(coll)
            created.append(coll)
        return created

    def _reset_components(self) -> None:
        """Discard lazily-created components so new settings apply on next use."""
        # Reset components so they re-initialize with new settings
        self._embedding_model = None
        self._ner_model = None
        self._classifier = None
        self._qdrant_store = None
        self._ocr_engine = None
        self._clip_model = None
        self._llm_providers = {}
        self._rag_engines = {}
        self._ingestor = None
        self._enrichment_manager = None
        self._attack_mapper = None
        self._case_manager = None
        self._watchlist_manager = None
        self._asset_manager = None
        self._detection_rules_manager = None
        self._annotation_manager = None
        self._decay_manager = None
        self._report_generator = None
        # Both of these own a daemon scheduler thread that holds a reference
        # back to the manager (so it is never collected) and an open SQLite
        # connection. Dropping the reference without closing leaves the old
        # scheduler polling forever on stale settings, against the same
        # database file the replacement manager is now writing to.
        self._close_scheduled_managers()
        self._feed_manager = None
        self._connector_manager = None
        # webhook_manager / misp / taxii / playbooks are not settings-dependent; keep across reloads
        self._playbook_runner = None

    def _close_scheduled_managers(self) -> None:
        """Stop and close any already-constructed background-polling managers.

        Deliberately reads the private attributes rather than the properties:
        the properties construct on access, and `connector_manager` in
        particular builds a full Ingestor (loading the embedding model), so
        touching them here would create the very thing we are trying to tear
        down — on every settings save and every process shutdown.
        """
        for attribute in ("_feed_manager", "_connector_manager"):
            manager = getattr(self, attribute, None)
            if manager is None:
                continue
            try:
                manager.close()
            except Exception:
                logger.debug("Failed to close %s cleanly", attribute, exc_info=True)

    def shutdown(self) -> None:
        """Release background resources on application shutdown."""
        self._close_scheduled_managers()
        self._feed_manager = None
        self._connector_manager = None

    def start_background_schedulers(self) -> None:
        """Start the feed/connector poll loops for whichever are enabled.

        Called both at startup and after a settings save — `_reset_components`
        discards the previous managers, so without re-starting here a settings
        change would silently leave the application with no pollers running.
        `start_scheduler` is idempotent (it no-ops when its thread is alive).
        """
        if self._settings.feeds.enabled and self.feed_manager:
            self.feed_manager.start_scheduler()
        if self._settings.connectors.enabled:
            self.connector_manager.start_scheduler()

    @property
    def embedding_model(self) -> Any:
        if self._embedding_model is None:
            from black_onyx.core.embeddings import EmbeddingModel
            self._embedding_model = EmbeddingModel(
                model_name=self._settings.embedding.model_name,
                device=self._settings.resolve_device(self._settings.embedding.device),
            )
        return self._embedding_model

    @property
    def ner_model(self) -> Any:
        if self._ner_model is None and self._settings.ingestion.enable_ner:
            from black_onyx.core.ner import NERModel
            self._ner_model = NERModel(
                model_name=self._settings.ner.model_name,
                labels=self._settings.ner.labels,
                threshold=self._settings.ner.threshold,
                device=self._settings.resolve_device(self._settings.ner.device),
            )
        return self._ner_model

    @property
    def classifier(self) -> Any:
        if self._classifier is None and self._settings.classifier.enabled:
            from black_onyx.core.classifier import Classifier
            self._classifier = Classifier(
                model_name=self._settings.classifier.model_name,
                device=self._settings.resolve_device(self._settings.classifier.device),
                enabled=True,
            )
        return self._classifier

    @property
    def qdrant_store(self) -> Any:
        if self._qdrant_store is None:
            from black_onyx.core.qdrant_store import QdrantStore
            api_key = None
            if self._settings.qdrant.api_key:
                api_key = self._settings.qdrant.api_key.get_secret_value()
            self._qdrant_store = QdrantStore(
                host=self._settings.qdrant.host,
                port=self._settings.qdrant.port,
                api_key=api_key,
                prefer_grpc=self._settings.qdrant.prefer_grpc,
                https=self._settings.qdrant.https,
                timeout=self._settings.qdrant.timeout,
            )
        return self._qdrant_store

    @property
    def ocr_engine(self) -> Any:
        if self._ocr_engine is None and self._settings.ingestion.enable_image_extraction:
            try:
                from black_onyx.extraction.ocr import OCREngine
                self._ocr_engine = OCREngine(
                    backend=self._settings.ocr.backend,
                    language=self._settings.ocr.language,
                    tesseract_cmd=self._settings.ocr.tesseract_cmd,
                )
            except ImportError:
                logger.warning("OCR dependencies not installed")
        return self._ocr_engine

    @property
    def clip_model(self) -> Any:
        if self._clip_model is None and self._settings.ingestion.enable_image_extraction:
            try:
                from black_onyx.extraction.clip import CLIPModel
                self._clip_model = CLIPModel(
                    model_name=self._settings.clip.model_name,
                    pretrained=self._settings.clip.pretrained,
                    device=self._settings.resolve_device(self._settings.clip.device),
                )
            except ImportError:
                logger.warning("CLIP dependencies not installed")
        return self._clip_model

    @property
    def llm_provider(self) -> Any:
        return self.get_llm_provider(self._settings.llm.provider)

    def get_llm_provider(self, provider_name: str) -> Any:
        if provider_name not in self._llm_providers:
            from black_onyx.llm.factory import create_provider
            api_keys: dict[str, str] = {}
            for env_name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]:
                val = os.environ.get(env_name, "")
                if val:
                    api_keys[env_name] = val
            self._llm_providers[provider_name] = create_provider(
                provider_type=provider_name,
                config=self._settings.llm,
                api_keys=api_keys,
            )
        return self._llm_providers[provider_name]

    @property
    def rag_engine(self) -> Any:
        return self.get_rag_engine(self._settings.llm.provider)

    def get_rag_engine(self, provider_name: str) -> Any:
        if provider_name not in self._rag_engines:
            from black_onyx.llm.rag import RAGEngine
            self._rag_engines[provider_name] = RAGEngine(
                llm_provider=self.get_llm_provider(provider_name),
                embedding_model=self.embedding_model,
                qdrant_store=self.qdrant_store,
                collections=self._settings.llm.rag.collections,
                top_k=self._settings.llm.rag.top_k,
                score_threshold=self._settings.llm.rag.score_threshold,
                chunk_context_window=self._settings.llm.rag.chunk_context_window,
                system_prompt=self._settings.llm.rag.system_prompt,
            )
        return self._rag_engines[provider_name]

    @property
    def session_manager(self) -> Any:
        if self._session_manager is None:
            from black_onyx.llm.session import ChatSessionManager
            self._session_manager = ChatSessionManager(persist_dir=self._settings.storage.state_dir)
        return self._session_manager

    @property
    def enrichment_manager(self) -> Any:
        if self._enrichment_manager is None and self._settings.enrichment.enabled:
            from black_onyx.enrichment.factory import create_enrichment_provider
            from black_onyx.enrichment.manager import EnrichmentManager
            # Resolve API keys from environment
            api_keys: dict[str, str] = {}
            for env_name in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "OTX_API_KEY", "NVD_API_KEY"]:
                val = os.environ.get(env_name, "")
                if val:
                    api_keys[env_name] = val
            # Also check config-provided keys
            for k, v in self._settings.enrichment.api_keys.items():
                if v and k not in api_keys:
                    api_keys[k] = v
            providers = [
                create_enrichment_provider(name, api_keys)
                for name in self._settings.enrichment.providers
            ]
            self._enrichment_manager = EnrichmentManager(
                providers=providers,
                persist_dir=self._settings.storage.state_dir,
                cache_ttl_hours=self._settings.enrichment.cache_ttl_hours,
                max_concurrent=self._settings.enrichment.max_concurrent,
                timeout_seconds=self._settings.enrichment.timeout_seconds,
            )
        return self._enrichment_manager

    @property
    def attack_mapper(self) -> Any:
        if self._attack_mapper is None and self._settings.threat_intel.mitre_attack_enabled:
            from black_onyx.threat.attack_mapper import AttackMapper
            self._attack_mapper = AttackMapper(
                data_dir=self._settings.threat_intel.mitre_attack_data_dir,
            )
        return self._attack_mapper

    @property
    def case_manager(self) -> Any:
        if self._case_manager is None:
            from black_onyx.threat.case_manager import CaseManager
            self._case_manager = CaseManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._case_manager

    @property
    def watchlist_manager(self) -> Any:
        if self._watchlist_manager is None:
            from black_onyx.threat.watchlist_manager import WatchlistManager
            self._watchlist_manager = WatchlistManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._watchlist_manager

    @property
    def asset_manager(self) -> Any:
        if self._asset_manager is None:
            from black_onyx.threat.asset_manager import AssetManager
            self._asset_manager = AssetManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._asset_manager

    @property
    def detection_rules_manager(self) -> Any:
        if self._detection_rules_manager is None:
            from black_onyx.threat.detection_rules_manager import DetectionRulesManager
            self._detection_rules_manager = DetectionRulesManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._detection_rules_manager

    @property
    def annotation_manager(self) -> Any:
        if self._annotation_manager is None:
            from black_onyx.threat.annotation_manager import AnnotationManager
            self._annotation_manager = AnnotationManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._annotation_manager

    @property
    def decay_manager(self) -> Any:
        if self._decay_manager is None:
            from black_onyx.threat.decay_manager import DecayManager
            self._decay_manager = DecayManager(
                persist_dir=self._settings.storage.state_dir,
                decay_rate=self._settings.threat_intel.decay_rate,
                stale_threshold_days=self._settings.threat_intel.stale_threshold_days,
            )
        return self._decay_manager

    @property
    def site_credential_store(self) -> Any:
        if self._site_credential_store is None:
            from black_onyx.auth.context import get_auth_service
            from black_onyx.site_credentials import SiteCredentialStore
            auth = get_auth_service()
            self._site_credential_store = SiteCredentialStore(auth.db, auth.config)
        return self._site_credential_store

    @property
    def report_generator(self) -> Any:
        if self._report_generator is None:
            from black_onyx.threat.report_generator import ReportGenerator
            llm = None
            try:
                llm = self.llm_provider
            except Exception as exc:
                logger.debug("Report LLM provider unavailable: %s", type(exc).__name__)
            self._report_generator = ReportGenerator(llm_provider=llm)
        return self._report_generator

    @property
    def feed_manager(self) -> Any:
        if self._feed_manager is None and self._settings.feeds.enabled:
            from black_onyx.feeds.feed_manager import FeedManager
            self._feed_manager = FeedManager(
                persist_dir=self._settings.storage.state_dir,
                ingestor=self.create_ingestor(),
                allowed_hosts=self._settings.feeds.allowed_hosts,
                max_response_bytes=self._settings.feeds.max_response_bytes,
                max_concurrent=self._settings.feeds.max_concurrent,
            )
            for feed_cfg in self._settings.feeds.feeds:
                self._feed_manager.add_feed_from_dict(feed_cfg)
        return self._feed_manager

    @property
    def connector_manager(self) -> Any:
        # Unlike feed_manager, always constructed regardless of
        # settings.connectors.enabled — there is no settings-page toggle to
        # flip that flag from, so gating CRUD behind it would make the admin
        # API unreachable. connectors.enabled only gates whether the
        # background scheduler starts (app.py lifespan); each connector row
        # has its own per-connector enabled flag for "configured but paused".
        if self._connector_manager is None:
            from black_onyx.connectors.connector_manager import DetectionConnectorManager
            self._connector_manager = DetectionConnectorManager(
                persist_dir=self._settings.storage.state_dir,
                ingestor_factory=self.create_ingestor,
                allowed_hosts=self._settings.connectors.allowed_hosts,
                max_response_bytes=self._settings.connectors.max_response_bytes,
                max_concurrent=self._settings.connectors.max_concurrent,
                asset_manager=self.asset_manager,
            )
        else:
            # Keep asset manager wired across reloads / lazy init order.
            try:
                self._connector_manager.set_asset_manager(self.asset_manager)
            except Exception:
                pass
        return self._connector_manager

    @property
    def webhook_manager(self) -> Any:
        if self._webhook_manager is None:
            from black_onyx.threat.webhook_manager import WebhookManager
            self._webhook_manager = WebhookManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._webhook_manager

    @property
    def misp_manager(self) -> Any:
        if self._misp_manager is None:
            from black_onyx.integrations.misp.sync_manager import MispSyncManager
            self._misp_manager = MispSyncManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._misp_manager

    @property
    def taxii_manager(self) -> Any:
        if self._taxii_manager is None:
            from black_onyx.taxii.publish_manager import TaxiiPublishManager
            self._taxii_manager = TaxiiPublishManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._taxii_manager

    @property
    def playbook_manager(self) -> Any:
        if self._playbook_manager is None:
            from black_onyx.automation.playbook_manager import PlaybookManager
            self._playbook_manager = PlaybookManager(
                persist_dir=self._settings.storage.state_dir,
            )
        return self._playbook_manager

    @property
    def playbook_runner(self) -> Any:
        if self._playbook_runner is None:
            from black_onyx.automation.runner import PlaybookRunner
            from black_onyx.threat.sigma_generator import SigmaRuleGenerator
            self._playbook_runner = PlaybookRunner(
                playbook_manager=self.playbook_manager,
                enrichment_manager=self.enrichment_manager,
                case_manager=self.case_manager,
                sigma_generator=SigmaRuleGenerator(),
                qdrant_store=self.qdrant_store,
            )
        return self._playbook_runner

    def create_ingestor(self, **overrides: Any) -> Any:
        """Create a new Ingestor instance (not cached, as it holds run state)."""
        from black_onyx.pipeline.ingestor import Ingestor
        def selected(name: str, default: Any) -> Any:
            value = overrides.get(name)
            return default if value is None else value
        return Ingestor(
            embedding_model=self.embedding_model,
            ner_model=self.ner_model,
            classifier=self.classifier,
            qdrant_store=self.qdrant_store,
            ocr_engine=self.ocr_engine,
            clip_model=self.clip_model,
            chunk_size=self._settings.chunking.chunk_size,
            chunk_overlap=self._settings.chunking.chunk_overlap,
            sentence_aware=self._settings.chunking.sentence_aware,
            batch_size=self._settings.ingestion.batch_size,
            max_workers=self._settings.ingestion.max_workers,
            enable_ner=selected("enable_ner", self._settings.ingestion.enable_ner),
            enable_classifier=selected("enable_classifier", self._settings.ingestion.enable_classifier),
            enable_code_detection=self._settings.ingestion.enable_code_detection,
            enable_image_extraction=selected(
                "enable_image_extraction", self._settings.ingestion.enable_image_extraction),
            use_multivector=self._settings.image.use_multivector,
            csv_path=selected("csv_path", self._settings.ingestion.csv_path),
            watchlist_manager=self.watchlist_manager,
            decay_manager=self.decay_manager,
            playbook_runner=self.playbook_runner,
            dedup_threshold=self._settings.image.dedup_threshold,
        )

    def register_job(
        self, job_id: str, ingestor: Any, tracker: Any, owner_user_id: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Register an active ingestion job."""
        from datetime import timedelta
        from black_onyx.auth.context import get_auth_service
        from black_onyx.auth.service import iso, utcnow

        self._active_jobs[job_id] = {
            "ingestor": ingestor,
            "tracker": tracker,
            "status": "running",
            "owner_user_id": owner_user_id,
        }
        now = utcnow()
        auth = get_auth_service()
        with auth.db.transaction() as db:
            db.execute("DELETE FROM jobs WHERE expires_at<?", (iso(now),))
            db.execute(
                "INSERT INTO jobs(job_id,owner_user_id,job_type,status,detail,created_at,updated_at,expires_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (job_id, owner_user_id, "ingestion", "running", json.dumps(detail or {}),
                 iso(now), iso(now), iso(now + timedelta(days=30))),
            )

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self._active_jobs.get(job_id)

    def update_job_status(
        self, job_id: str, status: str, detail: dict[str, Any] | None = None
    ) -> None:
        from black_onyx.auth.context import get_auth_service
        from black_onyx.auth.service import iso, utcnow

        normalized = "failed" if status == "error" else status
        if job_id in self._active_jobs:
            self._active_jobs[job_id]["status"] = normalized
        with get_auth_service().db.transaction() as db:
            if detail is None:
                db.execute(
                    "UPDATE jobs SET status=?,updated_at=? WHERE job_id=?",
                    (normalized, iso(utcnow()), job_id),
                )
            else:
                db.execute(
                    "UPDATE jobs SET status=?,detail=?,updated_at=? WHERE job_id=?",
                    (normalized, json.dumps(detail), iso(utcnow()), job_id),
                )

    def get_job_record(self, job_id: str, owner_user_id: str) -> dict[str, Any] | None:
        from black_onyx.auth.context import get_auth_service

        row = get_auth_service().db._conn.execute(
            "SELECT job_id,job_type,status,detail,created_at,updated_at "
            "FROM jobs WHERE job_id=? AND owner_user_id=?",
            (job_id, owner_user_id),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["detail"] = json.loads(result["detail"])
        return result

    def remove_job(self, job_id: str) -> None:
        self._active_jobs.pop(job_id, None)

    @property
    def active_jobs(self) -> dict[str, dict[str, Any]]:
        return dict(self._active_jobs)

    def get_system_info(self) -> dict[str, Any]:
        """Get system information for the info API."""
        device_info = get_device_info()
        try:
            qdrant_version = self.qdrant_store.get_server_version()
            collections = self.qdrant_store.list_collections()
        except Exception as e:
            qdrant_version = "error"
            collections = []
            logger.warning(f"Failed to get Qdrant info: {e}")

        return {
            "device": device_info,
            "qdrant_version": qdrant_version,
            "collections": collections,
        }


def get_service() -> AppService:
    """Get the singleton AppService instance."""
    return AppService()
