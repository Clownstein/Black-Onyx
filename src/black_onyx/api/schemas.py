"""API request/response schemas using Pydantic v2."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class ProviderSettings(BaseModel):
    base_url: Optional[str] = Field(default=None, max_length=2048)
    model: str = Field(min_length=1, max_length=256)
    temperature: float = Field(default=0.7, ge=0, le=2)
    max_tokens: int = Field(default=4096, ge=1, le=1_000_000)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        from urllib.parse import urlsplit
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("base_url must be an absolute HTTP(S) URL without credentials")
        return value.rstrip("/")


class LlamaCppSettings(BaseModel):
    n_ctx: int = Field(default=4096, ge=512, le=1_048_576)
    n_gpu_layers: int = Field(default=-1, ge=-1, le=10_000)
    temperature: float = Field(default=0.7, ge=0, le=2)
    max_tokens: int = Field(default=4096, ge=1, le=1_000_000)


class RAGSettings(BaseModel):
    enabled: bool = True
    collections: list[str] = Field(default_factory=lambda: ["all-knowledge"], max_length=50)
    top_k: int = Field(default=8, ge=1, le=100)
    score_threshold: float = Field(default=0.5, ge=0, le=1)
    chunk_context_window: int = Field(default=2, ge=0, le=20)


class LLMAdminSettings(BaseModel):
    provider: Literal["local", "openai", "openai_compatible", "claude", "gemini", "llama_cpp"] = "local"
    local: ProviderSettings
    openai: ProviderSettings
    openai_compatible: ProviderSettings
    claude: ProviderSettings
    gemini: ProviderSettings
    llama_cpp: LlamaCppSettings
    rag: RAGSettings


class IngestionAdminSettings(BaseModel):
    collection_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    batch_size: int = Field(ge=1, le=10_000)
    max_workers: int = Field(ge=1, le=64)
    max_upload_bytes: int = Field(ge=1_048_576, le=10 * 1024 * 1024 * 1024)
    max_upload_files: int = Field(ge=1, le=100_000)
    enable_ner: bool
    enable_classifier: bool
    enable_code_detection: bool
    enable_image_extraction: bool


class ChunkingAdminSettings(BaseModel):
    chunk_size: int = Field(ge=128, le=100_000)
    chunk_overlap: int = Field(ge=0, le=50_000)
    sentence_aware: bool

    @field_validator("chunk_overlap")
    @classmethod
    def validate_overlap(cls, value: int, info: Any) -> int:
        chunk_size = info.data.get("chunk_size")
        if chunk_size is not None and value >= chunk_size:
            raise ValueError("chunk_overlap must be smaller than chunk_size")
        return value


class FeedsAdminSettings(BaseModel):
    enabled: bool
    poll_interval_minutes: int = Field(ge=1, le=43_200)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=500)
    max_response_bytes: int = Field(ge=1024, le=1024 * 1024 * 1024)
    max_concurrent: int = Field(ge=1, le=64)

    @field_validator("allowed_hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        import re
        normalized = []
        for value in values:
            host = value.strip().lower().rstrip(".")
            if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
                raise ValueError(f"Invalid feed hostname: {value}")
            normalized.append(host)
        return sorted(set(normalized))


class SecretSettingsUpdate(BaseModel):
    openai_api_key: Optional[SecretStr] = None
    claude_api_key: Optional[SecretStr] = None
    gemini_api_key: Optional[SecretStr] = None
    qdrant_api_key: Optional[SecretStr] = None
    firecrawl_api_key: Optional[SecretStr] = None
    virustotal_api_key: Optional[SecretStr] = None
    abuseipdb_api_key: Optional[SecretStr] = None
    shodan_api_key: Optional[SecretStr] = None
    otx_api_key: Optional[SecretStr] = None
    misp_api_key: Optional[SecretStr] = None


class QdrantAdminSettings(BaseModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.:-]*$")
    port: int = Field(ge=1, le=65535)
    prefer_grpc: bool
    https: bool = False
    timeout: int = Field(ge=1, le=600)


class WebSearchAdminSettings(BaseModel):
    enabled: bool = False
    searxng_url: str = Field(default="http://searxng:8080", min_length=1, max_length=2048)
    max_results: int = Field(default=5, ge=1, le=20)
    max_tool_rounds: int = Field(default=3, ge=1, le=3)
    scrape_top_k: int = Field(default=3, ge=0, le=10)
    timeout_seconds: int = Field(default=30, ge=5, le=120)


class EnrichmentAdminSettings(BaseModel):
    enabled: bool = True
    providers: list[str] = Field(
        default_factory=lambda: ["virustotal", "abuseipdb", "shodan", "otx", "urlhaus", "threatfox"],
        max_length=20,
    )
    cache_ttl_hours: int = Field(default=24, ge=1, le=720)
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    max_concurrent: int = Field(default=5, ge=1, le=32)
    auto_enrich_on_match: bool = False


class AdminSettingsUpdate(BaseModel):
    llm: LLMAdminSettings
    ingestion: IngestionAdminSettings
    chunking: ChunkingAdminSettings
    feeds: FeedsAdminSettings
    qdrant: QdrantAdminSettings
    web_search: WebSearchAdminSettings
    enrichment: EnrichmentAdminSettings = Field(default_factory=EnrichmentAdminSettings)
    secrets: SecretSettingsUpdate = Field(default_factory=SecretSettingsUpdate)


class IngestRequest(BaseModel):
    """Request to start an ingestion job."""
    directory: str = Field(min_length=1, max_length=4096)
    collection: str = Field(default="all-knowledge", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    enable_ner: Optional[bool] = None
    enable_classifier: Optional[bool] = None
    enable_image_extraction: Optional[bool] = None


class IngestResponse(BaseModel):
    """Response to an ingestion start request."""
    job_id: str
    status: str = "started"
    message: str = ""


class SearchRequest(BaseModel):
    """Semantic search request."""
    query: str = Field(min_length=1, max_length=10_000)
    collection: str = Field(default="all-knowledge", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    limit: int = Field(default=10, ge=1, le=100)
    score_threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    vector_name: Literal["text", "clip"] = "text"


class SearchResult(BaseModel):
    """A single search result."""
    id: str
    score: float
    payload: dict[str, Any]
    collection: str = ""


class SearchResponse(BaseModel):
    """Search response."""
    query: str
    results: list[SearchResult]
    total: int


class ChatRequest(BaseModel):
    """Chat request (non-streaming)."""
    message: str = Field(min_length=1, max_length=100_000)
    session_id: Optional[str] = None
    provider: Optional[Literal["local", "openai", "openai_compatible", "claude", "gemini", "llama_cpp"]] = None
    collections: Optional[list[str]] = Field(default=None, max_length=50)
    images: Optional[list[str]] = Field(default=None, max_length=0)
    use_rag: bool = True
    use_web_search: bool = False


class ChatResponse(BaseModel):
    """Chat response (non-streaming)."""
    response: str
    session_id: str
    sources: list[dict[str, Any]] = Field(default_factory=list)
    model: str = ""


class CreateSessionRequest(BaseModel):
    """Create a new chat session."""
    title: str = Field(default="New Chat", min_length=1, max_length=200)
    provider: Optional[Literal["local", "openai", "openai_compatible", "claude", "gemini", "llama_cpp"]] = None


class CreateSessionResponse(BaseModel):
    """Response to session creation."""
    session_id: str


class SessionInfo(BaseModel):
    """Chat session metadata."""
    session_id: str
    title: str = ""
    provider: str = ""
    model: str = ""
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CollectionCreateRequest(BaseModel):
    """Create an empty Qdrant collection."""
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class CollectionInfo(BaseModel):
    """Qdrant collection info."""
    name: str
    points_count: int = 0
    vectors_count: int = 0
    vectors: Optional[dict[str, Any]] = None
    vector_size: Optional[int] = None
    distance: Optional[str] = None


class SystemInfo(BaseModel):
    """System information."""
    device: dict[str, Any] = Field(default_factory=dict)
    qdrant_version: str = "unknown"
    collections: list[CollectionInfo] = Field(default_factory=list)


class StatusResponse(BaseModel):
    """Generic status response."""
    status: str
    message: str = ""


# --- Threat Intelligence schemas ---

class IOCExtractRequest(BaseModel):
    """Request to extract IOCs from text."""
    text: str = Field(min_length=1, max_length=1_000_000)
    include_defanged: bool = True


class IOCExtractResponse(BaseModel):
    """Response with extracted IOCs."""
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    total_count: int = 0


class EnrichRequest(BaseModel):
    """Request to enrich a single IOC."""
    ioc_type: Literal["ip", "domain", "url", "hash", "email", "cve"]
    ioc_value: str = Field(min_length=1, max_length=4096)
    providers: Optional[list[str]] = Field(default=None, max_length=20)


class EnrichResponse(BaseModel):
    """Response with enrichment results."""
    ioc_value: str
    results: list[dict[str, Any]] = Field(default_factory=list)


class EnrichBatchRequest(BaseModel):
    """Request to enrich multiple IOCs."""
    iocs: list[dict[str, str]] = Field(min_length=1, max_length=500)


class EnrichBatchResponse(BaseModel):
    """Response with batch enrichment results."""
    results: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class STIXExportRequest(BaseModel):
    """Request to export IOCs as STIX bundle."""
    iocs: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)
    techniques: Optional[list[dict[str, Any]]] = Field(default=None, max_length=5_000)


class STIXExportResponse(BaseModel):
    """Response with STIX bundle."""
    bundle: dict[str, Any]


class SigmaGenerateRequest(BaseModel):
    """Request to generate a Sigma rule."""
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    title: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=10_000)
    level: Literal["informational", "low", "medium", "high", "critical"] = "medium"


class SigmaGenerateResponse(BaseModel):
    """Response with Sigma rule YAML."""
    rule: str


class YARAGenerateRequest(BaseModel):
    """Request to generate a YARA rule."""
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    rule_name: str = Field(default="", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    tags: Optional[list[str]] = Field(default=None, max_length=100)


class YARAGenerateResponse(BaseModel):
    """Response with YARA rule text."""
    rule: str


class GraphResponse(BaseModel):
    """Response with graph nodes and edges."""
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    type_counts: dict[str, int] = Field(default_factory=dict)
    truncated: bool = False


class EntityGraphRequest(BaseModel):
    """Request to build a relationship graph from indexed collections."""
    collections: list[str] = Field(default_factory=list, max_length=64)
    entity_types: list[str] = Field(default_factory=list, max_length=48)
    start_date: Optional[str] = Field(default=None, max_length=32)
    end_date: Optional[str] = Field(default=None, max_length=32)
    search: Optional[str] = Field(default=None, max_length=512)
    max_points_per_collection: int = Field(default=250, ge=1, le=2_000)
    max_nodes: int = Field(default=400, ge=10, le=3_000)


class EntityGraphResponse(GraphResponse):
    """Relationship graph plus the per-source accounting behind it."""
    sources: list[dict[str, Any]] = Field(default_factory=list)
    available_entity_types: list[dict[str, Any]] = Field(default_factory=list)
    points_scanned: int = 0
    points_matched: int = 0
    points_undated: int = 0


class CaseCreateRequest(BaseModel):
    """Request to create a case."""
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=100_000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    assignee: Optional[str] = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=100)
    external_incident_id: Optional[str] = Field(default=None, max_length=128)


class CaseUpdateRequest(BaseModel):
    """Request to update a case."""
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=100_000)
    status: Optional[Literal["open", "investigating", "resolved", "closed"]] = None
    priority: Optional[Literal["low", "medium", "high", "critical"]] = None
    severity: Optional[Literal["informational", "low", "medium", "high", "critical"]] = None
    assignee: Optional[str] = Field(default=None, max_length=200)
    tags: Optional[list[str]] = Field(default=None, max_length=100)
    detected_at: Optional[str] = Field(default=None, max_length=64)
    contained_at: Optional[str] = Field(default=None, max_length=64)
    closed_at: Optional[str] = Field(default=None, max_length=64)
    sla_due_at: Optional[str] = Field(default=None, max_length=64)


class CasePointRequest(BaseModel):
    collection: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    point_id: str = Field(min_length=1, max_length=256)


class CaseIOCRequest(BaseModel):
    ioc_type: str = Field(min_length=1, max_length=32)
    ioc_value: str = Field(min_length=1, max_length=4096)


class CaseNoteRequest(BaseModel):
    content: str = Field(min_length=1, max_length=100_000)


class CaseResponse(BaseModel):
    """Response with case details."""
    case_id: str
    title: str
    description: str = ""
    status: str = "open"
    priority: str = "medium"
    severity: str = "medium"
    assignee: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    detected_at: Optional[str] = None
    contained_at: Optional[str] = None
    closed_at: Optional[str] = None
    sla_due_at: Optional[str] = None
    external_incident_id: Optional[str] = None
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    points: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)


class CaseListResponse(BaseModel):
    """Response with list of cases."""
    cases: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


class WatchlistCreateRequest(BaseModel):
    """Request to create a watchlist."""
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10_000)


class WatchlistAddItemsRequest(BaseModel):
    """Request to add items to a watchlist."""
    items: list[dict[str, str]] = Field(min_length=1, max_length=1_000)


class WatchlistResponse(BaseModel):
    """Response with watchlist details."""
    list_id: str
    name: str
    description: str = ""
    item_count: int = 0


class AlertResponse(BaseModel):
    """Response with alert details."""
    alert_id: str
    list_id: str
    ioc_type: str = ""
    ioc_value: str = ""
    triggered_at: str = ""
    acknowledged: bool = False


class ReportGenerateRequest(BaseModel):
    """Request to generate an intelligence report."""
    title: str = Field(default="Threat Intelligence Report", min_length=1, max_length=200)
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    enrichments: Optional[list[dict[str, Any]]] = None
    mitre_techniques: Optional[list[dict[str, Any]]] = None
    case_id: Optional[str] = None
    format: Literal["markdown", "html", "pdf"] = "markdown"
    template: Optional[Literal["intel", "ops_digest"]] = None
    body_markdown: Optional[str] = Field(default=None, max_length=500_000)


class ReportResponse(BaseModel):
    """Response with generated report."""
    title: str
    format: str
    content: str
    download_url: Optional[str] = None


class FeedAddRequest(BaseModel):
    """Request to add a feed."""
    name: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,199}$")
    url: str = Field(min_length=9, max_length=4096)
    feed_type: Literal["rss", "atom", "taxii"] = "rss"
    collection: str = Field(default="all-knowledge", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    poll_interval_minutes: int = Field(default=60, ge=1, le=10_080)
    config: Optional[dict[str, Any]] = None


class FeedPollResponse(BaseModel):
    """Response from polling a feed."""
    feed: str = ""
    items_available: int = 0
    items_processed: int = 0
    items_failed: int = 0
    items_deferred: int = 0
    iocs_extracted: int = 0
    skipped: Optional[str] = None
    error: Optional[str] = None


class AnnotationCreateRequest(BaseModel):
    """Request to create an annotation."""
    model_config = ConfigDict(extra="forbid")
    collection: str
    point_id: str
    content: str


class TagRequest(BaseModel):
    """Request to add/remove a tag."""
    collection: str
    point_id: str
    tag: str = Field(min_length=1, max_length=100)


class NoteCreateRequest(BaseModel):
    """Request to create a note."""
    model_config = ConfigDict(extra="forbid")
    collection: str
    point_id: str
    content: str


class BookmarkRequest(BaseModel):
    """Request to toggle a bookmark."""
    model_config = ConfigDict(extra="forbid")
    collection: str
    point_id: str


class ConfidenceRequest(BaseModel):
    """Request to set confidence score."""
    model_config = ConfigDict(extra="forbid")
    collection: str
    point_id: str
    confidence: float = Field(ge=0.0, le=1.0)


class StatusUpdateRequest(BaseModel):
    """Request to set IOC status."""
    model_config = ConfigDict(extra="forbid")
    collection: str
    point_id: str
    status: Literal["new", "confirmed", "benign", "expired"]


class ThreatScoreRequest(BaseModel):
    """Request to compute a composite threat score."""
    ioc_value: str = Field(min_length=1, max_length=4096)
    ioc_type: Literal["ip", "domain", "url", "hash", "email", "cve"]
    providers: Optional[list[str]] = Field(default=None, max_length=20)


class ThreatScoreResponse(BaseModel):
    """Response with composite threat score."""
    ioc_value: str
    ioc_type: str
    score: float
    verdict: str
    contributing_providers: list[dict[str, Any]] = []
    malicious_count: int = 0
    total_providers: int = 0


class AttackExtractRequest(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)


class WebhookCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class WebhookEventRequest(BaseModel):
    """Inbound event payload for webhook-authenticated IOC ingestion."""
    text: Optional[str] = Field(default=None, max_length=1_000_000)
    iocs: Optional[dict[str, list[str]]] = None
    source: Optional[str] = Field(default=None, max_length=256)
    watchlist_id: Optional[str] = Field(default=None, max_length=64)
    add_to_watchlist: bool = False


class MispConfigureRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    api_key: Optional[SecretStr] = None
    api_key_env: str = Field(default="MISP_API_KEY", min_length=1, max_length=128)
    collection: str = Field(default="all-knowledge", max_length=128)
    enabled: bool = True


class MispPublishIOC(BaseModel):
    ioc_type: str = Field(min_length=1, max_length=64)
    ioc_value: str = Field(min_length=1, max_length=4096)


class MispPublishRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=64)
    iocs: list[MispPublishIOC] = Field(min_length=1, max_length=500)
    info: str = Field(default="", max_length=1024)


class TaxiiCollectionCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=2048)
    enabled: bool = True


class TaxiiApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class TaxiiApiKeyUpdateRequest(BaseModel):
    enabled: Optional[bool] = None


class TaxiiPublishRequest(BaseModel):
    collection_id: str = Field(min_length=1, max_length=64)
    iocs: list[MispPublishIOC] = Field(default_factory=list, max_length=500)
    objects: Optional[list[dict[str, Any]]] = None


class PlaybookStepModel(BaseModel):
    type: str = Field(min_length=1, max_length=64)
    model_config = {"extra": "allow"}


class PlaybookCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    trigger_type: str = Field(min_length=1, max_length=64)
    steps: list[dict[str, Any]] = Field(min_length=1, max_length=50)
    enabled: bool = True


class PlaybookUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    trigger_type: Optional[str] = Field(default=None, min_length=1, max_length=64)
    steps: Optional[list[dict[str, Any]]] = Field(default=None, min_length=1, max_length=50)
    enabled: Optional[bool] = None


class PlaybookRunRequest(BaseModel):
    context: dict[str, Any] = Field(default_factory=dict)


class OutboundEndpointCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=8, max_length=2048)
    enabled: bool = True


# --- Gallery hub: user sites & saved logins ---

GallerySection = Literal["investigate", "intelligence", "operations", "control", "sites"]
SiteOpenMode = Literal["new_tab", "embedded", "launcher"]


def validate_site_url(value: str, production: bool) -> str:
    from urllib.parse import urlsplit
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain embedded credentials")
    if parsed.scheme == "http":
        host = parsed.hostname.lower()
        allowed_dev_host = host == "localhost" or host.startswith("127.") or host == "::1"
        if production or not allowed_dev_host:
            raise ValueError("Only HTTPS URLs are allowed (except localhost in non-production)")
    return value.strip()


class SiteCreateRequest(BaseModel):
    """Request to pin an external site as a gallery tile."""
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=2048)
    login_url: Optional[str] = Field(default=None, max_length=2048)
    section: GallerySection = "sites"
    tags: list[str] = Field(default_factory=list, max_length=50)
    open_mode: SiteOpenMode = "new_tab"

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip()[:64] for v in values if v.strip()]
        return cleaned[:50]


class SiteUpdateRequest(BaseModel):
    """Request to update an existing site tile.

    Every field is `Optional[...] = None` so the "not provided, leave
    unchanged" case can be distinguished from "provided" via
    `model_dump(exclude_unset=True)` — but that same `Optional` typing would
    also accept an *explicit* `null` from the client for fields that must
    never actually be null (name/url/section/open_mode/tags all back
    NOT NULL columns or non-Optional response fields). The validator below
    closes that gap: it only runs when the field is actually present in the
    request (Pydantic skips validators on unset defaults), so omitting a
    field still works exactly as before, but `{"name": null}` now fails
    validation instead of reaching the database. `login_url` is
    deliberately exempt — clearing it back to "use the site URL" is a
    legitimate, supported update.
    """
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    url: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    login_url: Optional[str] = Field(default=None, max_length=2048)
    section: Optional[GallerySection] = None
    tags: Optional[list[str]] = Field(default=None, max_length=50)
    open_mode: Optional[SiteOpenMode] = None

    @field_validator("name", "url", "section", "open_mode", "tags", mode="before")
    @classmethod
    def reject_explicit_null(cls, value: Any, info: Any) -> Any:
        if value is None:
            raise ValueError(f"{info.field_name} cannot be cleared; omit it to leave it unchanged")
        return value


class SiteResponse(BaseModel):
    """A user-pinned external site tile. Never carries secret material."""
    site_id: str
    name: str
    url: str
    login_url: Optional[str] = None
    section: str
    tags: list[str] = Field(default_factory=list)
    open_mode: str
    favicon_url: Optional[str] = None
    has_credential: bool = False
    # Only meaningful for open_mode="embedded" — None until probed at least
    # once (probe_frameable), which happens automatically on create/update
    # when embedded is selected, and on-demand via POST .../probe.
    frameable: Optional[bool] = None
    frameable_checked_at: Optional[str] = None
    frameable_error: Optional[str] = None
    created_at: str
    updated_at: str


class SiteCredentialCreateRequest(BaseModel):
    """Request to save or rotate a site login. `secret` may be a password,
    API token, or session secret — not necessarily a password."""
    username: str = Field(min_length=1, max_length=512)
    secret: str = Field(min_length=1, max_length=8192)
    notes: Optional[str] = Field(default=None, max_length=2048)


class SiteCredentialRevealResponse(BaseModel):
    """Decrypted saved login — returned only from the single reveal endpoint."""
    username: str
    secret: str
    notes: Optional[str] = None
    updated_at: str
    last_accessed_at: Optional[str] = None


class ConnectorCreateRequest(BaseModel):
    """Request to register a pull-based detection connector (SIEM/EDR source).

    `config` never carries secrets — auth type, endpoint paths, pagination,
    and field mapping for generic_rest; presets ignore most of it and fill
    in vendor defaults. `credential_env` maps secret names ("api_key",
    "client_id", "client_secret", "bearer_token") to the *environment
    variable name* holding the real value, never the value itself.
    """
    name: str = Field(min_length=1, max_length=200)
    connector_type: Literal["generic_rest", "microsoft_defender", "crowdstrike_falcon"]
    base_url: str = Field(min_length=1, max_length=2048)
    config: dict[str, Any] = Field(default_factory=dict)
    credential_env: dict[str, str] = Field(default_factory=dict, max_length=10)
    collection: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    poll_interval_minutes: int = Field(default=60, ge=5, le=1440)
    tenant_id: Optional[str] = Field(default=None, max_length=200)
    enabled: bool = True


class ConnectorUpdateRequest(BaseModel):
    """Partial update — only enable/disable and poll interval are mutable
    after creation; edit config/credentials by deleting and recreating."""
    enabled: Optional[bool] = None
    poll_interval_minutes: Optional[int] = Field(default=None, ge=5, le=1440)


class ConnectorPushRequest(BaseModel):
    """Push-ingest detections for a connector without polling upstream.

    Each item is a raw vendor/generic payload that the connector's
    `normalize()` understands — same shape as poll results.
    """
    detections: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


class ConnectorResponse(BaseModel):
    """A configured detection connector. config/credential_env never carry
    secret values — only non-secret settings and environment variable names."""
    id: str
    name: str
    connector_type: str
    base_url: str
    tenant_id: Optional[str] = None
    collection: str
    enabled: bool
    poll_interval_minutes: int
    last_poll_at: Optional[str] = None
    last_poll_status: Optional[str] = None
    last_poll_error: Optional[str] = None
    config: dict[str, Any] = Field(default_factory=dict)
    credential_env: dict[str, str] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    push_token_prefix: Optional[str] = None
    has_push_token: bool = False

