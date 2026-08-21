"""API routes — all REST endpoints and WebSocket/SSE handlers."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Literal, Optional, cast

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import EventSourceResponse, FileResponse
from fastapi.sse import format_sse_event

from black_onyx.api.schemas import (
    ChatRequest,
    ChatResponse,
    CollectionCreateRequest,
    CollectionInfo,
    CreateSessionRequest,
    CreateSessionResponse,
    IngestRequest,
    IngestResponse,
    SearchRequest,
    SearchResponse,
    SearchResult,
    SessionInfo,
    StatusResponse,
    SystemInfo,
    # Threat intelligence schemas
    IOCExtractRequest,
    IOCExtractResponse,
    EnrichRequest,
    EnrichResponse,
    EnrichBatchRequest,
    EnrichBatchResponse,
    STIXExportRequest,
    STIXExportResponse,
    SigmaGenerateRequest,
    SigmaGenerateResponse,
    YARAGenerateRequest,
    YARAGenerateResponse,
    GraphResponse,
    EntityGraphRequest,
    EntityGraphResponse,
    CaseCreateRequest,
    CaseUpdateRequest,
    CasePointRequest,
    CaseIOCRequest,
    CaseNoteRequest,
    CaseResponse,
    CaseListResponse,
    WatchlistCreateRequest,
    WatchlistAddItemsRequest,
    WatchlistResponse,
    ReportGenerateRequest,
    ReportResponse,
    FeedAddRequest,
    FeedPollResponse,
    AnnotationCreateRequest,
    TagRequest,
    NoteCreateRequest,
    BookmarkRequest,
    ConfidenceRequest,
    StatusUpdateRequest,
    ThreatScoreRequest,
    ThreatScoreResponse,
    AttackExtractRequest,
    AdminSettingsUpdate,
    WebhookCreateRequest,
    WebhookEventRequest,
    MispConfigureRequest,
    MispPublishRequest,
    TaxiiCollectionCreateRequest,
    TaxiiApiKeyCreateRequest,
    TaxiiApiKeyUpdateRequest,
    TaxiiPublishRequest,
    PlaybookCreateRequest,
    PlaybookUpdateRequest,
    PlaybookRunRequest,
    OutboundEndpointCreateRequest,
    SiteCreateRequest,
    SiteUpdateRequest,
    SiteResponse,
    SiteCredentialCreateRequest,
    SiteCredentialRevealResponse,
    validate_site_url,
)
from black_onyx.api.service import get_service
from black_onyx.llm.base import ChatMessage
from black_onyx.auth.dependencies import current_principal, require_admin, require_analyst
from black_onyx.auth.context import get_auth_service
from black_onyx.auth.middleware import session_cookie_name
from black_onyx.auth.service import Principal
from black_onyx.favicon_fetcher import fetch_and_cache_favicon
from black_onyx.site_credentials import SiteCredentialError, SiteCredentialRateLimited

logger = logging.getLogger(__name__)

router = APIRouter()


# ===========================
# System info
# ===========================

@router.get("/api/v1/info", response_model=SystemInfo)
async def get_info() -> SystemInfo:
    """Get system information."""
    service = get_service()
    # Qdrant probing is blocking and retries for many seconds when the vector
    # store is unreachable; keep it off the event loop so one slow probe cannot
    # stall every other in-flight request.
    info = await asyncio.to_thread(service.get_system_info)
    return SystemInfo(**info)


@router.get("/api/v1/health", response_model=StatusResponse)
async def health_check() -> StatusResponse:
    """Health check endpoint."""
    return StatusResponse(status="ok", message="Black Onyx API is running")


@router.get("/api/v1/capabilities")
async def capabilities() -> dict[str, Any]:
    """Return safe feature status without configuration secrets or paths."""
    service = get_service()
    import importlib.util
    web_cfg = service.settings.web_search
    searxng_ok = False
    if web_cfg.enabled and web_cfg.searxng_url:
        try:
            from black_onyx.websearch.searxng import searxng_reachable
            searxng_ok = searxng_reachable(web_cfg.searxng_url, timeout=3)
        except Exception:
            searxng_ok = False
    firecrawl_configured = bool(
        service.runtime_secret_status().get("firecrawl_api_key")
    )
    configured = {
        "rag": service.settings.llm.rag.enabled,
        "image": service.settings.image.enabled,
        "enrichment": service.settings.enrichment.enabled,
        "feeds": service.settings.feeds.enabled,
        "mitre_attack": service.settings.threat_intel.mitre_attack_enabled,
        "web_search": web_cfg.enabled and searxng_ok,
        "pdf": importlib.util.find_spec("weasyprint") is not None,
    }
    reasons = {
        name: None if enabled else "Disabled by configuration or an optional dependency is unavailable"
        for name, enabled in configured.items()
    }
    if web_cfg.enabled and not searxng_ok:
        reasons["web_search"] = "SearXNG is unreachable or web search is misconfigured"
    elif not web_cfg.enabled:
        reasons["web_search"] = "Disabled by configuration or an optional dependency is unavailable"
    return {
        "features": configured,
        "disabled_reasons": reasons,
        "llm_provider": service.settings.llm.provider,
        "enrichment_providers": service.settings.enrichment.providers if service.settings.enrichment.enabled else [],
        "rag": {
            "enabled": service.settings.llm.rag.enabled,
            "collections": list(service.settings.llm.rag.collections or []),
            "top_k": service.settings.llm.rag.top_k,
        },
        "web_search": {
            "enabled": web_cfg.enabled,
            "searxng_reachable": searxng_ok,
            "firecrawl_configured": firecrawl_configured,
            "collection": web_cfg.collection,
        },
    }


def _admin_settings_payload() -> dict[str, Any]:
    service = get_service()
    settings = service.settings
    provider = lambda value, base_url=None: {
        **({"base_url": base_url} if base_url is not None else {}),
        "model": value.model,
        "temperature": value.temperature,
        "max_tokens": value.max_tokens,
    }
    return {
        "llm": {
            "provider": settings.llm.provider,
            "local": provider(settings.llm.local, settings.llm.local.base_url),
            "openai": provider(settings.llm.openai),
            "openai_compatible": provider(
                settings.llm.openai_compatible, settings.llm.openai_compatible.base_url
            ),
            "claude": provider(settings.llm.claude),
            "gemini": provider(settings.llm.gemini),
            "llama_cpp": {
                "n_ctx": settings.llm.llama_cpp.n_ctx,
                "n_gpu_layers": settings.llm.llama_cpp.n_gpu_layers,
                "temperature": settings.llm.llama_cpp.temperature,
                "max_tokens": settings.llm.llama_cpp.max_tokens,
            },
            "rag": {
                "enabled": settings.llm.rag.enabled,
                "collections": settings.llm.rag.collections,
                "top_k": settings.llm.rag.top_k,
                "score_threshold": settings.llm.rag.score_threshold,
                "chunk_context_window": settings.llm.rag.chunk_context_window,
            },
        },
        "ingestion": {
            key: getattr(settings.ingestion, key) for key in (
                "collection_name", "batch_size", "max_workers", "max_upload_bytes",
                "max_upload_files", "enable_ner", "enable_classifier",
                "enable_code_detection", "enable_image_extraction",
            )
        },
        "chunking": {
            key: getattr(settings.chunking, key)
            for key in ("chunk_size", "chunk_overlap", "sentence_aware")
        },
        "feeds": {
            key: getattr(settings.feeds, key) for key in (
                "enabled", "poll_interval_minutes", "allowed_hosts",
                "max_response_bytes", "max_concurrent",
            )
        },
        "qdrant": {
            key: getattr(settings.qdrant, key)
            for key in ("host", "port", "prefer_grpc", "https", "timeout")
        },
        "web_search": {
            key: getattr(settings.web_search, key) for key in (
                "enabled", "searxng_url", "max_results", "max_tool_rounds",
                "scrape_top_k", "timeout_seconds",
            )
        },
        "enrichment": {
            key: getattr(settings.enrichment, key) for key in (
                "enabled", "providers", "cache_ttl_hours", "timeout_seconds", "max_concurrent",
                "auto_enrich_on_match",
            )
        },
        "secrets": service.runtime_secret_status(),
    }


@router.get("/api/v1/admin/settings")
async def get_admin_settings(_: Principal = Depends(require_admin)) -> dict[str, Any]:
    """Return editable runtime configuration without secret values or sensitive paths."""
    return _admin_settings_payload()


@router.put("/api/v1/admin/settings")
async def update_admin_settings(
    request: AdminSettingsUpdate,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    """Validate, encrypt, persist, and activate administrator runtime settings."""
    config = request.model_dump(exclude={"secrets"})
    secret_updates = {
        name: value.get_secret_value() if value is not None else None
        for name, value in request.secrets.model_dump().items()
    }
    service = get_service()
    service.update_runtime_settings(config, secret_updates, principal.user_id)
    # The seeded auto-enrich playbook is not itself a settings field — it's the
    # concrete mechanism behind the enrichment.auto_enrich_on_match toggle, so
    # keep it create/enable/disable-in-sync with whatever was just saved.
    service.playbook_manager.ensure_default_watchlist_enrich_playbook(
        request.enrichment.auto_enrich_on_match,
    )
    return _admin_settings_payload()


@router.get("/api/v1/admin/sla-policy")
async def get_sla_policy(_: Principal = Depends(require_admin)) -> dict[str, Any]:
    hours = get_service().case_manager.get_sla_hours()
    return {"hours": hours, "unit": "hours"}


@router.put("/api/v1/admin/sla-policy")
async def update_sla_policy(
    body: dict[str, Any],
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    hours = body.get("hours") if isinstance(body.get("hours"), dict) else body
    try:
        updated = get_service().case_manager.set_sla_hours(hours)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"hours": updated, "unit": "hours"}


# ===========================
# Ingestion
# ===========================

@router.post("/api/v1/ingest", response_model=IngestResponse)
async def start_ingestion(
    request: IngestRequest,
    principal: Principal = Depends(require_admin),
) -> IngestResponse:
    """Start an ingestion job (runs in background)."""
    import threading

    from black_onyx.pipeline.checkpoint import CheckpointManager
    from black_onyx.pipeline.progress import ProgressTracker

    service = get_service()
    requested = Path(request.directory).resolve()
    allowed = [Path(root).resolve() for root in service.settings.ingestion.allowed_data_roots]
    allowed.append((Path(service.settings.storage.state_dir) / "uploads" / principal.user_id).resolve())
    if not any(requested == root or root in requested.parents for root in allowed):
        raise HTTPException(status_code=403, detail="Directory is outside configured data roots")
    if not requested.is_dir():
        raise HTTPException(status_code=400, detail="Ingestion directory does not exist")
    job_id = str(uuid.uuid4())

    # Create ingestor
    ingestor = service.create_ingestor(
        enable_ner=request.enable_ner,
        enable_classifier=request.enable_classifier,
        enable_image_extraction=request.enable_image_extraction,
    )

    # Create progress tracker with WebSocket broadcast callback
    tracker = ProgressTracker()
    service.register_job(
        job_id, ingestor, tracker, principal.user_id,
        {"collection": request.collection},
    )

    # Run ingestion in a background thread
    def run_ingestion() -> None:
        try:
            checkpoint = CheckpointManager(service.settings.storage.state_dir)
            stats = ingestor.process_directory(
                directory=request.directory,
                collection_name=request.collection,
                progress_tracker=tracker,
                checkpoint_manager=checkpoint,
            )
            final_status = "stopped" if stats.get("stopped") else "completed"
            service.update_job_status(job_id, final_status, stats)
            logger.info(f"Ingestion job {job_id} completed: {stats}")
        except Exception as e:
            service.update_job_status(job_id, "failed")
            logger.error(f"Ingestion job {job_id} failed: {e}")

    thread = threading.Thread(target=run_ingestion, daemon=True)
    thread.start()

    return IngestResponse(job_id=job_id, status="started", message=f"Ingesting from {request.directory}")


@router.post("/api/v1/ingest/upload", response_model=IngestResponse)
async def upload_for_ingestion(
    files: list[UploadFile] = File(...),
    collection: str = Form("all-knowledge"),
    principal: Principal = Depends(current_principal),
) -> IngestResponse:
    """Store bounded uploads under application state and start ingestion."""
    import shutil
    service = get_service()
    limits = service.settings.ingestion
    if len(files) > limits.max_upload_files:
        raise HTTPException(status_code=413, detail="Too many uploaded files")
    job_id = str(uuid.uuid4())
    upload_root = Path(service.settings.storage.state_dir) / "uploads" / principal.user_id / job_id
    upload_root.mkdir(parents=True, exist_ok=False)
    total = 0
    try:
        for uploaded in files:
            raw_name = (uploaded.filename or "upload.bin").replace("\\", "/")
            parts = [part for part in raw_name.split("/") if part not in {"", "."}]
            if not parts or any(part == ".." or "\x00" in part for part in parts):
                raise HTTPException(status_code=400, detail="Invalid upload filename")
            destination = upload_root.joinpath(*parts)
            if destination.exists():
                raise HTTPException(status_code=409, detail=f"Duplicate upload path: {raw_name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as target:
                while chunk := await uploaded.read(1024 * 1024):
                    total += len(chunk)
                    if total > limits.max_upload_bytes:
                        raise HTTPException(status_code=413, detail="Upload size limit exceeded")
                    target.write(chunk)
    except Exception:
        shutil.rmtree(upload_root, ignore_errors=True)
        raise
    request = IngestRequest(directory=str(upload_root), collection=collection)
    return await start_ingestion(request, principal)


@router.get("/api/v1/ingest/{job_id}/status")
async def get_ingest_status(
    job_id: str, principal: Principal = Depends(current_principal)
) -> dict[str, Any]:
    """Get the status of an ingestion job."""
    service = get_service()
    job = service.get_job(job_id)
    if not job or job["owner_user_id"] != principal.user_id:
        record = service.get_job_record(job_id, principal.user_id)
        if not record:
            raise HTTPException(status_code=404, detail="Job not found")
        return record
    tracker = job["tracker"]
    status = tracker.get_status()
    status["job_id"] = job_id
    status["job_status"] = job["status"]
    return status


@router.get("/api/v1/jobs")
async def list_jobs(
    limit: int = 50, principal: Principal = Depends(current_principal)
) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    rows = get_auth_service().db._conn.execute(
        "SELECT job_id,job_type,status,detail,created_at,updated_at FROM jobs "
        "WHERE owner_user_id=? AND expires_at>? ORDER BY updated_at DESC LIMIT ?",
        (principal.user_id, datetime.now(timezone.utc).isoformat(), limit),
    ).fetchall()
    return {"jobs": [{**dict(row), "detail": json.loads(row["detail"])} for row in rows]}


@router.post("/api/v1/ingest/{job_id}/stop", response_model=StatusResponse)
async def stop_ingestion(
    job_id: str, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Stop a running ingestion job."""
    service = get_service()
    job = service.get_job(job_id)
    if not job or job["owner_user_id"] != principal.user_id:
        raise HTTPException(status_code=404, detail="Job not found")
    job["ingestor"].stop()
    service.update_job_status(job_id, "stopping")
    return StatusResponse(status="stopping", message=f"Stopping job {job_id}")


# ===========================
# WebSocket for live ingestion progress
# ===========================

@router.websocket("/api/v1/ws/ingest/{job_id}")
async def ingest_progress_websocket(websocket: WebSocket, job_id: str) -> None:
    """WebSocket endpoint for live ingestion progress updates."""
    auth = get_auth_service()
    config = auth.config
    if not config.allows_origin(websocket.headers.get("origin")):
        await websocket.close(code=4403)
        return
    token = websocket.cookies.get(session_cookie_name(config), "")
    session = auth.principal_for_session(token) if token else None
    if not session:
        await websocket.close(code=4401)
        return
    principal, _ = session
    service = get_service()
    job = service.get_job(job_id)

    if not job or job["owner_user_id"] != principal.user_id:
        await websocket.close(code=4404)
        return
    await websocket.accept()

    tracker = job["tracker"]
    last_processed = -1

    try:
        while True:
            status = tracker.get_status()
            if status["processed"] != last_processed or status["running"]:
                await websocket.send_json({
                    "event": "progress",
                    "job_id": job_id,
                    **status,
                })
                last_processed = status["processed"]

            if job["status"] in ("completed", "failed", "stopped"):
                await websocket.send_json({
                    "event": "complete",
                    "job_id": job_id,
                    "status": job["status"],
                    **status,
                })
                break

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        logger.debug(f"WebSocket disconnected for job {job_id}")
    except Exception as e:
        logger.error(f"WebSocket error for job {job_id}: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            logger.debug("WebSocket was already closed for job %s", job_id)


# ===========================
# Search
# ===========================

@router.post("/api/v1/search", response_model=SearchResponse)
async def search(request: SearchRequest) -> SearchResponse:
    """Semantic search across a collection."""
    service = get_service()
    embedding_model = service.embedding_model
    store = service.qdrant_store

    query_vector = embedding_model.encode_single(request.query)
    if not query_vector:
        raise HTTPException(status_code=500, detail="Failed to encode query")

    results = store.search(
        collection_name=request.collection,
        query_vector=query_vector,
        limit=request.limit,
        score_threshold=request.score_threshold,
        using=request.vector_name,
        with_payload=True,
        with_vectors=False,
    )

    search_results = [
        SearchResult(
            id=str(r.id),
            score=r.score,
            payload=r.payload or {},
            collection=request.collection,
        )
        for r in results
    ]

    return SearchResponse(query=request.query, results=search_results, total=len(search_results))


@router.post("/api/v1/search/image", response_model=SearchResponse)
async def image_search(
    image: UploadFile = File(...),
    collection: str = Form("all-knowledge"),
    limit: int = Form(10, ge=1, le=100),
    score_threshold: float = Form(0.0, ge=0.0, le=1.0),
    principal: Principal = Depends(current_principal),
) -> SearchResponse:
    """Image-to-image search from a bounded browser upload."""
    service = get_service()
    clip_model = service.clip_model
    store = service.qdrant_store

    if clip_model is None:
        raise HTTPException(status_code=400, detail="CLIP model not available. Install image dependencies.")
    if not (image.content_type or "").startswith("image/"):
        raise HTTPException(status_code=415, detail="An image upload is required")
    suffix = Path(image.filename or "").suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}:
        raise HTTPException(status_code=415, detail="Unsupported image type")
    upload_dir = (
        Path(service.settings.storage.state_dir) / "uploads" / principal.user_id / str(uuid.uuid4())
    )
    upload_dir.mkdir(parents=True, exist_ok=False)
    upload_path = upload_dir / f"query{suffix}"
    size = 0
    try:
        with upload_path.open("wb") as target:
            while chunk := await image.read(1024 * 1024):
                size += len(chunk)
                if size > service.settings.ingestion.max_upload_bytes:
                    raise HTTPException(status_code=413, detail="Upload size limit exceeded")
                target.write(chunk)
        clip_vector = clip_model.embed_image(str(upload_path))
    finally:
        upload_path.unlink(missing_ok=True)
        upload_dir.rmdir()
    if not clip_vector:
        raise HTTPException(status_code=500, detail="Failed to encode image")

    results = store.search(
        collection_name=collection,
        query_vector=clip_vector,
        limit=limit,
        score_threshold=score_threshold,
        using="clip",
        with_payload=True,
        with_vectors=False,
    )

    search_results = [
        SearchResult(
            id=str(r.id),
            score=r.score,
            payload=r.payload or {},
            collection=collection,
        )
        for r in results
    ]

    return SearchResponse(query=f"image:{Path(image.filename or 'upload').name}", results=search_results, total=len(search_results))


# ===========================
# Collections
# ===========================

@router.get("/api/v1/collections", response_model=list[CollectionInfo])
async def list_collections() -> list[CollectionInfo]:
    """List all Qdrant collections."""
    service = get_service()
    collections = service.qdrant_store.list_collections()
    return [CollectionInfo(**col) for col in collections]


@router.post("/api/v1/collections", response_model=CollectionInfo)
async def create_collection(
    request: CollectionCreateRequest,
    _: Principal = Depends(require_admin),
) -> CollectionInfo:
    """Create an empty collection using the configured embedding layout."""
    service = get_service()
    try:
        service.ensure_collection(request.name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Collection creation failed")
        raise HTTPException(status_code=500, detail="Collection creation failed")
    info = service.qdrant_store.get_collection_info(request.name)
    if not info:
        raise HTTPException(status_code=500, detail="Collection created but could not be loaded")
    return CollectionInfo(**info)


@router.get("/api/v1/collections/{name}", response_model=CollectionInfo)
async def get_collection(name: str) -> CollectionInfo:
    """Get info about a specific collection."""
    service = get_service()
    info = service.qdrant_store.get_collection_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Collection not found: {name}")
    return CollectionInfo(**info)


@router.delete("/api/v1/collections/{name}", response_model=StatusResponse)
async def delete_collection(name: str, _: Principal = Depends(require_admin)) -> StatusResponse:
    """Delete a collection."""
    service = get_service()
    try:
        service.qdrant_store.delete_collection(name)
        return StatusResponse(status="ok", message=f"Deleted collection: {name}")
    except Exception:
        logger.exception("Collection deletion failed")
        raise HTTPException(status_code=500, detail="Collection deletion failed")


@router.delete("/api/v1/collections/{name}/points/{point_id}", response_model=StatusResponse)
async def delete_collection_point(
    name: str, point_id: str, _: Principal = Depends(require_admin)
) -> StatusResponse:
    """Delete one indexed evidence point."""
    service = get_service()
    point = service.qdrant_store.get_point(name, point_id)
    if point is None:
        raise HTTPException(status_code=404, detail="Point not found")
    service.qdrant_store.delete_point(name, point_id)
    return StatusResponse(status="ok", message=f"Deleted point {point_id}")


@router.get("/api/v1/collections/{name}/points")
async def list_points(name: str, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
    """List points in a collection (paginated)."""
    service = get_service()
    limit = max(1, min(limit, 100))
    offset: int | str | None = None
    if cursor:
        try:
            decoded = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
            if decoded.get("collection") != name or decoded.get("offset") is None:
                raise ValueError
            offset = decoded["offset"]
        except (ValueError, TypeError, json.JSONDecodeError):
            raise HTTPException(status_code=422, detail="Invalid collection cursor")
    points, next_offset = service.qdrant_store.scroll(
        collection_name=name,
        limit=limit,
        offset=offset,
        with_payload=True,
        with_vectors=False,
    )
    return {
        "points": [
            {"id": str(p.id), "payload": p.payload}
            for p in points
        ],
        "next_cursor": (
            base64.urlsafe_b64encode(
                json.dumps({"collection": name, "offset": next_offset}, separators=(",", ":")).encode()
            ).decode().rstrip("=") if next_offset is not None else None
        ),
    }


# ===========================
# Chat
# ===========================

@router.post("/api/v1/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest, principal: Principal = Depends(current_principal)
) -> ChatResponse:
    """Non-streaming chat with optional RAG."""
    service = get_service()
    session_mgr = service.session_manager
    if request.images:
        raise HTTPException(status_code=422, detail="Chat images must be uploaded, not supplied as server paths")

    # Get or create session
    if request.session_id and not session_mgr.is_owner(request.session_id, principal.user_id):
        raise HTTPException(status_code=404, detail="Session not found")
    provider_name = (
        session_mgr.get_session(request.session_id).get("provider")
        if request.session_id else request.provider
    ) or service.settings.llm.provider
    try:
        provider = service.get_llm_provider(provider_name)
    except ValueError:
        raise HTTPException(status_code=422, detail="Unsupported LLM provider")
    session_id = request.session_id or session_mgr.create_session(
        owner_id=principal.user_id, provider=provider_name
    )

    # Get history
    history = session_mgr.get_messages(session_id)

    # Build user message
    user_msg = ChatMessage(role="user", content=request.message, images=request.images)

    if request.use_rag and service.settings.llm.rag.enabled:
        rag = service.get_rag_engine(provider_name)
        response, chunks = rag.chat(
            request.message,
            history=history,
            collections=request.collections,
        )
        sources = [c.to_dict() for c in chunks]
    else:
        # Direct chat without RAG
        messages = history + [user_msg]
        response = provider.chat(
            messages=messages,
            system_prompt=service.settings.llm.rag.system_prompt,
        )
        sources = []

    # Save messages
    session_mgr.add_message(session_id, "user", request.message, request.images)
    session_mgr.add_message(session_id, "assistant", response.text)

    return ChatResponse(
        response=response.text,
        session_id=session_id,
        sources=sources,
        model=response.model,
    )


@router.post("/api/v1/chat/images", response_model=ChatResponse)
async def chat_with_images(
    images: list[UploadFile] = File(...),
    message: str = Form(..., min_length=1, max_length=100_000),
    session_id: Optional[str] = Form(None),
    provider: Optional[str] = Form(None),
    principal: Principal = Depends(current_principal),
) -> ChatResponse:
    """Send bounded image uploads to a vision-capable provider.

    Uploaded files exist only for the duration of the provider call. Their
    server paths and encoded contents are never accepted from, or returned to,
    the browser and are not persisted in chat history.
    """
    import shutil

    service = get_service()
    session_mgr = service.session_manager
    if not images or len(images) > 5:
        raise HTTPException(status_code=413, detail="Upload between one and five images")
    if session_id and not session_mgr.is_owner(session_id, principal.user_id):
        raise HTTPException(status_code=404, detail="Session not found")

    allowed_providers = {"local", "openai", "openai_compatible", "claude", "gemini", "llama_cpp"}
    provider_name = (
        session_mgr.get_session(session_id).get("provider") if session_id else provider
    ) or service.settings.llm.provider
    if provider_name not in allowed_providers:
        raise HTTPException(status_code=422, detail="Unsupported LLM provider")
    try:
        llm_provider = service.get_llm_provider(provider_name)
    except ValueError:
        raise HTTPException(status_code=422, detail="Unsupported LLM provider")
    if not llm_provider.supports_images:
        raise HTTPException(status_code=422, detail="Selected LLM provider does not support images")

    upload_dir = (
        Path(service.settings.storage.state_dir) / "uploads" / principal.user_id / str(uuid.uuid4())
    )
    upload_dir.mkdir(parents=True, exist_ok=False)
    paths: list[str] = []
    total = 0
    allowed_suffixes = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}
    try:
        for index, image in enumerate(images):
            suffix = Path(image.filename or "").suffix.lower()
            if not (image.content_type or "").startswith("image/") or suffix not in allowed_suffixes:
                raise HTTPException(status_code=415, detail="Unsupported image type")
            target = upload_dir / f"image-{index}{suffix}"
            with target.open("wb") as output:
                while chunk := await image.read(1024 * 1024):
                    total += len(chunk)
                    if total > service.settings.ingestion.max_upload_bytes:
                        raise HTTPException(status_code=413, detail="Upload size limit exceeded")
                    output.write(chunk)
            if target.stat().st_size == 0:
                raise HTTPException(status_code=400, detail="Empty image upload")
            with target.open("rb") as uploaded_file:
                header = uploaded_file.read(16)
            recognized = (
                header.startswith(b"\x89PNG\r\n\x1a\n")
                or header.startswith(b"\xff\xd8\xff")
                or header.startswith((b"GIF87a", b"GIF89a", b"BM", b"II*\x00", b"MM\x00*"))
                or (header.startswith(b"RIFF") and header[8:12] == b"WEBP")
            )
            if not recognized:
                raise HTTPException(status_code=415, detail="Image content does not match a supported format")
            paths.append(str(target))

        sid = session_id or session_mgr.create_session(
            owner_id=principal.user_id, provider=provider_name
        )
        history = session_mgr.get_messages(sid)
        response = llm_provider.chat(
            messages=history + [ChatMessage(role="user", content=message, images=paths)],
            system_prompt=service.settings.llm.rag.system_prompt,
        )
        session_mgr.add_message(sid, "user", f"{message}\n\n[{len(paths)} image(s) attached]")
        session_mgr.add_message(sid, "assistant", response.text)
        return ChatResponse(
            response=response.text,
            session_id=sid,
            sources=[],
            model=response.model,
        )
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


@router.post("/api/v1/chat/stream")
async def chat_stream(
    request: ChatRequest,
    principal: Principal = Depends(current_principal),
) -> EventSourceResponse:
    """Streaming chat via Server-Sent Events (SSE).

    Query params:
        message: The chat message
        session_id: Optional session ID
        use_rag: Whether to use RAG (default true)
        collections: Comma-separated collection names (optional)
    """
    service = get_service()
    session_mgr = service.session_manager
    if request.images:
        raise HTTPException(status_code=422, detail="Chat images must be uploaded, not supplied as server paths")

    # Get or create session
    message = request.message
    if request.session_id and not session_mgr.is_owner(request.session_id, principal.user_id):
        raise HTTPException(status_code=404, detail="Session not found")
    provider_name = (
        session_mgr.get_session(request.session_id).get("provider")
        if request.session_id else request.provider
    ) or service.settings.llm.provider
    try:
        provider = service.get_llm_provider(provider_name)
    except ValueError:
        raise HTTPException(status_code=422, detail="Unsupported LLM provider")
    sid = request.session_id or session_mgr.create_session(
        owner_id=principal.user_id, provider=provider_name
    )
    history = session_mgr.get_messages(sid)

    # Parse collections
    colls = request.collections
    use_web = bool(request.use_web_search and service.settings.web_search.enabled)

    async def event_generator() -> AsyncIterator[dict[str, str]]:
        # Send session ID first
        yield {"event": "session", "data": json.dumps({"session_id": sid})}

        if use_web:
            from black_onyx.websearch.orchestrator import WebSearchOrchestrator

            rag_context = ""
            if request.use_rag and service.settings.llm.rag.enabled:
                rag = service.get_rag_engine(provider_name)
                chunks = rag.retrieve(message, collections=colls)
                for chunk in chunks:
                    yield {"event": "source", "data": json.dumps(chunk.to_dict())}
                if chunks:
                    prompt = rag.build_context_prompt(message, chunks)
                    marker = "\n=== USER QUESTION ===\n"
                    rag_context = prompt.rsplit(marker, 1)[0] if marker in prompt else prompt
            orchestrator = WebSearchOrchestrator(
                service=service, llm=provider, session_id=sid,
            )
            async for event_type, data in orchestrator.run(
                message, history=history, rag_context=rag_context,
            ):
                if event_type == "source":
                    yield {"event": "source", "data": json.dumps(data)}
                elif event_type == "tool":
                    yield {"event": "tool", "data": json.dumps(data)}
                elif event_type == "token":
                    yield {"event": "token", "data": data}
        elif request.use_rag and service.settings.llm.rag.enabled:
            rag = service.get_rag_engine(provider_name)
            async for event_type, data in rag.chat_stream(
                message,
                history=history,
                collections=colls,
            ):
                if event_type == "context":
                    yield {"event": "source", "data": json.dumps(data.to_dict())}
                elif event_type == "token":
                    yield {"event": "token", "data": data}
        else:
            from black_onyx.llm.base import ChatMessage as CM
            messages = history + [CM(role="user", content=message)]
            async for token in provider.chat_stream(
                messages=messages,
                system_prompt=service.settings.llm.rag.system_prompt,
            ):
                yield {"event": "token", "data": token}

        yield {"event": "done", "data": ""}

    # Collect full response for session storage
    full_response_parts: list[str] = []

    async def wrapped_generator() -> AsyncIterator[bytes]:
        # FastAPI's EventSourceResponse is a StreamingResponse marker. Yielding
        # dicts (sse-starlette style) raises AttributeError on .encode(); encode
        # the SSE wire format explicitly so tokens stay raw for the browser client.
        try:
            async for event in event_generator():
                if event.get("event") == "token":
                    full_response_parts.append(event.get("data", ""))
                yield format_sse_event(
                    event=event.get("event"),
                    data_str=event.get("data", ""),
                )
        except Exception as exc:
            logger.exception("Chat stream failed for session %s", sid)
            error_text = f"Error: {exc}"
            full_response_parts.append(error_text)
            yield format_sse_event(event="token", data_str=error_text)
            yield format_sse_event(event="done", data_str="")
        # Save to session after streaming completes
        full_text = "".join(full_response_parts)
        session_mgr.add_message(sid, "user", message)
        session_mgr.add_message(sid, "assistant", full_text)

    return EventSourceResponse(cast(Any, wrapped_generator()))


# ===========================
# Chat sessions
# ===========================

@router.post("/api/v1/sessions", response_model=CreateSessionResponse)
async def create_session(
    request: CreateSessionRequest, principal: Principal = Depends(current_principal)
) -> CreateSessionResponse:
    """Create a new chat session."""
    service = get_service()
    provider = request.provider or service.settings.llm.provider
    session_id = service.session_manager.create_session(
        title=request.title,
        provider=provider,
        owner_id=principal.user_id,
    )
    return CreateSessionResponse(session_id=session_id)


@router.get("/api/v1/sessions", response_model=list[SessionInfo])
async def list_sessions(principal: Principal = Depends(current_principal)) -> list[SessionInfo]:
    """List all chat sessions."""
    service = get_service()
    sessions = service.session_manager.list_sessions(owner_id=principal.user_id)
    return [SessionInfo(**s) for s in sessions]


@router.get("/api/v1/sessions/{session_id}/messages")
async def get_session_messages(
    session_id: str, principal: Principal = Depends(current_principal)
) -> dict[str, Any]:
    """Get all messages in a session."""
    service = get_service()
    if not service.session_manager.is_owner(session_id, principal.user_id):
        raise HTTPException(status_code=404, detail="Session not found")
    messages = service.session_manager.get_messages(session_id)
    return {
        "session_id": session_id,
        "messages": [m.to_dict() for m in messages],
    }


@router.delete("/api/v1/sessions/{session_id}", response_model=StatusResponse)
async def delete_session(
    session_id: str, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Delete a chat session."""
    service = get_service()
    if not service.session_manager.is_owner(session_id, principal.user_id):
        raise HTTPException(status_code=404, detail="Session not found")
    service.session_manager.delete_session(session_id)
    return StatusResponse(status="ok", message=f"Deleted session: {session_id}")


# ===========================
# LLM providers
# ===========================

@router.get("/api/v1/llm/providers")
async def list_providers() -> dict[str, Any]:
    """List available LLM providers."""
    from black_onyx.llm.factory import list_available_providers
    return {"providers": list_available_providers()}


@router.get("/api/v1/llm/test")
async def test_llm() -> dict[str, Any]:
    """Test the current LLM provider connection."""
    service = get_service()
    return service.llm_provider.test_connection()


# ===========================
# IOC Extraction
# ===========================

@router.post("/api/v1/ioc/extract", response_model=IOCExtractResponse)
async def extract_iocs(req: IOCExtractRequest) -> IOCExtractResponse:
    """Extract IOCs from text."""
    from black_onyx.extraction.ioc import extract_iocs
    result = extract_iocs(req.text, include_defanged=req.include_defanged)
    return IOCExtractResponse(iocs=result.to_dict(), total_count=result.total_count)


@router.post("/api/v1/ioc/defang")
async def defang_iocs(iocs: list[str]) -> dict[str, list[str]]:
    """Defang a list of IOCs for safe sharing."""
    from black_onyx.extraction.ioc import defang_ioc
    return {"defanged": [defang_ioc(i) for i in iocs]}


@router.post("/api/v1/ioc/refang")
async def refang_iocs(iocs: list[str]) -> dict[str, list[str]]:
    """Refang a list of defanged IOCs."""
    from black_onyx.extraction.ioc import refang_ioc
    return {"refanged": [refang_ioc(i) for i in iocs]}


# ===========================
# IOC Enrichment
# ===========================

@router.post("/api/v1/enrich", response_model=EnrichResponse)
async def enrich_ioc(req: EnrichRequest) -> EnrichResponse:
    """Enrich a single IOC."""
    service = get_service()
    mgr = service.enrichment_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Enrichment not enabled in config")
    results = await mgr.enrich_ioc(req.ioc_type, req.ioc_value, req.providers)
    return EnrichResponse(
        ioc_value=req.ioc_value,
        results=[r.to_dict() for r in results],
    )


@router.post("/api/v1/enrich/batch", response_model=EnrichBatchResponse)
async def enrich_batch(req: EnrichBatchRequest) -> EnrichBatchResponse:
    """Enrich multiple IOCs."""
    service = get_service()
    mgr = service.enrichment_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Enrichment not enabled in config")
    ioc_list = [(d.get("ioc_type", ""), d.get("ioc_value", "")) for d in req.iocs]
    results = await mgr.enrich_batch(ioc_list)
    return EnrichBatchResponse(
        results={k: [r.to_dict() for r in v] for k, v in results.items()}
    )


@router.get("/api/v1/enrich/providers")
async def list_enrichment_providers() -> dict[str, Any]:
    """List configured enrichment providers."""
    service = get_service()
    mgr = service.enrichment_manager
    if mgr is None:
        return {"providers": [], "enabled": False}
    return {"providers": mgr.list_providers(), "enabled": True}


@router.post("/api/v1/threat/score", response_model=ThreatScoreResponse)
async def compute_threat_score(req: ThreatScoreRequest) -> ThreatScoreResponse:
    """Enrich an IOC and compute a composite threat score."""
    service = get_service()
    mgr = service.enrichment_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Enrichment not enabled in config")
    from black_onyx.enrichment.scorer import ThreatScorer
    results = await mgr.enrich_ioc(req.ioc_type, req.ioc_value, req.providers)
    scorer = ThreatScorer()
    score = scorer.score_ioc(req.ioc_value, req.ioc_type, results)
    return ThreatScoreResponse(
        ioc_value=score.ioc_value,
        ioc_type=score.ioc_type,
        score=score.score,
        verdict=score.verdict,
        contributing_providers=score.contributing_providers,
        malicious_count=score.malicious_count,
        total_providers=score.total_providers,
    )


# ===========================
# MITRE ATT&CK
# ===========================

@router.get("/api/v1/attack/technique/{technique_id}")
async def get_attack_technique(technique_id: str) -> dict[str, Any]:
    """Get details for a MITRE ATT&CK technique."""
    service = get_service()
    mapper = service.attack_mapper
    if mapper is None:
        raise HTTPException(status_code=400, detail="MITRE ATT&CK not enabled in config")
    tech = mapper.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return {"technique_id": technique_id, **tech}


@router.post("/api/v1/attack/extract")
async def extract_attack_techniques(req: AttackExtractRequest) -> dict[str, Any]:
    """Extract MITRE ATT&CK technique IDs from text."""
    service = get_service()
    mapper = service.attack_mapper
    if mapper is None:
        raise HTTPException(status_code=400, detail="MITRE ATT&CK not enabled in config")
    return {"techniques": mapper.extract_techniques_from_text(req.text)}


@router.post("/api/v1/attack/heatmap")
async def attack_heatmap(technique_ids: list[str]) -> dict[str, Any]:
    """Generate ATT&CK heatmap data."""
    service = get_service()
    mapper = service.attack_mapper
    if mapper is None:
        raise HTTPException(status_code=400, detail="MITRE ATT&CK not enabled in config")
    return mapper.generate_heatmap_data(technique_ids)


@router.get("/api/v1/attack/search")
async def search_attack_techniques(q: str, limit: int = 20) -> dict[str, Any]:
    """Search ATT&CK techniques by name or description."""
    service = get_service()
    mapper = service.attack_mapper
    if mapper is None:
        raise HTTPException(status_code=400, detail="MITRE ATT&CK not enabled in config")
    return {"techniques": mapper.search_techniques(q, limit)}


@router.post("/api/v1/admin/attack/refresh")
async def refresh_attack_data(
    principal: Principal = Depends(require_admin),
) -> StatusResponse:
    """Atomically refresh ATT&CK data from a configured, digest-pinned source."""
    from black_onyx.threat.attack_downloader import download_attack_data

    service = get_service()
    config = service.settings.threat_intel
    if not config.mitre_attack_source_url or not config.mitre_attack_source_sha256:
        raise HTTPException(status_code=409, detail="A pinned ATT&CK source is not configured")
    succeeded = await asyncio.to_thread(
        download_attack_data,
        config.mitre_attack_data_dir,
        config.mitre_attack_source_url,
        config.mitre_attack_source_sha256,
        config.mitre_attack_max_bytes,
    )
    if not succeeded:
        raise HTTPException(status_code=502, detail="ATT&CK refresh failed validation")
    service._attack_mapper = None
    get_auth_service().audit(principal, "attack.refresh")
    return StatusResponse(status="ok", message="ATT&CK cache refreshed")


# ===========================
# STIX Export
# ===========================

@router.post("/api/v1/stix/export", response_model=STIXExportResponse)
async def export_stix(req: STIXExportRequest) -> STIXExportResponse:
    """Export IOCs as a STIX 2.1 bundle."""
    from black_onyx.threat.stix_exporter import STIXExporter
    exporter = STIXExporter()
    bundle = exporter.export_bundle(
        iocs=req.iocs,
        techniques=req.techniques,
    )
    return STIXExportResponse(bundle=bundle)


# ===========================
# Detection Rule Generation
# ===========================

@router.post("/api/v1/rules/sigma", response_model=SigmaGenerateResponse)
async def generate_sigma_rule(req: SigmaGenerateRequest) -> SigmaGenerateResponse:
    """Generate a Sigma rule from IOCs."""
    from black_onyx.threat.sigma_generator import SigmaRuleGenerator
    gen = SigmaRuleGenerator()
    rule = gen.generate_from_iocs(
        iocs=req.iocs, title=req.title, description=req.description, level=req.level,
    )
    return SigmaGenerateResponse(rule=rule)


@router.post("/api/v1/rules/yara", response_model=YARAGenerateResponse)
async def generate_yara_rule(req: YARAGenerateRequest) -> YARAGenerateResponse:
    """Generate a YARA rule from IOCs."""
    from black_onyx.threat.yara_generator import YARARuleGenerator
    gen = YARARuleGenerator()
    rule = gen.generate_from_iocs(iocs=req.iocs, rule_name=req.rule_name, tags=req.tags)
    return YARAGenerateResponse(rule=rule)


# ===========================
# Graph Visualization
# ===========================

@router.post("/api/v1/graph/build", response_model=GraphResponse)
async def build_graph(payloads: list[dict[str, Any]]) -> GraphResponse:
    """Build a relationship graph from Qdrant payloads."""
    from black_onyx.threat.graph_builder import GraphBuilder
    builder = GraphBuilder()
    graph = builder.build_from_payloads(payloads)
    return GraphResponse(**graph)


def _payload_timestamp(payload: dict[str, Any]) -> str | None:
    """First usable time field on a payload, newest-intent first."""
    for key in ("indexed_at", "ioc_last_seen", "ioc_first_seen", "capture_time"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


@router.get("/api/v1/graph/sources")
async def graph_sources() -> dict[str, Any]:
    """List the collections and entity types available for graph building."""
    from black_onyx.threat.graph_builder import GraphBuilder
    service = get_service()
    collections = service.qdrant_store.list_collections()
    return {
        "sources": [
            {"collection": item["name"], "points": item.get("points_count") or 0}
            for item in collections
        ],
        "entity_types": GraphBuilder.entity_types(),
    }


@router.post("/api/v1/graph/entities", response_model=EntityGraphResponse)
async def build_entity_graph(req: EntityGraphRequest) -> EntityGraphResponse:
    """Build a relationship graph from indexed collections.

    Sources, entity types, an ingest-time window, and a text filter are all
    applied before the graph is assembled so an analyst can narrow a noisy
    corpus down to the relationships that matter.
    """
    from black_onyx.threat.graph_builder import GraphBuilder
    service = get_service()
    store = service.qdrant_store
    known = {item["name"] for item in store.list_collections()}
    targets = [name for name in req.collections if name in known] or sorted(known)
    unknown = [name for name in req.collections if name not in known]
    if unknown:
        raise HTTPException(
            status_code=404, detail=f"Unknown collection(s): {', '.join(sorted(unknown))}",
        )

    start = (req.start_date or "").strip() or None
    end = (req.end_date or "").strip() or None
    if end and len(end) == 10:
        end = f"{end}T23:59:59"
    needle = (req.search or "").strip().casefold() or None

    payloads: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    scanned = 0
    undated = 0
    for collection in targets:
        collection_scanned = 0
        collection_matched = 0
        offset: int | str | None = None
        remaining = req.max_points_per_collection
        while remaining > 0:
            page, offset = store.scroll(
                collection_name=collection,
                limit=min(remaining, 250),
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )
            if not page:
                break
            remaining -= len(page)
            for point in page:
                payload = dict(point.payload or {})
                collection_scanned += 1
                scanned += 1
                if start or end:
                    stamp = _payload_timestamp(payload)
                    if stamp is None:
                        undated += 1
                        continue
                    if start and stamp < start:
                        continue
                    if end and stamp > end:
                        continue
                if needle:
                    haystack = json.dumps(payload, default=str).casefold()
                    if needle not in haystack:
                        continue
                payload["collection"] = collection
                payload["point_id"] = str(point.id)
                payloads.append(payload)
                collection_matched += 1
            if offset is None:
                break
        sources.append({
            "collection": collection,
            "scanned": collection_scanned,
            "matched": collection_matched,
        })

    builder = GraphBuilder()
    graph = builder.build_from_payloads(
        payloads,
        entity_types=req.entity_types or None,
        max_nodes=req.max_nodes,
    )
    return EntityGraphResponse(
        **graph,
        sources=sources,
        available_entity_types=GraphBuilder.entity_types(),
        points_scanned=scanned,
        points_matched=len(payloads),
        points_undated=undated,
    )


@router.post("/api/v1/graph/attack", response_model=GraphResponse)
async def build_attack_graph(technique_ids: list[str]) -> GraphResponse:
    """Build a MITRE ATT&CK network graph."""
    service = get_service()
    mapper = service.attack_mapper
    if mapper is None:
        raise HTTPException(status_code=400, detail="MITRE ATT&CK not enabled in config")
    from black_onyx.threat.graph_builder import GraphBuilder
    builder = GraphBuilder()
    graph = builder.build_attack_graph(technique_ids, mapper)
    return GraphResponse(**graph)


# ===========================
# Case Management
# ===========================

@router.post("/api/v1/cases", response_model=CaseResponse)
async def create_case(req: CaseCreateRequest) -> CaseResponse:
    """Create a new investigation case."""
    service = get_service()
    mgr = service.case_manager
    case = mgr.create_case(
        title=req.title, description=req.description,
        priority=req.priority, assignee=req.assignee, tags=req.tags,
        external_incident_id=req.external_incident_id,
    )
    return CaseResponse(
        case_id=case.case_id, title=case.title, description=case.description,
        status=case.status, priority=case.priority, severity=case.severity,
        assignee=case.assignee, tags=case.tags,
        created_at=case.created_at, updated_at=case.updated_at,
        detected_at=case.detected_at, contained_at=case.contained_at,
        closed_at=case.closed_at, sla_due_at=case.sla_due_at,
        external_incident_id=case.external_incident_id,
    )


@router.get("/api/v1/cases", response_model=CaseListResponse)
async def list_cases(status: str | None = None, limit: int = 50) -> CaseListResponse:
    """List investigation cases."""
    service = get_service()
    mgr = service.case_manager
    cases = mgr.list_cases(status=status, limit=limit)
    return CaseListResponse(cases=[c.__dict__ for c in cases], total=len(cases))


@router.get("/api/v1/cases/{case_id}", response_model=CaseResponse)
async def get_case(case_id: str) -> CaseResponse:
    """Get case details."""
    service = get_service()
    mgr = service.case_manager
    case = mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    iocs = mgr.get_case_iocs(case_id)
    points = mgr.get_case_points(case_id)
    notes = mgr.get_notes(case_id)
    timeline = mgr.get_timeline(case_id)
    return CaseResponse(
        case_id=case.case_id, title=case.title, description=case.description,
        status=case.status, priority=case.priority, severity=case.severity,
        assignee=case.assignee, tags=case.tags,
        created_at=case.created_at, updated_at=case.updated_at,
        detected_at=case.detected_at, contained_at=case.contained_at,
        closed_at=case.closed_at, sla_due_at=case.sla_due_at,
        external_incident_id=case.external_incident_id,
        iocs=iocs, points=points, notes=notes, timeline=timeline,
    )


@router.patch("/api/v1/cases/{case_id}", response_model=CaseResponse)
async def update_case(case_id: str, req: CaseUpdateRequest) -> CaseResponse:
    """Update a case."""
    service = get_service()
    mgr = service.case_manager
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    case = mgr.update_case(case_id, **updates)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return CaseResponse(
        case_id=case.case_id, title=case.title, description=case.description,
        status=case.status, priority=case.priority, severity=case.severity,
        assignee=case.assignee, tags=case.tags,
        created_at=case.created_at, updated_at=case.updated_at,
        detected_at=case.detected_at, contained_at=case.contained_at,
        closed_at=case.closed_at, sla_due_at=case.sla_due_at,
        external_incident_id=case.external_incident_id,
    )


@router.delete("/api/v1/cases/{case_id}", response_model=StatusResponse)
async def delete_case(case_id: str) -> StatusResponse:
    """Delete a case."""
    service = get_service()
    mgr = service.case_manager
    mgr.delete_case(case_id)
    return StatusResponse(status="ok", message=f"Deleted case: {case_id}")


@router.post("/api/v1/cases/{case_id}/iocs", response_model=StatusResponse)
async def add_ioc_to_case(case_id: str, req: CaseIOCRequest) -> StatusResponse:
    """Add an IOC to a case."""
    service = get_service()
    mgr = service.case_manager
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    mgr.add_ioc_to_case(case_id, req.ioc_type, req.ioc_value)
    return StatusResponse(status="ok")


@router.post("/api/v1/cases/{case_id}/points", response_model=StatusResponse)
async def add_point_to_case(case_id: str, req: CasePointRequest) -> StatusResponse:
    mgr = get_service().case_manager
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    mgr.add_point_to_case(case_id, req.collection, req.point_id)
    return StatusResponse(status="ok")


@router.post("/api/v1/cases/{case_id}/notes", response_model=StatusResponse)
async def add_case_note(
    case_id: str, req: CaseNoteRequest, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Add a note to a case."""
    service = get_service()
    mgr = service.case_manager
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    note_id = mgr.add_note(case_id, principal.user_id, req.content)
    return StatusResponse(status="ok", message=f"Note created: {note_id}")


# ===========================
# Watchlists & Alerting
# ===========================

@router.post("/api/v1/watchlists", response_model=WatchlistResponse)
async def create_watchlist(req: WatchlistCreateRequest) -> WatchlistResponse:
    """Create a new watchlist."""
    service = get_service()
    mgr = service.watchlist_manager
    list_id = mgr.create_watchlist(name=req.name, description=req.description)
    return WatchlistResponse(list_id=list_id, name=req.name, description=req.description)


@router.get("/api/v1/watchlists")
async def list_watchlists() -> dict[str, Any]:
    """List all watchlists."""
    service = get_service()
    mgr = service.watchlist_manager
    return {"watchlists": mgr.list_watchlists()}


@router.post("/api/v1/watchlists/{list_id}/items", response_model=StatusResponse)
async def add_watchlist_items(list_id: str, req: WatchlistAddItemsRequest) -> StatusResponse:
    """Add items to a watchlist."""
    service = get_service()
    mgr = service.watchlist_manager
    items = [(d.get("ioc_type", ""), d.get("ioc_value", "")) for d in req.items]
    mgr.add_items(list_id, items)
    return StatusResponse(status="ok", message=f"Added {len(items)} items")


@router.get("/api/v1/watchlists/{list_id}/items")
async def get_watchlist_items(list_id: str) -> dict[str, Any]:
    """Get items in a watchlist."""
    service = get_service()
    mgr = service.watchlist_manager
    return {"items": mgr.get_items(list_id)}


@router.delete("/api/v1/watchlists/{list_id}/items/{item_id}", response_model=StatusResponse)
async def remove_watchlist_item(list_id: str, item_id: str) -> StatusResponse:
    mgr = get_service().watchlist_manager
    if not any(item.get("item_id") == item_id for item in mgr.get_items(list_id)):
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    mgr.remove_item(item_id)
    return StatusResponse(status="ok")


@router.delete("/api/v1/watchlists/{list_id}", response_model=StatusResponse)
async def delete_watchlist(list_id: str) -> StatusResponse:
    """Delete a watchlist."""
    service = get_service()
    mgr = service.watchlist_manager
    mgr.delete_watchlist(list_id)
    return StatusResponse(status="ok")


@router.get("/api/v1/alerts")
async def get_alerts(limit: int = 50, unacknowledged_only: bool = False) -> dict[str, Any]:
    """Get alerts."""
    service = get_service()
    mgr = service.watchlist_manager
    return {"alerts": mgr.get_alerts(limit=limit, unacknowledged_only=unacknowledged_only)}


@router.post("/api/v1/alerts/{alert_id}/acknowledge", response_model=StatusResponse)
async def acknowledge_alert(alert_id: str) -> StatusResponse:
    """Acknowledge an alert."""
    service = get_service()
    mgr = service.watchlist_manager
    mgr.acknowledge_alert(alert_id)
    return StatusResponse(status="ok")


# ===========================
# Intelligence Reporting
# ===========================

@router.post("/api/v1/reports/generate", response_model=ReportResponse)
async def generate_report(
    req: ReportGenerateRequest, principal: Principal = Depends(current_principal)
) -> ReportResponse:
    """Generate an intelligence report."""
    service = get_service()
    gen = service.report_generator
    if req.body_markdown and req.body_markdown.strip():
        markdown = req.body_markdown.strip()
    else:
        markdown = gen.generate_markdown_report(
            title=req.title, iocs=req.iocs,
            enrichments=req.enrichments, mitre_techniques=req.mitre_techniques,
            case_id=req.case_id,
        )
    report_id = str(uuid.uuid4())
    report_dir = Path(service.settings.storage.state_dir) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    if req.format == "html":
        content = gen.markdown_to_html(markdown)
        report_path = report_dir / f"{report_id}.html"
        report_path.write_text(content, encoding="utf-8")
    elif req.format == "pdf":
        content = ""
        report_path = report_dir / f"{report_id}.pdf"
        if not gen.generate_pdf(markdown, str(report_path)):
            raise HTTPException(status_code=409, detail="PDF support is unavailable")
    else:
        content = markdown
        report_path = report_dir / f"{report_id}.md"
        report_path.write_text(content, encoding="utf-8")
    template = req.template or ("ops_digest" if req.body_markdown else "intel")
    with get_auth_service().db.transaction() as db:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(reports)").fetchall()}
        if "template" in columns:
            db.execute(
                "INSERT INTO reports(report_id,title,format,relative_path,created_by,created_at,template) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    report_id, req.title, req.format, report_path.name, principal.user_id,
                    datetime.now(timezone.utc).isoformat(), template,
                ),
            )
        else:
            db.execute(
                "INSERT INTO reports(report_id,title,format,relative_path,created_by,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    report_id, req.title, req.format, report_path.name, principal.user_id,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    return ReportResponse(
        title=req.title, format=req.format, content=content,
        download_url=f"/api/v1/reports/{report_id}/download?format={req.format}",
    )


@router.get("/api/v1/reports")
async def list_reports(
    limit: int = 100,
    template: Optional[str] = None,
) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    columns = {
        row["name"]
        for row in get_auth_service().db._conn.execute("PRAGMA table_info(reports)").fetchall()
    }
    has_template = "template" in columns
    select_template = ",r.template" if has_template else ",'intel' AS template"
    sql = (
        "SELECT r.report_id,r.title,r.format,r.created_at,u.display_name AS created_by"
        f"{select_template} "
        "FROM reports r JOIN users u ON u.user_id=r.created_by "
    )
    params: list[Any] = []
    if template and has_template:
        sql += "WHERE r.template=? "
        params.append(template)
    sql += "ORDER BY r.created_at DESC LIMIT ?"
    params.append(limit)
    rows = get_auth_service().db._conn.execute(sql, tuple(params)).fetchall()
    return {"reports": [dict(row) for row in rows]}


@router.get("/api/v1/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    format: Literal["markdown", "html", "pdf"],
    principal: Principal = Depends(current_principal),
) -> FileResponse:
    extension = {"markdown": "md", "html": "html", "pdf": "pdf"}[format]
    row = get_auth_service().db._conn.execute(
        "SELECT relative_path,format FROM reports WHERE report_id=?", (str(report_id),)
    ).fetchone()
    if not row or row["format"] != format:
        raise HTTPException(status_code=404, detail="Report not found")
    report_dir = (Path(get_service().settings.storage.state_dir) / "reports").resolve()
    path = (report_dir / row["relative_path"]).resolve()
    try:
        path.relative_to(report_dir)
    except ValueError:
        raise HTTPException(status_code=404, detail="Report not found")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    media_type = {
        "markdown": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
    }[format]
    return FileResponse(path, media_type=media_type, filename=f"black-onyx-report.{extension}")


# ===========================
# Feed Ingestion
# ===========================

@router.post("/api/v1/feeds", response_model=StatusResponse)
async def add_feed(req: FeedAddRequest) -> StatusResponse:
    """Add a feed."""
    service = get_service()
    mgr = service.feed_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Feeds not enabled in config")
    try:
        mgr.add_feed(
            name=req.name, url=req.url, feed_type=req.feed_type,
            collection=req.collection, poll_interval_minutes=req.poll_interval_minutes,
            config=req.config,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        from black_onyx.core.collections import feed_collection_name
        service.ensure_collection(req.collection)
        service.ensure_collection(feed_collection_name(req.name))
    except Exception:
        logger.exception("Feed add succeeded but collection ensure failed")
    return StatusResponse(status="ok", message=f"Feed '{req.name}' added")


@router.get("/api/v1/feeds")
async def list_feeds() -> dict[str, Any]:
    """List all feeds."""
    service = get_service()
    mgr = service.feed_manager
    if mgr is None:
        return {"feeds": [], "enabled": False}
    return {"feeds": mgr.list_feeds(), "enabled": True}


@router.post("/api/v1/feeds/{feed_name}/poll", response_model=FeedPollResponse)
async def poll_feed(feed_name: str) -> FeedPollResponse:
    """Poll a single feed."""
    service = get_service()
    mgr = service.feed_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Feeds not enabled in config")
    result = await mgr.poll_feed(feed_name)
    return FeedPollResponse(**result)


@router.post("/api/v1/feeds/poll-all")
async def poll_all_feeds() -> dict[str, Any]:
    """Poll all enabled feeds."""
    service = get_service()
    mgr = service.feed_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Feeds not enabled in config")
    results = await mgr.poll_all()
    return {"results": results}


@router.delete("/api/v1/feeds/{feed_name}", response_model=StatusResponse)
async def remove_feed(feed_name: str) -> StatusResponse:
    """Remove a feed."""
    service = get_service()
    mgr = service.feed_manager
    if mgr is None:
        raise HTTPException(status_code=400, detail="Feeds not enabled in config")
    mgr.remove_feed(feed_name)
    return StatusResponse(status="ok")


# ===========================
# Inbound webhooks
# ===========================

@router.post("/api/v1/webhooks")
async def create_webhook(
    req: WebhookCreateRequest, _: Principal = Depends(require_admin)
) -> dict[str, Any]:
    """Create an inbound webhook token (token shown once)."""
    created = get_service().webhook_manager.create_webhook(req.name)
    return {
        **created,
        "endpoint": "/api/v1/webhooks/events",
        "auth_header": "X-Webhook-Token or Authorization: Bearer <token>",
    }


@router.get("/api/v1/webhooks")
async def list_webhooks(_: Principal = Depends(require_admin)) -> dict[str, Any]:
    """List inbound webhooks without revealing full tokens."""
    return {"webhooks": get_service().webhook_manager.list_webhooks()}


@router.delete("/api/v1/webhooks/{webhook_id}", response_model=StatusResponse)
async def delete_webhook(
    webhook_id: str, _: Principal = Depends(require_admin)
) -> StatusResponse:
    """Revoke an inbound webhook."""
    if not get_service().webhook_manager.delete_webhook(webhook_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return StatusResponse(status="ok", message="Webhook revoked")


@router.post("/api/v1/webhooks/{webhook_id}/enable", response_model=StatusResponse)
async def enable_webhook(
    webhook_id: str, _: Principal = Depends(require_admin)
) -> StatusResponse:
    if not get_service().webhook_manager.set_enabled(webhook_id, True):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/webhooks/{webhook_id}/disable", response_model=StatusResponse)
async def disable_webhook(
    webhook_id: str, _: Principal = Depends(require_admin)
) -> StatusResponse:
    if not get_service().webhook_manager.set_enabled(webhook_id, False):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/webhooks/events")
async def ingest_webhook_event(request: Request, req: WebhookEventRequest) -> dict[str, Any]:
    """Accept IOC text or structured indicators from an external system."""
    token = request.headers.get("x-webhook-token", "")
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    service = get_service()
    webhook = service.webhook_manager.authenticate(token)
    if webhook is None:
        raise HTTPException(status_code=401, detail="Invalid webhook token")

    merged: dict[str, list[str]] = {}
    if req.iocs:
        for key, values in req.iocs.items():
            if isinstance(values, list):
                merged.setdefault(key, []).extend(str(v) for v in values if v)

    if req.text and req.text.strip():
        from black_onyx.extraction.ioc import extract_iocs
        extracted = extract_iocs(req.text, include_defanged=True).to_dict()
        for key, values in extracted.items():
            if isinstance(values, list):
                merged.setdefault(key, []).extend(values)

    # Deduplicate
    for key in list(merged):
        merged[key] = list(dict.fromkeys(merged[key]))

    if not any(merged.values()):
        raise HTTPException(status_code=422, detail="No indicators found in payload")

    source = (req.source or f"webhook:{webhook['name']}").strip()
    service.decay_manager.record_sightings_batch(merged, source=source)
    service.decay_manager.update_all_scores()

    alerts = service.watchlist_manager.check_iocs(
        merged, collection="webhook", point_id=webhook["webhook_id"], context=source
    )

    added_items = 0
    if req.add_to_watchlist and req.watchlist_id:
        type_map = {
            "ipv4": "ip", "ipv6": "ip", "domains": "domain", "domain": "domain",
            "urls": "url", "url": "url", "md5": "hash", "sha1": "hash",
            "sha256": "hash", "sha512": "hash", "emails": "email", "email": "email",
        }
        items: list[tuple[str, str]] = []
        for key, values in merged.items():
            ioc_type = type_map.get(key, key if key in {"ip", "domain", "url", "hash", "email"} else "indicator")
            for value in values:
                items.append((ioc_type, value))
        if items:
            service.watchlist_manager.add_items(req.watchlist_id, items)
            added_items = len(items)

    total = sum(len(v) for v in merged.values())
    alert_ids = [a.get("alert_id") for a in alerts if a.get("alert_id")]
    event = service.webhook_manager.record_event(
        webhook_id=webhook["webhook_id"],
        webhook_name=webhook["name"],
        source=source,
        iocs=merged,
        alert_ids=alert_ids,
    )
    response: dict[str, Any] = {
        "status": "ok",
        "webhook": webhook["name"],
        "event_id": event.get("event_id") if event else None,
        "ioc_count": total,
        "iocs": merged,
        "alerts": alerts,
        "watchlist_items_added": added_items,
    }

    if alerts:
        try:
            ioc_list = []
            for key, values in merged.items():
                for value in values:
                    ioc_list.append({"ioc_type": key, "ioc_value": value})
            await service.playbook_runner.handle_trigger(
                "watchlist_alert",
                {
                    "alerts": alerts,
                    "iocs": ioc_list,
                    "source": source,
                    "webhook": webhook["name"],
                },
            )
        except Exception:
            logger.exception("Playbook watchlist_alert trigger failed")

    try:
        await service.playbook_runner.handle_trigger(
            "webhook_event",
            {
                "iocs": [{"ioc_type": k, "ioc_value": v} for k, vals in merged.items() for v in vals],
                "alerts": alerts,
                "source": source,
                "webhook": webhook["name"],
            },
        )
    except Exception:
        logger.exception("Playbook webhook_event trigger failed")

    return response


# ===========================
# MISP integration
# ===========================

@router.get("/api/v1/misp/status")
async def misp_status(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return get_service().misp_manager.get_status()


@router.put("/api/v1/misp/configure")
async def misp_configure(
    req: MispConfigureRequest,
    principal: Principal = Depends(require_admin),
) -> dict[str, Any]:
    service = get_service()
    if req.api_key is not None:
        from black_onyx.runtime_settings import apply_secret_environment
        runtime_config, _ = service._settings_store.load()
        secret_value = req.api_key.get_secret_value()
        secrets = service._settings_store.save(
            runtime_config,
            {"misp_api_key": secret_value if secret_value else ""},
            principal.user_id,
        )
        apply_secret_environment(
            service._settings, secrets, service._deployment_secret_environment,
        )
    try:
        return service.misp_manager.configure(
            url=req.url,
            api_key_env=req.api_key_env or "MISP_API_KEY",
            collection=req.collection,
            enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/v1/misp/sync")
async def misp_sync(
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        result = await asyncio.to_thread(get_service().misp_manager.sync_pull)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("MISP sync failed")
        raise HTTPException(status_code=502, detail=f"MISP sync failed: {exc}") from exc

    service = get_service()
    watchlist_name = str(result.get("collection") or "MISP").strip() or "MISP"
    iocs = result.get("iocs") or []
    items_added = 0
    if iocs:
        wm = service.watchlist_manager
        list_id = None
        for wl in wm.list_watchlists():
            if wl.get("name") == watchlist_name:
                list_id = wl["list_id"]
                break
        if list_id is None:
            list_id = wm.create_watchlist(
                watchlist_name, description="IOCs synced from MISP",
            )
        pairs = [
            (str(i["ioc_type"]), str(i["ioc_value"]))
            for i in iocs
            if i.get("ioc_type") and i.get("ioc_value")
        ]
        # Deduplicate within this sync batch
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for pair in pairs:
            if pair in seen:
                continue
            seen.add(pair)
            unique.append(pair)
        if unique:
            wm.add_items(list_id, unique)
            items_added = len(unique)

    return {
        "events": result.get("events") or [],
        "count": len(result.get("events") or []),
        "ioc_count": int(result.get("ioc_count") or 0),
        "watchlist": watchlist_name,
        "watchlist_items_added": items_added,
    }


@router.post("/api/v1/misp/publish")
async def misp_publish(
    req: MispPublishRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    iocs = [{"ioc_type": i.ioc_type, "ioc_value": i.ioc_value} for i in req.iocs]
    try:
        result = await asyncio.to_thread(
            get_service().misp_manager.publish_from_iocs, req.case_id, iocs, req.info,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("MISP publish failed")
        raise HTTPException(status_code=502, detail=f"MISP publish failed: {exc}") from exc
    # Also push into Postgres threat_intel match SoR (best-effort; never fails publish).
    from black_onyx.threat_intel_sync import sync_indicators_to_threat_intel

    match_sync = await sync_indicators_to_threat_intel(iocs, source="black-onyx-misp-publish")
    if isinstance(result, dict):
        result = {**result, "threat_intel_sync": match_sync}
    return result


@router.post("/api/v1/threat-intel/sync-indicators")
async def sync_tip_indicators_to_match_sor(
    req: MispPublishRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Explicit TIP → Postgres threat_intel sync (match-on-wire SoR). Does not publish to MISP."""
    from black_onyx.threat_intel_sync import sync_indicators_to_threat_intel

    iocs = [{"ioc_type": i.ioc_type, "ioc_value": i.ioc_value} for i in req.iocs]
    sync = await sync_indicators_to_threat_intel(iocs, source="black-onyx-tip")
    return {"status": sync.get("status", "ok"), "iocs": len(iocs), **sync}


# ===========================
# TAXII 2.1 management
# ===========================

@router.get("/api/v1/taxii/collections")
async def taxii_mgmt_list_collections(
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    return {"collections": get_service().taxii_manager.list_collections()}


@router.post("/api/v1/taxii/collections")
async def taxii_mgmt_create_collection(
    req: TaxiiCollectionCreateRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    return get_service().taxii_manager.create_collection(
        title=req.title, description=req.description, enabled=req.enabled,
    )


@router.get("/api/v1/taxii/keys")
async def taxii_mgmt_list_keys(
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    return {"keys": get_service().taxii_manager.list_api_keys()}


@router.post("/api/v1/taxii/keys")
async def taxii_mgmt_create_key(
    req: TaxiiApiKeyCreateRequest,
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    return get_service().taxii_manager.create_api_key(req.name)


@router.patch("/api/v1/taxii/keys/{key_id}")
async def taxii_mgmt_update_key(
    key_id: str,
    req: TaxiiApiKeyUpdateRequest,
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    mgr = get_service().taxii_manager
    if req.enabled is not None:
        if not mgr.set_api_key_enabled(key_id, req.enabled):
            raise HTTPException(status_code=404, detail="API key not found")
        mgr.audit_log(key_id, "key.enable" if req.enabled else "key.disable")
    keys = [k for k in mgr.list_api_keys() if k["key_id"] == key_id]
    if not keys:
        raise HTTPException(status_code=404, detail="API key not found")
    return keys[0]


@router.delete("/api/v1/taxii/keys/{key_id}", response_model=StatusResponse)
async def taxii_mgmt_delete_key(
    key_id: str,
    _: Principal = Depends(require_admin),
) -> StatusResponse:
    mgr = get_service().taxii_manager
    if not mgr.delete_api_key(key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    mgr.audit_log(key_id, "key.delete")
    return StatusResponse(status="ok", message="API key deleted")


@router.post("/api/v1/taxii/publish")
async def taxii_mgmt_publish(
    req: TaxiiPublishRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    mgr = get_service().taxii_manager
    objects: list[dict[str, Any]] = list(req.objects or [])
    if req.iocs:
        from black_onyx.threat.stix_exporter import STIXExporter
        exporter = STIXExporter()
        bundle = exporter.export_bundle(
            [{"ioc_type": i.ioc_type, "ioc_value": i.ioc_value} for i in req.iocs],
        )
        objects.extend(bundle.get("objects") or [])
    if not objects:
        raise HTTPException(status_code=422, detail="No STIX objects or IOCs to publish")
    try:
        result = mgr.publish_stix_objects(req.collection_id, objects)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.get("/api/v1/taxii/collections/{collection_id}/objects")
async def taxii_mgmt_list_objects(
    collection_id: str,
    limit: int = 100,
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    mgr = get_service().taxii_manager
    if mgr.get_collection(collection_id) is None:
        raise HTTPException(status_code=404, detail="Collection not found")
    return {"objects": mgr.list_objects(collection_id, limit=limit)}


# ===========================
# SOAR-lite playbooks
# ===========================

@router.get("/api/v1/playbooks")
async def list_playbooks(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {"playbooks": get_service().playbook_manager.list_playbooks()}


@router.post("/api/v1/playbooks")
async def create_playbook(
    req: PlaybookCreateRequest,
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    try:
        return get_service().playbook_manager.create_playbook(
            name=req.name,
            trigger_type=req.trigger_type,
            steps=req.steps,
            enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/v1/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: str, _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    playbook = get_service().playbook_manager.get_playbook(playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@router.put("/api/v1/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: str,
    req: PlaybookUpdateRequest,
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    try:
        updated = get_service().playbook_manager.update_playbook(
            playbook_id,
            name=req.name,
            trigger_type=req.trigger_type,
            steps=req.steps,
            enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return updated


@router.delete("/api/v1/playbooks/{playbook_id}", response_model=StatusResponse)
async def delete_playbook(
    playbook_id: str, _: Principal = Depends(require_admin),
) -> StatusResponse:
    if not get_service().playbook_manager.delete_playbook(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/playbooks/{playbook_id}/enable", response_model=StatusResponse)
async def enable_playbook(
    playbook_id: str, _: Principal = Depends(require_admin),
) -> StatusResponse:
    if not get_service().playbook_manager.set_enabled(playbook_id, True):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/playbooks/{playbook_id}/disable", response_model=StatusResponse)
async def disable_playbook(
    playbook_id: str, _: Principal = Depends(require_admin),
) -> StatusResponse:
    if not get_service().playbook_manager.set_enabled(playbook_id, False):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/playbooks/{playbook_id}/run")
async def run_playbook(
    playbook_id: str,
    req: PlaybookRunRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    mgr = get_service().playbook_manager
    if mgr.get_playbook(playbook_id) is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    run = mgr.start_run(playbook_id, req.context)
    return await get_service().playbook_runner.execute_run(run["run_id"])


@router.get("/api/v1/playbook-runs")
async def list_playbook_runs(
    limit: int = 50,
    playbook_id: str | None = None,
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    return {
        "runs": get_service().playbook_manager.list_runs(limit=limit, playbook_id=playbook_id),
    }


@router.get("/api/v1/playbook-runs/{run_id}")
async def get_playbook_run(
    run_id: str, _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    run = get_service().playbook_manager.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.post("/api/v1/playbook-runs/{run_id}/approve")
async def approve_playbook_run(
    run_id: str, _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        return await get_service().playbook_runner.continue_after_approval(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/v1/outbound-endpoints")
async def list_outbound_endpoints(
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    return {"endpoints": get_service().playbook_manager.list_endpoints()}


@router.post("/api/v1/outbound-endpoints")
async def create_outbound_endpoint(
    req: OutboundEndpointCreateRequest,
    _: Principal = Depends(require_admin),
) -> dict[str, Any]:
    try:
        return get_service().playbook_manager.create_endpoint(
            name=req.name, url=req.url, enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/api/v1/outbound-endpoints/{endpoint_id}", response_model=StatusResponse)
async def delete_outbound_endpoint(
    endpoint_id: str, _: Principal = Depends(require_admin),
) -> StatusResponse:
    if not get_service().playbook_manager.delete_endpoint(endpoint_id):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/outbound-endpoints/{endpoint_id}/enable", response_model=StatusResponse)
async def enable_outbound_endpoint(
    endpoint_id: str, _: Principal = Depends(require_admin),
) -> StatusResponse:
    if not get_service().playbook_manager.set_endpoint_enabled(endpoint_id, True):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return StatusResponse(status="ok")


@router.post("/api/v1/outbound-endpoints/{endpoint_id}/disable", response_model=StatusResponse)
async def disable_outbound_endpoint(
    endpoint_id: str, _: Principal = Depends(require_admin),
) -> StatusResponse:
    if not get_service().playbook_manager.set_endpoint_enabled(endpoint_id, False):
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return StatusResponse(status="ok")


# ===========================
# Analyst Collaboration
# ===========================

@router.post("/api/v1/annotations", response_model=StatusResponse)
async def create_annotation(
    req: AnnotationCreateRequest, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Create an annotation on a point."""
    service = get_service()
    mgr = service.annotation_manager
    ann_id = mgr.add_annotation(req.collection, req.point_id, principal.user_id, req.content)
    return StatusResponse(status="ok", message=f"Annotation created: {ann_id}")


@router.get("/api/v1/annotations/{collection}/{point_id}")
async def get_annotations(collection: str, point_id: str) -> dict[str, Any]:
    """Get annotations for a point."""
    service = get_service()
    mgr = service.annotation_manager
    return {"annotations": mgr.get_annotations(collection, point_id)}


@router.post("/api/v1/tags", response_model=StatusResponse)
async def add_tag(req: TagRequest) -> StatusResponse:
    """Add a tag to a point."""
    service = get_service()
    mgr = service.annotation_manager
    mgr.add_tag(req.collection, req.point_id, req.tag)
    return StatusResponse(status="ok")


@router.delete("/api/v1/tags", response_model=StatusResponse)
async def remove_tag(req: TagRequest) -> StatusResponse:
    """Remove a tag from a point."""
    service = get_service()
    mgr = service.annotation_manager
    mgr.remove_tag(req.collection, req.point_id, req.tag)
    return StatusResponse(status="ok")


@router.get("/api/v1/tags/{collection}/{point_id}")
async def get_tags(collection: str, point_id: str) -> dict[str, Any]:
    """Get tags for a point."""
    service = get_service()
    mgr = service.annotation_manager
    return {"tags": mgr.get_tags(collection, point_id)}


@router.post("/api/v1/notes", response_model=StatusResponse)
async def create_note(
    req: NoteCreateRequest, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Create a note on a point."""
    service = get_service()
    mgr = service.annotation_manager
    note_id = mgr.add_note(req.collection, req.point_id, principal.user_id, req.content)
    return StatusResponse(status="ok", message=f"Note created: {note_id}")


@router.get("/api/v1/notes/{collection}/{point_id}")
async def get_notes(collection: str, point_id: str) -> dict[str, Any]:
    """Get notes for a point."""
    service = get_service()
    mgr = service.annotation_manager
    return {"notes": mgr.get_notes(collection, point_id)}


@router.post("/api/v1/bookmarks", response_model=StatusResponse)
async def toggle_bookmark(
    req: BookmarkRequest, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Toggle bookmark status for a point."""
    service = get_service()
    mgr = service.annotation_manager
    bookmarked = mgr.toggle_bookmark(req.collection, req.point_id, principal.user_id)
    return StatusResponse(
        status="ok",
        message=f"{'Bookmarked' if bookmarked else 'Unbookmarked'}: {req.point_id}",
    )


@router.get("/api/v1/bookmarks")
async def get_bookmarks(
    collection: str | None = None, principal: Principal = Depends(current_principal)
) -> dict[str, Any]:
    """Get bookmarked points."""
    service = get_service()
    mgr = service.annotation_manager
    return {"bookmarks": mgr.get_bookmarked(collection=collection, user=principal.user_id)}


@router.post("/api/v1/confidence", response_model=StatusResponse)
async def set_confidence(
    req: ConfidenceRequest, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Set analyst confidence score for a point."""
    service = get_service()
    mgr = service.annotation_manager
    mgr.set_confidence(req.collection, req.point_id, req.confidence, principal.user_id)
    return StatusResponse(status="ok")


@router.post("/api/v1/ioc-status", response_model=StatusResponse)
async def set_ioc_status(
    req: StatusUpdateRequest, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Set IOC status (new, confirmed, benign, expired) for a point."""
    service = get_service()
    mgr = service.annotation_manager
    mgr.set_status(req.collection, req.point_id, req.status, principal.user_id)
    return StatusResponse(status="ok")


# ===========================
# IOC Decay & Freshness
# ===========================

@router.get("/api/v1/decay/tracked")
async def get_tracked_iocs(limit: int = 100) -> dict[str, Any]:
    """Get all tracked IOCs with decay scores."""
    service = get_service()
    mgr = service.decay_manager
    return {"iocs": mgr.get_all_tracked(limit=limit)}


@router.get("/api/v1/decay/stale")
async def get_stale_iocs(threshold: float = 0.3) -> dict[str, Any]:
    """Get stale IOCs below decay threshold."""
    service = get_service()
    mgr = service.decay_manager
    return {"iocs": mgr.get_stale_iocs(threshold_score=threshold)}


@router.get("/api/v1/decay/fresh")
async def get_fresh_iocs(threshold: float = 0.7) -> dict[str, Any]:
    """Get fresh IOCs above decay threshold."""
    service = get_service()
    mgr = service.decay_manager
    return {"iocs": mgr.get_fresh_iocs(threshold_score=threshold)}


@router.get("/api/v1/decay/summary")
async def get_decay_summary(stale_threshold: float = 0.3, fresh_threshold: float = 0.7) -> dict[str, Any]:
    """Cheap tracked/stale/fresh counts for gallery-tile-style summaries.

    Unlike /decay/stale and /decay/fresh (which return full, unbounded IOC
    lists), this never materializes IOC rows — safe to poll for a tile.
    """
    service = get_service()
    mgr = service.decay_manager
    return mgr.get_summary(stale_threshold=stale_threshold, fresh_threshold=fresh_threshold)


@router.get("/api/v1/decay/{ioc_value}")
async def get_ioc_decay_history(ioc_value: str) -> dict[str, Any]:
    """Get decay history for a specific IOC."""
    service = get_service()
    mgr = service.decay_manager
    history = mgr.get_ioc_history(ioc_value)
    if not history:
        raise HTTPException(status_code=404, detail="IOC not tracked")
    return history


@router.post("/api/v1/decay/update-scores", response_model=StatusResponse)
async def update_decay_scores() -> StatusResponse:
    """Recalculate all decay scores."""
    service = get_service()
    mgr = service.decay_manager
    count = mgr.update_all_scores()
    return StatusResponse(status="ok", message=f"Updated {count} IOC scores")


# ===========================
# Gallery hub: user sites & saved logins
# ===========================

def _site_row_to_response(row: Any) -> SiteResponse:
    return SiteResponse(
        site_id=row["site_id"],
        name=row["name"],
        url=row["url"],
        login_url=row["login_url"],
        section=row["section"],
        tags=json.loads(row["tags"] or "[]"),
        open_mode=row["open_mode"],
        # Fetched and cached lazily on first GET .../favicon, not here — site
        # creation must never block on (or fail because of) an external fetch.
        favicon_url=f"/api/v1/sites/{row['site_id']}/favicon",
        has_credential=row["credential_id"] is not None,
        frameable=bool(row["frameable"]) if row["frameable"] is not None else None,
        frameable_checked_at=row["frameable_checked_at"],
        frameable_error=row["frameable_error"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _get_owned_site(site_id: str, owner_user_id: str) -> Any:
    row = get_auth_service().db._conn.execute(
        "SELECT * FROM user_sites WHERE site_id=? AND owner_user_id=?",
        (site_id, owner_user_id),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Site not found")
    return row


async def _probe_and_store_frameability(site_id: str, url: str) -> None:
    """Run probe_frameable and persist the result onto the site row.

    One HTTP call, run synchronously as part of create/update/refresh —
    acceptable latency for an infrequent admin-ish action, and it means the
    gallery never has to poll for a probe result that might arrive later.
    Never raises: a probe failure must not fail the site create/update it
    rides along with.
    """
    from urllib.parse import urlsplit as _urlsplit

    from black_onyx.gallery.frame_probe import probe_frameable

    # The origin the target site would actually see as its frame ancestor —
    # needed so a `frame-ancestors` allowlist can be checked against us rather
    # than only `'none'` being treated as blocking.
    external = _urlsplit(get_service().settings.security.external_url)
    self_origin = f"{external.scheme}://{external.netloc}" if external.scheme and external.netloc else None
    try:
        result = await probe_frameable(url, self_origin)
    except Exception:
        logger.exception("Frameability probe crashed for site %s", site_id)
        result = {"frameable": False, "error": "Probe failed unexpectedly"}
    now = datetime.now(timezone.utc).isoformat()
    with get_auth_service().db.transaction() as db:
        db.execute(
            "UPDATE user_sites SET frameable=?, frameable_checked_at=?, frameable_error=? "
            "WHERE site_id=?",
            (1 if result["frameable"] else 0, now, result["error"], site_id),
        )


@router.get("/api/v1/sites", response_model=list[SiteResponse])
async def list_sites(principal: Principal = Depends(current_principal)) -> list[SiteResponse]:
    """List the current user's pinned external site tiles. Never includes
    secret material — only a has_credential flag."""
    rows = get_auth_service().db._conn.execute(
        "SELECT * FROM user_sites WHERE owner_user_id=? ORDER BY updated_at DESC",
        (principal.user_id,),
    ).fetchall()
    return [_site_row_to_response(row) for row in rows]


@router.post("/api/v1/sites", response_model=SiteResponse)
async def create_site(
    req: SiteCreateRequest, principal: Principal = Depends(current_principal)
) -> SiteResponse:
    """Pin a new external site as a gallery tile."""
    service = get_service()
    production = service.settings.security.production
    try:
        url = validate_site_url(req.url, production)
        login_url = validate_site_url(req.login_url, production) if req.login_url else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    site_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_auth_service().db.transaction() as db:
        db.execute(
            "INSERT INTO user_sites("
            "site_id,owner_user_id,name,url,login_url,section,tags,open_mode,"
            "favicon_relative_path,credential_id,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,NULL,NULL,?,?)",
            (site_id, principal.user_id, req.name.strip(), url, login_url, req.section,
             json.dumps(req.tags), req.open_mode, now, now),
        )
    get_auth_service().audit(principal, "site.create", "site", site_id, detail={"url": url})
    if req.open_mode == "embedded":
        await _probe_and_store_frameability(site_id, url)
    row = _get_owned_site(site_id, principal.user_id)
    return _site_row_to_response(row)


@router.patch("/api/v1/sites/{site_id}", response_model=SiteResponse)
async def update_site(
    site_id: str, req: SiteUpdateRequest, principal: Principal = Depends(current_principal)
) -> SiteResponse:
    """Update a pinned site's metadata, section, tags, or open mode."""
    service = get_service()
    production = service.settings.security.production
    existing = _get_owned_site(site_id, principal.user_id)
    updates = req.model_dump(exclude_unset=True)
    fields: list[str] = []
    values: list[Any] = []
    stale_favicon_path: str | None = None
    if "name" in updates:
        fields.append("name=?")
        values.append(updates["name"].strip())
    if "url" in updates:
        try:
            fields.append("url=?")
            values.append(validate_site_url(updates["url"], production))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        # The cached favicon belongs to the *old* URL — clear it so the next
        # GET .../favicon fetches fresh from the new one, rather than
        # silently serving the previous site's icon forever.
        fields.append("favicon_relative_path=NULL")
        stale_favicon_path = existing["favicon_relative_path"]
    if "login_url" in updates:
        try:
            login_url = validate_site_url(updates["login_url"], production) if updates["login_url"] else None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        fields.append("login_url=?")
        values.append(login_url)
    if "section" in updates:
        fields.append("section=?")
        values.append(updates["section"])
    if "tags" in updates:
        fields.append("tags=?")
        values.append(json.dumps(updates["tags"]))
    if "open_mode" in updates:
        fields.append("open_mode=?")
        values.append(updates["open_mode"])
    if fields:
        fields.append("updated_at=?")
        now = datetime.now(timezone.utc).isoformat()
        values.append(now)
        values.extend([site_id, principal.user_id])
        with get_auth_service().db.transaction() as db:
            db.execute(
                f"UPDATE user_sites SET {','.join(fields)} WHERE site_id=? AND owner_user_id=?",
                tuple(values),
            )
        if stale_favicon_path:
            try:
                (Path(service.settings.storage.state_dir) / stale_favicon_path).unlink(missing_ok=True)
            except OSError:
                logger.debug("Failed to remove stale cached favicon for site %s", site_id)
        get_auth_service().audit(principal, "site.update", "site", site_id)
        # Re-probe whenever the effective result of this update is an embedded
        # site whose URL or mode just changed — a stale probe from a
        # different URL, or no probe at all from switching into "embedded",
        # would otherwise leave the popup guessing.
        effective_open_mode = updates.get("open_mode", existing["open_mode"])
        switched_to_embedded = updates.get("open_mode") == "embedded"
        url_changed = "url" in updates
        if effective_open_mode == "embedded" and (switched_to_embedded or url_changed):
            effective_url = updates.get("url", existing["url"])
            await _probe_and_store_frameability(site_id, effective_url)
    row = _get_owned_site(site_id, principal.user_id)
    return _site_row_to_response(row)


@router.delete("/api/v1/sites/{site_id}", response_model=StatusResponse)
async def delete_site(
    site_id: str, principal: Principal = Depends(current_principal)
) -> StatusResponse:
    """Delete a pinned site tile and its saved login, if any.

    stored_credentials.site_id declares `ON DELETE CASCADE` and the
    connection runs with `PRAGMA foreign_keys=ON` (StateDatabase.__init__),
    so deleting the site row is sufficient — no separate credential delete
    needed here.
    """
    row = _get_owned_site(site_id, principal.user_id)
    with get_auth_service().db.transaction() as db:
        db.execute(
            "DELETE FROM user_sites WHERE site_id=? AND owner_user_id=?",
            (site_id, principal.user_id),
        )
    if row["favicon_relative_path"]:
        try:
            (Path(get_service().settings.storage.state_dir) / row["favicon_relative_path"]).unlink(missing_ok=True)
        except OSError:
            logger.debug("Failed to remove cached favicon for site %s", site_id)
    get_auth_service().audit(principal, "site.delete", "site", site_id)
    return StatusResponse(status="ok", message=f"Deleted site: {site_id}")


@router.post("/api/v1/sites/{site_id}/probe", response_model=SiteResponse)
async def probe_site_frameability(
    site_id: str, principal: Principal = Depends(current_principal)
) -> SiteResponse:
    """Re-run the embeddability probe on demand — a target site's framing
    headers can change after the initial probe, and the analyst may want to
    check again rather than wait for the next url/open_mode edit."""
    row = _get_owned_site(site_id, principal.user_id)
    await _probe_and_store_frameability(site_id, row["url"])
    get_auth_service().audit(principal, "site.probe", "site", site_id)
    return _site_row_to_response(_get_owned_site(site_id, principal.user_id))


@router.get("/api/v1/sites/{site_id}/favicon")
async def get_site_favicon(
    site_id: str, principal: Principal = Depends(current_principal)
) -> FileResponse:
    """Serve a site's favicon from our own origin (no third-party favicon
    CDN, so the CSP img-src allowlist stays 'self').

    Fetched and cached lazily on first request, not at site-creation time, so
    creating a site never blocks on (or fails because of) an external fetch.
    """
    import mimetypes

    row = _get_owned_site(site_id, principal.user_id)
    state_dir = Path(get_service().settings.storage.state_dir).resolve()
    if not row["favicon_relative_path"]:
        relative_path = await asyncio.to_thread(
            fetch_and_cache_favicon, row["url"], str(state_dir), site_id,
        )
        if relative_path is None:
            raise HTTPException(status_code=404, detail="Favicon unavailable")
        with get_auth_service().db.transaction() as db:
            db.execute(
                "UPDATE user_sites SET favicon_relative_path=? WHERE site_id=?",
                (relative_path, site_id),
            )
        row = _get_owned_site(site_id, principal.user_id)
    path = (state_dir / row["favicon_relative_path"]).resolve()
    try:
        path.relative_to(state_dir)
    except ValueError:
        raise HTTPException(status_code=404, detail="No cached favicon for this site")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No cached favicon for this site")
    media_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return FileResponse(path, media_type=media_type)


@router.post("/api/v1/sites/{site_id}/credential", response_model=StatusResponse)
async def create_or_rotate_site_credential(
    site_id: str, req: SiteCredentialCreateRequest, principal: Principal = Depends(current_principal),
) -> StatusResponse:
    """Save or rotate the single saved login for a site."""
    _get_owned_site(site_id, principal.user_id)
    store = get_service().site_credential_store
    try:
        _, rotated = store.create_or_rotate(
            principal.user_id, site_id, req.username, req.secret, req.notes,
        )
    except SiteCredentialError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    action = "site_credential.rotate" if rotated else "site_credential.create"
    get_auth_service().audit(principal, action, "site", site_id)
    return StatusResponse(status="ok", message="Saved login stored")


@router.get("/api/v1/sites/{site_id}/credential", response_model=SiteCredentialRevealResponse)
async def reveal_site_credential(
    site_id: str, request: Request, principal: Principal = Depends(current_principal),
) -> SiteCredentialRevealResponse:
    """Decrypt and return the saved login for a site.

    Rate-limited per user+site; every attempt is audited, including
    rate-limited rejections, since a burst of reveal attempts is itself a
    security-relevant signal regardless of outcome.
    """
    _get_owned_site(site_id, principal.user_id)
    store = get_service().site_credential_store
    try:
        result = store.reveal(principal.user_id, site_id)
    except SiteCredentialRateLimited as exc:
        get_auth_service().audit(
            principal, "site_credential.reveal", "site", site_id,
            ip=request.client.host if request.client else "", detail={"outcome": "rate_limited"},
        )
        raise HTTPException(status_code=429, detail=str(exc))
    except SiteCredentialError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    get_auth_service().audit(
        principal, "site_credential.reveal", "site", site_id,
        ip=request.client.host if request.client else "", detail={"outcome": "ok"},
    )
    return SiteCredentialRevealResponse(**result)


@router.delete("/api/v1/sites/{site_id}/credential", response_model=StatusResponse)
async def delete_site_credential(
    site_id: str, principal: Principal = Depends(current_principal),
) -> StatusResponse:
    """Remove the saved login for a site without deleting the site tile."""
    _get_owned_site(site_id, principal.user_id)
    store = get_service().site_credential_store
    if not store.delete(principal.user_id, site_id):
        raise HTTPException(status_code=404, detail="No saved login for this site")
    get_auth_service().audit(principal, "site_credential.delete", "site", site_id)
    return StatusResponse(status="ok", message="Saved login removed")
