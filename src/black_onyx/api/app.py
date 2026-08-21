"""FastAPI application — main entry point for the web UI backend."""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from black_onyx.api.routes import router
from black_onyx.api.routes_analytics import analytics_router
from black_onyx.api.routes_assets import assets_router
from black_onyx.api.routes_backup import backup_router
from black_onyx.api.routes_connectors import connectors_router
from black_onyx.api.routes_detection_rules import detection_rules_router
from black_onyx.api.routes_detection import detection_router
from black_onyx.auth.middleware import SecurityMiddleware
from black_onyx.auth.routes import admin_router, router as auth_router
from black_onyx.config import get_settings
from black_onyx.taxii.server import taxii_router

logger = logging.getLogger(__name__)


def _problem(request: Request, status_code: int, title: str) -> JSONResponse:
    return JSONResponse(
        {
            "type": "about:blank",
            "title": title[:500],
            "status": status_code,
            "request_id": getattr(request.state, "request_id", ""),
        },
        status_code=status_code,
        media_type="application/problem+json",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: setup logging on startup."""
    from black_onyx.core.logging_config import setup_logging
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    structured = os.environ.get("STRUCTURED_LOGGING", "").lower() in ("1", "true", "yes")
    setup_logging(level=log_level, structured=structured)
    service = None
    try:
        from black_onyx.api.service import get_service
        service = get_service()
        try:
            service.ensure_default_collections()
        except Exception:
            logger.exception("Failed to ensure default Qdrant collections on startup")
        service.start_background_schedulers()
        yield
    finally:
        # Closes only what was actually constructed. Reading
        # `service.connector_manager` here instead would *build* a manager —
        # and with it a full Ingestor plus embedding model — during shutdown,
        # since that property has no enabled-guard.
        if service:
            service.shutdown()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title="Black Onyx",
        description="Consolidated Qdrant data ingestion with FastAPI web UI, LLM chat with RAG, and image ingestion",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.security.docs_enabled and not settings.security.production else None,
        redoc_url=None,
    )

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.security.allowed_hosts)
    app.add_middleware(SecurityMiddleware, config=settings.security)

    @app.exception_handler(HTTPException)
    async def http_problem(request: Request, exc: HTTPException) -> JSONResponse:
        title = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return _problem(request, exc.status_code, title)

    @app.exception_handler(RequestValidationError)
    async def validation_problem(request: Request, _exc: RequestValidationError) -> JSONResponse:
        return _problem(request, 422, "Request validation failed")

    @app.exception_handler(Exception)
    async def internal_problem(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled API error", exc_info=exc)
        return _problem(request, 500, "Internal server error")

    # Include API routes
    app.include_router(router)
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(connectors_router)
    app.include_router(analytics_router)
    app.include_router(assets_router)
    app.include_router(detection_rules_router)
    app.include_router(detection_router)
    app.include_router(backup_router)
    # TAXII before catch-all static so /taxii2/* is not swallowed by SPA fallback
    app.include_router(taxii_router)

    # Serve static files (web UI)
    # Look for web/ directory relative to the package, then relative to CWD
    web_dir: Path | None = None
    package_parent = Path(__file__).resolve().parent.parent.parent  # src/ -> project root
    candidates = [
        package_parent / "web" / "dist",
        Path.cwd() / "web" / "dist",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            web_dir = c
            break

    if web_dir:
        # Mount static assets directory (CSS, JS, images)
        assets_dir = web_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        # Serve index.html at root
        @app.get("/")
        async def serve_index() -> FileResponse:
            return FileResponse(str(web_dir / "index.html"))

        # Fallback for client-side routing — only for non-API paths
        @app.get("/{full_path:path}")
        async def serve_static(full_path: str) -> FileResponse:
            # Don't intercept API, WebSocket, or TAXII paths
            if (
                full_path.startswith("api/")
                or full_path.startswith("ws/")
                or full_path.startswith("taxii2/")
            ):
                raise HTTPException(status_code=404, detail=f"Not found: /{full_path}")
            candidate = (web_dir / full_path).resolve()
            try:
                candidate.relative_to(web_dir.resolve())
            except ValueError:
                raise HTTPException(status_code=404, detail="Not found")
            file_path = candidate
            if file_path.exists() and file_path.is_file():
                return FileResponse(str(file_path))
            # Fallback to index.html for SPA routing
            return FileResponse(str(web_dir / "index.html"))
    else:
        logger.warning("Built web/dist directory not found; web UI will not be served")

    return app


app = create_app()


def main() -> int:
    """Run the FastAPI server with uvicorn."""
    import argparse

    parser = argparse.ArgumentParser(description="Run the Black Onyx web UI server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", "-p", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--log-level", default="info", help="Log level")
    args = parser.parse_args()

    import uvicorn

    print(f"Starting Black Onyx web UI at http://{args.host}:{args.port}")
    uvicorn.run(
        "black_onyx.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
        proxy_headers=bool(get_settings().security.trusted_proxies),
        forwarded_allow_ips=",".join(get_settings().security.trusted_proxies) or "127.0.0.1",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
