"""API package — FastAPI app, routes, schemas, service layer."""

from black_onyx.api.app import app, create_app, main
from black_onyx.api.service import AppService, get_service

__all__ = [
    "AppService",
    "app",
    "create_app",
    "get_service",
    "main",
]
