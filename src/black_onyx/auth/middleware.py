"""Session, CSRF, origin, RBAC, and response-security middleware."""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from black_onyx.auth.context import get_auth_service
from black_onyx.auth.service import Role
from black_onyx.config import SecurityConfig

SESSION_COOKIE = "__Host-blackonyx_session"
DEV_SESSION_COOKIE = "blackonyx_session"
CSRF_COOKIE = "blackonyx_csrf"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = {
    "/api/v1/health",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/password-reset/request",
    "/api/v1/auth/password-reset/confirm",
}
# Token-authenticated; skip session/CSRF/origin (validated in the route).
WEBHOOK_INGEST_PATH = "/api/v1/webhooks/events"
MCP_SERVICE_KEY_HEADER = "x-mcp-service-key"


def _has_machine_token_header(request: Request) -> bool:
    """True when the caller supplied a machine token header (not validated here)."""
    if (request.headers.get("x-webhook-token") or "").strip():
        return True
    if (request.headers.get("x-connector-token") or "").strip():
        return True
    auth = (request.headers.get("authorization") or "").strip()
    return auth.lower().startswith("bearer ")


def _is_token_ingest_request(request: Request) -> bool:
    """Machine-token ingest paths skip CSRF/origin only when a token header is present.

    Webhook ingest is always token-auth (route rejects missing/invalid tokens).
    Connector push is dual-mode: session+CSRF for admins, or push-token without CSRF.
    Treating every ``…/push`` as token ingest previously skipped CSRF for cookie
    sessions and enabled cross-site forged ingest.
    """
    if request.method != "POST":
        return False
    path = request.url.path
    if path == WEBHOOK_INGEST_PATH:
        return True
    if path.startswith("/api/v1/connectors/") and path.endswith("/push"):
        return _has_machine_token_header(request)
    return False


def _mcp_service_key_header(request: Request) -> str:
    return (request.headers.get(MCP_SERVICE_KEY_HEADER) or "").strip()


def session_cookie_name(config: SecurityConfig) -> str:
    """Use the hardened prefix only when the cookie satisfies its Secure contract."""
    return SESSION_COOKIE if config.secure_cookies else DEV_SESSION_COOKIE


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: SecurityConfig) -> None:
        super().__init__(app)
        self.config = config

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.request_id = request.headers.get("x-request-id") or secrets.token_hex(12)
        path = request.url.path
        is_api = path.startswith("/api/") or path.startswith("/ws/")
        auth = get_auth_service()
        mcp_key = _mcp_service_key_header(request)
        is_mcp_auth = False
        if mcp_key:
            mcp_principal = auth.principal_for_mcp_service_key(mcp_key)
            if mcp_principal is None:
                return self.problem(401, "Invalid MCP service key", request)
            request.state.principal = mcp_principal
            request.state.csrf_hash = ""
            is_mcp_auth = True
            session = None
        else:
            session_token = request.cookies.get(session_cookie_name(self.config), "")
            session = auth.principal_for_session(session_token) if session_token else None
            if session:
                request.state.principal, request.state.csrf_hash = session

        is_token_ingest = _is_token_ingest_request(request)
        skip_csrf_origin = is_token_ingest or is_mcp_auth

        if is_api and path not in PUBLIC_PATHS and not path.startswith("/api/v1/auth/"):
            if is_token_ingest:
                pass  # Bearer / X-Webhook-Token / X-Connector-Token validated in the route
            elif is_mcp_auth:
                denied = self._rbac_denied(request, request.state.principal.role)
                if denied:
                    return self.problem(403, "Insufficient permission", request)
            elif not session:
                return self.problem(401, "Authentication required", request)
            else:
                denied = self._rbac_denied(request, request.state.principal.role)
                if denied:
                    return self.problem(403, "Insufficient permission", request)

        if is_api and request.method not in SAFE_METHODS and not skip_csrf_origin:
            origin = request.headers.get("origin")
            if not self.config.allows_origin(origin):
                return self.problem(403, "Origin rejected", request)
            if path not in PUBLIC_PATHS:
                csrf = request.headers.get("x-csrf-token", "")
                if not session or not auth.verify_csrf(request.state.csrf_hash, csrf):
                    return self.problem(403, "CSRF validation failed", request)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        csp = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        # frame-src controls what OUR page may embed — orthogonal to
        # frame-ancestors above, which protects us from being framed by
        # others, and left untouched. Scoped to only the SPA shell response
        # (not every asset/API response, for performance — the same shape as
        # the production-only HSTS header just below) and to only the
        # authenticated user's own sites that were both opted into "embedded"
        # and already probe-confirmed frameable, so a site never becomes
        # embeddable just by being pinned — it has to have been checked.
        if getattr(request.state, "principal", None) and response.headers.get(
            "content-type", "",
        ).startswith("text/html"):
            origins = self._embedded_frame_origins(request.state.principal.user_id)
            if origins:
                csp += f"; frame-src 'self' {' '.join(sorted(origins))}"
        response.headers["Content-Security-Policy"] = csp
        if self.config.production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @staticmethod
    def _embedded_frame_origins(user_id: str) -> set[str]:
        rows = get_auth_service().db._conn.execute(
            "SELECT DISTINCT url FROM user_sites "
            "WHERE owner_user_id=? AND open_mode='embedded' AND frameable=1",
            (user_id,),
        ).fetchall()
        origins: set[str] = set()
        for row in rows:
            parsed = urlsplit(row["url"])
            if parsed.scheme and parsed.netloc:
                origins.add(f"{parsed.scheme}://{parsed.netloc}")
        return origins

    @staticmethod
    def _rbac_denied(request: Request, role: Role) -> bool:
        path, method = request.url.path, request.method
        if role is Role.ADMIN:
            return False
        if path.startswith("/api/v1/admin/"):
            return True
        if role is Role.VIEWER and method not in SAFE_METHODS:
            viewer_read_posts = {
                "/api/v1/search", "/api/v1/search/image", "/api/v1/attack/extract",
                "/api/v1/attack/heatmap", "/api/v1/graph/build", "/api/v1/graph/attack",
                "/api/v1/graph/entities",
            }
            # Sites are personal productivity data (pinned external links plus an
            # optional saved login), not privileged operations — every authenticated
            # role, including viewer, manages their own.
            if path not in viewer_read_posts and not path.startswith("/api/v1/sites"):
                return True
        if method == "DELETE" and path.startswith("/api/v1/collections/"):
            return True
        if role is not Role.ADMIN and method == "POST" and path == "/api/v1/collections":
            return True
        if role is not Role.ADMIN and (
            method == "DELETE" and path.startswith("/api/v1/feeds/")
            or method == "POST" and path == "/api/v1/feeds"
        ):
            return True
        return False

    @staticmethod
    def problem(status_code: int, detail: str, request: Request) -> JSONResponse:
        return JSONResponse(
            {"type": "about:blank", "title": detail, "status": status_code,
             "request_id": request.state.request_id},
            status_code=status_code,
            media_type="application/problem+json",
        )
