"""Config-driven REST polling connector.

The escape hatch for any REST-exposing detection source that isn't worth a
named preset: base URL, auth style, endpoint path, pagination style, and a
dotted-path field mapping all live in the connector's `config` JSON blob
rather than in Python. `MicrosoftDefenderConnector` and
`CrowdStrikeFalconConnector` are thin subclasses that just supply this same
config with vendor-specific defaults baked in, so the OAuth2/pagination/
field-mapping plumbing is written once, here, and exercised by all three.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from black_onyx.connectors.base import DetectionConnector, DetectionPullResult
from black_onyx.models.data_model import DataModel
from black_onyx.net.safe_url import validate_public_https_url

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 30.0
# Hard ceiling on pages fetched per poll call — bounds worst-case work the
# same way feeds.py bounds response size; a source with more backlog than
# this just resumes from the same cursor on the next scheduled poll rather
# than blocking the scheduler indefinitely.
MAX_PAGES_PER_POLL = 20
# OAuth2 tokens are treated as expired this many seconds before their real
# expiry, so a token that would lapse mid-request is refreshed pre-emptively
# instead of failing a call already in flight.
TOKEN_REFRESH_MARGIN_SECONDS = 60
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


async def _bounded_json(
    client: httpx.AsyncClient, method: str, url: str, max_bytes: int, **kwargs: Any,
) -> tuple[Any, httpx.Response]:
    """Stream a response and parse JSON only if it stayed under `max_bytes` —
    mirrors feed_manager.py's `_safe_fetch` byte cap, so a connector can't be
    driven to exhaust memory by an oversized or runaway response body.
    Returns (parsed_body, response) — the response is kept for callers that
    need `.links` (RFC 5988 pagination), which is header-derived and still
    valid after the body stream is closed."""
    import json as _json
    async with client.stream(method, url, **kwargs) as response:
        response.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"Response exceeded {max_bytes} byte limit")
            chunks.append(chunk)
        return _json.loads(b"".join(chunks) or b"{}"), response


def _get_path(obj: Any, path: str) -> Any:
    """Traverse a dotted path (`a.b.c`) through nested dicts/lists. Numeric
    segments index into lists. Returns None if any segment is missing —
    deliberately permissive, since not every detection carries every mapped
    field, and normalize() must not raise on a partial vendor payload.

    Some real APIs use a literal dot inside a single key name rather than
    nesting — Microsoft Graph's `@odata.nextLink` is exactly one top-level
    key, not `obj["@odata"]["nextLink"]`. A literal-key match is tried first
    at the top level before falling back to dotted traversal, so both shapes
    resolve correctly without needing an escaping syntax in `path`.
    """
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    current = obj
    if not path:
        return current
    for segment in path.split("."):
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(segment)
        else:
            return None
    return current


class GenericRestConnector(DetectionConnector):
    """Config shape (all under the connector's `config` dict):

    base_url: str — required.
    auth: {
        "type": "none" | "api_key_header" | "bearer_token" | "oauth2_client_credentials",
        "header_name": str (api_key_header only, default "X-API-Key"),
        "token_url": str (oauth2 only),
        "scope": str | None (oauth2 only),
    }
    detections_path: str — path appended to base_url, e.g. "/api/alerts".
    query_params: dict[str, str] — static query params sent on every request.
    since_param: str | None — query param name carrying the ISO timestamp of
        the last successful poll (omitted if None).
    response_items_path: str — dotted path to the list of detection items in
        the response body ("" for a bare top-level list).
    pagination: {
        "style": "none" | "cursor" | "offset" | "link_header" | "body_next_link",
        "cursor_response_path": str (cursor style — where the next cursor
            lives in the response body),
        "cursor_param": str (cursor style — query param to send it back as),
        "page_size_param": str | None (offset style),
        "page_size": int (offset style, default 100),
        "offset_param": str (offset style, default "offset"),
        "next_link_path": str (body_next_link style — dotted path to a full
            next-page URL in the response body, e.g. "@odata.nextLink" for
            Microsoft Graph; the next request replaces the URL and params
            entirely rather than appending a cursor query param),
    }
    field_map: dict[str, str] — DataModel field name -> dotted path into a
        raw detection item. Only list-typed IOC fields and a few scalars
        (title, mitre_techniques, mitre_tactics) are supported; unmapped
        fields are simply left at their DataModel default.
    id_path: str — dotted path to a stable per-detection identifier, used to
        build `source_file` for traceability (defaults to "id").

    secrets (resolved values, never env-var names — the manager resolves
    `credential_env` to actual values before constructing the connector):
        api_key, bearer_token, client_id, client_secret.
    """

    def __init__(self, name: str, config: dict[str, Any], secrets: dict[str, str]) -> None:
        self._name = name
        self._config = config
        self._secrets = secrets
        self._base_url = validate_public_https_url(config["base_url"], purpose="Connector base_url")
        self._auth_token: str | None = None
        self._auth_token_expires_at: float = 0.0

    @property
    def name(self) -> str:
        return self._name

    @property
    def source_type(self) -> str:
        return "generic_rest"

    async def authenticate(self) -> None:
        auth = self._config.get("auth") or {}
        auth_type = auth.get("type", "none")
        if auth_type != "oauth2_client_credentials":
            return  # api_key_header/bearer_token carry their own value per-request; nothing to refresh
        if self._auth_token and time.monotonic() < self._auth_token_expires_at:
            return
        token_url = validate_public_https_url(auth["token_url"], purpose="Connector token_url")
        payload = {
            "grant_type": "client_credentials",
            "client_id": self._secrets.get("client_id", ""),
            "client_secret": self._secrets.get("client_secret", ""),
        }
        if auth.get("scope"):
            payload["scope"] = auth["scope"]
        max_bytes = self._config.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS, trust_env=False) as client:
            body, _ = await _bounded_json(client, "POST", token_url, max_bytes, data=payload)
        self._auth_token = body["access_token"]
        expires_in = float(body.get("expires_in", 3600))
        self._auth_token_expires_at = time.monotonic() + expires_in - TOKEN_REFRESH_MARGIN_SECONDS

    def _auth_headers(self) -> dict[str, str]:
        auth = self._config.get("auth") or {}
        auth_type = auth.get("type", "none")
        if auth_type == "api_key_header":
            header_name = auth.get("header_name", "X-API-Key")
            return {header_name: self._secrets.get("api_key", "")}
        if auth_type == "bearer_token":
            return {"Authorization": f"Bearer {self._secrets.get('bearer_token', '')}"}
        if auth_type == "oauth2_client_credentials":
            return {"Authorization": f"Bearer {self._auth_token or ''}"}
        return {}

    async def pull_detections(
        self, since: datetime | None, cursor: str | None,
    ) -> DetectionPullResult:
        await self.authenticate()
        pagination = self._config.get("pagination") or {"style": "none"}
        style = pagination.get("style", "none")
        items_path = self._config.get("response_items_path", "")
        url = self._base_url.rstrip("/") + self._config.get("detections_path", "")

        # httpx's `params=` REPLACES a URL's own query string wholesale, even
        # when given an empty dict — so once a full next-page URL (with its
        # own embedded query string) is in play, params must become None, not
        # {}, or the resume/next-page URL's query string gets silently wiped.
        params: dict[str, Any] | None = dict(self._config.get("query_params") or {})
        since_param = self._config.get("since_param")
        if since_param and since:
            params[since_param] = since.astimezone(timezone.utc).isoformat()

        if style == "cursor" and cursor:
            params[pagination.get("cursor_param", "cursor")] = cursor
        elif style == "offset":
            params[pagination.get("offset_param", "offset")] = 0
            params[pagination.get("page_size_param", "limit")] = pagination.get("page_size", 100)
        elif style in {"body_next_link", "link_header"} and cursor:
            # For both of these the persisted cursor *is* the previously-seen
            # next-page URL — resume there directly instead of restarting from
            # detections_path, since the whole point of these styles is that
            # the next page replaces the URL rather than appending a param.
            url, params = cursor, None

        all_items: list[dict[str, Any]] = []
        next_cursor = cursor
        page_size = pagination.get("page_size", 100)
        max_bytes = self._config.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)

        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
        ) as client:
            for page in range(MAX_PAGES_PER_POLL):
                body, response = await _bounded_json(
                    client, "GET", url, max_bytes, params=params, headers=self._auth_headers(),
                )
                page_items = _get_path(body, items_path) if items_path else body
                if not isinstance(page_items, list):
                    logger.warning(
                        "Connector %s: response_items_path did not resolve to a list", self._name,
                    )
                    break
                all_items.extend(page_items)

                if style == "cursor":
                    next_page_cursor = _get_path(body, pagination.get("cursor_response_path", ""))
                    if not next_page_cursor:
                        break
                    next_cursor = str(next_page_cursor)
                    params[pagination.get("cursor_param", "cursor")] = next_cursor
                elif style == "offset":
                    # Offset restarts from 0 every poll by design: an offset
                    # into a live, newest-first result set is not a stable
                    # resume point across polls, so the `since` filter (or the
                    # manager's seen-detection dedupe) is what actually bounds
                    # repeat work. Explicitly clear the cursor rather than
                    # leaving the previous poll's value in place.
                    next_cursor = None
                    if len(page_items) < page_size:
                        break
                    params[pagination.get("offset_param", "offset")] = (
                        params[pagination.get("offset_param", "offset")] + page_size
                    )
                elif style == "link_header":
                    next_link = response.links.get("next", {}).get("url")
                    if not next_link:
                        next_cursor = None  # drained — nothing to resume from
                        break
                    # Persist the next-page URL so hitting MAX_PAGES_PER_POLL
                    # resumes here rather than restarting from page one.
                    next_cursor = str(next_link)
                    url, params = next_cursor, None
                elif style == "body_next_link":
                    # Some REST APIs (Microsoft Graph's @odata.nextLink, and
                    # others with the same shape) put the *complete next-page
                    # URL* in the response body rather than a bare cursor
                    # token or an HTTP Link header — the next request replaces
                    # the URL entirely and carries no separate query params.
                    next_link = _get_path(body, pagination.get("next_link_path", ""))
                    if not next_link:
                        next_cursor = None  # no further pages — nothing to resume from next poll
                        break
                    next_cursor = str(next_link)
                    url, params = next_cursor, None
                else:  # "none" — single page only
                    break
            else:
                logger.warning(
                    "Connector %s: hit MAX_PAGES_PER_POLL (%d); resuming next poll",
                    self._name, MAX_PAGES_PER_POLL,
                )

        return DetectionPullResult(detections=all_items, next_cursor=next_cursor, raw_count=len(all_items))

    def normalize(self, raw: dict[str, Any]) -> DataModel:
        field_map: dict[str, str] = self._config.get("field_map") or {}
        id_path = self._config.get("id_path", "id")
        detection_id = _get_path(raw, id_path) or "unknown"

        list_fields = {
            "ip_addresses", "domains", "urls", "md5_hashes", "sha1_hashes",
            "sha256_hashes", "sha512_hashes", "cve_ids", "mitre_techniques", "mitre_tactics",
        }
        kwargs: dict[str, Any] = {
            "source_file": f"connector:{self._name}:{detection_id}",
            "payload_type": "text",
            "ioc_status": "new",
        }
        title = _get_path(raw, field_map.get("title", "")) if field_map.get("title") else None
        kwargs["title"] = str(title) if title else f"{self._name} detection {detection_id}"
        kwargs["body_text"] = str(raw)[:4000]  # best-effort embeddable summary of the raw detection

        for data_model_field, path in field_map.items():
            if data_model_field in {"title"}:
                continue  # handled above
            value = _get_path(raw, path)
            if value is None:
                continue
            if data_model_field in list_fields:
                kwargs[data_model_field] = [str(v) for v in value] if isinstance(value, list) else [str(value)]
            else:
                kwargs[data_model_field] = value

        return DataModel(**kwargs)
