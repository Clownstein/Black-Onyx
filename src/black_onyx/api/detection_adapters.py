"""Operation-specific request adapters for the detection BFF proxy.

Each detection mutation the BFF forwards is declared here with the exact
identity fields its upstream schema expects. Session identity (tenant and
actor) is always server-derived; client-supplied identity fields are
overwritten or removed. Mutations with no declared adapter fail closed.

``fields`` mirrors the upstream request model when that model forbids extra
keys, so the BFF rejects bad bodies before they reach the service.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from fastapi import HTTPException

TenantMode = Literal["inject", "strip"]
BodyKind = Literal["json", "none", "raw"]

_IDENTITY_FIELDS = ("tenant_id", "actor", "author", "created_by")


@dataclass(frozen=True)
class Adapter:
    upstream: str
    method: str
    pattern: str
    tenant: TenantMode = "strip"
    actor_field: str | None = None
    fields: frozenset[str] | None = None
    body: BodyKind = "json"

    def matches(self, upstream: str, method: str, path: str) -> bool:
        return (
            self.upstream == upstream
            and self.method == method
            and re.fullmatch(self.pattern, path) is not None
        )


_SEG = r"[^/]+"


def _f(*names: str) -> frozenset[str]:
    return frozenset(names)


ADAPTERS: tuple[Adapter, ...] = (
    # ── incident-api: tenant from X-Tenant-Id, actor from detection JWT ──
    Adapter("incident", "POST", r"api/v1/incidents"),
    Adapter("incident", "PATCH", rf"api/v1/incidents/{_SEG}"),
    Adapter("incident", "POST", rf"api/v1/incidents/{_SEG}/comments"),
    Adapter("incident", "POST", rf"api/v1/incidents/{_SEG}/disposition"),
    Adapter("incident", "POST", rf"api/v1/incidents/{_SEG}/feedback"),
    Adapter("incident", "POST", r"api/v1/findings"),
    Adapter("incident", "POST", r"api/v1/search"),
    Adapter("incident", "POST", r"api/v1/hunt/federated", fields=_f("query", "size")),
    Adapter("incident", "POST", r"api/v1/hunt/vector"),
    Adapter("incident", "POST", r"api/v1/deployments"),
    Adapter("incident", "POST", r"api/v1/saved-hunts"),
    Adapter("incident", "DELETE", rf"api/v1/saved-hunts/{_SEG}", body="none"),
    Adapter("incident", "PUT", rf"api/v1/settings/notifications/{_SEG}"),
    Adapter("incident", "POST", r"api/v1/security-profiles"),
    Adapter("incident", "PATCH", rf"api/v1/security-profiles/{_SEG}"),
    Adapter("incident", "DELETE", rf"api/v1/security-profiles/{_SEG}", body="none"),
    Adapter("incident", "POST", rf"api/v1/security-profiles/{_SEG}/evaluate", body="none"),
    Adapter("incident", "POST", rf"api/v1/security-profiles/{_SEG}/attest"),
    Adapter("incident", "POST", rf"api/v1/security-profiles/{_SEG}/exceptions"),
    Adapter("incident", "POST", rf"api/v1/security-profiles/{_SEG}/certification-package"),
    # ── asset-registry ──
    Adapter("assets", "POST", r"api/v1/assets"),
    Adapter("assets", "PUT", rf"api/v1/assets/{_SEG}"),
    Adapter("assets", "PATCH", rf"api/v1/assets/{_SEG}"),
    Adapter("assets", "DELETE", rf"api/v1/assets/{_SEG}", body="none"),
    # ── threat-intel-service (strict models without tenant_id) ──
    Adapter("ti", "POST", r"api/v1/indicators/upload-stix"),
    Adapter("ti", "POST", r"api/v1/feeds/(kev|taxii|misp)/sync", body="none"),
    Adapter("ti", "POST", r"api/v1/match", fields=_f("observables")),
    Adapter("ti", "POST", r"api/v1/match/semantic", fields=_f("observables", "top_k", "min_similarity")),
    Adapter("ti", "POST", r"api/v1/indicators/upsert", fields=_f("indicators")),
    # ── integration-hub ──
    Adapter("hub", "POST", r"api/v1/vuln/ingest", tenant="inject",
            fields=_f("tenant_id", "asset_id", "scanner", "report")),
    Adapter("hub", "POST", r"api/v1/integrations/siem/export", fields=_f("format", "incident")),
    Adapter("hub", "POST", r"api/v1/thehive/cases", fields=_f("incident", "case_id")),
    Adapter("hub", "POST", r"api/v1/response/request", tenant="inject", actor_field="actor",
            fields=_f("tenant_id", "incident_id", "playbook_id", "action", "dry_run", "payload", "actor")),
    Adapter("hub", "POST", rf"api/v1/response/{_SEG}/approve", actor_field="actor",
            fields=_f("actor", "dry_run")),
    Adapter("hub", "POST", r"api/v1/dfir/collect", tenant="inject",
            fields=_f("tenant_id", "asset_id", "artifact", "incident_id", "dry_run", "detail", "notes")),
    Adapter("hub", "POST", r"api/v1/identity/idp/sync", fields=_f("provider", "payload")),
    Adapter("hub", "POST", r"api/v1/identity/hr/sync", fields=_f("format", "csv_text", "payload")),
    Adapter("hub", "POST", r"api/v1/identity/evaluate", tenant="inject",
            fields=_f("tenant_id", "idp_users", "hr_employees")),
    # ── response-orchestrator ──
    Adapter("response", "POST", r"api/v1/response/request", tenant="inject", actor_field="actor",
            fields=_f("tenant_id", "incident_id", "playbook_id", "action", "dry_run", "payload", "actor")),
    Adapter("response", "POST", rf"api/v1/response/{_SEG}/approve", actor_field="actor",
            fields=_f("actor", "dry_run")),
    Adapter("response", "POST", rf"api/v1/response/{_SEG}/reject", actor_field="actor",
            fields=_f("actor", "dry_run")),
    Adapter("response", "POST", r"api/v1/response/reconciliation/scan", body="none"),
    # ── notification-service ──
    Adapter("notify", "POST", r"api/v1/notifications/test", tenant="inject",
            fields=_f("incident_id", "tenant_id", "title", "severity", "summary", "channels",
                      "email_to", "webhook_url")),
    Adapter("notify", "POST", r"api/v1/notifications/incident", tenant="inject"),
    Adapter("notify", "POST", r"api/v1/notifications/outbox/flush", body="none"),
    Adapter("notify", "POST", rf"api/v1/notifications/outbox/{_SEG}/retry", body="none"),
    # ── training-orchestrator ──
    Adapter("training", "POST", rf"api/v1/models/{_SEG}/training-jobs", tenant="inject",
            actor_field="created_by",
            fields=_f("tenant_id", "dataset_id", "source_query", "time_range_start", "time_range_end",
                      "excluded_incidents", "created_by", "hyperparameters", "run_async",
                      "dataset_path", "dataset_reviewed", "demo_synthetic")),
    Adapter("training", "POST", rf"api/v1/models/{_SEG}/versions/{_SEG}/promote", fields=_f("alias")),
    Adapter("training", "POST", rf"api/v1/models/{_SEG}/versions/{_SEG}/rollback", body="none"),
    Adapter("training", "POST", rf"api/v1/models/{_SEG}/drift/observations", tenant="inject",
            fields=_f("tenant_id", "observed")),
    # ── ingestion-gateway (Go; tenant is part of each event contract) ──
    Adapter("ingest", "POST", r"api/v1/ingest/[a-z-]+", tenant="inject", body="raw"),
    # Malware triage requires tenant_id in the JSON body and rejects anything
    # else. Multipart uploads stay untouched because they are not JSON.
    Adapter("ingest", "POST", r"api/v1/malware(/.*)?", tenant="inject", body="raw",
            fields=_f("tenant_id", "sha256", "sha1", "md5", "file_name", "content_base64",
                      "queue_sandbox", "policy_allow_detonate", "machine_profile", "asset_id")),
    # ── model-gateway ──
    Adapter("models", "POST", r"v1/predict", tenant="inject"),
)


def find_adapter(upstream: str, method: str, path: str) -> Adapter | None:
    method = method.upper()
    path = path.strip("/")
    for adapter in ADAPTERS:
        if adapter.matches(upstream, method, path):
            return adapter
    return None


def adapt_body(
    upstream: str,
    path: str,
    method: str,
    body: bytes,
    *,
    tenant_id: str,
    actor: str,
    content_type: str = "application/json",
) -> bytes:
    """Return the upstream body for one declared detection operation.

    Raises 404 for undeclared mutations, 403 for conflicting tenant identity
    and 422 for fields the upstream schema would reject.
    """
    adapter = find_adapter(upstream, method, path)
    if adapter is None:
        raise HTTPException(status_code=404, detail="Detection operation is not exposed by the BFF")
    if adapter.body == "none":
        return b""
    is_json = "json" in (content_type or "application/json").lower()
    if not body or (adapter.body == "raw" and not is_json):
        return body
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        if adapter.body == "raw":
            return body
        raise HTTPException(status_code=400, detail="Detection request body must be JSON") from exc
    if not isinstance(payload, dict):
        if adapter.body == "raw":
            return body
        raise HTTPException(status_code=422, detail="Detection request body must be a JSON object")
    supplied_tenant = payload.get("tenant_id")
    if supplied_tenant is not None and supplied_tenant != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_id does not match session tenant")
    for key in _IDENTITY_FIELDS:
        payload.pop(key, None)
    if adapter.tenant == "inject":
        payload["tenant_id"] = tenant_id
    if adapter.actor_field:
        payload[adapter.actor_field] = actor
    if adapter.fields is not None:
        unknown = sorted(set(payload) - adapter.fields)
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"Unsupported fields for this detection operation: {', '.join(unknown)}",
            )
    if "owner" in payload and str(payload.get("owner") or "").strip() in ("", "session"):
        payload["owner"] = actor
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")
