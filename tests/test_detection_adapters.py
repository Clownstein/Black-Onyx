"""Strict round trips between BFF detection adapters and upstream request models."""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from black_onyx.api.detection_adapters import ADAPTERS, adapt_body, find_adapter

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"

# (upstream, method, concrete path) -> (source file, strict model class)
STRICT_MODELS = {
    ("ti", "POST", "api/v1/match"): ("threat-intel-service/threat_intel_service/main.py", "MatchRequest"),
    ("ti", "POST", "api/v1/match/semantic"): ("threat-intel-service/threat_intel_service/main.py", "SemanticMatchRequest"),
    ("ti", "POST", "api/v1/indicators/upsert"): ("threat-intel-service/threat_intel_service/main.py", "IndicatorUpsertBatch"),
    ("hub", "POST", "api/v1/vuln/ingest"): ("integration-hub/integration_hub/main.py", "VulnIngestRequest"),
    ("hub", "POST", "api/v1/integrations/siem/export"): ("integration-hub/integration_hub/main.py", "SiemExportRequest"),
    ("hub", "POST", "api/v1/thehive/cases"): ("integration-hub/integration_hub/main.py", "TheHiveCaseRequest"),
    ("hub", "POST", "api/v1/response/request"): ("integration-hub/integration_hub/main.py", "ResponseRequestBody"),
    ("hub", "POST", "api/v1/response/r1/approve"): ("integration-hub/integration_hub/main.py", "ApproveBody"),
    ("hub", "POST", "api/v1/dfir/collect"): ("integration-hub/integration_hub/main.py", "DfirCollectBody"),
    ("hub", "POST", "api/v1/identity/idp/sync"): ("integration-hub/integration_hub/main.py", "IdpSyncRequest"),
    ("hub", "POST", "api/v1/identity/hr/sync"): ("integration-hub/integration_hub/main.py", "HrSyncRequest"),
    ("hub", "POST", "api/v1/identity/evaluate"): ("integration-hub/integration_hub/main.py", "IdentityEvaluateRequest"),
    ("response", "POST", "api/v1/response/request"): ("response-orchestrator/response_orchestrator/main.py", "RequestBody"),
    ("response", "POST", "api/v1/response/r1/approve"): ("response-orchestrator/response_orchestrator/main.py", "ApproveBody"),
    ("response", "POST", "api/v1/response/r1/reject"): ("response-orchestrator/response_orchestrator/main.py", "ApproveBody"),
    ("notify", "POST", "api/v1/notifications/test"): ("notification-service/notification_service/main.py", "NotificationTestRequest"),
    ("training", "POST", "api/v1/models/log-model/training-jobs"): ("training-orchestrator/training_orchestrator/schemas.py", "TrainingJobCreate"),
    ("training", "POST", "api/v1/models/log-model/versions/3/promote"): ("training-orchestrator/training_orchestrator/schemas.py", "PromoteRequest"),
    ("training", "POST", "api/v1/models/log-model/drift/observations"): ("training-orchestrator/training_orchestrator/schemas.py", "DriftObservationCreate"),
    ("incident", "POST", "api/v1/hunt/federated"): ("incident-api/incident_api/federated_hunt.py", "FederatedHuntRequest"),
}


def _model_fields(source: str, class_name: str) -> set[str]:
    files = [SERVICES / source]
    tree_by_file = {f: ast.parse(f.read_text(encoding="utf-8")) for f in files}
    for tree in tree_by_file.values():
        classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        if class_name not in classes:
            continue
        fields: set[str] = set()
        node = classes[class_name]
        while node is not None:
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    if stmt.target.id != "model_config":
                        fields.add(stmt.target.id)
            bases = [b.id for b in node.bases if isinstance(b, ast.Name) and b.id in classes]
            node = classes[bases[0]] if bases else None
        return fields
    raise AssertionError(f"{class_name} not found in {source}")


@pytest.mark.parametrize("key", sorted(STRICT_MODELS))
def test_adapter_fields_match_strict_upstream_model(key):
    upstream, method, path = key
    adapter = find_adapter(upstream, method, path)
    assert adapter is not None, key
    source, class_name = STRICT_MODELS[key]
    expected = _model_fields(source, class_name)
    assert adapter.fields == expected
    if adapter.tenant == "inject":
        assert "tenant_id" in expected
    else:
        assert "tenant_id" not in expected
    if adapter.actor_field:
        assert adapter.actor_field in expected


def test_every_adapter_is_reachable_and_unique():
    seen = set()
    for adapter in ADAPTERS:
        key = (adapter.upstream, adapter.method, adapter.pattern)
        assert key not in seen
        seen.add(key)


def test_threat_intel_match_never_receives_tenant():
    out = adapt_body(
        "ti", "api/v1/match", "POST", b'{"observables":[{"type":"ip","value":"1.2.3.4"}]}',
        tenant_id="tenant-a", actor="a@x",
    )
    assert json.loads(out) == {"observables": [{"type": "ip", "value": "1.2.3.4"}]}


def test_training_job_round_trip_stamps_tenant_and_creator():
    out = adapt_body(
        "training", "api/v1/models/log-model/training-jobs", "POST",
        b'{"dataset_id":"d1","created_by":"spoof","actor":"spoof"}',
        tenant_id="tenant-a", actor="alice@x",
    )
    assert json.loads(out) == {"dataset_id": "d1", "tenant_id": "tenant-a", "created_by": "alice@x"}


def test_promote_strips_identity_fields():
    out = adapt_body(
        "training", "api/v1/models/log-model/versions/3/promote", "POST",
        b'{"alias":"champion","tenant_id":"tenant-a","actor":"x"}',
        tenant_id="tenant-a", actor="alice@x",
    )
    assert json.loads(out) == {"alias": "champion"}


def test_unknown_fields_rejected_before_upstream():
    with pytest.raises(HTTPException) as exc:
        adapt_body(
            "response", "api/v1/response/r1/approve", "POST", b'{"dry_run":true,"force":true}',
            tenant_id="t", actor="a",
        )
    assert exc.value.status_code == 422


def test_undeclared_mutation_fails_closed():
    with pytest.raises(HTTPException) as exc:
        adapt_body("incident", "api/v1/admin/drop", "POST", b"{}", tenant_id="t", actor="a")
    assert exc.value.status_code == 404


def test_cross_tenant_body_rejected_on_every_json_adapter():
    for adapter in ADAPTERS:
        if adapter.body != "json":
            continue
        path = adapter.pattern.replace("[^/]+", "x").replace("(kev|taxii|misp)", "kev")
        with pytest.raises(HTTPException) as exc:
            adapt_body(adapter.upstream, path, adapter.method, b'{"tenant_id":"other"}',
                       tenant_id="mine", actor="a")
        assert exc.value.status_code == 403, adapter


def test_bodyless_operations_drop_client_body():
    out = adapt_body(
        "training", "api/v1/models/log-model/versions/3/rollback", "POST", b"{}",
        tenant_id="t", actor="a",
    )
    assert out == b""


def test_malware_json_gets_session_tenant():
    out = adapt_body(
        "ingest", "api/v1/malware/analyze", "POST",
        b'{"file_name":"sample.exe","content_base64":"YWI="}',
        tenant_id="tenant-a", actor="analyst@example.com",
    )
    assert json.loads(out) == {
        "file_name": "sample.exe",
        "content_base64": "YWI=",
        "tenant_id": "tenant-a",
    }


def test_multipart_malware_upload_passes_through():
    raw = b"--b\r\ncontent\r\n--b--"
    out = adapt_body(
        "ingest", "api/v1/malware/submit", "POST", raw,
        tenant_id="t", actor="a", content_type="multipart/form-data; boundary=b",
    )
    assert out == raw
