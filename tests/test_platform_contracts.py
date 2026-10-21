"""Wire contracts for serving, security-tool approvals and deployment revisions."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"

PAIRS = [
    ("serving/model_serving_desired.schema.json", "serving/examples/valid_model_serving_desired.json"),
    ("serving/model_serving_report.schema.json", "serving/examples/valid_model_serving_report.json"),
    ("security-tools/tool_execution_request.schema.json", "security-tools/examples/valid_tool_execution_request.json"),
    ("security-tools/tool_approval_request.schema.json", "security-tools/examples/valid_tool_approval_request.json"),
    ("security-tools/agent_run_response.schema.json", "security-tools/examples/valid_agent_run_response.json"),
    ("admin/deployment_revision.schema.json", "admin/examples/valid_deployment_revision.json"),
]


def _load(rel: str) -> dict:
    return json.loads((CONTRACTS / rel).read_text(encoding="utf-8"))


@pytest.mark.parametrize(("schema_rel", "example_rel"), PAIRS)
def test_examples_validate(schema_rel: str, example_rel: str) -> None:
    schema = _load(schema_rel)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(_load(example_rel), schema)


def test_challenge_provider_registry_contract_pins_fixed_addresses() -> None:
    schema = _load("security-tools/challenge_provider_registry.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    valid = {
        "owned-lab": {
            "status_url": "http://challenge-api.security-lab.svc/status",
            "submit_url": "http://challenge-api.security-lab.svc/submit",
            "allowed_ips": ["10.88.0.10"],
        }
    }
    jsonschema.validate(valid, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"owned-lab": {**valid["owned-lab"], "redirect": "http://attacker.test"}}, schema)


def test_pending_agent_run_requires_run_id() -> None:
    schema = _load("security-tools/agent_run_response.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"answer": "", "rounds": 1, "status": "pending_approval"}, schema)


def test_live_deployment_revision_matches_contract(tmp_path, monkeypatch) -> None:
    from black_onyx.auth.database import StateDatabase
    from black_onyx.ops.deploy_controller import DeploymentController

    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "a" * 48)
    controller = DeploymentController(StateDatabase(str(tmp_path)))
    revision = controller.create_revision(
        "compose", env_changes={"BLACK_ONYX_DETECTION_TENANT": "acme"}, actor="admin-1",
    )
    jsonschema.validate(revision.as_dict(), _load("admin/deployment_revision.schema.json"))


def test_approval_digest_fields_match_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    gateway = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
    sys.path.insert(0, str(gateway))
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")
    from security_gateway.approvals import request_digest

    example = _load("security-tools/examples/valid_tool_approval_request.json")
    digest = request_digest("user-1", "Write", example)
    assert len(digest) == 64
    # Every field the digest binds is declared by the approval contract.
    bound = {
        "arguments", "session_id", "network_profile", "destinations", "ports",
        "lab_profile_id", "resolved_targets", "timeout",
    }
    assert bound <= set(_load("security-tools/tool_approval_request.schema.json")["properties"])
