"""Inventory of every effective Black Onyx setting and where its value comes from.

Two kinds of settings exist:

* **Application settings** fields of :class:`black_onyx.config.Settings`.
  Their effective value is resolved (highest wins) from the administrator
  runtime override, ``QDRANT_<SECTION>__<FIELD>`` environment variables, the
  YAML config file, then the model default.
* **Deployment settings** environment variables consumed by the TIP process
  or by other services (security gateway/runner, detection services). The TIP
  process can only observe its own environment; values owned by other
  containers are managed through the deployment controller
  (:mod:`black_onyx.ops.deploy_controller`) and reported as ``deployment``.

Secret values are never returned: only whether a secret is configured.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, SecretStr

from .compose_setting_inventory import COMPOSE_DEPLOYMENT_SETTING_SPECS

# Sections the runtime admin API may change without a restart; every other
# section is read at startup (or by another process) and needs a restart.
LIVE_SECTIONS = frozenset({
    "llm", "ingestion", "chunking", "feeds", "qdrant", "web_search", "mcp_tools", "enrichment",
})

SECTION_CONSUMERS: dict[str, str] = {
    "ingestion": "black-onyx ingestion pipeline",
    "qdrant": "black-onyx vector store client",
    "embedding": "black-onyx embedding model",
    "ner": "black-onyx NER model",
    "classifier": "black-onyx classifier",
    "chunking": "black-onyx ingestion pipeline",
    "llm": "black-onyx chat / RAG providers",
    "image": "black-onyx image extraction",
    "ocr": "black-onyx OCR engine",
    "clip": "black-onyx CLIP model",
    "logging": "black-onyx logging",
    "enrichment": "black-onyx IOC enrichment",
    "threat_intel": "black-onyx threat-intel manager",
    "feeds": "black-onyx feed poller",
    "connectors": "black-onyx connector poller",
    "web_search": "black-onyx web search tool",
    "mcp_tools": "black-onyx in-chat MCP tool loop",
    "security_tools": "black-onyx security BFF",
    "storage": "black-onyx state database",
    "security": "black-onyx auth / HTTP security",
}

_SECRET_FIELD_SUFFIXES = ("api_key", "password", "secret", "token")


@dataclass(frozen=True)
class DeploymentSetting:
    """An environment-level setting and the process that consumes it."""

    name: str
    category: str
    consumers: tuple[str, ...]
    description: str
    secret: bool = False
    default: str | None = None
    # Values a production deployment must hold; enforced by the controller.
    production_required: str | None = None
    # Allowed values (for flags/enums); None means free text validated elsewhere.
    choices: tuple[str, ...] | None = None


_FLAG = ("true", "false")

DEPLOYMENT_SETTINGS: tuple[DeploymentSetting, ...] = (
    # Authentication and identity
    DeploymentSetting("BLACK_ONYX_AUTH_SECRET", "authentication",
                      ("black-onyx", "incident-api", "asset-registry"),
                      "Session/settings root secret and detection-service HMAC fallback.", secret=True),
    DeploymentSetting("BLACK_ONYX_MCP_SERVICE_KEY", "authentication", ("black-onyx", "black-onyx-tools"),
                      "MCP tool server service key (X-MCP-Service-Key).", secret=True),
    DeploymentSetting("BLACK_ONYX_MCP_ACTOR_USER_ID", "authentication", ("black-onyx-tools",),
                      "Analyst/admin user the MCP tool server acts as."),
    DeploymentSetting("BLACK_ONYX_DETECTION_TENANT", "authentication", ("black-onyx",),
                      "Tenant stamped on every detection BFF call."),
    DeploymentSetting("BLACK_ONYX_DEFAULT_TENANT_ID", "authentication", ("detection services",),
                      "Default detection tenant for service-side jobs."),
    DeploymentSetting("OIDC_DISABLED", "authentication", ("incident-api", "asset-registry"),
                      "Disable detection-service OIDC verification (isolated labs only).",
                      default="false", choices=_FLAG, production_required="false"),
    DeploymentSetting("ALLOW_DEMO_KEYS", "authentication", ("incident-api",),
                      "Accept demo service keys (isolated labs only).",
                      default="false", choices=_FLAG, production_required="false"),
    # MCP / security tool gates
    DeploymentSetting("SECURITY_GATEWAY_KEY", "security tools", ("black-onyx", "security-gateway"),
                      "HMAC key for BFF-signed gateway actor assertions (>=32 chars).", secret=True),
    DeploymentSetting("SECURITY_RUNNER_TOKEN", "security tools", ("security-gateway", "security-runner"),
                      "Gateway-to-runner bearer token.", secret=True),
    DeploymentSetting("SECURITY_APPROVAL_DB", "security tools", ("security-gateway",),
                      "Durable approval and paused-agent-run database path."),
    DeploymentSetting("SECURITY_AGENT_TOOL_HTTP_TIMEOUT", "security tools", ("security-gateway",),
                      "Agent-to-gateway tool-call timeout in seconds.", default="330"),
    DeploymentSetting("ENABLE_BASH_TOOL", "security tools", ("security-gateway",),
                      "Enable the gated Bash tool.", default="false", choices=_FLAG,
                      production_required="false"),
    DeploymentSetting("ENABLE_HYDRA", "security tools", ("security-gateway",),
                      "Enable hydra brute force.", default="false", choices=_FLAG),
    DeploymentSetting("ENABLE_TCPDUMP", "security tools", ("security-gateway",),
                      "Enable packet capture.", default="false", choices=_FLAG),
    DeploymentSetting("ENABLE_CAST_SEND", "security tools", ("security-gateway",),
                      "Enable blockchain transactions.", default="false", choices=_FLAG),
    DeploymentSetting("SQLMAP_EXPLOIT_MODE", "security tools", ("security-gateway", "black-onyx"),
                      "Allow sqlmap exploitation mode.", default="false", choices=_FLAG,
                      production_required="false"),
    DeploymentSetting("TOOL_APPROVAL", "security tools", ("black-onyx",),
                      "MCP tool approval policy.", default="required", choices=("required", "auto"),
                      production_required="required"),
    DeploymentSetting("SECURITY_TWO_PERSON_TIERS", "security tools", ("security-gateway",),
                      "Comma-separated tool tiers that need a second administrator's approval.",
                      default=""),
    DeploymentSetting("TOOL_ROUTER_ENABLED", "security tools", ("security-gateway",),
                      "Enable the FunctionGemma first-stage tool router.", default="false", choices=_FLAG),
    # Egress
    DeploymentSetting(
        "ALLOW_PUBLIC_TARGETS",
        "egress",
        ("security-gateway",),
        "Allow non-lab public scanning of third-party hosts (security-gateway network_profile=public). "
        "Security Lab tool runs stay gated by lab profiles and approvals; this flag only lifts the "
        "egress block on public IPs outside isolated lab networks.",
        default="false",
        choices=_FLAG,
    ),
    DeploymentSetting("ALLOW_PRIVATE_TARGETS", "egress", ("security-gateway",),
                      "Permit private network targets (isolated labs only).", default="false",
                      choices=_FLAG, production_required="false"),
    DeploymentSetting("ALLOWED_TARGETS", "egress", ("security-gateway",),
                      "Explicit target allowlist.", default=""),
    DeploymentSetting("SECURITY_EGRESS_NETWORK", "egress",
                      ("security-gateway", "security-runner"),
                      "Reserved egress network name; network tools remain disabled until per-job filtering is verified.",
                      default=""),
    DeploymentSetting("SECURITY_EGRESS_VERIFIED", "egress", ("security-gateway", "security-runner"),
                      "Operator attestation set only after independent per-job network escape testing.",
                      default="false", choices=_FLAG),
    DeploymentSetting("SECURITY_CAPTURE_VERIFIED", "egress", ("security-gateway", "security-runner"),
                      "Independent operator attestation for registered-lab packet capture isolation.",
                      default="false", choices=_FLAG),
    DeploymentSetting("SECURITY_LAB_PROFILES_JSON", "egress", ("security-runner",),
                      "Registered owned-lab networks, CIDRs, and exact TCP port scopes.", default=""),
    # Sandbox
    DeploymentSetting("SECURITY_SANDBOX_IMAGE", "sandbox", ("security-runner",),
                      "Digest-pinned sandbox image (name@sha256:...)."),
    DeploymentSetting("SECURITY_GUARD_IMAGE", "sandbox", ("security-runner",),
                      "Digest-pinned trusted per-job firewall and capture helper image."),
    DeploymentSetting("SECURITY_SESSIONS_HOST_ROOT", "sandbox", ("security-runner",),
                      "Host directory holding per-session workspaces."),
    DeploymentSetting("SECURITY_DOCKER_SOCKET_GID", "sandbox", ("security-runner",),
                      "Group ID authorized to use the Docker socket."),
    DeploymentSetting("SANDBOX_RUNNER_RUNTIME", "sandbox", ("security-runner",),
                      "OCI runtime for sandbox containers (runc, runsc).", default="runc"),
    DeploymentSetting("BLACK_ONYX_BFF_INTERNAL_URL", "security tools", ("security-gateway",),
                      "Fixed internal TIP BFF origin for actor-bound trusted adapters."),
    DeploymentSetting("SECURITY_CHALLENGE_PROVIDERS_JSON", "security tools", ("security-gateway",),
                      "Operator-registered challenge IDs, fixed endpoints, and exact IPv4 pins.", default=""),
    DeploymentSetting("SECURITY_RUNNER_MAX_JOBS_PER_SESSION", "sandbox", ("security-runner",),
                      "Maximum concurrent jobs in one session.", default="2"),
    DeploymentSetting("SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES", "sandbox", ("security-runner",),
                      "Maximum session workspace size in bytes.", default="1073741824"),
    # Providers
    DeploymentSetting("LLM_BASE_URL", "providers", ("security-gateway",),
                      "Security agent LLM endpoint."),
    DeploymentSetting("LLM_MODEL_NAME", "providers", ("security-gateway",), "Security agent model name."),
    DeploymentSetting("OPENAI_API_KEY", "providers", ("black-onyx",), "OpenAI API key.", secret=True),
    DeploymentSetting("ANTHROPIC_API_KEY", "providers", ("black-onyx",), "Anthropic API key.", secret=True),
    DeploymentSetting("GEMINI_API_KEY", "providers", ("black-onyx",), "Gemini API key.", secret=True),
    DeploymentSetting("OPENROUTER_API_KEY", "providers", ("black-onyx",), "OpenRouter API key.", secret=True),
    DeploymentSetting("FIRECRAWL_API_KEY", "providers", ("black-onyx",), "Firecrawl API key.", secret=True),
    # Model / training
    DeploymentSetting("TRAINING_API_KEY", "model/training", ("black-onyx", "training-orchestrator"),
                      "Training orchestrator service key.", secret=True),
    DeploymentSetting("TRAINING_ARTIFACT_SIGNING_KEY", "model/training",
                      ("training-orchestrator", "inference-worker", "model-gateway"),
                      "Model package signing key.", secret=True),
    DeploymentSetting("TRAINING_DATASETS_DIR", "model/training", ("training-orchestrator",),
                      "Reviewed dataset root."),
    DeploymentSetting("MODEL_GATEWAY_API_KEY", "model/training",
                      ("black-onyx", "model-gateway", "inference-worker"),
                      "Model gateway service key.", secret=True),
    DeploymentSetting("INFER_API_KEY", "model/training", ("inference-worker",),
                      "Inference API key.", secret=True),
    DeploymentSetting("CODE_PROCESSOR_CODEQL_ENABLED", "model/training", ("code-processor",),
                      "Enable CodeQL analysis in the code processor.", default="false", choices=_FLAG),
    DeploymentSetting("CODE_PROCESSOR_CODEQL_RAM_MB", "model/training", ("code-processor",),
                      "Maximum CodeQL memory in MiB.", default="1024"),
    DeploymentSetting("CODE_PROCESSOR_MEMORY_LIMIT", "model/training", ("code-processor",),
                      "Container memory limit for the code processor.", default="2g"),
    # Connectors / detection service keys
    DeploymentSetting("INCIDENT_API_SERVICE_KEY", "connectors", ("black-onyx", "incident-api"),
                      "Incident API service key.", secret=True),
    DeploymentSetting("THREAT_INTEL_SERVICE_API_KEY", "connectors", ("black-onyx", "threat-intel-service"),
                      "Threat intel service key.", secret=True),
    DeploymentSetting("INTEGRATION_HUB_API_KEY", "connectors", ("black-onyx", "integration-hub"),
                      "Integration hub service key.", secret=True),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_API_KEY", "connectors",
                      ("black-onyx", "response-orchestrator", "integration-hub"),
                      "Response orchestrator service key.", secret=True),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_APPROVER_API_KEY", "connectors", ("black-onyx", "response-orchestrator"),
                      "Server-held credential for live response approval.", secret=True),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_EDR_PROVIDER", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "EDR backend for isolate-host. Empty uses the generic EDR API; wazuh uses active response."),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_API_URL", "routing",
                      ("response-orchestrator", "integration-hub"),
                      "Wazuh server API URL used to dispatch host isolation."),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_API_USER", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "Wazuh server API user for host isolation.", secret=True),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_API_PASSWORD", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "Wazuh server API password for host isolation.", secret=True),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_API_CA_FILE", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "CA bundle path for the Wazuh server API."),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_API_VERIFY_TLS", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "Verify the Wazuh server API certificate.", default="true", choices=_FLAG),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_AR_COMMAND", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "Linux Wazuh active-response command for host isolation.",
                      default="!black-onyx-isolate"),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_AR_COMMAND_WINDOWS", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "Windows Wazuh active-response command for host isolation.",
                      default="!black-onyx-isolate.cmd"),
    DeploymentSetting("RESPONSE_ORCHESTRATOR_WAZUH_ISOLATION_ALLOW", "connectors",
                      ("response-orchestrator", "integration-hub"),
                      "Comma-separated IPs or CIDRs an isolated host may still reach."),
    DeploymentSetting("API_KEYS", "connectors", ("ingestion-gateway", "black-onyx"),
                      "Ingestion gateway API keys.", secret=True),
    DeploymentSetting("ASSET_REGISTRY_SERVICE_KEY", "connectors",
                      ("black-onyx", "asset-registry", "collector-enroll", "host-state-processor"),
                      "Asset registry service key.", secret=True),
    DeploymentSetting("OBJECT_STORE_ACCESS_KEY", "connectors",
                      ("incident-api", "ids-processor", "malware-triage", "malware-orchestrator"),
                      "Least-privilege object-store access key for evidence services.", secret=True),
    DeploymentSetting("OBJECT_STORE_SECRET_KEY", "connectors",
                      ("incident-api", "ids-processor", "malware-triage", "malware-orchestrator"),
                      "Least-privilege object-store secret for evidence services.", secret=True),
    DeploymentSetting("EMBEDDING_API_KEY", "connectors",
                      ("embedding-worker", "incident-api", "correlation-engine", "profile-evaluator", "threat-intel-service"),
                      "Embedding service key.", secret=True),
    DeploymentSetting("MALWARE_SERVICE_API_KEY", "connectors",
                      ("malware-orchestrator", "malware-triage", "ingestion-gateway"),
                      "Malware service key.", secret=True),
    DeploymentSetting("CODE_ENRICHMENT_API_KEY", "connectors", ("code-enrichment-worker",),
                      "Code enrichment worker API key.", secret=True),
    DeploymentSetting("CAPE_URL", "connectors", ("malware-orchestrator",),
                      "Operator-managed CAPE service URL."),
    DeploymentSetting("CAPE_TOKEN", "connectors", ("malware-orchestrator",),
                      "Operator-managed CAPE service token.", secret=True),
    DeploymentSetting("CAPE_GUEST_IMAGE_URL", "connectors", ("bootstrap",),
                      "Operator-controlled HTTPS URL for the KVM analysis guest."),
    DeploymentSetting("CAPE_GUEST_IMAGE_SHA256", "connectors", ("bootstrap",),
                      "Required SHA-256 for the KVM analysis guest."),
    DeploymentSetting("CAPE_GUEST_IMAGE_FILE", "connectors", ("bootstrap",),
                      "Filename for the verified KVM guest image.", default="win10.qcow2"),
    DeploymentSetting("PROCESSOR_API_KEY", "connectors", ("detection processors",),
                      "Detection processor service key.", secret=True),
    DeploymentSetting("PROFILE_EVALUATOR_API_KEY", "connectors", ("profile-evaluator",),
                      "Profile evaluator service key.", secret=True),
    DeploymentSetting("WEBHOOK_SECRETS", "connectors", ("ingestion-gateway",),
                      "Code-provider webhook secrets.", secret=True),
    DeploymentSetting("VIRUSTOTAL_API_KEY", "connectors", ("black-onyx",), "VirusTotal key.", secret=True),
    DeploymentSetting("ABUSEIPDB_API_KEY", "connectors", ("black-onyx",), "AbuseIPDB key.", secret=True),
    DeploymentSetting("SHODAN_API_KEY", "connectors", ("black-onyx", "security-gateway"), "Shodan key.", secret=True),
    DeploymentSetting("OTX_API_KEY", "connectors", ("black-onyx",), "AlienVault OTX key.", secret=True),
    DeploymentSetting("MISP_API_KEY", "connectors", ("black-onyx",), "MISP key.", secret=True),
    DeploymentSetting(
        "BLACK_ONYX_MISP_INTERNAL_HOSTS",
        "connectors",
        ("black-onyx", "cli"),
        "Comma-separated hostnames allowed for internal Docker MISP (http).",
        default="misp",
    ),
    DeploymentSetting("MISP_DB_PASSWORD", "connectors", ("misp", "misp-db"),
                      "MISP MariaDB application password.", secret=True),
    DeploymentSetting("MISP_DB_ROOT_PASSWORD", "connectors", ("misp-db",),
                      "MISP MariaDB root password.", secret=True),
    DeploymentSetting("MISP_ADMIN_EMAIL", "connectors", ("misp",),
                      "MISP initial admin email.", default="admin@localhost"),
    DeploymentSetting("MISP_ADMIN_PASSPHRASE", "connectors", ("misp",),
                      "MISP initial admin passphrase.", secret=True),
    DeploymentSetting("MISP_HOST_PORT", "connectors", ("misp",),
                      "Loopback host port for the bundled MISP UI.", default="8088"),
    DeploymentSetting("INGEST_GATEWAY_HOST_PORT", "infrastructure", ("ingestion-gateway",),
                      "Loopback host port for the ingestion gateway.", default="18090"),
    DeploymentSetting("INGEST_GATEWAY_REMOTE_BIND", "infrastructure", ("ingestion-gateway",),
                      "Non-loopback bind for remote agents (Tailscale IP).", default="127.0.0.1"),
    DeploymentSetting("INGEST_GATEWAY_REMOTE_PORT", "infrastructure", ("ingestion-gateway",),
                      "Published port for the remote ingest bind.", default="18091"),
    DeploymentSetting("INGEST_GATEWAY_REMOTE_URL", "infrastructure", ("black-onyx",),
                      "Explicit gateway URL shown to remote collectors (overrides bind/port)."),
    DeploymentSetting("ASSET_REGISTRY_HOST_PORT", "infrastructure", ("asset-registry",),
                      "Loopback host port for asset-registry.", default="18081"),
    DeploymentSetting("ASSET_REGISTRY_REMOTE_BIND", "infrastructure", ("asset-registry",),
                      "Non-loopback bind for remote agents (Tailscale IP).", default="127.0.0.1"),
    DeploymentSetting("ASSET_REGISTRY_REMOTE_PORT", "infrastructure", ("asset-registry",),
                      "Published port for the remote registry bind.", default="18082"),
    DeploymentSetting("ASSET_REGISTRY_REMOTE_URL", "infrastructure", ("black-onyx",),
                      "Explicit registry URL shown to remote collectors (overrides bind/port)."),
    DeploymentSetting("WAZUH_MANAGER_ADDRESS", "connectors", ("black-onyx",),
                      "Host/IP Wazuh agents use to reach the host manager (collector guides)."),
    DeploymentSetting("BLACK_ONYX_COLLECTOR_INGEST_KEY", "connectors", ("black-onyx",),
                      "Ingestion key handed to collectors (defaults to the first API_KEYS entry).",
                      secret=True),
    DeploymentSetting("WAZUH_REGISTRATION_PASSWORD", "connectors", ("black-onyx",),
                      "Wazuh agent enrollment (authd) password, generated by install_wazuh_host.sh.",
                      secret=True),
    # Notifications
    DeploymentSetting("NOTIFICATION_API_KEY", "notifications", ("black-onyx", "notification-service"),
                      "Notification service key.", secret=True),
    DeploymentSetting("NOTIFICATION_WEBHOOK_URL", "notifications", ("notification-service",),
                      "Default notification webhook."),
    DeploymentSetting("NOTIFICATION_DEFAULT_EMAIL_TO", "notifications", ("notification-service",),
                      "Default email recipient."),
    DeploymentSetting("SMTP_HOST", "notifications", ("notification-service",), "SMTP relay host."),
    DeploymentSetting("SMTP_USERNAME", "notifications", ("notification-service", "black-onyx"),
                      "SMTP username.", secret=True),
    DeploymentSetting("SMTP_PASSWORD", "notifications", ("notification-service", "black-onyx"),
                      "SMTP password.", secret=True),
    DeploymentSetting("NOTIFICATION_SMTP_PASSWORD", "notifications",
                      ("notification-service", "notification-outbox-worker"),
                      "Notification SMTP password.", secret=True),
    DeploymentSetting("NOTIFICATION_WEBHOOK_SECRET", "notifications", ("notification-service", "black-onyx"),
                      "Notification webhook signing secret.", secret=True),
    # Shared infrastructure secrets are managed through approved deployment revisions.
    DeploymentSetting("BLACK_ONYX_DATABASE_URL", "infrastructure", ("black-onyx", "postgres"),
                      "Postgres URL for auth + tip schemas (database black_onyx). Required in production.",
                      secret=True),
    DeploymentSetting("SECURITY_GATEWAY_DATABASE_URL", "infrastructure", ("security-gateway", "postgres"),
                      "Postgres URL for security-gateway approvals and challenge state "
                      "(also read by web backups).", secret=True),
    DeploymentSetting("POSTGRES_PASSWORD", "infrastructure", ("postgres", "detection services"),
                      "Detection Postgres password.", secret=True,
                      default="__COMPOSE_SECRET_DEFAULT_CONFIGURED__"),
    DeploymentSetting("REDIS_PASSWORD", "infrastructure", ("redis", "correlation-engine"),
                      "Detection Redis password.", secret=True,
                      default="__COMPOSE_SECRET_DEFAULT_CONFIGURED__"),
    DeploymentSetting("MINIO_ROOT_PASSWORD", "infrastructure",
                      ("minio", "incident-api", "ingestion-gateway"),
                      "MinIO root password.", secret=True),
    DeploymentSetting("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "infrastructure",
                      ("opensearch", "incident-api"),
                      "OpenSearch initial administrator password.", secret=True),
    DeploymentSetting("SEARXNG_SECRET", "infrastructure", ("searxng",),
                      "SearXNG application secret.", secret=True,
                      default="__COMPOSE_SECRET_DEFAULT_CONFIGURED__"),
    # Retention and backup
    DeploymentSetting("BLACK_ONYX_BACKUP_RETENTION", "retention", ("black-onyx",),
                      "Number of backup archives kept under storage.state_dir/backups (0 keeps all).", default="7"),
    DeploymentSetting("BLACK_ONYX_AUDIT_RETENTION_DAYS", "retention", ("black-onyx",),
                      "Audit event retention in days (0 keeps all).", default="365"),
)

DEPLOYMENT_SETTINGS += tuple(DeploymentSetting(*spec) for spec in COMPOSE_DEPLOYMENT_SETTING_SPECS)
DEPLOYMENT_SETTINGS_BY_NAME = {item.name: item for item in DEPLOYMENT_SETTINGS}


@dataclass
class SettingEntry:
    key: str
    section: str
    kind: str
    type: str
    desired: Any
    effective: Any
    default: Any
    source: str
    consumers: list[str]
    editable: bool
    restart_required: bool
    secret: bool
    validation: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "section": self.section, "kind": self.kind, "type": self.type,
            "desired": self.desired, "effective": self.effective, "default": self.default,
            "source": self.source, "consumers": self.consumers, "editable": self.editable,
            "restart_required": self.restart_required, "secret": self.secret,
            "validation": self.validation, "description": self.description,
        }


def _is_secret_field(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in _SECRET_FIELD_SUFFIXES) and not lowered.endswith("_env")


def _plain(value: Any) -> Any:
    if isinstance(value, SecretStr):
        return "***"
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, Path):
        return str(value)
    return value


def _lookup(data: dict[str, Any] | None, path: tuple[str, ...]) -> tuple[bool, Any]:
    current: Any = data or {}
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _constraints(info: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in getattr(info, "metadata", []) or []:
        for attr in ("ge", "gt", "le", "lt", "min_length", "max_length", "pattern"):
            value = getattr(item, attr, None)
            if value is not None:
                out[attr] = value
    annotation = getattr(info, "annotation", None)
    choices = getattr(annotation, "__args__", None)
    if choices and all(isinstance(choice, str) for choice in choices):
        out["choices"] = list(choices)
    return out


def _type_name(info: Any) -> str:
    annotation = getattr(info, "annotation", None)
    name = getattr(annotation, "__name__", None)
    return name or str(annotation).replace("typing.", "")


def load_yaml_config(path: str | None) -> dict[str, Any]:
    if not path or not Path(path).is_file():
        return {}
    import yaml

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def application_entries(
    effective: BaseModel,
    runtime_config: dict[str, Any],
    yaml_config: dict[str, Any],
    environ: dict[str, str] | None = None,
) -> list[SettingEntry]:
    """Walk every Settings leaf field and resolve its source."""
    environ = dict(os.environ if environ is None else environ)
    entries: list[SettingEntry] = []

    def walk(model: BaseModel, path: tuple[str, ...]) -> None:
        for name, info in type(model).model_fields.items():
            value = getattr(model, name)
            full = (*path, name)
            if isinstance(value, BaseModel):
                walk(value, full)
                continue
            section = full[0]
            env_name = "QDRANT_" + "__".join(part.upper() for part in full)
            has_runtime, desired = _lookup(runtime_config, full)
            if has_runtime:
                source = "runtime"
            elif env_name in environ:
                source = "environment"
            elif _lookup(yaml_config, full)[0]:
                source = "config_file"
            else:
                source = "default"
            secret = _is_secret_field(name)
            default = info.get_default(call_default_factory=True) if not info.is_required() else None
            live = section in LIVE_SECTIONS
            entries.append(SettingEntry(
                key=".".join(full),
                section=section,
                kind="application",
                type=_type_name(info),
                desired=None if secret else (_plain(desired) if has_runtime else None),
                effective={"configured": bool(value)} if secret else _plain(value),
                default=None if secret else _plain(default),
                source=source,
                consumers=[SECTION_CONSUMERS.get(section, "black-onyx")],
                editable=live and not secret,
                restart_required=not live,
                secret=secret,
                validation=_constraints(info),
                description=str(info.description or ""),
            ))

    walk(effective, ())
    return entries


def deployment_entries(
    desired_env: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
) -> list[SettingEntry]:
    """Report deployment settings; ``desired_env`` comes from the active revision."""
    environ = dict(os.environ if environ is None else environ)
    desired_env = desired_env or {}
    entries = []
    for item in DEPLOYMENT_SETTINGS:
        visible = item.name in environ
        if visible:
            source, raw = "environment", environ[item.name]
        elif item.name in desired_env:
            source, raw = "deployment", desired_env[item.name]
        elif item.default is not None:
            source, raw = "default", item.default
        else:
            source, raw = "unset", None
        in_tip = "black-onyx" in item.consumers
        if item.secret:
            effective: Any = {"configured": bool(raw)}
            desired: Any = {"configured": bool(desired_env.get(item.name))} if item.name in desired_env else None
        else:
            effective = raw if (visible or not in_tip) else (raw if source == "default" else None)
            desired = desired_env.get(item.name)
        validation: dict[str, Any] = {}
        if item.choices:
            validation["choices"] = list(item.choices)
        if item.production_required is not None:
            validation["production_required"] = item.production_required
        entries.append(SettingEntry(
            key=item.name, section=item.category, kind="deployment", type="string",
            desired=desired, effective=effective, default=None if item.secret else item.default, source=source,
            consumers=list(item.consumers), editable=True, restart_required=True,
            secret=item.secret, validation=validation, description=item.description,
        ))
    return entries


def validate_deployment_value(name: str, value: str, *, production: bool) -> str | None:
    """Return an error for an invalid deployment value, else None."""
    item = DEPLOYMENT_SETTINGS_BY_NAME.get(name)
    if item is None:
        return f"{name} is not a managed deployment setting"
    if "\x00" in value or "\n" in value or len(value) > 8192:
        return f"{name} contains invalid characters or is too long"
    if item.choices and value.lower() not in item.choices:
        return f"{name} must be one of: {', '.join(item.choices)}"
    if production and item.production_required is not None and value.lower() != item.production_required:
        return f"{name} must be {item.production_required!r} in production"
    if name == "SECURITY_GATEWAY_KEY" and value and len(value) < 32:
        return "SECURITY_GATEWAY_KEY must be at least 32 characters"
    if name in {"SECURITY_RUNNER_MAX_JOBS_PER_SESSION", "SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES"}:
        try:
            amount = int(value)
        except ValueError:
            return f"{name} must be a positive integer"
        if amount <= 0:
            return f"{name} must be a positive integer"
    if name in {"SECURITY_AGENT_TOOL_HTTP_TIMEOUT", "CODE_PROCESSOR_CODEQL_RAM_MB"}:
        try:
            amount = int(value)
        except ValueError:
            return f"{name} must be a positive integer"
        if amount <= 0:
            return f"{name} must be a positive integer"
    if name == "SECURITY_DOCKER_SOCKET_GID":
        try:
            group_id = int(value)
        except ValueError:
            return "SECURITY_DOCKER_SOCKET_GID must be a nonnegative integer"
        if group_id < 0:
            return "SECURITY_DOCKER_SOCKET_GID must be a nonnegative integer"
    if name == "SECURITY_SANDBOX_IMAGE" and value:
        import re

        if not re.fullmatch(r"(?:[^\s]+@)?sha256:[a-f0-9]{64}", value):
            return "SECURITY_SANDBOX_IMAGE must be pinned by sha256 digest"
    return None


# Deployment settings the detection Helm chart consumes, mapped to keys of the
# operator Secret (``secrets.name``, default black-onyx-detection-secrets).
HELM_SECRET_KEYS: dict[str, str] = {
    "BLACK_ONYX_AUTH_SECRET": "oidcHsSecret",
    "OBJECT_STORE_ACCESS_KEY": "objectStoreAccessKey",
    "OBJECT_STORE_SECRET_KEY": "objectStoreSecretKey",
    "PROCESSOR_API_KEY": "processorApiKey",
    "EMBEDDING_API_KEY": "embeddingApiKey",
    "ASSET_REGISTRY_SERVICE_KEY": "assetRegistryServiceKey",
    "PROFILE_EVALUATOR_API_KEY": "profileEvaluatorApiKey",
    "CODE_ENRICHMENT_API_KEY": "codeEnrichmentApiKey",
    "MALWARE_SERVICE_API_KEY": "malwareServiceApiKey",
    "CAPE_URL": "capeUrl",
    "CAPE_TOKEN": "capeToken",
    "MODEL_GATEWAY_API_KEY": "modelGatewayApiKey",
    "INFER_API_KEY": "inferApiKey",
    "INCIDENT_API_SERVICE_KEY": "incidentApiServiceKey",
    "THREAT_INTEL_SERVICE_API_KEY": "threatIntelServiceKey",
    "INTEGRATION_HUB_API_KEY": "integrationHubApiKey",
    "RESPONSE_ORCHESTRATOR_API_KEY": "responseOrchestratorApiKey",
    "RESPONSE_ORCHESTRATOR_APPROVER_API_KEY": "responseApproverApiKey",
    "RESPONSE_ORCHESTRATOR_WAZUH_API_USER": "wazuhApiUser",
    "RESPONSE_ORCHESTRATOR_WAZUH_API_PASSWORD": "wazuhApiPassword",
    "API_KEYS": "ingestApiKeys",
    "NOTIFICATION_API_KEY": "notificationApiKey",
    "NOTIFICATION_WEBHOOK_SECRET": "notificationWebhookSecret",
    "SMTP_PASSWORD": "notificationSmtpPassword",
    "TRAINING_API_KEY": "trainingApiKey",
    "TRAINING_ARTIFACT_SIGNING_KEY": "trainingArtifactSigningKey",
}

# Every key written by the signed Helm handoff is scoped to the namespace and
# Deployment that consume it. This keeps credentials from being copied into
# unrelated workload namespaces and drives targeted rollout restarts.
HELM_SECRET_CONSUMERS: dict[str, dict[str, tuple[str, ...]]] = {
    "BLACK_ONYX_AUTH_SECRET": {"application": ("incident-api", "asset-registry")},
    "OBJECT_STORE_ACCESS_KEY": {
        "application": ("incident-api",),
        "processing": ("ids-processor", "malware-triage", "malware-orchestrator"),
    },
    "OBJECT_STORE_SECRET_KEY": {
        "application": ("incident-api",),
        "processing": ("ids-processor", "malware-triage", "malware-orchestrator"),
    },
    "PROCESSOR_API_KEY": {"processing": (
        "code-processor", "flow-processor", "firewall-processor", "host-state-processor",
        "ids-processor", "malware-processor", "metrics-processor",
    )},
    "EMBEDDING_API_KEY": {
        "processing": ("embedding-worker", "correlation-engine"),
        "application": ("profile-evaluator",),
    },
    "ASSET_REGISTRY_SERVICE_KEY": {
        "application": ("asset-registry",),
        "processing": ("correlation-engine", "host-state-processor"),
    },
    "PROFILE_EVALUATOR_API_KEY": {"application": ("profile-evaluator",)},
    "CODE_ENRICHMENT_API_KEY": {"processing": ("code-enrichment-worker",)},
    "MALWARE_SERVICE_API_KEY": {
        "ingestion": ("ingestion-gateway",),
        "processing": ("malware-triage", "malware-orchestrator"),
    },
    "CAPE_URL": {"processing": ("malware-orchestrator",)},
    "CAPE_TOKEN": {"processing": ("malware-orchestrator",)},
    "MODEL_GATEWAY_API_KEY": {
        "models": ("model-gateway",),
        "processing": ("inference-worker",),
    },
    "INFER_API_KEY": {"processing": ("inference-worker",)},
    "INCIDENT_API_SERVICE_KEY": {
        "application": ("incident-api", "integration-hub", "profile-evaluator"),
        "processing": ("correlation-engine", "code-enrichment-worker", "inference-worker"),
    },
    "THREAT_INTEL_SERVICE_API_KEY": {
        "application": ("threat-intel-service", "integration-hub"),
        "processing": ("correlation-engine",),
    },
    "INTEGRATION_HUB_API_KEY": {"application": ("integration-hub",)},
    "RESPONSE_ORCHESTRATOR_API_KEY": {"application": ("response-orchestrator",)},
    "RESPONSE_ORCHESTRATOR_APPROVER_API_KEY": {"application": ("response-orchestrator",)},
    "RESPONSE_ORCHESTRATOR_WAZUH_API_USER": {
        "application": ("response-orchestrator", "integration-hub"),
    },
    "RESPONSE_ORCHESTRATOR_WAZUH_API_PASSWORD": {
        "application": ("response-orchestrator", "integration-hub"),
    },
    "API_KEYS": {"ingestion": ("ingestion-gateway",)},
    "NOTIFICATION_API_KEY": {
        "application": ("notification-service", "notification-outbox-worker"),
        "processing": ("correlation-engine",),
    },
    "NOTIFICATION_WEBHOOK_SECRET": {"application": ("notification-service",)},
    "SMTP_PASSWORD": {"application": ("notification-service", "notification-outbox-worker")},
    "TRAINING_API_KEY": {
        "models": (
            "model-gateway", "log-model", "network-model", "metrics-model", "code-model",
            "host-state-model",
        ),
        "training": ("training-orchestrator",),
    },
    "TRAINING_ARTIFACT_SIGNING_KEY": {
        "models": (
            "log-model", "network-model", "metrics-model", "code-model", "host-state-model",
        ),
        "training": ("training-orchestrator", "training-worker"),
    },
}

# Chart values that production installs must hold; a revision cannot change them.
HELM_PRODUCTION_INVARIANTS: dict[str, Any] = {
    "security.oidcDisabled": False,
    "security.allowDemoKeys": False,
    "security.requireServiceKeys": True,
    "networkPolicy.denyIngressDefault": True,
    "securityContext.runAsNonRoot": True,
    "modelServing.enabled": True,
    "correlationEngine.assetRegistryRequired": True,
}
