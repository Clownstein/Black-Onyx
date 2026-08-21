"""Microsoft Defender for Endpoint connector, via the Microsoft Graph Security
`alerts_v2` API.

A thin `GenericRestConnector` subclass: OAuth2 client-credentials against
Azure AD, the Graph alerts_v2 endpoint, and `@odata.nextLink`-style pagination
are all expressible through the generic engine's existing config shape, so
this class only supplies MDE-specific defaults plus a `normalize()` override
for the one thing the generic engine's single-dotted-path-per-field mapping
genuinely cannot express: MDE alerts carry their IOCs in a single
heterogeneous `evidence` array (mixed ip/file/url/process entries identified
by an `entityType` discriminator), not one array per IOC type.
"""

from __future__ import annotations

from typing import Any

from black_onyx.connectors.generic_rest import GenericRestConnector, _get_path
from black_onyx.models.data_model import DataModel

GRAPH_BASE_URL = "https://graph.microsoft.com"
ALERTS_PATH = "/v1.0/security/alerts_v2"


class MicrosoftDefenderConnector(GenericRestConnector):
    """Required config keys: `tenant_id`. Optional: `severity_filter`
    (Graph OData $filter fragment appended verbatim, e.g.
    "severity eq 'high'") if the admin wants to narrow what gets pulled.

    Required secrets: `client_id`, `client_secret` (an Azure AD app
    registration with the `SecurityAlert.Read.All` application permission,
    admin-consented).
    """

    def __init__(self, name: str, config: dict[str, Any], secrets: dict[str, str]) -> None:
        tenant_id = config.get("tenant_id")
        if not tenant_id:
            raise ValueError("Microsoft Defender connector requires config.tenant_id")
        query_params = {}
        if config.get("severity_filter"):
            query_params["$filter"] = config["severity_filter"]
        full_config = {
            **config,
            "base_url": GRAPH_BASE_URL,
            "detections_path": ALERTS_PATH,
            "auth": {
                "type": "oauth2_client_credentials",
                "token_url": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                "scope": "https://graph.microsoft.com/.default",
            },
            "query_params": query_params,
            "response_items_path": "value",
            "pagination": {"style": "body_next_link", "next_link_path": "@odata.nextLink"},
            "since_param": None,  # alerts_v2 has no simple since= param; $filter covers narrowing instead
        }
        super().__init__(name=name, config=full_config, secrets=secrets)

    @property
    def source_type(self) -> str:
        return "microsoft_defender"

    def normalize(self, raw: dict[str, Any]) -> DataModel:
        alert_id = raw.get("id") or "unknown"
        title = raw.get("title") or f"Microsoft Defender alert {alert_id}"
        severity = str(raw.get("severity") or "").lower()

        ip_addresses: list[str] = []
        domains: list[str] = []
        urls: list[str] = []
        sha256_hashes: list[str] = []
        md5_hashes: list[str] = []
        for entry in raw.get("evidence") or []:
            entity_type = str(entry.get("@odata.type") or entry.get("entityType") or "").lower()
            if "ip" in entity_type and entry.get("ipAddress"):
                ip_addresses.append(str(entry["ipAddress"]))
            elif "url" in entity_type and entry.get("url"):
                urls.append(str(entry["url"]))
            elif "domain" in entity_type or entry.get("domainName"):
                if entry.get("domainName"):
                    domains.append(str(entry["domainName"]))
            elif "file" in entity_type or entity_type == "" and entry.get("fileDetails"):
                file_details = entry.get("fileDetails") or entry
                if file_details.get("sha256"):
                    sha256_hashes.append(str(file_details["sha256"]))
                if file_details.get("md5"):
                    md5_hashes.append(str(file_details["md5"]))

        mitre_techniques = [str(t) for t in (raw.get("mitreTechniques") or [])]
        event_time = (
            raw.get("alertCreationTime")
            or raw.get("firstActivityDateTime")
            or raw.get("createdDateTime")
            or raw.get("lastUpdateDateTime")
        )
        hostname = None
        username = None
        for entry in raw.get("evidence") or []:
            if not hostname and (entry.get("deviceDnsName") or entry.get("hostName")):
                hostname = str(entry.get("deviceDnsName") or entry.get("hostName"))
            if not username and entry.get("accountName"):
                username = str(entry.get("accountName"))

        summary = raw.get("description") or title
        return DataModel(
            title=title,
            body_text=f"{title}. {summary}"[:4000],
            source_file=f"connector:{self.name}:{alert_id}",
            payload_type="text",
            ioc_status="new",
            ip_addresses=ip_addresses,
            domains=domains,
            urls=urls,
            sha256_hashes=sha256_hashes,
            md5_hashes=md5_hashes,
            mitre_techniques=mitre_techniques,
            ioc_tags=[severity] if severity else [],
            capture_time=str(event_time) if event_time else None,
            enrichment_data={
                "event_time": str(event_time) if event_time else None,
                "severity": severity,
                "hostname": hostname,
                "username": username,
            },
        )
