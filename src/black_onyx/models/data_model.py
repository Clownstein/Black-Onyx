"""Single canonical DataModel for all Qdrant payloads.

All multi-value fields use List[str] for consistency. Image-specific fields
are included for image ingestion support.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Fields that should always be coerced to List[str]
_LIST_FIELDS: frozenset[str] = frozenset({
    "bitcoin_address", "ethereum_address", "monero_address", "litecoin_address",
    "zcash_address", "emails", "phone_numbers", "irc_addresses", "gpg_keys",
    "ssh_keys", "discord_invite", "whatsapp_invite", "paypal_link",
    "justforfans", "fancentro", "camsoda", "chaturbate", "soulcams",
    "stripchat", "twitch", "fansly", "person_name", "username",
    "business_name", "address", "city", "state", "country", "zip_code",
    "longitude", "latitude", "urls", "image_urls", "messages",
    "group_name", "group_type", "crime", "crime_type", "ip_addresses",
    "google_analytics_ids", "facebook_analytics_ids",
    "code_snippets", "code_languages", "social_profiles", "cryptos",
    "ner_entities",
    # IOC fields
    "md5_hashes", "sha1_hashes", "sha256_hashes", "sha512_hashes",
    "cve_ids", "domains", "cidr_ranges", "mac_addresses", "asns",
    "cpes", "jarm_fingerprints", "mitre_techniques", "mitre_tactics",
    "yara_rules", "sigma_rules", "user_agents", "defanged_iocs",
    "ioc_tags", "annotations",
})


class DataModel(BaseModel):
    """Canonical data model for all Qdrant point payloads.

    Text ingestion populates text/metadata fields.
    Image ingestion also populates image-specific fields.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # --- Core text fields ---
    title: Optional[str] = None
    body_text: Optional[str] = None
    source_file: Optional[str] = None
    chunk_index: int = 0
    total_chunks: int = 1

    # --- Payload metadata ---
    payload_type: str = "text"  # "text", "image", "mixed"
    embedding_model: Optional[str] = None
    embedding_type: Optional[str] = None
    # Set at model construction, immediately before upsert, so time-range filters
    # (relationship graph, decay reviews) have a dependable indexing timestamp.
    indexed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    # --- Crypto addresses ---
    bitcoin_address: list[str] = Field(default_factory=list)
    ethereum_address: list[str] = Field(default_factory=list)
    monero_address: list[str] = Field(default_factory=list)
    litecoin_address: list[str] = Field(default_factory=list)
    zcash_address: list[str] = Field(default_factory=list)

    # --- Contact info ---
    emails: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    irc_addresses: list[str] = Field(default_factory=list)
    gpg_keys: list[str] = Field(default_factory=list)
    ssh_keys: list[str] = Field(default_factory=list)

    # --- Invite / payment links ---
    discord_invite: list[str] = Field(default_factory=list)
    whatsapp_invite: list[str] = Field(default_factory=list)
    paypal_link: list[str] = Field(default_factory=list)

    # --- Adult site URLs ---
    justforfans: list[str] = Field(default_factory=list)
    fancentro: list[str] = Field(default_factory=list)
    camsoda: list[str] = Field(default_factory=list)
    chaturbate: list[str] = Field(default_factory=list)
    soulcams: list[str] = Field(default_factory=list)
    stripchat: list[str] = Field(default_factory=list)
    twitch: list[str] = Field(default_factory=list)
    fansly: list[str] = Field(default_factory=list)

    # --- NER entities ---
    person_name: list[str] = Field(default_factory=list)
    username: list[str] = Field(default_factory=list)
    business_name: list[str] = Field(default_factory=list)
    address: list[str] = Field(default_factory=list)
    city: list[str] = Field(default_factory=list)
    state: list[str] = Field(default_factory=list)
    country: list[str] = Field(default_factory=list)
    zip_code: list[str] = Field(default_factory=list)
    longitude: list[str] = Field(default_factory=list)
    latitude: list[str] = Field(default_factory=list)

    # --- URLs ---
    urls: list[str] = Field(default_factory=list)
    image_urls: list[str] = Field(default_factory=list)

    # --- Messages / groups ---
    messages: list[str] = Field(default_factory=list)
    group_name: list[str] = Field(default_factory=list)
    group_type: list[str] = Field(default_factory=list)
    crime: list[str] = Field(default_factory=list)
    crime_type: list[str] = Field(default_factory=list)

    # --- Network ---
    ip_addresses: list[str] = Field(default_factory=list)
    google_analytics_ids: list[str] = Field(default_factory=list)
    facebook_analytics_ids: list[str] = Field(default_factory=list)

    # --- Code ---
    code_snippets: list[str] = Field(default_factory=list)
    code_languages: list[str] = Field(default_factory=list)

    # --- Social / crypto (dict-like, stored as list of "platform:handle" strings) ---
    social_profiles: list[str] = Field(default_factory=list)
    cryptos: list[str] = Field(default_factory=list)

    # --- NER raw entities (list of "label:text" strings) ---
    ner_entities: list[str] = Field(default_factory=list)

    # --- Classification ---
    classification: Optional[str] = None
    classification_score: Optional[float] = None

    # --- IOC (Indicator of Compromise) fields ---
    md5_hashes: list[str] = Field(default_factory=list)
    sha1_hashes: list[str] = Field(default_factory=list)
    sha256_hashes: list[str] = Field(default_factory=list)
    sha512_hashes: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    cidr_ranges: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    asns: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    jarm_fingerprints: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    yara_rules: list[str] = Field(default_factory=list)
    sigma_rules: list[str] = Field(default_factory=list)
    user_agents: list[str] = Field(default_factory=list)
    defanged_iocs: list[str] = Field(default_factory=list)

    # --- Enrichment fields ---
    enrichment_data: dict[str, Any] = Field(default_factory=dict)
    ioc_decay_score: Optional[float] = None
    ioc_first_seen: Optional[str] = None
    ioc_last_seen: Optional[str] = None
    ioc_confidence: Optional[float] = None
    ioc_tags: list[str] = Field(default_factory=list)
    ioc_status: Optional[str] = None  # "new", "confirmed", "benign", "expired"

    # --- Case management link ---
    case_id: Optional[str] = None

    # --- Analyst collaboration ---
    annotations: list[dict[str, Any]] = Field(default_factory=list)
    bookmarked: bool = False

    # --- Image-specific fields ---
    image_width: Optional[int] = None
    image_height: Optional[int] = None
    image_format: Optional[str] = None
    image_hash: Optional[str] = None  # perceptual hash string
    exif_data: Optional[dict[str, Any]] = None
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    capture_time: Optional[str] = None
    ocr_text: Optional[str] = None

    @field_validator("*", mode="before")
    @classmethod
    def coerce_list_fields(cls, value: Any, info: Any) -> Any:
        """Coerce string values to single-element lists for list fields.

        For fields in _LIST_FIELDS, if a raw string is provided, wrap it in a list.
        Empty strings and None are converted to empty lists.
        """
        if info.field_name in _LIST_FIELDS:
            if value is None or value == "":
                return []
            if isinstance(value, str):
                return [value]
            if isinstance(value, (list, tuple)):
                return [str(v) for v in value if v is not None and v != ""]
            return [str(value)]
        return value

    def merge_metadata(self, metadata: dict[str, Any]) -> None:
        """Merge extracted metadata dict into this model's fields.

        For list fields, extends the existing list with new values (deduplicated).
        For scalar fields, sets the value if currently None.
        """
        for key, new_values in metadata.items():
            if not hasattr(self, key):
                continue
            if key in _LIST_FIELDS:
                current = getattr(self, key) or []
                if isinstance(new_values, dict) and key in ("social_profiles", "cryptos"):
                    # Convert dict to "key:value" strings for social_profiles/cryptos
                    for k, v in new_values.items():
                        if isinstance(v, list):
                            for item in v:
                                entry = f"{k}:{item}"
                                if entry not in current:
                                    current.append(entry)
                        else:
                            entry = f"{k}:{v}"
                            if entry not in current:
                                current.append(entry)
                elif isinstance(new_values, list):
                    for v in new_values:
                        if v not in current:
                            current.append(v)
                elif isinstance(new_values, str) and new_values not in current:
                    current.append(new_values)
                setattr(self, key, current)
            elif isinstance(new_values, dict):
                # For non-list dict fields, store as-is if currently None
                if getattr(self, key) is None:
                    setattr(self, key, new_values)
            else:
                if getattr(self, key) is None and new_values is not None:
                    setattr(self, key, new_values)
