"""MinIO helper for incident evidence download (PCAP excerpts, malware artifacts)."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote, urlparse

from incident_api.config import settings

logger = logging.getLogger("incident-api.minio")


def _client() -> Any | None:
    if not settings.minio_access_key or not settings.minio_secret_key:
        return None
    try:
        import boto3
    except ImportError:
        return None
    endpoint = (settings.minio_endpoint or "").strip() or None
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=settings.minio_access_key,
        aws_secret_access_key=settings.minio_secret_key,
        region_name=settings.minio_region or "us-east-1",
    )


_TENANT_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def parse_s3_uri(uri: str) -> tuple[str, str]:
    text = uri.strip()
    parsed = urlparse(text)
    if parsed.scheme != "s3" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("invalid evidence URI")
    bucket = parsed.netloc
    key = parsed.path.lstrip("/")
    if not _BUCKET.fullmatch(bucket) or not key or "\\" in key or any(
        part in {"", ".", ".."} for part in key.split("/")
    ):
        raise ValueError("invalid evidence URI")
    return bucket, key


def validate_tenant_evidence_uri(uri: str, tenant_id: str) -> tuple[str, str]:
    bucket, key = parse_s3_uri(uri)
    tenant = tenant_id.strip()
    if not _TENANT_SEGMENT.fullmatch(tenant):
        raise ValueError("tenant does not have a valid evidence namespace")
    configured = {part.strip() for part in settings.evidence_buckets.split(",") if part.strip()}
    parts = key.split("/")
    allowed_roots = {"reports", "artifacts", "captures", "pcap"}
    tenant_owned = (
        len(parts) >= 3 and parts[0] in allowed_roots and parts[1] == tenant
    ) or (len(parts) >= 2 and parts[0] == tenant)
    if bucket not in configured or not tenant_owned:
        raise ValueError("evidence object is outside the tenant artifact namespace")
    return bucket, key


def download_evidence_bytes(uri: str, tenant_id: str) -> bytes:
    """Fetch object bytes for an evidence_ref URI. Raises on missing boto3/MinIO."""
    bucket, key = validate_tenant_evidence_uri(uri, tenant_id)
    client = _client()
    if client is None:
        raise RuntimeError("evidence storage is unavailable")
    resp = client.get_object(Bucket=bucket, Key=key)
    body = resp["Body"]
    try:
        declared_size = int(resp.get("ContentLength", 0) or 0)
        if declared_size > settings.evidence_max_bytes:
            raise ValueError("evidence object exceeds the download size limit")
        data = bytes(body.read(settings.evidence_max_bytes + 1))
        if len(data) > settings.evidence_max_bytes:
            raise ValueError("evidence object exceeds the download size limit")
        return data
    finally:
        body.close()


def describe_evidence_uri(uri: str, tenant_id: str) -> dict[str, Any]:
    bucket, key = validate_tenant_evidence_uri(uri, tenant_id)
    filename = key.rsplit("/", 1)[-1]
    return {
        "bucket": bucket,
        "key": key,
        "filename": filename,
        "content_disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
        "downloadable": _client() is not None,
    }
