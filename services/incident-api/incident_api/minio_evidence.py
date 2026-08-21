"""MinIO helper for incident evidence download (PCAP excerpts, malware artifacts)."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from incident_api.config import settings

logger = logging.getLogger("incident-api.minio")


def _client() -> Any | None:
    try:
        import boto3
    except ImportError:
        return None
    endpoint = (settings.minio_endpoint or "").strip() or None
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=settings.minio_access_key or "minioadmin",
        aws_secret_access_key=settings.minio_secret_key or "minioadmin",
        region_name=settings.minio_region or "us-east-1",
    )


def parse_s3_uri(uri: str) -> tuple[str, str]:
    text = uri.strip()
    if text.startswith("s3://"):
        rest = text[5:]
        if "?" in rest:
            rest = rest.split("?", 1)[0]
        bucket, _, key = rest.partition("/")
        if not bucket or not key:
            raise ValueError(f"invalid s3 uri: {uri}")
        return bucket, key
    parsed = urlparse(text)
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"invalid object uri: {uri}")
    return parts[0], "/".join(parts[1:])


def download_evidence_bytes(uri: str) -> bytes:
    """Fetch object bytes for an evidence_ref URI. Raises on missing boto3/MinIO."""
    bucket, key = parse_s3_uri(uri)
    client = _client()
    if client is None:
        raise RuntimeError("boto3 not installed")
    resp = client.get_object(Bucket=bucket, Key=key)
    return bytes(resp["Body"].read())


def describe_evidence_uri(uri: str) -> dict[str, Any]:
    bucket, key = parse_s3_uri(uri)
    return {
        "uri": uri,
        "bucket": bucket,
        "key": key,
        "downloadable": _client() is not None,
        "endpoint": settings.minio_endpoint,
    }
