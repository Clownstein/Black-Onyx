"""MinIO / S3-compatible object helpers for selective PCAP excerpts.

Uses optional ``boto3`` when installed; otherwise records URIs and skips
upload/download so unit tests and air-gapped hosts still work.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ids_processor.config import settings

logger = logging.getLogger("ids-processor.minio")


@dataclass
class ObjectRef:
    uri: str
    sha256: str
    bucket: str
    key: str
    size_bytes: int
    uploaded: bool


def build_uri(bucket: str, key: str) -> str:
    endpoint = (settings.minio_endpoint or "http://localhost:9000").rstrip("/")
    return f"s3://{bucket}/{key}?endpoint={endpoint}"


def parse_uri(uri: str) -> tuple[str, str]:
    """Return (bucket, key) from s3://bucket/key or https endpoint path."""
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


def put_bytes(
    data: bytes,
    *,
    key: str,
    bucket: str | None = None,
    content_type: str = "application/vnd.tcpdump.pcap",
) -> ObjectRef:
    bucket_name = bucket or settings.minio_bucket or "anomaly-pcap"
    digest = hashlib.sha256(data).hexdigest()
    uri = build_uri(bucket_name, key)
    client = _client()
    uploaded = False
    if client is not None:
        try:
            client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type,
                Metadata={"sha256": digest},
            )
            uploaded = True
        except Exception:  # noqa: BLE001 — soft-fail for missing MinIO
            logger.exception("minio put_object failed for %s/%s", bucket_name, key)
    else:
        logger.debug("boto3 unavailable; recording PCAP uri without upload")
    return ObjectRef(
        uri=uri,
        sha256=digest,
        bucket=bucket_name,
        key=key,
        size_bytes=len(data),
        uploaded=uploaded,
    )


def get_bytes(uri: str) -> bytes:
    bucket, key = parse_uri(uri)
    client = _client()
    if client is None:
        raise RuntimeError("boto3 not installed; cannot download object")
    resp = client.get_object(Bucket=bucket, Key=key)
    body = resp["Body"].read()
    return bytes(body)


def evidence_ref_for_pcap(
    data: bytes,
    *,
    asset_id: str,
    alert_id: str | int | None = None,
) -> dict[str, Any]:
    """Upload (or record) a PCAP excerpt and return a finding evidence_refs entry."""
    safe_asset = "".join(c if c.isalnum() or c in "-_" else "_" for c in asset_id)[:64]
    alert_part = str(alert_id or "excerpt")
    key = f"pcap/{safe_asset}/{alert_part}.pcap"
    ref = put_bytes(data, key=key)
    return {
        "type": "pcap",
        "uri": ref.uri,
        "sha256": ref.sha256,
        "size_bytes": ref.size_bytes,
        "uploaded": ref.uploaded,
        "filter": {"asset_id": asset_id, "alert_id": alert_id},
    }
