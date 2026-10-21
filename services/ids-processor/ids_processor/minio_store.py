"""MinIO / S3-compatible object helpers for selective PCAP excerpts.

Uploads need MinIO credentials and ``boto3``; without them no evidence ref is
produced (findings never point at objects that were not stored).
"""

from __future__ import annotations

import hashlib
import logging
import re
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
    # Plain s3:// URIs: incident-api rejects query strings on evidence refs.
    return f"s3://{bucket}/{key}"


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


def _ensure_bucket(client: Any, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = str((exc.response.get("Error") or {}).get("Code") or "")
        if code not in {"404", "NoSuchBucket", "NotFound"}:
            raise
        client.create_bucket(Bucket=bucket)


def put_bytes(
    data: bytes,
    *,
    key: str,
    bucket: str | None = None,
    content_type: str = "application/vnd.tcpdump.pcap",
) -> ObjectRef:
    bucket_name = bucket or settings.minio_bucket or "black-onyx-pcap"
    digest = hashlib.sha256(data).hexdigest()
    uri = build_uri(bucket_name, key)
    client = _client()
    uploaded = False
    if client is not None:
        try:
            _ensure_bucket(client, bucket_name)
            client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type,
                Metadata={"sha256": digest},
            )
            uploaded = True
        except Exception:  # noqa: BLE001 soft-fail for missing MinIO
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


_TENANT_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def evidence_ref_for_pcap(
    data: bytes,
    *,
    tenant_id: str,
    asset_id: str,
    alert_id: str | int | None = None,
) -> dict[str, Any] | None:
    """Upload a PCAP excerpt and return a finding evidence_refs entry.

    Objects live under ``pcap/<tenant>/...`` so incident-api can enforce the
    tenant namespace on download. Returns None when the upload did not happen:
    a finding must never reference an object that does not exist.
    """
    tenant = tenant_id.strip()
    if not _TENANT_SEGMENT.fullmatch(tenant):
        logger.warning("tenant id %r cannot form an evidence namespace; skipping PCAP upload", tenant_id)
        return None
    safe_asset = "".join(c if c.isalnum() or c in "-_" else "_" for c in asset_id)[:64] or "unknown"
    safe_alert = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(alert_id or "excerpt"))[:64]
    digest = hashlib.sha256(data).hexdigest()
    key = f"pcap/{tenant}/{safe_asset}/{safe_alert}-{digest[:16]}.pcap"
    ref = put_bytes(data, key=key)
    if not ref.uploaded:
        return None
    return {
        "type": "pcap",
        "uri": ref.uri,
        "sha256": ref.sha256,
        "size_bytes": ref.size_bytes,
        "filter": {"asset_id": asset_id, "alert_id": alert_id},
    }
