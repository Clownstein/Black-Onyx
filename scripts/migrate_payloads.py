#!/usr/bin/env python3
"""Migrate old Qdrant payloads to the current schema.

Old payloads may use singular field names (e.g. "domain", "ip", "url")
or lack fields like "ioc_type", "extraction_date", "source_collection".
This script scrolls through all points in a collection and updates
payloads to match the current canonical DataModel.

Usage:
    python scripts/migrate_payloads.py --collection all-knowledge
    python scripts/migrate_payloads.py --collection all-knowledge --dry-run
    python scripts/migrate_payloads.py --all-collections
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from qdrant_client import QdrantClient

# Field renames: old_singular -> new_plural
FIELD_RENAMES: dict[str, str] = {
    "domain": "domains",
    "ip": "ips",
    "url": "urls",
    "email": "emails",
    "phone": "phones",
    "cve": "cves",
    "md5": "md5_hashes",
    "sha1": "sha1_hashes",
    "sha256": "sha256_hashes",
    "sha512": "sha512_hashes",
    "yara_rule": "yara_rules",
    "sigma_rule": "sigma_rules",
    "mitre_technique": "mitre_techniques",
    "mitre_tactic": "mitre_tactics",
    "defanged_ioc": "defanged_iocs",
}

# Fields to add with defaults if missing
DEFAULT_FIELDS: dict[str, Any] = {
    "extraction_date": None,  # Will be set to current timestamp if missing
    "schema_version": "2.0",
}


def migrate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Migrate a single payload dict to the current schema.

    Args:
        payload: The original payload dict.

    Returns:
        Migrated payload dict.
    """
    migrated = dict(payload)

    # Rename singular fields to plural
    for old_name, new_name in FIELD_RENAMES.items():
        if old_name in migrated and new_name not in migrated:
            value = migrated.pop(old_name)
            # Wrap scalar values in a list
            if not isinstance(value, list):
                value = [value]
            migrated[new_name] = value
        elif old_name in migrated and new_name in migrated:
            # Both exist — merge and remove old
            old_val = migrated.pop(old_name)
            if not isinstance(old_val, list):
                old_val = [old_val]
            existing = migrated[new_name] if isinstance(migrated[new_name], list) else [migrated[new_name]]
            merged = list(dict.fromkeys(existing + old_val))  # dedupe preserving order
            migrated[new_name] = merged

    # Add default fields if missing
    from datetime import datetime, timezone
    for field, default in DEFAULT_FIELDS.items():
        if field not in migrated:
            if default is None and field == "extraction_date":
                migrated[field] = datetime.now(timezone.utc).isoformat()
            else:
                migrated[field] = default

    # Ensure body_text exists (rename from 'text' or 'content' if present)
    if "body_text" not in migrated:
        if "text" in migrated:
            migrated["body_text"] = migrated.pop("text")
        elif "content" in migrated:
            migrated["body_text"] = migrated.pop("content")

    # Ensure chunk_index is int
    if "chunk_index" in migrated and not isinstance(migrated["chunk_index"], int):
        try:
            migrated["chunk_index"] = int(migrated["chunk_index"])
        except (ValueError, TypeError):
            pass

    return migrated


def migrate_collection(
    client: QdrantClient,
    collection_name: str,
    dry_run: bool = False,
    batch_size: int = 100,
) -> tuple[int, int]:
    """Migrate all payloads in a collection.

    Args:
        client: QdrantClient instance.
        collection_name: Name of the collection to migrate.
        dry_run: If True, only report what would change.
        batch_size: Number of points to process per batch.

    Returns:
        Tuple of (total_points, migrated_points).
    """
    total = 0
    migrated_count = 0
    offset = None

    print(f"  Scrolling collection '{collection_name}'...")

    while True:
        points, next_offset = client.scroll(
            collection_name=collection_name,
            limit=batch_size,
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )

        if not points:
            break

        total += len(points)
        points_to_update: list[tuple[Any, dict[str, Any]]] = []

        for point in points:
            old_payload = point.payload or {}
            new_payload = migrate_payload(old_payload)

            if new_payload != old_payload:
                migrated_count += 1
                if not dry_run:
                    # Compute only the changed keys to avoid overwriting unchanged fields
                    changed_keys = {
                        k: new_payload[k] for k in new_payload
                        if k not in old_payload or new_payload[k] != old_payload.get(k)
                    }
                    # Also include keys that were removed (set to None to delete)
                    for k in old_payload:
                        if k not in new_payload:
                            changed_keys[k] = None
                    if changed_keys:
                        points_to_update.append((point.id, changed_keys))

        # Update payloads in batches (preserves vectors)
        if points_to_update and not dry_run:
            try:
                for point_id, changed_keys in points_to_update:
                    # Set None values via delete_payload, others via set_payload
                    to_set = {k: v for k, v in changed_keys.items() if v is not None}
                    to_delete = [k for k, v in changed_keys.items() if v is None]
                    if to_set:
                        client.set_payload(
                            collection_name=collection_name,
                            payload=to_set,
                            points=[point_id],
                        )
                    if to_delete:
                        client.delete_payload(
                            collection_name=collection_name,
                            keys=to_delete,
                            points=[point_id],
                        )
            except Exception as e:
                print(f"  WARNING: Failed to update batch: {e}")

        if next_offset is None:
            break
        offset = next_offset

    return total, migrated_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate old Qdrant payloads to current schema")
    parser.add_argument("--collection", type=str, help="Collection name to migrate")
    parser.add_argument("--all-collections", action="store_true", help="Migrate all collections")
    parser.add_argument("--dry-run", action="store_true", help="Only report changes, don't update")
    parser.add_argument("--qdrant-url", type=str, default="http://localhost:6333", help="Qdrant URL")
    parser.add_argument("--qdrant-api-key", type=str, default=None, help="Qdrant API key")
    args = parser.parse_args()

    if not args.collection and not args.all_collections:
        parser.error("Specify --collection or --all-collections")

    client = QdrantClient(url=args.qdrant_url, api_key=args.qdrant_api_key)

    if args.all_collections:
        collections = [c.name for c in client.get_collections().collections]
    else:
        collections = [args.collection]

    print(f"{'DRY RUN: ' if args.dry_run else ''}Migrating {len(collections)} collection(s)...")
    total_migrated = 0
    total_points = 0

    for col_name in collections:
        print(f"\nCollection: {col_name}")
        try:
            total, migrated = migrate_collection(client, col_name, dry_run=args.dry_run)
            print(f"  Points: {total}, Migrated: {migrated}")
            total_migrated += migrated
            total_points += total
        except Exception as e:
            print(f"  ERROR: {e}")

    print(f"\n{'DRY RUN ' if args.dry_run else ''}Summary: {total_migrated}/{total_points} payloads migrated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
