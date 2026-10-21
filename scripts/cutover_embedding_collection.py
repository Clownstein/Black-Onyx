#!/usr/bin/env python3
"""Patch TIP config to cut over to a re-indexed Qdrant collection.

Usage:
    uv run python scripts/cutover_embedding_collection.py --target all-knowledge-qwen3
    uv run python scripts/cutover_embedding_collection.py --target all-knowledge-qwen3 --apply
    uv run python scripts/cutover_embedding_collection.py --target all-knowledge-qwen3 --config config.yaml --apply
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def _patch_yaml_text(text: str, target: str) -> str:
    """Best-effort YAML patch without requiring PyYAML write round-trip."""
    updated = text

    # Prefer ingestion.collection_name when present
    if re.search(r"(?m)^ingestion:\s*$", updated):
        updated = re.sub(
            r"(ingestion:\s*\n(?:[ \t]+.+\n)*?[ \t]+collection_name:\s*)([\"']?)[^\n\"']+\2",
            rf'\1"{target}"',
            updated,
            count=1,
        )
    else:
        updated = re.sub(
            r"(collection_name:\s*)([\"']?)[^\n\"']+\2",
            rf'\1"{target}"',
            updated,
            count=1,
        )

    # Prefer llm.rag.collections when present
    if re.search(r"(?m)^(?:[ \t]+)?rag:\s*$", updated) or "rag:" in updated:
        updated = re.sub(
            r"(rag:\s*\n(?:[ \t]+.+\n)*?[ \t]+collections:\s*)\[[^\]]*\]",
            rf'\1["{target}"]',
            updated,
            count=1,
        )
    else:
        updated = re.sub(
            r"(collections:\s*)\[[^\]]*\]",
            rf'\1["{target}"]',
            updated,
            count=1,
        )
    return updated


def apply_cutover(config_path: Path, target: str, *, dry_run: bool) -> dict[str, object]:
    if not config_path.is_file():
        raise SystemExit(f"Config not found: {config_path}")

    original = config_path.read_text(encoding="utf-8")
    patched = _patch_yaml_text(original, target)
    changed = patched != original

    result: dict[str, object] = {
        "config": str(config_path),
        "target_collection": target,
        "changed": changed,
        "applied": False,
    }

    if dry_run or not changed:
        result["preview"] = patched if changed else original
        return result

    backup = config_path.with_suffix(config_path.suffix + ".bak")
    backup.write_text(original, encoding="utf-8")
    config_path.write_text(patched, encoding="utf-8")
    result["applied"] = True
    result["backup"] = str(backup)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="TIP embedding collection cutover helper")
    parser.add_argument("--target", required=True, help="New Qdrant collection name (post re-index)")
    parser.add_argument("--config", default="config.yaml", help="Config file to update")
    parser.add_argument("--collections", nargs="*", default=[], help="Legacy; ignored — RAG list set to --target")
    parser.add_argument("--apply", action="store_true", help="Write patched config (creates .bak)")
    args = parser.parse_args()

    steps = [
        f"1. Finish re-index: uv run python scripts/reindex_tip_collections.py --source <old> --target {args.target}",
        f"   Or from files: ... --from-ingest-dir ./data --target {args.target}",
        f"2. Patch config: uv run python scripts/cutover_embedding_collection.py --target {args.target} --config {args.config} --apply",
        "3. Restart TIP API so settings reload.",
        "4. Smoke test: semantic search + RAG chat + MCP black_onyx_evidence_search.",
        "5. Drop or archive the old collection once satisfied.",
    ]
    print("\n".join(steps))

    result = apply_cutover(Path(args.config), args.target, dry_run=not args.apply)
    # Do not dump full preview into stdout when applying
    if "preview" in result and args.apply is False:
        preview = str(result.pop("preview"))
        result["preview_chars"] = len(preview)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
