#!/usr/bin/env python3
"""Upsert offline ATT&CK technique vectors into Qdrant ``attack_tech_v1``.

Air-gap restore path: reads ``data/attack/attack_tech_seed.json`` (or
``data/threat-intel/attack_tech_vectors.json``), embeds text with the configured
SecureBERT-compatible transformer, and upserts into Qdrant. The model must be
available locally or downloadable by Transformers; there is no fake fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SEED = ROOT / "data" / "attack" / "attack_tech_seed.json"
ALT_SEED = ROOT / "data" / "threat-intel" / "attack_tech_vectors.json"


def _load_embedder(model_name: str):
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise SystemExit("torch and transformers are required for ATT&CK embeddings") from exc
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)
    model.eval()

    def embed(text: str) -> list[float]:
        encoded = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            output = model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1)
            pooled = (output * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
            vector = torch.nn.functional.normalize(pooled, p=2, dim=1)[0]
        return vector.cpu().tolist()

    return embed


def _load_techniques(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "techniques" in payload:
        return list(payload["techniques"] or [])
    if isinstance(payload, list):
        return payload
    raise SystemExit(f"unrecognized seed shape in {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=Path, default=None)
    # attack_tech_v1 is shared reference data; use the shared-tenant sentinel.
    parser.add_argument("--tenant-id", default="__global__")
    parser.add_argument("--qdrant-url", default=os.environ.get("QDRANT_URL", ""))
    parser.add_argument("--model", default="cisco-ai/SecureBERT2.0-biencoder")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    seed = args.seed
    if seed is None:
        seed = DEFAULT_SEED if DEFAULT_SEED.is_file() else ALT_SEED
    if not seed.is_file():
        print(f"seed not found: {seed}", file=sys.stderr)
        return 1

    techniques = _load_techniques(seed)
    print(f"loaded {len(techniques)} techniques from {seed}")

    if args.dry_run or not str(args.qdrant_url).strip():
        print("dry-run or QDRANT_URL unset — skipping upsert")
        return 0

    try:
        from black_onyx_vector import VectorClient
    except ImportError:
        print("black_onyx_vector not installed", file=sys.stderr)
        return 1

    client = VectorClient(url=args.qdrant_url)
    if not client.available:
        print(f"qdrant unavailable at {args.qdrant_url}", file=sys.stderr)
        return 1

    client.ensure_collections()
    embed = _load_embedder(args.model)
    points = []
    for tech in techniques:
        tech_id = str(tech.get("technique_id") or tech.get("id") or "")
        if not tech_id:
            continue
        text = " ".join(
            str(p)
            for p in (
                tech.get("technique_id"),
                tech.get("name"),
                tech.get("tactic"),
                tech.get("text") or tech.get("description"),
            )
            if p
        )
        points.append(
            {
                "id": tech_id,
                "vector": embed(text),
                "payload": {
                    "tenant_id": args.tenant_id,
                    "technique_id": tech_id,
                    "name": tech.get("name"),
                    "tactic": tech.get("tactic"),
                    "text": text,
                    "embed_model": args.model,
                    "embed_version": "transformers",
                },
            }
        )
    if not points:
        print("no points to upsert")
        return 0
    client.upsert("attack_tech_v1", points)
    print(f"upserted {len(points)} points into attack_tech_v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
