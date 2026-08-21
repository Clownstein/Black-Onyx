"""Extract Qdrant payload JSON Schemas from qdrant_implementation.md."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "qdrant_implementation.md"
OUT = ROOT / "contracts" / "qdrant"

NAME_MAP = {
    "FindingsV1Payload": "findings_v1",
    "IncidentsV1Payload": "incidents_v1",
    "FeaturesBaselineV1Payload": "features_baseline_v1",
    "TiTextV1Payload": "ti_text_v1",
    "AttackTechV1Payload": "attack_tech_v1",
    "RunbooksV1Payload": "runbooks_v1",
}


def main() -> None:
    text = DOC.read_text(encoding="utf-8")
    for title, fname in NAME_MAP.items():
        pattern = (
            r'\{\s*"\$schema"[^{}]*?"title"\s*:\s*"'
            + re.escape(title)
            + r'".*?"additionalProperties"\s*:\s*false\s*\}'
        )
        match = re.search(pattern, text, flags=re.S)
        if not match:
            print("MISS", title)
            continue
        data = json.loads(match.group(0))
        path = OUT / f"{fname}.payload.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("WROTE", path.name, "props", len(data["properties"]))


if __name__ == "__main__":
    main()
