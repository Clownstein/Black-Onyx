#!/usr/bin/env python3
"""Write an offline ATT&CK technique text bundle for air-gap restore into attack_tech_v1."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data" / "attack" / "attack_tech_seed.json"

TECHNIQUES = [
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "text": "Adversaries may abuse command and script interpreters to execute commands.",
    },
    {
        "technique_id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "text": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
    },
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "text": "Adversaries may communicate using application layer protocols to avoid detection.",
    },
]


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "collection": "attack_tech_v1",
        "embed_model": "cisco-ai/SecureBERT2.0-biencoder",
        "embed_version": "securebert2.0-biencoder",
        "techniques": TECHNIQUES,
    }
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
