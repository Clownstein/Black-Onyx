"""Template vocabulary helpers."""

from __future__ import annotations

import json
from pathlib import Path

SPECIAL_TOKENS = ["[PAD]", "[CLS]", "[SEP]", "[MASK]", "[UNK]"]


class TemplateVocab:
    def __init__(self, token_to_id: dict[str, int] | None = None) -> None:
        if token_to_id is None:
            self.token_to_id = {tok: idx for idx, tok in enumerate(SPECIAL_TOKENS)}
        else:
            self.token_to_id = dict(token_to_id)
        self.id_to_token = {v: k for k, v in self.token_to_id.items()}

    @property
    def pad_id(self) -> int:
        return self.token_to_id["[PAD]"]

    @property
    def mask_id(self) -> int:
        return self.token_to_id["[MASK]"]

    @property
    def unk_id(self) -> int:
        return self.token_to_id["[UNK]"]

    def add(self, token: str) -> int:
        if token not in self.token_to_id:
            idx = len(self.token_to_id)
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token
        return self.token_to_id[token]

    def encode(self, token: str) -> int:
        return self.token_to_id.get(token, self.unk_id)

    def decode(self, idx: int) -> str:
        return self.id_to_token.get(idx, "[UNK]")

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.token_to_id, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> TemplateVocab:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data)


SEVERITY_TO_ID = {
    "DEBUG": 0,
    "INFO": 1,
    "NOTICE": 2,
    "WARN": 3,
    "WARNING": 3,
    "ERROR": 4,
    "CRITICAL": 5,
    "ALERT": 6,
    "EMERGENCY": 7,
}


def severity_id(severity: str | None) -> int:
    if not severity:
        return 1
    return SEVERITY_TO_ID.get(severity.upper(), 1)
