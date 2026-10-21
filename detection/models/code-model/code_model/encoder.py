"""DistilBERT-style compact encoder for code diffs (torch + optional ONNX).

Avoids a hard dependency on `transformers`; uses a small hashed-token encoder
with 2 transformer layers and a risk head. Sklearn LogisticRegression remains
the primary fallback when torch/ONNX artifacts are absent.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import numpy as np

try:
    import torch
    from torch import nn

    _TORCH = True
except ImportError:  # pragma: no cover
    torch = None  # type: ignore
    nn = None  # type: ignore
    _TORCH = False

VOCAB_SIZE = 4096
MAX_LEN = 128
PAD_ID = 0


def _stable_bucket(token: str, buckets: int) -> int:
    digest = hashlib.md5(token.encode("utf-8")).hexdigest()
    return int(digest, 16) % buckets


def tokenize_diff(text: str, max_len: int = MAX_LEN) -> np.ndarray:
    """Hash-bucket tokenize a diff into fixed-length int ids."""
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[+\-*/=(){}\[\].]|[0-9]+", text.lower())
    ids = [PAD_ID] * max_len
    for i, tok in enumerate(tokens[:max_len]):
        # Stable positive bucket in [1, VOCAB_SIZE-1]
        ids[i] = 1 + _stable_bucket(tok, VOCAB_SIZE - 1)
    return np.asarray(ids, dtype=np.int64)


if _TORCH:

    class DistilCodeEncoder(nn.Module):
        """Compact DistilBERT-style encoder → risk logit/probability."""

        def __init__(
            self,
            vocab_size: int = VOCAB_SIZE,
            hidden_size: int = 128,
            num_layers: int = 2,
            num_heads: int = 4,
            intermediate_size: int = 256,
            max_len: int = MAX_LEN,
            dropout: float = 0.1,
        ) -> None:
            super().__init__()
            self.embeddings = nn.Embedding(vocab_size, hidden_size, padding_idx=PAD_ID)
            self.pos = nn.Embedding(max_len, hidden_size)
            layer = nn.TransformerEncoderLayer(
                d_model=hidden_size,
                nhead=num_heads,
                dim_feedforward=intermediate_size,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
            self.norm = nn.LayerNorm(hidden_size)
            self.head = nn.Linear(hidden_size, 1)
            self.max_len = max_len
            self.hidden_size = hidden_size

        def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
            # input_ids: [B, T]
            b, t = input_ids.shape
            positions = torch.arange(t, device=input_ids.device).unsqueeze(0).expand(b, -1)
            mask = input_ids == PAD_ID
            h = self.embeddings(input_ids) + self.pos(positions)
            encoded = self.encoder(h, src_key_padding_mask=mask)
            # CLS-like: mean of non-pad tokens
            valid = (~mask).unsqueeze(-1).float()
            pooled = (encoded * valid).sum(dim=1) / valid.sum(dim=1).clamp(min=1.0)
            pooled = self.norm(pooled)
            return torch.sigmoid(self.head(pooled)).squeeze(-1)

else:  # pragma: no cover

    class DistilCodeEncoder:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("torch is required for DistilCodeEncoder")


def encode_batch(texts: list[str], max_len: int = MAX_LEN) -> np.ndarray:
    return np.stack([tokenize_diff(t, max_len=max_len) for t in texts], axis=0)
