"""Compact Transformer for log template sequences (LogBERT-style).

Training objectives mirror LogBERT (arXiv:2103.04475):
  - Masked log-key (template) language modeling (MLM)
  - Sequence-level corruption / anomaly classification head

Inference uses per-position prediction mismatch (and optional attention mass)
as contributors before Platt/isotonic calibration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import torch
from torch import nn


@dataclass
class LogTransformerConfig:
    vocab_size: int = 128
    hidden_size: int = 256
    num_hidden_layers: int = 4
    num_attention_heads: int = 4
    intermediate_size: int = 512
    max_position_embeddings: int = 128
    dropout: float = 0.1
    num_severity: int = 8
    pad_token_id: int = 0
    mask_token_id: int = 3
    unk_token_id: int = 4

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> LogTransformerConfig:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class LogTransformer(nn.Module):
    """LogBERT-style encoder: MLM head + corruption head over Drain3 template IDs."""

    def __init__(self, config: LogTransformerConfig) -> None:
        super().__init__()
        self.config = config
        self.token_embeddings = nn.Embedding(
            config.vocab_size, config.hidden_size, padding_idx=config.pad_token_id
        )
        self.position_embeddings = nn.Embedding(config.max_position_embeddings, config.hidden_size)
        self.severity_embeddings = nn.Embedding(config.num_severity, config.hidden_size)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.hidden_size,
            nhead=config.num_attention_heads,
            dim_feedforward=config.intermediate_size,
            dropout=config.dropout,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=config.num_hidden_layers)
        self.layer_norm = nn.LayerNorm(config.hidden_size)
        self.mlm_head = nn.Linear(config.hidden_size, config.vocab_size)
        self.corruption_head = nn.Linear(config.hidden_size, 1)
        # Lightweight attention pooling for contributor attribution (UniNet-style mass).
        self.attn_query = nn.Linear(config.hidden_size, 1)
        self.dropout = nn.Dropout(config.dropout)

    def forward(
        self,
        input_ids: torch.Tensor,
        severity_ids: torch.Tensor | None = None,
        attention_mask: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        batch, seq_len = input_ids.shape
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch, -1)
        hidden = self.token_embeddings(input_ids) + self.position_embeddings(positions)
        if severity_ids is not None:
            hidden = hidden + self.severity_embeddings(severity_ids.clamp(0, self.config.num_severity - 1))
        hidden = self.dropout(self.layer_norm(hidden))

        key_padding_mask = None
        if attention_mask is not None:
            key_padding_mask = attention_mask == 0

        encoded = self.encoder(hidden, src_key_padding_mask=key_padding_mask)
        token_logits = self.mlm_head(encoded)
        # Attention mass over non-padding positions (for top-k contributors).
        attn_logits = self.attn_query(encoded).squeeze(-1)
        if attention_mask is not None:
            attn_logits = attn_logits.masked_fill(attention_mask == 0, -1e9)
            weights = attention_mask.unsqueeze(-1).float()
            pooled = (encoded * weights).sum(dim=1) / weights.sum(dim=1).clamp(min=1.0)
        else:
            pooled = encoded.mean(dim=1)
        attention_weights = torch.softmax(attn_logits, dim=-1)
        corruption_logit = self.corruption_head(pooled).squeeze(-1)
        return {
            "token_logits": token_logits,
            "corruption_logit": corruption_logit,
            "hidden": encoded,
            "attention_weights": attention_weights,
        }
