"""Optional HuggingFace CodeBERT / CodeReviewer encoder for diff risk scoring.

Falls back to the hashed-token DistilCodeEncoder when `transformers` is unavailable
or when training with `--encoder distil` (default).
"""

from __future__ import annotations

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

DEFAULT_HF_MODEL = "microsoft/codebert-base"
MAX_LEN = 256


def hf_available() -> bool:
    try:
        import transformers  # noqa: F401

        return True
    except ImportError:
        return False


if _TORCH:

    class HFCodeRiskEncoder(nn.Module):
        """Fine-tunable CodeBERT-style encoder with binary risk head."""

        def __init__(
            self,
            model_name: str = DEFAULT_HF_MODEL,
            max_len: int = MAX_LEN,
            dropout: float = 0.1,
        ) -> None:
            super().__init__()
            from transformers import AutoModel

            self.backbone = AutoModel.from_pretrained(model_name)
            hidden = int(self.backbone.config.hidden_size)
            self.dropout = nn.Dropout(dropout)
            self.head = nn.Linear(hidden, 1)
            self.max_len = max_len
            self.model_name = model_name

        def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
            outputs = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
            if hasattr(outputs, "pooler_output") and outputs.pooler_output is not None:
                pooled = outputs.pooler_output
            else:
                mask = attention_mask.unsqueeze(-1).float()
                pooled = (outputs.last_hidden_state * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
            pooled = self.dropout(pooled)
            return torch.sigmoid(self.head(pooled)).squeeze(-1)

else:  # pragma: no cover

    class HFCodeRiskEncoder:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("torch and transformers are required for HFCodeRiskEncoder")


def get_tokenizer(model_name: str = DEFAULT_HF_MODEL):
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(model_name)


def encode_texts_hf(
    texts: list[str],
    *,
    model_name: str = DEFAULT_HF_MODEL,
    max_len: int = MAX_LEN,
) -> tuple[np.ndarray, np.ndarray]:
    """Tokenize diff texts for HF encoder input."""
    tok = get_tokenizer(model_name)
    batch = tok(
        texts,
        padding="max_length",
        truncation=True,
        max_length=max_len,
        return_tensors="np",
    )
    return batch["input_ids"].astype(np.int64), batch["attention_mask"].astype(np.int64)
