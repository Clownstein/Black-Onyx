from __future__ import annotations

import hashlib
import math
from typing import Any

import numpy as np
import torch
from torch import nn

# Feature layout (20-dim). Indices 0-13 preserved from v1; 14-19 enriched TLS/DNS.
# 0 src_port, 1 dst_port, 2 tcp, 3 udp, 4 log1p(bytes), 5 log1p(packets),
# 6 failed, 7 dst_is_external, 8 egress, 9 ingress, 10 peer_hash,
# 11 has_bytes, 12 sensitive_port, 13 web_port,
# 14 ja3_bucket, 15 ja4_bucket, 16 sni_rarity, 17 dns_entropy,
# 18 has_tls, 19 has_dns
FEATURE_DIM = 20


def _bucket_hash(value: Any, buckets: int = 64) -> float:
    if value is None or value == "":
        return 0.0
    digest = hashlib.md5(str(value).encode("utf-8")).hexdigest()
    return float(int(digest, 16) % buckets) / float(buckets)


def _sni_rarity(flow: dict[str, Any]) -> float:
    """Higher when SNI looks rare / missing on TLS-looking traffic."""
    tls = flow.get("tls") if isinstance(flow.get("tls"), dict) else {}
    sni = flow.get("sni") or tls.get("sni") or flow.get("server_name")
    if sni is None or sni == "":
        # Missing SNI on external HTTPS-ish ports is mildly suspicious
        dst = int(flow.get("dst_port") or 0)
        if dst in {443, 8443} and flow.get("dst_is_external"):
            return 0.7
        return 0.0
    sni_s = str(sni).lower()
    # Crude rarity: long / many labels / non-alphanumeric heavy
    labels = sni_s.split(".")
    rarity = min(1.0, 0.15 * max(0, len(labels) - 2) + 0.02 * max(0, len(sni_s) - 20))
    if any(ch.isdigit() for ch in sni_s.replace(".", "")):
        rarity = min(1.0, rarity + 0.25)
    return float(rarity)


def _dns_entropy(flow: dict[str, Any]) -> float:
    """Shannon entropy of DNS qname (normalized); high for tunneling-like names."""
    dns = flow.get("dns") if isinstance(flow.get("dns"), dict) else {}
    qname = flow.get("dns_qname") or dns.get("qname") or dns.get("query") or flow.get("qname")
    if not qname:
        return 0.0
    s = str(qname).lower()
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    # Normalize by log2(alphabet upper bound ~40)
    return float(min(1.0, ent / 5.0))


def _ja3(flow: dict[str, Any]) -> Any:
    tls = flow.get("tls") if isinstance(flow.get("tls"), dict) else {}
    return flow.get("ja3") or tls.get("ja3") or flow.get("ja3_hash")


def _ja4(flow: dict[str, Any]) -> Any:
    tls = flow.get("tls") if isinstance(flow.get("tls"), dict) else {}
    return flow.get("ja4") or tls.get("ja4") or flow.get("ja4_hash")


class FlowTransformer(nn.Module):
    """Compact flow transformer: hidden=128, layers=3, heads=4.

    Attention pooling exposes top-k flow contributions for evidence.
    """

    def __init__(
        self,
        input_dim: int = FEATURE_DIM,
        hidden_size: int = 128,
        num_layers: int = 3,
        num_heads: int = 4,
        intermediate_size: int = 384,
        max_len: int = 256,
        dropout: float = 0.1,
    ) -> None:
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_size)
        self.pos = nn.Parameter(torch.randn(1, max_len, hidden_size) * 0.02)
        layer = nn.TransformerEncoderLayer(
            d_model=hidden_size,
            nhead=num_heads,
            dim_feedforward=intermediate_size,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.attn_query = nn.Linear(hidden_size, 1)
        self.head = nn.Sequential(
            nn.LayerNorm(hidden_size),
            nn.Linear(hidden_size, 1),
        )
        self.max_len = max_len
        self.input_dim = input_dim

    def encode(
        self, x: torch.Tensor, mask: torch.Tensor | None = None
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Return (encoded [B,T,H], attention_weights [B,T])."""
        b, t, _ = x.shape
        h = self.input_proj(x) + self.pos[:, :t, :]
        encoded = self.encoder(h, src_key_padding_mask=mask)
        attn_logits = self.attn_query(encoded).squeeze(-1)
        if mask is not None:
            attn_logits = attn_logits.masked_fill(mask, -1e9)
        weights = torch.softmax(attn_logits, dim=-1)
        return encoded, weights

    def forward(self, x: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        # x: [B, T, F]
        encoded, weights = self.encode(x, mask)
        if mask is not None:
            valid = (~mask).unsqueeze(-1).float()
            pooled = (encoded * valid).sum(dim=1) / valid.sum(dim=1).clamp(min=1.0)
        else:
            pooled = (encoded * weights.unsqueeze(-1)).sum(dim=1)
        return torch.sigmoid(self.head(pooled)).squeeze(-1)

    def forward_with_attention(
        self, x: torch.Tensor, mask: torch.Tensor | None = None
    ) -> tuple[torch.Tensor, torch.Tensor]:
        encoded, weights = self.encode(x, mask)
        if mask is not None:
            valid = (~mask).unsqueeze(-1).float()
            pooled = (encoded * valid).sum(dim=1) / valid.sum(dim=1).clamp(min=1.0)
        else:
            pooled = (encoded * weights.unsqueeze(-1)).sum(dim=1)
        score = torch.sigmoid(self.head(pooled)).squeeze(-1)
        return score, weights


def flows_to_tensor(
    flows: list[dict[str, Any]], max_len: int = 256
) -> tuple[np.ndarray, np.ndarray]:
    feats = []
    for flow in flows[:max_len]:
        ja3 = _ja3(flow)
        ja4 = _ja4(flow)
        has_tls = 1.0 if (ja3 or ja4 or flow.get("sni") or flow.get("tls")) else 0.0
        has_dns = 1.0 if (
            flow.get("dns_qname") or flow.get("qname") or flow.get("dns")
        ) else 0.0
        feats.append(
            [
                float(flow.get("src_port", 0)) / 65535.0,
                float(flow.get("dst_port", 0)) / 65535.0,
                1.0 if flow.get("protocol") == "tcp" else 0.0,
                1.0 if flow.get("protocol") == "udp" else 0.0,
                np.log1p(float(flow.get("bytes", 0))),
                np.log1p(float(flow.get("packets", 0))),
                1.0 if flow.get("failed") else 0.0,
                1.0 if flow.get("dst_is_external") else 0.0,
                1.0 if flow.get("direction") == "egress" else 0.0,
                1.0 if flow.get("direction") == "ingress" else 0.0,
                _bucket_hash(flow.get("peer_hash", ""), buckets=1000),
                float(flow.get("bytes", 0) > 0),
                float(flow.get("dst_port", 0) in {22, 23, 3389, 445}),
                float(flow.get("dst_port", 0) in {80, 443, 8080}),
                _bucket_hash(ja3),
                _bucket_hash(ja4),
                _sni_rarity(flow),
                _dns_entropy(flow),
                has_tls,
                has_dns,
            ]
        )
    arr = np.zeros((max_len, FEATURE_DIM), dtype=np.float32)
    mask = np.ones((max_len,), dtype=bool)
    n = len(feats)
    if n:
        arr[:n] = np.asarray(feats, dtype=np.float32)
        mask[:n] = False
    return arr, mask


def attention_contributors(
    flows: list[dict[str, Any]],
    attention_weights: np.ndarray,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Rank flows by attention mass for evidence/contributors."""
    n = min(len(flows), len(attention_weights))
    ranked = sorted(range(n), key=lambda i: float(attention_weights[i]), reverse=True)
    out: list[dict[str, Any]] = []
    for i in ranked[:top_k]:
        flow = flows[i]
        out.append(
            {
                "index": i,
                "contribution": round(float(attention_weights[i]), 6),
                "dst_port": flow.get("dst_port"),
                "protocol": flow.get("protocol"),
                "failed": bool(flow.get("failed")),
                "dst_is_external": bool(flow.get("dst_is_external")),
                "ja3_bucket": _bucket_hash(_ja3(flow)),
                "ja4_bucket": _bucket_hash(_ja4(flow)),
                "sni_rarity": _sni_rarity(flow),
                "dns_entropy": _dns_entropy(flow),
                "type": "attention",
            }
        )
    return out


def feature_contributors(flows: list[dict[str, Any]], top_k: int = 5) -> list[dict[str, Any]]:
    """Heuristic contributors when attention weights unavailable."""
    scored: list[dict[str, Any]] = []
    for i, flow in enumerate(flows):
        score = (
            0.35 * (1.0 if flow.get("failed") else 0.0)
            + 0.2 * (1.0 if flow.get("dst_is_external") else 0.0)
            + 0.15 * _sni_rarity(flow)
            + 0.15 * _dns_entropy(flow)
            + 0.1 * (1.0 if flow.get("dst_port", 0) in {22, 23, 3389, 445} else 0.0)
            + 0.05 * (1.0 if _ja3(flow) or _ja4(flow) else 0.0)
        )
        scored.append(
            {
                "index": i,
                "contribution": round(score, 6),
                "dst_port": flow.get("dst_port"),
                "protocol": flow.get("protocol"),
                "failed": bool(flow.get("failed")),
                "dst_is_external": bool(flow.get("dst_is_external")),
                "ja3_bucket": _bucket_hash(_ja3(flow)),
                "ja4_bucket": _bucket_hash(_ja4(flow)),
                "sni_rarity": _sni_rarity(flow),
                "dns_entropy": _dns_entropy(flow),
                "type": "feature",
            }
        )
    scored.sort(key=lambda c: c["contribution"], reverse=True)
    return scored[:top_k]


def heuristic_score(batch: dict[str, Any]) -> dict[str, Any]:
    """Fallback scorer when ONNX/torch artifact is unavailable."""
    flows = batch.get("flows") or []
    detections = batch.get("detections") or []
    aggregates = batch.get("aggregates") or {}
    score = 0.1
    if detections:
        score = max(float(d.get("score", 0.5)) for d in detections)
    else:
        failed = int(aggregates.get("failed_connections") or 0)
        ports = int(aggregates.get("distinct_dst_ports") or 0)
        external = int(aggregates.get("external_peers") or 0)
        # Enrich with TLS/DNS signals when present on flows
        tls_boost = sum(_sni_rarity(f) + _dns_entropy(f) for f in flows) * 0.05
        score = min(
            0.95,
            0.15 + failed * 0.05 + max(0, ports - 5) * 0.03 + external * 0.02 + tls_boost,
        )
    contributors = feature_contributors(flows)
    severity = "low"
    if score >= 0.95:
        severity = "critical"
    elif score >= 0.86:
        severity = "high"
    elif score >= 0.72:
        severity = "medium"
    return {
        "risk_score": round(float(score), 4),
        "raw_score": round(float(score), 4),
        "calibrated_score": round(float(score), 4),
        "severity": severity,
        "model_name": "network-model",
        "model_version": "1.4.0-heuristic",
        "contributors": contributors,
        "evidence": {
            "detections": detections,
            "aggregates": aggregates,
            "flow_count": len(flows),
            "top_contributors": contributors,
        },
    }
