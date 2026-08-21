"""Drain3-backed template extraction."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from log_processor.masking import mask_message

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_./:-]{2,}")


@dataclass(frozen=True)
class TemplateResult:
    template_id: str
    template: str
    masked_message: str
    is_novel: bool
    cluster_id: int


class TemplateExtractor:
    def __init__(self) -> None:
        config = TemplateMinerConfig()
        config.profiling_enabled = False
        config.drain_sim_th = 0.4
        config.drain_depth = 4
        config.drain_max_children = 100
        config.masking_instructions = []
        self._miner = TemplateMiner(config=config)
        self._seen_cluster_ids: set[int] = set()

    def extract(self, message: str) -> TemplateResult:
        masked = mask_message(message)
        result = self._miner.add_log_message(masked)
        cluster_id = int(result["cluster_id"])
        template = str(result["template_mined"])
        is_novel = cluster_id not in self._seen_cluster_ids
        self._seen_cluster_ids.add(cluster_id)
        template_id = self._template_id(template, cluster_id)
        return TemplateResult(
            template_id=template_id,
            template=template,
            masked_message=masked,
            is_novel=is_novel,
            cluster_id=cluster_id,
        )

    @staticmethod
    def _template_id(template: str, cluster_id: int) -> str:
        digest = hashlib.sha256(f"{cluster_id}:{template}".encode()).hexdigest()[:12]
        tokens = [t.lower() for t in _TOKEN_RE.findall(template) if t not in {"<*>", "<IP>", "<UUID>", "<EMAIL>", "<NUM>"}]
        slug = "-".join(tokens[:4]) if tokens else "event"
        slug = re.sub(r"[^a-z0-9.-]+", "-", slug).strip("-") or "event"
        return f"tpl-{slug}-{digest}"
