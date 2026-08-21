"""Core package — device detection, embeddings, NER, classifier, Qdrant store."""

from black_onyx.core.classifier import Classifier
from black_onyx.core.device import get_device, get_device_info
from black_onyx.core.embeddings import EmbeddingModel
from black_onyx.core.ner import DEFAULT_LABELS, NERModel
from black_onyx.core.qdrant_store import QdrantStore

__all__ = [
    "Classifier",
    "DEFAULT_LABELS",
    "EmbeddingModel",
    "NERModel",
    "QdrantStore",
    "get_device",
    "get_device_info",
]
