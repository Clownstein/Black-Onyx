"""NER model wrapper — lazy-loaded GLiNER with thread-safe access."""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# Default entity labels for PII / OSINT extraction
DEFAULT_LABELS: list[str] = [
    "person", "organization", "email", "phone number",
    "address", "city", "state", "country", "zip code",
    "username", "business name",
]


class NERModel:
    """Lazy-loaded NER model using GLiNER, protected by a threading lock.

    GLiNER is NOT thread-safe for concurrent predict_entities calls.
    This wrapper serializes access via a threading.Lock.
    """

    def __init__(
        self,
        model_name: str = "urchade/gliner_multi_pii-v1",
        labels: list[str] | None = None,
        threshold: float = 0.5,
        device: str = "cpu",
    ) -> None:
        """Store configuration without loading the model.

        Args:
            model_name: HuggingFace model name for GLiNER.
            labels: Entity labels to detect. Defaults to DEFAULT_LABELS.
            threshold: Confidence threshold for entity detection.
            device: Torch device string.
        """
        self._model_name = model_name
        self._labels = labels if labels is not None else list(DEFAULT_LABELS)
        self._threshold = threshold
        self._device = device
        self._model: Any = None
        self._lock = threading.Lock()

    @property
    def model(self) -> Any:
        """Lazy-load the GLiNER model on first access."""
        if self._model is None:
            logger.info(f"Loading NER model: {self._model_name} on {self._device}")
            from gliner import GLiNER
            self._model = GLiNER.from_pretrained(self._model_name)
            if self._device != "cpu":
                self._model = self._model.to(self._device)
            logger.info("NER model loaded successfully")
        return self._model

    def predict(self, text: str, threshold: float | None = None) -> list[dict[str, Any]]:
        """Extract named entities from text (thread-safe).

        Args:
            text: Input text to analyze.
            threshold: Override the default threshold.

        Returns:
            List of entity dicts: {"text", "label", "start", "end", "score"}.
        """
        if not text or not text.strip():
            return []
        thresh = threshold if threshold is not None else self._threshold
        with self._lock:
            entities = self.model.predict_entities(text, self._labels, threshold=thresh)
        return [
            {
                "text": e.get("text", ""),
                "label": e.get("label", ""),
                "start": e.get("start", 0),
                "end": e.get("end", 0),
                "score": e.get("score", 0.0),
            }
            for e in entities
        ]

    def predict_batch(self, texts: list[str], threshold: float | None = None) -> list[list[dict[str, Any]]]:
        """Extract named entities from multiple texts (thread-safe, serialized).

        Args:
            texts: List of input texts.
            threshold: Override the default threshold.

        Returns:
            List of lists of entity dicts.
        """
        thresh = threshold if threshold is not None else self._threshold
        results: list[list[dict[str, Any]]] = []
        with self._lock:
            for text in texts:
                if not text or not text.strip():
                    results.append([])
                    continue
                entities = self.model.predict_entities(text, self._labels, threshold=thresh)
                results.append([
                    {
                        "text": e.get("text", ""),
                        "label": e.get("label", ""),
                        "start": e.get("start", 0),
                        "end": e.get("end", 0),
                        "score": e.get("score", 0.0),
                    }
                    for e in entities
                ])
        return results

    def map_to_datamodel_fields(self, entities: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Map NER entities to DataModel field names.

        Maps entity labels to DataModel list fields:
        - "person" -> person_name
        - "organization" -> business_name
        - "email" -> emails
        - "phone number" -> phone_numbers
        - "address" -> address
        - "city" -> city
        - "state" -> state
        - "country" -> country
        - "zip code" -> zip_code
        - "username" -> username
        - "business name" -> business_name

        Args:
            entities: List of entity dicts from predict().

        Returns:
            Dict mapping DataModel field names to lists of entity text values.
        """
        label_to_field: dict[str, str] = {
            "person": "person_name",
            "organization": "business_name",
            "email": "emails",
            "phone number": "phone_numbers",
            "address": "address",
            "city": "city",
            "state": "state",
            "country": "country",
            "zip code": "zip_code",
            "username": "username",
            "business name": "business_name",
        }
        result: dict[str, list[str]] = {}
        for entity in entities:
            label = entity.get("label", "").lower()
            text = entity.get("text", "")
            field_name = label_to_field.get(label)
            if field_name and text:
                if field_name not in result:
                    result[field_name] = []
                if text not in result[field_name]:
                    result[field_name].append(text)
            # Also store as "label:text" in ner_entities
        return result

    @property
    def labels(self) -> list[str]:
        return list(self._labels)

    @property
    def is_loaded(self) -> bool:
        return self._model is not None
