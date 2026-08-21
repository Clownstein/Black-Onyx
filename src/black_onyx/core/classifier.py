"""Optional text classifier — configurable HuggingFace text-classification model."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class Classifier:
    """Optional text classification model.

    If disabled or no model name is configured, classify() returns
    {"label": "disabled"}. If the model fails to load, it gracefully
    degrades to {"label": "error", "error": str}.
    """

    def __init__(
        self,
        model_name: str = "",
        device: str = "cpu",
        enabled: bool = False,
    ) -> None:
        """Store configuration without loading the model.

        Args:
            model_name: HuggingFace text-classification model name.
            device: Torch device string.
            enabled: Whether classification is enabled.
        """
        self._model_name = model_name
        self._device = device
        self._enabled = enabled
        self._pipeline: Any = None
        self._load_error: str | None = None
        self._load_attempted: bool = False

    @property
    def pipeline(self) -> Any:
        """Lazy-load the classification pipeline on first access."""
        if not self._enabled or not self._model_name:
            return None
        if not self._load_attempted:
            self._load_attempted = True
            try:
                logger.info(f"Loading classifier model: {self._model_name}")
                from transformers import pipeline as hf_pipeline
                self._pipeline = hf_pipeline(
                    "text-classification",
                    model=self._model_name,
                    device=self._device if self._device != "cpu" else -1,
                )
                logger.info("Classifier model loaded successfully")
            except Exception as e:
                self._load_error = str(e)
                logger.error(f"Failed to load classifier model: {e}")
        return self._pipeline

    def classify(self, text: str) -> dict[str, Any]:
        """Classify a text string.

        Args:
            text: Input text to classify.

        Returns:
            Dict with "label" and "score" keys, or error/disabled indicators.
        """
        if not self._enabled or not self._model_name:
            return {"label": "disabled", "score": 0.0}
        if self._load_error:
            return {"label": "error", "error": self._load_error, "score": 0.0}
        pipe = self.pipeline
        if pipe is None:
            return {"label": "error", "error": "Model not loaded", "score": 0.0}
        try:
            # Truncate text to avoid exceeding model max length
            truncated = text[:512] if len(text) > 512 else text
            result = pipe(truncated)
            if isinstance(result, list) and result:
                return {"label": result[0].get("label", "unknown"),
                        "score": float(result[0].get("score", 0.0))}
            return {"label": "unknown", "score": 0.0}
        except Exception as e:
            logger.error(f"Classification error: {e}")
            return {"label": "error", "error": str(e), "score": 0.0}

    def classify_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Classify multiple text strings.

        Args:
            texts: List of input texts.

        Returns:
            List of classification dicts.
        """
        return [self.classify(t) for t in texts]

    @property
    def is_loaded(self) -> bool:
        return self._pipeline is not None

    @property
    def is_enabled(self) -> bool:
        return self._enabled and bool(self._model_name)

    @property
    def load_error(self) -> str | None:
        return self._load_error
