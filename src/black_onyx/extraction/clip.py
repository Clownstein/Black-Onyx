"""CLIP model wrapper — lazy-loaded OpenCLIP for image and text embeddings."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class CLIPModel:
    """Lazy-loaded CLIP model using OpenCLIP for vision and text embeddings.

    The model is not loaded until first use, allowing the application
    to start quickly and only load the model when needed.
    """

    def __init__(
        self,
        model_name: str = "ViT-B-32",
        pretrained: str = "openai",
        device: str = "cpu",
    ) -> None:
        """Store configuration without loading the model.

        Args:
            model_name: OpenCLIP model architecture name (e.g. "ViT-B-32").
            pretrained: Pretrained weights identifier (e.g. "openai", "laion2b_s34b_b79k").
            device: Torch device string ('cuda', 'cpu', 'mps').
        """
        self._model_name = model_name
        self._pretrained = pretrained
        self._device = device
        self._model: Any = None
        self._preprocess: Any = None
        self._tokenizer: Any = None
        self._embedding_dim: int | None = None

    def _load(self) -> None:
        """Lazy-load the OpenCLIP model, preprocess transform, and tokenizer."""
        if self._model is not None:
            return
        logger.info(f"Loading CLIP model: {self._model_name} (pretrained={self._pretrained}) on {self._device}")
        import open_clip
        self._model, _, self._preprocess = open_clip.create_model_and_transforms(
            self._model_name,
            pretrained=self._pretrained,
            device=self._device,
        )
        self._model.eval()  # CRITICAL: must call before inference
        self._tokenizer = open_clip.get_tokenizer(self._model_name)
        logger.info("CLIP model loaded successfully")

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    def embed_image(self, image_path: str) -> list[float]:
        """Encode an image into a CLIP embedding vector.

        Args:
            image_path: Path to the image file.

        Returns:
            Embedding vector as a list of floats. Empty list on error.
        """
        try:
            import torch
            from PIL import Image

            self._load()
            image = Image.open(image_path).convert("RGB")
            image_tensor = self._preprocess(image).unsqueeze(0).to(self._device)

            with torch.no_grad():
                features = self._model.encode_image(image_tensor)
                # Normalize for cosine similarity
                features = features / features.norm(dim=-1, keepdim=True)
                return features.cpu().numpy()[0].tolist()
        except ImportError:
            logger.error("open_clip_torch or Pillow not installed. Install with: pip install open-clip-torch Pillow")
            return []
        except Exception as e:
            logger.error(f"CLIP image embedding failed for {image_path}: {e}")
            return []

    def embed_text(self, text: str) -> list[float]:
        """Encode text into a CLIP embedding vector.

        Args:
            text: Input text string.

        Returns:
            Embedding vector as a list of floats. Empty list on error.
        """
        try:
            import torch

            self._load()
            tokens = self._tokenizer([text]).to(self._device)

            with torch.no_grad():
                features = self._model.encode_text(tokens)
                # Normalize for cosine similarity
                features = features / features.norm(dim=-1, keepdim=True)
                return features.cpu().numpy()[0].tolist()
        except ImportError:
            logger.error("open_clip_torch not installed. Install with: pip install open-clip-torch")
            return []
        except Exception as e:
            logger.error(f"CLIP text embedding failed: {e}")
            return []

    def get_embedding_dim(self) -> int:
        """Get the CLIP embedding dimension (loads model if needed).

        Returns:
            Integer embedding dimension.
        """
        if self._embedding_dim is None:
            vec = self.embed_text("test")
            self._embedding_dim = len(vec)
        return self._embedding_dim

    @property
    def model_name(self) -> str:
        return self._model_name
