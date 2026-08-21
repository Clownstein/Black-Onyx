"""OCR engine — Tesseract and PaddleOCR backends."""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class OCREngine:
    """OCR engine with pluggable backends (Tesseract or PaddleOCR).

    Tesseract is the default backend. PaddleOCR is available as an alternative
    via the [ocr-paddle] optional dependency.
    """

    def __init__(
        self,
        backend: str = "tesseract",
        language: str = "eng",
        tesseract_cmd: Optional[str] = None,
    ) -> None:
        """Store configuration without loading any backend.

        Args:
            backend: "tesseract" or "paddle".
            language: OCR language code(s). For Tesseract, e.g. "eng" or "eng+fra".
            tesseract_cmd: Path to tesseract binary (Windows). If None, uses PATH.
        """
        self._backend = backend
        self._language = language
        self._tesseract_cmd = tesseract_cmd
        self._paddle_engine: Any = None
        self._load_attempted: bool = False
        self._load_error: Optional[str] = None

        # Set tesseract command path if provided (must be set before any OCR call)
        if backend == "tesseract" and tesseract_cmd:
            try:
                import pytesseract
                pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
                logger.info(f"Set tesseract command path: {tesseract_cmd}")
            except ImportError:
                logger.warning("pytesseract not installed; OCR will not be available")

    def _load_paddle(self) -> Any:
        """Lazy-load PaddleOCR engine."""
        if not self._load_attempted:
            self._load_attempted = True
            try:
                from paddleocr import PaddleOCR
                self._paddle_engine = PaddleOCR(use_angle_cls=True, lang=self._language)
                logger.info("PaddleOCR engine loaded")
            except ImportError:
                self._load_error = "paddleocr not installed. Install with: pip install paddleocr"
                logger.error(self._load_error)
            except Exception as e:
                self._load_error = str(e)
                logger.error(f"Failed to load PaddleOCR: {e}")
        return self._paddle_engine

    def extract_text(self, image_path: str) -> str:
        """Extract text from an image using the configured backend.

        Args:
            image_path: Path to the image file.

        Returns:
            Extracted text string. Empty string if no text found or on error.
        """
        if self._backend == "tesseract":
            return self._extract_tesseract(image_path)
        elif self._backend == "paddle":
            return self._extract_paddle(image_path)
        else:
            logger.error(f"Unknown OCR backend: {self._backend}")
            return ""

    def _extract_tesseract(self, image_path: str) -> str:
        """Extract text using Tesseract OCR."""
        try:
            import pytesseract
            from PIL import Image
            img = Image.open(image_path)
            text = pytesseract.image_to_string(img, lang=self._language)
            return text.strip()
        except ImportError:
            logger.warning("pytesseract not installed; OCR unavailable. Install with: pip install pytesseract Pillow")
            return ""
        except Exception as e:
            logger.error(f"Tesseract OCR failed for {image_path}: {e}")
            return ""

    def _extract_paddle(self, image_path: str) -> str:
        """Extract text using PaddleOCR."""
        engine = self._load_paddle()
        if engine is None:
            return ""
        try:
            result = engine.ocr(image_path, cls=True)
            if not result or not result[0]:
                return ""
            texts: list[str] = []
            for line in result[0]:
                if line and len(line) >= 2:
                    text_info = line[1]
                    if isinstance(text_info, tuple) and len(text_info) >= 1:
                        texts.append(text_info[0])
                    elif isinstance(text_info, str):
                        texts.append(text_info)
            return " ".join(texts).strip()
        except Exception as e:
            logger.error(f"PaddleOCR failed for {image_path}: {e}")
            return ""

    def get_available_languages(self) -> list[str]:
        """Get available OCR languages for the current backend.

        Returns:
            List of language codes.
        """
        if self._backend == "tesseract":
            try:
                import pytesseract
                return pytesseract.get_languages(config="")
            except Exception:
                return ["eng"]
        return [self._language]

    @property
    def is_available(self) -> bool:
        """Check if the OCR backend is available."""
        if self._backend == "tesseract":
            try:
                import pytesseract  # noqa: F401
                return True
            except ImportError:
                return False
        elif self._backend == "paddle":
            return self._load_paddle() is not None
        return False

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error
