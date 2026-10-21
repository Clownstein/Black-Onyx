"""Enums for file types, payload types, and entity types."""

from __future__ import annotations

from enum import Enum


class PayloadType(str, Enum):
    """Type of data stored in a Qdrant point."""
    TEXT = "text"
    IMAGE = "image"
    MIXED = "mixed"


class EmbeddingType(str, Enum):
    """Type of embedding vector."""
    TEXT = "text"
    CLIP_VISION = "clip_vision"
    CODEBERT = "codebert"


class FileType(str, Enum):
    """High-level file category."""
    TEXT = "text"
    HTML = "html"
    PDF = "pdf"
    IMAGE = "image"
    UNKNOWN = "unknown"


# Extension sets for file type detection
TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".txt", ".csv", ".tsv", ".json", ".jsonl", ".xml", ".log",
    ".ndjson", ".stix", ".stix2", ".sarif", ".md", ".rst", ".yaml",
    ".yml", ".ini", ".cfg", ".conf", ".ioc", ".eml",
})

HTML_EXTENSIONS: frozenset[str] = frozenset({".html", ".htm", ".xhtml"})

PDF_EXTENSIONS: frozenset[str] = frozenset({".pdf"})

IMAGE_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif", ".gif",
})

# Extensions that textract can handle (when installed as optional extra)
TEXTRACT_EXTENSIONS: frozenset[str] = frozenset({
    ".doc", ".docx", ".pptx", ".xlsx", ".odt", ".rtf", ".epub",
    ".ps", ".eml", ".msg", ".mp3", ".ogg", ".wav", ".flac",
})


def detect_file_type(filepath: str) -> FileType:
    """Detect the file type from its extension.

    Args:
        filepath: Path to the file.

    Returns:
        FileType enum value.
    """
    import os
    ext = os.path.splitext(filepath)[1].lower()
    if ext in HTML_EXTENSIONS:
        return FileType.HTML
    if ext in PDF_EXTENSIONS:
        return FileType.PDF
    if ext in IMAGE_EXTENSIONS:
        return FileType.IMAGE
    if ext in TEXT_EXTENSIONS:
        return FileType.TEXT
    if ext in TEXTRACT_EXTENSIONS:
        return FileType.TEXT
    return FileType.UNKNOWN
