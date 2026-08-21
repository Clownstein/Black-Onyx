"""Models package — DataModel and enums."""

from black_onyx.models.data_model import DataModel, _LIST_FIELDS
from black_onyx.models.enums import (
    EmbeddingType,
    FileType,
    PayloadType,
    TEXT_EXTENSIONS,
    HTML_EXTENSIONS,
    PDF_EXTENSIONS,
    IMAGE_EXTENSIONS,
    TEXTRACT_EXTENSIONS,
    detect_file_type,
)

__all__ = [
    "DataModel",
    "_LIST_FIELDS",
    "EmbeddingType",
    "FileType",
    "PayloadType",
    "TEXT_EXTENSIONS",
    "HTML_EXTENSIONS",
    "PDF_EXTENSIONS",
    "IMAGE_EXTENSIONS",
    "TEXTRACT_EXTENSIONS",
    "detect_file_type",
]
