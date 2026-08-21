"""Extraction package — text, metadata, patterns, code, chunking, image, OCR, CLIP, EXIF."""

from black_onyx.extraction.chunking import chunk_text, chunk_text_auto, chunk_text_sentence_aware
from black_onyx.extraction.code import detect_code_snippets
from black_onyx.extraction.metadata import (
    extract_metadata_from_html,
    extract_metadata_from_text,
    map_crypto_to_fields,
)
from black_onyx.extraction.text import extract_text_from_file

__all__ = [
    "chunk_text",
    "chunk_text_auto",
    "chunk_text_sentence_aware",
    "detect_code_snippets",
    "extract_metadata_from_html",
    "extract_metadata_from_text",
    "extract_text_from_file",
    "map_crypto_to_fields",
]
