"""Text chunking with sliding window and sentence-aware modes."""

from __future__ import annotations

import re


def chunk_text(
    text: str,
    chunk_size: int = 2048,
    overlap: int = 200,
) -> list[str]:
    """Chunk text using a sliding window with overlap.

    Args:
        text: Input text to chunk.
        chunk_size: Maximum size of each chunk in characters.
        overlap: Number of characters to overlap between consecutive chunks.

    Returns:
        List of text chunks. Empty list if input is empty.

    Raises:
        ValueError: If overlap >= chunk_size.
    """
    if not text or not text.strip():
        return []

    if overlap >= chunk_size:
        raise ValueError(f"overlap ({overlap}) must be less than chunk_size ({chunk_size})")

    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    start = 0
    step = chunk_size - overlap

    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += step

    return chunks


def chunk_text_sentence_aware(
    text: str,
    chunk_size: int = 2048,
    overlap: int = 200,
) -> list[str]:
    """Chunk text with sentence-boundary awareness.

    Attempts to break chunks at sentence boundaries to preserve context.
    Falls back to simple chunking if the text has no sentence delimiters.

    Args:
        text: Input text to chunk.
        chunk_size: Target size of each chunk in characters.
        overlap: Number of characters to overlap.

    Returns:
        List of text chunks.
    """
    if not text or not text.strip():
        return []

    if overlap >= chunk_size:
        raise ValueError(f"overlap ({overlap}) must be less than chunk_size ({chunk_size})")

    if len(text) <= chunk_size:
        return [text]

    # Split into sentences using common delimiters
    # This regex splits on . ! ? followed by whitespace, while preserving the delimiter
    sentences = re.split(r"(?<=[.!?])\s+", text)

    chunks: list[str] = []
    current_chunk: list[str] = []
    current_size = 0
    overlap_text = ""

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue

        # If a single sentence is longer than chunk_size, split it further
        if len(sentence) > chunk_size:
            # Save current chunk if any
            if current_chunk:
                chunks.append(" ".join(current_chunk))
                current_chunk = []
                current_size = 0

            # Split the long sentence with simple chunking
            sub_chunks = chunk_text(sentence, chunk_size, overlap)
            chunks.extend(sub_chunks)
            # Set overlap text for the next iteration
            if sub_chunks:
                overlap_text = sub_chunks[-1][-overlap:] if overlap > 0 else ""
            continue

        # Check if adding this sentence would exceed chunk_size
        if current_size + len(sentence) + 1 > chunk_size and current_chunk:
            chunks.append(" ".join(current_chunk))

            # Build overlap: keep last N characters of the current chunk
            if overlap > 0:
                last_text = " ".join(current_chunk)
                overlap_text = last_text[-overlap:]
                current_chunk = [overlap_text] if overlap_text else []
                current_size = len(overlap_text)
            else:
                current_chunk = []
                current_size = 0

        current_chunk.append(sentence)
        current_size += len(sentence) + 1  # +1 for the space

    # Don't forget the last chunk
    if current_chunk:
        chunks.append(" ".join(current_chunk))

    return chunks


def chunk_text_auto(
    text: str,
    chunk_size: int = 2048,
    overlap: int = 200,
    sentence_aware: bool = True,
) -> list[str]:
    """Automatically choose the best chunking strategy.

    Args:
        text: Input text to chunk.
        chunk_size: Maximum/target chunk size in characters.
        overlap: Overlap between chunks in characters.
        sentence_aware: If True, use sentence-aware chunking; otherwise simple sliding window.

    Returns:
        List of text chunks.
    """
    if sentence_aware:
        return chunk_text_sentence_aware(text, chunk_size, overlap)
    return chunk_text(text, chunk_size, overlap)
