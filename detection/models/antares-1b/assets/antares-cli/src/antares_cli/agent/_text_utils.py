"""Shared text-processing utilities for the agent layer."""

from __future__ import annotations


def strip_bpe_spaces(value: str) -> str:
    """Remove spaces injected by BPE tokenization around path separators."""
    result = value
    result = result.replace(" /", "/").replace("/ ", "/")
    result = result.replace(" .", ".").replace(". ", ".")
    result = result.replace(" _", "_").replace("_ ", "_")
    result = result.replace(" -", "-").replace("- ", "-")
    return result
