"""Tests for Qdrant collection dimension helpers."""

from black_onyx.core.collections import text_vector_size


def test_qwen3_full_dim():
    assert text_vector_size("dengcao/Qwen3-Embedding-4B:Q4_K_M") == 2560
    assert text_vector_size("hf.co/Qwen/Qwen3-Embedding-4B-GGUF:Q4_K_M") == 2560
    assert text_vector_size("Qwen/Qwen3-Embedding-4B") == 2560


def test_explicit_dimensions_override():
    assert text_vector_size("all-mpnet-base-v2", dimensions=2560) == 2560
