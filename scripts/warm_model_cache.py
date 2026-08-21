"""Pre-download the configured embedding model into the model cache.

The first chat or search request otherwise blocks while several hundred
megabytes download, which looks like a hung stream in the browser.
"""

from __future__ import annotations

import sys

from black_onyx.config import get_settings


def main() -> int:
    settings = get_settings()
    device = settings.resolve_device(settings.embedding.device)
    model_name = settings.embedding.model_name
    print(f"Warming embedding model {model_name} on {device}", flush=True)

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(model_name, device=device)
    vector = model.encode(["warm cache"], convert_to_numpy=True, show_progress_bar=False)
    print(f"Embedding model ready: dimension {len(vector[0])}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
