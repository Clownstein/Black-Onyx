#!/usr/bin/env python3
"""Smoke-test local Ollama targets for the AI platform operator cutover.

Does not require TIP or Qdrant only Ollama on localhost:11434.

Usage:
    uv run python scripts/smoke_ollama_ai_platform.py
    uv run python scripts/smoke_ollama_ai_platform.py --embed-model hf.co/Qwen/Qwen3-Embedding-4B-GGUF:Q4_K_M
    uv run python scripts/smoke_ollama_ai_platform.py --chat-model Black-Onyx-5B:Q8_0
"""

from __future__ import annotations

import argparse
import json
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test Ollama embed + chat for Black Onyx")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument(
        "--embed-model",
        default="hf.co/Qwen/Qwen3-Embedding-4B-GGUF:Q4_K_M",
    )
    parser.add_argument("--chat-model", default="Black-Onyx-5B:Q8_0")
    parser.add_argument("--dimensions", type=int, default=2560)
    parser.add_argument("--skip-chat", action="store_true")
    args = parser.parse_args()

    base = args.ollama_url.rstrip("/")
    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: object = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    try:
        tags = httpx.get(f"{base}/api/tags", timeout=10.0)
        names = [m.get("name") for m in (tags.json().get("models") or [])]
        record("ollama_tags", tags.status_code == 200, names[:12])
        record("embed_model_present", args.embed_model in names or any(args.embed_model in (n or "") for n in names), args.embed_model)
        record("chat_model_present", args.chat_model in names or any(args.chat_model.split(":")[0] in (n or "") for n in names), args.chat_model)
    except Exception as exc:
        record("ollama_tags", False, str(exc))

    try:
        emb = httpx.post(
            f"{base}/api/embed",
            json={
                "model": args.embed_model,
                "input": "Cobalt Strike beaconing C2 notes",
                "dimensions": args.dimensions,
            },
            timeout=180.0,
        )
        vector = ((emb.json().get("embeddings") or [[]])[0]) if emb.status_code == 200 else []
        record(
            "embed_2560",
            emb.status_code == 200 and len(vector) == args.dimensions,
            {"status": emb.status_code, "dim": len(vector)},
        )
    except Exception as exc:
        record("embed_2560", False, str(exc))

    if not args.skip_chat:
        try:
            chat = httpx.post(
                f"{base}/v1/chat/completions",
                json={
                    "model": args.chat_model,
                    "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
                    "max_tokens": 16,
                    "temperature": 0.0,
                },
                timeout=180.0,
            )
            content = ""
            if chat.status_code == 200:
                content = (((chat.json().get("choices") or [{}])[0].get("message") or {}).get("content") or "")
            record(
                "chat_openai_compat",
                chat.status_code == 200 and bool(content.strip()),
                {"status": chat.status_code, "preview": content[:80]},
            )
        except Exception as exc:
            record("chat_openai_compat", False, str(exc))

    print(json.dumps({"checks": checks}, indent=2))
    return 0 if all(c["ok"] for c in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
