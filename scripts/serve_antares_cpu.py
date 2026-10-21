"""CPU OpenAI-compatible server for the Antares-1B safetensors checkpoint.

vLLM's published image requires CUDA. This process is the no-GPU path: same
/health, /v1/completions, and /v1/chat/completions contract, model id
``antares-1b``.
"""

from __future__ import annotations

import os
import time
import uuid

import torch
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_ID = "antares-1b"
MODEL_PATH = os.environ.get("ANTARES_MODEL_PATH", "/models/antares-1b")

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForCausalLM.from_pretrained(MODEL_PATH, dtype=torch.bfloat16)
model.eval()

app = FastAPI()


class CompletionBody(BaseModel):
    model: str = MODEL_ID
    prompt: str | list[str] = ""
    max_tokens: int = 64
    temperature: float = 0.0


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatBody(BaseModel):
    model: str = MODEL_ID
    messages: list[ChatMessage]
    max_tokens: int = 64
    temperature: float = 0.0


def _generate(prompt: str, max_tokens: int, temperature: float) -> str:
    max_tokens = max(1, min(int(max_tokens), 4096))
    inputs = tokenizer(prompt, return_tensors="pt")
    do_sample = temperature > 0
    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            do_sample=do_sample,
            temperature=temperature if do_sample else None,
            pad_token_id=tokenizer.eos_token_id,
            # Granite hybrid's first DynamicCache has no linear-attention state,
            # and the mask helper raises instead of treating that as a new sequence.
            use_cache=False,
        )
    new_tokens = output[0, inputs["input_ids"].shape[1] :]
    return tokenizer.decode(new_tokens, skip_special_tokens=True)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/models")
def models() -> dict:
    return {
        "object": "list",
        "data": [{"id": MODEL_ID, "object": "model", "owned_by": "black-onyx"}],
    }


@app.post("/v1/completions")
def completions(body: CompletionBody) -> dict:
    prompt = body.prompt[0] if isinstance(body.prompt, list) else body.prompt
    text = _generate(prompt, body.max_tokens, body.temperature)
    return {
        "id": f"cmpl-{uuid.uuid4().hex}",
        "object": "text_completion",
        "created": int(time.time()),
        "model": MODEL_ID,
        "choices": [{"index": 0, "text": text, "finish_reason": "stop"}],
    }


@app.post("/v1/chat/completions")
def chat(body: ChatBody) -> dict:
    prompt = tokenizer.apply_chat_template(
        [message.model_dump() for message in body.messages],
        tokenize=False,
        add_generation_prompt=True,
    )
    text = _generate(prompt, body.max_tokens, body.temperature)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
