"""OpenAI-compatible chat completions client for the security gateway.

Talks to vLLM (or any OpenAI-compatible server) at ``{base_url}/v1/chat/completions``.
The Antares-1B / IBM Granite 4.0 model uses the Gemma-style chat template
embedded in the model directory, so we send plain chat messages and let
vLLM apply the template server-side.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GenerateResult:
    """Result from an LLM generation call."""

    content: str
    usage: dict[str, int] = field(
        default_factory=lambda: {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
    )
    status: str | None = None


class LLMClient:
    """Async client that calls OpenAI-compatible ``POST /v1/chat/completions``.

    The security gateway uses this to drive the agent loop. The model name
    and base URL are configured via environment variables:

      - ``LLM_BASE_URL``   (default ``http://vllm:8001``)
      - ``LLM_MODEL_NAME`` (default ``antares-1b``)
      - ``LLM_TIMEOUT``    (default ``300``)
    """

    def __init__(
        self,
        base_url: str | None = None,
        model_name: str | None = None,
        api_key: str | None = None,
        timeout_s: float = 300.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "http://vllm:8001")).rstrip("/")
        self.model_name = model_name or os.environ.get("LLM_MODEL_NAME", "antares-1b")
        self.timeout_s = timeout_s or float(os.environ.get("LLM_TIMEOUT", "300"))
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        key = api_key or os.environ.get("LLM_API_KEY")
        if key:
            self._headers["Authorization"] = f"Bearer {key}"
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_s)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    async def healthcheck(self) -> bool:
        """Return whether the configured LLM service answers its health probe."""
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/health",
                headers=self._headers,
                timeout=min(self.timeout_s, 5.0),
            )
            return 200 <= resp.status_code < 300
        except httpx.HTTPError:
            return False

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> GenerateResult:
        """Send a chat completion request and return the assistant text.

        Args:
            messages: List of ``{role, content}`` dicts.
            tools: Optional list of OpenAI-style tool definitions.
            max_tokens: Maximum output tokens.
            temperature: Sampling temperature.

        Returns:
            GenerateResult with the assistant content and usage stats.
        """
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        # Note: We intentionally do NOT send `tools` / `tool_choice` to vLLM.
        # The Black Onyx agent loop uses control-token format (tool declarations
        # in the system prompt + parsed from text output), not the OpenAI
        # tool-calling API. This avoids requiring --enable-auto-tool-choice.

        url = f"{self.base_url}/v1/chat/completions"
        start = time.perf_counter()
        last_exc: Exception | None = None

        for attempt in range(2):
            try:
                client = await self._get_client()
                resp = await client.post(url, json=payload, headers=self._headers)
                if resp.status_code >= 400:
                    body_snip = (resp.text or "")[:2000]
                    raise httpx.HTTPStatusError(
                        f"Chat completions error {resp.status_code}: {body_snip}",
                        request=resp.request,
                        response=resp,
                    )
                data = resp.json()
                last_exc = None
                break
            except (
                httpx.ReadError,
                httpx.ConnectError,
                httpx.RemoteProtocolError,
                httpx.WriteError,
            ) as exc:
                last_exc = exc
                if self._client is not None:
                    try:
                        await self._client.aclose()
                    except Exception:
                        pass
                    self._client = None
                if attempt == 0:
                    logger.warning("LLM connection error (attempt %d): %s", attempt + 1, exc)
                    continue
                raise
        else:
            if last_exc is not None:
                raise last_exc

        latency_ms = int((time.perf_counter() - start) * 1000)
        logger.debug(
            "LLM chat completed in %dms (model=%s, messages=%d)",
            latency_ms,
            self.model_name,
            len(messages),
        )

        # Extract assistant content from the response
        content = ""
        choices = data.get("choices") or []
        if choices:
            choice = choices[0]
            msg = choice.get("message") or {}
            content = msg.get("content") or ""
            native_calls = msg.get("tool_calls") or []
            if native_calls and "<|tool_call>" not in content:
                content = _control_tokens_from_openai_tool_calls(native_calls, content)

        usage_raw = data.get("usage") or {}
        usage = {
            "prompt_tokens": int(usage_raw.get("prompt_tokens", 0)),
            "completion_tokens": int(usage_raw.get("completion_tokens", 0)),
            "total_tokens": int(usage_raw.get("total_tokens", 0)),
        }

        return GenerateResult(
            content=content,
            usage=usage,
            status=str(data.get("status")) if data.get("status") else None,
        )


def _control_tokens_from_openai_tool_calls(tool_calls: list[Any], content: str) -> str:
    """Map OpenAI-style tool_calls into Black Onyx control tokens for the parser."""
    parts: list[str] = []
    if content.strip():
        parts.append(content.strip())
    for index, call in enumerate(tool_calls):
        if not isinstance(call, dict):
            continue
        fn = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = str(fn.get("name") or "").strip()
        if not name or any(ch in name for ch in " \n{}<>"):
            continue
        raw_args = fn.get("arguments", "{}")
        if isinstance(raw_args, dict):
            args = json.dumps(raw_args, separators=(",", ":"))
        elif isinstance(raw_args, str) and raw_args.strip().startswith("{"):
            args = raw_args.strip()
        else:
            args = "{}"
        call_id = str(call.get("id") or f"call_{index}")
        parts.append(f"<|tool_call>call:{name}:{call_id}{args}<tool_call|>")
    return "\n".join(parts)
