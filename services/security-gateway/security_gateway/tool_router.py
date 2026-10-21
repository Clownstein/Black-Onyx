"""Optional FunctionGemma first-stage tool router.

The router proposes at most one tool call through an OpenAI-compatible Chat
Completions endpoint. Black Onyx remains responsible for analysis, subsequent
tool calls, and the final answer.

Ported from the archived ``model-tools/agent/tool_router.py``.

Eval gate: only document this router as recommended after the frozen eval suite
shows a lower parse/dispatch error rate than the single-model path.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .parser import ParsedToolCall

logger = logging.getLogger(__name__)


class ToolRouterError(RuntimeError):
    """Raised when a router response cannot safely produce a tool proposal."""


class FunctionGemmaToolRouter:
    """Call a small OpenAI-compatible model to propose one tool invocation.

    Uses the OpenAI Chat Completions tool-calling API (``tool_choice: "auto"``)
    to get a single tool proposal. The main LLM (Black-Onyx-5B) then runs with
    the control-token format for the actual multi-turn agent loop.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_s: float = 30.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        self._http_client = http_client
        self._owns_http_client = http_client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.timeout_s)
        return self._http_client

    async def aclose(self) -> None:
        """Close the internally-owned HTTP client."""
        if self._owns_http_client and self._http_client is not None:
            try:
                await self._http_client.aclose()
            except Exception:
                pass
            self._http_client = None

    async def propose(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> Optional[ParsedToolCall]:
        """Return one validated proposal, or ``None`` when no tool is selected.

        Args:
            messages: Conversation messages (system + user + history).
            tools: OpenAI-style tool definitions.

        Returns:
            A ``ParsedToolCall`` with name + arguments, or ``None`` if the
            router declines to propose a tool.
        """
        if not tools:
            return None

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0.0,
            "max_tokens": 256,
        }
        try:
            client = await self._get_client()
            response = await client.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ToolRouterError(f"tool router request failed: {exc}") from exc

        try:
            choice = data["choices"][0]
            message = choice.get("message", {})
            tool_calls = message.get("tool_calls", [])
            if not tool_calls:
                return None
            tc = tool_calls[0]
            func = tc.get("function", {})
            name = func.get("name", "")
            import json as _json

            args_raw = func.get("arguments", "{}")
            try:
                arguments = (
                    _json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                )
            except (ValueError, TypeError):
                arguments = {}
            call_id = tc.get("id", "router-0")
            if not name:
                return None
            return ParsedToolCall(name=name, arguments=arguments, call_id=call_id)
        except (KeyError, IndexError, TypeError) as exc:
            raise ToolRouterError(
                f"tool router returned malformed response: {exc}"
            ) from exc
