"""Sandbox runner client HTTP client for the security-runner service.

Merged from model-tools/sandbox/runner_client.py. Provides a typed async
client for the runner's /execute endpoint with timeout, retry, and
authentication.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from black_onyx_sandbox.schemas import ExecutionRequest, ExecutionResult

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
MAX_RETRIES = 2
RETRY_DELAY = 1.0


class RunnerClient:
    """Async HTTP client for the security-runner service."""

    def __init__(
        self,
        runner_url: str,
        *,
        token: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self._url = runner_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._max_retries = max_retries

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a command in the sandbox runner.

        Returns an ExecutionResult. Raises RunnerError on auth or connection
        failures.
        """
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=request.timeout + 30.0, trust_env=False
                ) as client:
                    resp = await client.post(
                        f"{self._url}/execute",
                        headers=self._headers(),
                        json=request.model_dump(),
                    )
                if resp.status_code == 401:
                    raise RunnerError("Runner authentication failed")
                if resp.status_code == 429:
                    raise RunnerError("Runner rate limited")
                if resp.status_code >= 500:
                    raise RunnerError(f"Runner error: {resp.status_code}")
                if resp.status_code != 200:
                    raise RunnerError(f"Runner returned {resp.status_code}: {resp.text[:200]}")
                data = resp.json()
                return ExecutionResult(**data)
            except httpx.HTTPError as exc:
                last_error = exc
                logger.warning("Runner attempt %d failed: %s", attempt + 1, exc)
                if attempt < self._max_retries:
                    import asyncio
                    await asyncio.sleep(RETRY_DELAY)
        raise RunnerError(f"Runner unavailable after {self._max_retries + 1} attempts: {last_error}")

    async def health(self) -> dict[str, Any]:
        """Check the runner's health endpoint."""
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.get(f"{self._url}/healthz", headers=self._headers())
        if resp.status_code != 200:
            raise RunnerError(f"Runner health check failed: {resp.status_code}")
        return resp.json()


class RunnerError(Exception):
    """Raised when the runner service returns an error or is unavailable."""
    pass
