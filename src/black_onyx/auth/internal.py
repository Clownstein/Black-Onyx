"""In-request principal for trusted in-process MCP tool HTTP calls."""

from __future__ import annotations

from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import AsyncIterator

from black_onyx.auth.service import Principal

INTERNAL_TOOL_HEADER = "x-black-onyx-internal-tool"

_internal_principal: ContextVar[Principal | None] = ContextVar("_internal_principal", default=None)


def get_internal_principal() -> Principal | None:
    return _internal_principal.get()


@asynccontextmanager
async def internal_tool_context(principal: Principal) -> AsyncIterator[None]:
    token = _internal_principal.set(principal)
    try:
        yield
    finally:
        _internal_principal.reset(token)
