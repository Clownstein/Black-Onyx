"""ASGI request-body limits applied before JSON parsing."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        lengths = [value for name, value in scope.get("headers", []) if name.lower() == b"content-length"]
        if len(lengths) > 1:
            await self._reject(scope, receive, send, 400, "Ambiguous Content-Length")
            return
        if lengths:
            try:
                declared = int(lengths[0].decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                await self._reject(scope, receive, send, 400, "Invalid Content-Length")
                return
            if declared < 0:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length")
                return
            if declared > self.max_bytes:
                await self._reject(scope, receive, send, 413, "Request body is too large")
                return
        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                await self._reject(scope, receive, send, 413, "Request body is too large")
                return
            body.extend(chunk)
            more_body = bool(message.get("more_body", False))
        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(
        scope: Scope, receive: Receive, send: Send, status_code: int, detail: str
    ) -> None:
        await JSONResponse(status_code=status_code, content={"detail": detail})(scope, receive, send)
