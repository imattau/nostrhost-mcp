"""Streamable-HTTP transport with NIP-98 client authentication.

Wraps the MCP SDK's ASGI app with a middleware that verifies each request's
``Authorization: Nostr <event>`` header against the shared nostrhost-policy
verifier and binds the authenticated pubkey as the operation ``actor``. The
server binds loopback only; it is never exposed publicly
(docs/MCP-TRANSITION.md §7).
"""

from __future__ import annotations

from typing import Any

from .auth import AuthError, Nip98Auth
from .server import actor_context


class Nip98AuthMiddleware:
    """ASGI middleware: verify NIP-98 and set the actor contextvar."""

    def __init__(self, app: Any, auth: Nip98Auth | None = None) -> None:
        self.app = app
        self.auth = auth or Nip98Auth()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                continue
            chunks.append(message.get("body") or b"")
            if not message.get("more_body"):
                break
        body = b"".join(chunks)

        headers = {k.lower(): v for k, v in (scope.get("headers") or [])}
        authorization = headers.get(b"authorization")
        try:
            decoded = authorization.decode("utf-8") if authorization else None
        except UnicodeDecodeError as exc:
            raise AuthError("malformed Authorization header") from exc

        path = scope.get("path") or "/"
        query = (scope.get("query_string") or b"").decode("latin-1")
        url = path + (f"?{query}" if query else "")
        actor = self.auth.verify(decoded, method=scope.get("method", "GET"), url=url, body=body)

        token = actor_context.set(actor)
        sent_request = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal sent_request
            if not sent_request:
                sent_request = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        try:
            await self.app(scope, replay_receive, send)
        finally:
            actor_context.reset(token)
