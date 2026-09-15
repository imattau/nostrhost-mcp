"""Tests for the NIP-98 HTTP middleware (auth + request-size guard)."""

from __future__ import annotations

import pytest

from nostrhost_mcp.auth import Nip98Auth
from nostrhost_mcp.http import MAX_REQUEST_BODY_BYTES, Nip98AuthMiddleware


def _receive_body(chunks: list[bytes], more_flags: list[bool]):
    index = 0

    async def receive():
        nonlocal index
        if index >= len(chunks):
            return {"type": "http.disconnect"}
        body = chunks[index]
        more = more_flags[index] if index < len(more_flags) else False
        index += 1
        return {"type": "http.request", "body": body, "more_body": more}

    return receive


def _run_middleware(app, *, body_bytes: bytes, more_flags: list[bool] | None = None, auth=None) -> tuple[int, bytes]:
    """Drive the middleware with a single request body."""
    messages: list[dict] = []

    async def send(message):
        messages.append(message)

    class _BoomAuth:
        def verify(self, *args, **kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("authentication must not run before the size guard")

    chunks = [body_bytes] if not more_flags else []
    if more_flags:
        chunks = [body_bytes[:1], body_bytes[1:]]
    middleware = Nip98AuthMiddleware(app=app, auth=auth if auth is not None else _BoomAuth())
    scope = {
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 54321),
    }
    import asyncio

    asyncio.get_event_loop().run_until_complete(middleware(scope, _receive_body(chunks, more_flags or []), send))

    status = next((m["status"] for m in messages if m["type"] == "http.response.start"), None)
    body = b"".join(m["body"] for m in messages if m["type"] == "http.response.body")
    return status, body


def test_oversized_request_body_is_rejected_before_auth():
    status, body = _run_middleware(app=lambda *a, **k: None, body_bytes=b"x" * (MAX_REQUEST_BODY_BYTES + 1))
    assert status == 413
    assert b"too large" in body


def test_request_body_at_limit_reaches_auth_not_size_guard():
    # At exactly the limit the body passes the size guard and reaches auth,
    # which rejects the missing Authorization header (401) — not a 413.
    status, body = _run_middleware(
        app=lambda *a, **k: None,
        body_bytes=b"x" * MAX_REQUEST_BODY_BYTES,
        auth=Nip98Auth(),
    )
    assert status == 401
    assert b"too large" not in body


def test_multipart_request_body_is_aggregated_and_capped():
    # Split body (more_body=True) must be aggregated, then the cap enforced.
    status, body = _run_middleware(
        app=lambda *a, **k: None,
        body_bytes=b"y" * (MAX_REQUEST_BODY_BYTES + 2),
        more_flags=[True],
    )
    assert status == 413
    assert b"too large" in body