"""HTTP transport proof: NIP-98-authenticated streamable HTTP on loopback.

Proves the Nip98AuthMiddleware: a valid per-request NIP-98 header passes
through to the MCP app; a missing/invalid header is rejected before the app.
"""

from __future__ import annotations

import json

import httpx

from nostrhost_policy.auth.signing import ClientIdentity

URL = "http://127.0.0.1:8930/mcp"


def mcp_request(payload: dict, *, auth: str | None) -> tuple[int, str]:
    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if auth is not None:
        headers["Authorization"] = auth
    chunks: list[bytes] = []
    status = None
    with httpx.stream("POST", URL, content=body, headers=headers, timeout=20) as r:
        status = r.status_code
        try:
            for i, chunk in enumerate(r.iter_bytes()):
                chunks.append(chunk)
                if i >= 2:  # enough to capture the first SSE frame(s)
                    break
        except Exception:  # noqa: BLE001 - an SSE stream may close mid-chunk
            pass
    return status or 0, b"".join(chunks).decode("utf-8", "replace")


def main() -> int:
    sk = "0" * 63 + "1"  # throwaway client identity for the proof
    identity = ClientIdentity.from_key_string(sk)
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "nostrhost-mcp-probe", "version": "0.1"},
        },
    }
    body = json.dumps(init_payload).encode()
    good_auth = identity.sign_nip98(method="POST", url=URL, body=body)
    print("== valid NIP-98 initialize ->", end=" ")
    status, text = mcp_request(init_payload, auth=good_auth)
    print(f"HTTP {status}")
    print("   response head:", text[:220].replace("\n", " "))

    print("== missing Authorization ->", end=" ")
    status, text = mcp_request(init_payload, auth=None)
    print(f"HTTP {status}", "|", text[:160].replace("\n", " "))

    print("== garbage Authorization ->", end=" ")
    status, text = mcp_request(init_payload, auth="Bearer junk")
    print(f"HTTP {status}", "|", text[:160].replace("\n", " "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
