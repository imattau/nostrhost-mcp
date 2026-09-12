"""Phase 2 proof: native capability grants authorize MCP clients.

The stdio server runs as the node's operator key (a relay-admitted writer)
but is bound via --actor-pubkey to a fresh, non-privileged client identity —
exactly the HTTP/NIP-98 flow: requester = trusted node key, actor = client.
With the daemon authorizing the actor (kind-31100 scopes), a fresh client:
- is rejected `unauthorized` before any grant
- runs read ops after `nostrhost capability grant <pk> server.read`
- is rejected for a write op whose scope it lacks
- gets approval_required once services.restart is granted, then SUCCEEDED
  after control-plane approval.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

RELAY = os.environ.get("CONTROL_RELAY", "ws://127.0.0.1:4848")
MCP_BIN = "/opt/nostrhost/venv/bin/nostrhost-mcp"
NOSTRHOST_BIN = "/usr/bin/nostrhost"


def gen_pk() -> str:
    from coincurve import PublicKeyXOnly

    sk = secrets.token_bytes(32).hex()
    return PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def grant(pk: str, scopes: str) -> None:
    subprocess.run(
        [NOSTRHOST_BIN, "capability", "grant", pk, *scopes.split()],
        check=True, capture_output=True,
    )


async def main() -> int:
    client_pk = gen_pk()
    print(f"== fresh client identity: {client_pk[:16]}… (no grants yet)")

    server_params = StdioServerParameters(
        command=MCP_BIN,
        args=["serve", "--stdio", "--event-timeout", "45", "--actor-pubkey", client_pk],
        env={"NOSTRHOST_CONTROL_RELAY": RELAY, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n== read BEFORE any grant (expect unauthorized)")
            res = await session.call_tool("system.status", {})
            body = json.loads(res.content[0].text)
            reason = (body.get("reason") or body.get("error") or "").lower()
            print(f"   ok: {body.get('ok')} | reason: {reason}")

            print("\n== grant server.read -> read (expect ok=True)")
            grant(client_pk, "server.read")
            await asyncio.sleep(1.5)
            res = await session.call_tool("system.status", {})
            body = json.loads(res.content[0].text)
            result = body.get("result") or {}
            print(f"   ok: {body.get('ok')} | hostname: {result.get('hostname')} | versions present: {'versions' in result}")

            print("\n== write WITHOUT services.restart (server returns approval_required, daemon rejects)")
            res = await session.call_tool("service.restart", {"name": "caddy"})
            body = json.loads(res.content[0].text)
            denied_op = body.get("operation_id")
            print(f"   status: {body.get('status')} | operation_id: {denied_op}")
            await asyncio.sleep(2)
            res = await session.call_tool("op_status", {"operation_id": denied_op})
            body = json.loads(res.content[0].text)
            reason = (body.get("reason") or body.get("error") or "")
            print(f"   denied-write phase: {body.get('phase')} | unauthorized? {'unauthorized' in str(reason).lower()}")

            print("\n== grant services.restart -> write (expect approval_required)")
            grant(client_pk, "services.restart")
            await asyncio.sleep(1.5)
            res = await session.call_tool("service.restart", {"name": "caddy"})
            body = json.loads(res.content[0].text)
            status, op_id = body.get("status"), body.get("operation_id")
            print(f"   status: {status} | operation_id: {op_id}")

            print("\n== approve via control plane, poll op_status (expect SUCCEEDED)")
            subprocess.run(["/usr/bin/nostr-opctl", "approve", op_id], check=True, capture_output=True)
            await asyncio.sleep(2)
            res = await session.call_tool("op_status", {"operation_id": op_id})
            body = json.loads(res.content[0].text)
            print(f"   phase: {body.get('phase')} | ok: {body.get('ok')}")
            return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
