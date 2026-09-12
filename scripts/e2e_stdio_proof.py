"""End-to-end proof: a real MCP client over nostrhost-mcp stdio.

Launches `nostrhost-mcp serve --stdio`, initializes, lists tools, calls a read
operation (system.status) to a terminal result, calls a write operation
(service.restart) expecting approval_required + operation_id, then polls
op_status.
"""

from __future__ import annotations

import asyncio
import json

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> int:
    server_params = StdioServerParameters(
        command="/opt/nostrhost/venv/bin/nostrhost-mcp",
        args=["serve", "--stdio", "--event-timeout", "45"],
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print("== server info:", init.server_info)

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"== tools listed: {len(names)}")
            for want in ("system.status", "app.list", "service.restart", "op_status"):
                print(f"   {'OK ' if want in names else 'MISSING'} {want}")

            print("\n== call system.status (read, should stream to terminal result)")
            res = await session.call_tool("system.status", {})
            body = json.loads(res.content[0].text)
            print("   ok:", body.get("ok"), "| hostname:", (body.get("result") or {}).get("hostname"), "| versions present:", "versions" in (body.get("result") or {}))

            print("\n== call service.restart (write, expect approval_required + operation_id)")
            res2 = await session.call_tool("service.restart", {"name": "caddy"})
            body2 = json.loads(res2.content[0].text)
            print("   status:", body2.get("status"), "| operation_id:", body2.get("operation_id"))
            op_id = body2.get("operation_id")

            print("\n== op_status on the pending write (expect REQUESTED/EXECUTING, not terminal)")
            res3 = await session.call_tool("op_status", {"operation_id": op_id})
            body3 = json.loads(res3.content[0].text)
            print("   phase:", body3.get("phase"))

            print("\n== approve it via the control plane (nostr-opctl) then re-poll")
            import subprocess

            subprocess.run(["/usr/bin/nostr-opctl", "approve", op_id], check=True, capture_output=True)
            await asyncio.sleep(2)
            res4 = await session.call_tool("op_status", {"operation_id": op_id})
            body4 = json.loads(res4.content[0].text)
            print("   phase after approval:", body4.get("phase"), "| ok:", body4.get("ok"))
            return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
