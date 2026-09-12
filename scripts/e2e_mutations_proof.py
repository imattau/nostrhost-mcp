"""Phase 3 proof: signed mutations + streaming through the MCP server.

Drives the stdio server (bound via --actor-pubkey to a fresh client, exactly
the HTTP/NIP-98 flow) through mutation categories against the real
operationsd + control relay:

- a write whose scope the actor lacks is rejected `unauthorized` (gating)
- after granting the scopes, each mutation submits a signed kind-2200,
  returns approval_required + operation_id, and reaches SUCCEEDED once an
  administrator approves in the control plane:
    service.control   (services)
    credential.set/remove  (credential broker)
    dns.subscribe/unsubscribe  (nostr-native free hostname)
    domain.add/remove  (native domains + DNS)
    backup.create      (restic backup, minimal system part)
    package.plan + package.reconcile  (native app lifecycle, resource engine)
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
OPCTL_BIN = "/usr/bin/nostr-opctl"
CATALOGUE = "/var/lib/nostrhost/catalogue.json"
PACKAGE_TOML = "/root/catalogue/package.toml"

FAILURES: list[str] = []


def gen_pk() -> str:
    from nostr_sdk import Keys

    sk = secrets.token_bytes(32).hex()
    return Keys.parse(sk).public_key().to_hex()


def grant(pk: str, scopes: str) -> None:
    subprocess.run(
        [NOSTRHOST_BIN, "capability", "grant", pk, *scopes.split()],
        check=True, capture_output=True,
    )


def check(cond: bool, label: str) -> None:
    status = "OK" if cond else "FAIL"
    print(f"   [{status}] {label}")
    if not cond:
        FAILURES.append(label)


def opctl_approve(op_id: str) -> None:
    subprocess.run([OPCTL_BIN, "approve", op_id], check=True, capture_output=True)


async def poll_terminal(session, op_id: str, *, expect_ok: bool = True, max_waits: int = 25) -> dict:
    body: dict = {}
    for _ in range(max_waits):
        await asyncio.sleep(3)
        res = await session.call_tool("op_status", {"operation_id": op_id})
        body = json.loads(res.content[0].text)
        if body.get("phase") in ("SUCCEEDED", "FAILED", "REJECTED"):
            break
    return body


async def mutate(session, tool: str, args: dict, label: str, *, expect_ok: bool = True) -> dict:
    """Submit a mutation, get approval_required, approve, poll to terminal."""
    res = await session.call_tool(tool, args)
    body = json.loads(res.content[0].text)
    op_id = body.get("operation_id")
    status = body.get("status")
    check(status == "approval_required" and op_id, f"{label}: approval_required + operation_id")
    if not op_id:
        return body
    opctl_approve(op_id)
    terminal = await poll_terminal(session, op_id)
    phase = terminal.get("phase")
    ok = terminal.get("ok")
    check(phase == ("SUCCEEDED" if expect_ok else "FAILED"), f"{label}: terminal phase={phase} ok={ok}")
    return terminal


async def main() -> int:
    client_pk = gen_pk()
    print(f"== fresh client identity: {client_pk[:16]}… (no grants yet)")
    try:
        await run_proof(client_pk)
    except Exception as exc:  # noqa: BLE001 - surface the failure in the summary
        print(f"   [EXC] {type(exc).__name__}: {str(exc)[:120]}")
        FAILURES.append(str(exc))
    print("\n== RESULT ==")
    if FAILURES:
        print(f"PHASE3-PROOF-FAIL ({len(FAILURES)}):")
        for f in FAILURES:
            print("   -", f)
        return 1
    print("PHASE3-PROOF-OK")
    return 0


async def run_proof(client_pk: str) -> None:
    server_params = StdioServerParameters(
        command=MCP_BIN,
        args=["serve", "--stdio", "--event-timeout", "45", "--actor-pubkey", client_pk],
        env={"NOSTRHOST_CONTROL_RELAY": RELAY, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = listed.tools if hasattr(listed, "tools") else listed
            names = {getattr(t, "name", None) for t in tools}
            for required in (
                "service.control", "backup.create", "credential.set", "credential.remove",
                "dns.subscribe", "dns.unsubscribe", "domain.add", "domain.remove",
                "package.plan", "package.reconcile", "app.remove", "rollback.apply",
                "state.reconcile", "dns.apply",
            ):
                check(required in names, f"tool exposed: {required}")

            print("\n== write WITHOUT services.write scope (expect daemon rejects unauthorized)")
            res = await session.call_tool("service.control", {"name": "caddy", "action": "restart"})
            body = json.loads(res.content[0].text)
            denied_op = body.get("operation_id")
            terminal = await poll_terminal(session, denied_op)
            reason = str(terminal.get("reason") or terminal.get("error") or "")
            check(
                terminal.get("phase") == "FAILED" and "unauthorized" in reason.lower(),
                f"denied write: phase={terminal.get('phase')} reason={reason[:60]}",
            )

            print("\n== grant all mutation scopes")
            grant(client_pk, "services.write backups.create dns.credentials.read dns.credentials.write dns.write domains.write apps.read apps.write")
            await asyncio.sleep(2)

            await mutate(session, "service.control", {"name": "caddy", "action": "restart"}, "service.control restart")

            await mutate(session, "credential.set", {"provider": "cloudflare", "name": "mcp-proof", "value": "tok_phase3"}, "credential.set")
            res = await session.call_tool("credential.list", {})
            listed = json.loads(res.content[0].text)
            creds = (listed.get("result") or {}).get("credentials", [])
            check(any("cloudflare" in str(c) and "mcp-proof" in str(c) for c in creds), "credential.list shows the broker secret")
            await mutate(session, "credential.remove", {"provider": "cloudflare", "name": "mcp-proof"}, "credential.remove")

            await mutate(session, "dns.subscribe", {"hostname": "mcp-proof.nohost.me"}, "dns.subscribe free hostname")
            await mutate(session, "dns.unsubscribe", {"hostname": "mcp-proof.nohost.me"}, "dns.unsubscribe")

            await mutate(session, "domain.add", {"domain": "d6.test", "provider_type": "manual"}, "domain.add d6.test")
            await mutate(session, "domain.remove", {"domain": "d6.test"}, "domain.remove d6.test")

            await mutate(session, "backup.create", {"name": "phase3-mcp", "system": ["conf_ldap"]}, "backup.create (minimal)")

            print("\n== native app lifecycle: package.plan -> package.reconcile")
            with open(PACKAGE_TOML, "r") as fh:
                pkg_toml = fh.read()
            try:
                import tomllib
                package = tomllib.loads(pkg_toml)
            except ImportError:  # pragma: no cover
                import tomli as tomllib
                package = tomllib.loads(pkg_toml)
            with open(CATALOGUE, "r") as fh:
                catalogue = json.load(fh)
            entry = next((e["declaration"] for e in catalogue.get("entries", []) if e.get("declaration", {}).get("AppID") == "nostrhost-test"), {})
            provenance = {
                "app_id": entry.get("AppID"),
                "version": entry.get("Version"),
                "repository": entry.get("Repository"),
                "revision": entry.get("Commit"),
                "manifest_sha256": entry.get("ManifestHash"),
                "package_path": entry.get("PackagePath"),
            }
            res = await session.call_tool("package.plan", {"package": package, "catalogue": provenance})
            plan = json.loads(res.content[0].text)
            envelope = plan.get("result", {}).get("envelope") or plan.get("result", {})
            check(bool(envelope.get("plan_sha256")) and bool(envelope.get("operations")), "package.plan returns a plan envelope")
            await mutate(session, "package.reconcile", {"plan": envelope}, "package.reconcile install nostrhost-test")


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
