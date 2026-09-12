"""Phase 4 proof: the approval flow stays out of the MCP server.

docs/MCP-TRANSITION.md §7 Phase 4 gate:

    OpenCode -> nostrhost-mcp -> read server status -> list apps ->
    request app install -> owner approval -> install executes ->
    health check -> result returned

The adapter only *surfaces* the boundary (approval_required + operation_id
+ op_status); pushing approval is a control-plane utility (nostr-opctl
approve / NIP-46). This proof drives the stdio server (bound via
--actor-pubkey to a fresh client) against the real operationsd + relay and
additionally proves the parts that give the gate its teeth:

- the MCP tool surface exposes NO approval/rejection tools
- reads (server status, app list, domains) flow through the adapter
- an app install (native package.plan -> package.reconcile) executes only
  after *owner* approval and passes a health check over HTTP
- owner co-signature: for an owner-signature-gated op (domain.remove,
  domains.remove rule by default) an approval signed by a *non-owner* admin
  is ignored (operation stays pending); the owner's approval executes it
- a control-plane rejection marks the operation REJECTED through op_status
  and nothing executes (no side effects)

Setup (root, idempotent):
- a second admin key (non-owner) is added to /etc/nostrhost/operator.toml
  so the daemon accepts its approval event and can then be shown to lack the
  owner's signature
- d6.test is pre-provisioned for the manual-provider domain proof
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
import urllib.request

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

RELAY = os.environ.get("CONTROL_RELAY", "ws://127.0.0.1:4848")
MCP_BIN = "/opt/nostrhost/venv/bin/nostrhost-mcp"
NOSTRHOST_BIN = "/usr/bin/nostrhost"
OPCTL_BIN = "/usr/bin/nostr-opctl"
CATALOGUE = "/var/lib/nostrhost/catalogue.json"
PACKAGE_TOML = "/root/catalogue/package.toml"
OPERATOR_TOML = "/etc/nostrhost/operator.toml"
SECOND_ADMIN_SK = "/root/phase4-admin.sk"
D6_HOSTS_ENTRY = "127.0.0.1 d6.test"
D6_CADDY_CONF = "/etc/caddy/conf.d/d6.test.conf"

FAILURES: list[str] = []


def gen_pk() -> str:
    from coincurve import PublicKeyXOnly

    sk = secrets.token_bytes(32).hex()
    return PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def gen_keypair() -> tuple[str, str]:
    from coincurve import PublicKeyXOnly

    sk = secrets.token_bytes(32).hex()
    return sk, PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def grant(pk: str, scopes: str) -> None:
    subprocess.run([NOSTRHOST_BIN, "capability", "grant", pk, *scopes.split()], check=True, capture_output=True)


def check(cond: bool, label: str) -> None:
    status = "OK" if cond else "FAIL"
    print(f"   [{status}] {label}")
    if not cond:
        FAILURES.append(label)


def opctl_approve(op_id: str, admin_sk: str | None = None) -> None:
    cmd = [OPCTL_BIN, "approve", op_id]
    if admin_sk:
        cmd += ["--admin-sk", admin_sk]
    subprocess.run(cmd, check=True, capture_output=True)


def opctl_reject(op_id: str, reason: str) -> None:
    subprocess.run([OPCTL_BIN, "reject", op_id, "--reason", reason], check=True, capture_output=True)


def curl_ok(url: str) -> tuple[int, str]:
    """Follow redirects (auth flow) and return (status_code, body)."""
    try:
        proc = subprocess.run(["curl", "-skL", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", url], capture_output=True, text=True)
        return int(proc.stdout.strip() or 0), ""
    except (ValueError, FileNotFoundError):
        return -1, ""


# -- setup ---------------------------------------------------------------- #

def ensure_d6_test() -> None:
    if D6_HOSTS_ENTRY not in open("/etc/hosts").read():
        with open("/etc/hosts", "a") as fh:
            fh.write(D6_HOSTS_ENTRY + "\n")
    if not os.path.exists(D6_CADDY_CONF):
        with open(D6_CADDY_CONF, "w") as fh:
            fh.write("d6.test {\n\ttls internal\n}\n")
    subprocess.run(["systemctl", "reload", "caddy"], check=True, capture_output=True)


def ensure_second_admin() -> tuple[str, str]:
    """Idempotently register a non-owner admin; returns (sk, pubkey)."""
    if os.path.exists(SECOND_ADMIN_SK):
        sk = open(SECOND_ADMIN_SK).read().strip()
        sk, pubkey = _second_admin_keypair(sk)
    else:
        sk, pubkey = gen_keypair()
        with open(SECOND_ADMIN_SK, "w") as fh:
            fh.write(sk + "\n")
        os.chmod(SECOND_ADMIN_SK, 0o600)
    changed = _add_admin_to_operator_toml(pubkey)
    if changed:
        subprocess.run(["systemctl", "restart", "nostr-operationsd"], check=True, capture_output=True)
        time.sleep(3)
    _relay_allow_pubkey(pubkey)
    return sk, pubkey


def _relay_allow_pubkey(pubkey: str) -> None:
    """Allowlist the key on the control relay (NIP-86 allowpubkey as operator).

    The relay is allowlist_mode=true, so without this a non-owner admin's
    approval event would be rejected at the relay before the daemon can ever
    consider (and deliberately ignore) it."""
    import tomllib

    from coincurve import PublicKeyXOnly

    conf = tomllib.load(open(OPERATOR_TOML, "rb"))
    sk = conf["operator_sk"]
    op_pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    body = json.dumps({"method": "allowpubkey", "params": [pubkey, "phase4 non-owner admin"]}, separators=(",", ":")).encode()
    content = base64.b64encode(body).decode()
    payload_hash = hashlib.sha256(body).hexdigest()
    tags = [["u", RELAY], ["method", "allowpubkey"], ["payload", payload_hash]]
    event = _sign_nip86(sk, op_pk, content, tags)
    req = urllib.request.Request(
        "http://127.0.0.1:4848/",
        data=body,
        headers={
            "Content-Type": "application/nostr+json+rpc",
            "Authorization": "Nostr " + base64.b64encode(json.dumps(event).encode()).decode(),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _sign_nip86(sk: str, pk: str, content: str, tags: list) -> dict:
    from coincurve import PrivateKey

    created_at = int(time.time())
    serialized = json.dumps([0, pk, created_at, 24133, tags, content], separators=(",", ":"), ensure_ascii=False).encode()
    event_id = hashlib.sha256(serialized).hexdigest()
    sig = PrivateKey(bytes.fromhex(sk)).sign_schnorr(bytes.fromhex(event_id)).hex()
    return {"id": event_id, "pubkey": pk, "created_at": created_at, "kind": 24133, "tags": tags, "content": content, "sig": sig}


def _second_admin_keypair(sk: str) -> tuple[str, str]:
    from coincurve import PublicKeyXOnly

    return sk, PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def _add_admin_to_operator_toml(pubkey: str) -> bool:
    text = open(OPERATOR_TOML).read()
    m = re.search(r"(?m)^admins\s*=\s*\[([^\]]*)\]", text)
    if m:
        existing = [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]
        if pubkey in existing:
            return False
        newline = "admins = [" + ", ".join(f'"{pk}"' for pk in existing + [pubkey]) + "]"
        text = text[: m.start()] + newline + text[m.end():]
    else:
        text += f'\nadmins = ["{pubkey}"]\n'
    with open(OPERATOR_TOML, "w") as fh:
        fh.write(text)
    return True


# -- MCP flow helpers ------------------------------------------------------ #

async def poll_terminal(session, op_id: str, *, max_waits: int = 25) -> dict:
    body: dict = {}
    for _ in range(max_waits):
        await asyncio.sleep(3)
        res = await session.call_tool("op_status", {"operation_id": op_id})
        body = json.loads(res.content[0].text)
        if body.get("phase") in ("SUCCEEDED", "FAILED", "REJECTED"):
            break
    return body


async def submit(session, tool: str, args: dict, label: str) -> dict:
    """Submit a mutation and assert the approval boundary is surfaced."""
    res = await session.call_tool(tool, args)
    body = json.loads(res.content[0].text)
    op_id = body.get("operation_id")
    status = body.get("status")
    check(status == "approval_required" and op_id, f"{label}: approval_required + operation_id")
    return body


async def mutate(session, tool: str, args: dict, label: str, *, admin_sk: str | None = None) -> dict:
    """Submit a mutation, approve (default: owner/operator), poll to terminal."""
    body = await submit(session, tool, args, label)
    op_id = body.get("operation_id")
    if not op_id:
        return body
    opctl_approve(op_id, admin_sk)
    terminal = await poll_terminal(session, op_id)
    phase = terminal.get("phase")
    ok = terminal.get("ok")
    check(phase == "SUCCEEDED", f"{label}: terminal phase={phase} ok={ok}")
    return terminal


# -- proof ------------------------------------------------------------------ #

async def main() -> int:
    print("== setup: second (non-owner) admin + d6.test prerequisites")
    sk2, pk2 = ensure_second_admin()
    ensure_d6_test()
    print(f"   non-owner admin: {pk2[:16]}…")

    client_pk = gen_pk()
    print(f"== fresh client identity: {client_pk[:16]}… (no grants yet)")
    try:
        await run_proof(client_pk, pk2, sk2)
    except Exception as exc:  # noqa: BLE001 - surface the failure in the summary
        print(f"   [EXC] {type(exc).__name__}: {str(exc)[:120]}")
        FAILURES.append(str(exc))
    print("\n== RESULT ==")
    if FAILURES:
        print(f"PHASE4-PROOF-FAIL ({len(FAILURES)}):")
        for f in FAILURES:
            print("   -", f)
        return 1
    print("PHASE4-PROOF-OK")
    return 0


async def run_proof(client_pk: str, second_admin_pk: str, second_admin_sk: str) -> None:
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

            print("\n== approval stays out of the MCP surface")
            offenders = [n for n in names if n and any(h in n.lower() for h in ("approve", "reject", "confirm", "accept", "deny", "approval"))]
            check(offenders == [], f"no approval/rejection tools exposed (found: {offenders})")
            check("op_status" in names, "op_status helper exposed")

            print("\n== reads: server status + list apps + domains (Phase 4 gate reads)")
            grant(client_pk, "server.read apps.read domains.read services.read dns.read apps.write domains.write dns.credentials.write")
            await asyncio.sleep(2)
            res = await session.call_tool("system.status", {})
            body = json.loads(res.content[0].text)
            result = body.get("result") or {}
            check(body.get("ok") is True, f"system.status: ok={body.get('ok')}")
            check(bool(result.get("hostname") or result.get("system")), "system.status returns host facts")
            res = await session.call_tool("app.list", {})
            body = json.loads(res.content[0].text)
            apps = (body.get("result") or {}).get("apps") or {}
            check(body.get("ok") is True and isinstance(apps, dict), f"app.list returns the app registry ({len(apps)} apps)")
            res = await session.call_tool("domain.list", {})
            body = json.loads(res.content[0].text)
            check(body.get("ok") is True, f"domain.list: ok={body.get('ok')}")

            print("\n== app install (native) -> owner approval -> executes -> health check")
            with open(PACKAGE_TOML, "r") as fh:
                pkg_toml = fh.read()
            import tomllib

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
            terminal = await mutate(session, "package.reconcile", {"plan": envelope}, "package.reconcile install nostrhost-test")
            op_results = (terminal.get("result") or {}).get("results") or []
            health_op = next((r for r in op_results if r.get("operation") == "health.http.check"), None)
            health_result = (health_op or {}).get("result") or {}
            check(bool(health_op) and health_result.get("healthy") is True, f"health check in install result: {json.dumps(health_result)[:120]}")
            status, _ = curl_ok("https://nostrhost.test/nostrhost-test/")
            check(200 <= status < 300, f"health check: /nostrhost-test/ reachable (final HTTP {status})")
            res = await session.call_tool("app.list", {})
            body = json.loads(res.content[0].text)
            apps = (body.get("result") or {}).get("apps") or {}
            installed = apps.get("nostrhost-test") or {}
            check(bool(installed) and installed.get("source") == "nostr", f"app.list shows nostrhost-test installed (native={installed.get('native')})")

            print("\n== owner co-signature: a non-owner admin approval must be ignored")
            await mutate(session, "domain.add", {"domain": "d6.test", "provider_type": "manual"}, "domain.add d6.test (admin-gated)")
            res = await session.call_tool("domain.remove", {"domain": "d6.test"})
            body = json.loads(res.content[0].text)
            op_id = body.get("operation_id")
            check(body.get("status") == "approval_required" and op_id, "domain.remove d6.test: approval_required (owner-gated op)")
            opctl_approve(op_id, second_admin_sk)
            await asyncio.sleep(4)
            res = await session.call_tool("op_status", {"operation_id": op_id})
            body = json.loads(res.content[0].text)
            check(body.get("phase") in ("REQUESTED", "APPROVED"), f"non-owner admin approval ignored (still pending, phase={body.get('phase')})")
            opctl_approve(op_id)
            terminal = await poll_terminal(session, op_id)
            check(terminal.get("phase") == "SUCCEEDED", f"owner approval executes domain.remove: phase={terminal.get('phase')}")

            print("\n== control-plane rejection surfaces REJECTED and runs nothing")
            body = await submit(session, "credential.set", {"provider": "cloudflare", "name": "reject-proof", "value": "tok_reject"}, "credential.set reject-proof")
            op_id = body.get("operation_id")
            opctl_reject(op_id, "phase-4 manual rejection")
            terminal = await poll_terminal(session, op_id)
            check(terminal.get("phase") == "REJECTED", f"rejected op surfaces REJECTED through op_status: phase={terminal.get('phase')}")
            res = await session.call_tool("credential.list", {"provider": "cloudflare"})
            body = json.loads(res.content[0].text)
            creds = (body.get("result") or {}).get("credentials") or []
            check(not any("reject-proof" in str(c) for c in creds), "rejected credential.set left no broker state")

            print("\n== teardown: drop d6.test leftovers")
            for path in (D6_CADDY_CONF,):
                if os.path.exists(path):
                    os.remove(path)
            hosts = open("/etc/hosts").read().replace(D6_HOSTS_ENTRY + "\n", "")
            open("/etc/hosts", "w").write(hosts)
            subprocess.run(["systemctl", "reload", "caddy"], check=True, capture_output=True)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
