# nostrhost-mcp

Thin MCP protocol adapter over the NostrHost native operation model.

**MCP is an interface, not an authority boundary.** This package owns the MCP
protocol, generated tool schemas, NIP-98 client authentication, result
redaction and transport — while authority, policy, approvals, execution and
state all live in NostrHost itself (the installed fork + control plane).

See `docs/MCP-TRANSITION.md` in the `imattau/nostrhost` umbrella for the full
plan and the frozen `yunohost-mcp` feature inventory.

## Design

```text
Claude / Codex / OpenCode
          ↓
         MCP
          ↓
    nostrhost-mcp         ← this package (thin, no root, no policy)
          ↓
   signed kind-2200 operation request
          ↓
       control relay      ws://127.0.0.1:4848
          ↓
    nostr-operationsd     ← authority/policy/approval/execution/audit
          ↓
   2201/2203/2204/2205 chain events  (correlated by request id)
```

- **Tools are generated** from the installed fork's operation catalogue
  (`yunohost.nostr_operations.operation_catalog()`) — the registry is the
  single source of truth, shared with the CLI, API and Admin forms.
- **Read operations run immediately** (un-gated). **Write operations** return
  `approval_required` + `operation_id` and execute only after an admin (or
  NIP-46 owner) approves in the control plane; poll `op_status` for the
  result.
- **`mcp_status`** answers locally, without submitting an operation: is this
  endpoint reachable, and which identity (if any) is this call recognised
  as. Use it instead of a registry op to sanity-check a new connection — it
  still works even if the control relay or executor is down.
- **HTTP transport** verifies each request's NIP-98 header against
  `nostrhost-policy` and binds the client npub as the operation `actor`. It
  binds **loopback only** — the MCP server is never exposed publicly.
- **Redaction** strips secret-shaped values from results before they reach the
  AI model.

## On-node prerequisites

The adapter depends on the installed NostrHost fork and policy library (like
the CLI and `nostr-api`):

- the fork package (`yunohost.nostr_operations`, `yunohost.nostr_mcp_adapter`,
  `yunohost.nostr_identity.publish_to_relay`, `yunohost.nostrhost.events`) —
  shipped by `nostrhost-core` / `python3-nostrhost`;
- `nostrhost-policy` for NIP-98 verification and redaction;
- a running control relay (`nostrhost-control` on `ws://127.0.0.1:4848`) and
  the operation executor (`nostr-operationsd`).

## Usage

```bash
# stdio (Claude Code / Codex / OpenCode local MCP)
nostrhost-mcp serve --stdio

# streamable HTTP on loopback (OpenCode Web → localhost)
nostrhost-mcp serve --http 8930

# override keys/relay (defaults come from the fork operator config)
nostrhost-mcp serve --stdio --agent-sk <hex> --control-relay ws://127.0.0.1:4848 --server-pubkey <hex>

# print the generated catalogue
nostrhost-mcp list-tools
```

Agent config for MCP clients (e.g. `opencode.json`):

```json
{ "mcpServers": { "nostrhost": { "command": "nostrhost-mcp", "args": ["serve", "--stdio"] } } }
```

## Deploy

`deploy/nostrhost-mcp.service` runs the adapter as an unprivileged `nostr-mcp`
user with no host write authority. Supply the (delegated) agent key via
`/etc/nostrhost/mcp.env` (`NOSTRHOST_AGENT_SK=...`), root-owned and read-only.

## Development

```bash
uv sync
PYTHONPATH=.../forks/yunohost/src  # the fork, for on-host integration
uv run pytest
```