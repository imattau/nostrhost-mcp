"""Command-line entrypoint for nostrhost-mcp.

``nostrhost-mcp serve`` runs the adapter over stdio (Claude Code / Codex /
OpenCode local MCP) or streamable HTTP bound to loopback (OpenCode Web →
localhost). ``nostrhost-mcp list-tools`` prints the generated catalogue.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any


def _build_server(args: argparse.Namespace, *, catalog: list[dict[str, Any]] | None = None) -> Any:
    from .client import OperationClient
    from .config import load_config
    from .server import NostrHostServer

    config = load_config(
        agent_sk=args.agent_sk,
        control_relay=args.control_relay,
        server_pubkey=args.server_pubkey,
        event_timeout=args.event_timeout,
        actor_pubkey=args.actor_pubkey,
    )
    client = OperationClient(config)
    return NostrHostServer(client, config, catalog=catalog)


def _cmd_list_tools(args: argparse.Namespace) -> int:
    from .registry import local_helper_tools, load_catalog, tool_meta

    catalog = load_catalog()
    entries = [tool_meta(entry) for entry in catalog] + local_helper_tools()
    for entry in entries:
        print(f"{entry['name']}\t{entry['description']}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    server = _build_server(args)
    if args.http:
        return _serve_http(server, args.http, allowed_hosts=args.http_allowed_hosts)
    server.run(transport="stdio")
    return 0


def _serve_http(server: Any, port: int, *, allowed_hosts: list[str] | None = None) -> int:
    import uvicorn

    from .http import Nip98AuthMiddleware

    # streamable_http_app() defaults host="127.0.0.1", which makes the MCP SDK
    # auto-enable DNS-rebinding protection with only loopback allowed_hosts. That
    # is correct for a direct loopback client but rejects requests that arrive
    # through a reverse proxy with a different Host header (e.g. Caddy in front,
    # mcp.nostrhost.test). When the operator names additional hosts, pass an
    # explicit TransportSecuritySettings so the proxy's Host header is accepted
    # while DNS-rebinding protection stays on for everything else.
    kwargs = {}
    if allowed_hosts:
        from mcp.server.transport_security import TransportSecuritySettings

        # The middleware's allowed_hosts are matched two ways: an exact host
        # match, or a `base:*` pattern that only matches a host WITH a port.
        # A reverse proxy forwards Host without a port (e.g. mcp.nostrhost.test),
        # so each additional host needs both the bare name and the wildcard form.
        extra = []
        for h in allowed_hosts:
            extra.append(h)
            extra.append(f"{h}:*")
        kwargs["transport_security"] = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1", "localhost", "127.0.0.1:*", "localhost:*", "[::1]:*"] + extra,
        )

    app = server.streamable_http_app(**kwargs)
    wrapped = Nip98AuthMiddleware(app)
    uvicorn.run(wrapped, host="127.0.0.1", port=int(port), log_level="warning")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nostrhost-mcp", description="Thin MCP protocol adapter over the NostrHost operation model")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the MCP adapter (stdio or loopback streamable HTTP)")
    serve.add_argument("--stdio", action="store_true", help="serve over stdio (default)")
    serve.add_argument("--http", metavar="PORT", type=int, default=0, help="serve streamable HTTP on 127.0.0.1:PORT (loopback only)")
    serve.add_argument("--http-allowed-hosts", metavar="HOST", nargs="*", default=None, help="additional Host headers to accept behind a reverse proxy (DNS-rebinding allowlist)")
    serve.add_argument("--agent-sk", metavar="HEX", default=None, help="agent secret key (default: fork operator config)")
    serve.add_argument("--control-relay", metavar="URL", default=None, help="control relay URL (default: ws://127.0.0.1:4848)")
    serve.add_argument("--server-pubkey", metavar="HEX", default=None, help="verify 2203/2204/2205 signatures against this server pubkey")
    serve.add_argument("--event-timeout", type=float, default=90.0, help="seconds to wait for a terminal 2204 (default 90)")
    serve.add_argument("--actor-pubkey", metavar="HEX", default=None, help="bind this stdio server to an actor identity (default: the requester)")
    serve.set_defaults(func=_cmd_serve)

    lst = sub.add_parser("list-tools", help="print the generated tool catalogue")
    lst.set_defaults(func=_cmd_list_tools)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
