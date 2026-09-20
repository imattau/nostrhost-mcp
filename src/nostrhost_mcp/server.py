"""The MCP server: generated tools over the signed operation chain.

Subclasses the official MCP ``MCPServer`` (v2) and overrides ``list_tools`` /
``call_tool`` so every tool is generated from the fork's operation catalogue
(registry = single source of truth). The server never holds root authority:
it only signs kind-2200 requests with its agent key and correlates the
2201/2203/2204/2205 chain from the loopback control relay.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.server import MCPTool
from mcp.types import CallToolResult, TextContent

from . import __version__
from .client import OperationClient, OperationClientError
from .config import Config, is_hex64
from .redaction import redact
from .registry import catalog_by_name, load_catalog, local_helper_tools, tool_meta

KIND_EXECUTION_STARTED = 2203
KIND_EXECUTION_PROGRESS = 2205
KIND_EXECUTION_RESULT = 2204
KIND_OPERATION_REJECTION = 2202

# The authenticated actor (HTTP transport) rides a contextvar so call_tool can
# tag the signed request with the client npub without per-call plumbing.
actor_context: contextvars.ContextVar[str | None] = contextvars.ContextVar("nostrhost_mcp_actor", default=None)


async def _run_blocking(function, /, *args):
    """Run one blocking relay call without sharing executor lifecycle state."""
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="nostrhost-mcp")
    try:
        return await loop.run_in_executor(executor, partial(function, *args))
    finally:
        executor.shutdown(wait=True)


class NostrHostServer(MCPServer):
    """Generated MCP tools over the native operation chain."""

    def __init__(self, client: OperationClient, config: Config, *, catalog: dict[str, Any] | None = None) -> None:
        super().__init__(
            name="nostrhost-mcp",
            title="NostrHost MCP",
            version=__version__,
            description="Thin MCP protocol adapter over the NostrHost native operation model",
            instructions=(
                "Tools are generated from the NostrHost operation registry. Read tools run "
                "immediately; write tools called by an admin run immediately too (the admin's "
                "own authority is the approval), while a non-admin caller gets "
                "approval_required + operation_id and the operation executes once an "
                "administrator (or NIP-46 owner) signs the approval in the control plane. "
                "Poll with op_status to collect the final result."
            ),
        )
        self._client = client
        self._config = config
        self._catalog = catalog if catalog is not None else load_catalog()
        self._by_name = catalog_by_name(self._catalog)
        self._tools: list[MCPTool] = []
        self._rebuild_tools()

    def _rebuild_tools(self) -> None:
        metas = [tool_meta(entry) for entry in self._catalog["operations"]] + local_helper_tools()
        self._tools = [
            MCPTool(
                name=meta["name"],
                title=meta["name"],
                description=meta["description"],
                inputSchema=meta["input_schema"],
                # Approval-gated calls return an asynchronous approval envelope,
                # not the operation's terminal result. Advertising the terminal
                # schema there would make the MCP contract false.
                outputSchema=(meta.get("output_schema") if meta.get("approval_minimum") == "none" else None),
            )
            for meta in metas
        ]

    # -- MCP protocol overrides --------------------------------------------- #

    async def list_tools(self) -> list[MCPTool]:  # type: ignore[override]
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict[str, Any], context=None) -> CallToolResult:  # type: ignore[override]
        if name == "op_status":
            return await self._call_op_status(arguments, context)
        if name == "mcp_status":
            return self._call_mcp_status()
        spec = self._by_name.get(name)
        if spec is None:
            raise ToolError(f"unknown tool {name!r}")
        actor = actor_context.get() or self._config.actor_pubkey
        try:
            submitted = await _run_blocking(self._client.submit, name, arguments or {}, actor and actor or None)
        except OperationClientError as exc:
            raise ToolError(str(exc)) from exc
        request_id = submitted.get("_nostr", {}).get("request_id")
        if not request_id:
            raise ToolError("operation submission did not return a request id")
        if spec.get("approval", {}).get("minimum") != "none" and not self._actor_is_admin(actor):
            return self._approval_required(name, request_id, spec)
        return await self._run_to_result(name, request_id, context)

    def _actor_is_admin(self, actor: str | None) -> bool:
        """Whether the authenticated actor is a configured admin.

        The control-plane daemon auto-approves an approval-gated operation
        whose actor is an admin, so an admin's own call reaches a terminal
        result without a separate approval - reporting ``approval_required``
        for it would be false. Empty/unresolvable admin set fails closed
        (the caller sees the normal approval_required boundary).
        """
        return bool(actor) and actor.lower() in self._config.admin_pubkeys

    # -- result translation -------------------------------------------------- #

    def _approval_required(self, tool: str, request_id: str, spec: dict[str, Any]) -> CallToolResult:
        body = {
            "status": "approval_required",
            "operation_id": request_id,
            "tool": tool,
            "scopes": spec.get("scopes", []),
            "risk": spec.get("risk"),
            "note": "approval happens in the control plane (nostr-opctl approve or NIP-46); poll op_status for the result",
        }
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(body, indent=2))])

    async def _typed_events(self, request_id: str):
        """Yield verified, typed chain events for ``request_id``.

        Pumps the client's event stream (via ``asyncio.to_thread``, since the
        underlying iterator blocks), drops any event that fails
        ``verify_result_event``, and yields ``(kind, body)`` for the four
        chain-event kinds a caller might care about: started, progress,
        rejection and result. ``body`` is the parsed event payload (an empty
        dict for the started event, which carries no content). Any other
        event kind, or a relay/stream hiccup, ends iteration silently — a
        stream problem must not crash the server.
        """
        events = self._client.events(request_id)
        queue: asyncio.Queue[object] = asyncio.Queue()
        finished = object()
        loop = asyncio.get_running_loop()

        def pump() -> None:
            """Consume the blocking relay iterator in one worker invocation.

            A single producer keeps iterator ownership on one thread and
            preserves event ordering while the async consumer reports progress.
            """
            try:
                for event in events:
                    loop.call_soon_threadsafe(queue.put_nowait, event)
            except Exception:  # noqa: BLE001 - normalized to end-of-stream below
                pass
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, finished)

        producer = asyncio.create_task(_run_blocking(pump))
        try:
            while True:
                event = await queue.get()
                if event is finished:
                    return
                if not isinstance(event, dict):
                    continue
                if not self._client.verify_result_event(event):
                    continue
                kind = int(event.get("kind") or 0)
                if kind == KIND_EXECUTION_STARTED:
                    yield kind, {}
                elif kind == KIND_EXECUTION_PROGRESS:
                    yield kind, self._client.parse_progress_event(event)
                elif kind == KIND_OPERATION_REJECTION:
                    reason = ""
                    try:
                        reason = str((json.loads(event.get("content") or "{}") or {}).get("reason") or "")
                    except (TypeError, json.JSONDecodeError):
                        pass
                    yield kind, {"reason": reason}
                elif kind == KIND_EXECUTION_RESULT:
                    yield kind, self._client.parse_result_event(event)
        except Exception:  # noqa: BLE001 - a relay/stream hiccup must not crash the server
            return
        finally:
            # The relay iterator is contractually finite (terminal result,
            # rejection, or configured timeout). Let its worker finish cleanly.
            await producer

    async def _run_to_result(self, tool: str, request_id: str, context) -> CallToolResult:
        """Stream the chain to the terminal 2204 and return the redacted result."""
        progress: dict[str, Any] = {}
        async for kind, body in self._typed_events(request_id):
            if kind == KIND_EXECUTION_PROGRESS:
                if body:
                    progress = body
                    try:
                        p = float(body.get("progress") or 0)
                        if context is not None:
                            await context.report_progress(max(0.0, min(1.0, p)), 1.0)
                    except (TypeError, ValueError):
                        pass
            elif kind == KIND_OPERATION_REJECTION:
                # Previously unhandled here: this loop only reacted to
                # progress/result events, so a rejected operation ran to the
                # full event_timeout and came back as "pending" instead of
                # reporting the rejection immediately.
                return self._result_content(
                    {"ok": False, "status": "rejected", "error": body.get("reason") or "operation rejected"},
                    request_id,
                    tool,
                )
            elif kind == KIND_EXECUTION_RESULT:
                return self._result_content(body, request_id, tool)
        return self._result_content(
            {"ok": False, "status": "pending", "error": f"no terminal result within {self._config.event_timeout}s", "_nostr_progress": progress},
            request_id,
            tool,
        )

    async def _call_op_status(self, arguments: dict[str, Any], context) -> CallToolResult:
        operation_id = str((arguments or {}).get("operation_id") or "").strip()
        if not is_hex64(operation_id):
            raise ToolError("op_status requires a 64-hex operation_id")
        latest: dict[str, Any] = {"phase": "REQUESTED"}
        async for kind, body in self._typed_events(operation_id):
            if kind == KIND_EXECUTION_STARTED:
                latest = {"phase": "EXECUTING"}
            elif kind == KIND_EXECUTION_PROGRESS:
                if body:
                    latest = {"phase": "EXECUTING", "stage": body.get("stage"), "progress": body.get("progress")}
            elif kind == KIND_OPERATION_REJECTION:
                latest = {"phase": "REJECTED", "reason": body.get("reason", "")}
                break
            elif kind == KIND_EXECUTION_RESULT:
                phase = "SUCCEEDED" if body.get("ok") else "FAILED"
                latest = {"phase": phase, **body}
                break
        body = {"operation_id": operation_id, **latest}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(redact(body), indent=2))])

    def _call_mcp_status(self) -> CallToolResult:
        """Answer locally: is this endpoint up, and who is this call recognised as.

        Unlike every generated tool, this never submits a signed operation —
        reaching this code at all already proves the transport, and (over
        HTTP) NIP-98 auth, are working. It exists because the adapter has no
        ``whoami`` op (the registry has none) and a status check that goes
        through the full 2200 chain would fail exactly when it's most useful
        (relay/executor down). See docs/MCP-TRANSITION.md Issue 10.
        """
        actor = actor_context.get()
        if actor:
            actor_source = "nip98"
        elif self._config.actor_pubkey:
            actor = self._config.actor_pubkey
            actor_source = "configured"
        else:
            actor = None
            actor_source = "unbound"
        body = {
            "server": "nostrhost-mcp",
            "version": __version__,
            "tools_available": len(self._tools),
            "control_relay": self._config.control_relay,
            "agent_pubkey": self._config.agent_pubkey,
            "server_signature_verified": bool(self._config.server_pubkey),
            "actor": actor,
            "actor_source": actor_source,
        }
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(body, indent=2))])

    def _result_content(self, body: dict[str, Any], request_id: str, tool: str) -> CallToolResult:
        payload = {"operation_id": request_id, "tool": tool, **body}
        redacted = self._redact_payload(payload, tool=tool)
        structured = None
        if body.get("ok") is True and isinstance(redacted.get("result"), dict):
            structured = redacted["result"]
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(redacted, indent=2))],
            structuredContent=structured,
            # Generated tools advertise the operation's success schema.  A
            # rejection or timeout cannot satisfy that schema, so mark it as
            # a protocol-level tool error.  MCP clients then surface the text
            # envelope instead of rejecting the response for missing
            # structured content and misreporting the whole server as down.
            isError=body.get("ok") is not True,
        )

    @staticmethod
    def _redact_payload(value: Any, *, tool: str = "") -> Any:
        value = redact(value)
        if tool.startswith("nsite."):
            return NostrHostServer._redact_nsite(value)
        return value

    @staticmethod
    def _redact_nsite(value: Any) -> Any:
        """Phase 3b: redact untrusted NIP-5A free text and site titles.

        Manifest ``content`` is arbitrary user content and a site ``title``
        comes from the manifest's untrusted ``title`` tag — both are replaced
        with a marker before they can reach an MCP client's context, so a
        hostile manifest cannot inject text (prompt injection) or bloat the
        result. Identity (pubkey/label/kind/d/hashes) is preserved. Curated
        collections (kind 30004) carry their own untrusted ``title``,
        ``description`` and ``image`` fields, which are redacted the same way.
        """
        if isinstance(value, dict):
            return {
                k: (
                    "[REDACTED]"
                    if k in ("content", "title", "description", "image") and isinstance(v, str)
                    else NostrHostServer._redact_nsite(v)
                )
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [NostrHostServer._redact_nsite(v) for v in value]
        return value
