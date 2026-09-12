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
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.server import MCPTool
from mcp.types import CallToolResult, TextContent

from . import __version__
from .client import OperationClient, OperationClientError
from .config import Config
from .registry import catalog_by_name, load_catalog, local_helper_tools, tool_meta

KIND_EXECUTION_STARTED = 2203
KIND_EXECUTION_PROGRESS = 2205
KIND_EXECUTION_RESULT = 2204

# The authenticated actor (HTTP transport) rides a contextvar so call_tool can
# tag the signed request with the client npub without per-call plumbing.
actor_context: contextvars.ContextVar[str | None] = contextvars.ContextVar("nostrhost_mcp_actor", default=None)


class NostrHostServer(MCPServer):
    """Generated MCP tools over the native operation chain."""

    def __init__(self, client: OperationClient, config: Config, *, catalog: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            name="nostrhost-mcp",
            title="NostrHost MCP",
            version=__version__,
            description="Thin MCP protocol adapter over the NostrHost native operation model",
            instructions=(
                "Tools are generated from the NostrHost operation registry. Read tools run "
                "immediately; write tools return approval_required + operation_id and execute "
                "only after an administrator (or NIP-46 owner) signs the approval in the "
                "control plane. Poll with op_status to collect the final result."
            ),
        )
        self._client = client
        self._config = config
        self._catalog = catalog if catalog is not None else load_catalog()
        self._by_name = catalog_by_name(self._catalog)
        self._tools: list[MCPTool] = []
        self._rebuild_tools()

    def _rebuild_tools(self) -> None:
        metas = [tool_meta(entry) for entry in self._catalog] + local_helper_tools()
        self._tools = [
            MCPTool(name=meta["name"], title=meta["name"], description=meta["description"], input_schema=meta["input_schema"])
            for meta in metas
        ]

    # -- MCP protocol overrides --------------------------------------------- #

    async def list_tools(self) -> list[MCPTool]:  # type: ignore[override]
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict[str, Any], context=None) -> CallToolResult:  # type: ignore[override]
        if name == "op_status":
            return await self._call_op_status(arguments, context)
        spec = self._by_name.get(name)
        if spec is None:
            raise ToolError(f"unknown tool {name!r}")
        actor = actor_context.get() or self._config.actor_pubkey
        try:
            submitted = await asyncio.to_thread(self._client.submit, name, arguments or {}, actor and actor or None)
        except OperationClientError as exc:
            raise ToolError(str(exc)) from exc
        request_id = submitted.get("_nostr", {}).get("request_id")
        if not request_id:
            raise ToolError("operation submission did not return a request id")
        if spec.get("require_approval"):
            return self._approval_required(name, request_id, spec)
        return await self._run_to_result(name, request_id, context)

    # -- result translation -------------------------------------------------- #

    def _approval_required(self, tool: str, request_id: str, spec: dict[str, Any]) -> CallToolResult:
        body = {
            "status": "approval_required",
            "operation_id": request_id,
            "tool": tool,
            "scope": spec.get("scope"),
            "risk": spec.get("risk"),
            "note": "approval happens in the control plane (nostr-opctl approve or NIP-46); poll op_status for the result",
        }
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(body, indent=2))])

    async def _run_to_result(self, tool: str, request_id: str, context) -> CallToolResult:
        """Stream the chain to the terminal 2204 and return the redacted result."""
        events = self._client.events(request_id)
        progress: dict[str, Any] = {}
        while True:
            event = await asyncio.to_thread(next, events, None)
            if event is None:
                break
            if not self._client.verify_result_event(event):
                continue
            kind = int(event.get("kind") or 0)
            if kind == KIND_EXECUTION_PROGRESS:
                body = self._client.parse_progress_event(event)
                if body:
                    progress = body
                    try:
                        p = float(body.get("progress") or 0)
                        if context is not None:
                            await context.report_progress(max(0.0, min(1.0, p)), 1.0)
                    except (TypeError, ValueError):
                        pass
            elif kind == KIND_EXECUTION_RESULT:
                body = self._client.parse_result_event(event)
                return self._result_content(body, request_id, tool)
        return self._result_content(
            {"ok": False, "status": "pending", "error": f"no terminal result within {self._config.event_timeout}s", "_nostr_progress": progress},
            request_id,
            tool,
        )

    async def _call_op_status(self, arguments: dict[str, Any], context) -> CallToolResult:
        operation_id = str((arguments or {}).get("operation_id") or "").strip()
        if len(operation_id) != 64 or any(c not in "0123456789abcdefABCDEF" for c in operation_id):
            raise ToolError("op_status requires a 64-hex operation_id")
        events = self._client.events(operation_id)
        latest: dict[str, Any] = {"phase": "REQUESTED"}
        while True:
            event = await asyncio.to_thread(next, events, None)
            if event is None:
                break
            if not self._client.verify_result_event(event):
                continue
            kind = int(event.get("kind") or 0)
            if kind == KIND_EXECUTION_STARTED:
                latest = {"phase": "EXECUTING"}
            elif kind == KIND_EXECUTION_PROGRESS:
                body = self._client.parse_progress_event(event)
                if body:
                    latest = {"phase": "EXECUTING", "stage": body.get("stage"), "progress": body.get("progress")}
            elif kind == KIND_EXECUTION_RESULT:
                body = self._client.parse_result_event(event)
                phase = "SUCCEEDED" if body.get("ok") else "FAILED"
                latest = {"phase": phase, **body}
                break
        body = {"operation_id": operation_id, **latest}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(self._redact(body), indent=2))])

    def _result_content(self, body: dict[str, Any], request_id: str, tool: str) -> CallToolResult:
        payload = {"operation_id": request_id, "tool": tool, **body}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(self._redact(payload), indent=2))])

    @staticmethod
    def _redact(value: Any) -> Any:
        try:
            from nostrhost_policy.redaction import redact
        except ImportError:
            return value
        return redact(value)
