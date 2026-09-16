"""Thin operation client over the installed fork's protocol-neutral adapter.

``NostrMCPAdapter`` (in the fork) owns the signed kind-2200 authoring,
publishing and chain correlation; this module wires it to a real relay
transport and adds 2204 server-signature verification — one of the layers
the adapter keeps (docs/MCP-TRANSITION.md §2). Result redaction lives in
``nostrhost_mcp.redaction`` and is applied by the server before a result
reaches an MCP client.
"""

from __future__ import annotations

import json
from typing import Any

from .config import Config


class OperationClientError(ValueError):
    """The fork package or relay could not be reached safely."""


def _verify_server_signature(event: dict[str, Any], server_pubkey: str) -> bool:
    """Verify a 2203/2204/2205 event's signature against the server key."""
    try:
        from nostr_sdk import Event, PublicKey

        expected = PublicKey.parse(server_pubkey).to_hex()
        parsed = Event.from_json(json.dumps(event))
        if parsed.author().to_hex() != expected:
            return False
        return bool(parsed.verify())
    except Exception:  # noqa: BLE001 - malformed SDK event/key means failed verification
        return False


class OperationClient:
    """Submits signed operations and correlates their chain events."""

    def __init__(self, config: Config) -> None:
        self.config = config
        from .registry import load_catalog

        self.catalog_digest = load_catalog()["digest"]
        self._adapter = self._build_adapter()

    def _build_adapter(self) -> Any:
        try:
            from .registry import ensure_yunohost

            ensure_yunohost()
            from yunohost.nostr_identity import publish_to_relay
            from yunohost.nostr_mcp_adapter import NostrMCPAdapter
        except ImportError as exc:  # pragma: no cover - fork not installed
            raise OperationClientError("the NostrHost fork (yunohost.*) is not installed on this host") from exc
        return NostrMCPAdapter(
            requester_sk=self.config.agent_sk,
            requester_pubkey=self.config.agent_pubkey,
            control_relay=self.config.control_relay,
            transport=publish_to_relay,
        )

    def submit(self, name: str, arguments: dict[str, Any] | None, actor_pubkey: str | None = None) -> dict[str, Any]:
        """Publish one signed operation request; returns the correlation id."""
        try:
            result = self._adapter.call_tool(name, arguments or {}, actor_pubkey=actor_pubkey)
        except ValueError as exc:
            raise OperationClientError(str(exc)) from exc
        return result

    def events(self, request_id: str):
        """Stream the request's chain events (started/progress/result)."""
        return self._adapter.events(request_id, timeout=self.config.event_timeout)

    def verify_result_event(self, event: dict[str, Any]) -> bool:
        """Server-signature check on a 2203/2204/2205 event.

        Fails CLOSED when no server pubkey is configured: loopback is not a
        trust boundary, and an unverified result (possibly forged by any
        local process) must never be presented to a client/agent as genuine.
        ``load_config`` derives the server pubkey from the fork operator
        config, so a normal deployment always has one.
        """
        if not self.config.server_pubkey:
            return False
        return _verify_server_signature(event, self.config.server_pubkey)

    def parse_result_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Extract the typed body of a kind-2204 result event."""
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise OperationClientError("malformed 2204 content") from exc
        if not isinstance(body, dict):
            raise OperationClientError("malformed 2204 content")
        if body.get("catalog_digest") != self.catalog_digest:
            raise OperationClientError("2204 result catalogue digest mismatch")
        return body

    @staticmethod
    def parse_progress_event(event: dict[str, Any]) -> dict[str, Any]:
        """Extract the typed body of a kind-2205 progress event."""
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            return {}
        return body if isinstance(body, dict) else {}
