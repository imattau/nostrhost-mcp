"""Thin operation client over the installed fork's protocol-neutral adapter.

``NostrMCPAdapter`` (in the fork) owns the signed kind-2200 authoring,
publishing and chain correlation; this module wires it to a real relay
transport and adds 2204 server-signature verification + result redaction —
the layers the adapter keeps (docs/MCP-TRANSITION.md §2).
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
        from coincurve import PublicKeyXOnly

        expected = bytes.fromhex(server_pubkey)
        if bytes.fromhex(str(event.get("pubkey", ""))) != expected:
            return False
        return bool(PublicKeyXOnly(expected).verify(bytes.fromhex(str(event.get("sig", ""))), bytes.fromhex(str(event.get("id", "")))))
    except (ValueError, TypeError):
        return False


def _redact_result(body: dict[str, Any]) -> dict[str, Any]:
    """Redact secret-shaped values before returning results to an AI model."""
    try:
        from nostrhost_policy.redaction import redact
    except ImportError:
        return body
    return redact(body)


class OperationClient:
    """Submits signed operations and correlates their chain events."""

    def __init__(self, config: Config) -> None:
        self.config = config
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
        """Best-effort server-signature check on a 2203/2204/2205 event."""
        if not self.config.server_pubkey:
            return True  # no server key configured -> trust the loopback relay
        return _verify_server_signature(event, self.config.server_pubkey)

    @staticmethod
    def parse_result_event(event: dict[str, Any]) -> dict[str, Any]:
        """Extract the typed body of a kind-2204 result event."""
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise OperationClientError("malformed 2204 content") from exc
        if not isinstance(body, dict):
            raise OperationClientError("malformed 2204 content")
        return body

    @staticmethod
    def parse_progress_event(event: dict[str, Any]) -> dict[str, Any]:
        """Extract the typed body of a kind-2205 progress event."""
        try:
            body = json.loads(event.get("content") or "{}")
        except (TypeError, json.JSONDecodeError):
            return {}
        return body if isinstance(body, dict) else {}
