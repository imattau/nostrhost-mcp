"""Client authentication for the streamable-HTTP transport.

Every HTTP request carries a NIP-98 ``Authorization: Nostr <event>`` header
signed by the client identity. This module verifies it with the shared
``nostrhost_policy`` NIP-98 verifier (replay-protected) and returns the
authenticated pubkey, which becomes the ``actor`` tag on submitted operations.
The MCP server never holds the client's key and never grants authority on its
own — the daemon evaluates the requester's capabilities/delegations.
"""

from __future__ import annotations

from typing import Any


class AuthError(ValueError):
    """The NIP-98 credential could not be verified."""


class Nip98Auth:
    """Replay-protected NIP-98 verifier backed by nostrhost_policy."""

    def __init__(self, clock_skew_seconds: int = 60) -> None:
        self._verify = None
        self._replay = None
        self._clock_skew = clock_skew_seconds

    def _ensure(self) -> None:
        if self._verify is not None:
            return
        try:
            from nostrhost_policy.auth.nip98 import verify_nip98_request
            from nostrhost_policy.auth.replay import ReplayCache
        except ImportError as exc:  # pragma: no cover - policy not installed
            raise AuthError("nostrhost-policy is not installed; the HTTP transport cannot authenticate clients") from exc

        self._replay = ReplayCache()
        self._verify = verify_nip98_request

    def verify(self, authorization: str | None, *, method: str, url: str, body: bytes) -> str:
        """Verify a NIP-98 header and return the authenticated hex pubkey."""
        self._ensure()
        if not authorization:
            raise AuthError("missing Authorization header (expected 'Nostr <event>')")
        try:
            identity = self._verify(
                authorization_header=authorization,
                method=method,
                url=url,
                body=body,
                replay_cache=self._replay,
                clock_skew_seconds=self._clock_skew,
            )
        except ValueError as exc:
            raise AuthError(f"NIP-98 verification failed: {exc}") from exc
        return str(identity.pubkey)


def redact_secret_shaped(value: Any) -> Any:
    """Redact secret-shaped values in results (lazy policy import)."""
    try:
        from nostrhost_policy.redaction import redact
    except ImportError:
        return value
    return redact(value)
