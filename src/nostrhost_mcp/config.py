"""Runtime configuration for the nostrhost-mcp adapter.

The adapter runs on the NostrHost node and depends on the installed fork
package (``yunohost.nostr_operations`` etc.) exactly like the CLI and
``nostr-api`` do. The requester key defaults to the operator key from the
fork's operator config so a local operator works out of the box; a dedicated
(possibly delegated) agent key can be supplied with ``--agent-sk``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def is_hex64(value: str) -> bool:
    """True if ``value`` is exactly 64 lowercase/uppercase hex characters."""
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


@dataclass(frozen=True)
class Config:
    agent_sk: str
    agent_pubkey: str
    control_relay: str
    server_pubkey: str | None = None
    event_timeout: float = 90.0
    actor_pubkey: str | None = None
    admin_pubkeys: tuple[str, ...] = ()


def _derive_pubkey(sk: str) -> str:
    from nostr_sdk import Keys

    try:
        return Keys.parse(sk).public_key().to_hex()
    except Exception as exc:  # noqa: BLE001 - normalize rust-nostr parse errors
        raise ValueError("not a valid secp256k1 private key") from exc


def _fork_operator_defaults(control_relay: str | None) -> tuple[str, str, str]:
    """Resolve (agent_sk, agent_pubkey, control_relay) from the fork config.

    Imported lazily so this module stays importable before the fork is
    installed (e.g. for ``--list-tools`` during development).
    """
    from yunohost.nostr_operations import _control_relay, _operator_config

    cfg = _operator_config(None, control_relay)
    relay = control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY") or _control_relay(None)
    return cfg.operator_sk, cfg.operator_pubkey, relay


def _fork_server_pubkey() -> str | None:
    """The executor's server pubkey (the key the daemon signs 2203/2204/2205
    with), from the fork operator config. None when the fork config is not
    available (e.g. development, or the node is not yet bootstrapped)."""
    try:
        from yunohost.nostr_operations import _operator_config

        return _operator_config(None, None).server_pubkey
    except Exception:  # noqa: BLE001 - unavailable fork config means no key
        return None


def _fork_admin_pubkeys() -> tuple[str, ...]:
    """The configured admin pubkeys from the fork operator config.

    The daemon auto-approves an approval-gated operation when its actor is an
    admin (``OperationEngine._actor_approves``); the adapter needs the same
    set so it does not report ``approval_required`` for an admin's own call.
    Empty when the fork config is unavailable (development / unbootstrapped),
    which makes the adapter fall back to reporting ``approval_required``
    (fail closed).
    """
    try:
        from yunohost.nostr_operations import _operator_config

        return tuple(str(admin).lower() for admin in _operator_config(None, None).admins if admin)
    except Exception:  # noqa: BLE001 - unavailable fork config means no admin set
        return ()


def load_config(
    *,
    agent_sk: str | None = None,
    control_relay: str | None = None,
    server_pubkey: str | None = None,
    event_timeout: float = 90.0,
    actor_pubkey: str | None = None,
    require_agent_key: bool = False,
) -> Config:
    """Build a :class:`Config`, defaulting the key/relay to the fork config."""
    sk = agent_sk or os.environ.get("NOSTRHOST_AGENT_SK") or os.environ.get("NOSTRHOST_OPERATOR_SK")
    relay = control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY")
    if require_agent_key and not (agent_sk or os.environ.get("NOSTRHOST_AGENT_SK")):
        # M6: a network-facing process must never silently hold the operator
        # key. The operator provisions a scoped agent key (which the control
        # plane's trusted-broker support lets relay client actors) — or, if
        # they truly intend operator-key operation, sets NOSTRHOST_AGENT_SK
        # to that key explicitly. Never fall back to reading operator.toml.
        raise ValueError(
            "serving over HTTP requires a scoped agent key: pass --agent-sk or set NOSTRHOST_AGENT_SK "
            "(the operator key must not be held by a network-facing process)"
        )
    if sk:
        sk = str(sk).strip()
        if not is_hex64(sk):
            raise ValueError("agent secret key must be 64 hex characters")
        pubkey = _derive_pubkey(sk)
        if not relay:
            _, _, relay = _fork_operator_defaults(None)
    else:
        sk, pubkey, relay = _fork_operator_defaults(relay)
    # Server-signature verification key: explicit flag/env wins; otherwise
    # derive it from the fork operator config (the daemon's server key). If
    # it is still unset, result verification FAILS CLOSED (verify_result_event
    # returns False) — loopback is not a trust boundary.
    if server_pubkey:
        server_pubkey = str(server_pubkey).strip()
    elif os.environ.get("NOSTRHOST_SERVER_PUBKEY"):
        server_pubkey = os.environ.get("NOSTRHOST_SERVER_PUBKEY").strip()
    else:
        server_pubkey = _fork_server_pubkey()
    if server_pubkey and not is_hex64(server_pubkey):
        raise ValueError("server pubkey must be 64 hex characters")
    # Admin set used to decide whether an approval-gated tool auto-executes.
    # Explicit env wins (comma-separated); otherwise derive it from the same
    # operator config the daemon reads so the two never drift.
    raw_admins = os.environ.get("NOSTRHOST_ADMIN_PUBKEYS")
    if raw_admins is not None:
        admin_pubkeys = tuple(part.strip().lower() for part in raw_admins.split(",") if part.strip())
    else:
        admin_pubkeys = _fork_admin_pubkeys()
    return Config(
        agent_sk=sk,
        agent_pubkey=pubkey,
        control_relay=relay,
        server_pubkey=server_pubkey,
        event_timeout=max(1.0, float(event_timeout)),
        actor_pubkey=actor_pubkey,
        admin_pubkeys=admin_pubkeys,
    )
