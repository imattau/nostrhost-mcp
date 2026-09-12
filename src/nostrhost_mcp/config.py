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


@dataclass(frozen=True)
class Config:
    agent_sk: str
    agent_pubkey: str
    control_relay: str
    server_pubkey: str | None = None
    event_timeout: float = 90.0
    actor_pubkey: str | None = None


def _derive_pubkey(sk: str) -> str:
    from coincurve import PublicKeyXOnly

    return PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()


def _fork_operator_defaults(control_relay: str | None) -> tuple[str, str, str]:
    """Resolve (agent_sk, agent_pubkey, control_relay) from the fork config.

    Imported lazily so this module stays importable before the fork is
    installed (e.g. for ``--list-tools`` during development).
    """
    from yunohost.nostr_operations import _control_relay, _operator_config

    cfg = _operator_config(None, control_relay)
    relay = control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY") or _control_relay(None)
    return cfg.operator_sk, cfg.operator_pubkey, relay


def load_config(
    *,
    agent_sk: str | None = None,
    control_relay: str | None = None,
    server_pubkey: str | None = None,
    event_timeout: float = 90.0,
    actor_pubkey: str | None = None,
) -> Config:
    """Build a :class:`Config`, defaulting the key/relay to the fork config."""
    sk = agent_sk or os.environ.get("NOSTRHOST_AGENT_SK") or os.environ.get("NOSTRHOST_OPERATOR_SK")
    relay = control_relay or os.environ.get("NOSTRHOST_CONTROL_RELAY")
    if sk:
        sk = str(sk).strip()
        if not (len(sk) == 64 and all(c in "0123456789abcdefABCDEF" for c in sk)):
            raise ValueError("agent secret key must be 64 hex characters")
        pubkey = _derive_pubkey(sk)
        if not relay:
            _, _, relay = _fork_operator_defaults(None)
    else:
        sk, pubkey, relay = _fork_operator_defaults(relay)
    if server_pubkey:
        server_pubkey = str(server_pubkey).strip()
        if not (len(server_pubkey) == 64 and all(c in "0123456789abcdefABCDEF" for c in server_pubkey)):
            raise ValueError("server pubkey must be 64 hex characters")
    return Config(
        agent_sk=sk,
        agent_pubkey=pubkey,
        control_relay=relay,
        server_pubkey=server_pubkey,
        event_timeout=max(1.0, float(event_timeout)),
        actor_pubkey=actor_pubkey,
    )
