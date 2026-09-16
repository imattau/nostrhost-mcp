"""Tests for the operation client: signature verification, parsing, config."""

from __future__ import annotations

import json

import pytest
from nostr_sdk import EventBuilder, Keys, Kind

from nostrhost_mcp.client import OperationClientError, _verify_server_signature
from nostrhost_mcp.config import load_config


def test_verify_server_signature_accepts_authentic_event():
    keys = Keys.parse("0" * 63 + "1")
    pk = keys.public_key().to_hex()
    signed = EventBuilder(Kind(2204), '{"ok":true}').finalize(keys)
    event = json.loads(signed.as_json())
    assert _verify_server_signature(event, pk) is True


def test_verify_server_signature_rejects_wrong_key():
    event = {
        "id": "a" * 64,
        "pubkey": "b" * 64,
        "sig": "c" * 128,
    }
    assert _verify_server_signature(event, "d" * 64) is False


def test_verify_server_signature_handles_malformed():
    assert _verify_server_signature({"id": "x"}, "zz") is False


def test_parse_result_event_extracts_body():
    from nostrhost_mcp.client import OperationClient as _Client

    client = object.__new__(_Client)
    client.catalog_digest = "sha256:test"
    body = client.parse_result_event(
        {"content": json.dumps({"ok": True, "catalog_digest": "sha256:test", "result": {}})}
    )
    assert body["ok"] is True
    with pytest.raises(OperationClientError):
        client.parse_result_event({"content": "not json"})
    with pytest.raises(OperationClientError):
        client.parse_result_event({"content": json.dumps([1, 2])})
    with pytest.raises(OperationClientError, match="digest mismatch"):
        client.parse_result_event({"content": json.dumps({"ok": True, "catalog_digest": "sha256:old"})})


def test_load_config_derives_pubkey_and_relay():
    sk = "0" * 63 + "1"
    cfg = load_config(agent_sk=sk, control_relay="ws://127.0.0.1:4848")
    assert len(cfg.agent_pubkey) == 64
    assert cfg.control_relay == "ws://127.0.0.1:4848"
    assert cfg.agent_sk == sk


def test_load_config_admin_pubkeys_env_override(monkeypatch):
    monkeypatch.setenv("NOSTRHOST_ADMIN_PUBKEYS", "A" * 64 + ", " + "b" * 64)
    cfg = load_config(agent_sk="0" * 63 + "1", control_relay="ws://r")
    assert cfg.admin_pubkeys == ("a" * 64, "b" * 64)


def test_load_config_admin_pubkeys_default_empty_without_fork(monkeypatch):
    monkeypatch.delenv("NOSTRHOST_ADMIN_PUBKEYS", raising=False)
    monkeypatch.delenv("NOSTRHOST_OPERATOR_SK", raising=False)
    monkeypatch.setenv("NOSTRHOST_OPERATOR_CONFIG", "/nonexistent/nostrhost-operator.toml")
    cfg = load_config(agent_sk="0" * 63 + "1", control_relay="ws://r")
    # The fork operator config is unavailable, so the admin set fails closed
    # to empty (callers keep the approval boundary).
    assert cfg.admin_pubkeys == ()


def test_load_config_rejects_bad_key():
    with pytest.raises(ValueError):
        load_config(agent_sk="xyz", control_relay="ws://127.0.0.1:4848")


def test_load_config_rejects_bad_server_pubkey():
    with pytest.raises(ValueError):
        load_config(agent_sk="0" * 64, control_relay="ws://r", server_pubkey="nope")


def test_http_serve_requires_explicit_agent_key():
    """M6: a network-facing process must never silently fall back to the
    operator key; the HTTP path fails closed without an explicit agent key."""
    with pytest.raises(ValueError, match="agent key"):
        load_config(require_agent_key=True)

    # Providing an explicit agent key satisfies the check.
    cfg = load_config(agent_sk="0" * 63 + "1", control_relay="ws://r", require_agent_key=True)
    assert len(cfg.agent_pubkey) == 64
