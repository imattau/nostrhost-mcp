"""Tests for the operation client: signature verification, parsing, config."""

from __future__ import annotations

import json

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from nostrhost_mcp.client import OperationClientError, _verify_server_signature
from nostrhost_mcp.config import load_config


def test_verify_server_signature_accepts_authentic_event():
    sk = bytes.fromhex("0" * 63 + "1")
    priv = PrivateKey(sk)
    pk = PublicKeyXOnly.from_secret(sk).format().hex()
    event_id = bytes.fromhex("a" * 64)
    sig = priv.sign_schnorr(event_id)
    event = {
        "id": "a" * 64,
        "pubkey": pk,
        "sig": sig.hex(),
    }
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

    body = _Client.parse_result_event({"content": json.dumps({"ok": True, "result": {}})})
    assert body["ok"] is True
    with pytest.raises(OperationClientError):
        _Client.parse_result_event({"content": "not json"})
    with pytest.raises(OperationClientError):
        _Client.parse_result_event({"content": json.dumps([1, 2])})


def test_load_config_derives_pubkey_and_relay():
    sk = "0" * 63 + "1"
    cfg = load_config(agent_sk=sk, control_relay="ws://127.0.0.1:4848")
    assert len(cfg.agent_pubkey) == 64
    assert cfg.control_relay == "ws://127.0.0.1:4848"
    assert cfg.agent_sk == sk


def test_load_config_rejects_bad_key():
    with pytest.raises(ValueError):
        load_config(agent_sk="xyz", control_relay="ws://127.0.0.1:4848")


def test_load_config_rejects_bad_server_pubkey():
    with pytest.raises(ValueError):
        load_config(agent_sk="0" * 64, control_relay="ws://r", server_pubkey="nope")
