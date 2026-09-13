"""Tests for the MCP server over a fake operation client."""

from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from nostrhost_mcp.config import Config
from nostrhost_mcp.server import NostrHostServer, actor_context

from .test_registry import FAKE_CATALOG

REQ_ID = "a" * 64


class FakeContext:
    def __init__(self):
        self.progress = []

    async def report_progress(self, progress, total):
        self.progress.append((progress, total))


class FakeClient:
    def __init__(self, streams=None):
        self.submits = []
        self.streams = streams or {}

    def submit(self, name, arguments, actor_pubkey=None):
        self.submits.append((name, arguments, actor_pubkey))
        return {"_nostr": {"request_id": REQ_ID, "kind": 2200}}

    def events(self, request_id):
        return iter(self.streams.get(request_id, []))

    def verify_result_event(self, event):
        return True

    def parse_result_event(self, event):
        body = json.loads(event["content"])
        return body

    def parse_progress_event(self, event):
        return json.loads(event["content"])


def _config() -> Config:
    return Config(
        agent_sk="b" * 64,
        agent_pubkey="c" * 64,
        control_relay="ws://127.0.0.1:4848",
    )


def _stream(started=True, progress=None, result=None):
    events = []
    if started:
        events.append({"kind": 2203, "id": "1" * 64, "pubkey": "d" * 64, "sig": "e" * 128, "content": ""})
    if progress:
        events.append({"kind": 2205, "id": "2" * 64, "pubkey": "d" * 64, "sig": "e" * 128, "content": json.dumps(progress)})
    if result:
        events.append({"kind": 2204, "id": "3" * 64, "pubkey": "d" * 64, "sig": "e" * 128, "content": json.dumps(result)})
    return events


@pytest.mark.asyncio
async def test_list_tools_includes_catalog_and_helpers():
    server = NostrHostServer(FakeClient(), _config(), catalog=FAKE_CATALOG)
    tools = await server.list_tools()
    names = [t.name for t in tools]
    assert "system.status" in names
    assert "app.install" in names
    assert "op_status" in names
    assert "mcp_status" in names
    assert len(names) == len(FAKE_CATALOG) + 2


@pytest.mark.asyncio
async def test_read_tool_streams_to_terminal_result():
    client = FakeClient(
        streams={
            REQ_ID: _stream(
                progress={"stage": "executing", "progress": 0.5},
                result={"ok": True, "result": {"hostname": "nh"}},
            )
        }
    )
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    ctx = FakeContext()
    result = await server.call_tool("system.status", {}, context=ctx)
    assert client.submits == [("system.status", {}, None)]
    body = json.loads(result.content[0].text)
    assert body["operation_id"] == REQ_ID
    assert body["ok"] is True
    assert body["result"] == {"hostname": "nh"}
    assert ctx.progress == [(0.5, 1.0)]


@pytest.mark.asyncio
async def test_write_tool_returns_approval_required_immediately():
    client = FakeClient()
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    result = await server.call_tool("app.install", {"app": "foo"})
    assert client.submits == [("app.install", {"app": "foo"}, None)]
    body = json.loads(result.content[0].text)
    assert body["status"] == "approval_required"
    assert body["operation_id"] == REQ_ID
    assert body["tool"] == "app.install"
    assert body["risk"] == "high"


@pytest.mark.asyncio
async def test_actor_is_passed_to_submit():
    client = FakeClient(streams={REQ_ID: _stream(result={"ok": True, "result": {}})})
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    token = actor_context.set("f" * 64)
    try:
        await server.call_tool("system.status", {}, context=FakeContext())
    finally:
        actor_context.reset(token)
    assert client.submits[0][2] == "f" * 64


@pytest.mark.asyncio
async def test_mcp_status_is_unbound_when_no_actor_configured():
    client = FakeClient()
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    result = await server.call_tool("mcp_status", {})
    body = json.loads(result.content[0].text)
    assert body["server"] == "nostrhost-mcp"
    assert body["tools_available"] == len(FAKE_CATALOG) + 2
    assert body["control_relay"] == "ws://127.0.0.1:4848"
    assert body["actor"] is None
    assert body["actor_source"] == "unbound"
    assert client.submits == []  # answered locally, no operation submitted


@pytest.mark.asyncio
async def test_mcp_status_reports_configured_actor():
    config = Config(agent_sk="b" * 64, agent_pubkey="c" * 64, control_relay="ws://127.0.0.1:4848", actor_pubkey="1" * 64)
    server = NostrHostServer(FakeClient(), config, catalog=FAKE_CATALOG)
    result = await server.call_tool("mcp_status", {})
    body = json.loads(result.content[0].text)
    assert body["actor"] == "1" * 64
    assert body["actor_source"] == "configured"


@pytest.mark.asyncio
async def test_mcp_status_prefers_nip98_actor_over_configured():
    config = Config(agent_sk="b" * 64, agent_pubkey="c" * 64, control_relay="ws://127.0.0.1:4848", actor_pubkey="1" * 64)
    server = NostrHostServer(FakeClient(), config, catalog=FAKE_CATALOG)
    token = actor_context.set("f" * 64)
    try:
        result = await server.call_tool("mcp_status", {})
    finally:
        actor_context.reset(token)
    body = json.loads(result.content[0].text)
    assert body["actor"] == "f" * 64
    assert body["actor_source"] == "nip98"


@pytest.mark.asyncio
async def test_unknown_tool_raises_tool_error():
    server = NostrHostServer(FakeClient(), _config(), catalog=FAKE_CATALOG)
    with pytest.raises(ToolError):
        await server.call_tool("definitely.not", {})


@pytest.mark.asyncio
async def test_op_status_returns_terminal_result():
    client = FakeClient(streams={REQ_ID: _stream(result={"ok": False, "error": "boom"})})
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    result = await server.call_tool("op_status", {"operation_id": REQ_ID})
    body = json.loads(result.content[0].text)
    assert body["phase"] == "FAILED"
    assert body["error"] == "boom"


@pytest.mark.asyncio
async def test_op_status_rejects_bad_id():
    server = NostrHostServer(FakeClient(), _config(), catalog=FAKE_CATALOG)
    with pytest.raises(ToolError):
        await server.call_tool("op_status", {"operation_id": "short"})


@pytest.mark.asyncio
async def test_op_status_surfaces_rejection():
    client = FakeClient(
        streams={
            REQ_ID: [
                {"kind": 2202, "id": "1" * 64, "pubkey": "d" * 64, "sig": "e" * 128, "content": json.dumps({"reason": "not today"})}
            ]
        }
    )
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    result = await server.call_tool("op_status", {"operation_id": REQ_ID})
    body = json.loads(result.content[0].text)
    assert body["phase"] == "REJECTED"
    assert body["reason"] == "not today"


@pytest.mark.asyncio
async def test_read_tool_timeout_returns_pending():
    client = FakeClient(streams={REQ_ID: []})
    server = NostrHostServer(client, _config(), catalog=FAKE_CATALOG)
    result = await server.call_tool("system.status", {}, context=FakeContext())
    body = json.loads(result.content[0].text)
    assert body["status"] == "pending"
    assert body["ok"] is False
