"""Tests for the registry -> MCP tool generation layer."""

from __future__ import annotations

from nostrhost_mcp.registry import catalog_by_name, local_helper_tools, tool_meta

FAKE_CATALOG = [
    {
        "name": "system.status",
        "scope": "server.read",
        "require_approval": False,
        "risk": "low",
        "reversibility": "reversible",
        "description": "read-only host snapshot",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "app.install",
        "scope": "apps.install",
        "require_approval": True,
        "risk": "high",
        "reversibility": "partial",
        "description": "install one app",
        "input_schema": {
            "type": "object",
            "properties": {"app": {"type": "string"}},
            "required": ["app"],
        },
    },
]


def test_catalog_by_name_indexes_entries():
    by_name = catalog_by_name(FAKE_CATALOG)
    assert set(by_name) == {"system.status", "app.install"}
    assert by_name["app.install"]["require_approval"] is True


def test_tool_meta_preserves_schema_and_description():
    meta = tool_meta(FAKE_CATALOG[1])
    assert meta["name"] == "app.install"
    assert meta["description"] == "install one app"
    assert meta["input_schema"]["required"] == ["app"]


def test_tool_meta_defaults_schema_when_missing():
    meta = tool_meta({"name": "x", "description": "y", "require_approval": True})
    assert meta["input_schema"] == {"type": "object", "properties": {}}


def test_local_helper_tools_expose_op_status():
    helpers = local_helper_tools()
    names = {h["name"] for h in helpers}
    assert "op_status" in names
    status = next(h for h in helpers if h["name"] == "op_status")
    assert "operation_id" in status["input_schema"]["required"]
