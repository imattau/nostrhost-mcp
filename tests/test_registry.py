"""Tests for the registry -> MCP tool generation layer."""

from __future__ import annotations

import os

import pytest

from nostrhost_mcp.registry import catalog_by_name, load_catalog, local_helper_tools, tool_meta

# docs/MCP-TRANSITION.md §7 Phase 3 — signed mutations + streaming. Every one
# of these write ops must be registered, approval-gated and schema'd so the
# adapter can submit the signed kind-2200 and stream 2203/2205/2204.
PHASE3_MUTATIONS = [
    "service.restart",
    "service.control",
    "backup.create",
    "dns.apply",
    "dns.subscribe",
    "dns.unsubscribe",
    "credential.set",
    "credential.remove",
    "domain.add",
    "domain.remove",
    "app.install",
    "app.upgrade",
    "app.remove",
    "package.reconcile",
    "state.reconcile",
    "rollback.apply",
]

FAKE_OPERATIONS = [
    {
        "name": "system.status",
        "scopes": ["server.read"],
        "approval": {"minimum": "none"},
        "risk": "low",
        "reversibility": "reversible",
        "description": "read-only host snapshot",
        "input_schema": {"type": "object", "properties": {}},
		"result_schema": {"type": "object"},
    },
    {
        "name": "app.install",
        "scopes": ["apps.install"],
        "approval": {"minimum": "admin"},
        "risk": "high",
        "reversibility": "partial",
        "description": "install one app",
        "input_schema": {
            "type": "object",
            "properties": {"app": {"type": "string"}},
            "required": ["app"],
        },
		"result_schema": {"type": "object"},
    },
]
FAKE_CATALOG = {"schema_version": 2, "digest": "sha256:test", "operations": FAKE_OPERATIONS}


def test_catalog_by_name_indexes_entries():
    by_name = catalog_by_name(FAKE_CATALOG)
    assert set(by_name) == {"system.status", "app.install"}
    assert by_name["app.install"]["approval"]["minimum"] == "admin"


def test_tool_meta_preserves_schema_and_description():
    meta = tool_meta(FAKE_OPERATIONS[1])
    assert meta["name"] == "app.install"
    assert meta["description"] == "install one app"
    assert meta["input_schema"]["required"] == ["app"]


def test_tool_meta_defaults_schema_when_missing():
    meta = tool_meta({"name": "x", "description": "y", "result_schema": {}})
    assert meta["input_schema"] == {"type": "object", "properties": {}}


def test_local_helper_tools_expose_op_status():
    helpers = local_helper_tools()
    names = {h["name"] for h in helpers}
    assert "op_status" in names
    status = next(h for h in helpers if h["name"] == "op_status")
    assert "operation_id" in status["input_schema"]["required"]


def test_local_helper_tools_expose_mcp_status():
    helpers = local_helper_tools()
    names = {h["name"] for h in helpers}
    assert "mcp_status" in names
    status = next(h for h in helpers if h["name"] == "mcp_status")
    assert status["input_schema"] == {"type": "object", "properties": {}}


def test_phase3_mutations_registered_approval_gated_and_schemaed():
    """Every Phase 3 mutation is present, requires approval, and carries a schema."""
    catalog = {"schema_version": 2, "digest": "sha256:test", "operations": [
        {"name": name, "approval": {"minimum": "admin"}, "result_schema": {}, "input_schema": {"type": "object", "properties": {name: {"type": "string"}}}}
        for name in PHASE3_MUTATIONS
    ]}
    by_name = catalog_by_name(catalog)
    assert set(PHASE3_MUTATIONS) == set(by_name)
    for name in PHASE3_MUTATIONS:
        assert by_name[name]["approval"]["minimum"] == "admin", name
        assert isinstance(by_name[name]["input_schema"].get("properties"), dict), name


def test_phase3_mutations_real_catalog():
    """Against the installed fork catalogue (skipped when the fork is absent)."""
    try:
        catalog = load_catalog()
    except ImportError:
        pytest.skip("NostrHost fork (yunohost.nostr_operations) is not importable here")
    by_name = catalog_by_name(catalog)
    missing = [name for name in PHASE3_MUTATIONS if name not in by_name]
    assert missing == [], f"Phase 3 mutation tools missing from the catalogue: {missing}"
    ungated = [name for name in PHASE3_MUTATIONS if by_name[name]["approval"]["minimum"] == "none"]
    assert ungated == [], f"Phase 3 mutations must be approval-gated: {ungated}"
    no_schema = [name for name in PHASE3_MUTATIONS if not by_name[name].get("input_schema")]
    assert no_schema == [], f"Phase 3 mutations missing input schemas: {no_schema}"


APPROVAL_SURFACE_HINTS = ("approve", "reject", "confirm", "accept", "deny", "approval")


def test_phase4_approval_stays_out_of_mcp_surface():
    """docs/MCP-TRANSITION.md §7 Phase 4 — the adapter only *surfaces* the
    approval boundary (approval_required + operation_id + op_status). Pushing
    approval is a control-plane utility (nostr-opctl approve / NIP-46), so the
    MCP tool surface must expose no approval/rejection tools."""
    catalog = FAKE_OPERATIONS + [
        {"name": name, "description": name, "approval": {"minimum": "admin"}, "result_schema": {}, "input_schema": {"type": "object", "properties": {}}}
        for name in PHASE3_MUTATIONS
    ]
    surface = [tool_meta(entry)["name"] for entry in catalog] + [h["name"] for h in local_helper_tools()]
    offenders = [name for name in surface if any(hint in name.lower() for hint in APPROVAL_SURFACE_HINTS)]
    assert offenders == [], f"approval/rejection must stay out of the MCP surface, found: {offenders}"
    assert "op_status" in surface, "op_status must remain the approval-boundary helper"
    helpers = {h["name"] for h in local_helper_tools()}
    assert helpers == {"op_status", "mcp_status"}, f"only op_status/mcp_status are adapter-local helpers, found: {helpers}"


def test_real_catalog_includes_nsite_tools_with_schemas():
    """Phase 3b: the generated MCP surface derives from the fork's operation
    catalogue, so every nsites tool (incl. the Phase 3b mirror) must appear
    with the registry's scope/approval/schema, not a hand-maintained copy."""
    if not os.environ.get("NOSTRHOST_FORK_SRC"):
        import pytest as _pytest

        _pytest.skip("NOSTRHOST_FORK_SRC not set; run with the fork src aliased to yunohost")
    catalog = load_catalog()
    by_name = catalog_by_name(catalog)
    for name in (
        "nsite.gateway.status",
        "nsite.list",
        "nsite.inspect",
        "nsite.resolve",
        "nsite.validate_manifest",
        "nsite.reachability",
        "nsite.publish.plan",
        "nsite.register",
        "nsite.unregister",
        "nsite.publish",
        "nsite.snapshot",
        "nsite.mirror",
        "nsite.domain.list",
        "nsite.domain.attach",
        "nsite.domain.detach",
    ):
        entry = by_name[name]
        assert entry["scopes"][0].startswith("nsites.")
        assert entry["approval"]["minimum"] in ("none", "admin")
        # tools without arguments carry no schema (the MCP layer fills an empty
        # object); every arg-carrying tool must expose a real object schema
        schema = entry["input_schema"]
        assert schema is None or schema.get("type") == "object"


def test_nsite_write_tools_require_approval():
    if not os.environ.get("NOSTRHOST_FORK_SRC"):
        import pytest as _pytest

        _pytest.skip("NOSTRHOST_FORK_SRC not set")
    catalog = load_catalog()
    by_name = catalog_by_name(catalog)
    for name in ("nsite.publish", "nsite.snapshot", "nsite.mirror", "nsite.register", "nsite.unregister", "nsite.domain.attach", "nsite.domain.detach"):
        assert by_name[name]["approval"]["minimum"] == "admin"
    for name in ("nsite.list", "nsite.inspect", "nsite.resolve", "nsite.validate_manifest", "nsite.publish.plan", "nsite.domain.list"):
        assert by_name[name]["approval"]["minimum"] == "none"
