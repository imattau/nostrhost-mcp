"""Operation registry bridge: the fork's registry is the single source of
truth, and this module turns its catalogue into MCP tool metadata.

The fork exposes a versioned ``operation_catalog()`` document containing the
canonical input/output schemas, scopes, approval floor and safety metadata.
Generated MCP tools, Admin forms and API docs all derive from that document.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from typing import Any


def ensure_yunohost() -> None:
    """Make the fork's package importable.

    On a NostrHost node the fork is installed as a real ``yunohost`` package.
    For development the fork lives as a flat ``src/`` tree; when
    ``NOSTRHOST_FORK_SRC`` points at it, alias ``yunohost`` to that directory
    (the same alias the fork's own test conftest applies).
    """
    try:
        import yunohost  # noqa: F401
    except ImportError:
        src = os.environ.get("NOSTRHOST_FORK_SRC")
        if src and Path(src).is_dir():
            pkg = types.ModuleType("yunohost")
            pkg.__path__ = [str(Path(src))]  # type: ignore[attr-defined]
            sys.modules.setdefault("yunohost", pkg)


def load_catalog() -> dict[str, Any]:
    """The versioned operation catalogue from the installed fork."""
    ensure_yunohost()
    from yunohost.nostr_operations import operation_catalog

    document = operation_catalog()
    if not isinstance(document, dict) or document.get("schema_version") != 2:
        raise RuntimeError("NostrHost operation catalogue v2 is required")
    if not isinstance(document.get("operations"), list) or not isinstance(document.get("digest"), str):
        raise RuntimeError("NostrHost operation catalogue v2 is malformed")
    return document


def catalog_by_name(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["name"]: entry for entry in catalog["operations"]}


def tool_meta(entry: dict[str, Any]) -> dict[str, Any]:
    """MCP ``Tool``-style metadata for one catalogue entry."""
    return {
        "name": entry["name"],
        "description": entry["description"],
        "input_schema": entry.get("input_schema") or {"type": "object", "properties": {}},
        "output_schema": entry["result_schema"],
        "approval_minimum": entry.get("approval", {}).get("minimum", "none"),
    }


def local_helper_tools() -> list[dict[str, Any]]:
    """Adapter-local helper tools (not registry operations).

    These assist result translation (the layer the adapter keeps, per
    docs/MCP-TRANSITION.md §2) — e.g. polling an in-flight operation that is
    awaiting approval. They never carry authority themselves.
    """
    return [
        {
            "name": "op_status",
            "description": "poll the live state of a submitted operation (REQUESTED/APPROVED/EXECUTING/SUCCEEDED/FAILED); returns the result when terminal",
            "input_schema": {
                "type": "object",
                "properties": {"operation_id": {"type": "string", "description": "the 64-hex kind-2200 request event id", "minLength": 64, "maxLength": 64}},
                "required": ["operation_id"],
            },
        },
        {
            "name": "mcp_status",
            "description": "adapter self-check: whether this endpoint is reachable and which identity (if any) this call is recognised as — answered locally, no operation submitted",
            "input_schema": {"type": "object", "properties": {}},
        },
    ]
