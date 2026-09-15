"""Shared lazy-import redaction helper.

``nostrhost_policy`` is an optional sibling package: on a host where it is
not installed (e.g. local development, `--list-tools`), redaction is a
no-op rather than a hard dependency. Every module that needs to redact
secret-shaped values before they reach an MCP client goes through this one
helper instead of re-implementing the try/except import.
"""

from __future__ import annotations

from typing import Any


def redact(value: Any) -> Any:
    """Redact secret-shaped values, or return ``value`` unchanged if the
    ``nostrhost_policy`` redaction package is not installed."""
    try:
        from nostrhost_policy.redaction import redact as _redact
    except ImportError:
        return value
    return _redact(value)
