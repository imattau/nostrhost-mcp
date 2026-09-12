"""nostrhost-mcp — thin MCP protocol adapter over the NostrHost operation model.

MCP is an interface, not an authority boundary: this package owns the MCP
protocol, generated tool schemas, NIP-98 client authentication, result
redaction and transport, while all authority, policy, approval, execution and
state live in NostrHost itself (the installed fork + control plane).

See docs/MCP-TRANSITION.md in the umbrella repo for the full plan.
"""

__version__ = "0.1.0"
