"""MCP (Model Context Protocol) adapter types for SCP.

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`McpServer` and
:class:`McpClient` into pure handle wrappers. Use
:meth:`scp_sdk.SCP.mcp_serve` to start a server and
:meth:`scp_sdk.SCP.mcp_client_connect_stdio` /
:meth:`scp_sdk.SCP.mcp_client_connect_sse` to connect a client. Every
subsequent operation (``list_tools``, ``invoke``, ``stop``,
``disconnect``, etc.) lives on :class:`scp_sdk.SCP`.

Per-instance migration moved the stdio allowlist onto each :class:`SCP` instance.
Use :meth:`scp_sdk.SCP.mcp_configure_stdio_allowlist`,
:meth:`scp_sdk.SCP.mcp_disable_stdio_allowlist`,
:meth:`scp_sdk.SCP.mcp_reset_stdio_allowlist`, and
:meth:`scp_sdk.SCP.mcp_get_stdio_allowlist` — the previous module-level
free functions were deleted because they implied a process-global state
that no longer exists.

See ``.docs/adrs/phase-3.md`` ADR-015 for the full design, ADR-048 for
the façade consolidation rationale, and ADR-048 §1 for the per-instance
multi-instance neutrality requirement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ValidationError

if TYPE_CHECKING:
    from scp_sdk.scp import McpAllowlistState

logger = logging.getLogger("scp_sdk")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Supported MCP transport modes.
_VALID_TRANSPORTS: frozenset[str] = frozenset({"stdio", "sse"})

#: Default allowlist of MCP server binaries for stdio transport.
#: Matches the Rust-side ``DEFAULT_ALLOWLIST`` in ``scp-mcp/src/allowlist.rs``.
#: The Rust layer is the single source of truth; use
#: :func:`get_stdio_allowlist` to query the live state at runtime.
DEFAULT_STDIO_ALLOWLIST: frozenset[str] = frozenset(
    {
        "uvx",
        "npx",
        "bunx",
        "pipx",
        "python",
        "python3",
        "node",
        "bun",
        "deno",
        "docker",
        "podman",
        "scp-mcp",
    }
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class McpToolDefinition:
    """An MCP tool definition as returned by an external MCP server.

    Represents a tool available for invocation, with its name, description,
    and JSON Schema for input parameters.
    """

    #: The tool name.
    name: str

    #: Human-readable description of the tool.
    description: str | None = None

    #: JSON Schema describing the tool's input parameters.
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class McpProvenance:
    """SCP provenance metadata for results from external MCP tool calls.

    Records the external tool source, the invoking agent's DID, the SCP
    context in which the invocation was made, and the timestamp.
    """

    #: The source of the tool result, formatted as ``"mcp:{tool_name}"``.
    source: str

    #: The DID of the agent that invoked the tool.
    invoked_by: str

    #: The SCP context ID in which the invocation was made.
    context: str

    #: The timestamp of the invocation (milliseconds since Unix epoch).
    timestamp: int


@dataclass
class McpToolResult:
    """The result of invoking an external MCP tool, wrapped with SCP provenance.

    Contains the tool output content, an error flag, and provenance metadata
    tracing the result to its source.
    """

    #: The tool output content (list of content items).
    content: list[dict[str, Any]]

    #: Whether the tool call resulted in an error.
    is_error: bool

    #: SCP provenance metadata.
    provenance: McpProvenance


# ---------------------------------------------------------------------------
# McpServer / McpClient — pure handle wrappers
# ---------------------------------------------------------------------------


class McpServer:
    """Opaque handle to a running MCP server.

    Construct via :meth:`scp_sdk.SCP.mcp_serve`. All lifecycle operations
    (``stop``, ``wait``, ``info``) live on :class:`scp_sdk.SCP` — pass
    ``server._raw_handle`` to invoke them.
    """

    __slots__ = ("_raw_handle",)

    def __init__(self, handle: Any) -> None:
        self._raw_handle = handle


class McpClient:
    """Opaque handle to a connected MCP client.

    Construct via :meth:`scp_sdk.SCP.mcp_client_connect_stdio` or
    :meth:`scp_sdk.SCP.mcp_client_connect_sse`. All operations
    (``list_tools``, ``invoke``, ``disconnect``, ``info``) live on
    :class:`scp_sdk.SCP` — pass ``client._raw_handle`` to invoke them.
    """

    __slots__ = ("_raw_handle",)

    def __init__(self, handle: Any) -> None:
        self._raw_handle = handle


# ---------------------------------------------------------------------------
# Pre-flight client-connect validation
#
# The stdio allowlist itself is per-instance state on the Rust bridge and
# accessed through :class:`scp_sdk.SCP` methods. This pure
# helper validates connect parameters and, when an instance allowlist
# snapshot is provided, performs a defense-in-depth membership check
# before crossing the FFI boundary.
# ---------------------------------------------------------------------------


def validate_client_connect(
    transport: str,
    *,
    command: list[str] | None = None,
    url: str | None = None,
    allowlist_state: McpAllowlistState | None = None,
) -> None:
    """Validate MCP client connect parameters before FFI dispatch.

    Raises :class:`~scp_sdk.errors.ValidationError` with a canonical
    error code when a parameter is missing or the stdio command shape is
    invalid (path, missing).

    When *allowlist_state* is supplied (typically the dict returned by
    :meth:`scp_sdk.SCP.mcp_get_stdio_allowlist`), the basename is also
    checked against ``allowlist_state["allowed"]`` unless
    ``allowlist_state["unrestricted"]`` is ``True``. Callers without an
    instance can omit *allowlist_state* — the bridge will still reject
    unlisted commands, but only after the FFI round-trip.
    """
    if transport not in _VALID_TRANSPORTS:
        raise ValidationError(
            f"transport must be 'stdio' or 'sse', got {transport!r}",
            code="SCP-MCP-10002",
        )

    if transport == "stdio" and not command:
        raise ValidationError(
            "command is required for stdio transport",
            code="SCP-MCP-10004",
        )

    if transport == "sse" and not url:
        raise ValidationError(
            "url is required for sse transport",
            code="SCP-MCP-10005",
        )

    if transport == "stdio" and command:
        import os

        binary = command[0]
        basename = os.path.basename(binary)

        if binary != basename:
            raise ValidationError(
                f"command must be a bare binary name, not a path: "
                f"'{binary}'. The OS will resolve it via PATH.",
                code="SCP-MCP-10006",
            )

        if allowlist_state is not None:
            if not allowlist_state.get(
                "unrestricted", False
            ) and basename not in allowlist_state.get("allowed", []):
                allowed = sorted(allowlist_state.get("allowed", []))
                raise ValidationError(
                    f"command '{basename}' is not in the MCP stdio allowlist. "
                    f"Allowed: {allowed}. "
                    f"Call scp.mcp_configure_stdio_allowlist("
                    f"['{basename}']) first.",
                    code="SCP-MCP-10006",
                )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def cli_main() -> None:
    """CLI entry point for ``scp-mcp serve``.

    Parses command-line arguments and starts an MCP server for a given
    SCP identity. Suitable for integration with MCP hosts that launch
    servers as subprocesses.

    Usage::

        scp-mcp serve --identity <did> --relay <relay_url> --transport stdio
    """
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        prog="scp-mcp",
        description="SCP MCP adapter -- expose SCP contexts as MCP tools",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Start an MCP server for a given SCP identity",
    )
    serve_parser.add_argument(
        "--identity",
        required=True,
        help="DID of the SCP identity to serve (e.g. did:dht:z6Mk...)",
    )
    serve_parser.add_argument(
        "--relay",
        required=True,
        help="URL of the SCP relay to connect to",
    )
    serve_parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport mode (default: stdio)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        asyncio.run(_cli_serve(args.identity, args.relay, args.transport))


async def _cli_serve(did: str, relay_url: str, transport: str) -> None:
    """Internal async implementation of the ``scp-mcp serve`` command.

    Loads the identity, connects to the relay, discovers active contexts,
    and starts the MCP server. Owns its own :class:`SCP` instance —
    CLI entry points always construct a fresh instance (ADR-048).
    """
    from scp_sdk.scp import SCP

    logger.info(
        "scp-mcp serve: identity=%s, relay=%s, transport=%s",
        did,
        relay_url,
        transport,
    )

    with SCP() as scp:
        # Step 1: Load the identity.
        await scp.identity_load(did)

        # Step 2: Connect to the relay.
        await scp.transport_connect(relay_url)

        # Step 3: Load active contexts via the bridge.
        context_handles = await scp.mcp_load_contexts(did, relay_url)

        # Step 4: Start the MCP server.
        context_ids = [h["context_id"] for h in context_handles]
        handle = await scp.mcp_serve(did, context_ids, transport)

        logger.info(
            "MCP server running: %d contexts, transport=%s",
            len(context_ids),
            transport,
        )

        # Block until the server exits (stdin EOF for stdio, signal for SSE).
        try:
            await scp.mcp_server_wait(handle)
        except KeyboardInterrupt:
            logger.info("Received interrupt, shutting down MCP server")
            await scp.mcp_server_stop(handle)


__all__ = [
    "DEFAULT_STDIO_ALLOWLIST",
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "cli_main",
    "validate_client_connect",
]
