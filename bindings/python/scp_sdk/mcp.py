"""MCP (Model Context Protocol) adapter for SCP.

Wraps the Rust ``scp-mcp`` crate via the ``_scp_core`` PyO3 bridge layer,
providing:

- :func:`serve_mcp` -- starts an MCP server that dynamically exposes tools
  from the agent's active SCP contexts.
- :class:`McpClient` -- connects to external MCP servers and wraps tool
  results with SCP provenance metadata.

Transport parameter accepts ``"stdio"`` (line-delimited JSON over
stdin/stdout) or ``"sse"`` (HTTP with Server-Sent Events).

See ``.docs/adrs/phase-3.md`` ADR-015 for the full design.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import TransportError, ValidationError

if TYPE_CHECKING:
    from scp_sdk.context import Context
    from scp_sdk.identity import Identity

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
# Lazy bridge import
# ---------------------------------------------------------------------------


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise TransportError(
            "The _scp_core extension module is not installed. "
            "Install scp-sdk with: pip install scp-sdk",
            code="SCP-MCP-8001",
        ) from exc


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
# McpServer
# ---------------------------------------------------------------------------


class McpServer:
    """An MCP server that exposes SCP context tools to MCP-compatible models.

    Created by :func:`serve_mcp`.  The server dynamically exposes tools
    from the agent's active SCP contexts, namespaced by context ID
    (e.g. ``context_a/send_message``).

    Tools are capability-filtered: only tools the agent's role permits
    are listed.  Built-in tools per context include ``send_message``,
    ``read_messages``, and ``list_members``.
    """

    __slots__ = ("_contexts", "_handle", "_identity", "_transport")

    def __init__(
        self,
        handle: Any,
        identity: Identity,
        contexts: list[Context],
        transport: str,
    ) -> None:
        self._handle = handle
        self._identity = identity
        self._contexts = list(contexts)
        self._transport = transport

    @property
    def transport(self) -> str:
        """The transport mode (``"stdio"`` or ``"sse"``)."""
        return self._transport

    @property
    def contexts(self) -> list[Context]:
        """The active SCP contexts being served."""
        return list(self._contexts)

    async def stop(self) -> None:
        """Stop the MCP server gracefully.

        Raises:
            TransportError: If shutdown fails.
        """
        logger.info("Stopping MCP server (transport=%s)", self._transport)
        bridge = _bridge()
        bridge.py_mcp_server_stop(self._handle)
        logger.debug("MCP server stopped")

    def __repr__(self) -> str:
        ctx_ids = [c.context_id for c in self._contexts]
        return f"McpServer(transport={self._transport!r}, contexts={ctx_ids!r})"


# ---------------------------------------------------------------------------
# serve_mcp
# ---------------------------------------------------------------------------


async def serve_mcp(
    identity: Identity,
    contexts: list[Context],
    transport: str = "stdio",
) -> McpServer:
    """Start an MCP server that exposes SCP context tools.

    The server dynamically exposes tools from the agent's active SCP
    contexts.  Tools are namespaced by context ID (e.g.
    ``context_a/send_message``).  Only tools the agent's role permits
    are listed (capability filtering).

    Args:
        identity: The SCP identity running the server.
        contexts: List of active SCP contexts to expose.
        transport: Transport mode -- ``"stdio"`` (default) for
            line-delimited JSON over stdin/stdout, or ``"sse"`` for
            HTTP with Server-Sent Events.

    Returns:
        An :class:`McpServer` instance.

    Raises:
        ValidationError: If *transport* is not ``"stdio"`` or ``"sse"``.
        TransportError: If the server fails to start.

    Example::

        from scp_sdk.mcp import serve_mcp

        server = await serve_mcp(
            identity=my_identity,
            contexts=[context_a, context_b],
            transport="stdio",
        )
    """
    if transport not in _VALID_TRANSPORTS:
        raise ValidationError(
            f"transport must be 'stdio' or 'sse', got {transport!r}",
            code="SCP-MCP-8002",
        )

    if not contexts:
        raise ValidationError(
            "at least one context is required",
            code="SCP-MCP-8003",
        )

    logger.info(
        "Starting MCP server: identity=%s, contexts=%d, transport=%s",
        identity.did,
        len(contexts),
        transport,
    )

    bridge = _bridge()

    context_ids = [c.context_id for c in contexts]
    handle = bridge.py_mcp_serve(
        identity.did,
        context_ids,
        transport,
    )

    server = McpServer(
        handle=handle,
        identity=identity,
        contexts=contexts,
        transport=transport,
    )

    logger.info("MCP server started (transport=%s)", transport)
    return server


# ---------------------------------------------------------------------------
# McpClient
# ---------------------------------------------------------------------------


def configure_stdio_allowlist(
    *,
    additional_binaries: list[str] | None = None,
) -> None:
    """Add binary names to the stdio subprocess allowlist.

    By default, only well-known MCP server launchers are permitted
    (see :data:`DEFAULT_STDIO_ALLOWLIST`). Call this to extend the list
    with custom binary names.

    This is additive — previously added binaries are retained. To reset
    to defaults, use :func:`reset_stdio_allowlist`.

    Args:
        additional_binaries: Bare binary names to add (e.g.
            ``["my-custom-server"]``). Path separators, empty strings,
            and NUL bytes are rejected.

    Raises:
        ValidationError: If any entry contains path separators, NUL
            bytes, or is empty.

    Example::

        from scp_sdk.mcp import configure_stdio_allowlist

        configure_stdio_allowlist(additional_binaries=["my-custom-server"])
    """
    if not additional_binaries:
        return

    bridge = _bridge()
    bridge.py_mcp_configure_stdio_allowlist(additional_binaries)


def disable_stdio_allowlist(
    *,
    i_trust_all_commands: bool = False,
) -> None:
    """Disable the stdio allowlist entirely (unrestricted mode).

    After calling this, **any** binary can be spawned as a subprocess.
    Only use when the command source is fully trusted.

    Args:
        i_trust_all_commands: Must be ``True`` to confirm the security
            bypass. Raises ``ValidationError`` if ``False``.

    Raises:
        ValidationError: If *i_trust_all_commands* is not ``True``.

    Example::

        from scp_sdk.mcp import disable_stdio_allowlist

        disable_stdio_allowlist(i_trust_all_commands=True)
    """
    if not i_trust_all_commands:
        raise ValidationError(
            "You must pass i_trust_all_commands=True to disable the "
            "stdio allowlist. This allows arbitrary command execution.",
            code="SCP-MCP-8007",
        )

    logger.warning(
        "MCP stdio allowlist DISABLED — arbitrary commands will be "
        "permitted. Only use this when the command source is fully "
        "trusted."
    )

    bridge = _bridge()
    bridge.py_mcp_disable_stdio_allowlist()


def reset_stdio_allowlist() -> None:
    """Reset the stdio allowlist to its default state.

    Restores the default binaries, removes any additions, and
    re-enables allowlist enforcement (clears unrestricted mode).

    Example::

        from scp_sdk.mcp import reset_stdio_allowlist

        reset_stdio_allowlist()
    """
    bridge = _bridge()
    bridge.py_mcp_reset_stdio_allowlist()
    logger.info("MCP stdio allowlist reset to defaults")


def get_stdio_allowlist() -> dict[str, Any]:
    """Return the current stdio allowlist state.

    Returns:
        A dict with keys:

        - ``"allowed"``: sorted list of allowed binary names
        - ``"unrestricted"``: ``True`` if the allowlist is bypassed

    Example::

        from scp_sdk.mcp import get_stdio_allowlist

        state = get_stdio_allowlist()
        print(state["allowed"])       # ['bun', 'bunx', 'deno', ...]
        print(state["unrestricted"])  # False
    """
    bridge = _bridge()
    return bridge.py_mcp_get_stdio_allowlist()


class McpClient:
    """Client for consuming external MCP servers with SCP provenance wrapping.

    Connects to external MCP servers via stdio or SSE, lists their tools,
    and invokes them with SCP provenance metadata attached to every result.

    Use :meth:`connect` to create an instance.

    Example::

        from scp_sdk.mcp import McpClient

        client = await McpClient.connect("stdio", command=["uvx", "some-mcp-server"])
        tools = await client.list_tools()
        result = await client.invoke(
            tool="external_tool",
            input={"key": "value"},
            context=my_context,
            identity=my_identity,
        )
    """

    __slots__ = ("_command", "_handle", "_transport")

    def __init__(self, handle: Any, transport: str, command: list[str] | None) -> None:
        self._handle = handle
        self._transport = transport
        self._command = command

    @classmethod
    async def connect(
        cls,
        transport: str,
        *,
        command: list[str] | None = None,
        url: str | None = None,
    ) -> McpClient:
        """Connect to an external MCP server.

        Args:
            transport: Transport mode -- ``"stdio"`` to spawn a subprocess,
                or ``"sse"`` to connect via HTTP/SSE.
            command: For ``"stdio"`` transport, the command and arguments to
                spawn (e.g. ``["uvx", "some-mcp-server"]``). The first
                element must be a bare binary name in the stdio allowlist
                (see :func:`configure_stdio_allowlist`).
            url: For ``"sse"`` transport, the URL of the SSE endpoint.

        Returns:
            A connected :class:`McpClient` instance.

        Raises:
            ValidationError: If transport is invalid, required parameters
                are missing, or the command is not in the stdio allowlist.
            TransportError: If the connection fails.

        Example::

            client = await McpClient.connect(
                "stdio",
                command=["uvx", "some-mcp-server"],
            )
        """
        if transport not in _VALID_TRANSPORTS:
            raise ValidationError(
                f"transport must be 'stdio' or 'sse', got {transport!r}",
                code="SCP-MCP-8002",
            )

        if transport == "stdio" and not command:
            raise ValidationError(
                "command is required for stdio transport",
                code="SCP-MCP-8004",
            )

        if transport == "sse" and not url:
            raise ValidationError(
                "url is required for sse transport",
                code="SCP-MCP-8005",
            )

        # Pre-validate the command binary against the allowlist before
        # crossing the FFI boundary. This gives a Python-native error with
        # actionable guidance.
        if transport == "stdio" and command:
            import os

            binary = command[0]
            basename = os.path.basename(binary)

            if binary != basename:
                raise ValidationError(
                    f"command must be a bare binary name, not a path: "
                    f"'{binary}'. The OS will resolve it via PATH.",
                    code="SCP-MCP-8006",
                )

            state = get_stdio_allowlist()
            if not state["unrestricted"] and basename not in state["allowed"]:
                allowed = sorted(state["allowed"])
                raise ValidationError(
                    f"command '{basename}' is not in the MCP stdio allowlist. "
                    f"Allowed: {allowed}. "
                    f"Call configure_stdio_allowlist("
                    f"additional_binaries=['{basename}']) first.",
                    code="SCP-MCP-8006",
                )

        logger.info(
            "Connecting MCP client: transport=%s, command=%s, url=%s",
            transport,
            command,
            url,
        )

        bridge = _bridge()

        if transport == "stdio":
            handle = bridge.py_mcp_client_connect_stdio(command)
        else:
            handle = bridge.py_mcp_client_connect_sse(url)

        client = cls(handle=handle, transport=transport, command=command)
        logger.info("MCP client connected (transport=%s)", transport)
        return client

    async def list_tools(self) -> list[McpToolDefinition]:
        """List available tools from the external MCP server.

        Returns:
            A list of :class:`McpToolDefinition` objects.

        Raises:
            TransportError: If the server communication fails.
        """
        bridge = _bridge()
        raw_tools = bridge.py_mcp_client_list_tools(self._handle)
        return [
            McpToolDefinition(
                name=t["name"],
                description=t.get("description"),
                input_schema=t.get("inputSchema", {}),
            )
            for t in raw_tools
        ]

    async def invoke(
        self,
        tool: str,
        input: dict[str, Any],
        context: Context,
        identity: Identity,
    ) -> McpToolResult:
        """Invoke an external tool with SCP provenance wrapping.

        Calls the external MCP tool and wraps the result with provenance
        metadata recording the source tool, invoking agent, context, and
        timestamp.

        Args:
            tool: The name of the external tool to invoke.
            input: The tool's input arguments.
            context: The SCP context for provenance tracking.
            identity: The SCP identity for signing / provenance.

        Returns:
            An :class:`McpToolResult` with content and provenance.

        Raises:
            ToolError: If the tool invocation fails.
            TransportError: If server communication fails.
        """
        bridge = _bridge()
        raw = bridge.py_mcp_client_invoke(
            self._handle,
            tool,
            input,
            context.context_id,
            identity.did,
        )

        provenance = McpProvenance(
            source=raw["provenance"]["source"],
            invoked_by=raw["provenance"]["invoked_by"],
            context=raw["provenance"]["context"],
            timestamp=raw["provenance"]["timestamp"],
        )

        return McpToolResult(
            content=raw.get("content", []),
            is_error=raw.get("is_error", False),
            provenance=provenance,
        )

    async def disconnect(self) -> None:
        """Disconnect from the external MCP server.

        Raises:
            TransportError: If disconnection fails.
        """
        logger.info("Disconnecting MCP client (transport=%s)", self._transport)
        bridge = _bridge()
        bridge.py_mcp_client_disconnect(self._handle)
        logger.debug("MCP client disconnected")

    def __repr__(self) -> str:
        return f"McpClient(transport={self._transport!r}, command={self._command!r})"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def cli_main() -> None:
    """CLI entry point for ``scp-mcp serve``.

    Parses command-line arguments and starts an MCP server for a given
    SCP identity.  Suitable for integration with MCP hosts that launch
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
    and starts the MCP server.

    Args:
        did: The DID string of the identity to serve.
        relay_url: The relay URL to connect to.
        transport: The MCP transport mode (``"stdio"`` or ``"sse"``).
    """
    from scp_sdk.identity import Identity
    from scp_sdk.transport import connect_relay

    logger.info(
        "scp-mcp serve: identity=%s, relay=%s, transport=%s",
        did,
        relay_url,
        transport,
    )

    # Step 1: Load the identity.
    await Identity.load(did)

    # Step 2: Connect to the relay.
    await connect_relay(relay_url)

    # Step 3: Load active contexts via the bridge.
    bridge = _bridge()
    context_handles = bridge.py_mcp_load_contexts(did, relay_url)

    # Step 4: Start the MCP server.
    context_ids = [h["context_id"] for h in context_handles]
    handle = bridge.py_mcp_serve(did, context_ids, transport)

    logger.info(
        "MCP server running: %d contexts, transport=%s",
        len(context_ids),
        transport,
    )

    # Block until the server exits (stdin EOF for stdio, signal for SSE).
    await _wait_for_shutdown(handle, transport)


async def _wait_for_shutdown(handle: Any, transport: str) -> None:
    """Wait for the MCP server to shut down.

    For stdio transport, waits until stdin is closed (EOF).
    For SSE transport, waits until a termination signal is received.
    """
    import asyncio

    bridge = _bridge()
    try:
        # The bridge provides a blocking wait that we run in a thread
        # to avoid blocking the asyncio event loop.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, bridge.py_mcp_server_wait, handle)
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down MCP server")
        bridge.py_mcp_server_stop(handle)


__all__ = [
    "DEFAULT_STDIO_ALLOWLIST",
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "cli_main",
    "configure_stdio_allowlist",
    "disable_stdio_allowlist",
    "get_stdio_allowlist",
    "reset_stdio_allowlist",
    "serve_mcp",
]
