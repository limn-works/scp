"""Tests for the SCP MCP adapter Python wrapper.

Covers:
- McpToolDefinition / McpProvenance / McpToolResult dataclass construction
- :meth:`SCP.mcp_client_connect_sse` / ``mcp_client_connect_stdio`` input
  validation (transport/command/url/allowlist)
- :func:`validate_client_connect` pure-Python pre-flight validation
- CLI entry point argument parsing
- Module-level ``__all__`` and package re-exports
- ``DEFAULT_STDIO_ALLOWLIST`` invariants
- Allowlist API (``configure_stdio_allowlist``, ``disable_stdio_allowlist``,
  ``reset_stdio_allowlist``, ``get_stdio_allowlist``)

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`McpServer` and
:class:`McpClient` into pure handle wrappers. :func:`serve_mcp` /
:meth:`McpClient.connect` / :meth:`McpServer.stop` etc. are now methods
on :class:`scp_sdk.SCP` — see :meth:`SCP.mcp_serve`,
:meth:`SCP.mcp_client_connect_stdio`, :meth:`SCP.mcp_client_connect_sse`,
and :meth:`SCP.mcp_server_stop`.

Tests mock the ``_native`` bridge where needed; no Rust extension required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.errors import ValidationError
from scp_sdk.mcp import (
    DEFAULT_STDIO_ALLOWLIST,
    McpClient,
    McpProvenance,
    McpServer,
    McpToolDefinition,
    McpToolResult,
    cli_main,
    configure_stdio_allowlist,
    disable_stdio_allowlist,
    get_stdio_allowlist,
    reset_stdio_allowlist,
    validate_client_connect,
)

# -----------------------------------------------------------------------
# McpToolDefinition tests
# -----------------------------------------------------------------------


class TestMcpToolDefinition:
    """Tests for the McpToolDefinition dataclass."""

    def test_construction_with_all_fields(self) -> None:
        tool = McpToolDefinition(
            name="weather_lookup",
            description="Look up weather for a city",
            input_schema={"type": "object", "properties": {"city": {"type": "string"}}},
        )
        assert tool.name == "weather_lookup"
        assert tool.description == "Look up weather for a city"
        assert tool.input_schema["type"] == "object"

    def test_construction_with_defaults(self) -> None:
        tool = McpToolDefinition(name="simple_tool")
        assert tool.name == "simple_tool"
        assert tool.description is None
        assert tool.input_schema == {}

    def test_equality(self) -> None:
        a = McpToolDefinition(name="tool_a", description="desc")
        b = McpToolDefinition(name="tool_a", description="desc")
        assert a == b

    def test_inequality_on_name(self) -> None:
        a = McpToolDefinition(name="tool_a")
        b = McpToolDefinition(name="tool_b")
        assert a != b


# -----------------------------------------------------------------------
# McpProvenance tests
# -----------------------------------------------------------------------


class TestMcpProvenance:
    """Tests for the McpProvenance dataclass."""

    def test_construction(self) -> None:
        prov = McpProvenance(
            source="mcp:weather_lookup",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-cooking",
            timestamp=1_700_000_000_000,
        )
        assert prov.source == "mcp:weather_lookup"
        assert prov.invoked_by == "did:dht:z6MkAlice"
        assert prov.context == "ctx-cooking"
        assert prov.timestamp == 1_700_000_000_000

    def test_source_format_convention(self) -> None:
        prov = McpProvenance(
            source="mcp:some_tool",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-1",
            timestamp=0,
        )
        assert prov.source.startswith("mcp:")


# -----------------------------------------------------------------------
# McpToolResult tests
# -----------------------------------------------------------------------


class TestMcpToolResult:
    """Tests for the McpToolResult dataclass."""

    def test_construction_success(self) -> None:
        prov = McpProvenance(
            source="mcp:search",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-abc",
            timestamp=1_700_000_000_000,
        )
        result = McpToolResult(
            content=[{"type": "text", "text": "result"}],
            is_error=False,
            provenance=prov,
        )
        assert result.content[0]["text"] == "result"
        assert result.is_error is False
        assert result.provenance is prov

    def test_construction_error(self) -> None:
        prov = McpProvenance(
            source="mcp:failing_tool",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-abc",
            timestamp=1_700_000_000_000,
        )
        result = McpToolResult(
            content=[{"type": "text", "text": "error message"}],
            is_error=True,
            provenance=prov,
        )
        assert result.is_error is True

    def test_empty_content(self) -> None:
        prov = McpProvenance(
            source="mcp:noop",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-1",
            timestamp=0,
        )
        result = McpToolResult(content=[], is_error=False, provenance=prov)
        assert result.content == []

    def test_provenance_equality(self) -> None:
        a = McpProvenance(source="mcp:x", invoked_by="did:dht:zA", context="ctx-1", timestamp=1)
        b = McpProvenance(source="mcp:x", invoked_by="did:dht:zA", context="ctx-1", timestamp=1)
        assert a == b


# -----------------------------------------------------------------------
# _VALID_TRANSPORTS tests
# -----------------------------------------------------------------------


class TestValidTransports:
    """Tests for the private ``_VALID_TRANSPORTS`` constant."""

    def test_contains_stdio(self) -> None:
        from scp_sdk.mcp import _VALID_TRANSPORTS

        assert "stdio" in _VALID_TRANSPORTS

    def test_contains_sse(self) -> None:
        from scp_sdk.mcp import _VALID_TRANSPORTS

        assert "sse" in _VALID_TRANSPORTS

    def test_is_frozen(self) -> None:
        from scp_sdk.mcp import _VALID_TRANSPORTS

        assert isinstance(_VALID_TRANSPORTS, frozenset)

    def test_only_two_transports(self) -> None:
        from scp_sdk.mcp import _VALID_TRANSPORTS

        assert len(_VALID_TRANSPORTS) == 2


# -----------------------------------------------------------------------
# validate_client_connect (pure-Python pre-flight) tests
# -----------------------------------------------------------------------


class TestValidateClientConnect:
    """Tests for :func:`validate_client_connect` — the pure-Python guard."""

    def test_rejects_invalid_transport(self) -> None:
        with pytest.raises(ValidationError, match="transport must be"):
            validate_client_connect("http", command=["echo"])

    def test_stdio_requires_command(self) -> None:
        with pytest.raises(ValidationError, match="command is required"):
            validate_client_connect("stdio")

    def test_sse_requires_url(self) -> None:
        with pytest.raises(ValidationError, match="url is required"):
            validate_client_connect("sse")

    def test_validation_error_codes(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            validate_client_connect("invalid")
        assert exc_info.value.code == "SCP-MCP-10002"

        with pytest.raises(ValidationError) as exc_info:
            validate_client_connect("stdio")
        assert exc_info.value.code == "SCP-MCP-10004"

        with pytest.raises(ValidationError) as exc_info:
            validate_client_connect("sse")
        assert exc_info.value.code == "SCP-MCP-10005"

    def test_rejects_absolute_path(self) -> None:
        with pytest.raises(ValidationError, match="bare binary name"):
            validate_client_connect("stdio", command=["/usr/bin/node"])

    def test_rejects_relative_path(self) -> None:
        with pytest.raises(ValidationError, match="bare binary name"):
            validate_client_connect("stdio", command=["./node"])

    def test_rejects_path_traversal(self) -> None:
        with pytest.raises(ValidationError, match="bare binary name"):
            validate_client_connect("stdio", command=["../../bin/node"])

    def test_path_rejection_error_code(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            validate_client_connect("stdio", command=["/tmp/evil/node"])
        assert exc_info.value.code == "SCP-MCP-10006"

    def test_rejects_non_allowlist_binary(self) -> None:
        # Default allowlist excludes arbitrary binary names.
        reset_stdio_allowlist()
        try:
            with pytest.raises(ValidationError, match="allowlist"):
                validate_client_connect("stdio", command=["my-custom-server"])
        finally:
            reset_stdio_allowlist()

    def test_allows_configured_binary(self) -> None:
        reset_stdio_allowlist()
        try:
            configure_stdio_allowlist(additional_binaries=["any-binary"])
            # Does not raise.
            validate_client_connect("stdio", command=["any-binary"])
        finally:
            reset_stdio_allowlist()


# -----------------------------------------------------------------------
# SCP.mcp_client_connect_* validation tests via mocked _native
# -----------------------------------------------------------------------


class TestScpMcpClientConnectValidation:
    """Tests for :meth:`SCP.mcp_client_connect_stdio` /
    :meth:`SCP.mcp_client_connect_sse` pre-flight validation.
    """

    @pytest.mark.asyncio
    async def test_stdio_rejects_empty_command(self) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native = MagicMock()
        with pytest.raises(ValidationError):
            await SCP.mcp_client_connect_stdio(scp, [])

    @pytest.mark.asyncio
    async def test_sse_rejects_missing_url(self) -> None:
        from scp_sdk.scp import SCP

        scp = MagicMock()
        scp._native = MagicMock()
        with pytest.raises(ValidationError):
            await SCP.mcp_client_connect_sse(scp, "")


# -----------------------------------------------------------------------
# Handle wrapper tests
# -----------------------------------------------------------------------


class TestMcpClientWrapper:
    """Tests for the :class:`McpClient` pure-handle wrapper."""

    def test_construction_stores_handle(self) -> None:
        raw = MagicMock()
        client = McpClient(raw)
        assert client._raw_handle is raw


class TestMcpServerWrapper:
    """Tests for the :class:`McpServer` pure-handle wrapper."""

    def test_construction_stores_handle(self) -> None:
        raw = MagicMock()
        server = McpServer(raw)
        assert server._raw_handle is raw


# -----------------------------------------------------------------------
# CLI argument parsing tests
# -----------------------------------------------------------------------


class TestCliMain:
    """Tests for the :func:`cli_main` entry point."""

    def test_serve_command_requires_identity(self) -> None:
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["scp-mcp", "serve", "--relay", "wss://relay.test"]):
                cli_main()

    def test_serve_command_requires_relay(self) -> None:
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["scp-mcp", "serve", "--identity", "did:dht:z6MkTest"]):
                cli_main()

    def test_missing_subcommand_exits(self) -> None:
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["scp-mcp"]):
                cli_main()

    def test_invalid_transport_falls_through_to_argparse(self) -> None:
        with pytest.raises(SystemExit):
            with patch(
                "sys.argv",
                [
                    "scp-mcp",
                    "serve",
                    "--identity",
                    "did:dht:z6MkTest",
                    "--relay",
                    "wss://relay.test",
                    "--transport",
                    "websocket",
                ],
            ):
                cli_main()


# -----------------------------------------------------------------------
# Package-level re-export tests
# -----------------------------------------------------------------------


class TestPackageReExports:
    """Tests that the top-level package re-exports MCP types."""

    def test_mcp_types_accessible_from_top_level(self) -> None:
        import scp_sdk

        assert scp_sdk.McpClient is McpClient
        assert scp_sdk.McpServer is McpServer
        assert scp_sdk.McpToolDefinition is McpToolDefinition
        assert scp_sdk.McpToolResult is McpToolResult
        assert scp_sdk.McpProvenance is McpProvenance


# -----------------------------------------------------------------------
# Module __all__ tests
# -----------------------------------------------------------------------


class TestModuleAll:
    """Tests for the module's ``__all__`` export list."""

    def test_all_contains_core_exports(self) -> None:
        from scp_sdk import mcp

        required = {
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
        }
        assert required.issubset(set(mcp.__all__))

    def test_all_names_are_importable(self) -> None:
        from scp_sdk import mcp

        for name in mcp.__all__:
            assert hasattr(mcp, name), f"{name} in __all__ but not importable"


# -----------------------------------------------------------------------
# DEFAULT_STDIO_ALLOWLIST tests
# -----------------------------------------------------------------------


class TestDefaultStdioAllowlist:
    """Tests for the :data:`DEFAULT_STDIO_ALLOWLIST` constant."""

    def test_is_frozenset(self) -> None:
        assert isinstance(DEFAULT_STDIO_ALLOWLIST, frozenset)

    def test_contains_known_binaries(self) -> None:
        for name in ("uvx", "npx", "node", "python3", "docker", "scp-mcp"):
            assert name in DEFAULT_STDIO_ALLOWLIST

    def test_does_not_contain_shells(self) -> None:
        for name in ("sh", "bash", "zsh", "fish", "cmd", "powershell"):
            assert name not in DEFAULT_STDIO_ALLOWLIST

    def test_no_paths_in_entries(self) -> None:
        for name in DEFAULT_STDIO_ALLOWLIST:
            assert "/" not in name, f"path separator in allowlist entry: {name}"
            assert "\\" not in name, f"backslash in allowlist entry: {name}"


# -----------------------------------------------------------------------
# Stdio allowlist API tests (pure Python validation, no bridge required)
# -----------------------------------------------------------------------


class TestStdioAllowlistApi:
    """Tests for the module-level allowlist functions (Python-side validation)."""

    def test_configure_with_no_binaries_is_noop(self) -> None:
        """Calling with no binaries should not error."""
        # Early return before calling the bridge — so no bridge needed.
        configure_stdio_allowlist()

    def test_disable_requires_confirmation(self) -> None:
        with pytest.raises(ValidationError, match="i_trust_all_commands"):
            disable_stdio_allowlist()

    def test_disable_rejects_false_confirmation(self) -> None:
        with pytest.raises(ValidationError, match="i_trust_all_commands"):
            disable_stdio_allowlist(i_trust_all_commands=False)

    def test_reset_round_trips(self) -> None:
        """After ``reset_stdio_allowlist``, the default allowlist is active."""
        reset_stdio_allowlist()
        state = get_stdio_allowlist()
        assert "unrestricted" in state
        assert state["unrestricted"] is False
        for name in ("uvx", "npx", "node", "python3"):
            assert name in state["allowed"]

    def test_configure_adds_binaries(self) -> None:
        reset_stdio_allowlist()
        try:
            configure_stdio_allowlist(additional_binaries=["my-mcp-server"])
            state = get_stdio_allowlist()
            assert "my-mcp-server" in state["allowed"]
        finally:
            reset_stdio_allowlist()
