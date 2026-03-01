"""Tests for the SCP MCP adapter Python wrapper.

Covers:
- McpToolDefinition dataclass construction
- McpProvenance dataclass construction and field access
- McpToolResult dataclass construction
- serve_mcp transport validation
- McpClient.connect transport validation
- CLI entry point argument parsing
- Module-level __all__ exports
- Package-level re-exports

Tests that require the ``_scp_core`` bridge are skipped; these tests
exercise the pure-Python surface: dataclasses, validation, and argument
parsing.

See ``.docs/adrs/phase-3.md`` ADR-015 and ``.docs/standards/python.md``
for conventions.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.errors import TransportError, ValidationError
from scp_sdk.mcp import (
    _VALID_TRANSPORTS,
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
    serve_mcp,
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
        """Provenance source follows the ``mcp:{tool_name}`` format."""
        prov = McpProvenance(
            source="mcp:my_tool",
            invoked_by="did:dht:z6MkBob",
            context="ctx-1",
            timestamp=42,
        )
        assert prov.source.startswith("mcp:")

    def test_equality(self) -> None:
        kwargs = dict(
            source="mcp:tool",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-1",
            timestamp=100,
        )
        assert McpProvenance(**kwargs) == McpProvenance(**kwargs)


# -----------------------------------------------------------------------
# McpToolResult tests
# -----------------------------------------------------------------------


class TestMcpToolResult:
    """Tests for the McpToolResult dataclass."""

    def test_construction_success(self) -> None:
        prov = McpProvenance(
            source="mcp:calculator",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-math",
            timestamp=1_700_000_000_000,
        )
        result = McpToolResult(
            content=[{"type": "text", "text": "42"}],
            is_error=False,
            provenance=prov,
        )
        assert len(result.content) == 1
        assert result.content[0]["text"] == "42"
        assert not result.is_error
        assert result.provenance.source == "mcp:calculator"

    def test_construction_error(self) -> None:
        prov = McpProvenance(
            source="mcp:flaky_tool",
            invoked_by="did:dht:z6MkAlice",
            context="ctx-1",
            timestamp=999,
        )
        result = McpToolResult(
            content=[{"type": "text", "text": "tool failed"}],
            is_error=True,
            provenance=prov,
        )
        assert result.is_error
        # Provenance is still attached even for error results.
        assert result.provenance.source == "mcp:flaky_tool"

    def test_empty_content(self) -> None:
        prov = McpProvenance(
            source="mcp:void_tool",
            invoked_by="did:dht:z6MkBob",
            context="ctx-2",
            timestamp=0,
        )
        result = McpToolResult(content=[], is_error=False, provenance=prov)
        assert result.content == []


# -----------------------------------------------------------------------
# Transport validation tests
# -----------------------------------------------------------------------


class TestValidTransports:
    """Tests for the _VALID_TRANSPORTS constant."""

    def test_contains_stdio(self) -> None:
        assert "stdio" in _VALID_TRANSPORTS

    def test_contains_sse(self) -> None:
        assert "sse" in _VALID_TRANSPORTS

    def test_is_frozen(self) -> None:
        assert isinstance(_VALID_TRANSPORTS, frozenset)

    def test_only_two_transports(self) -> None:
        assert len(_VALID_TRANSPORTS) == 2


# -----------------------------------------------------------------------
# serve_mcp validation tests
# -----------------------------------------------------------------------


class TestServeMcpValidation:
    """Tests for serve_mcp input validation (no bridge required)."""

    @pytest.mark.asyncio
    async def test_rejects_invalid_transport(self) -> None:
        mock_identity = MagicMock()
        mock_identity.did = "did:dht:z6MkAlice"
        mock_context = MagicMock()
        mock_context.context_id = "ctx-1"

        with pytest.raises(ValidationError, match="transport must be"):
            await serve_mcp(
                identity=mock_identity,
                contexts=[mock_context],
                transport="websocket",
            )

    @pytest.mark.asyncio
    async def test_rejects_empty_contexts(self) -> None:
        mock_identity = MagicMock()
        mock_identity.did = "did:dht:z6MkAlice"

        with pytest.raises(ValidationError, match="at least one context"):
            await serve_mcp(
                identity=mock_identity,
                contexts=[],
                transport="stdio",
            )

    @pytest.mark.asyncio
    async def test_validation_error_has_correct_code_for_transport(self) -> None:
        mock_identity = MagicMock()
        mock_identity.did = "did:dht:z6MkAlice"
        mock_context = MagicMock()
        mock_context.context_id = "ctx-1"

        with pytest.raises(ValidationError) as exc_info:
            await serve_mcp(
                identity=mock_identity,
                contexts=[mock_context],
                transport="invalid",
            )
        assert exc_info.value.code == "SCP-MCP-8002"

    @pytest.mark.asyncio
    async def test_validation_error_has_correct_code_for_empty_contexts(self) -> None:
        mock_identity = MagicMock()
        mock_identity.did = "did:dht:z6MkAlice"

        with pytest.raises(ValidationError) as exc_info:
            await serve_mcp(
                identity=mock_identity,
                contexts=[],
                transport="stdio",
            )
        assert exc_info.value.code == "SCP-MCP-8003"


# -----------------------------------------------------------------------
# McpClient.connect validation tests
# -----------------------------------------------------------------------


class TestMcpClientConnectValidation:
    """Tests for McpClient.connect input validation (no bridge required)."""

    @pytest.mark.asyncio
    async def test_rejects_invalid_transport(self) -> None:
        with pytest.raises(ValidationError, match="transport must be"):
            await McpClient.connect("http", command=["echo"])

    @pytest.mark.asyncio
    async def test_stdio_requires_command(self) -> None:
        with pytest.raises(ValidationError, match="command is required"):
            await McpClient.connect("stdio")

    @pytest.mark.asyncio
    async def test_sse_requires_url(self) -> None:
        with pytest.raises(ValidationError, match="url is required"):
            await McpClient.connect("sse")

    @pytest.mark.asyncio
    async def test_validation_error_codes(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            await McpClient.connect("invalid")
        assert exc_info.value.code == "SCP-MCP-8002"

        with pytest.raises(ValidationError) as exc_info:
            await McpClient.connect("stdio")
        assert exc_info.value.code == "SCP-MCP-8004"

        with pytest.raises(ValidationError) as exc_info:
            await McpClient.connect("sse")
        assert exc_info.value.code == "SCP-MCP-8005"


# -----------------------------------------------------------------------
# McpServer tests
# -----------------------------------------------------------------------


class TestMcpServer:
    """Tests for the McpServer class."""

    def test_repr(self) -> None:
        mock_handle = MagicMock()
        mock_identity = MagicMock()
        mock_identity.did = "did:dht:z6MkAlice"
        mock_context = MagicMock()
        mock_context.context_id = "ctx-abc"

        server = McpServer(
            handle=mock_handle,
            identity=mock_identity,
            contexts=[mock_context],
            transport="stdio",
        )

        r = repr(server)
        assert "McpServer" in r
        assert "stdio" in r
        assert "ctx-abc" in r

    def test_transport_property(self) -> None:
        server = McpServer(
            handle=MagicMock(),
            identity=MagicMock(),
            contexts=[],
            transport="sse",
        )
        assert server.transport == "sse"

    def test_contexts_returns_copy(self) -> None:
        ctx = MagicMock()
        ctx.context_id = "ctx-1"
        server = McpServer(
            handle=MagicMock(),
            identity=MagicMock(),
            contexts=[ctx],
            transport="stdio",
        )
        contexts = server.contexts
        assert len(contexts) == 1
        # Ensure it is a copy, not the same list.
        contexts.append(MagicMock())
        assert len(server.contexts) == 1


# -----------------------------------------------------------------------
# McpClient repr test
# -----------------------------------------------------------------------


class TestMcpClientRepr:
    """Tests for McpClient repr."""

    def test_repr_stdio(self) -> None:
        client = McpClient(
            handle=MagicMock(),
            transport="stdio",
            command=["uvx", "some-server"],
        )
        r = repr(client)
        assert "McpClient" in r
        assert "stdio" in r
        assert "uvx" in r

    def test_repr_sse(self) -> None:
        client = McpClient(
            handle=MagicMock(),
            transport="sse",
            command=None,
        )
        r = repr(client)
        assert "McpClient" in r
        assert "sse" in r


# -----------------------------------------------------------------------
# CLI argument parsing tests
# -----------------------------------------------------------------------


class TestCliMain:
    """Tests for the cli_main entry point."""

    def test_serve_command_requires_identity(self) -> None:
        """Missing --identity should cause SystemExit."""
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["scp-mcp", "serve", "--relay", "wss://relay.test"]):
                cli_main()

    def test_serve_command_requires_relay(self) -> None:
        """Missing --relay should cause SystemExit."""
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["scp-mcp", "serve", "--identity", "did:dht:z6MkTest"]):
                cli_main()

    def test_missing_subcommand_exits(self) -> None:
        """No subcommand should cause SystemExit."""
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["scp-mcp"]):
                cli_main()

    def test_invalid_transport_falls_through_to_argparse(self) -> None:
        """Invalid --transport value is rejected by argparse choices."""
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
# Bridge import error tests
# -----------------------------------------------------------------------


class TestBridgeImportError:
    """Tests that missing _scp_core raises TransportError."""

    @pytest.mark.asyncio
    async def test_serve_mcp_raises_on_missing_bridge(self) -> None:
        """serve_mcp raises TransportError when _scp_core is not available."""
        mock_identity = MagicMock()
        mock_identity.did = "did:dht:z6MkAlice"
        mock_context = MagicMock()
        mock_context.context_id = "ctx-1"

        with patch(
            "scp_sdk.mcp._bridge",
            side_effect=TransportError(
                "The _scp_core extension module is not installed.",
                code="SCP-MCP-8001",
            ),
        ):
            with pytest.raises(TransportError, match="_scp_core"):
                await serve_mcp(
                    identity=mock_identity,
                    contexts=[mock_context],
                    transport="stdio",
                )

    @pytest.mark.asyncio
    async def test_client_connect_raises_on_missing_bridge(self) -> None:
        """McpClient.connect raises TransportError when _scp_core is not available."""
        with patch(
            "scp_sdk.mcp._bridge",
            side_effect=TransportError(
                "The _scp_core extension module is not installed.",
                code="SCP-MCP-8001",
            ),
        ):
            with pytest.raises(TransportError, match="_scp_core"):
                await McpClient.connect("stdio", command=["echo"])


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
        assert scp_sdk.serve_mcp is serve_mcp


# -----------------------------------------------------------------------
# Module __all__ tests
# -----------------------------------------------------------------------


class TestModuleAll:
    """Tests for the module's __all__ export list."""

    def test_all_contains_expected_names(self) -> None:
        from scp_sdk import mcp

        expected = {
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
            "register_tool_handler",
            "reset_stdio_allowlist",
            "serve_mcp",
        }
        assert set(mcp.__all__) == expected

    def test_all_names_are_importable(self) -> None:
        from scp_sdk import mcp

        for name in mcp.__all__:
            assert hasattr(mcp, name), f"{name} in __all__ but not importable"


# -----------------------------------------------------------------------
# DEFAULT_STDIO_ALLOWLIST tests
# -----------------------------------------------------------------------


class TestDefaultStdioAllowlist:
    """Tests for the DEFAULT_STDIO_ALLOWLIST constant."""

    def test_is_frozenset(self) -> None:
        assert isinstance(DEFAULT_STDIO_ALLOWLIST, frozenset)

    def test_contains_known_binaries(self) -> None:
        for name in ("uvx", "npx", "node", "python3", "docker", "scp-mcp"):
            assert name in DEFAULT_STDIO_ALLOWLIST

    def test_does_not_contain_shells(self) -> None:
        for name in ("sh", "bash", "zsh", "fish", "cmd", "powershell"):
            assert name not in DEFAULT_STDIO_ALLOWLIST

    def test_no_paths_in_entries(self) -> None:
        """All entries must be bare basenames, no path separators."""
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
        # This returns early before calling the bridge, so no bridge needed.
        configure_stdio_allowlist()

    def test_disable_requires_confirmation(self) -> None:
        """disable_stdio_allowlist must receive i_trust_all_commands=True."""
        with pytest.raises(ValidationError, match="i_trust_all_commands"):
            disable_stdio_allowlist()

    def test_disable_rejects_false_confirmation(self) -> None:
        with pytest.raises(ValidationError, match="i_trust_all_commands"):
            disable_stdio_allowlist(i_trust_all_commands=False)


# -----------------------------------------------------------------------
# McpClient.connect allowlist pre-validation tests (no bridge required)
# -----------------------------------------------------------------------


class TestMcpClientAllowlistPreValidation:
    """Tests that connect() rejects paths before calling the bridge."""

    @pytest.mark.asyncio
    async def test_rejects_absolute_path(self) -> None:
        with pytest.raises(ValidationError, match="bare binary name"):
            await McpClient.connect("stdio", command=["/usr/bin/node"])

    @pytest.mark.asyncio
    async def test_rejects_relative_path(self) -> None:
        with pytest.raises(ValidationError, match="bare binary name"):
            await McpClient.connect("stdio", command=["./node"])

    @pytest.mark.asyncio
    async def test_rejects_path_traversal(self) -> None:
        with pytest.raises(ValidationError, match="bare binary name"):
            await McpClient.connect("stdio", command=["../../bin/node"])

    @pytest.mark.asyncio
    async def test_path_rejection_error_code(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            await McpClient.connect("stdio", command=["/tmp/evil/node"])
        assert exc_info.value.code == "SCP-MCP-8006"

    @pytest.mark.asyncio
    async def test_unlisted_binary_rejected_with_actionable_message(self) -> None:
        """An unlisted bare binary should produce a message with configure instructions."""
        mock_bridge = MagicMock()
        mock_bridge.py_mcp_get_stdio_allowlist.return_value = {
            "allowed": list(DEFAULT_STDIO_ALLOWLIST),
            "unrestricted": False,
        }
        with patch("scp_sdk.mcp._bridge", return_value=mock_bridge):
            with pytest.raises(ValidationError, match="configure_stdio_allowlist"):
                await McpClient.connect("stdio", command=["my-custom-server"])

    @pytest.mark.asyncio
    async def test_unrestricted_skips_basename_check(self) -> None:
        """When unrestricted, any bare binary should be allowed (passes to bridge)."""
        mock_bridge = MagicMock()
        mock_bridge.py_mcp_get_stdio_allowlist.return_value = {
            "allowed": [],
            "unrestricted": True,
        }
        mock_bridge.py_mcp_client_connect_stdio.return_value = "handle-123"
        with patch("scp_sdk.mcp._bridge", return_value=mock_bridge):
            client = await McpClient.connect("stdio", command=["any-binary"])
            assert client._transport == "stdio"


# -----------------------------------------------------------------------
# Package re-export tests (updated)
# -----------------------------------------------------------------------


class TestPackageReExportsAllowlist:
    """Tests that allowlist functions are re-exported from top-level."""

    def test_configure_accessible(self) -> None:
        import scp_sdk

        assert scp_sdk.configure_stdio_allowlist is configure_stdio_allowlist

    def test_disable_accessible(self) -> None:
        import scp_sdk

        assert scp_sdk.disable_stdio_allowlist is disable_stdio_allowlist

    def test_reset_accessible(self) -> None:
        import scp_sdk

        assert scp_sdk.reset_stdio_allowlist is reset_stdio_allowlist

    def test_get_accessible(self) -> None:
        import scp_sdk

        assert scp_sdk.get_stdio_allowlist is get_stdio_allowlist
