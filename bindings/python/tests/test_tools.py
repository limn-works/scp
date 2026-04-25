"""Tests for SCP Python SDK tool wrappers (cross-context invocation and sessions).

Phase 4 PR 5 Agent B+C (#1549) moved the cross-context / session tool
helpers onto :class:`scp_sdk.SCP`:

- :meth:`SCP.tool_invoke_cross_context` — cross-context invocation (§6.2)
- :meth:`SCP.tool_session_create` / :meth:`SCP.tool_session_invoke`
  / :meth:`SCP.tool_session_close` — stateful tool sessions (§6.2.1)

These tests verify the SCP-level surface with mocked ``_native`` bridges:

- ``chain_depth`` validation in :meth:`SCP.tool_invoke_cross_context`
  (0 OK, 255 OK, negative/overflow/float/bool rejected)
- ``ttl_seconds`` validation in :meth:`SCP.tool_session_create`
  (None OK, 0 OK, negative/float/bool rejected)

Tests mock the PyO3 ``_native`` bridge; no Rust extension required.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scp_sdk.errors import (
    ContextError,
    CryptoError,
    IdentityError,
    ScpError,
    ToolError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.tools import _translate_bridge_error

# ---------------------------------------------------------------------------
# _translate_bridge_error tests (still in scp_sdk.tools)
# ---------------------------------------------------------------------------


class TestTranslateBridgeError:
    """Tests for the bridge-to-SDK exception translator."""

    @pytest.mark.parametrize(
        ("bridge_name", "expected_sdk_cls"),
        [
            ("IdentityError", IdentityError),
            ("ContextError", ContextError),
            ("UcanError", UcanPermissionError),
            ("CryptoError", CryptoError),
            ("TransportError", TransportError),
            ("ToolError", ToolError),
            ("ValidationError", ValidationError),
        ],
    )
    def test_known_bridge_errors_map_to_sdk_types(
        self,
        bridge_name: str,
        expected_sdk_cls: type[ScpError],
    ) -> None:
        """Each bridge error variant in BRIDGE_ERROR_MAP produces the correct SDK type."""
        bridge_cls = type(bridge_name, (Exception,), {})
        bridge_exc = bridge_cls("something went wrong")

        result = _translate_bridge_error(bridge_exc)

        assert isinstance(result, expected_sdk_cls)
        assert result.message == "something went wrong"

    def test_unknown_bridge_error_falls_back_to_context_error(self) -> None:
        """An unmapped bridge exception class name falls back to ContextError."""
        bridge_cls = type("SomeUnknownBridgeError", (Exception,), {})
        bridge_exc = bridge_cls("unexpected failure")

        result = _translate_bridge_error(bridge_exc)

        assert isinstance(result, ContextError)
        assert "unexpected failure" in result.message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DUMMY_CTX_SRC = "ctx-source-001"
_DUMMY_CTX_TGT = "ctx-target-002"
_DUMMY_TOOL = "calculator"
_DUMMY_DID = "did:dht:z6MkAlice"
_DUMMY_UCAN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.test"


def _make_scp(native: MagicMock | None = None) -> MagicMock:
    """Build a mock SCP wrapper whose ``_native`` stands in for the bridge."""
    scp = MagicMock()
    scp._native = native if native is not None else MagicMock()
    return scp


# ---------------------------------------------------------------------------
# chain_depth validation tests (SCP.tool_invoke_cross_context)
# ---------------------------------------------------------------------------


class TestChainDepthValidation:
    """chain_depth must be an int in 0-255."""

    async def test_chain_depth_zero_accepted(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_invoke_cross_context.return_value = {"ok": True}
        scp = _make_scp(native)

        result = await SCP.tool_invoke_cross_context(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_CTX_TGT,
            _DUMMY_TOOL,
            {},
            _DUMMY_DID,
            _DUMMY_UCAN,
            0,
        )
        assert result == {"ok": True}

    async def test_chain_depth_255_accepted(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_invoke_cross_context.return_value = {"ok": True}
        scp = _make_scp(native)

        result = await SCP.tool_invoke_cross_context(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_CTX_TGT,
            _DUMMY_TOOL,
            {},
            _DUMMY_DID,
            _DUMMY_UCAN,
            255,
        )
        assert result == {"ok": True}

    async def test_chain_depth_negative_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await SCP.tool_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_TOOL,
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
                -1,
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_256_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await SCP.tool_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_TOOL,
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
                256,
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_float_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await SCP.tool_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_TOOL,
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
                1.5,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_bool_true_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await SCP.tool_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_TOOL,
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
                True,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_bool_false_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await SCP.tool_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_TOOL,
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
                False,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"


# ---------------------------------------------------------------------------
# ttl_seconds validation tests (SCP.tool_session_create)
# ---------------------------------------------------------------------------


class TestTtlSecondsValidation:
    """ttl_seconds must be a non-negative int or None."""

    async def test_ttl_none_accepted(self) -> None:
        """``None`` passes validation — session persists for the context lifetime (§6.2.1)."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_session_create.return_value = "sess-new"
        scp = _make_scp(native)

        sid = await SCP.tool_session_create(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_TOOL,
            _DUMMY_CTX_TGT,
            None,
        )
        assert sid == "sess-new"

    async def test_ttl_zero_accepted(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_session_create.return_value = "sess-new"
        scp = _make_scp(native)

        sid = await SCP.tool_session_create(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_TOOL,
            _DUMMY_CTX_TGT,
            0,
        )
        assert sid == "sess-new"

    async def test_ttl_negative_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.tool_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_TOOL,
                _DUMMY_CTX_TGT,
                -1,
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_float_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.tool_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_TOOL,
                _DUMMY_CTX_TGT,
                3.14,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_bool_true_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.tool_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_TOOL,
                _DUMMY_CTX_TGT,
                True,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_bool_false_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.tool_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_TOOL,
                _DUMMY_CTX_TGT,
                False,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"


# ---------------------------------------------------------------------------
# Data-class exports — ToolDefinition / ToolCost / TestVector remain
# ---------------------------------------------------------------------------


class TestToolsExports:
    """Verify the remaining data-class exports survived the façade deletion."""

    def test_tool_definition_exported(self) -> None:
        from scp_sdk import tools

        assert "ToolDefinition" in tools.__all__

    def test_tool_cost_exported(self) -> None:
        from scp_sdk import tools

        assert "ToolCost" in tools.__all__

    def test_test_vector_exported(self) -> None:
        from scp_sdk import tools

        assert "TestVector" in tools.__all__
