"""Tests for SCP Python SDK tool wrappers (cross-context invocation and sessions).

Covers:
- ``_translate_bridge_error`` mapping from bridge exceptions to SDK types.
- ``_scp_core is None`` guard -- all 4 functions raise ``ContextError``
  with code ``SCP-CTX-2001``.
- ``chain_depth`` validation in ``invoke_cross_context`` -- boundary
  values (0 OK, 255 OK, -1 error, 256 error, float error, bool rejected).
- ``ttl_seconds`` validation in ``session_create`` -- boundary values
  (0 OK, -1 error, float error, bool rejected).
- ``__all__`` exports -- all 4 async wrappers are present.

Tests mock ``scp_sdk.tools._scp_core``; no Rust extension required.

See ``.docs/adrs/phase-3.md`` ADR-014 and spec sections 6.2 / 6.2.1.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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
from scp_sdk.tools import (
    _translate_bridge_error,
    invoke_cross_context,
    session_create,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DUMMY_CTX_SRC = "ctx-source-001"
_DUMMY_CTX_TGT = "ctx-target-002"
_DUMMY_TOOL = "calculator"
_DUMMY_DID = "did:dht:z6MkAlice"
_DUMMY_UCAN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.test"


# ---------------------------------------------------------------------------
# _translate_bridge_error tests
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
        # Dynamically create a class with the given name to simulate a bridge exception.
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
# _scp_core is None guard tests
# ---------------------------------------------------------------------------


class TestScpCoreNoneGuard:
    """All 4 wrappers raise ContextError(code=SCP-CTX-2001) when the
    bridge module is not available."""

    @pytest.mark.skip(reason="obsolete after #1549 Phase 4 PR 4 — SDK requires explicit scp: SCP")
    async def test_invoke_cross_context_raises_without_bridge(self) -> None:
        pass

    @pytest.mark.skip(reason="obsolete after #1549 Phase 4 PR 4 — SDK requires explicit scp: SCP")
    async def test_session_create_raises_without_bridge(self) -> None:
        pass

    @pytest.mark.skip(reason="obsolete after #1549 Phase 4 PR 4 — SDK requires explicit scp: SCP")
    async def test_session_invoke_raises_without_bridge(self) -> None:
        pass

    @pytest.mark.skip(reason="obsolete after #1549 Phase 4 PR 4 — SDK requires explicit scp: SCP")
    async def test_session_close_raises_without_bridge(self) -> None:
        pass


# ---------------------------------------------------------------------------
# chain_depth validation tests (invoke_cross_context)
# ---------------------------------------------------------------------------


class TestChainDepthValidation:
    """chain_depth must be an int in 0-255."""

    async def test_chain_depth_zero_accepted(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke_cross_context.return_value = {"ok": True}
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            result = await invoke_cross_context(
                scp=MagicMock(),
                source_context_id=_DUMMY_CTX_SRC,
                target_context_id=_DUMMY_CTX_TGT,
                tool_id=_DUMMY_TOOL,
                input={},
                invoker_did=_DUMMY_DID,
                ucan_token=_DUMMY_UCAN,
                chain_depth=0,
            )
        assert result == {"ok": True}

    async def test_chain_depth_255_accepted(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke_cross_context.return_value = {"ok": True}
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            result = await invoke_cross_context(
                scp=MagicMock(),
                source_context_id=_DUMMY_CTX_SRC,
                target_context_id=_DUMMY_CTX_TGT,
                tool_id=_DUMMY_TOOL,
                input={},
                invoker_did=_DUMMY_DID,
                ucan_token=_DUMMY_UCAN,
                chain_depth=255,
            )
        assert result == {"ok": True}

    async def test_chain_depth_negative_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="chain_depth") as exc_info:
                await invoke_cross_context(
                    scp=MagicMock(),
                    source_context_id=_DUMMY_CTX_SRC,
                    target_context_id=_DUMMY_CTX_TGT,
                    tool_id=_DUMMY_TOOL,
                    input={},
                    invoker_did=_DUMMY_DID,
                    ucan_token=_DUMMY_UCAN,
                    chain_depth=-1,
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_256_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="chain_depth") as exc_info:
                await invoke_cross_context(
                    scp=MagicMock(),
                    source_context_id=_DUMMY_CTX_SRC,
                    target_context_id=_DUMMY_CTX_TGT,
                    tool_id=_DUMMY_TOOL,
                    input={},
                    invoker_did=_DUMMY_DID,
                    ucan_token=_DUMMY_UCAN,
                    chain_depth=256,
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_float_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="chain_depth") as exc_info:
                await invoke_cross_context(
                    scp=MagicMock(),
                    source_context_id=_DUMMY_CTX_SRC,
                    target_context_id=_DUMMY_CTX_TGT,
                    tool_id=_DUMMY_TOOL,
                    input={},
                    invoker_did=_DUMMY_DID,
                    ucan_token=_DUMMY_UCAN,
                    chain_depth=1.5,  # type: ignore[arg-type]
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_bool_true_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="chain_depth") as exc_info:
                await invoke_cross_context(
                    scp=MagicMock(),
                    source_context_id=_DUMMY_CTX_SRC,
                    target_context_id=_DUMMY_CTX_TGT,
                    tool_id=_DUMMY_TOOL,
                    input={},
                    invoker_did=_DUMMY_DID,
                    ucan_token=_DUMMY_UCAN,
                    chain_depth=True,  # type: ignore[arg-type]
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_bool_false_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="chain_depth") as exc_info:
                await invoke_cross_context(
                    scp=MagicMock(),
                    source_context_id=_DUMMY_CTX_SRC,
                    target_context_id=_DUMMY_CTX_TGT,
                    tool_id=_DUMMY_TOOL,
                    input={},
                    invoker_did=_DUMMY_DID,
                    ucan_token=_DUMMY_UCAN,
                    chain_depth=False,  # type: ignore[arg-type]
                )
            assert exc_info.value.code == "SCP-VALID-7002"


# ---------------------------------------------------------------------------
# ttl_seconds validation tests (session_create)
# ---------------------------------------------------------------------------


class TestTtlSecondsValidation:
    """ttl_seconds must be a non-negative int or None."""

    async def test_ttl_none_accepted(self) -> None:
        """None passes validation (session persists for context lifetime per spec 6.2.1).

        Since ``_scp_core`` is patched to None, a ``ContextError`` is
        expected from the bridge guard — not a ``ValidationError``.
        """
        with patch("scp_sdk.tools._scp_core", None):
            with pytest.raises(ContextError, match="_scp_core") as exc_info:
                await session_create(
                    scp=MagicMock(),
                    context_id=_DUMMY_CTX_SRC,
                    tool_id=_DUMMY_TOOL,
                    source_context_id=_DUMMY_CTX_TGT,
                    ttl_seconds=None,
                )
            assert exc_info.value.code == "SCP-CTX-2001"

    async def test_ttl_zero_accepted(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.tool_session_create.return_value = "sess-new"
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            sid = await session_create(
                scp=MagicMock(),
                context_id=_DUMMY_CTX_SRC,
                tool_id=_DUMMY_TOOL,
                source_context_id=_DUMMY_CTX_TGT,
                ttl_seconds=0,
            )
        assert sid == "sess-new"

    async def test_ttl_negative_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
                await session_create(
                    scp=MagicMock(),
                    context_id=_DUMMY_CTX_SRC,
                    tool_id=_DUMMY_TOOL,
                    source_context_id=_DUMMY_CTX_TGT,
                    ttl_seconds=-1,
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_float_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
                await session_create(
                    scp=MagicMock(),
                    context_id=_DUMMY_CTX_SRC,
                    tool_id=_DUMMY_TOOL,
                    source_context_id=_DUMMY_CTX_TGT,
                    ttl_seconds=3.14,  # type: ignore[arg-type]
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_bool_true_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
                await session_create(
                    scp=MagicMock(),
                    context_id=_DUMMY_CTX_SRC,
                    tool_id=_DUMMY_TOOL,
                    source_context_id=_DUMMY_CTX_TGT,
                    ttl_seconds=True,  # type: ignore[arg-type]
                )
            assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_bool_false_rejected(self) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.tools._scp_core", mock_bridge):
            with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
                await session_create(
                    scp=MagicMock(),
                    context_id=_DUMMY_CTX_SRC,
                    tool_id=_DUMMY_TOOL,
                    source_context_id=_DUMMY_CTX_TGT,
                    ttl_seconds=False,  # type: ignore[arg-type]
                )
            assert exc_info.value.code == "SCP-VALID-7002"


# ---------------------------------------------------------------------------
# __all__ exports test
# ---------------------------------------------------------------------------


class TestToolsAllExports:
    """Verify all 4 async wrappers are in tools.__all__."""

    def test_all_contains_invoke_cross_context(self) -> None:
        from scp_sdk import tools

        assert "invoke_cross_context" in tools.__all__

    def test_all_contains_session_create(self) -> None:
        from scp_sdk import tools

        assert "session_create" in tools.__all__

    def test_all_contains_session_invoke(self) -> None:
        from scp_sdk import tools

        assert "session_invoke" in tools.__all__

    def test_all_contains_session_close(self) -> None:
        from scp_sdk import tools

        assert "session_close" in tools.__all__
