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

    def test_saga_result_exported(self) -> None:
        from scp_sdk import tools

        assert "SagaResult" in tools.__all__


# ---------------------------------------------------------------------------
# Cross-context tool-invocation saga (§6.2.4 / ADR-049 §3a)
# SCP.tool_invoke_cross_context_saga
# ---------------------------------------------------------------------------

_DUMMY_CTX_CALLER = "ctx-caller-001"
_DUMMY_NONCE_HEX = "0123456789abcdef0123456789abcdef"
_DUMMY_TS_MS = 1_700_000_000_000
_DUMMY_REG_ID = "reg-tool-007"


def _committed_native(
    saga_id: str = "saga-committed-001",
    receipt: bytes | None = b"receipt-bytes",
    output: bytes | None = b"output-bytes",
) -> MagicMock:
    """Build a mock ``_native`` whose saga call returns a committed result.

    The committed terminal is a ``SimpleNamespace`` (not a bare ``MagicMock``)
    so the wrapper reads concrete ``saga_id`` / ``receipt`` / ``output``
    values rather than auto-generated mock attributes.
    """
    from types import SimpleNamespace

    native = MagicMock()
    native.tool_invoke_cross_context_saga.return_value = SimpleNamespace(
        saga_id=saga_id, receipt=receipt, output=output
    )
    return native


async def _invoke_saga(scp: MagicMock, *, chain_depth: int = 0, timestamp_ms: int = _DUMMY_TS_MS):
    from scp_sdk.scp import SCP

    return await SCP.tool_invoke_cross_context_saga(
        scp,
        _DUMMY_CTX_CALLER,
        _DUMMY_CTX_TGT,
        _DUMMY_DID,
        _DUMMY_REG_ID,
        {"a": 1},
        _DUMMY_NONCE_HEX,
        timestamp_ms,
        chain_depth,
    )


class TestSagaHappyPath:
    """A committed saga returns a faithful :class:`SagaResult` pass-through."""

    async def test_committed_returns_saga_result(self) -> None:
        from scp_sdk.tools import SagaResult

        scp = _make_scp(_committed_native())

        result = await _invoke_saga(scp)

        assert isinstance(result, SagaResult)
        assert result.saga_id == "saga-committed-001"
        assert result.receipt == b"receipt-bytes"
        assert result.output == b"output-bytes"

    async def test_committed_passes_through_null_receipt_and_output(self) -> None:
        """``None`` receipt/output are surfaced verbatim — never synthesized."""
        from scp_sdk.tools import SagaResult

        scp = _make_scp(_committed_native(receipt=None, output=None))

        result = await _invoke_saga(scp)

        assert isinstance(result, SagaResult)
        assert result.receipt is None
        assert result.output is None

    async def test_native_called_with_forwarded_arguments(self) -> None:
        native = _committed_native()
        scp = _make_scp(native)

        await _invoke_saga(scp, chain_depth=7, timestamp_ms=42)

        native.tool_invoke_cross_context_saga.assert_called_once_with(
            _DUMMY_CTX_CALLER,
            _DUMMY_CTX_TGT,
            _DUMMY_DID,
            _DUMMY_REG_ID,
            {"a": 1},
            _DUMMY_NONCE_HEX,
            42,
            7,
            None,
        )


# Bridge-shaped terminal exceptions: same NAMES the PyO3 bridge raises, with
# the structured datum carried positionally in ``args[2]``. The wrapper
# dispatches by class name and reads ``args`` structurally.
_BridgeSagaAborted = type("SagaAbortedError", (Exception,), {})
_BridgeSagaNeedsRepair = type("SagaNeedsRepairError", (Exception,), {})
_BridgeSagaBusy = type("SagaBusyError", (Exception,), {})


def _native_raising(exc: BaseException) -> MagicMock:
    native = MagicMock()
    native.tool_invoke_cross_context_saga.side_effect = exc
    return native


class TestSagaAbortedTranslation:
    """Prepare-phase abort → SDK SagaAbortedError, retry_after_ms preserved."""

    async def test_abort_without_backoff_preserves_none(self) -> None:
        from scp_sdk.errors import SagaAbortedError

        scp = _make_scp(_native_raising(_BridgeSagaAborted("rejected", "SCP-SAGA-13050", None)))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        # The back-off hint MUST survive as ``None`` — never coerced to ``0``
        # (``0`` would read as "retry immediately" and re-trip the limiter).
        assert exc_info.value.retry_after_ms is None
        assert exc_info.value.code == "SCP-SAGA-13050"
        assert exc_info.value.message == "rejected"

    async def test_abort_with_backoff_preserves_int(self) -> None:
        from scp_sdk.errors import SagaAbortedError

        scp = _make_scp(_native_raising(_BridgeSagaAborted("rate limited", "SCP-SAGA-13067", 1500)))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.retry_after_ms == 1500
        assert exc_info.value.retry_after_ms is not None
        assert exc_info.value.code == "SCP-SAGA-13067"


class TestSagaNeedsRepairTranslation:
    """Commit-retry exhaustion → SDK SagaNeedsRepairError, saga_id preserved."""

    async def test_needs_repair_preserves_saga_id(self) -> None:
        from scp_sdk.errors import SagaNeedsRepairError

        scp = _make_scp(
            _native_raising(_BridgeSagaNeedsRepair("diverged", "SCP-SAGA-13065", "saga-repair-abc"))
        )

        with pytest.raises(SagaNeedsRepairError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.saga_id == "saga-repair-abc"
        assert exc_info.value.code == "SCP-SAGA-13065"


class TestSagaBusyTranslation:
    """Participant-set overlap → SDK SagaBusyError, contended_context preserved."""

    async def test_busy_preserves_contended_context(self) -> None:
        from scp_sdk.errors import SagaBusyError

        scp = _make_scp(
            _native_raising(_BridgeSagaBusy("busy", "SCP-SAGA-13066", "ctx-shared-xyz"))
        )

        with pytest.raises(SagaBusyError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.contended_context == "ctx-shared-xyz"
        assert exc_info.value.code == "SCP-SAGA-13066"


class TestSagaNonSagaErrorPassthrough:
    """A non-saga bridge exception is re-raised unchanged (not swallowed)."""

    async def test_unrelated_exception_reraised(self) -> None:
        sentinel = RuntimeError("unrelated boom")
        scp = _make_scp(_native_raising(sentinel))

        with pytest.raises(RuntimeError, match="unrelated boom") as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value is sentinel


class TestSagaChainDepthValidation:
    """chain_depth must be an int in 0-255 (saga wrapper mirrors the sync one)."""

    async def test_chain_depth_zero_accepted(self) -> None:
        scp = _make_scp(_committed_native())
        result = await _invoke_saga(scp, chain_depth=0)
        assert result.saga_id == "saga-committed-001"

    async def test_chain_depth_255_accepted(self) -> None:
        scp = _make_scp(_committed_native())
        result = await _invoke_saga(scp, chain_depth=255)
        assert result.saga_id == "saga-committed-001"

    async def test_chain_depth_negative_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=-1)
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_256_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=256)
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_float_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=1.5)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_bool_true_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=True)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_chain_depth_bool_false_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=False)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"


class TestSagaTimestampValidation:
    """timestamp_ms must be a non-negative int (rejects bool/float/negative)."""

    async def test_timestamp_zero_accepted(self) -> None:
        scp = _make_scp(_committed_native())
        result = await _invoke_saga(scp, timestamp_ms=0)
        assert result.saga_id == "saga-committed-001"

    async def test_timestamp_negative_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="timestamp_ms") as exc_info:
            await _invoke_saga(scp, timestamp_ms=-1)
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_timestamp_float_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="timestamp_ms") as exc_info:
            await _invoke_saga(scp, timestamp_ms=1.5)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_timestamp_bool_true_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="timestamp_ms") as exc_info:
            await _invoke_saga(scp, timestamp_ms=True)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
