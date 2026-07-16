"""Tests for SCP Python SDK outlet wrappers (cross-context invocation and sessions).

Phase 4 PR 5 Agent B+C (#1549) moved the cross-context / session outlet
helpers onto :class:`scp_sdk.SCP`:

- :meth:`SCP.outlet_invoke_cross_context` — cross-context invocation (§6.2)
- :meth:`SCP.outlet_session_create` / :meth:`SCP.outlet_session_invoke`
  / :meth:`SCP.outlet_session_close` — stateful outlet sessions (§6.2.1)

These tests verify the SCP-level surface with mocked ``_native`` bridges:

- ``chain_depth`` validation in :meth:`SCP.outlet_invoke_cross_context`
  (0 OK, 255 OK, negative/overflow/float/bool rejected)
- ``ttl_seconds`` validation in :meth:`SCP.outlet_session_create`
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
    OutletError,
    ScpError,
    TransportError,
    UcanPermissionError,
    ValidationError,
    _coded_bridge_error,
)

# ---------------------------------------------------------------------------
# _coded_bridge_error tests (centralized in scp_sdk.errors; used by outlets)
# ---------------------------------------------------------------------------


class TestCodedBridgeError:
    """Tests for the bridge-to-SDK exception translator."""

    @pytest.mark.parametrize(
        ("bridge_name", "expected_sdk_cls"),
        [
            ("IdentityError", IdentityError),
            ("ContextError", ContextError),
            ("UcanError", UcanPermissionError),
            ("CryptoError", CryptoError),
            ("TransportError", TransportError),
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

        result = _coded_bridge_error(bridge_exc)

        assert isinstance(result, expected_sdk_cls)
        assert result.message == "something went wrong"

    def test_unknown_bridge_error_falls_back_to_context_error(self) -> None:
        """An unmapped bridge exception class name falls back to ContextError."""
        bridge_cls = type("SomeUnknownBridgeError", (Exception,), {})
        bridge_exc = bridge_cls("unexpected failure")

        result = _coded_bridge_error(bridge_exc)

        assert isinstance(result, ContextError)
        assert "unexpected failure" in result.message

    def test_extracts_scp_code_from_leading_bracket(self) -> None:
        """Structured SCP code at position 0 is recovered into .code."""
        bridge_cls = type("ContextError", (Exception,), {})
        bridge_exc = bridge_cls("[SCP-CTX-2023] context error: state lookup failed")

        result = _coded_bridge_error(bridge_exc)

        assert result.code == "SCP-CTX-2023"

    def test_embedded_code_is_not_captured(self) -> None:
        """A [SCP-...] token buried in the message body must not masquerade as the code."""
        bridge_cls = type("ContextError", (Exception,), {})
        bridge_exc = bridge_cls("failed to process token: [SCP-CTX-2076] embedded")

        result = _coded_bridge_error(bridge_exc)

        assert result.code != "SCP-CTX-2076"

    def test_already_typed_scperror_returned_unchanged(self) -> None:
        """An already-typed ScpError passthrough must preserve the original instance."""
        original = ContextError("already typed", code="SCP-CTX-2099")

        result = _coded_bridge_error(original)

        assert result is original


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DUMMY_CTX_SRC = "ctx-source-001"
_DUMMY_CTX_TGT = "ctx-target-002"
_DUMMY_OUTLET = "calculator"
_DUMMY_DID = "did:dht:z6MkAlice"
_DUMMY_UCAN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.test"


def _make_scp(native: MagicMock | None = None) -> MagicMock:
    """Build a mock SCP wrapper whose ``_native`` stands in for the bridge."""
    scp = MagicMock()
    scp._native = native if native is not None else MagicMock()
    return scp


# ---------------------------------------------------------------------------
# chain_depth validation tests (SCP.outlet_invoke_cross_context)
# ---------------------------------------------------------------------------


class TestChainDepthValidation:
    """chain_depth must be an int in 0-255."""

    async def test_chain_depth_zero_accepted(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.outlet_invoke_cross_context.return_value = {"ok": True}
        scp = _make_scp(native)

        result = await SCP.outlet_invoke_cross_context(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_CTX_TGT,
            _DUMMY_OUTLET,
            {},
            _DUMMY_DID,
            _DUMMY_UCAN,
            0,
        )
        assert result == {"ok": True}

    async def test_chain_depth_255_accepted(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.outlet_invoke_cross_context.return_value = {"ok": True}
        scp = _make_scp(native)

        result = await SCP.outlet_invoke_cross_context(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_CTX_TGT,
            _DUMMY_OUTLET,
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
            await SCP.outlet_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_OUTLET,
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
            await SCP.outlet_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_OUTLET,
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
            await SCP.outlet_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_OUTLET,
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
            await SCP.outlet_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_OUTLET,
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
            await SCP.outlet_invoke_cross_context(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_CTX_TGT,
                _DUMMY_OUTLET,
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
                False,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"


# ---------------------------------------------------------------------------
# ttl_seconds validation tests (SCP.outlet_session_create)
# ---------------------------------------------------------------------------


class TestTtlSecondsValidation:
    """ttl_seconds must be a non-negative int or None."""

    async def test_ttl_none_accepted(self) -> None:
        """``None`` passes validation — session persists for the context lifetime (§6.2.1)."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.outlet_session_create.return_value = "sess-new"
        scp = _make_scp(native)

        sid = await SCP.outlet_session_create(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_OUTLET,
            _DUMMY_CTX_TGT,
            None,
        )
        assert sid == "sess-new"

    async def test_ttl_zero_accepted(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.outlet_session_create.return_value = "sess-new"
        scp = _make_scp(native)

        sid = await SCP.outlet_session_create(
            scp,
            _DUMMY_CTX_SRC,
            _DUMMY_OUTLET,
            _DUMMY_CTX_TGT,
            0,
        )
        assert sid == "sess-new"

    async def test_ttl_negative_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.outlet_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_OUTLET,
                _DUMMY_CTX_TGT,
                -1,
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_float_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.outlet_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_OUTLET,
                _DUMMY_CTX_TGT,
                3.14,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_bool_true_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.outlet_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_OUTLET,
                _DUMMY_CTX_TGT,
                True,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"

    async def test_ttl_bool_false_rejected(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp()
        with pytest.raises(ValidationError, match="ttl_seconds") as exc_info:
            await SCP.outlet_session_create(
                scp,
                _DUMMY_CTX_SRC,
                _DUMMY_OUTLET,
                _DUMMY_CTX_TGT,
                False,  # type: ignore[arg-type]
            )
        assert exc_info.value.code == "SCP-VALID-7002"


# ---------------------------------------------------------------------------
# Data-class exports — OutletDefinition / OutletCost / TestVector remain
# ---------------------------------------------------------------------------


class TestOutletsExports:
    """Verify the remaining data-class exports survived the façade deletion."""

    def test_outlet_definition_exported(self) -> None:
        from scp_sdk import outlets

        assert "OutletDefinition" in outlets.__all__

    def test_outlet_cost_exported(self) -> None:
        from scp_sdk import outlets

        assert "OutletCost" in outlets.__all__

    def test_outlet_kind_exported(self) -> None:
        import scp_sdk
        from scp_sdk import outlets

        assert "OutletKind" in outlets.__all__
        assert "OutletKind" in scp_sdk.__all__
        assert scp_sdk.OutletKind is outlets.OutletKind

    def test_test_vector_exported(self) -> None:
        from scp_sdk import outlets

        assert "TestVector" in outlets.__all__

    def test_saga_result_exported(self) -> None:
        from scp_sdk import outlets

        assert "SagaResult" in outlets.__all__


# ---------------------------------------------------------------------------
# Cross-context outlet-invocation saga (§6.2.4 / ADR-049 §3a)
# SCP.outlet_invoke_cross_context_saga
# ---------------------------------------------------------------------------

_DUMMY_CTX_CALLER = "ctx-caller-001"
_DUMMY_NONCE_HEX = "0123456789abcdef0123456789abcdef"
_DUMMY_TS_MS = 1_700_000_000_000
_DUMMY_REG_ID = "reg-outlet-007"


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
    native.outlet_invoke_cross_context_saga.return_value = SimpleNamespace(
        saga_id=saga_id, receipt=receipt, output=output
    )
    return native


async def _invoke_saga(
    scp: MagicMock,
    *,
    chain_depth: int = 0,
    timestamp_ms: int = _DUMMY_TS_MS,
    ucan_proof_id: str | None = None,
):
    from scp_sdk.scp import SCP

    return await SCP.outlet_invoke_cross_context_saga(
        scp,
        _DUMMY_CTX_CALLER,
        _DUMMY_CTX_TGT,
        _DUMMY_DID,
        _DUMMY_REG_ID,
        {"a": 1},
        _DUMMY_NONCE_HEX,
        timestamp_ms,
        chain_depth,
        ucan_proof_id,
    )


class TestSagaHappyPath:
    """A committed saga returns a faithful :class:`SagaResult` pass-through."""

    async def test_committed_returns_saga_result(self) -> None:
        from scp_sdk.outlets import SagaResult

        scp = _make_scp(_committed_native())

        result = await _invoke_saga(scp)

        assert isinstance(result, SagaResult)
        assert result.saga_id == "saga-committed-001"
        assert result.receipt == b"receipt-bytes"
        assert result.output == b"output-bytes"

    async def test_committed_passes_through_null_receipt_and_output(self) -> None:
        """``None`` receipt/output are surfaced verbatim — never synthesized."""
        from scp_sdk.outlets import SagaResult

        scp = _make_scp(_committed_native(receipt=None, output=None))

        result = await _invoke_saga(scp)

        assert isinstance(result, SagaResult)
        assert result.receipt is None
        assert result.output is None

    async def test_native_called_with_forwarded_arguments(self) -> None:
        native = _committed_native()
        scp = _make_scp(native)

        await _invoke_saga(scp, chain_depth=7, timestamp_ms=42)

        native.outlet_invoke_cross_context_saga.assert_called_once_with(
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

    async def test_native_forwards_ucan_proof_id(self) -> None:
        """A non-default ``ucan_proof_id`` is forwarded as the 9th positional arg."""
        native = _committed_native()
        scp = _make_scp(native)

        await _invoke_saga(scp, ucan_proof_id="some-proof-id")

        native.outlet_invoke_cross_context_saga.assert_called_once_with(
            _DUMMY_CTX_CALLER,
            _DUMMY_CTX_TGT,
            _DUMMY_DID,
            _DUMMY_REG_ID,
            {"a": 1},
            _DUMMY_NONCE_HEX,
            _DUMMY_TS_MS,
            0,
            "some-proof-id",
        )


# Bridge-shaped terminal exceptions: same NAMES the PyO3 bridge raises, with
# the structured datum carried positionally in ``args[2]``. The wrapper
# dispatches by class name and reads ``args`` structurally.
_BridgeSagaAborted = type("SagaAbortedError", (Exception,), {})
_BridgeSagaNeedsRepair = type("SagaNeedsRepairError", (Exception,), {})
_BridgeSagaBusy = type("SagaBusyError", (Exception,), {})


def _native_raising(exc: BaseException) -> MagicMock:
    native = MagicMock()
    native.outlet_invoke_cross_context_saga.side_effect = exc
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

    async def test_abort_without_code_falls_back_to_generic_default(self) -> None:
        """A bridge abort that omits the code (1-tuple ``args``) surfaces the
        generic ``SCP-SAGA-13067`` class default — never a more specific code.

        The bridge always supplies an explicit ``SCP-SAGA-13xxx`` code; this
        exercises the ``code is None`` translation branch so the class default
        stays load-bearing (the generic abort code, not a Prepare-reason code).
        """
        from scp_sdk.errors import SagaAbortedError

        scp = _make_scp(_native_raising(_BridgeSagaAborted("rejected")))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.code == "SCP-SAGA-13067"
        assert exc_info.value.retry_after_ms is None
        assert exc_info.value.message == "rejected"

    async def test_abort_bool_datum_is_not_coerced_to_retry(self) -> None:
        """A bridge abort whose datum is a ``bool`` MUST NOT be read as a
        back-off hint — ``retry_after_ms`` stays ``None``.

        ``bool`` is a subclass of ``int`` in Python, so ``isinstance(True, int)``
        is ``True``; without the ``and not isinstance(datum, bool)`` guard the
        translation would coerce ``True`` into the int ``1`` and surface a
        bogus 1 ms back-off. This pins that guard load-bearing.
        """
        from scp_sdk.errors import SagaAbortedError

        scp = _make_scp(_native_raising(_BridgeSagaAborted("aborted", "SCP-SAGA-13067", True)))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        # The bool datum is rejected structurally: not ``True``, not ``1``.
        assert exc_info.value.retry_after_ms is None
        assert exc_info.value.code == "SCP-SAGA-13067"
        assert exc_info.value.message == "aborted"

    async def test_abort_non_string_code_arg_falls_back_to_generic_default(self) -> None:
        """A bridge terminal whose ``args[1]`` is a non-string (a 2-tuple
        ``(message, datum)`` with no code slot) MUST NOT surface that value as
        the error ``code`` — it falls back to the ``SCP-SAGA-13067`` default.

        The translator guards the code read with ``isinstance(args[1], str)``;
        without it the int ``1500`` (a datum, not a code) would become the
        ``code``. The production bridge always sends a string code, so this
        pins the defensive guard against a malformed-arity bridge terminal.
        """
        from scp_sdk.errors import SagaAbortedError

        scp = _make_scp(_native_raising(_BridgeSagaAborted("rate limited", 1500)))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        # ``1500`` sits at args[1] (the code slot) but is not a string, so it is
        # neither read as the code nor (being absent from args[2]) as a back-off.
        assert exc_info.value.code == "SCP-SAGA-13067"
        assert exc_info.value.retry_after_ms is None

    async def test_abort_empty_args_falls_back_without_index_error(self) -> None:
        """A bridge terminal raised with NO args translates cleanly: the
        message read is guarded by ``str(args[0]) if len(args) > 0 else
        str(exc)`` so it never indexes ``args[0]`` out of range, and the
        code/back-off fall back.

        Dropping the ``len(args) > 0`` guard would raise ``IndexError`` on the
        empty tuple instead of producing a typed SDK terminal; this pins it.
        """
        from scp_sdk.errors import SagaAbortedError

        scp = _make_scp(_native_raising(_BridgeSagaAborted()))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.code == "SCP-SAGA-13067"
        assert exc_info.value.retry_after_ms is None

    async def test_translated_saga_error_chains_original_bridge_cause(self) -> None:
        """The wrapper re-raises the typed SDK terminal ``from`` the bridge
        exception, so ``__cause__`` preserves the original for debugging.

        Dropping the ``from exc`` clause would leave ``__cause__`` as ``None``
        (only the implicit ``__context__`` would be set); this pins the
        explicit cause chain.
        """
        from scp_sdk.errors import SagaAbortedError

        bridge_exc = _BridgeSagaAborted("rate limited", "SCP-SAGA-13067", 1500)
        scp = _make_scp(_native_raising(bridge_exc))

        with pytest.raises(SagaAbortedError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.__cause__ is bridge_exc


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

    async def test_needs_repair_without_code_falls_back_to_generic_default(self) -> None:
        """A bridge needs-repair that omits the code (1-tuple ``args``) surfaces
        the ``SCP-SAGA-13065`` class default, and a missing datum yields ``""``.

        The bridge always supplies an explicit code; this exercises the
        ``code is None`` translation branch so the class default stays
        load-bearing (a typo in ``_default_code`` would otherwise pass).
        """
        from scp_sdk.errors import SagaNeedsRepairError

        scp = _make_scp(_native_raising(_BridgeSagaNeedsRepair("needs repair")))

        with pytest.raises(SagaNeedsRepairError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.code == "SCP-SAGA-13065"
        assert exc_info.value.saga_id == ""
        assert exc_info.value.message == "needs repair"


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

    async def test_busy_without_code_falls_back_to_generic_default(self) -> None:
        """A bridge busy that omits the code (1-tuple ``args``) surfaces the
        ``SCP-SAGA-13066`` class default, and a missing datum yields ``""``.

        The bridge always supplies an explicit code; this exercises the
        ``code is None`` translation branch so the class default stays
        load-bearing (a typo in ``_default_code`` would otherwise pass).
        """
        from scp_sdk.errors import SagaBusyError

        scp = _make_scp(_native_raising(_BridgeSagaBusy("busy")))

        with pytest.raises(SagaBusyError) as exc_info:
            await _invoke_saga(scp)

        assert exc_info.value.code == "SCP-SAGA-13066"
        assert exc_info.value.contended_context == ""
        assert exc_info.value.message == "busy"


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
        # Fail-fast: validation MUST reject before the side-effectful saga fires.
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_chain_depth_256_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=256)
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_chain_depth_float_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=1.5)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_chain_depth_bool_true_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=True)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_chain_depth_bool_false_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="chain_depth") as exc_info:
            await _invoke_saga(scp, chain_depth=False)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()


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
        # Fail-fast: validation MUST reject before the side-effectful saga fires.
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_timestamp_float_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="timestamp_ms") as exc_info:
            await _invoke_saga(scp, timestamp_ms=1.5)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_timestamp_bool_true_rejected(self) -> None:
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="timestamp_ms") as exc_info:
            await _invoke_saga(scp, timestamp_ms=True)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()

    async def test_timestamp_bool_false_rejected(self) -> None:
        # ``False == 0`` but a bool is still rejected: the u64 boundary takes
        # the type, not the numeric value.
        scp = _make_scp(_committed_native())
        with pytest.raises(ValidationError, match="timestamp_ms") as exc_info:
            await _invoke_saga(scp, timestamp_ms=False)  # type: ignore[arg-type]
        assert exc_info.value.code == "SCP-VALID-7002"
        scp._native.outlet_invoke_cross_context_saga.assert_not_called()


class TestSagaErrorTaxonomy:
    """The three §6.2.4 saga terminals are ``OutletError`` subclasses.

    Cross-context outlet invocation is a OUTLET operation, so its terminal
    failures live under :class:`OutletError` — a caller that catches
    ``OutletError`` catches all three. Re-parenting any of them (e.g. to a
    bare ``ScpError``) would silently break that contract; these pin it.
    """

    def test_saga_errors_are_outlet_errors(self) -> None:
        from scp_sdk.errors import (
            SagaAbortedError,
            SagaBusyError,
            SagaNeedsRepairError,
        )

        assert issubclass(SagaAbortedError, OutletError)
        assert issubclass(SagaNeedsRepairError, OutletError)
        assert issubclass(SagaBusyError, OutletError)
