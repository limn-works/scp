"""Behavioral tests for the cross-context STREAMING-saga SDK surface (SCP-OUT-047).

These exercise the SDK-layer :class:`~scp_sdk.outlets.StreamingSagaHandle`
async-iterator + the :meth:`scp_sdk.SCP.outlet_invoke_cross_context_streaming_saga`
open wrapper and :meth:`scp_sdk.SCP.recover_streaming_saga_truncated_close`
recover wrapper against a scripted mock ``_native`` bridge that plays back the
§5.4.5 ``OutletStreamChunk`` wire shape (``serde_bytes`` fields as integer
arrays) — the SAME mock-``_native`` convention every other Python outlet/saga
test uses (``test_outlets.py`` / ``test_outlets_streaming.py``).

**Layer boundary (why these are scripted, not live).** The streaming saga's
full committed / non-blocking / truncated-close paths require the runtime
actor-state interface + budget injection, which has NO bridge-public wiring
(identical to the unary saga export). Those runtime assertions —
non-blocking-open while the saga FSM is genuinely pre-Committed, the durable
prefix ``billed_count``, and the outlet exec fn being invoked EXACTLY once on a
replayed truncated close — are owned by the ``scp-runtime`` integration test
``xctx_streaming_saga_truncated_close_ac7`` and the ``scp-ffi`` Rust
``e2e_bridge.rs`` bridge tests (``xctx_streaming_saga_*``), NOT re-faked here.
The FFI recover returns ``()`` and surfaces NO ``billed_count`` to the SDK, so
that datum is not observable at this layer by construction.

What THESE tests own is the SDK wrapper's own behavior, driven end-to-end
through the public SDK surface:

- **AC6 (non-blocking-open)** — the open returns a handle WITHOUT starting the
  saga; the handle then consumes chunks progressively as produced (a gated,
  delayed terminal) — proving the SDK drains the receiver rather than blocking
  until the stream terminates.
- **AC5 (caller_did-mismatch rejection)** — a ``caller_did`` the bridge does not
  host / is not a member of ``caller_context_id`` rejects the open with the
  mapped saga terminal (:class:`SagaAbortedError`, ``SCP-SAGA-13050``); the
  receiver is NEVER handed out (poll is never issued, ``saga_id`` stays ``None``).
- **AC8 (reconnect truncated-close recovery)** — driving recover through the SDK
  resolves ``Committed`` (returns ``None``); the money-moving invoker gate
  (``SCP-PERM-3001``) and a ``NeedsRepair`` terminal translate to the typed SDK
  errors.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

from scp_sdk.errors import (
    ContextError,
    OutletError,
    ProtocolError,
    SagaAbortedError,
    SagaNeedsRepairError,
)
from scp_sdk.outlets import Aggregate, StreamingSagaHandle
from scp_sdk.scp import SCP

# ---------------------------------------------------------------------------
# Wire-shape chunk builders (match §5.4.5 OutletStreamChunk serialization —
# the bridge forwards A's operator-signed chunks VERBATIM).
# ---------------------------------------------------------------------------

_REQUEST_ID = list(b"\x47" * 16)
_SIG = list(b"\x33" * 64)


def _chunk(sequence: int, payload: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "request_id": _REQUEST_ID,
            "sequence": sequence,
            "payload": payload,
            "sig": _SIG,
        }
    ).encode()


def _data(sequence: int, value: Any) -> bytes:
    return _chunk(sequence, {"@type": "data", "value": value})


def _end(sequence: int, aggregate: Any, execution_time_ms: int = 42) -> bytes:
    return _chunk(
        sequence,
        {
            "@type": "end",
            "aggregate": aggregate,
            "provenance": {"source": "outlet", "quality": "verified"},
            "execution_time_ms": execution_time_ms,
        },
    )


def _error(sequence: int, code: str, message: str, terminal: bool = True) -> bytes:
    return _chunk(
        sequence,
        {"@type": "error", "code": code, "message": message, "terminal": terminal},
    )


def _bridge_exc(name: str, *args: Any) -> Exception:
    """Build a ``_scp_core``-style bridge exception whose CLASS NAME drives SDK
    translation (``BRIDGE_ERROR_MAP`` / ``_saga_terminal_from_bridge`` both
    dispatch on ``type(exc).__name__``, matching how the PyO3 bridge raises its
    ``ContextError`` / ``SagaAbortedError`` / ``SagaNeedsRepairError`` classes).

    Saga terminals carry ``(formatted_message, code, datum)`` positionally, so
    the datum is read structurally — mirroring the real ``ScpPyError`` ->
    ``SagaAbortedError::new_err((formatted, code, retry_after_ms))`` conversion.
    """
    return type(name, (Exception,), {})(*args)


# ---------------------------------------------------------------------------
# Scripted mock bridge for the streaming-saga surface.
# ---------------------------------------------------------------------------

_SAGA_ID = "saga-xctx-0047"


class _FakeSagaNative:
    """A thread-safe scripted ``_scp_core.SCP`` stand-in for the streaming saga.

    ``outlet_streaming_saga_open`` returns ``_SAGA_ID`` (recording the full
    positional arg tuple); ``outlet_streaming_saga_poll_next`` plays back
    ``chunks`` in order then ``None``; ``outlet_streaming_saga_recover_truncated_close``
    records its call and returns ``None`` (a successful ``Committed`` seal).
    """

    def __init__(self, chunks: list[bytes], saga_id: str = _SAGA_ID) -> None:
        self._chunks = list(chunks)
        self._i = 0
        self._lock = threading.Lock()
        self._saga_id = saga_id
        self.open_calls: list[tuple[Any, ...]] = []
        self.poll_calls = 0
        self.recover_calls: list[tuple[str, str]] = []

    def outlet_streaming_saga_open(self, *args: Any) -> str:
        self.open_calls.append(args)
        return self._saga_id

    def outlet_streaming_saga_poll_next(self, saga_id: str) -> list[int] | None:
        with self._lock:
            self.poll_calls += 1
            if self._i >= len(self._chunks):
                return None
            chunk = self._chunks[self._i]
            self._i += 1
            # PyO3 marshals the bridge's Vec<u8> to a Python list[int]; mirror
            # that so the SDK's ``bytes(raw)`` coercion stays honestly exercised.
            return list(chunk)

    def outlet_streaming_saga_recover_truncated_close(self, saga_id: str, caller_did: str) -> None:
        self.recover_calls.append((saga_id, caller_did))


def _make_scp(native: Any) -> MagicMock:
    """A mock ``SCP`` whose ``_native`` is the scripted bridge. The SDK methods
    are invoked UNBOUND with this mock as ``self`` (the ``test_outlets.py``
    convention), so only ``self._native`` is exercised — no real extension."""
    scp = MagicMock()
    scp._native = native
    return scp


_CALLER_CTX = "a" * 64
_TARGET_CTX = "b" * 64
_CALLER_DID = "did:dht:z6MkStreamingSagaCaller01"
_OUTLET_ID = "outlet-xctx-1"
_NONCE = "00112233445566778899aabbccddeeff"
_TS = 1_700_000_000_000
_UCAN = "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp0cnVlfQ.placeholder"


def _open_saga(native: Any, **overrides: Any) -> StreamingSagaHandle:
    scp = _make_scp(native)
    kwargs: dict[str, Any] = {
        "caller_context_id": _CALLER_CTX,
        "target_context_id": _TARGET_CTX,
        "caller_did": _CALLER_DID,
        "outlet_registration_id": _OUTLET_ID,
        "input": {"a": "x", "b": "y"},
        "asserted_nonce_hex": _NONCE,
        "timestamp_ms": _TS,
        "chain_depth": 1,
        "ucan_token": _UCAN,
        "estimated_chunk_count": 8,
    }
    kwargs.update(overrides)
    return SCP.outlet_invoke_cross_context_streaming_saga(scp, **kwargs)


# ---------------------------------------------------------------------------
# AC6 — non-blocking open: the caller consumes chunks as produced.
# ---------------------------------------------------------------------------


class _GatedTerminalSagaNative(_FakeSagaNative):
    """Plays back ``data_chunks`` immediately, then BLOCKS on the terminal until
    the test releases it — modelling a slow saga still producing / pre-Committed.

    Proves the SDK drains chunks progressively rather than blocking the open
    until the stream terminates: the consumer receives every data chunk (and the
    promptly-returned ``saga_id``) while the terminal is still gated.
    """

    def __init__(self, data_chunks: list[bytes], terminal_chunk: bytes) -> None:
        super().__init__(data_chunks)
        self._terminal = terminal_chunk
        self._gate = threading.Event()

    def outlet_streaming_saga_poll_next(self, saga_id: str) -> list[int] | None:
        with self._lock:
            self.poll_calls += 1
            if self._i < len(self._chunks):
                chunk = self._chunks[self._i]
                self._i += 1
                return list(chunk)
        # All data drained — the terminal is not yet available (the saga is
        # still producing). Park until the test releases it.
        if not self._gate.wait(timeout=5.0):  # pragma: no cover - deadline guard
            raise AssertionError("terminal gate was never released")
        return list(self._terminal)

    def release_terminal(self) -> None:
        self._gate.set()


class TestAc6NonBlockingOpen:
    """AC6: a slow (>1 chunk, delayed-terminal) streaming saga — the SDK open
    returns a handle promptly and the caller consumes chunks as produced."""

    async def test_open_returns_handle_without_starting_saga(self) -> None:
        native = _FakeSagaNative([_data(0, {"n": 0}), _end(1, {"total": 1})])
        handle = _open_saga(native)
        # The open is LAZY: the call returned a handle WITHOUT opening the saga
        # (no Commit-transition, no escrow reservation yet).
        assert isinstance(handle, StreamingSagaHandle)
        assert native.open_calls == []
        assert native.poll_calls == 0
        assert handle.saga_id is None

    async def test_consumes_chunks_before_gated_terminal(self) -> None:
        data = [_data(0, {"n": 0}), _data(1, {"n": 1}), _data(2, {"n": 2})]
        native = _GatedTerminalSagaNative(data, _end(3, {"total": 3}))
        handle = _open_saga(native)

        # Consume the produced data chunks while the terminal is still GATED
        # (the saga is mid-stream / pre-Committed). The open returned the
        # durable saga_id promptly — it did NOT block until the stream ended.
        seen = [await handle.__anext__() for _ in range(3)]
        assert [c.payload["value"] for c in seen] == [{"n": 0}, {"n": 1}, {"n": 2}]
        assert handle.saga_id == _SAGA_ID
        assert len(native.open_calls) == 1  # opened exactly once, lazily
        assert not handle._closed  # stream still open, terminal pending

        # Release the gated terminal; the stream then closes on the End chunk.
        native.release_terminal()
        terminal = await handle.__anext__()
        assert terminal.is_terminal
        assert terminal.kind == "end"
        with pytest.raises(StopAsyncIteration):
            await handle.__anext__()

    async def test_open_forwards_full_param_set_in_ffi_order(self) -> None:
        native = _FakeSagaNative([_end(0, {"ok": True})])
        handle = _open_saga(native, proof_tokens=["p0"], ucan_proof_id="pid-1", timeout_ms=1234)
        await handle  # drives the (lazy) open
        assert native.open_calls == [
            (
                _CALLER_CTX,
                _TARGET_CTX,
                _CALLER_DID,
                _OUTLET_ID,
                {"a": "x", "b": "y"},
                _NONCE,
                _TS,
                1,
                _UCAN,
                ["p0"],
                "pid-1",
                1234,
                8,
            )
        ]

    async def test_await_drains_to_aggregate(self) -> None:
        native = _FakeSagaNative([_data(0, {"n": 0}), _end(1, {"total": 5}, execution_time_ms=99)])
        handle = _open_saga(native)
        result = await handle
        assert isinstance(result, Aggregate)
        assert result.value == {"total": 5}
        assert result.execution_time_ms == 99


# ---------------------------------------------------------------------------
# AC5 — caller_did mismatch rejects the open; the receiver is never handed out.
# ---------------------------------------------------------------------------


class TestAc5CallerDidMismatch:
    """AC5: the §6.2.4 caller-principal binding rejects an unhosted / non-member
    ``caller_did`` on the open, BEFORE the saga runs — the mapped saga terminal
    surfaces and the receiver (poll) is never handed out."""

    class _RejectingOpenNative(_FakeSagaNative):
        def __init__(self, exc: Exception) -> None:
            super().__init__([])
            self._open_exc = exc

        def outlet_streaming_saga_open(self, *args: Any) -> str:
            self.open_calls.append(args)
            raise self._open_exc

    async def test_unhosted_caller_rejected_as_saga_aborted_on_await(self) -> None:
        # The bridge raises SagaAbortedError(formatted, code, retry_after_ms) —
        # the §6.2.4 caller-axis rejection (SCP-SAGA-13050), exactly as
        # xctx_streaming_saga_unhosted_caller_rejected_before_saga asserts.
        native = self._RejectingOpenNative(
            _bridge_exc(
                "SagaAbortedError",
                "[SCP-SAGA-13050] saga aborted: caller_did "
                "'did:dht:...' is not an identity hosted by this bridge",
                "SCP-SAGA-13050",
                None,
            )
        )
        handle = _open_saga(native, caller_did="did:dht:z6MkUnhosted01")

        with pytest.raises(SagaAbortedError) as excinfo:
            await handle  # aggregate() drives the open, which rejects
        assert excinfo.value.code == "SCP-SAGA-13050"
        # The receiver is NEVER handed out: the open failed, so no saga_id was
        # pinned and poll_next was never issued.
        assert handle.saga_id is None
        assert native.poll_calls == 0

    async def test_non_member_caller_rejected_on_first_iteration(self) -> None:
        native = self._RejectingOpenNative(
            _bridge_exc(
                "SagaAbortedError",
                "[SCP-SAGA-13050] saga aborted: caller is hosted by this bridge "
                "but is not a member of the caller context",
                "SCP-SAGA-13050",
                None,
            )
        )
        handle = _open_saga(native)
        with pytest.raises(SagaAbortedError) as excinfo:
            async for _chunk in handle:  # first __anext__ opens -> rejects
                pass
        assert excinfo.value.code == "SCP-SAGA-13050"
        assert handle.saga_id is None
        assert native.poll_calls == 0


# ---------------------------------------------------------------------------
# AC8 — reconnect-driven key-bearing truncated-close recovery.
# ---------------------------------------------------------------------------


class TestAc8ReconnectTruncatedClose:
    """AC8: the SDK recover wrapper drives the key-bearing crash-recovery
    truncated close. Success resolves ``Committed`` (returns ``None``); the
    money-moving invoker gate and a ``NeedsRepair`` terminal translate to typed
    SDK errors.

    The runtime-owned assertions (``billed_count`` == durable prefix, outlet
    exec invoked EXACTLY once) are covered by the ``scp-runtime`` test
    ``xctx_streaming_saga_truncated_close_ac7`` — the FFI recover returns ``()``
    and surfaces no ``billed_count`` to the SDK by construction.
    """

    async def test_recover_success_resolves_committed(self) -> None:
        native = _FakeSagaNative([])
        scp = _make_scp(native)
        result = await SCP.recover_streaming_saga_truncated_close(scp, _SAGA_ID, _CALLER_DID)
        assert result is None  # Committed — sealed the durable prefix
        assert native.recover_calls == [(_SAGA_ID, _CALLER_DID)]

    async def test_recover_non_invoker_rejected_perm_3001(self) -> None:
        # CRITICAL #1: recovery is money-moving, so a hosted-but-non-invoker
        # caller is rejected with a typed ContextError carrying SCP-PERM-3001
        # (embedded in the formatted message by the ScpPyError Display impl).
        class _NonInvokerNative(_FakeSagaNative):
            def outlet_streaming_saga_recover_truncated_close(
                self, saga_id: str, caller_did: str
            ) -> None:
                raise _bridge_exc(
                    "ContextError",
                    "[SCP-PERM-3001] context error: caller "
                    f"'{caller_did}' is not the invoker pinned at stream open",
                )

        scp = _make_scp(_NonInvokerNative([]))
        with pytest.raises(ContextError) as excinfo:
            await SCP.recover_streaming_saga_truncated_close(scp, _SAGA_ID, "did:dht:stranger")
        assert "SCP-PERM-3001" in str(excinfo.value)

    async def test_recover_needs_repair_terminal_translated(self) -> None:
        # The seal cannot complete (target not resident / dispatch fails): the
        # saga stays unresolved and the bridge raises SagaNeedsRepairError,
        # carrying the durable saga_id repair handle for a later retry.
        class _NeedsRepairNative(_FakeSagaNative):
            def outlet_streaming_saga_recover_truncated_close(
                self, saga_id: str, caller_did: str
            ) -> None:
                raise _bridge_exc(
                    "SagaNeedsRepairError",
                    "[SCP-SAGA-13065] saga needs repair: seal dispatch failed",
                    "SCP-SAGA-13065",
                    saga_id,
                )

        scp = _make_scp(_NeedsRepairNative([]))
        with pytest.raises(SagaNeedsRepairError) as excinfo:
            await SCP.recover_streaming_saga_truncated_close(scp, _SAGA_ID, _CALLER_DID)
        assert excinfo.value.code == "SCP-SAGA-13065"
        assert excinfo.value.saga_id == _SAGA_ID


# ---------------------------------------------------------------------------
# Supporting SDK-wrapper contract coverage.
# ---------------------------------------------------------------------------


class TestStreamingSagaHandleContract:
    async def test_terminal_error_chunk_raises_typed_outlet_error(self) -> None:
        native = _FakeSagaNative(
            [_data(0, {"n": 0}), _error(1, "SCP-OUTLET-6130", "handler panic")]
        )
        handle = _open_saga(native)
        with pytest.raises(OutletError) as excinfo:
            await handle
        assert excinfo.value.code == "SCP-OUTLET-6130"

    async def test_abnormal_sender_drop_without_end_raises_protocol_error(self) -> None:
        # poll_next -> None before any terminal chunk (abnormal sender drop).
        native = _FakeSagaNative([_data(0, {"n": 0})])
        handle = _open_saga(native)
        with pytest.raises(ProtocolError):
            await handle

    async def test_unknown_saga_id_poll_surfaces_context_error(self) -> None:
        class _UnknownSagaNative(_FakeSagaNative):
            def outlet_streaming_saga_poll_next(self, saga_id: str) -> list[int] | None:
                self.poll_calls += 1
                raise _bridge_exc("ContextError", "no active saga 'x'")

        handle = _open_saga(_UnknownSagaNative([]))
        with pytest.raises(ContextError):
            async for _chunk in handle:
                pass

    async def test_sequence_gap_raises_stream_gap_without_cancel(self) -> None:
        from scp_sdk.errors import StreamGap

        # seq0 then seq2 (seq1 MISSING) — no live cross-context cancel plane, so
        # the gap is a purely local terminal (no bridge cancel round-trip exists).
        native = _FakeSagaNative([_data(0, {"n": 0}), _data(2, {"n": 2})])
        handle = _open_saga(native)
        with pytest.raises(StreamGap):
            async for _chunk in handle:
                pass

    async def test_second_concurrent_driver_raises_protocol_error(self) -> None:
        native = _FakeSagaNative([_data(i, {"n": i}) for i in range(5)])
        handle = _open_saga(native)
        first = asyncio.ensure_future(handle.__anext__())
        await asyncio.sleep(0)  # let `first` set _draining and suspend
        with pytest.raises(ProtocolError):
            await handle.__anext__()
        await first

    async def test_chain_depth_out_of_range_rejected(self) -> None:
        from scp_sdk.errors import ValidationError

        native = _FakeSagaNative([])
        with pytest.raises(ValidationError):
            _open_saga(native, chain_depth=256)
        with pytest.raises(ValidationError):
            _open_saga(native, chain_depth=True)
        # No open was attempted for the rejected calls.
        assert native.open_calls == []

    async def test_negative_timestamp_rejected(self) -> None:
        from scp_sdk.errors import ValidationError

        native = _FakeSagaNative([])
        with pytest.raises(ValidationError):
            _open_saga(native, timestamp_ms=-1)
        assert native.open_calls == []


class TestPublicSurface:
    def test_streaming_saga_handle_exported(self) -> None:
        import scp_sdk

        assert scp_sdk.StreamingSagaHandle is StreamingSagaHandle

    def test_open_and_recover_methods_present(self) -> None:
        assert hasattr(SCP, "outlet_invoke_cross_context_streaming_saga")
        assert hasattr(SCP, "recover_streaming_saga_truncated_close")
