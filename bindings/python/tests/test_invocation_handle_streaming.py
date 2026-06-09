"""SCP-OUT-038 Python SDK integration tests.

Covers AC14-18 of the SDK InvocationHandle control-plane story:

- AC14 — happy path: stream 10 Data chunks + End → iterator yields 11
  chunks; ``await handle`` returns ``Aggregate`` carried by End.
- AC15 — mid-stream ``grant_credit`` works (we exercise the SDK path
  end-to-end at the InvocationHandle level by injecting chunks; the
  bridge-level grant_credit round-trip is validated in
  ``test_outlet_stream.py``).
- AC16 — mid-stream ``cancel`` works the same way.
- AC17 — ``grant_credit`` / ``cancel`` raise :class:`StreamAlreadyClosed`
  after End arrives.
- AC18 — ``grant_credit`` raises :class:`StreamAlreadyClosed` after a
  terminal ``Error{terminal: true}`` chunk arrives.

The tests drive an :class:`InvocationHandle` through a directly-populated
``asyncio.Queue`` so the lifecycle behavior is exercised without
depending on a multi-chunk-emitting bridge handler — bridge-level
streaming is independently covered by the runtime tests in
``crates/scp-runtime/.../stream.rs``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from scp_sdk.errors import (
    Credit,
    OutletExecutionError,
    OutletProtocolError,
    StreamAlreadyClosed,
    ValidationError,
)
from scp_sdk.outlets import (
    Aggregate,
    InvocationHandle,
    OutletNamespace,
    OutletStreamChunk,
    _chunk_dict_to_dataclass,
)

# ---------------------------------------------------------------------------
# Helpers — populate a queue with synthetic chunk sequences.
# ---------------------------------------------------------------------------


def _data_chunk(seq: int, value: dict[str, Any]) -> OutletStreamChunk:
    return OutletStreamChunk(
        request_id=b"\x11" * 16,
        sequence=seq,
        payload_type="data",
        value=value,
    )


def _end_chunk(seq: int, aggregate: Any) -> OutletStreamChunk:
    return OutletStreamChunk(
        request_id=b"\x11" * 16,
        sequence=seq,
        payload_type="end",
        aggregate=aggregate,
        execution_time_ms=42,
    )


def _error_chunk(seq: int, *, terminal: bool, code: str = "SCP-TOOL-6131") -> OutletStreamChunk:
    return OutletStreamChunk(
        request_id=b"\x11" * 16,
        sequence=seq,
        payload_type="error",
        code=code,
        message="synthetic error",
        terminal=terminal,
    )


async def _seed_queue(
    q: asyncio.Queue[OutletStreamChunk | BaseException | None],
    items: list[OutletStreamChunk | BaseException | None],
) -> None:
    for item in items:
        await q.put(item)


# ---------------------------------------------------------------------------
# AC14 — 10 Data chunks + End → 11 chunks observed; aggregate populated.
# ---------------------------------------------------------------------------


class TestHappyPath:
    """OUT-038 AC14 — 10 Data + End round-trip via the iterator path."""

    @pytest.mark.asyncio
    async def test_iterator_yields_11_chunks_for_10_data_plus_end(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        chunks: list[OutletStreamChunk | BaseException | None] = []
        for i in range(10):
            chunks.append(_data_chunk(seq=i, value={"i": i}))
        chunks.append(_end_chunk(seq=10, aggregate={"sum": 45}))
        chunks.append(None)  # terminator
        await _seed_queue(q, chunks)

        handle = InvocationHandle(q, request_id="aa" * 16)
        observed: list[OutletStreamChunk] = []
        async for chunk in handle:
            observed.append(chunk)
        assert len(observed) == 11, f"expected 11 chunks (10 Data + End), got {len(observed)}"
        # First 10 are Data; last is End.
        assert all(c.payload_type == "data" for c in observed[:10])
        assert observed[10].payload_type == "end"
        assert observed[10].aggregate == {"sum": 45}

    @pytest.mark.asyncio
    async def test_aggregate_await_returns_end_aggregate(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        chunks: list[OutletStreamChunk | BaseException | None] = [
            _data_chunk(seq=0, value={"x": 1}),
            _data_chunk(seq=1, value={"x": 2}),
            _end_chunk(seq=2, aggregate={"total": 3}),
            None,
        ]
        await _seed_queue(q, chunks)

        handle = InvocationHandle(q, request_id="aa" * 16)
        agg: Aggregate = await handle
        assert agg.value == {"total": 3}
        assert agg.execution_time_ms == 42


# ---------------------------------------------------------------------------
# Dual-consumption guard (cross-SDK consistency-B).
# ---------------------------------------------------------------------------


class TestDualConsumptionGuard:
    """A handle backed by a single underlying source cannot be drained as
    BOTH ``await handle`` (aggregate) and ``async for chunk in handle``
    (stream). The convergence target — matching the Kotlin reference —
    is the Protocol-class shape: :class:`OutletProtocolError` with code
    ``SCP-TOOL-6020`` and slug ``protocol.handle-double-consumed`` (was
    a generic ``ContextError`` / ``SCP-CTX-2020`` before round-5/6
    convergence)."""

    @pytest.mark.asyncio
    async def test_aggregate_then_iterate_raises_protocol_error(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await _seed_queue(q, [_end_chunk(seq=0, aggregate={"sum": 1}), None])
        handle = InvocationHandle(q, request_id="aa" * 16)
        await handle  # claim "aggregate"
        with pytest.raises(OutletProtocolError) as excinfo:
            handle.__aiter__()  # claim "stream" — conflict
        assert excinfo.value.code == "SCP-TOOL-6020"
        assert excinfo.value.slug == "protocol.handle-double-consumed"
        assert excinfo.value.class_wire == "protocol"

    @pytest.mark.asyncio
    async def test_iterate_then_aggregate_raises_protocol_error(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await _seed_queue(q, [_end_chunk(seq=0, aggregate={"sum": 1}), None])
        handle = InvocationHandle(q, request_id="aa" * 16)
        handle.__aiter__()  # claim "stream"
        with pytest.raises(OutletProtocolError) as excinfo:
            await handle  # claim "aggregate" — conflict
        assert excinfo.value.code == "SCP-TOOL-6020"
        assert excinfo.value.slug == "protocol.handle-double-consumed"

    @pytest.mark.asyncio
    async def test_same_mode_reconsumption_is_idempotent(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await _seed_queue(q, [_end_chunk(seq=0, aggregate={"sum": 1}), None])
        handle = InvocationHandle(q, request_id="aa" * 16)
        # Re-claiming the SAME mode must NOT raise — the guard only
        # rejects switching to a DIFFERENT mode.
        handle.__aiter__()
        handle.__aiter__()  # no raise


# ---------------------------------------------------------------------------
# AC15 — mid-stream grant_credit
# ---------------------------------------------------------------------------


class TestMidStreamGrantCredit:
    """OUT-038 AC15 — grant_credit succeeds while the stream is active."""

    @pytest.mark.asyncio
    async def test_grant_credit_mid_stream_active(self, monkeypatch: Any) -> None:
        """While the stream is open (no terminal observed), grant_credit
        routes to the bridge and the bridge result is forwarded.

        We monkeypatch the bridge call to avoid a real round-trip — the
        round-trip itself is independently validated by the runtime
        tests; here we verify the SDK forwards the typed Credit
        argument and surfaces the result.
        """
        from scp_sdk import outlets as outlets_mod

        captured: dict[str, Any] = {}

        def fake_grant(request_id_hex: str, caller_did: str, grant_int: int) -> int:
            captured["request_id"] = request_id_hex
            captured["caller_did"] = caller_did
            captured["grant"] = grant_int
            return 99  # synthetic new total

        # Build a fake bridge object exposing the grant function.
        class _FakeBridge:
            outlet_stream_grant_credit = staticmethod(fake_grant)

        monkeypatch.setattr(outlets_mod, "_scp_core", _FakeBridge)

        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        # Inject a Data chunk so the stream is "active" (no terminal yet).
        await q.put(_data_chunk(seq=0, value={"i": 0}))
        handle = InvocationHandle(
            q,
            request_id="bb" * 16,
            invoker_did="did:dht:z6MkInvoker",
        )
        # Pull one chunk — the iterator must NOT see a terminal.
        chunk = await handle.__anext__()
        assert chunk.payload_type == "data"
        assert handle.is_terminated is False

        # Now grant credit — should succeed.
        new_total = await handle.grant_credit(Credit(15))
        assert new_total == 99
        assert captured["request_id"] == "bb" * 16
        assert captured["caller_did"] == "did:dht:z6MkInvoker"
        assert captured["grant"] == 15


# ---------------------------------------------------------------------------
# AC16 — mid-stream cancel
# ---------------------------------------------------------------------------


class TestMidStreamCancel:
    """OUT-038 AC16 — cancel succeeds while the stream is active."""

    @pytest.mark.asyncio
    async def test_cancel_mid_stream_returns_ack_seq(self, monkeypatch: Any) -> None:
        from scp_sdk import outlets as outlets_mod

        captured: dict[str, Any] = {}

        def fake_cancel(request_id_hex: str, caller_did: str) -> int | None:
            captured["request_id"] = request_id_hex
            captured["caller_did"] = caller_did
            return 5  # synthetic cancel-ack seq

        class _FakeBridge:
            outlet_stream_cancel = staticmethod(fake_cancel)

        monkeypatch.setattr(outlets_mod, "_scp_core", _FakeBridge)

        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_data_chunk(seq=0, value={}))
        handle = InvocationHandle(
            q,
            request_id="cc" * 16,
            invoker_did="did:dht:z6MkInvoker",
        )
        await handle.__anext__()  # consume the Data chunk
        assert handle.is_terminated is False

        # CRITICAL #3 — cancel no longer takes next_seq; the bridge
        # derives it from the runtime's emission cursor.
        ack = await handle.cancel()
        assert ack == 5
        assert captured["request_id"] == "cc" * 16
        assert captured["caller_did"] == "did:dht:z6MkInvoker"


# ---------------------------------------------------------------------------
# AC17 — post-End grant_credit + cancel raise StreamAlreadyClosed
# ---------------------------------------------------------------------------


class TestPostTerminalLifecycleGuard:
    """OUT-038 AC17 / AC18 — control-plane raises after terminal chunk."""

    @pytest.mark.asyncio
    async def test_grant_credit_after_end_raises_stream_already_closed(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_end_chunk(seq=0, aggregate={"ok": True}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="dd" * 16)

        # Drain the iterator so the terminal is observed.
        observed: list[OutletStreamChunk] = []
        async for chunk in handle:
            observed.append(chunk)
        assert len(observed) == 1
        assert handle.is_terminated is True

        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(10))

    @pytest.mark.asyncio
    async def test_cancel_after_end_raises_stream_already_closed(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_end_chunk(seq=0, aggregate={"ok": True}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="dd" * 16)

        async for _ in handle:
            pass
        # CRITICAL #3 — cancel no longer accepts a caller-supplied
        # next_seq; the bridge derives it from the runtime's emission
        # cursor. The post-terminal lifecycle guard fires BEFORE the
        # cancel ever reaches the bridge, so the call is parameterless.
        with pytest.raises(StreamAlreadyClosed):
            await handle.cancel()

    @pytest.mark.asyncio
    async def test_grant_credit_after_terminal_error_raises_stream_already_closed(self) -> None:
        # AC18 — Error{terminal:true} is a terminal chunk; subsequent
        # grant_credit raises StreamAlreadyClosed.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_error_chunk(seq=0, terminal=True))
        await q.put(None)
        handle = InvocationHandle(q, request_id="ee" * 16)

        # Drain iterator — the terminal Error chunk closes the stream.
        async for _ in handle:
            pass
        assert handle.is_terminated is True

        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(10))

    @pytest.mark.asyncio
    async def test_cancel_after_terminal_error_raises_stream_already_closed(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_error_chunk(seq=0, terminal=True))
        await q.put(None)
        handle = InvocationHandle(q, request_id="ee" * 16)

        async for _ in handle:
            pass
        with pytest.raises(StreamAlreadyClosed):
            await handle.cancel()

    @pytest.mark.asyncio
    async def test_aggregate_path_marks_terminated_after_end(self) -> None:
        # The aggregate-await path also marks the handle as terminated
        # so subsequent grant_credit / cancel raise.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_end_chunk(seq=0, aggregate={"v": 1}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="ff" * 16)

        agg = await handle
        assert agg.value == {"v": 1}
        assert handle.is_terminated is True

        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(10))


# ---------------------------------------------------------------------------
# AC13 sibling-depth — StreamAlreadyClosed under OutletProtocolError
# ---------------------------------------------------------------------------


class TestStreamAlreadyClosedDepth:
    """OUT-038 AC13 — StreamAlreadyClosed sits at protocol-class depth."""

    def test_stream_already_closed_is_outlet_protocol_error(self) -> None:
        # Per AC13: parent class is OutletProtocolError (the Python
        # subclass for OutletErrorClass::Protocol), not OutletError
        # directly. This puts StreamAlreadyClosed at the same depth as
        # other protocol-class errors.
        from scp_sdk.errors import OutletError, OutletProtocolError

        err = StreamAlreadyClosed()
        assert isinstance(err, OutletProtocolError)
        assert isinstance(err, OutletError)
        # The class_wire matches the Protocol class.
        assert err.class_wire == "protocol"

    def test_stream_already_closed_carries_invariant_code_and_slug(self) -> None:
        err = StreamAlreadyClosed()
        assert err.code == "SCP-TOOL-6101"
        assert err.slug == "protocol.stream-already-closed"


# ---------------------------------------------------------------------------
# AC12 — End.aggregate validation against aggregate_schema
# ---------------------------------------------------------------------------


class TestAggregateSchemaValidation:
    """OUT-038 AC12 — End.aggregate is validated against aggregate_schema."""

    @pytest.mark.asyncio
    async def test_aggregate_passes_validation_for_matching_schema(self) -> None:
        # If `jsonschema` isn't installed, the validation path raises
        # OutputError; the bridge ships it as a soft dep. Skip when
        # missing so the test is robust on environments without it.
        pytest.importorskip("jsonschema")

        schema = {
            "type": "object",
            "properties": {"sum": {"type": "integer"}},
            "required": ["sum"],
        }
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_end_chunk(seq=0, aggregate={"sum": 45}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="01" * 16, aggregate_schema=schema)

        agg = await handle
        assert agg.value == {"sum": 45}

    @pytest.mark.asyncio
    async def test_aggregate_fails_validation_for_mismatched_schema(self) -> None:
        pytest.importorskip("jsonschema")

        from scp_sdk.errors import OutputError

        schema = {
            "type": "object",
            "properties": {"sum": {"type": "integer"}},
            "required": ["sum"],
        }
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        # Aggregate is missing the required `sum` field.
        await q.put(_end_chunk(seq=0, aggregate={"wrong_field": 99}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="01" * 16, aggregate_schema=schema)

        with pytest.raises(OutputError):
            await handle


# ---------------------------------------------------------------------------
# Aggregate path with terminal Error
# ---------------------------------------------------------------------------


class TestAggregateAwaitWithErrorTerminal:
    @pytest.mark.asyncio
    async def test_aggregate_raises_outlet_execution_error_on_terminal_error(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_error_chunk(seq=0, terminal=True))
        await q.put(None)
        handle = InvocationHandle(q, request_id="02" * 16)

        with pytest.raises(OutletExecutionError):
            await handle


# ---------------------------------------------------------------------------
# Abnormal closure — bridge `None` arrives BEFORE any terminal chunk.
# ---------------------------------------------------------------------------


class TestAbnormalClosure:
    """The bridge pump emits `None` to signal end-of-receiver. When the
    `None` arrives WITHOUT a prior terminal chunk (transport drop,
    executor crash, bridge fault) the SDK MUST surface this as an
    :class:`OutletExecutionError` (`SCP-TOOL-6131`, NO slug) on both the
    await and iterator paths — NEVER as a degenerate
    ``Aggregate(value=None)`` or a silent ``StopAsyncIteration``. The
    no-slug shape is the cross-SDK convergence target (Python is the
    reference; TypeScript / Swift / Kotlin match it)."""

    @pytest.mark.asyncio
    async def test_await_path_raises_execution_error_when_pump_closes_without_terminal(
        self,
    ) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        # Push only `None` — no Data chunks, no End/Error{terminal:true}.
        # This simulates the bridge receiver returning `None` without
        # the executor ever emitting a terminal chunk.
        await q.put(None)
        handle = InvocationHandle(q, request_id="ab" * 16)

        with pytest.raises(OutletExecutionError) as excinfo:
            await handle
        assert excinfo.value.code == "SCP-TOOL-6131"
        assert "stream closed without terminal chunk" in str(excinfo.value)
        # After abnormal closure the handle marks terminated so
        # subsequent control-plane calls fail-fast per AC13.
        assert handle.is_terminated is True

    @pytest.mark.asyncio
    async def test_await_path_raises_after_some_data_then_abnormal_close(self) -> None:
        # Producer delivered some Data chunks then closed without a
        # terminal — the abnormal-closure path STILL fires (the
        # consumer never saw End / Error{terminal:true}).
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_data_chunk(seq=0, value={"x": 1}))
        await q.put(_data_chunk(seq=1, value={"x": 2}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="ac" * 16)

        with pytest.raises(OutletExecutionError) as excinfo:
            await handle
        assert excinfo.value.code == "SCP-TOOL-6131"

    @pytest.mark.asyncio
    async def test_iterator_raises_execution_error_when_pump_closes_without_terminal(
        self,
    ) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_data_chunk(seq=0, value={"i": 0}))
        await q.put(None)  # abnormal close — no terminal yielded
        handle = InvocationHandle(q, request_id="ad" * 16)

        observed: list[OutletStreamChunk] = []
        with pytest.raises(OutletExecutionError) as excinfo:
            async for chunk in handle:
                observed.append(chunk)
        assert excinfo.value.code == "SCP-TOOL-6131"
        # The Data chunk was successfully yielded before the abnormal
        # close raised; the abnormal closure does not retroactively
        # invalidate already-delivered chunks.
        assert len(observed) == 1
        assert observed[0].payload_type == "data"
        assert handle.is_terminated is True

    @pytest.mark.asyncio
    async def test_iterator_clean_end_with_terminal_then_none_does_not_raise(self) -> None:
        # Regression guard: when the iterator HAS observed a terminal
        # chunk (End / Error{terminal:true}), the trailing `None`
        # produced by the pump MUST resolve as a normal end-of-
        # iteration (`StopAsyncIteration`) — NOT an abnormal-closure
        # error. The terminal-then-none path is the happy path.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_end_chunk(seq=0, aggregate={"ok": True}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="ae" * 16)

        observed: list[OutletStreamChunk] = []
        async for chunk in handle:
            observed.append(chunk)
        assert len(observed) == 1
        assert observed[0].payload_type == "end"
        # No OutletExecutionError raised — iteration ended cleanly.


# ---------------------------------------------------------------------------
# Error-chunk code parity — a no-code error chunk yields SCP-TOOL-6200 on
# the iterate path regardless of the terminal flag, matching TS/Swift/Kotlin
# (mirrors Kotlin OutletStreamErrorMappingTest / Swift coverage).
# ---------------------------------------------------------------------------


def _error_chunk_dict(seq: int, *, terminal: bool, code: str | None) -> dict[str, Any]:
    """Build a bridge-shaped error chunk dict (as emitted by the PyO3
    bridge) and run it through the production conversion layer — the
    layer that owns the ``SCP-TOOL-6200`` default."""
    d: dict[str, Any] = {
        "request_id": b"\x11" * 16,
        "sequence": seq,
        "payload_type": "error",
        "message": "synthetic error",
        "terminal": terminal,
    }
    if code is not None:
        d["code"] = code
    return d


class TestIteratePathErrorCodeParity:
    """The iterate path (``async for``) yields a coded error chunk for a
    no-code error chunk whether or not it is terminal — the non-terminal
    case was previously broken (fell through with ``code=None``)."""

    @pytest.mark.asyncio
    async def test_iterate_terminal_no_code_error_yields_6200(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_chunk_dict_to_dataclass(_error_chunk_dict(seq=0, terminal=True, code=None)))
        await q.put(None)
        handle = InvocationHandle(q, request_id="ba" * 16)

        observed: list[OutletStreamChunk] = []
        async for chunk in handle:
            observed.append(chunk)
        assert len(observed) == 1
        assert observed[0].payload_type == "error"
        assert observed[0].terminal is True
        assert observed[0].code == "SCP-TOOL-6200"

    @pytest.mark.asyncio
    async def test_iterate_non_terminal_no_code_error_yields_6200(self) -> None:
        # The previously-broken case: a NON-terminal informational error
        # chunk keeps the stream open and MUST carry SCP-TOOL-6200.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(_chunk_dict_to_dataclass(_error_chunk_dict(seq=0, terminal=False, code=None)))
        await q.put(_end_chunk(seq=1, aggregate={"ok": True}))
        await q.put(None)
        handle = InvocationHandle(q, request_id="bb" * 16)

        observed: list[OutletStreamChunk] = []
        async for chunk in handle:
            observed.append(chunk)
        # Non-terminal error did not close the stream — End still arrives.
        assert len(observed) == 2
        assert observed[0].payload_type == "error"
        assert observed[0].terminal is False
        assert observed[0].code == "SCP-TOOL-6200"
        assert observed[1].payload_type == "end"

    @pytest.mark.asyncio
    async def test_iterate_error_with_code_not_clobbered(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        await q.put(
            _chunk_dict_to_dataclass(_error_chunk_dict(seq=0, terminal=True, code="SCP-TOOL-6131"))
        )
        await q.put(None)
        handle = InvocationHandle(q, request_id="bc" * 16)

        observed: list[OutletStreamChunk] = []
        async for chunk in handle:
            observed.append(chunk)
        assert len(observed) == 1
        assert observed[0].code == "SCP-TOOL-6131"


# ---------------------------------------------------------------------------
# Bug 1 — receiver-side revocation re-check loop must not leak when the
# handle is opened for its control plane only and never consumed.
# ---------------------------------------------------------------------------


class TestRecheckLoopTeardown:
    """A streaming handle opened but never consumed must not leak its
    §5.4.5 receiver-side revocation re-check loop.

    Before the fix, ``is_terminated`` only flipped on the consumer paths
    (``await handle`` / ``async for``), so the recheck loop's
    ``while not handle.is_terminated`` polled ``ucan_validate`` for the
    process lifetime when no consumer ever drained the stream. The fix
    flips ``is_terminated`` from the eager pump (so a naturally-ended
    stream stops the loop without a consumer) and adds ``aclose()`` (so a
    control-plane-only caller can release the loop explicitly).
    """

    @pytest.mark.asyncio
    async def test_eager_pump_terminal_lets_recheck_loop_exit_without_consumer(self) -> None:
        # Simulate the production wiring: an eager pump that produces a
        # terminal chunk + sentinel and flips the handle terminal flag,
        # and a recheck loop that exits on ``not handle.is_terminated``.
        # The stream is NEVER consumed. The recheck loop must still exit.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="ab" * 16, invoker_did="did:dht:invoker")

        recheck_iterations = 0

        async def _recheck_loop() -> None:
            nonlocal recheck_iterations
            # Mirrors the production loop's exit condition.
            while not handle.is_terminated:
                recheck_iterations += 1
                await asyncio.sleep(0.001)

        async def _eager_pump() -> None:
            # Produce a terminal chunk + sentinel, then flip the flag —
            # exactly what the production streaming pump's `finally` does.
            q.put_nowait(_end_chunk(seq=0, aggregate={"v": 1}))
            q.put_nowait(None)
            handle._mark_terminated()

        recheck = asyncio.create_task(_recheck_loop())
        await _eager_pump()
        # The loop must observe the flipped flag and exit promptly even
        # though nothing consumed the queue.
        await asyncio.wait_for(recheck, timeout=1.0)
        assert handle.is_terminated is True
        assert recheck.done()

    @pytest.mark.asyncio
    async def test_aclose_cancels_recheck_and_pump_and_fail_closes_control_plane(self) -> None:
        # A control-plane-only caller (grant_credit then abandon) calls
        # aclose() to release the background tasks. aclose() must cancel
        # both, mark terminated, and make later grant_credit fail-closed.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="ac" * 16, invoker_did="did:dht:invoker")

        pump_cancelled = asyncio.Event()
        recheck_cancelled = asyncio.Event()

        async def _never_ending_pump() -> None:
            try:
                while True:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                pump_cancelled.set()
                raise

        async def _never_ending_recheck() -> None:
            try:
                # The real loop polls ucan_validate every tick forever
                # while not terminated; emulate the unbounded poll.
                while not handle.is_terminated:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                recheck_cancelled.set()
                raise

        handle._pump_task = asyncio.create_task(_never_ending_pump())
        handle._recheck_task = asyncio.create_task(_never_ending_recheck())

        # Let the tasks start running.
        await asyncio.sleep(0.02)
        assert handle.is_terminated is False

        await handle.aclose()

        assert handle.is_terminated is True
        assert pump_cancelled.is_set()
        assert recheck_cancelled.is_set()
        # Control plane fail-closes after close.
        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(5))

    @pytest.mark.asyncio
    async def test_aclose_is_idempotent(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="ad" * 16, invoker_did="did:dht:invoker")
        # No background tasks attached — aclose() must still be a safe,
        # repeatable no-op that marks the handle terminated.
        await handle.aclose()
        await handle.aclose()
        assert handle.is_terminated is True

    @pytest.mark.asyncio
    async def test_async_context_manager_closes_handle(self) -> None:
        # `async with ctx.outlets.invoke(...) as handle:` is the idiomatic
        # control-plane-only pattern — the background tasks are released on
        # block exit even though the chunk stream is never consumed.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="af" * 16, invoker_did="did:dht:invoker")

        recheck_cancelled = asyncio.Event()

        async def _never_ending_recheck() -> None:
            try:
                while not handle.is_terminated:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                recheck_cancelled.set()
                raise

        handle._recheck_task = asyncio.create_task(_never_ending_recheck())
        await asyncio.sleep(0.02)

        async with handle as h:
            assert h is handle

        assert handle.is_terminated is True
        assert recheck_cancelled.is_set()


# ---------------------------------------------------------------------------
# Factory uses the running loop (get_running_loop), not a fresh loop
# ---------------------------------------------------------------------------


class TestFactoryRunningLoop:
    """The synchronous ``invoke`` factory schedules its background pump on
    the CALLER's running event loop.

    The factory must use ``asyncio.get_running_loop()`` — never
    ``new_event_loop()``. A fresh, never-run loop would schedule the pump
    on a loop that is never driven, so ``await handle`` would hang
    forever. These tests prove the pump actually runs (driven by the live
    loop) and that the factory refuses to run outside a loop at all.
    """

    @pytest.mark.asyncio
    async def test_one_shot_pump_runs_on_running_loop(self, monkeypatch: Any) -> None:
        from scp_sdk import outlets as outlets_mod

        def fake_invoke(
            context_id: str,
            outlet_id: str,
            input: dict[str, Any],
            invoker_did: str,
            ucan_token: str | None,
            proof_tokens: list[str] | None,
            spending_ucan: str | None,
        ) -> dict[str, Any]:
            return {"ok": True}

        class _FakeBridge:
            context_outlet_invoke = staticmethod(fake_invoke)

        # Both the module-level `_scp_core` (read directly inside the pump)
        # and `_require_bridge()` resolve to the fake.
        monkeypatch.setattr(outlets_mod, "_scp_core", _FakeBridge)

        ns = OutletNamespace("did:dht:ctx", "did:dht:creator")
        handle = ns.invoke(
            "outlet-x",
            {"in": 1},
            ucan_token="ucan-token",
        )
        # If the pump were scheduled on a never-run loop this would hang;
        # `wait_for` bounds the proof. The aggregate resolving is the
        # evidence the pump ran on the live running loop.
        agg = await asyncio.wait_for(handle, timeout=1.0)
        assert agg.value == {"ok": True}

    def test_invoke_outside_running_loop_raises_runtime_error(self, monkeypatch: Any) -> None:
        # Calling the synchronous factory with NO running loop must raise
        # RuntimeError from `get_running_loop()` rather than silently
        # spinning up a fresh, never-run loop (the old broken fallback).
        from scp_sdk import outlets as outlets_mod

        class _FakeBridge:
            @staticmethod
            def context_outlet_invoke(*_a: Any, **_k: Any) -> dict[str, Any]:
                return {"ok": True}

        monkeypatch.setattr(outlets_mod, "_scp_core", _FakeBridge)

        ns = OutletNamespace("did:dht:ctx", "did:dht:creator")
        with pytest.raises(RuntimeError):
            ns.invoke("outlet-x", {"in": 1}, ucan_token="ucan-token")


# ---------------------------------------------------------------------------
# aclose() re-raises the CALLER's own cancellation
# ---------------------------------------------------------------------------


class TestAcloseCancellationPropagation:
    """``aclose()`` swallows the child tasks' expected cancellation but
    must propagate a cancellation aimed at the CALLER's own task.

    Swallowing the caller's cancellation would break structured
    concurrency: an outer ``task.cancel()`` that lands while ``aclose()``
    is awaiting a child task must still tear the caller down.
    """

    @pytest.mark.asyncio
    async def test_aclose_swallows_child_cancellation(self) -> None:
        # The normal case: aclose() cancels its own child tasks and the
        # CancelledError they raise (child finishes in the cancelled
        # state) is swallowed — aclose() completes normally.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="ba" * 16, invoker_did="did:dht:invoker")

        async def _never_ending() -> None:
            while True:
                await asyncio.sleep(0.01)

        handle._pump_task = asyncio.create_task(_never_ending())
        await asyncio.sleep(0.02)

        # Must NOT raise — the child's cancellation is expected and owned
        # by aclose().
        await handle.aclose()
        assert handle.is_terminated is True

    @pytest.mark.asyncio
    async def test_aclose_reraises_caller_cancellation(self) -> None:
        # A cancellation that interrupts aclose()'s `await task` but is NOT
        # the awaited child's own cancellation (the child did not finish in
        # the cancelled state) must propagate, not be swallowed. This is
        # the caller's-own-cancellation case.
        #
        # Deterministic seam: a task-shaped stand-in whose `await` raises
        # CancelledError while `cancelled()` reports False — exactly the
        # signature of "an external cancel hit our await, the child is not
        # itself cancelled". aclose() must re-raise on this shape.
        class _ExternalCancelTask:
            """Mimics an asyncio.Task whose await is interrupted by an
            EXTERNAL cancellation. `cancelled()` stays False because the
            task itself did not finish cancelled."""

            def __init__(self) -> None:
                self._cancel_calls = 0

            def done(self) -> bool:
                return False

            def cancel(self) -> bool:
                self._cancel_calls += 1
                return True

            def cancelled(self) -> bool:
                # NOT cancelled — the CancelledError raised below belongs
                # to the caller, not to this child task.
                return False

            def __await__(self):  # type: ignore[no-untyped-def]
                async def _raise() -> None:
                    raise asyncio.CancelledError

                return _raise().__await__()

        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="bc" * 16, invoker_did="did:dht:invoker")
        handle._pump_task = _ExternalCancelTask()  # type: ignore[assignment]

        # aclose() must NOT swallow this CancelledError — it belongs to the
        # caller (the awaited child is not `cancelled()`).
        with pytest.raises(asyncio.CancelledError):
            await handle.aclose()

    @pytest.mark.asyncio
    async def test_aclose_swallows_childs_own_cancellation(self) -> None:
        # The mirror case: a child that finishes in the cancelled state
        # (its own expected response to aclose()'s cancel) is swallowed —
        # aclose() completes normally. Distinguishes from the caller's-own
        # cancellation case above purely by `cancelled()`.
        class _SelfCancelledTask:
            def done(self) -> bool:
                return False

            def cancel(self) -> bool:
                return True

            def cancelled(self) -> bool:
                # The child finished cancelled — this CancelledError is its
                # OWN, owned by aclose(), and must be swallowed.
                return True

            def __await__(self):  # type: ignore[no-untyped-def]
                async def _raise() -> None:
                    raise asyncio.CancelledError

                return _raise().__await__()

        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="bd" * 16, invoker_did="did:dht:invoker")
        handle._recheck_task = _SelfCancelledTask()  # type: ignore[assignment]

        # Must NOT raise — the child's own cancellation is owned by aclose.
        await handle.aclose()
        assert handle.is_terminated is True


# ---------------------------------------------------------------------------
# await handle AFTER aclose() must ERROR (StreamAlreadyClosed), never hang.
# ---------------------------------------------------------------------------


class TestAwaitAfterAclose:
    """``aclose()`` settles the consumption channel so a later ``await
    handle`` / ``async for`` ERRORS within a short timeout rather than
    hanging on an empty queue whose only producer (the pump) was cancelled.
    """

    @pytest.mark.asyncio
    async def test_await_after_aclose_raises_not_hang(self) -> None:
        # Unbounded handle — empty queue, no pump pushing a terminal chunk.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="f6" * 16, invoker_did="did:dht:invoker")
        await handle.aclose()

        # wait_for surfaces a hang as TimeoutError; the fix makes the await
        # raise StreamAlreadyClosed first.
        with pytest.raises(StreamAlreadyClosed):
            await asyncio.wait_for(handle, timeout=1.0)

    @pytest.mark.asyncio
    async def test_iterate_after_aclose_raises_not_hang(self) -> None:
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="07" * 16, invoker_did="did:dht:invoker")
        await handle.aclose()

        async def _drain() -> None:
            async for _chunk in handle:
                pass

        with pytest.raises(StreamAlreadyClosed):
            await asyncio.wait_for(_drain(), timeout=1.0)


# ---------------------------------------------------------------------------
# invoke() one-shot ucan_token pre-check parity (Finding 5, SCP-VALID-7003).
# ---------------------------------------------------------------------------


class TestInvokeOneShotUcanPrecheck:
    """A degenerate single-shot ``invoke`` without ``ucan_token`` raises a
    Validation error at the SDK boundary (``SCP-VALID-7003``) — parity with
    the stronger TS DX across all four SDKs. The bridge's
    ``context_outlet_invoke`` requires a non-empty UCAN, so a ``None`` is
    invalid; failing at the call site gives a precise error.
    """

    def test_one_shot_without_ucan_raises_validation(self) -> None:
        namespace = OutletNamespace("ctx-id", "did:dht:creator")
        with pytest.raises(ValidationError) as exc_info:
            namespace.invoke("outlet-x", {})
        assert exc_info.value.code == "SCP-VALID-7003"
