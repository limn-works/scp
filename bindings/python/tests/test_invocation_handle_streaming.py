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
    StreamAlreadyClosed,
)
from scp_sdk.outlets import (
    Aggregate,
    InvocationHandle,
    OutletStreamChunk,
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
        assert err.code == "SCP-TOOL-6102"
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
    :class:`OutletExecutionError` (`SCP-TOOL-6131` /
    `execution.stream-gap`) on both the await and iterator paths —
    NEVER as a degenerate ``Aggregate(value=None)`` or a silent
    ``StopAsyncIteration``."""

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
