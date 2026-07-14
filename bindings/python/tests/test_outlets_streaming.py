"""Contract tests for the single-verb outlet streaming surface (SCP-OUT-038).

These exercise the SDK-layer InvocationHandle contract — the awaitable +
async-iterable handle, the ``Credit`` newtype, ``grant_credit`` / ``cancel``
control-plane methods, and the lifecycle guard — against a scripted mock
``_native`` bridge that plays back a JSON chunk sequence in the exact §5.4.5
``OutletStreamChunk`` wire shape (``serde_bytes`` fields as integer arrays).

The scripted bridge lets these tests validate ALL of the SDK's iteration /
aggregation / control-plane / lifecycle logic without a built Rust extension —
the same mock-``_native`` convention every other Python outlet test uses. The
LIVE wire path (a real stream pumped over MLS with funded escrow and a granted
capability) is covered by the Rust PyO3 live-poll test in
``crates/scp-ffi/src/outlet_stream.rs`` (C7); it is NOT re-faked here.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scp_sdk.context import Context
from scp_sdk.errors import (
    ContextError,
    InvalidGrant,
    OutletError,
    ProtocolError,
    StreamAlreadyClosed,
    StreamGap,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.outlets import (
    Aggregate,
    Credit,
    InvocationHandle,
    Outlets,
    OutletStreamChunk,
)

# ---------------------------------------------------------------------------
# Wire-shape chunk builders (match §5.4.5 OutletStreamChunk serialization).
# ---------------------------------------------------------------------------

_REQUEST_ID = list(b"\x01" * 16)
_SIG = list(b"\x22" * 64)


def _chunk(sequence: int, payload: dict[str, Any]) -> bytes:
    """Serialize one OutletStreamChunk exactly as ``outlet_stream_poll_next``
    returns it: request_id / sig as ``serde_bytes`` integer arrays, payload
    internally tagged by ``@type``."""
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


def _progress(sequence: int, pct: int, note: str | None = None) -> bytes:
    payload: dict[str, Any] = {"@type": "progress", "pct": pct}
    if note is not None:
        payload["note"] = note
    return _chunk(sequence, payload)


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


# ---------------------------------------------------------------------------
# Scripted mock bridge.
# ---------------------------------------------------------------------------


class _FakeNative:
    """A thread-safe scripted ``_scp_core.SCP`` stand-in.

    ``outlet_stream_poll_next`` plays back ``chunks`` in order then returns
    ``None``; open / grant / cancel calls are recorded for assertions.
    """

    def __init__(self, chunks: list[bytes], handle_id: str = "stream-1") -> None:
        self._chunks = list(chunks)
        self._i = 0
        self._lock = threading.Lock()
        self._handle_id = handle_id
        self.open_calls: list[tuple[Any, ...]] = []
        self.grant_calls: list[tuple[str, str, int]] = []
        self.cancel_calls: list[tuple[str, str]] = []

    def outlet_stream_open(
        self,
        context_id: str,
        outlet_id: str,
        input: dict[str, Any],
        caller_did: str,
        ucan_token: str,
        proof_tokens: list[str] | None,
        spending_ucan: str | None,
        timeout_ms: int | None,
        estimated_chunk_count: int | None,
    ) -> str:
        self.open_calls.append(
            (context_id, outlet_id, input, caller_did, ucan_token, estimated_chunk_count)
        )
        return self._handle_id

    def outlet_stream_poll_next(self, handle_id: str) -> list[int] | None:
        with self._lock:
            if self._i >= len(self._chunks):
                return None
            chunk = self._chunks[self._i]
            self._i += 1
            # PyO3 marshals the bridge's `Vec<u8>` to a Python `list[int]`, not
            # `bytes` — mirror that so the SDK's `bytes(raw)` coercion stays
            # honestly exercised.
            return list(chunk)

    def outlet_stream_grant_credit(self, handle_id: str, caller_did: str, grant: int) -> None:
        self.grant_calls.append((handle_id, caller_did, grant))

    def outlet_stream_cancel(self, handle_id: str, caller_did: str) -> None:
        self.cancel_calls.append((handle_id, caller_did))


def _bridge_exc(name: str, message: str) -> Exception:
    """Build a `_scp_core`-style bridge exception whose CLASS NAME drives
    `BRIDGE_ERROR_MAP` translation (the SDK dispatches on `type(exc).__name__`,
    matching how the real PyO3 bridge raises `UcanError` / `ValidationError` /
    `ContextError` classes)."""
    return type(name, (Exception,), {})(message)


class _RaisingOpenNative(_FakeNative):
    """A bridge whose `outlet_stream_open` rejects."""

    def __init__(self, exc: Exception) -> None:
        super().__init__([])
        self._open_exc = exc

    def outlet_stream_open(self, *args: Any, **kwargs: Any) -> str:
        raise self._open_exc


class _RaisingPollNative(_FakeNative):
    """A bridge that streams `fail_after` chunks then rejects mid-drain."""

    def __init__(self, chunks: list[bytes], exc: Exception, fail_after: int) -> None:
        super().__init__(chunks)
        self._poll_exc = exc
        self._fail_after = fail_after
        self._polls = 0

    def outlet_stream_poll_next(self, handle_id: str) -> list[int] | None:
        self._polls += 1
        if self._polls > self._fail_after:
            raise self._poll_exc
        return super().outlet_stream_poll_next(handle_id)


def _make_ctx(
    native: _FakeNative,
    context_id: str = "ctx-1",
    identity_did: str = "did:dht:caller",
) -> Context:
    scp = SimpleNamespace(_native=native)
    raw_handle = SimpleNamespace(context_id=context_id, state="active")
    return Context(raw_handle, identity_did=identity_did, scp=scp)


def _invoke(native: _FakeNative, **kwargs: Any) -> InvocationHandle:
    ctx = _make_ctx(native)
    defaults: dict[str, Any] = {"ucan_token": "ucan-abc"}
    defaults.update(kwargs)
    return ctx.outlets.invoke("outlet-1", {"q": "x"}, **defaults)


# ---------------------------------------------------------------------------
# Credit newtype.
# ---------------------------------------------------------------------------


class TestCredit:
    def test_valid_credit(self) -> None:
        assert Credit(1).value == 1
        assert Credit(10).value == 10
        assert Credit(2**32 - 1).value == 2**32 - 1

    def test_zero_raises_invalid_grant(self) -> None:
        with pytest.raises(InvalidGrant):
            Credit(0)

    def test_negative_raises_invalid_grant_not_value_error(self) -> None:
        with pytest.raises(InvalidGrant):
            Credit(-1)
        # Must be InvalidGrant specifically, never a bare ValueError.
        try:
            Credit(-5)
        except InvalidGrant:
            pass
        except ValueError:  # pragma: no cover - would be a regression
            pytest.fail("Credit(-5) raised ValueError, expected InvalidGrant")

    def test_at_or_above_u32_ceiling_raises_invalid_grant(self) -> None:
        with pytest.raises(InvalidGrant):
            Credit(2**32)
        with pytest.raises(InvalidGrant):
            Credit(2**32 + 100)

    def test_bool_rejected(self) -> None:
        # bool is an int subclass; Credit(True) must not silently become Credit(1).
        with pytest.raises(InvalidGrant):
            Credit(True)

    def test_non_int_rejected_as_invalid_grant_not_type_error(self) -> None:
        with pytest.raises(InvalidGrant):
            Credit("10")  # type: ignore[arg-type]

    def test_invalid_grant_hierarchy(self) -> None:
        assert issubclass(InvalidGrant, ProtocolError)
        assert issubclass(ProtocolError, OutletError)
        assert issubclass(StreamAlreadyClosed, ProtocolError)

    def test_credit_equality_and_repr(self) -> None:
        assert Credit(4) == Credit(4)
        assert Credit(4) != Credit(5)
        assert repr(Credit(4)) == "Credit(4)"


# ---------------------------------------------------------------------------
# invoke() surface + accessor.
# ---------------------------------------------------------------------------


class TestOutletsAccessor:
    def test_ctx_outlets_returns_outlets(self) -> None:
        ctx = _make_ctx(_FakeNative([]))
        assert isinstance(ctx.outlets, Outlets)

    def test_invoke_returns_handle_without_blocking(self) -> None:
        native = _FakeNative([_data(0, {"n": 1}), _end(1, {"n": 1})])
        handle = _invoke(native)
        assert isinstance(handle, InvocationHandle)
        # Lazy open: invoke() must not have opened the stream yet.
        assert native.open_calls == []

    def test_context_without_scp_raises(self) -> None:
        from scp_sdk.errors import ContextError

        raw_handle = SimpleNamespace(context_id="ctx-x", state="active")
        bare = Context(raw_handle, identity_did="did:dht:x")
        with pytest.raises(ContextError):
            _ = bare.outlets


# ---------------------------------------------------------------------------
# Iteration + aggregation.
# ---------------------------------------------------------------------------


class TestStreaming:
    async def test_async_iterates_all_chunks_including_progress(self) -> None:
        chunks = [
            _data(0, {"n": 0}),
            _progress(1, 5000, note="halfway"),
            _data(2, {"n": 1}),
            _end(3, {"total": 2}),
        ]
        native = _FakeNative(chunks)
        handle = _invoke(native)

        collected = [chunk async for chunk in handle]

        assert [c.kind for c in collected] == ["data", "progress", "data", "end"]
        # Progress chunk is surfaced, not filtered.
        progress = collected[1]
        assert progress.kind == "progress"
        assert progress.payload["pct"] == 5000
        assert progress.payload["note"] == "halfway"
        # Chunk decoding: sequence + opaque hex request_id/signature.
        assert collected[0].sequence == 0
        assert collected[0].request_id == bytes(_REQUEST_ID).hex()
        assert collected[0].signature == bytes(_SIG).hex()
        assert collected[-1].is_terminal is True

    async def test_await_returns_aggregate(self) -> None:
        native = _FakeNative([_data(0, {"n": 1}), _end(1, {"total": 1}, execution_time_ms=77)])
        handle = _invoke(native)

        result = await handle

        assert isinstance(result, Aggregate)
        assert result.value == {"total": 1}
        assert result.execution_time_ms == 77
        assert result.provenance == {"source": "outlet", "quality": "verified"}

    async def test_await_helper_after_full_iteration_returns_cached_aggregate(self) -> None:
        # AC: 10 Data + End -> iterator yields 11 chunks AND the await helper
        # returns End.aggregate (same handle, no re-drain).
        chunks = [_data(i, {"n": i}) for i in range(10)]
        chunks.append(_end(10, {"total": 10}))
        native = _FakeNative(chunks)
        handle = _invoke(native)

        collected = [chunk async for chunk in handle]
        assert len(collected) == 11
        assert sum(1 for c in collected if c.kind == "data") == 10

        result = await handle
        assert result.value == {"total": 10}

    async def test_stream_opens_exactly_once(self) -> None:
        native = _FakeNative([_data(0, {"n": 1}), _end(1, {"n": 1})])
        handle = _invoke(native)
        _ = [chunk async for chunk in handle]
        assert len(native.open_calls) == 1
        # open forwarded the caller identity + ucan.
        ctx_id, outlet_id, _inp, caller, ucan, _est = native.open_calls[0]
        assert (ctx_id, outlet_id, caller, ucan) == (
            "ctx-1",
            "outlet-1",
            "did:dht:caller",
            "ucan-abc",
        )

    async def test_error_terminal_raises_typed_outlet_error_on_await(self) -> None:
        native = _FakeNative([_data(0, {"n": 1}), _error(1, "SCP-OUTLET-6130", "handler panic")])
        handle = _invoke(native)

        with pytest.raises(OutletError) as excinfo:
            await handle
        assert excinfo.value.code == "SCP-OUTLET-6130"
        assert "handler panic" in str(excinfo.value)

    async def test_stream_without_end_raises_protocol_error(self) -> None:
        # Sender drops without a terminal chunk (poll_next -> None).
        native = _FakeNative([_data(0, {"n": 1})])
        handle = _invoke(native)
        with pytest.raises(ProtocolError):
            await handle

    async def test_caller_did_override(self) -> None:
        native = _FakeNative([_end(0, {"ok": True})])
        handle = _invoke(native, caller_did="did:dht:other")
        await handle
        assert native.open_calls[0][3] == "did:dht:other"


# ---------------------------------------------------------------------------
# Control plane: grant_credit / cancel.
# ---------------------------------------------------------------------------


class TestControlPlane:
    async def test_grant_credit_forwards_to_bridge(self) -> None:
        native = _FakeNative([_data(0, {"n": 0}), _data(1, {"n": 1}), _end(2, {"n": 1})])
        handle = _invoke(native)

        await handle.grant_credit(Credit(4))

        assert native.grant_calls == [("stream-1", "did:dht:caller", 4)]

    async def test_grant_credit_mid_stream_reflected(self) -> None:
        # AC: call grantCredit mid-stream; the grant reaches the bridge and the
        # stream continues to its terminal.
        chunks = [_data(i, {"n": i}) for i in range(4)]
        chunks.append(_end(4, {"total": 4}))
        native = _FakeNative(chunks)
        handle = _invoke(native)

        seen = 0
        async for chunk in handle:
            seen += 1
            if seen == 2:
                await handle.grant_credit(Credit(8))
        assert native.grant_calls == [("stream-1", "did:dht:caller", 8)]
        assert seen == 5

    async def test_grant_credit_requires_credit_newtype_at_runtime(self) -> None:
        native = _FakeNative([_end(0, {"n": 1})])
        handle = _invoke(native)
        with pytest.raises(InvalidGrant):
            await handle.grant_credit(10)  # type: ignore[arg-type]
        # A raw int never reached the bridge.
        assert native.grant_calls == []

    async def test_cancel_forwards_to_bridge(self) -> None:
        native = _FakeNative([_data(0, {"n": 0}), _end(1, {"n": 0})])
        handle = _invoke(native)

        # Open the stream first (pull one chunk); cancel then signs at the bridge.
        # (cancel BEFORE any open is a local no-op — see TestCancelBeforeOpen.)
        await handle.__anext__()
        await handle.cancel()

        assert native.cancel_calls == [("stream-1", "did:dht:caller")]

    async def test_cancel_mid_stream_then_terminal(self) -> None:
        # AC: cancel mid-stream; a terminal chunk still arrives and closes it.
        chunks = [_data(0, {"n": 0}), _data(1, {"n": 1}), _end(2, {"cancelled": True})]
        native = _FakeNative(chunks)
        handle = _invoke(native)

        seen = 0
        async for chunk in handle:
            seen += 1
            if seen == 1:
                await handle.cancel()
        assert native.cancel_calls == [("stream-1", "did:dht:caller")]
        assert seen == 3


# ---------------------------------------------------------------------------
# Lifecycle guard: control plane after terminal raises StreamAlreadyClosed.
# ---------------------------------------------------------------------------


class TestLifecycleGuard:
    async def test_grant_after_end_raises_stream_already_closed(self) -> None:
        native = _FakeNative([_data(0, {"n": 1}), _end(1, {"n": 1})])
        handle = _invoke(native)
        await handle  # drain to End
        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(10))
        assert native.grant_calls == []

    async def test_cancel_after_end_raises_stream_already_closed(self) -> None:
        native = _FakeNative([_end(0, {"n": 1})])
        handle = _invoke(native)
        await handle
        with pytest.raises(StreamAlreadyClosed):
            await handle.cancel()
        assert native.cancel_calls == []

    async def test_grant_after_terminal_error_raises_stream_already_closed(self) -> None:
        native = _FakeNative([_error(0, "SCP-OUTLET-6130", "boom", terminal=True)])
        handle = _invoke(native)
        # Consume the terminal error chunk via iteration (observable), which
        # closes the stream without raising in the iterator.
        collected = [chunk async for chunk in handle]
        assert collected[-1].kind == "error"
        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(10))

    async def test_grant_after_end_via_iteration_raises(self) -> None:
        native = _FakeNative([_data(0, {"n": 0}), _end(1, {"n": 0})])
        handle = _invoke(native)
        _ = [chunk async for chunk in handle]
        with pytest.raises(StreamAlreadyClosed):
            await handle.cancel()


# ---------------------------------------------------------------------------
# Bridge-error translation: data-plane FFI rejections surface as SDK types.
# ---------------------------------------------------------------------------


class TestBridgeErrorTranslation:
    async def test_open_ucan_denial_surfaces_as_ucan_permission_error(self) -> None:
        native = _RaisingOpenNative(_bridge_exc("UcanError", "authorization denied"))
        handle = _invoke(native)
        with pytest.raises(UcanPermissionError):
            await handle  # aggregate() drains -> open() rejects

    async def test_open_schema_violation_surfaces_as_validation_error(self) -> None:
        native = _RaisingOpenNative(_bridge_exc("ValidationError", "input schema"))
        handle = _invoke(native)
        with pytest.raises(ValidationError):
            async for _chunk in handle:  # first __anext__ opens -> rejects
                pass

    async def test_poll_mid_drain_error_surfaces_as_sdk_type(self) -> None:
        # Stream one Data chunk, then the bridge rejects the next poll with a
        # ContextError (e.g. unknown handle / transport fault) mid-drain.
        native = _RaisingPollNative(
            [_data(0, {"n": 0})],
            _bridge_exc("ContextError", "no active stream"),
            fail_after=1,
        )
        handle = _invoke(native)
        with pytest.raises(ContextError):
            _ = [chunk async for chunk in handle]


# ---------------------------------------------------------------------------
# Concurrent-consumer guard: a second driver on the shared drain fails loud.
# ---------------------------------------------------------------------------


class TestConcurrentConsumer:
    async def test_second_concurrent_driver_raises_protocol_error(self) -> None:
        native = _FakeNative([_data(i, {"n": i}) for i in range(5)])
        handle = _invoke(native)

        # Start a first drive and let it reach its outstanding poll await.
        first = asyncio.ensure_future(handle.__anext__())
        await asyncio.sleep(0)  # yield so `first` sets _draining and suspends

        with pytest.raises(ProtocolError):
            await handle.__anext__()  # second concurrent driver -> loud failure

        await first  # let the legitimate first driver finish


# ---------------------------------------------------------------------------
# cancel() before first poll is a local no-op close (no stream open).
# ---------------------------------------------------------------------------


class TestCancelBeforeOpen:
    async def test_cancel_before_open_does_not_open_stream(self) -> None:
        native = _FakeNative([_data(0, {"n": 0}), _end(1, {"n": 0})])
        handle = _invoke(native)

        await handle.cancel()

        # No stream was opened and no bridge cancel was signed.
        assert native.open_calls == []
        assert native.cancel_calls == []
        # The handle is now closed: further control-plane calls are guarded.
        with pytest.raises(StreamAlreadyClosed):
            await handle.cancel()
        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(1))

    async def test_grant_credit_before_open_does_open_stream(self) -> None:
        # A grant needs a live stream, so grant_credit (unlike cancel) opens.
        native = _FakeNative([_end(0, {"n": 0})])
        handle = _invoke(native)
        await handle.grant_credit(Credit(2))
        assert len(native.open_calls) == 1
        assert native.grant_calls == [("stream-1", "did:dht:caller", 2)]


# ---------------------------------------------------------------------------
# Public-surface invariant: no public invoke_stream / invokeStream (SCP-OUT-006).
# ---------------------------------------------------------------------------


class TestPublicSurfaceInvariant:
    def test_no_public_invoke_stream_symbol(self) -> None:
        import scp_sdk
        import scp_sdk.outlets as outlets_mod

        assert not hasattr(scp_sdk, "invoke_stream")
        assert not hasattr(outlets_mod, "invoke_stream")
        assert not hasattr(InvocationHandle, "invoke_stream")
        # The public verb is invoke; poll_next/grant_credit are not free funcs.
        assert not hasattr(outlets_mod, "poll_next")
        assert not hasattr(outlets_mod, "grant_credit")

    def test_no_invoke_stream_token_in_bindings_sources(self) -> None:
        # Mirrors the SCP-OUT-006 grep AC:
        #   grep -rn 'invoke_stream\|invokeStream' bindings/ -> 0
        bindings = Path(__file__).resolve().parents[2]
        assert bindings.name == "bindings"
        assert bindings.is_dir()
        # The AC scopes the ban to the PUBLIC surface. Exempt (per the AC):
        #   - test files (reference the token in negative assertions),
        #   - generated / internal bridge wrappers the user never calls
        #     directly (Swift Internal/ScpBindings, TS internal/napi|wasm),
        #   - comment lines (a doc-comment naming the token is not a symbol).
        skip_parts = {
            "node_modules",
            "build",
            "tests",
            "Tests",
            ".build",
            "dist",
            "Internal",
            "internal",
        }
        comment_starts = ("#", "//", "*", "/*", '"', "'")
        offenders: list[str] = []
        for path in bindings.rglob("*"):
            if path.suffix not in {".py", ".ts", ".swift", ".kt"}:
                continue
            if skip_parts & set(path.parts):
                continue
            if path.name.startswith("test_") or path.name.endswith((".test.ts", "Tests.swift")):
                continue
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.lstrip()
                if stripped.startswith(comment_starts):
                    continue
                if "invoke_stream" in line or "invokeStream" in line:
                    offenders.append(f"{path}: {line.strip()}")
        assert offenders == [], f"public invoke_stream found in: {offenders}"


# ---------------------------------------------------------------------------
# AC6 conformance-vector smoke: each of the 7 cross-layer streaming vectors
# (tests/conformance/vectors/outlet_stream_vectors.json) drives the mock and
# asserts the SDK reaches the vector's expected terminal.
# ---------------------------------------------------------------------------

_VECTORS_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "conformance"
    / "vectors"
    / "outlet_stream_vectors.json"
)


def _load_vectors() -> dict[str, dict[str, Any]]:
    data = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
    return {v["name"]: v for v in data["vectors"]}


_VECTORS: dict[str, dict[str, Any]] = _load_vectors()

_EXPECTED_NAMES = frozenset(
    {
        "non_streaming",
        "multi_chunk",
        "cancellation",
        "error_terminal",
        "error_recoverable",
        "sequence_gap",
        "credit_stall",
    }
)


def _vector_chunks(vector: dict[str, Any]) -> list[bytes]:
    """Serialize a vector's chunk list into the mock's wire-byte playback."""
    return [_chunk(c["sequence"], c["payload"]) for c in vector["chunks"]]


def _end_aggregate(vector: dict[str, Any]) -> Any:
    for c in vector["chunks"]:
        if c["payload"].get("@type") == "end":
            return c["payload"]["aggregate"]
    return None


class TestConformanceVectorSmoke:
    """AC6: the 7 cross-layer streaming vectors -> the SDK's expected terminal.

    IMPORTANT boundary — where the terminal comes from:

    - ``credit_stall`` and ``cancellation`` surface a terminal the BRIDGE
      delivers. The mock plays a framework terminal (a ``terminal: true`` Error
      for the credit stall; a cancel-ack ``End`` after the consumer cancels)
      and the SDK faithfully surfaces ``poll_next``'s terminal — the SDK cannot
      itself stall an executor, so it does not synthesize these terminals.
    - ONLY ``sequence_gap`` requires ACTIVE SDK-side detection: the drain tracks
      the expected sequence, detects the hole ITSELF, signs the cancel through
      the bridge, and raises :class:`StreamGap`. The mock feeds NO pre-baked
      cancel-ack for that vector (that would be test-gaming) — the recorded
      cancel call proves the SDK generated it.
    """

    def test_vectors_cover_exactly_the_seven_names(self) -> None:
        assert set(_VECTORS) == _EXPECTED_NAMES

    async def test_non_streaming_ok(self) -> None:
        v = _VECTORS["non_streaming"]
        result = await _invoke(_FakeNative(_vector_chunks(v)))
        assert result.value == {"sum": 3}
        assert result.value == _end_aggregate(v)

    async def test_multi_chunk_ok(self) -> None:
        # multi_chunk interleaves a non-billable Progress chunk (§5.4.5): the SDK
        # drain FORWARDS it (surfaced, not filtered), the monotonicity cursor
        # advances across it, and the stream still closes Ok.
        v = _VECTORS["multi_chunk"]
        handle = _invoke(_FakeNative(_vector_chunks(v)))
        collected = [chunk async for chunk in handle]
        assert any(c.kind == "progress" for c in collected), (
            "the Progress chunk is yielded through the SDK drain"
        )
        assert collected[-1].kind == "end", "the stream closes Ok with End"
        result = await handle
        assert result.value == {"total": 10}
        assert result.value == _end_aggregate(v)

    async def test_error_recoverable_ok(self) -> None:
        # The non-terminal Error (seq1) is yielded as a chunk but does NOT
        # terminate; data seq2/seq3 then End seq4 close with Ok.
        v = _VECTORS["error_recoverable"]
        handle = _invoke(_FakeNative(_vector_chunks(v)))
        collected = [chunk async for chunk in handle]
        assert [c.kind for c in collected] == ["data", "error", "data", "data", "end"]
        assert collected[1].payload["terminal"] is False
        result = await handle
        assert result.value == _end_aggregate(v)

    async def test_error_terminal_raises_typed_error_6130(self) -> None:
        v = _VECTORS["error_terminal"]
        assert v["expected_error_code"] == "SCP-OUTLET-6130"
        with pytest.raises(OutletError) as excinfo:
            await _invoke(_FakeNative(_vector_chunks(v)))
        assert excinfo.value.code == "SCP-OUTLET-6130"

    async def test_credit_stall_raises_typed_error_6133(self) -> None:
        # Bridge-delivered terminal: mock plays data seq0 then a framework
        # Error seq1 {terminal:true, code 6133}. The SDK surfaces it faithfully.
        v = _VECTORS["credit_stall"]
        assert v["expected_error_code"] == "SCP-OUTLET-6133"
        with pytest.raises(OutletError) as excinfo:
            await _invoke(_FakeNative(_vector_chunks(v)))
        assert excinfo.value.code == "SCP-OUTLET-6133"

    async def test_cancellation_reaches_terminal(self) -> None:
        # Bridge-delivered terminal: consumer calls cancel() after chunk index 1;
        # the mock plays through to its cancel-ack End. The SDK records the cancel
        # and surfaces the bridge's terminal (Cancelled).
        v = _VECTORS["cancellation"]
        native = _FakeNative(_vector_chunks(v))
        handle = _invoke(native)
        idx = 0
        async for _chunk_seen in handle:
            if idx == 1:
                await handle.cancel()
            idx += 1
        assert native.cancel_calls == [("stream-1", "did:dht:caller")]
        assert idx == len(v["chunks"])
        result = await handle
        assert result.value == {"cancelled": True}

    async def test_sequence_gap_detected_signed_cancel_and_raises_6131(self) -> None:
        # ACTIVE SDK detection: mock plays data seq0, seq1, seq3 (seq2 MISSING).
        # The drain detects the gap at seq3, itself signs a cancel through the
        # bridge, and raises StreamGap(6131). NO pre-baked cancel-ack is fed.
        v = _VECTORS["sequence_gap"]
        assert v["expected_error_code"] == "SCP-OUTLET-6131"
        native = _FakeNative(_vector_chunks(v))
        handle = _invoke(native)
        with pytest.raises(StreamGap) as excinfo:
            await handle
        assert excinfo.value.code == "SCP-OUTLET-6131"
        # The SDK ITSELF signed the receiver cancel (not fed by the mock).
        assert native.cancel_calls == [("stream-1", "did:dht:caller")]
        # Terminal cache: the gap is sticky and control-plane is now guarded.
        with pytest.raises(StreamGap):
            await handle
        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(1))


class TestChunkParsing:
    def test_malformed_chunk_raises_outlet_error(self) -> None:
        with pytest.raises(OutletError):
            OutletStreamChunk._from_bridge_bytes(b"not json")

    def test_hex_string_request_id_accepted(self) -> None:
        raw = json.dumps(
            {
                "request_id": "aabb",
                "sequence": 0,
                "payload": {"@type": "data", "value": 1},
                "sig": "ccdd",
            }
        ).encode()
        chunk = OutletStreamChunk._from_bridge_bytes(raw)
        assert chunk.request_id == "aabb"
        assert chunk.signature == "ccdd"
        assert chunk.kind == "data"
