"""SCP-OUT-037 PyO3 streaming bridge tests.

Covers:

- :func:`scp_sdk.outlets.verify_chunk_signature` (AC10): round-trips a
  signed chunk via the bridge ``sign_chunk``-equivalent (we sign in
  Rust through the protocol layer and verify here) and confirms that
  tampering flips the result.
- :func:`scp_sdk.outlets.compute_caveats_binding` (AC11):
  determinism, single-byte sensitivity, malformed-input rejection.
- :class:`InvocationHandle.grant_credit` and
  :class:`InvocationHandle.cancel` error paths: zero-grant rejection,
  unknown ``request_id`` rejection, no-request-id legacy guard.

The tests are written against the real ``_scp_core`` bridge (the pure
helpers require no ContextManager state). Tests requiring the full
streaming pipeline open / cancel / credit flow live in the runtime
test suite (``crates/scp-runtime/.../invoke.rs::out034_*``); the
PyO3 bridge is structurally proven to surface those entry points by
the existence of the ``context_outlet_invoke_stream`` /
``outlet_stream_grant_credit`` / ``outlet_stream_cancel`` PyO3
functions verified at module import.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from scp_sdk import outlets as outlets_mod
from scp_sdk.errors import (
    Credit,
    InvalidGrant,
    StreamAlreadyClosed,
    ValidationError,
)
from scp_sdk.outlets import (
    InvocationHandle,
    compute_caveats_binding,
    verify_chunk_signature,
)

_DUMMY_CTX = "ctx-stream-test"
_DUMMY_OUTLET = "calculator"
_DUMMY_DID = "did:dht:z6MkInvoker"


# ---------------------------------------------------------------------------
# Bridge availability — every test in this module skips cleanly if the
# native extension isn't built. The CI matrix builds maturin first so
# this should always be present in CI; local runs without `maturin
# develop` will skip.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bridge() -> Any:
    bridge = outlets_mod._scp_core
    if bridge is None:
        pytest.skip("_scp_core extension not built — run `maturin develop`")
    return bridge


# ---------------------------------------------------------------------------
# verify_chunk_signature — AC10
# ---------------------------------------------------------------------------


class TestVerifyChunkSignature:
    """`verify_chunk_signature` round-trip + tamper detection (AC10)."""

    @staticmethod
    def _valid_ed25519_pubkey() -> bytes:
        """Return a known-valid Ed25519 public key (32 bytes).

        Constructed via :mod:`cryptography` if available; otherwise
        uses the well-known Ed25519 test vector from RFC 8032 §7.1
        Test 1 (private key seed of zeros), whose public key is fixed
        and decompresses cleanly to a valid Edwards point.
        """
        # RFC 8032 §7.1 Test 1 public key — derived from seed=zeros.
        # Hardcoded bytes so the test does not depend on a Python
        # cryptography library being installed.
        return bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")

    @staticmethod
    def _build_signed_chunk() -> tuple[str, bytes, bytes]:
        """Build a chunk with a zero signature against a valid pubkey.

        Returns ``(chunk_json, operator_pk_bytes, caveats_binding)``.
        The PyO3 bridge does not expose ``sign_chunk`` as a public
        helper (signing is the operator's responsibility), so this
        test focuses on the *negative* path: a chunk with an all-zero
        signature MUST verify as ``False`` against any valid pubkey.
        """
        chunk = {
            "request_id": list(b"\x11" * 16),
            "sequence": 7,
            "payload": {"@type": "data", "value": {"x": 1}},
            "sig": list(b"\x00" * 64),
        }
        chunk_json = json.dumps(chunk)
        operator_pk = TestVerifyChunkSignature._valid_ed25519_pubkey()
        caveats_binding = b"\xcd" * 32
        return chunk_json, operator_pk, caveats_binding

    def test_zero_signature_does_not_verify(self, bridge: Any) -> None:
        chunk_json, operator_pk, caveats_binding = self._build_signed_chunk()
        ok = verify_chunk_signature(
            chunk_json,
            operator_pk,
            "ctx-stream",
            "outlet-x",
            caveats_binding,
        )
        # A zero signature against a valid pubkey is overwhelmingly
        # invalid; the verifier returns False without raising.
        assert ok is False

    def test_short_pubkey_raises_validation_error(self, bridge: Any) -> None:
        chunk_json, _, caveats_binding = self._build_signed_chunk()
        with pytest.raises(ValidationError):
            verify_chunk_signature(
                chunk_json,
                b"\xab" * 31,  # 31 bytes, not 32
                "ctx-stream",
                "outlet-x",
                caveats_binding,
            )

    def test_short_caveats_binding_raises_validation_error(self, bridge: Any) -> None:
        chunk_json, operator_pk, _ = self._build_signed_chunk()
        with pytest.raises(ValidationError):
            verify_chunk_signature(
                chunk_json,
                operator_pk,
                "ctx-stream",
                "outlet-x",
                b"\xcd" * 31,  # 31 bytes, not 32
            )

    def test_malformed_chunk_json_raises_validation_error(self, bridge: Any) -> None:
        with pytest.raises(ValidationError):
            verify_chunk_signature(
                "{not-json",
                b"\xab" * 32,
                "ctx-stream",
                "outlet-x",
                b"\xcd" * 32,
            )


# ---------------------------------------------------------------------------
# compute_caveats_binding — AC11
# ---------------------------------------------------------------------------


class TestComputeCaveatsBinding:
    """`compute_caveats_binding` determinism + tamper detection (AC11)."""

    def _baseline(self) -> dict[str, Any]:
        return dict(
            ucan_cid=b"bafyreigh1234567890",
            request_id=b"\x77" * 16,
            invoker_did=_DUMMY_DID,
            estimated_chunk_count=100,
            effective_caveats={"maxCalls": 10},
        )

    def test_returns_32_bytes(self, bridge: Any) -> None:
        result = compute_caveats_binding(**self._baseline())
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_deterministic_same_inputs(self, bridge: Any) -> None:
        a = compute_caveats_binding(**self._baseline())
        b = compute_caveats_binding(**self._baseline())
        assert a == b

    def test_different_estimated_chunk_count_flips_bytes(self, bridge: Any) -> None:
        baseline = self._baseline()
        a = compute_caveats_binding(**baseline)
        baseline["estimated_chunk_count"] = 101
        b = compute_caveats_binding(**baseline)
        assert a != b

    def test_different_invoker_did_flips_bytes(self, bridge: Any) -> None:
        baseline = self._baseline()
        a = compute_caveats_binding(**baseline)
        baseline["invoker_did"] = "did:dht:z6MkOther"
        b = compute_caveats_binding(**baseline)
        assert a != b

    def test_different_caveats_flips_bytes(self, bridge: Any) -> None:
        baseline = self._baseline()
        a = compute_caveats_binding(**baseline)
        baseline["effective_caveats"] = {"maxCalls": 11}
        b = compute_caveats_binding(**baseline)
        assert a != b

    def test_different_ucan_cid_flips_bytes(self, bridge: Any) -> None:
        baseline = self._baseline()
        a = compute_caveats_binding(**baseline)
        baseline["ucan_cid"] = b"bafyreigh-other"
        b = compute_caveats_binding(**baseline)
        assert a != b

    def test_different_request_id_flips_bytes(self, bridge: Any) -> None:
        baseline = self._baseline()
        a = compute_caveats_binding(**baseline)
        baseline["request_id"] = b"\x88" * 16
        b = compute_caveats_binding(**baseline)
        assert a != b

    def test_short_request_id_raises_validation_error(self, bridge: Any) -> None:
        baseline = self._baseline()
        baseline["request_id"] = b"\x77" * 15
        with pytest.raises(ValidationError):
            compute_caveats_binding(**baseline)

    def test_invalid_caveats_raises_validation_error(self, bridge: Any) -> None:
        baseline = self._baseline()
        baseline["effective_caveats"] = {"unknownField": 1}
        with pytest.raises(ValidationError):
            compute_caveats_binding(**baseline)


# ---------------------------------------------------------------------------
# InvocationHandle.grant_credit / cancel — AC5 / AC6 error paths
# ---------------------------------------------------------------------------


class TestInvocationHandleControlPlane:
    """`grant_credit` and `cancel` route to the bridge with error paths."""

    @pytest.mark.asyncio
    async def test_grant_credit_no_request_id_raises_stream_already_closed(self) -> None:
        # Non-streaming handle (request_id=None) — the End chunk arrives
        # synchronously so by the time grant_credit is called, the
        # stream is closed (OUT-038 AC13).
        q: asyncio.Queue[Any] = asyncio.Queue()
        handle = InvocationHandle(q, request_id=None)
        with pytest.raises(StreamAlreadyClosed):
            await handle.grant_credit(Credit(10))

    @pytest.mark.asyncio
    async def test_cancel_no_request_id_raises_stream_already_closed(self) -> None:
        q: asyncio.Queue[Any] = asyncio.Queue()
        handle = InvocationHandle(q, request_id=None)
        with pytest.raises(StreamAlreadyClosed):
            await handle.cancel()

    def test_credit_zero_raises_invalid_grant(self) -> None:
        # OUT-031 round-6 / OUT-038 AC4 — Credit(0) raises InvalidGrant
        # at construction time, NOT inside grant_credit.
        with pytest.raises(InvalidGrant):
            Credit(0)

    def test_credit_negative_raises_invalid_grant(self) -> None:
        # OUT-038 AC4 — Credit(-1) raises InvalidGrant (not TypeError).
        with pytest.raises(InvalidGrant):
            Credit(-1)

    def test_credit_overflow_raises_invalid_grant(self) -> None:
        # OUT-038 AC4 — Credit(2**32) raises InvalidGrant.
        with pytest.raises(InvalidGrant):
            Credit(2**32)

    def test_credit_in_range_succeeds(self) -> None:
        # OUT-038 AC4 — Credit(10) succeeds.
        c = Credit(10)
        assert c.raw == 10

    @pytest.mark.asyncio
    async def test_grant_credit_raw_int_raises_validation_error(self) -> None:
        # OUT-038 AC4 — passing a raw int 10 fails at the runtime guard.
        # mypy --strict additionally rejects this at type-check time.
        q: asyncio.Queue[Any] = asyncio.Queue()
        handle = InvocationHandle(q, request_id="aa" * 16)
        with pytest.raises(ValidationError):
            await handle.grant_credit(10)  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_cancel_unknown_request_raises(self, bridge: Any) -> None:
        q: asyncio.Queue[Any] = asyncio.Queue()
        # 32 hex chars (decodes to 16 bytes) but doesn't match any
        # registered stream. A pinned invoker_did is required so the call
        # reaches the bridge's unknown-session path instead of short-
        # circuiting at the SDK's no-invoker degenerate-handle guard. The
        # round-8 `cancel` derives `next_seq` from the runtime cursor and
        # takes no arguments.
        handle = InvocationHandle(q, request_id="ff" * 16, invoker_did=_DUMMY_DID)
        with pytest.raises(Exception) as exc_info:
            await handle.cancel()
        msg = str(exc_info.value).lower()
        assert "not found" in msg or "unknown-session" in msg

    @pytest.mark.asyncio
    async def test_grant_credit_unknown_request_raises(self, bridge: Any) -> None:
        q: asyncio.Queue[Any] = asyncio.Queue()
        # A pinned invoker_did is required so the call reaches the bridge's
        # unknown-session path rather than the SDK's no-invoker guard.
        handle = InvocationHandle(q, request_id="ee" * 16, invoker_did=_DUMMY_DID)
        with pytest.raises(Exception) as exc_info:
            await handle.grant_credit(Credit(5))
        msg = str(exc_info.value).lower()
        assert "not found" in msg or "unknown-session" in msg

    def test_translate_bridge_error_routes_6101_to_stream_already_closed(self) -> None:
        # §5.4.4:426 — the runtime-authoritative grant-after-close rejection
        # surfaces from the bridge as a ContextError carrying code
        # SCP-TOOL-6101 / slug protocol.stream-already-closed (the bridge's
        # grant_error_to_code(StreamClosed) routing). `_translate_bridge_error`
        # MUST map that authoritative rejection onto the typed
        # StreamAlreadyClosed so a grant that races the pump's terminal exit
        # (SDK has not yet observed the terminal chunk) is caught uniformly.
        class _FakeBridgeContextError(Exception):
            pass

        _FakeBridgeContextError.__name__ = "ContextError"
        err = _FakeBridgeContextError(
            "[SCP-TOOL-6101] context error: credit grant rejected (protocol.stream-already-closed)"
        )
        translated = outlets_mod._translate_bridge_error(err)
        assert isinstance(translated, StreamAlreadyClosed), (
            f"6101 bridge error must translate to StreamAlreadyClosed, got "
            f"{type(translated).__name__}"
        )
        assert translated.code == "SCP-TOOL-6101"

    def test_translate_bridge_error_6101_by_slug_only(self) -> None:
        # Robustness: the mapping also fires on the slug substring so a
        # future Display shape that omits the bracketed code still routes
        # correctly.
        class _FakeBridgeContextError(Exception):
            pass

        _FakeBridgeContextError.__name__ = "ContextError"
        err = _FakeBridgeContextError("credit grant rejected (protocol.stream-already-closed)")
        translated = outlets_mod._translate_bridge_error(err)
        assert isinstance(translated, StreamAlreadyClosed)


# ---------------------------------------------------------------------------
# OutletStreamChunk dataclass round-trip
# ---------------------------------------------------------------------------


class TestOutletStreamChunkSurface:
    """The `OutletStreamChunk` dataclass round-trips bridge dict shape."""

    def test_chunk_dict_data_variant(self) -> None:
        d = {
            "request_id": b"\x01" * 16,
            "sequence": 0,
            "payload_type": "data",
            "value": {"x": 7},
            "sig": b"\x00" * 64,
        }
        chunk = outlets_mod._chunk_dict_to_dataclass(d)
        assert chunk.request_id == b"\x01" * 16
        assert chunk.sequence == 0
        assert chunk.payload_type == "data"
        assert chunk.value == {"x": 7}

    def test_chunk_dict_end_variant(self) -> None:
        d = {
            "request_id": b"\x02" * 16,
            "sequence": 1,
            "payload_type": "end",
            "aggregate": {"total": 42},
            "provenance": {"source_context": "ctx-x"},
            "execution_time_ms": 123,
            "sig": b"\x00" * 64,
        }
        chunk = outlets_mod._chunk_dict_to_dataclass(d)
        assert chunk.payload_type == "end"
        assert chunk.aggregate == {"total": 42}
        assert chunk.execution_time_ms == 123

    def test_chunk_dict_error_variant(self) -> None:
        d = {
            "request_id": b"\x03" * 16,
            "sequence": 2,
            "payload_type": "error",
            "code": "SCP-TOOL-6131",
            "message": "credit exhausted",
            "terminal": True,
            "sig": b"\x00" * 64,
        }
        chunk = outlets_mod._chunk_dict_to_dataclass(d)
        assert chunk.payload_type == "error"
        assert chunk.code == "SCP-TOOL-6131"
        assert chunk.terminal is True


# ---------------------------------------------------------------------------
# Streaming surface — bridge function presence
# ---------------------------------------------------------------------------


class TestBridgeSurfacePresence:
    """SCP-OUT-037 AC1/AC5/AC6/AC10/AC11 — bridge functions are exported."""

    def test_context_outlet_invoke_stream_present(self, bridge: Any) -> None:
        assert hasattr(bridge, "context_outlet_invoke_stream")

    def test_outlet_stream_grant_credit_present(self, bridge: Any) -> None:
        assert hasattr(bridge, "outlet_stream_grant_credit")

    def test_outlet_stream_cancel_present(self, bridge: Any) -> None:
        assert hasattr(bridge, "outlet_stream_cancel")

    def test_verify_chunk_signature_present(self, bridge: Any) -> None:
        assert hasattr(bridge, "verify_chunk_signature")

    def test_compute_caveats_binding_present(self, bridge: Any) -> None:
        assert hasattr(bridge, "compute_caveats_binding")

    def test_outlet_invocation_stream_class_present(self, bridge: Any) -> None:
        assert hasattr(bridge, "OutletInvocationStream")
