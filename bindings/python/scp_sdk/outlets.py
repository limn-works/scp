"""Outlet-related dataclasses, namespaces, and InvocationHandle for the SCP Python SDK.

This module exposes the :class:`OutletNamespace` class that is mounted
on :class:`~scp_sdk.context.Context` as ``ctx.outlets``. The namespace
provides the full outlet verb set plus two sub-namespaces:

- ``ctx.outlets.sessions`` — stateful outlet sessions (§6.2.1.1)
- ``ctx.outlets.offers``   — cross-context outlet interface offers
  (formerly ``interface_*``; §6.2.0.1)

Key types
---------

- :class:`OutletDefinition` — registration metadata (name, schemas, operator, …).
- :class:`OutletCost` — per-invocation cost (§5.4.1).
- :class:`TestVector`  — expected input/output pairs for outlet verification.
- :class:`SessionId` — UUIDv7 newtype for :class:`OutletSessionsNamespace` APIs.
- :class:`InvocationHandle` — dual-mode consumer: ``await`` aggregates,
  ``async for`` iterates chunks.
- :class:`OutletStreamChunk` — per-chunk payload emitted during streaming
  invocation (§5.4.5).
- :class:`InvocationCaveats` — 11-field narrowed-UCAN caveat record (§7.3.8).
- :class:`InvokeCrossContextOptions` — dataclass wrapping the four
  target/outlet_id/input/ucan parameters with keyword-only invocation
  (API MAJOR 22).

This module replaces the legacy ``tools.py`` module (pre-rename).
Error codes remain ``SCP-TOOL-*`` per §9.18 (registered namespace).
"""

from __future__ import annotations

import asyncio
import enum
import json
import re
import secrets
import time
from collections.abc import Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NewType

from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    ContextError,
    Credit,
    OutletError,
    OutletExecutionError,
    OutletNotFoundError,
    OutletProtocolError,
    OutputError,
    RetryPolicy,
    StreamAlreadyClosed,
    ValidationError,
)

if TYPE_CHECKING:
    from scp_sdk.identity import Identity

try:
    import _scp_core  # type: ignore[import-not-found]
except ImportError:
    _scp_core = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# SessionId newtype (API MAJOR 28) — distinct from OutletId/str.
# ---------------------------------------------------------------------------

SessionId = NewType("SessionId", str)


#: 10-minute clock-skew tolerance window (§9.14).
_UUID7_SKEW_TOLERANCE_MS: int = 10 * 60 * 1000

#: Canonical UUID v7 regex (8-4-4-4-12 lowercase hex; version nibble 7; variant bits 10).
_UUID7_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _validate_session_id(raw: str, *, now_ms: int | None = None) -> None:
    """Validate that ``raw`` is a canonical UUIDv7 (per §6.2.1.1(a))."""
    if not isinstance(raw, str):
        raise ValidationError(
            f"SessionId must be str, got {type(raw).__name__}",
            code="SCP-VALID-7010",
        )
    if not _UUID7_RE.match(raw):
        raise ValidationError(
            f"SessionId must be a canonical UUIDv7 (8-4-4-4-12 lowercase hex, "
            f"version 7, variant 10); got {raw!r}",
            code="SCP-VALID-7010",
        )
    ts_hex = raw[0:8] + raw[9:13]
    ts_ms = int(ts_hex, 16)
    current_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    if ts_ms < current_ms - _UUID7_SKEW_TOLERANCE_MS:
        raise ValidationError(
            f"SessionId timestamp {ts_ms} is more than 10 minutes in the past (now {current_ms})",
            code="SCP-VALID-7010",
        )
    if ts_ms > current_ms + _UUID7_SKEW_TOLERANCE_MS:
        raise ValidationError(
            f"SessionId timestamp {ts_ms} is more than 10 minutes in the future (now {current_ms})",
            code="SCP-VALID-7010",
        )


def new_session_id() -> SessionId:
    """Generate a UUIDv7-format SessionId from a CSPRNG source."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = secrets.token_bytes(10)
    b = bytearray(16)
    b[0] = (ts_ms >> 40) & 0xFF
    b[1] = (ts_ms >> 32) & 0xFF
    b[2] = (ts_ms >> 24) & 0xFF
    b[3] = (ts_ms >> 16) & 0xFF
    b[4] = (ts_ms >> 8) & 0xFF
    b[5] = ts_ms & 0xFF
    b[6] = 0x70 | (rand_bytes[0] & 0x0F)
    b[7] = rand_bytes[1]
    b[8] = 0x80 | (rand_bytes[2] & 0x3F)
    b[9] = rand_bytes[3]
    b[10:16] = rand_bytes[4:10]
    hex_str = b.hex()
    raw = f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"
    return SessionId(raw)


# ---------------------------------------------------------------------------
# OutletKind — outlet semantic class (Query vs Action), SCP-OUT-017.
# ---------------------------------------------------------------------------


class OutletKind(enum.Enum):
    """Outlet semantic class (§5.4.2).

    ``Query`` outlets are read-only and idempotent (UCAN stem
    ``outlet_query:{id}``); ``Action`` outlets may mutate state (UCAN stem
    ``outlet_call:{id}``).

    Required at the SDK surface across all 4 bindings (SCP-OUT-017).
    Crosses the bridge boundary as the lowercase string ``"query"`` /
    ``"action"`` matching the §5.4.2 wire vocabulary.
    """

    Query = "query"
    Action = "action"

    @classmethod
    def parse(cls, value: OutletKind | str) -> OutletKind:
        """Coerce ``value`` to an :class:`OutletKind` instance.

        Accepts an existing :class:`OutletKind` (returned unchanged) or
        the lowercase string ``"query"`` / ``"action"`` matching the
        §5.4.2 wire vocabulary. Other values raise
        :class:`ValidationError`.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value)
            except ValueError as exc:
                raise ValidationError(
                    f"OutletKind must be 'query' or 'action' (§5.4.2 wire vocabulary), "
                    f"got {value!r}",
                    code="SCP-VALID-7050",
                ) from exc
        raise ValidationError(
            f"OutletKind must be an OutletKind or str, got {type(value).__name__}",
            code="SCP-VALID-7050",
        )


# ---------------------------------------------------------------------------
# OutletDefinition / TestVector / OutletCost
# ---------------------------------------------------------------------------


@dataclass
class TestVector:
    """A single test vector for outlet verification (§5.4.1)."""

    input: dict[str, Any]
    expected_output: dict[str, Any]
    description: str = ""


@dataclass
class OutletCost:
    """Per-invocation cost metadata for an outlet (§5.4.1)."""

    amount: int
    currency: str
    payee: str
    cost_formula: str | None = None


@dataclass(kw_only=True)
class OutletDefinition:
    """Definition of an outlet registered in an SCP context (§5.4.1).

    ``kind`` is REQUIRED — there is no default. Per SCP-OUT-017, all 4
    SDKs surface :class:`OutletKind` as a required parameter; passing a
    definition without ``kind`` raises :class:`TypeError` from the
    dataclass machinery (the dataclass is keyword-only).
    """

    name: str
    description: str
    kind: OutletKind
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    operator: Identity | str | None
    test_vectors: list[TestVector] | None = None
    implementation_hash: bytes | None = None
    cost: OutletCost | None = None


# ---------------------------------------------------------------------------
# Streaming types (§5.4.5) — SDK-layer definitions.
# ---------------------------------------------------------------------------


@dataclass
class OutletStreamChunk:
    """One chunk of a streamed outlet invocation (§5.4.5)."""

    request_id: bytes
    sequence: int
    payload_type: str
    value: Any | None = None
    pct: int | None = None
    note: str | None = None
    aggregate: Any | None = None
    provenance: dict[str, Any] | None = None
    execution_time_ms: int | None = None
    code: str | None = None
    message: str | None = None
    terminal: bool | None = None


@dataclass
class Aggregate:
    """The collected aggregate returned by awaiting an :class:`InvocationHandle`."""

    value: Any
    provenance: dict[str, Any] | None = None
    execution_time_ms: int | None = None


# ---------------------------------------------------------------------------
# InvocationCaveats (§7.3.8) — SDK-layer definition.
# ---------------------------------------------------------------------------


@dataclass
class InvocationCaveats:
    """Narrowed UCAN invocation caveats (§7.3.8, 11 fields)."""

    amount_max_per_call: int | None = None
    amount_max_cumulative: int | None = None
    valid_from: int | None = None
    valid_until: int | None = None
    hours_of_day: int | None = None
    days_of_week: int | None = None
    max_calls: int | None = None
    rate_window: int | None = None
    input_schema: dict[str, Any] | None = None
    allowed_adapters: list[str] | None = None
    allowed_target_dids: list[str] | None = None
    origin_kind: str | None = None


# ---------------------------------------------------------------------------
# InvokeCrossContextOptions — keyword-only dataclass (API MAJOR 22).
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class InvokeCrossContextOptions:
    """Options for :meth:`OutletNamespace.invoke_cross_context` (API MAJOR 22)."""

    target: str
    outlet_id: str
    input: dict[str, Any]
    ucan: str
    chain_depth: int = 0
    proof_tokens: list[str] | None = None


# ---------------------------------------------------------------------------
# Bridge error translation helper.
# ---------------------------------------------------------------------------


def _translate_bridge_error(exc: Exception) -> Exception:
    """Translate a ``_scp_core`` bridge exception to an SDK exception."""
    sdk_cls = BRIDGE_ERROR_MAP.get(type(exc).__name__, ContextError)
    message = str(exc)
    # Pre-OUT-031: ``OutletError`` was a concrete class; the bridge mapped
    # ``ToolError`` and ``OutletError`` here. Post-OUT-031 ``OutletError`` is
    # abstract and the map points at ``OutletProtocolError``. Walk the issubclass
    # chain so the legacy ``not found`` / ``execution`` heuristics keep firing.
    if isinstance(sdk_cls, type) and issubclass(sdk_cls, OutletError):
        lowered = message.lower()
        if "not found" in lowered:
            return OutletNotFoundError(message)
        if "execution" in lowered or "failed" in lowered:
            return OutletExecutionError(message)
    return sdk_cls(message)


def _require_bridge() -> Any:
    if _scp_core is None:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        )
    return _scp_core


def outlet_catalog_rotation_validator(
    *,
    prior_catalog: list[dict[str, Any]],
    new_catalog: list[dict[str, Any]],
    prior_append_time_secs: int,
    new_append_time_secs: int,
) -> None:
    """SCP-OUT-041d catalog-rotation dwell-time validator (Python SDK).

    Calls the PyO3 ``outlet_catalog_rotation_validator`` bridge — pure
    function, requires no context state. Returns ``None`` on success;
    raises :class:`OutletProtocolError` (the typed
    ``CatalogRotationTooFrequent`` rejection) when the new registration
    is within the §5.4.4 round-5 24-hour dwell floor of the prior.

    Args:
        prior_catalog: Prior registration's ``message_catalog`` as a
            list of ``{"key": str, "template": str}`` dicts (matches the
            Rust ``MessageTemplate`` JSON shape).
        new_catalog: New registration's ``message_catalog`` (same
            shape). The validator is silent when it equals
            ``prior_catalog`` (catalog unchanged).
        prior_append_time_secs: Prior registration's event-log append
            time, in Unix seconds.
        new_append_time_secs: Prospective new registration append time,
            in Unix seconds.

    Raises:
        OutletProtocolError: ``CatalogRotationTooFrequent`` rejection.
    """
    import json as _json

    bridge = _require_bridge()
    envelope_json = bridge.outlet_catalog_rotation_validator(
        _json.dumps(prior_catalog),
        _json.dumps(new_catalog),
        int(prior_append_time_secs),
        int(new_append_time_secs),
    )
    if envelope_json == "":
        return
    envelope = _json.loads(envelope_json)
    raise OutletError.from_wire(envelope)


# ---------------------------------------------------------------------------
# Streaming bridge helpers (SCP-OUT-037).
# ---------------------------------------------------------------------------


def verify_chunk_signature(
    chunk_json: str,
    operator_pk: bytes,
    context_id: str,
    outlet_id: str,
    caveats_binding: bytes,
) -> bool:
    """Verify a chunk's ``SCP-OUTLET-CHUNK-SIG-V1:`` signature.

    Pure helper — exposes the §5.4.5 per-chunk signature verifier
    (SCP-OUT-037 AC10). ``chunk_json`` is the JSON serialisation of a
    full :data:`OutletStreamChunk`; the bridge round-trips it through
    the typed wire form so the verification path covers exactly the
    bytes the operator signed.

    Returns ``True`` when the signature is valid for the supplied
    preimage components, ``False`` otherwise (including malformed
    signatures, bad canonicalisation, or any preimage tamper).

    Raises :class:`ValidationError` on malformed inputs (non-32-byte
    public key / caveats_binding, malformed JSON).
    """
    bridge = _require_bridge()
    try:
        return bool(
            bridge.verify_chunk_signature(
                chunk_json,
                operator_pk,
                context_id,
                outlet_id,
                caveats_binding,
            )
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc


def compute_caveats_binding(
    *,
    ucan_cid: bytes,
    request_id: bytes,
    invoker_did: str,
    estimated_chunk_count: int,
    effective_caveats: dict[str, Any],
) -> bytes:
    """Compute the §5.4.5 32-byte ``caveats_binding`` (SCP-OUT-037 AC11).

    Hashes the ``SCP-OUTLET-CAVEAT-BIND-V1:`` preimage block byte-for-
    byte: ``len_be32(ucan_cid) || ucan_cid || request_id ||
    len_be32(invoker_did) || invoker_did ||
    estimated_chunk_count_be || len_be32(canonical_jcs(caveats)) ||
    canonical_jcs(caveats)``. The bridge runs RFC 8785 JCS over
    ``effective_caveats`` (with the round-5 omit-none convention) so
    SDK callers do not need an in-language JCS implementation.

    Args:
        ucan_cid: CID of the opening UCAN.
        request_id: 16-byte stream ``request_id``.
        invoker_did: Invoker DID string.
        estimated_chunk_count: Invoker-declared upper bound on
            billable chunks (``u32``).
        effective_caveats: Dict matching the
            :class:`InvocationCaveats` JSON shape (camelCase keys).

    Returns:
        32-byte SHA-256 hash.
    """
    if len(request_id) != 16:
        raise ValidationError(
            f"request_id must be exactly 16 bytes, got {len(request_id)}",
            code="SCP-VALID-7000",
        )
    bridge = _require_bridge()
    try:
        result = bridge.compute_caveats_binding(
            ucan_cid,
            request_id,
            invoker_did,
            int(estimated_chunk_count),
            json.dumps(effective_caveats),
        )
    except Exception as exc:
        raise _translate_bridge_error(exc) from exc
    return bytes(result)


def _native_anext_blocking(stream_obj: Any) -> Any:
    """Synchronously drive one step of the native PyO3 async iterator.

    ``stream_obj`` is an ``OutletInvocationStream`` instance whose
    ``__anext__`` returns a Python coroutine — but in our case the
    bridge implementation is built against ``block_on`` so the
    coroutine resolves immediately. We invoke ``__anext__`` in a
    worker thread (via :func:`asyncio.to_thread` from the caller),
    catch ``StopAsyncIteration``, and return ``None`` to signal
    completion.
    """
    try:
        return stream_obj.__anext__()
    except StopAsyncIteration:
        return None


def _chunk_dict_to_dataclass(d: dict[str, Any]) -> OutletStreamChunk:
    """Translate a bridge-emitted chunk dict to :class:`OutletStreamChunk`.

    The bridge already builds variant-specific dicts (see
    ``chunk_to_py_dict`` in ``crates/scp-ffi/src/outlet_stream.rs``).
    This helper maps each variant onto the dataclass fields the SDK
    expects.
    """
    return OutletStreamChunk(
        request_id=bytes(d["request_id"]),
        sequence=int(d["sequence"]),
        payload_type=d["payload_type"],
        value=d.get("value"),
        pct=d.get("pct"),
        note=d.get("note"),
        aggregate=d.get("aggregate"),
        provenance=d.get("provenance"),
        execution_time_ms=d.get("execution_time_ms"),
        code=d.get("code"),
        message=d.get("message"),
        terminal=d.get("terminal"),
    )


# ---------------------------------------------------------------------------
# InvocationHandle — dual consumption (await aggregate / async for chunks).
# ---------------------------------------------------------------------------


class InvocationHandle:
    """Handle returned by :meth:`OutletNamespace.invoke`.

    Supports BOTH consumption styles (API MAJOR 21):

    * ``aggregate = await handle`` — awaits the stream to completion and
      returns the :class:`Aggregate` carried by the terminal ``end`` chunk.
    * ``async for chunk in handle:`` — yields :class:`OutletStreamChunk`
      instances as they arrive.

    The two styles are mutually exclusive per handle: once one is chosen,
    the other raises :class:`OutletProtocolError` (slug
    ``protocol.handle-double-consumed``, code ``SCP-TOOL-6020``) — the
    Protocol-class shape converged across all four SDKs.

    SCP-OUT-038 control plane: every handle exposes
    :meth:`grant_credit` and :meth:`cancel`. When a handle was opened
    against the §5.4.5 streaming bridge it carries a real ``request_id``
    and the control-plane methods route to the bridge. When the handle
    represents a degenerate single-shot invocation (no streaming bridge
    open), the stream "ends" immediately on construction so the
    control-plane methods raise :class:`StreamAlreadyClosed` per AC13.

    Lifecycle guard (AC13): once the stream has emitted a terminal
    chunk (``End`` or ``Error{terminal: true}``) — observable either
    via the iterator or via ``await`` — subsequent calls to
    :meth:`grant_credit` / :meth:`cancel` raise
    :class:`StreamAlreadyClosed`.
    """

    def __init__(
        self,
        chunks: asyncio.Queue[OutletStreamChunk | BaseException | None],
        *,
        request_id: str | None = None,
        invoker_did: str | None = None,
        aggregate_schema: dict[str, Any] | None = None,
    ) -> None:
        self._chunks = chunks
        self._consumed: str | None = None
        self._request_id = request_id
        # CRITICAL #1 fix — pinned invoker DID, threaded through to
        # every control-plane bridge call as ``caller_did`` so the
        # bridge can verify against its registry's pinned identity.
        self._invoker_did = invoker_did
        self._aggregate_schema = aggregate_schema
        # Terminal-chunk observed: set once an End / Error{terminal:true}
        # chunk passes through the iterator or the aggregate await path.
        # AC13 lifecycle guard rejects grant_credit / cancel after this.
        self._terminated = False

    @property
    def request_id(self) -> str | None:
        """Hex-encoded §5.4.5 16-byte ``request_id`` for this stream.

        ``None`` for handles backed by the non-streaming bridge.
        """
        return self._request_id

    @property
    def is_terminated(self) -> bool:
        """``True`` once a terminal chunk has been observed.

        Tracked so :meth:`grant_credit` / :meth:`cancel` can fail-fast
        with :class:`StreamAlreadyClosed` per OUT-038 AC13 rather than
        round-tripping the bridge for a known-dead session.
        """
        return self._terminated

    def _guard(self, mode: str) -> None:
        if self._consumed is not None and self._consumed != mode:
            # Dual-consumption guard — a handle backed by a single
            # underlying source cannot be drained as BOTH ``await handle``
            # (aggregate) and ``async for chunk in handle`` (stream). The
            # cross-SDK convergence target (Kotlin reference, OUT-038 AC13
            # lifecycle-under-Protocol) is the Protocol-class shape: code
            # ``SCP-TOOL-6020``, slug ``protocol.handle-double-consumed``.
            # Round-5/6 chose ``OutletProtocolError`` (the §5.4.4
            # Protocol-class type) over the generic ``ContextError`` so all
            # four SDKs raise the same class for this condition.
            raise OutletProtocolError(
                f"InvocationHandle already consumed as {self._consumed}; cannot switch to {mode}",
                code="SCP-TOOL-6020",
                slug="protocol.handle-double-consumed",
                retry=RetryPolicy.never(),
            )
        self._consumed = mode

    def __await__(self) -> Generator[Any, None, Aggregate]:
        self._guard("aggregate")
        return self._await_aggregate().__await__()

    async def _await_aggregate(self) -> Aggregate:
        while True:
            item = await self._chunks.get()
            if isinstance(item, BaseException):
                # Rethrowing terminates the stream from the awaiter's
                # perspective — record terminal so the control-plane
                # lifecycle guard fires on subsequent grant_credit /
                # cancel calls.
                self._terminated = True
                raise item
            if item is None:
                # Abnormal closure — the pump pushed `None` (end-of-
                # queue sentinel) BEFORE any terminal chunk was observed.
                # The bridge receiver closed without the executor
                # emitting `End` / `Error{terminal:true}` (transport
                # drop, executor crash, bridge fault). Surface as
                # `execution.stream-gap` (`SCP-TOOL-6131`) per §5.4.4
                # instead of returning a degenerate `Aggregate(None)`
                # that would let a caller mistake a stream gap for a
                # successful aggregate-null outcome.
                self._terminated = True
                raise OutletExecutionError(
                    "stream closed without terminal chunk",
                    code="SCP-TOOL-6131",
                )
            if item.payload_type == "end":
                self._terminated = True
                self._validate_aggregate_against_schema(item.aggregate)
                return Aggregate(
                    value=item.aggregate,
                    provenance=item.provenance,
                    execution_time_ms=item.execution_time_ms,
                )
            if item.payload_type == "error":
                if item.terminal:
                    self._terminated = True
                raise OutletExecutionError(
                    item.message or "outlet execution failed",
                    code=item.code or "SCP-TOOL-6200",
                )

    def _validate_aggregate_against_schema(self, aggregate_value: Any) -> None:
        """Validate End.aggregate against the registered aggregate_schema.

        Per §5.4.5 the End chunk's aggregate must conform to the
        outlet's ``aggregate_schema``. The bridge already pinned the
        schema at registration; the SDK enforces it on the receive side
        as defense in depth so a malformed aggregate is surfaced as
        :class:`OutputError` rather than silently propagating to caller.

        No-op when no schema is bound to the handle (``aggregate_schema
        is None``) — the End chunk is forwarded unchanged.
        """
        if self._aggregate_schema is None:
            return
        try:
            import jsonschema
        except ImportError:
            # `jsonschema` is a soft dep; if missing we surface a clear
            # OutputError so the SDK developer knows to install it.
            raise OutputError(
                "aggregate_schema validation requires the 'jsonschema' package; "
                "install scp_sdk[validation] to enable",
                code="SCP-TOOL-6140",
            ) from None
        try:
            jsonschema.validate(instance=aggregate_value, schema=self._aggregate_schema)
        except jsonschema.ValidationError as exc:
            raise OutputError(
                f"End.aggregate does not match aggregate_schema: {exc.message}",
                code="SCP-TOOL-6140",
            ) from exc

    def __aiter__(self) -> InvocationHandle:
        self._guard("stream")
        return self

    async def __anext__(self) -> OutletStreamChunk:
        item = await self._chunks.get()
        if isinstance(item, BaseException):
            self._terminated = True
            raise item
        if item is None:
            # Clean end-of-iteration vs. abnormal closure:
            # - If a terminal chunk (End / Error{terminal:true}) was
            #   already yielded, `self._terminated` is True and this
            #   `None` is the normal end-of-queue marker — raise
            #   `StopAsyncIteration` per the iterator protocol.
            # - Otherwise the bridge receiver closed without the
            #   executor ever emitting a terminal chunk; surface as
            #   `execution.stream-gap` (`SCP-TOOL-6131`) per §5.4.4 so
            #   the caller sees a real error, not silent completion.
            if self._terminated:
                raise StopAsyncIteration
            self._terminated = True
            raise OutletExecutionError(
                "stream closed without terminal chunk",
                code="SCP-TOOL-6131",
            )
        if item.payload_type == "end":
            # AC2 / AC14: End is observable as a chunk in the iterator
            # (yielded as part of the 11-chunk count for 10 Data + End).
            # Mark terminated so subsequent control-plane calls fail.
            self._terminated = True
            self._validate_aggregate_against_schema(item.aggregate)
            return item
        if item.payload_type == "error" and item.terminal:
            self._terminated = True
            return item
        return item

    async def grant_credit(self, grant: Credit) -> int:
        """Issue an additional credit grant against the stream (§5.4.5).

        Internally constructs a signed ``OutletStreamCredit`` per
        ``SCP-OUTLET-CREDIT-V1:`` (the bridge handles signing under the
        invoker's pinned key) and forwards it to the runtime via
        ``outlet_stream_grant_credit``. ``grant`` MUST be a typed
        :class:`Credit` instance — passing a raw ``int`` fails at
        ``mypy --strict`` per OUT-031 round-6.

        Raises :class:`StreamAlreadyClosed` (OUT-038 AC13) when the
        stream has already terminated. Raises :class:`InvalidGrant`
        when the supplied :class:`Credit` was constructed with
        ``raw <= 0`` or ``raw > 2**32 - 1`` (defense-in-depth — the
        :class:`Credit` constructor already enforces this).

        Returns the new running credit total reported by the runtime.
        """
        if not isinstance(grant, Credit):
            # Defense-in-depth runtime guard. Also satisfies the case
            # where the caller circumvents mypy --strict (e.g. dynamic
            # callers from non-typed Python).
            raise ValidationError(
                f"grant_credit requires a Credit instance; got {type(grant).__name__}. "
                f"Wrap a raw int as `Credit(n)` first.",
                code="SCP-VALID-7060",
            )
        if self._terminated:
            raise StreamAlreadyClosed(
                "grant_credit rejected: stream has already emitted a terminal chunk",
            )
        if self._request_id is None:
            # Non-streaming handle reaches terminal state immediately on
            # construction. We treat the initial state of a non-streaming
            # handle as "already closed" for control-plane purposes per
            # OUT-038 AC13 — the End chunk arrived synchronously so by
            # the time the caller invokes grant_credit, the stream is
            # closed.
            raise StreamAlreadyClosed(
                "grant_credit rejected: handle was opened without a streaming session "
                "(degenerate single-shot invoke; the End chunk arrived synchronously)",
            )
        if self._invoker_did is None:
            raise StreamAlreadyClosed(
                "grant_credit rejected: handle has no pinned invoker DID "
                "(degenerate single-shot invoke); cancel/grant requires the "
                "streaming bridge to authenticate the caller",
            )
        bridge = _require_bridge()
        try:
            return await asyncio.to_thread(
                bridge.outlet_stream_grant_credit,
                self._request_id,
                self._invoker_did,
                grant.raw,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

    async def cancel(self) -> int | None:
        """Cancel an active stream (§5.4.5 cancellation + billing boundary).

        The bridge derives the canonical ``next_seq`` from the runtime's
        current emission cursor — never accepts caller input.
        CRITICAL #3 fix: a caller-supplied ``next_seq`` lets the caller
        forge ``cancel_ack_seq``.

        Raises :class:`StreamAlreadyClosed` (OUT-038 AC13) when the
        stream has already terminated.

        Returns the recorded cancel-ack sequence, or ``None`` if the
        stream had already terminated at the moment the cancel reached
        the runtime (the runtime ignores the cancel per §5.4.5
        idempotency rule).
        """
        if self._terminated:
            raise StreamAlreadyClosed(
                "cancel rejected: stream has already emitted a terminal chunk",
            )
        if self._request_id is None:
            raise StreamAlreadyClosed(
                "cancel rejected: handle was opened without a streaming session "
                "(degenerate single-shot invoke; the End chunk arrived synchronously)",
            )
        if self._invoker_did is None:
            raise StreamAlreadyClosed(
                "cancel rejected: handle has no pinned invoker DID — bridge "
                "caller authentication unavailable",
            )
        bridge = _require_bridge()
        try:
            return await asyncio.to_thread(
                bridge.outlet_stream_cancel,
                self._request_id,
                self._invoker_did,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc


# ---------------------------------------------------------------------------
# OutletOffersNamespace — cross-context outlet interface offers (§6.2.0.1).
# ---------------------------------------------------------------------------


class OutletOffersNamespace:
    """``ctx.outlets.offers`` — cross-context outlet interface offers."""

    def __init__(self, context_id: str) -> None:
        self._context_id = context_id

    async def propose(
        self,
        outlet_id: str,
        target_context_id: str,
        rate_limit_json: str | None = None,
    ) -> dict[str, Any]:
        """Propose an outlet interface offer to a target context (step 1)."""
        bridge = _require_bridge()
        try:
            result_json = await asyncio.to_thread(
                bridge.context_outlet_interface_offer,
                self._context_id,
                outlet_id,
                target_context_id,
                rate_limit_json,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc
        return json.loads(result_json)

    async def accept(self, interface_json: str) -> dict[str, Any]:
        """Accept an outlet interface offer (step 4)."""
        bridge = _require_bridge()
        try:
            result_json = await asyncio.to_thread(
                bridge.context_outlet_interface_accept,
                self._context_id,
                interface_json,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc
        return json.loads(result_json)

    async def revoke(self, interface_id_hex: str) -> dict[str, Any]:
        """Revoke an accepted outlet interface (step 5)."""
        bridge = _require_bridge()
        try:
            result_json = await asyncio.to_thread(
                bridge.context_outlet_interface_revoke,
                self._context_id,
                interface_id_hex,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc
        return json.loads(result_json)

    async def list(self) -> list[dict[str, Any]]:
        """List outbound outlet interface offers for this context.

        The bridge does not yet surface an offer-listing endpoint;
        applications iterate via their event log. Returns an empty list
        as a stable no-op at the SDK layer.
        """
        return []


# ---------------------------------------------------------------------------
# OutletSessionsNamespace — stateful outlet sessions (§6.2.1.1).
# ---------------------------------------------------------------------------


class OutletSessionsNamespace:
    """``ctx.outlets.sessions`` — stateful outlet sessions (§6.2.1.1)."""

    def __init__(self, context_id: str) -> None:
        self._context_id = context_id

    async def open(
        self,
        outlet_id: str,
        source_context_id: str,
        ttl_seconds: int | None = None,
    ) -> SessionId:
        """Open a stateful outlet session and return a typed :class:`SessionId`."""
        if ttl_seconds is not None and (
            isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 0
        ):
            raise ValidationError(
                f"ttl_seconds must be a non-negative integer, got {ttl_seconds!r}",
                code="SCP-VALID-7002",
            )
        bridge = _require_bridge()
        try:
            raw = await asyncio.to_thread(
                bridge.context_outlet_session_open,
                self._context_id,
                outlet_id,
                source_context_id,
                ttl_seconds,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc
        if _UUID7_RE.match(raw):
            _validate_session_id(raw)
        return SessionId(raw)

    async def invoke(
        self,
        session_id: SessionId,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str,
        proof_tokens: list[str] | None = None,
    ) -> dict[str, Any]:
        """Invoke an outlet within an active session."""
        if not isinstance(session_id, str):
            raise ValidationError(
                f"session_id must be a SessionId (str), got {type(session_id).__name__}",
                code="SCP-VALID-7010",
            )
        bridge = _require_bridge()
        try:
            return await asyncio.to_thread(
                bridge.context_outlet_session_invoke,
                self._context_id,
                session_id,
                input,
                invoker_did,
                ucan_token,
                proof_tokens,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

    async def close(self, session_id: SessionId) -> None:
        """Close a stateful outlet session."""
        if not isinstance(session_id, str):
            raise ValidationError(
                f"session_id must be a SessionId (str), got {type(session_id).__name__}",
                code="SCP-VALID-7010",
            )
        bridge = _require_bridge()
        try:
            await asyncio.to_thread(
                bridge.context_outlet_session_close,
                self._context_id,
                session_id,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc


# ---------------------------------------------------------------------------
# OutletNamespace — top-level `ctx.outlets` surface.
# ---------------------------------------------------------------------------


class OutletNamespace:
    """``ctx.outlets`` — outlet surface for a context.

    Verbs: :meth:`register`, :meth:`invoke`, :meth:`update`, :meth:`get`,
    :meth:`list`, :meth:`verify`, :meth:`deregister`. Sub-namespaces:
    :attr:`sessions` and :attr:`offers`.
    """

    def __init__(self, context_id: str, creator_did: str) -> None:
        self._context_id = context_id
        self._creator_did = creator_did
        self.sessions = OutletSessionsNamespace(context_id)
        self.offers = OutletOffersNamespace(context_id)

    def _build_registration(self, definition: OutletDefinition) -> dict[str, Any]:
        operator_did = (
            definition.operator.did
            if hasattr(definition.operator, "did")
            else (definition.operator or self._creator_did)
        )
        # SCP-OUT-017: kind is REQUIRED on the SDK surface and on the wire.
        # `OutletKind.parse` accepts either an `OutletKind` instance or the
        # lowercase string `"query"` / `"action"` so callers who supplied
        # the wire form directly continue to work.
        kind_obj = OutletKind.parse(definition.kind)
        operator_did_str: str = (
            operator_did if isinstance(operator_did, str) else self._creator_did  # type: ignore[unreachable]
        )
        registration: dict[str, Any] = {
            "name": definition.name,
            "description": definition.description,
            "kind": kind_obj.value,
            "input_schema": definition.input_schema,
            "output_schema": definition.output_schema,
            "operator": operator_did_str,
            # SCP-OUT-012/017: bridge expects `operator_did` for raw dict
            # callers; SDK callers go through this builder so we set both
            # the SDK-friendly `operator` and the bridge-required
            # `operator_did` — the bridge reads `operator_did`.
            "operator_did": operator_did_str,
        }
        if definition.test_vectors is not None:
            registration["test_vectors"] = [
                {
                    "input": tv.input,
                    "expected_output": tv.expected_output,
                    "description": tv.description,
                }
                for tv in definition.test_vectors
            ]
        if definition.implementation_hash is not None:
            registration["implementation_hash"] = definition.implementation_hash.hex()
        if definition.cost is not None:
            registration["cost"] = {
                "amount": definition.cost.amount,
                "currency": definition.cost.currency,
                "payee": definition.cost.payee,
                "cost_formula": definition.cost.cost_formula,
            }
        return registration

    # -- register / invoke / update / get / list / verify / deregister ------

    async def register(
        self,
        definition: OutletDefinition | None = None,
        *,
        kind: OutletKind | str | None = None,
        name: str | None = None,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        operator: Identity | str | None = None,
        test_vectors: list[TestVector] | None = None,
        implementation_hash: bytes | None = None,
        cost: OutletCost | None = None,
    ) -> str:
        """Register an outlet in the context (SCP-OUT-017).

        ``kind`` is REQUIRED. Two call styles are supported:

        1. **Dataclass form** — pass an :class:`OutletDefinition` (which
           already carries a required ``kind``) as the sole positional or
           keyword argument. ``kind`` may optionally override the value
           on the definition::

               await ctx.outlets.register(
                   OutletDefinition(
                       name="weather",
                       description="...",
                       kind=OutletKind.Query,
                       input_schema={...},
                       output_schema={...},
                       operator=alice,
                   )
               )

        2. **Keyword form** — pass each field as a keyword argument
           including the required ``kind=`` argument::

               await ctx.outlets.register(
                   kind=OutletKind.Action,
                   name="send-email",
                   description="...",
                   input_schema={...},
                   output_schema={...},
                   operator=alice,
               )

        Calls without ``kind`` (and without a definition that supplies
        it) raise :class:`TypeError` from the dataclass machinery, or
        :class:`ValidationError` from the keyword-form path.

        Returns the assigned outlet id.
        """
        if definition is not None:
            if any(
                v is not None
                for v in (
                    name,
                    description,
                    input_schema,
                    output_schema,
                    operator,
                    test_vectors,
                    implementation_hash,
                    cost,
                )
            ):
                raise ValidationError(
                    "pass either an OutletDefinition or keyword args, not both",
                    code="SCP-VALID-7002",
                )
            resolved_kind = OutletKind.parse(kind) if kind is not None else definition.kind
            built = OutletDefinition(
                name=definition.name,
                description=definition.description,
                kind=resolved_kind,
                input_schema=definition.input_schema,
                output_schema=definition.output_schema,
                operator=definition.operator,
                test_vectors=definition.test_vectors,
                implementation_hash=definition.implementation_hash,
                cost=definition.cost,
            )
        else:
            if kind is None:
                raise ValidationError(
                    "register() requires `kind` (OutletKind.Query or "
                    "OutletKind.Action) — SCP-OUT-017 makes kind REQUIRED on "
                    "all 4 SDKs",
                    code="SCP-VALID-7050",
                )
            if name is None or description is None or input_schema is None or output_schema is None:
                raise ValidationError(
                    "register() requires keyword args name, description, input_schema, "
                    "output_schema, kind (or pass an OutletDefinition)",
                    code="SCP-VALID-7002",
                )
            built = OutletDefinition(
                name=name,
                description=description,
                kind=OutletKind.parse(kind),
                input_schema=input_schema,
                output_schema=output_schema,
                operator=operator,
                test_vectors=test_vectors,
                implementation_hash=implementation_hash,
                cost=cost,
            )
        bridge = _require_bridge()
        registration = self._build_registration(built)
        try:
            return await asyncio.to_thread(
                bridge.context_outlet_register,
                self._context_id,
                registration,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

    async def register_query(
        self,
        definition: OutletDefinition | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        operator: Identity | str | None = None,
        test_vectors: list[TestVector] | None = None,
        implementation_hash: bytes | None = None,
        cost: OutletCost | None = None,
    ) -> str:
        """Convenience: register an outlet with ``kind=OutletKind.Query``.

        Equivalent to :meth:`register` with ``kind=OutletKind.Query``.
        Useful for the common path where the outlet is read-only.
        """
        return await self.register(
            definition,
            kind=OutletKind.Query,
            name=name,
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
            operator=operator,
            test_vectors=test_vectors,
            implementation_hash=implementation_hash,
            cost=cost,
        )

    async def register_action(
        self,
        definition: OutletDefinition | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        operator: Identity | str | None = None,
        test_vectors: list[TestVector] | None = None,
        implementation_hash: bytes | None = None,
        cost: OutletCost | None = None,
    ) -> str:
        """Convenience: register an outlet with ``kind=OutletKind.Action``.

        Equivalent to :meth:`register` with ``kind=OutletKind.Action``.
        """
        return await self.register(
            definition,
            kind=OutletKind.Action,
            name=name,
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
            operator=operator,
            test_vectors=test_vectors,
            implementation_hash=implementation_hash,
            cost=cost,
        )

    def invoke(
        self,
        outlet_id: str,
        input: dict[str, Any],
        ucan_token: str | None = None,
        identity: Identity | None = None,
        proof_tokens: list[str] | None = None,
        spending_ucan: str | None = None,
        *,
        caveats_binding: bytes | None = None,
        stream_epoch: int | None = None,
        credit_window: int | None = None,
        estimated_chunk_count: int | None = None,
        aggregate_schema: dict[str, Any] | None = None,
        ucan_recheck_secs: int = 10,
    ) -> InvocationHandle:
        """Invoke an outlet in the context — the ONE public verb (OUT-038 AC1).

        Returns an :class:`InvocationHandle`. ``await handle`` returns
        the aggregate; ``async for chunk in handle`` yields chunks.
        One method, two consumption styles (API MAJOR 21). The handle
        also exposes :meth:`InvocationHandle.grant_credit` /
        :meth:`InvocationHandle.cancel` control-plane methods (OUT-038
        AC2-3).

        When ``caveats_binding`` and ``stream_epoch`` are supplied,
        the SDK opens a real §5.4.5 streaming session via the
        ``context_outlet_invoke_stream`` bridge — the returned handle
        carries a real ``request_id`` and grant_credit / cancel route
        to the runtime. When omitted, the SDK falls back to the
        non-streaming bridge (degenerate single-chunk case per §5.4.5)
        and the handle's lifecycle ends as soon as the synthesized
        ``End`` chunk arrives — control-plane methods then raise
        :class:`StreamAlreadyClosed` per OUT-038 AC13.

        Args:
            outlet_id: Outlet to invoke.
            input: JSON-serialisable dict matching the outlet's input
                schema.
            ucan_token: UCAN authorising the invocation. Required for
                streaming-mode invocations (when ``caveats_binding`` is
                supplied) — the bridge re-runs the 11-step ADR-016
                pipeline at open.
            identity: Optional invoker identity; falls back to the
                context creator DID.
            proof_tokens: Optional encoded parent UCAN tokens for
                delegation chain traversal (ADR-016 step 3).
            spending_ucan: Optional spending-cap UCAN for paid outlets.
            caveats_binding: 32-byte SHA-256 over the §5.4.5
                ``SCP-OUTLET-CAVEAT-BIND-V1:`` preimage; pass the
                output of :func:`compute_caveats_binding`. When
                supplied, opens a real streaming session.
            stream_epoch: Hosting context's MLS epoch counter at open
                acceptance. Required when ``caveats_binding`` is set.
            credit_window: Optional initial credit window override;
                defaults to §5.4.5 ``DEFAULT_CREDIT_WINDOW`` (32) on
                the bridge side. Streaming-mode only.
            estimated_chunk_count: Optional invoker-declared upper
                bound on billable Data chunks. Streaming-mode only.
            aggregate_schema: Optional JSON Schema for the End chunk's
                ``aggregate`` value (§5.4.5). When supplied, the
                handle validates the End chunk's aggregate against
                this schema before resolving the awaitable. When
                omitted, no aggregate validation runs (defense in
                depth; the registration-time ``aggregate_schema`` is
                authoritative on the runtime side).
        """
        invoker_did = identity.did if identity is not None else self._creator_did
        context_id = self._context_id
        if caveats_binding is not None and stream_epoch is not None:
            return self._invoke_streaming(
                context_id=context_id,
                outlet_id=outlet_id,
                input=input,
                invoker_did=invoker_did,
                ucan_token=ucan_token,
                caveats_binding=caveats_binding,
                stream_epoch=stream_epoch,
                proof_tokens=proof_tokens,
                credit_window=credit_window,
                estimated_chunk_count=estimated_chunk_count,
                spending_ucan=spending_ucan,
                aggregate_schema=aggregate_schema,
                ucan_recheck_secs=ucan_recheck_secs,
            )
        if caveats_binding is not None or stream_epoch is not None:
            raise ValidationError(
                "streaming-mode invoke requires BOTH caveats_binding (32 bytes) "
                "and stream_epoch; pass them together or omit both for the "
                "degenerate single-shot path",
                code="SCP-VALID-7002",
            )
        return self._invoke_one_shot(
            context_id=context_id,
            outlet_id=outlet_id,
            input=input,
            invoker_did=invoker_did,
            ucan_token=ucan_token,
            proof_tokens=proof_tokens,
            spending_ucan=spending_ucan,
            aggregate_schema=aggregate_schema,
        )

    def _invoke_one_shot(
        self,
        *,
        context_id: str,
        outlet_id: str,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str | None,
        proof_tokens: list[str] | None,
        spending_ucan: str | None,
        aggregate_schema: dict[str, Any] | None,
    ) -> InvocationHandle:
        """Degenerate single-shot path — calls ``context_outlet_invoke``.

        The bridge returns the End.aggregate value directly; the SDK
        synthesizes a single ``end`` chunk for the iterator and resolves
        the aggregate await with it. Control-plane methods on the
        returned handle raise :class:`StreamAlreadyClosed` (OUT-038
        AC13) because the stream "ends" synchronously.
        """
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()

        async def _pump() -> None:
            bridge = _scp_core
            if bridge is None:
                q.put_nowait(
                    ContextError(
                        "failed to import _scp_core -- is the Rust extension built?",
                        code="SCP-CTX-2001",
                    )
                )
                q.put_nowait(None)
                return
            try:
                result = await asyncio.to_thread(
                    bridge.context_outlet_invoke,
                    context_id,
                    outlet_id,
                    input,
                    invoker_did,
                    ucan_token,
                    proof_tokens,
                    spending_ucan,
                )
            except Exception as exc:
                q.put_nowait(_translate_bridge_error(exc))
                q.put_nowait(None)
                return
            q.put_nowait(
                OutletStreamChunk(
                    request_id=b"\x00" * 16,
                    sequence=0,
                    payload_type="end",
                    aggregate=result,
                )
            )
            q.put_nowait(None)

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        handle = InvocationHandle(q, aggregate_schema=aggregate_schema)
        # Pump task ownership lives on the handle for the lifetime of the stream.
        handle._pump_task = loop.create_task(_pump())  # type: ignore[attr-defined]
        return handle

    def _invoke_streaming(
        self,
        *,
        context_id: str,
        outlet_id: str,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str | None,
        caveats_binding: bytes,
        stream_epoch: int,
        proof_tokens: list[str] | None,
        credit_window: int | None,
        estimated_chunk_count: int | None,
        spending_ucan: str | None,
        aggregate_schema: dict[str, Any] | None,
        ucan_recheck_secs: int = 10,
    ) -> InvocationHandle:
        """Open a §5.4.5 streaming outlet invocation (OUT-038 internal).

        Internal helper called by :meth:`invoke` when a caveats_binding
        + stream_epoch pair is supplied. Calls the PyO3
        ``context_outlet_invoke_stream`` bridge, wraps the resulting
        native async iterator in an :class:`InvocationHandle`, and
        returns it. The handle's
        :attr:`InvocationHandle.request_id` is the §5.4.5 16-byte
        ``request_id`` rendered as 32-char lowercase hex — the lookup
        key for :meth:`InvocationHandle.grant_credit` and
        :meth:`InvocationHandle.cancel`.

        This method is intentionally name-prefixed with ``_`` to keep
        the public SDK surface to the single :meth:`invoke` verb per
        OUT-038 AC1 (no ``invoke_stream`` at the public layer).
        """
        if len(caveats_binding) != 32:
            raise ValidationError(
                f"caveats_binding must be exactly 32 bytes, got {len(caveats_binding)}",
                code="SCP-VALID-7000",
            )
        if ucan_token is None:
            raise ValidationError(
                "streaming-mode invoke requires ucan_token (the bridge re-runs the "
                "11-step ADR-016 pipeline at open)",
                code="SCP-VALID-7002",
            )
        bridge = _require_bridge()
        try:
            stream_obj = bridge.context_outlet_invoke_stream(
                context_id,
                outlet_id,
                input,
                invoker_did,
                ucan_token,
                caveats_binding.hex(),
                int(stream_epoch),
                proof_tokens,
                credit_window,
                estimated_chunk_count,
                spending_ucan,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

        request_id_hex = stream_obj.request_id

        # Bridge the native PyO3 async iterator (one chunk per
        # `__anext__`) into the asyncio.Queue InvocationHandle expects.
        # We pump in the background so the handle's `_await_aggregate`
        # / iterator paths are unchanged.
        q: asyncio.Queue[OutletStreamChunk | BaseException | None] = asyncio.Queue()

        async def _pump() -> None:
            try:
                while True:
                    chunk_dict = await asyncio.to_thread(_native_anext_blocking, stream_obj)
                    if chunk_dict is None:
                        break
                    chunk = _chunk_dict_to_dataclass(chunk_dict)
                    q.put_nowait(chunk)
                    if chunk.payload_type in ("end",):
                        break
                    if chunk.payload_type == "error" and chunk.terminal:
                        break
            except Exception as exc:
                q.put_nowait(_translate_bridge_error(exc))
            finally:
                q.put_nowait(None)

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        handle = InvocationHandle(
            q,
            request_id=request_id_hex,
            invoker_did=invoker_did,
            aggregate_schema=aggregate_schema,
        )
        handle._pump_task = loop.create_task(_pump())  # type: ignore[attr-defined]

        # §5.4.5 receiver-side revocation re-check (RevokedMidStream /
        # SCP-TOOL-6110). Per spec the SDK framework MUST periodically
        # re-check the opening UCAN's revocation status during the
        # stream's active lifetime, every `stream_ucan_recheck_secs`,
        # and on observed revocation MUST terminate the stream.
        # Re-validates the UCAN against the same context — a token
        # revoked since open surfaces as `UcanError::TokenRevoked` from
        # the bridge's 11-step pipeline. The recheck loop calls
        # `outlet_stream_terminate` which routes through
        # `StreamSessionHandle::terminate_with_error` on the runtime
        # and emits a synthetic terminal Error chunk under the pinned
        # operator key. Already-emitted chunks remain authorized; the
        # stream closes at or before `ucan_recheck_secs` after the
        # revocation event regardless of executor behavior.
        async def _recheck_loop() -> None:
            from scp_sdk.errors import UcanError as _UcanError

            capability = f"tool_invoke:{outlet_id}"
            bridge = _scp_core
            if bridge is None or ucan_token is None:
                # No bridge or no token — re-check is impossible. The
                # streaming open path already requires `ucan_token` so
                # this is defense-in-depth.
                return
            try:
                while not handle.is_terminated:
                    await asyncio.sleep(max(1, ucan_recheck_secs))
                    if handle.is_terminated:
                        break
                    try:
                        await asyncio.to_thread(
                            bridge.ucan_validate,
                            context_id,
                            ucan_token,
                            capability,
                            invoker_did,
                            proof_tokens,
                        )
                    except _UcanError as exc:
                        # Revocation surfaces from the bridge as a
                        # `UcanError`. Other UcanError modes (expired,
                        # malformed) also indicate the token is no
                        # longer valid for this stream — the spec ties
                        # the receiver-side check to revocation
                        # specifically, but any UCAN failure is a
                        # superset signal. Terminate with the spec's
                        # `RevokedMidStream` slug + code regardless of
                        # the underlying UcanError variant.
                        try:
                            # PyO3 bridge accepts the closed-set
                            # `TerminateReason` slug as a string and
                            # derives the §5.4.4 code from it; the
                            # `message` extension is the only caller-
                            # supplied human text.
                            await asyncio.to_thread(
                                bridge.outlet_stream_terminate,
                                request_id_hex,
                                invoker_did,
                                "authorization.revoked-mid-stream",
                                str(exc),
                            )
                        except Exception:
                            # Terminate is recoverable from the SDK's
                            # perspective — `AlreadyTerminated` /
                            # `AlreadyPending` indicate the stream
                            # has already left the runtime control
                            # plane. Stop the recheck loop either way.
                            pass
                        break
                    except Exception:
                        # Non-UCAN errors (network, runtime) are NOT
                        # revocation signals — keep re-checking on the
                        # next tick. The stream continues normally.
                        pass
            except asyncio.CancelledError:
                # Task cancellation (e.g. parent loop shutdown) —
                # propagate cleanly.
                raise

        handle._recheck_task = loop.create_task(_recheck_loop())  # type: ignore[attr-defined]
        return handle

    async def update(
        self,
        outlet_id: str,
        definition: OutletDefinition,
        updater_did: str | None = None,
    ) -> str:
        """Update an outlet registration in-place (operator re-signs)."""
        bridge = _require_bridge()
        registration = self._build_registration(definition)
        try:
            return await asyncio.to_thread(
                bridge.context_outlet_update,
                self._context_id,
                outlet_id,
                registration,
                updater_did or self._creator_did,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

    async def get(self, outlet_id: str) -> dict[str, Any]:
        """Get a single outlet registration by id."""
        bridge = _require_bridge()
        try:
            result_json = await asyncio.to_thread(
                bridge.context_outlet_get,
                self._context_id,
                outlet_id,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc
        return json.loads(result_json)

    async def list(self) -> list[str]:
        """List outlet ids registered in this context."""
        bridge = _require_bridge()
        try:
            return await asyncio.to_thread(
                bridge.context_outlet_list,
                self._context_id,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

    async def verify(self, outlet_id: str) -> dict[str, Any]:
        """Run the outlet's test vectors and return a verification result."""
        bridge = _require_bridge()
        try:
            raw = await asyncio.to_thread(
                bridge.context_outlet_verify,
                self._context_id,
                outlet_id,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc
        if hasattr(raw, "outlet_id"):
            return {
                "outlet_id": raw.outlet_id,
                "passed": raw.passed,
                "failures": list(raw.failures),
            }
        return dict(raw) if isinstance(raw, dict) else {"result": raw}

    async def deregister(self, outlet_id: str, actor_did: str | None = None) -> None:
        """Deregister an outlet from the context."""
        bridge = _require_bridge()
        try:
            await asyncio.to_thread(
                bridge.context_outlet_deregister,
                self._context_id,
                outlet_id,
                actor_did or self._creator_did,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc

    # -- invoke_cross_context (review item 31) ------------------------------

    async def invoke_cross_context(
        self,
        options: InvokeCrossContextOptions | None = None,
        *,
        target: str | None = None,
        outlet_id: str | None = None,
        input: dict[str, Any] | None = None,
        ucan: str | None = None,
        chain_depth: int = 0,
        proof_tokens: list[str] | None = None,
    ) -> dict[str, Any]:
        """Invoke an outlet in a target context (API MAJOR 22).

        Keyword-only form::

            await ctx.outlets.invoke_cross_context(
                target="ctx-42",
                outlet_id="calculator",
                input={"x": 1},
                ucan="eyJ...",
            )

        Or pass an :class:`InvokeCrossContextOptions` instance.

        Positional two-string invocation is REJECTED to prevent silent
        target/outlet_id swap.
        """
        if options is not None:
            if any(v is not None for v in (target, outlet_id, input, ucan)):
                raise ValidationError(
                    "pass either the options-dataclass or keyword args, not both",
                    code="SCP-VALID-7002",
                )
            target = options.target
            outlet_id = options.outlet_id
            input = options.input
            ucan = options.ucan
            chain_depth = options.chain_depth
            proof_tokens = options.proof_tokens
        if target is None or outlet_id is None or input is None or ucan is None:
            raise ValidationError(
                "invoke_cross_context requires keyword args target, outlet_id, input, "
                "ucan (or an InvokeCrossContextOptions instance)",
                code="SCP-VALID-7002",
            )
        if (
            isinstance(chain_depth, bool)
            or not isinstance(chain_depth, int)
            or chain_depth < 0
            or chain_depth > 255
        ):
            raise ValidationError(
                f"chain_depth must be an integer in range 0-255, got {chain_depth!r}",
                code="SCP-VALID-7002",
            )
        bridge = _require_bridge()
        try:
            return await asyncio.to_thread(
                bridge.context_outlet_invoke_cross_context,
                self._context_id,
                target,
                outlet_id,
                input,
                self._creator_did,
                ucan,
                chain_depth,
                proof_tokens,
            )
        except Exception as exc:
            raise _translate_bridge_error(exc) from exc


__all__ = [
    "Aggregate",
    "Credit",
    "InvocationCaveats",
    "InvocationHandle",
    "InvokeCrossContextOptions",
    "OutletCost",
    "OutletDefinition",
    "OutletKind",
    "OutletNamespace",
    "OutletOffersNamespace",
    "OutletSessionsNamespace",
    "OutletStreamChunk",
    "SessionId",
    "StreamAlreadyClosed",
    "TestVector",
    "compute_caveats_binding",
    "new_session_id",
    "verify_chunk_signature",
]
