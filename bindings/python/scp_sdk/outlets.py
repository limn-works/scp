"""Outlet types and the single-verb streaming invocation surface for the SCP Python SDK.

Registration / definition types:

- :class:`OutletDefinition` -- an outlet registered in a context (§5.4.1).
- :class:`OutletKind` -- Query vs Action semantic class (§5.4.2).
- :class:`OutletCost` -- per-invocation cost metadata (§5.4.1).
- :class:`TestVector` -- an input/output pair for outlet verification.
- :class:`SagaResult` -- the committed terminal of a §6.2.4 cross-context saga.

The streaming invocation surface (§5.4.5, SCP-OUT-006 / SCP-OUT-038) — the
SINGLE public verb ``ctx.outlets.invoke(...)`` and the objects it returns:

- :class:`Outlets` -- the ``ctx.outlets`` accessor holding :meth:`Outlets.invoke`.
- :class:`InvocationHandle` -- awaitable (aggregated ``End`` result) + async-iterable
  (per-chunk) handle with :meth:`~InvocationHandle.grant_credit` /
  :meth:`~InvocationHandle.cancel` control-plane methods.
- :class:`Credit` -- validated non-zero ``u32`` credit-grant newtype.
- :class:`OutletStreamChunk` -- one decoded stream chunk.
- :class:`Aggregate` -- the aggregated terminal result of an invocation.

The streaming FFI ops are wrapped BEHIND :class:`InvocationHandle`: the SDK
exposes no separate stream-invocation, poll, or credit-grant free function.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 3,
``.docs/standards/python.md`` for conventions, spec §5.4 for outlets, and
§5.4.5 for progressive output (streaming).
"""

from __future__ import annotations

import asyncio
import enum
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, final

from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    ContextError,
    InvalidGrant,
    OutletError,
    ProtocolError,
    StreamAlreadyClosed,
    StreamGap,
    ValidationError,
    _coded_bridge_error,
    _saga_terminal_from_bridge,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Generator

    from scp_sdk.identity import Identity


#: Matches the leading ``[SCP-CAT-NNNN]`` code the bridge's ``ScpPyError``
#: ``Display`` prepends to its message (``[SCP-PERM-3001] context error: ...``).
#: Anchored at the start so only the bridge's own code prefix is extracted; an
#: unbracketed message yields no match and the SDK class default stands.
_LEADING_BRIDGE_CODE: Final = re.compile(r"^\[(SCP-[A-Z]+-\d+)\]")


def _translate_bridge_error(exc: Exception) -> Exception:
    """Translate a ``_scp_core`` bridge exception to an SDK exception.

    Uses :data:`~scp_sdk.errors.BRIDGE_ERROR_MAP` to look up the SDK type by
    the bridge exception's class name (falling back to
    :class:`~scp_sdk.errors.ContextError` for unmapped types), and preserves
    the bridge's structured ``SCP-CAT-NNNN`` code as the SDK exception's
    ``.code`` so a caller can branch on it — not merely read it out of the
    message text. The bridge's ``ScpPyError`` ``Display`` prepends the code in
    brackets (``[SCP-PERM-3001] ...``); that leading code is extracted and
    passed through, so a money-moving rejection (e.g. a non-invoker
    grant/cancel/recover) surfaces ``.code == "SCP-PERM-3001"`` rather than the
    receiving SDK class's generic default. An unbracketed bridge message carries
    no recoverable code, so the SDK class default applies.
    """
    sdk_cls = BRIDGE_ERROR_MAP.get(type(exc).__name__, ContextError)
    message = str(exc)
    match = _LEADING_BRIDGE_CODE.match(message)
    code = match.group(1) if match is not None else None
    return sdk_cls(message, code)


# ---------------------------------------------------------------------------
# OutletKind — outlet semantic class (Query vs Action), §5.4.2.
# ---------------------------------------------------------------------------


class OutletKind(enum.Enum):
    """Outlet semantic class (§5.4.2).

    ``Query`` outlets are read-only and idempotent (UCAN stem
    ``outlet_query:{id}``); ``Action`` outlets may mutate state (UCAN stem
    ``outlet_call:{id}``).

    Required at the SDK surface across all 4 bindings. Crosses the bridge
    boundary as the lowercase string ``"query"`` / ``"action"`` matching the
    §5.4.2 wire vocabulary.
    """

    Query = "query"
    Action = "action"

    @classmethod
    def parse(cls, value: OutletKind | str) -> OutletKind:
        """Coerce ``value`` to an :class:`OutletKind` instance.

        Accepts an existing :class:`OutletKind` (returned unchanged) or
        the lowercase string ``"query"`` / ``"action"`` matching the
        §5.4.2 wire vocabulary. Other values raise
        :class:`~scp_sdk.errors.ValidationError` (code ``SCP-VALID-7050``).
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


@dataclass
class TestVector:
    """A single test vector for outlet verification.

    Test vectors define expected input/output pairs that an outlet
    implementation must satisfy.  They are used during outlet registration
    to verify that the implementation matches its declared behaviour.
    """

    #: Input data to feed the outlet (JSON-compatible dict).
    input: dict[str, Any]

    #: Expected output from the outlet (JSON-compatible dict).
    expected_output: dict[str, Any]

    #: Human-readable description of what this vector tests.
    description: str = ""


@dataclass
class OutletCost:
    """Per-invocation cost metadata for an outlet (spec section 5.4.1).

    All monetary values are in the smallest currency unit (e.g., cents
    for USD, satoshis for BTC).
    """

    #: Cost per invocation in the smallest currency unit.
    amount: int

    #: ISO 4217 or protocol-defined currency code.
    currency: str

    #: DID of the payment recipient.  May differ from the outlet operator.
    payee: str

    #: Optional pricing formula identifier for dynamic pricing (spec section 19.4).
    cost_formula: str | None = None


@dataclass(kw_only=True)
class OutletDefinition:
    """Definition of an outlet registered in an SCP context (§5.4.1).

    Mirrors ADR-014 acceptance criterion 3.  The ``operator`` field
    accepts either an ``Identity`` object (from ``scp_sdk.identity``,
    defined in a separate story) or a plain DID string.

    ``kind`` is REQUIRED — there is no default. All 4 SDKs surface
    :class:`OutletKind` as a required field; the dataclass is keyword-only,
    so omitting ``kind`` raises :class:`TypeError` from the dataclass
    machinery. It selects the outlet's UCAN capability stem
    (``outlet_query:{id}`` for :attr:`OutletKind.Query`,
    ``outlet_call:{id}`` for :attr:`OutletKind.Action`; §5.4.2).

    Example::

        outlet = OutletDefinition(
            name="recipe_search",
            description="Search recipes by ingredients",
            kind=OutletKind.Query,
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            output_schema={"type": "object", "properties": {"results": {"type": "array"}}},
            operator="did:dht:z6MkOperator",
        )
    """

    #: Unique outlet name within the context.
    name: str

    #: Human-readable description of the outlet's purpose.
    description: str

    #: Outlet semantic class (Query vs Action, §5.4.2). REQUIRED — selects the
    #: outlet's UCAN capability stem.
    kind: OutletKind

    #: JSON Schema describing the outlet's input.
    input_schema: dict[str, Any]

    #: JSON Schema describing the outlet's output.
    output_schema: dict[str, Any]

    #: DID string or :class:`~scp_sdk.identity.Identity` object of the
    #: outlet operator.
    operator: Identity | str | None

    #: Optional test vectors for verification.
    test_vectors: list[TestVector] | None = None

    #: Optional implementation hash for integrity verification.
    implementation_hash: bytes | None = None

    #: Optional per-invocation cost metadata (spec section 5.4.1).
    cost: OutletCost | None = None

    #: The operator's 64-byte Ed25519 signature over the section 5.4.1 V2
    #: canonical registration digest.
    #:
    #: Supply this when registering an outlet operated by someone else, whose
    #: key this SDK instance does not hold. Leave it ``None`` when ``operator``
    #: names an identity created on this instance: the bridge then signs the
    #: registration with that identity's own key. Registration fails when the
    #: SDK can neither sign nor read a supplied signature, because
    #: ``register_outlet`` verifies the signature against the key
    #: ``operator_did`` encodes.
    operator_signature: bytes | None = None

    #: Registration timestamp, in seconds since the Unix epoch.
    #:
    #: An operator signing out of band chooses this value and hands it to the
    #: registrant alongside :attr:`operator_signature`, because the section
    #: 5.4.1 preimage commits ``registered_at``; a bridge-chosen clock reading
    #: would produce a digest the operator never signed. Leave it ``None`` to
    #: let the bridge stamp the current second.
    registered_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the registration dict the PyO3 bridge expects.

        Produces the exact key shape consumed by
        ``scp-ffi/src/outlets.rs::outlet_register_impl`` and its
        ``extract_*`` helpers:

        - ``name`` / ``description`` — strings.
        - ``kind`` — the lowercase §5.4.2 wire string (``self.kind.value``).
        - ``operator_did`` — the operator's DID: ``operator.did`` when
          ``operator`` is an :class:`~scp_sdk.identity.Identity`, otherwise
          the string itself.
        - ``schema`` — ``{"input_schema": …, "output_schema": …}``.
        - ``test_vectors`` — list of ``{input, expected_output, description}``
          dicts (present only when set).
        - ``implementation_hash`` — 64-char lowercase hex string (the bridge's
          ``extract_implementation_hash`` decodes hex, not raw bytes; present
          only when set).
        - ``cost`` — ``{amount, currency, payee, cost_formula}`` (present only
          when set).
        - ``operator_signature`` — the operator's 64 signature bytes (present
          only when set; absent means the bridge signs with the operator's own
          key from its key custody).
        - ``registered_at`` — seconds since the Unix epoch (present only when
          set; absent means the bridge stamps the current second).
        """
        operator = self.operator
        # ``operator`` is an Identity (has ``.did``), a plain DID string, or None.
        operator_did = operator if operator is None or isinstance(operator, str) else operator.did
        result: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "kind": self.kind.value,
            "operator_did": operator_did,
            "schema": {
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
            },
        }
        if self.test_vectors is not None:
            result["test_vectors"] = [
                {
                    "input": tv.input,
                    "expected_output": tv.expected_output,
                    "description": tv.description,
                }
                for tv in self.test_vectors
            ]
        if self.implementation_hash is not None:
            result["implementation_hash"] = self.implementation_hash.hex()
        if self.cost is not None:
            result["cost"] = {
                "amount": self.cost.amount,
                "currency": self.cost.currency,
                "payee": self.cost.payee,
                "cost_formula": self.cost.cost_formula,
            }
        if self.operator_signature is not None:
            result["operator_signature"] = self.operator_signature
        if self.registered_at is not None:
            result["registered_at"] = self.registered_at
        return result


# ---------------------------------------------------------------------------
# Cross-context outlet invocation (spec section 6.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SagaResult:
    """The committed terminal of a §6.2.4 cross-context outlet-invocation saga.

    Returned by :meth:`scp_sdk.SCP.outlet_invoke_cross_context_saga` only on a
    ``Committed`` terminal — every non-committed terminal raises a typed saga
    exception (:class:`~scp_sdk.errors.SagaAbortedError`,
    :class:`~scp_sdk.errors.SagaNeedsRepairError`, or
    :class:`~scp_sdk.errors.SagaBusyError`) instead.

    The fields are a faithful pass-through of the bridge result: ``receipt``
    and ``output`` are surfaced exactly as the bridge returns them (``None``
    when absent — never synthesized). See spec §6.2.4 and ADR-049 §3a.
    """

    #: The durable saga identifier (supervisor-minted, never a caller input).
    saga_id: str

    #: The target's signed ``CrossContextOutletReceipt`` bytes (JCS), or ``None``.
    receipt: bytes | None = None

    #: The captured outlet output bytes (the receipt's canonical ``output_jcs``),
    #: or ``None``.
    output: bytes | None = None


# ---------------------------------------------------------------------------
# Stateful outlet sessions (spec section 6.2.1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Progressive output (streaming) — the single public invoke() verb (§5.4.5)
# ---------------------------------------------------------------------------
#
# SCP-OUT-006 / SCP-OUT-038: the public SDK surface exposes EXACTLY ONE verb —
# ``ctx.outlets.invoke(...)`` — returning an :class:`InvocationHandle` that is
# BOTH awaitable (drains to the aggregated ``End`` result) and async-iterable
# (yields each :class:`OutletStreamChunk` as it arrives). There is no public
# ``invoke_stream`` / ``poll_next`` / ``grant_credit`` free function: the
# streaming FFI ops (``outlet_stream_open`` / ``outlet_stream_poll_next`` /
# ``outlet_stream_grant_credit`` / ``outlet_stream_cancel``) are wrapped
# BEHIND the handle. A non-streaming outlet is the degenerate two-chunk case
# (``Data`` then ``End``); the wire contract is always the streaming form
# (§5.4.5 "Non-streaming invocation").

#: Exclusive upper bound of the ``u32`` credit-grant range. A grant must be a
#: non-zero ``u32``: ``1 <= grant < 2**32``.
_U32_CEIL: Final[int] = 2**32


@final
class Credit:
    """A validated, non-zero ``u32`` stream-credit grant (§5.4.5).

    Construct with ``Credit(n)``. ``n`` MUST be an ``int`` in the half-open
    interval ``[1, 2**32)``. Any other value — ``0``, a negative, ``>= 2**32``,
    a ``bool``, a ``float``, or a non-int — raises
    :class:`~scp_sdk.errors.InvalidGrant` at construction (the SCP-OUT-031
    round-6 uniform rule; never a bare ``TypeError`` / ``ValueError``).

    :meth:`InvocationHandle.grant_credit` consumes a :class:`Credit`, never a
    raw ``int`` — passing ``handle.grant_credit(10)`` is a ``mypy --strict``
    type error (there is no implicit ``int`` -> ``Credit`` coercion), forcing
    the caller through the validating constructor.

    Example::

        await handle.grant_credit(Credit(4))
    """

    __slots__ = ("value",)

    #: The validated grant magnitude (a non-zero ``u32``).
    value: int

    def __init__(self, value: int) -> None:
        # ``bool`` is an ``int`` subclass — reject it explicitly so ``Credit(True)``
        # does not silently become ``Credit(1)``.
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidGrant(
                f"Credit must be an int in [1, 2**32), got {value!r}",
            )
        if value < 1 or value >= _U32_CEIL:
            raise InvalidGrant(
                f"Credit must be a non-zero u32 in [1, 2**32), got {value}",
            )
        self.value = value

    def __repr__(self) -> str:
        return f"Credit({self.value})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Credit) and other.value == self.value

    def __hash__(self) -> int:
        return hash((Credit, self.value))


def _bytes_to_hex(raw: Any) -> str:
    """Render a bridge byte field (JSON array of ``u8``, or a hex string) as hex.

    ``serde_bytes`` fields (``request_id``, ``sig``) serialize to a JSON array
    of integers under ``serde_json``; a hardened bridge or a fixture may instead
    emit a hex string. Both are coerced to a lowercase hex string so the SDK
    surface is stable regardless of the encoding.
    """
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (list, tuple)):
        return bytes(int(b) & 0xFF for b in raw).hex()
    return str(raw)


@dataclass(frozen=True)
class OutletStreamChunk:
    """One chunk in an outlet stream (§5.4.5).

    Yielded by iterating an :class:`InvocationHandle`. ``Progress`` chunks are
    surfaced (not filtered), so a consumer sees the full ``Data`` / ``Progress``
    / ``End`` / ``Error`` sequence in order.
    """

    #: Strictly monotonic per-stream sequence number, starting at ``0``.
    sequence: int

    #: Payload variant tag: ``"data"``, ``"progress"``, ``"end"``, or
    #: ``"error"`` (the wire ``@type``).
    kind: str

    #: The variant's fields, minus the ``@type`` tag. For ``data``:
    #: ``{"value": ...}``; ``progress``: ``{"pct": int, "note": str | None}``;
    #: ``end``: ``{"aggregate": ..., "provenance": ..., "execution_time_ms":
    #: int}``; ``error``: ``{"code": str, "message": str, "terminal": bool}``.
    payload: dict[str, Any]

    #: Stream identifier as a lowercase hex string (opaque to the SDK).
    request_id: str

    #: Operator's per-chunk Ed25519 signature as a lowercase hex string
    #: (opaque to the SDK; verified runtime-side per §5.4.5).
    signature: str

    @property
    def is_terminal(self) -> bool:
        """``True`` for the chunk that closes the stream (``End``, or an
        ``Error`` with ``terminal: true``)."""
        if self.kind == "end":
            return True
        if self.kind == "error":
            return bool(self.payload.get("terminal", False))
        return False

    @classmethod
    def _from_bridge_bytes(cls, raw: bytes) -> OutletStreamChunk:
        """Parse the JSON-serialized ``OutletStreamChunk`` returned by
        ``outlet_stream_poll_next``.

        Raises :class:`~scp_sdk.errors.OutletError` if the bytes are not a
        well-formed chunk (a bridge/transport invariant violation).
        """
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise OutletError(
                f"malformed outlet stream chunk from bridge: {exc}",
                code="SCP-OUTLET-6100",
            ) from exc
        if not isinstance(obj, dict):
            raise OutletError(
                "malformed outlet stream chunk from bridge: expected an object",
                code="SCP-OUTLET-6100",
            )
        payload = obj.get("payload")
        if not isinstance(payload, dict) or "@type" not in payload:
            raise OutletError(
                "malformed outlet stream chunk from bridge: missing payload/@type",
                code="SCP-OUTLET-6100",
            )
        variant = {k: v for k, v in payload.items() if k != "@type"}
        return cls(
            sequence=int(obj.get("sequence", 0)),
            kind=str(payload["@type"]),
            payload=variant,
            request_id=_bytes_to_hex(obj.get("request_id", "")),
            signature=_bytes_to_hex(obj.get("sig", "")),
        )


@dataclass(frozen=True)
class Aggregate:
    """The aggregated terminal result of an outlet invocation (§5.4.5 ``End``).

    Returned by ``await handle`` / :meth:`InvocationHandle.aggregate`. Carries
    the full ``End`` chunk payload: the aggregate output value (matching the
    outlet's ``aggregate_schema``, validated executor-side per §5.4.5), the
    provenance record for the stream output, and the summed wall-clock
    execution time.
    """

    #: Aggregate output value — the ``End.aggregate`` field (matches the
    #: outlet's ``aggregate_schema``, or the last ``Data`` value when the
    #: outlet declares none, per §5.4.5).
    value: Any

    #: Provenance metadata for the full stream output (§5.4.5 ``End.provenance``).
    provenance: dict[str, Any]

    #: Total wall-clock execution time in milliseconds, summed across the
    #: stream's lifetime.
    execution_time_ms: int


@dataclass
class _StreamOpenParams:
    """The immutable ``outlet_stream_open`` argument set, captured at
    :meth:`Outlets.invoke` and replayed on the (lazy) first open."""

    context_id: str
    outlet_id: str
    input: dict[str, Any]
    caller_did: str
    ucan_token: str
    proof_tokens: list[str] | None = None
    spending_ucan: str | None = None
    timeout_ms: int | None = None
    estimated_chunk_count: int | None = None


class InvocationHandle:
    """The single object returned by ``ctx.outlets.invoke(...)`` (SCP-OUT-038).

    An ``InvocationHandle`` is simultaneously:

    - **Awaitable** — ``await handle`` (equivalently ``await handle.aggregate()``)
      drains the stream to its terminal and returns the :class:`Aggregate`
      built from the ``End`` chunk. A terminal ``Error`` chunk raises a typed
      :class:`~scp_sdk.errors.OutletError` carrying the chunk's
      ``SCP-OUTLET-NNNN`` code.
    - **Async-iterable** — ``async for chunk in handle`` yields each
      :class:`OutletStreamChunk` (``Data`` and ``Progress`` included) up to and
      including the terminal chunk.

    **One shared drain, three directions.** Both surfaces consume the SAME
    underlying stream and share one terminal-capture; the executor's chunk
    sequence is drained exactly once. So:

    1. **iterate then aggregate** — after ``async for`` runs to the terminal,
       ``await handle`` / :meth:`aggregate` returns the CACHED ``Aggregate``
       (no re-drain).
    2. **aggregate then iterate** — after ``await handle``, a subsequent
       ``async for`` yields NOTHING (the stream is already fully drained).
    3. **partial-iterate then aggregate** — ``aggregate`` drains the REMAINING
       chunks to the terminal and returns the executor's ``End.aggregate``.

    A stream has a single consumer: draining it from two coroutines
    concurrently (e.g. two ``async for`` loops, or ``await`` racing iteration)
    raises :class:`~scp_sdk.errors.ProtocolError` on the second driver rather
    than silently splitting the chunk sequence between them.

    Two control-plane methods extend the handle:

    - :meth:`grant_credit` — extend the executor's billable credit window.
    - :meth:`cancel` — request stream cancellation.

    Both raise :class:`~scp_sdk.errors.StreamAlreadyClosed` once the stream has
    reached a terminal chunk (the §5.4.5 lifecycle guard).

    The stream is opened lazily — ``invoke`` returns immediately without
    blocking, and the ``outlet_stream_open`` FFI call happens on first
    iteration, ``await``, or ``grant_credit`` (a grant needs a live stream).
    ``cancel`` on a never-opened handle is a local no-op close — it does NOT
    open the stream (no escrow reservation / admission slot) just to cancel it.
    The blocking PyO3 calls (``open`` / ``poll_next`` / ``grant_credit`` /
    ``cancel`` run ``block_on`` internally) are dispatched via
    :func:`asyncio.to_thread` so they never block the event loop, and any
    bridge rejection they raise is translated to the matching SDK exception
    type (``UcanPermissionError`` / ``ValidationError`` / ``ContextError`` /
    …) on every surface — data plane and control plane alike.
    """

    __slots__ = (
        "_aggregate",
        "_closed",
        "_draining",
        "_error",
        "_expected_sequence",
        "_handle_id",
        "_native",
        "_open_lock",
        "_params",
    )

    def __init__(self, native: Any, params: _StreamOpenParams) -> None:
        self._native = native
        self._params = params
        self._handle_id: str | None = None
        self._open_lock = asyncio.Lock()
        # Set once a terminal chunk (End / terminal Error) is observed, or the
        # sender drops without a terminal. Gates the control-plane lifecycle.
        self._closed = False
        # In-flight re-entrancy guard: True while a ``__anext__`` poll is
        # outstanding, so a second concurrent driver fails loud instead of
        # stealing chunks from the shared single-consumer drain.
        self._draining = False
        # Captured terminal state, read back by aggregate().
        self._aggregate: Aggregate | None = None
        self._error: OutletError | None = None
        # §5.4.5 receiver-side monotonicity cursor: the sequence the NEXT chunk
        # must carry. Strictly monotonic per request_id, starting at 0; a chunk
        # whose sequence differs is a StreamGap (defense-in-depth — same-context
        # streams never gap over their lossless ordered channel).
        self._expected_sequence = 0

    async def _ensure_open(self) -> str:
        """Open the stream exactly once (idempotent), returning the bridge
        handle id. Guarded by a lock so concurrent first-touches (e.g. a
        ``grant_credit`` racing the first ``__anext__``) open only one stream.
        """
        if self._handle_id is not None:
            return self._handle_id
        async with self._open_lock:
            if self._handle_id is None:
                p = self._params
                try:
                    handle_id = await asyncio.to_thread(
                        self._native.outlet_stream_open,
                        p.context_id,
                        p.outlet_id,
                        p.input,
                        p.caller_did,
                        p.ucan_token,
                        p.proof_tokens,
                        p.spending_ucan,
                        p.timeout_ms,
                        p.estimated_chunk_count,
                    )
                except Exception as exc:
                    # Open rejections (UCAN denial, input-schema violation,
                    # escrow InsufficientFunds/overflow) surface on the first
                    # await / iteration / control call as the matching SDK type.
                    raise _coded_bridge_error(exc) from exc
                self._handle_id = str(handle_id)
            return self._handle_id

    def __aiter__(self) -> AsyncIterator[OutletStreamChunk]:
        return self

    async def __anext__(self) -> OutletStreamChunk:
        if self._closed:
            raise StopAsyncIteration
        if self._draining:
            raise ProtocolError(
                "InvocationHandle is already being drained by another consumer; "
                "an outlet stream has a single shared drain — do not iterate or "
                "await it from two coroutines concurrently",
                code="SCP-OUTLET-6100",
            )
        self._draining = True
        try:
            handle_id = await self._ensure_open()
            try:
                raw = await asyncio.to_thread(self._native.outlet_stream_poll_next, handle_id)
            except Exception as exc:
                # A mid-drain bridge rejection (unknown handle, transport fault)
                # surfaces on `async for` / `aggregate` as the matching SDK type.
                raise _coded_bridge_error(exc) from exc
            if raw is None:
                # Abnormal terminal: sender dropped without a terminal chunk.
                self._closed = True
                raise StopAsyncIteration
            chunk = OutletStreamChunk._from_bridge_bytes(bytes(raw))
            if chunk.sequence != self._expected_sequence:
                # §5.4.5 "Ordering and gaps": a non-contiguous sequence (a hole,
                # or a regression) is a receiver-detected StreamGap. Mark the
                # drain terminal, cancel the stream through the SAME bridge path
                # public cancel() uses, and raise — WITHOUT yielding the offending
                # chunk. The check spans all chunk kinds (Data/Progress/End/Error)
                # since sequences are strictly monotonic across them.
                self._closed = True
                gap = StreamGap(
                    f"outlet stream sequence gap: expected {self._expected_sequence}, "
                    f"got {chunk.sequence} (§5.4.5)",
                )
                self._error = gap
                # Best-effort receiver cancel: the StreamGap is the reported
                # terminal, so a cancel-path failure must not mask it.
                try:
                    await self._send_cancel(handle_id)
                except Exception:  # best-effort teardown
                    pass
                raise gap
            self._expected_sequence += 1
            if chunk.is_terminal:
                # Terminal chunk closes the stream. Capture the terminal state
                # for aggregate(), mark closed, then still YIELD the terminal
                # chunk so an iterating consumer observes it (End counts toward
                # the visible chunk sequence).
                self._closed = True
                if chunk.kind == "end":
                    self._aggregate = Aggregate(
                        value=chunk.payload.get("aggregate"),
                        provenance=_as_dict(chunk.payload.get("provenance")),
                        execution_time_ms=int(chunk.payload.get("execution_time_ms", 0)),
                    )
                elif chunk.kind == "error":
                    self._error = OutletError(
                        str(chunk.payload.get("message", "outlet stream error")),
                        code=str(chunk.payload.get("code", "SCP-OUTLET-6000")),
                    )
            return chunk
        finally:
            self._draining = False

    def __await__(self) -> Generator[Any, None, Aggregate]:
        return self.aggregate().__await__()

    async def aggregate(self) -> Aggregate:
        """Drain the stream to its terminal and return the :class:`Aggregate`.

        Idempotent: if the stream has already been drained (by ``await`` or by
        full iteration), the captured :class:`Aggregate` is returned without
        re-draining. A terminal ``Error`` chunk raises the typed
        :class:`~scp_sdk.errors.OutletError` it carried; a stream that ends
        without an ``End`` chunk raises :class:`~scp_sdk.errors.ProtocolError`.

        The returned ``value`` matches the outlet's ``aggregate_schema``:
        conformance is enforced executor-side at ``End`` emission (§5.4.5), so
        the SDK surfaces the validated aggregate faithfully rather than
        re-running JSON-Schema validation the executor already performed.
        """
        while not self._closed:
            try:
                await self.__anext__()
            except StopAsyncIteration:
                break
        if self._error is not None:
            raise self._error
        if self._aggregate is None:
            raise ProtocolError(
                "outlet stream closed without an End chunk",
                code="SCP-OUTLET-6100",
            )
        return self._aggregate

    async def grant_credit(self, grant: Credit) -> None:
        """Grant ``grant`` additional billable chunks of credit to the live
        stream (§5.4.5 credit-based backpressure).

        ``grant`` is a validated :class:`Credit`, never a raw ``int``. The FFI
        bridge signs the ``OutletStreamCredit`` internally under the pinned
        invoker's custody key and auto-assigns the strictly-monotonic
        ``monotonic_seq`` — the SDK never touches the invoker key or a
        replay counter (ADR-006).

        Raises :class:`~scp_sdk.errors.StreamAlreadyClosed` if the stream has
        already reached a terminal chunk; otherwise propagates any bridge
        rejection (e.g. ``SCP-PERM-3001`` for a non-invoker caller, or an
        escrow ``InsufficientFunds`` / ``EscrowOverflow``).
        """
        if not isinstance(grant, Credit):
            # Defense in depth: mypy --strict already rejects a raw int, but a
            # dynamically-typed caller must still fail loud and uniform.
            raise InvalidGrant(
                f"grant_credit requires a Credit, got {type(grant).__name__}",
            )
        if self._closed:
            raise StreamAlreadyClosed(
                "cannot grant credit: the outlet stream has already closed",
            )
        handle_id = await self._ensure_open()
        try:
            await asyncio.to_thread(
                self._native.outlet_stream_grant_credit,
                handle_id,
                self._params.caller_did,
                grant.value,
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def cancel(self) -> None:
        """Request cancellation of the live stream (§5.4.5 cancellation).

        The FFI bridge signs the ``OutletCancel`` internally under the pinned
        invoker's custody key at the runtime-derived cursor (the SDK never
        supplies a ``next_seq``). The executor emits exactly one terminal
        cancel-ack chunk within ``stream_cancel_ack_secs``; billing reflects
        the ``cancel_ack_seq``.

        Cancelling a handle whose stream was never opened is a local no-op
        close: it marks the handle closed WITHOUT opening the stream, so a
        cancel never reserves escrow / an admission slot (and never surfaces an
        open-time rejection) just to tear the stream down.

        Raises :class:`~scp_sdk.errors.StreamAlreadyClosed` if the stream has
        already reached a terminal chunk; otherwise propagates any bridge
        rejection (e.g. ``SCP-PERM-3001`` for a non-invoker caller).
        """
        if self._closed:
            raise StreamAlreadyClosed(
                "cannot cancel: the outlet stream has already closed",
            )
        handle_id = self._handle_id
        if handle_id is None:
            # Never opened — cancel is a local close, not a bridge round-trip.
            self._closed = True
            return
        await self._send_cancel(handle_id)

    async def _send_cancel(self, handle_id: str) -> None:
        """Sign and send an ``OutletCancel`` through the bridge (§5.4.5).

        The single bridge cancel round-trip shared by the public
        :meth:`cancel` and the drain's StreamGap teardown, so both cancel
        through the identical signed path.
        """
        try:
            await asyncio.to_thread(
                self._native.outlet_stream_cancel,
                handle_id,
                self._params.caller_did,
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a bridge-supplied provenance field to a dict (empty when absent)."""
    return value if isinstance(value, dict) else {}


class Outlets:
    """The ``ctx.outlets`` accessor — the home of the single ``invoke`` verb.

    Bound to one :class:`~scp_sdk.context.Context`: it carries the context id
    and the caller DID that context is scoped to, and dispatches to the
    context's owning :class:`~scp_sdk.SCP` native bridge. Construct via
    :attr:`scp_sdk.context.Context.outlets`, never directly.
    """

    __slots__ = ("_context_id", "_default_caller_did", "_native")

    def __init__(self, native: Any, context_id: str, default_caller_did: str) -> None:
        self._native = native
        self._context_id = context_id
        self._default_caller_did = default_caller_did

    def invoke(
        self,
        outlet_id: str,
        input: dict[str, Any],
        *,
        ucan_token: str,
        caller_did: str | None = None,
        proof_tokens: list[str] | None = None,
        spending_ucan: str | None = None,
        timeout_ms: int | None = None,
        estimated_chunk_count: int | None = None,
    ) -> InvocationHandle:
        """Invoke ``outlet_id`` and return its :class:`InvocationHandle`.

        This is the ONLY public invocation verb (SCP-OUT-006). The returned
        handle is both awaitable (``await handle`` -> :class:`Aggregate`) and
        async-iterable (``async for chunk in handle``); the streaming FFI ops
        are wrapped behind it. ``invoke`` itself performs no I/O and does not
        block — the stream opens lazily on first ``await`` / iteration /
        control-plane call.

        Args:
            outlet_id: Registration id of the target outlet.
            input: JSON-compatible input value (validated against the outlet's
                ``input_schema`` at open).
            ucan_token: The invoker's authorizing UCAN (required).
            caller_did: The invoking DID. Defaults to the context's
                ``identity_did`` when omitted; must equal the DID pinned as the
                stream invoker for the control-plane methods to authorize.
            proof_tokens: Optional UCAN delegation-chain proof tokens.
            spending_ucan: Optional spending-authorization UCAN for a paid
                (Action) outlet.
            timeout_ms: Optional per-stream timeout in milliseconds.
            estimated_chunk_count: Optional invoker-declared upper bound on
                billable chunks (feeds the §5.4.5 ``caveats_binding``).
        """
        params = _StreamOpenParams(
            context_id=self._context_id,
            outlet_id=outlet_id,
            input=input,
            caller_did=caller_did if caller_did is not None else self._default_caller_did,
            ucan_token=ucan_token,
            proof_tokens=proof_tokens,
            spending_ucan=spending_ucan,
            timeout_ms=timeout_ms,
            estimated_chunk_count=estimated_chunk_count,
        )
        return InvocationHandle(self._native, params)


# ---------------------------------------------------------------------------
# Cross-context STREAMING saga (§5.4.5 / §6.2.4, SCP-OUT-047)
# ---------------------------------------------------------------------------
#
# The STREAMING sibling of the unary block-until-terminal
# :meth:`scp_sdk.SCP.outlet_invoke_cross_context_saga`. Per the ADR-049 §3a
# streaming wait-model amendment, the streaming saga returns its chunk receiver
# PROMPTLY at the Commit-transition (the caller consumes chunks as produced) and
# reaches ``Committed`` ASYNCHRONOUSLY at seal-close — it MUST NOT block until
# the stream terminates (an LLM stream can exceed the unary saga's ~95s bound;
# the credit ceiling bounds chunk count, not wall-clock). The bridge open
# (``outlet_streaming_saga_open``) returns a durable ``saga_id`` promptly, and
# the SDK drives the stream by polling ``outlet_streaming_saga_poll_next(saga_id)``
# behind :class:`StreamingSagaHandle` — modelled on the same-context
# :class:`InvocationHandle` async iterator.
#
# There is NO live control plane (grant_credit / cancel) for the cross-context
# saga stream: per §6.2.5 / SCP-OUT-046 the cross-context stream runs with
# ``cancel_ack_ceiling = u64::MAX`` (no live mid-stream OutletCancel channel).
# The handle is therefore async-iterable + awaitable ONLY — the credit window is
# fixed at open via ``estimated_chunk_count``.


def _translate_saga_open_error(exc: Exception) -> Exception:
    """Translate an ``outlet_streaming_saga_open`` bridge exception to an SDK type.

    The streaming-saga open can reject at the §6.2.4 caller-principal binding or
    a Prepare/Commit-transition as one of the three saga terminals
    (:class:`~scp_sdk.errors.SagaAbortedError` — e.g. an unhosted / non-member
    ``caller_did`` with ``SCP-SAGA-13050``; :class:`~scp_sdk.errors.SagaBusyError`;
    :class:`~scp_sdk.errors.SagaNeedsRepairError`), OR with a plain input / UCAN
    rejection (``ValidationError`` / ``UcanError`` / ``ContextError``). Saga
    terminals are mapped STRUCTURALLY via
    :func:`~scp_sdk.errors._saga_terminal_from_bridge` (preserving the
    ``retry_after_ms`` / ``saga_id`` / ``contended_context`` datum); anything
    else falls through to :data:`~scp_sdk.errors.BRIDGE_ERROR_MAP`.
    """
    translated = _saga_terminal_from_bridge(exc)
    return translated if translated is not None else _translate_bridge_error(exc)


@dataclass
class _StreamingSagaOpenParams:
    """The immutable ``outlet_streaming_saga_open`` argument set, captured at
    :meth:`scp_sdk.SCP.outlet_invoke_cross_context_streaming_saga` and replayed
    on the (lazy) first open. Mirrors the FFI open param order exactly."""

    caller_context_id: str
    target_context_id: str
    caller_did: str
    outlet_registration_id: str
    input: dict[str, Any]
    asserted_nonce_hex: str
    timestamp_ms: int
    chain_depth: int
    ucan_token: str
    proof_tokens: list[str] | None = None
    ucan_proof_id: str | None = None
    timeout_ms: int | None = None
    estimated_chunk_count: int | None = None


class StreamingSagaHandle:
    """The async-iterable + awaitable handle for a §6.2.4 cross-context
    STREAMING saga (SCP-OUT-047).

    Returned by
    :meth:`scp_sdk.SCP.outlet_invoke_cross_context_streaming_saga`. Modelled on
    the same-context :class:`InvocationHandle`, minus the live control plane
    (there is no cross-context grant_credit / cancel — §6.2.5 / SCP-OUT-046).
    It is simultaneously:

    - **Async-iterable** — ``async for chunk in handle`` opens the saga on the
      first pull (``outlet_streaming_saga_open`` returns the durable ``saga_id``
      PROMPTLY at the Commit-transition, NOT block-until-terminal), then yields
      each :class:`OutletStreamChunk` polled from
      ``outlet_streaming_saga_poll_next(saga_id)`` up to and including the
      terminal. Iteration stops on a terminal-flagged chunk (``End`` / terminal
      ``Error``) OR on ``None`` (an abnormal sender-drop terminal).
    - **Awaitable** — ``await handle`` (equivalently
      :meth:`~StreamingSagaHandle.aggregate`) drains to the terminal and returns
      the :class:`Aggregate` from the ``End`` chunk; a terminal ``Error`` chunk
      raises the typed :class:`~scp_sdk.errors.OutletError` it carried.

    The saga is opened LAZILY — the ``outlet_invoke_cross_context_streaming_saga``
    call returns immediately without starting the saga; the open (which drives
    the saga to the Commit-transition and reserves escrow) happens on first
    iteration / ``await``. The blocking PyO3 calls (``open`` runs the saga to the
    Commit-transition; ``poll_next`` blocks on ``recv()``) are dispatched via
    :func:`asyncio.to_thread` so they never block the event loop, and any bridge
    rejection is translated to the matching SDK type — saga terminals
    (:class:`~scp_sdk.errors.SagaAbortedError` /
    :class:`~scp_sdk.errors.SagaBusyError` /
    :class:`~scp_sdk.errors.SagaNeedsRepairError`) on the open, and
    ``ContextError`` for an unknown / evicted ``saga_id`` on a poll.

    A stream has a single consumer: draining it from two coroutines
    concurrently raises :class:`~scp_sdk.errors.ProtocolError` on the second
    driver rather than silently splitting the chunk sequence.
    """

    __slots__ = (
        "_aggregate",
        "_closed",
        "_draining",
        "_error",
        "_expected_sequence",
        "_native",
        "_open_lock",
        "_params",
        "_saga_id",
    )

    def __init__(self, native: Any, params: _StreamingSagaOpenParams) -> None:
        self._native = native
        self._params = params
        # The durable saga id, minted by the supervisor and returned by open.
        # Doubles as the poll_next key. ``None`` until the (lazy) first open.
        self._saga_id: str | None = None
        self._open_lock = asyncio.Lock()
        # Set once a terminal chunk (End / terminal Error) is observed, or the
        # sender drops without a terminal (poll_next -> None).
        self._closed = False
        # In-flight re-entrancy guard: True while a poll is outstanding, so a
        # second concurrent driver fails loud instead of stealing chunks.
        self._draining = False
        # Captured terminal state, read back by aggregate().
        self._aggregate: Aggregate | None = None
        self._error: OutletError | None = None
        # §5.4.5 receiver-side monotonicity cursor: the sequence the NEXT chunk
        # must carry. The bridge forwards A's operator-signed chunks VERBATIM
        # over a lossless ordered mpsc channel (no re-sequencing), so a
        # non-contiguous sequence is a StreamGap (defense-in-depth). There is no
        # live cancel plane, so the gap is a local terminal — the SDK does not
        # sign a receiver cancel (unlike the same-context handle).
        self._expected_sequence = 0

    @property
    def saga_id(self) -> str | None:
        """The durable supervisor-minted saga id, available once the saga has
        been opened (after the first iteration / ``await``); ``None`` before."""
        return self._saga_id

    async def _ensure_open(self) -> str:
        """Open the saga exactly once (idempotent), returning the durable
        ``saga_id``. Guarded by a lock so concurrent first-touches open only one
        saga.
        """
        if self._saga_id is not None:
            return self._saga_id
        async with self._open_lock:
            if self._saga_id is None:
                p = self._params
                try:
                    saga_id = await asyncio.to_thread(
                        self._native.outlet_streaming_saga_open,
                        p.caller_context_id,
                        p.target_context_id,
                        p.caller_did,
                        p.outlet_registration_id,
                        p.input,
                        p.asserted_nonce_hex,
                        p.timestamp_ms,
                        p.chain_depth,
                        p.ucan_token,
                        p.proof_tokens,
                        p.ucan_proof_id,
                        p.timeout_ms,
                        p.estimated_chunk_count,
                    )
                except Exception as exc:
                    # Open rejections — the §6.2.4 caller-principal binding
                    # (unhosted / non-member caller_did), a Prepare/Commit saga
                    # terminal, or an input/UCAN rejection — surface on the first
                    # await / iteration as the matching SDK type. The receiver is
                    # NEVER handed out (self._saga_id stays None).
                    raise _translate_saga_open_error(exc) from exc
                self._saga_id = str(saga_id)
            return self._saga_id

    def __aiter__(self) -> AsyncIterator[OutletStreamChunk]:
        return self

    async def __anext__(self) -> OutletStreamChunk:
        if self._closed:
            raise StopAsyncIteration
        if self._draining:
            raise ProtocolError(
                "StreamingSagaHandle is already being drained by another consumer; "
                "a cross-context streaming saga has a single shared drain — do not "
                "iterate or await it from two coroutines concurrently",
                code="SCP-OUTLET-6100",
            )
        self._draining = True
        try:
            saga_id = await self._ensure_open()
            try:
                raw = await asyncio.to_thread(self._native.outlet_streaming_saga_poll_next, saga_id)
            except Exception as exc:
                # A mid-drain bridge rejection (unknown / evicted saga_id,
                # serialization fault) surfaces as the matching SDK type.
                raise _translate_bridge_error(exc) from exc
            if raw is None:
                # Abnormal terminal: the sender dropped without a terminal chunk.
                self._closed = True
                raise StopAsyncIteration
            chunk = OutletStreamChunk._from_bridge_bytes(bytes(raw))
            if chunk.sequence != self._expected_sequence:
                # §5.4.5 "Ordering and gaps": a non-contiguous sequence is a
                # receiver-detected StreamGap. There is NO live cross-context
                # cancel plane (§6.2.5 / SCP-OUT-046), so the gap is a purely
                # local terminal — mark closed and raise WITHOUT yielding the
                # offending chunk and WITHOUT a bridge cancel round-trip.
                self._closed = True
                gap = StreamGap(
                    f"cross-context streaming-saga sequence gap: expected "
                    f"{self._expected_sequence}, got {chunk.sequence} (§5.4.5)",
                )
                self._error = gap
                raise gap
            self._expected_sequence += 1
            if chunk.is_terminal:
                # Terminal chunk closes the stream. Capture the terminal state
                # for aggregate(), mark closed, then still YIELD the terminal
                # chunk so an iterating consumer observes it.
                self._closed = True
                if chunk.kind == "end":
                    self._aggregate = Aggregate(
                        value=chunk.payload.get("aggregate"),
                        provenance=_as_dict(chunk.payload.get("provenance")),
                        execution_time_ms=int(chunk.payload.get("execution_time_ms", 0)),
                    )
                elif chunk.kind == "error":
                    self._error = OutletError(
                        str(chunk.payload.get("message", "outlet stream error")),
                        code=str(chunk.payload.get("code", "SCP-OUTLET-6000")),
                    )
            return chunk
        finally:
            self._draining = False

    def __await__(self) -> Generator[Any, None, Aggregate]:
        return self.aggregate().__await__()

    async def aggregate(self) -> Aggregate:
        """Drain the saga stream to its terminal and return the :class:`Aggregate`.

        Idempotent: if the stream has already been drained (by ``await`` or by
        full iteration), the captured :class:`Aggregate` is returned without
        re-draining. A terminal ``Error`` chunk raises the typed
        :class:`~scp_sdk.errors.OutletError` it carried; a stream that ends
        without an ``End`` chunk (an abnormal sender-drop) raises
        :class:`~scp_sdk.errors.ProtocolError`.
        """
        while not self._closed:
            try:
                await self.__anext__()
            except StopAsyncIteration:
                break
        if self._error is not None:
            raise self._error
        if self._aggregate is None:
            raise ProtocolError(
                "cross-context streaming saga closed without an End chunk",
                code="SCP-OUTLET-6100",
            )
        return self._aggregate


# ---------------------------------------------------------------------------
# Bidirectional consent protocol (spec section 6.2.0.1)
# ---------------------------------------------------------------------------


__all__ = [
    "Aggregate",
    "Credit",
    "InvocationHandle",
    "OutletCost",
    "OutletDefinition",
    "OutletKind",
    "OutletStreamChunk",
    "Outlets",
    "SagaResult",
    "StreamingSagaHandle",
    "TestVector",
]
