"""SCP exception hierarchy.

All SCP SDK exceptions are rooted at :class:`ScpError`. Each subclass
corresponds to a specific error domain and carries a human-readable
``message`` and a machine-readable ``code`` following the format
``SCP-{CATEGORY}-{NUMBER}`` (see ``.docs/standards/sdk-common.md``).

The hierarchy wraps bridge-level ``ScpPyError`` variants from the
``_scp_core`` PyO3 extension when available, adding Pythonic ergonomics
and additional context.

Exception hierarchy::

    ScpError (root)
    +-- IdentityError         -- DID creation, resolution, key rotation
    +-- ContextError          -- Context lifecycle (create, join, leave, close)
    +-- UcanPermissionError   -- UCAN capability validation
    +-- CryptoError           -- Encryption, decryption, signature
    +-- TransportError        -- Network, relay, connection
    +-- OutletError           -- Outlet registration, invocation, verification
    +-- ValidationError       -- Input validation, schema, parameters

Note: The permission error is named ``UcanPermissionError`` to avoid
shadowing Python's built-in ``PermissionError``.
"""

from __future__ import annotations

import re


class ScpError(Exception):
    """Base exception for all SCP errors.

    Attributes:
        message: Human-readable description of the error.
        code: Machine-readable error code (format: ``SCP-{CATEGORY}-{NUMBER}``).
    """

    #: Default error code for the base class.
    _default_code: str = "SCP-UNKNOWN-0000"

    def __init__(self, message: str, code: str | None = None) -> None:
        self.message = message
        self.code = code if code is not None else self._default_code
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(message={self.message!r}, code={self.code!r})"

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class IdentityError(ScpError):
    """Identity creation, resolution, or key management failure."""

    _default_code: str = "SCP-IDENT-1000"


class ContextError(ScpError):
    """Context lifecycle errors (create, join, leave, close)."""

    _default_code: str = "SCP-CTX-2000"


class UcanPermissionError(ScpError):
    """UCAN capability validation failure.

    Named ``UcanPermissionError`` instead of ``PermissionError`` to avoid
    shadowing Python's built-in ``PermissionError``.
    """

    _default_code: str = "SCP-PERM-3000"


class CryptoError(ScpError):
    """Encryption, decryption, or signature failure.

    Error messages from this class never leak key material or internal
    crypto state.
    """

    _default_code: str = "SCP-CRYPTO-4000"


class TransportError(ScpError):
    """Network or relay communication failure."""

    _default_code: str = "SCP-TRANS-5000"


class OutletError(ScpError):
    """Outlet registration, invocation, or verification failure."""

    _default_code: str = "SCP-OUTLET-6000"


class ProtocolError(OutletError):
    """Protocol-class outlet failure (``OutletErrorClass::Protocol``, §5.4.4).

    The common parent for every protocol-class condition — stream-lifecycle
    violations, stream-already-open, unknown-session — so a ``catch``/``except``
    author can handle all protocol-class errors through one branch. It is a
    DIRECT subclass of :class:`OutletError`; its protocol-class siblings sit at
    this same inheritance depth (the round-5 cross-SDK symmetry rule of
    SCP-OUT-038: lifecycle errors sit at the same depth as their
    semantic-class siblings).

    On the wire the class renders as the lowercase variant ``"protocol"`` and
    carries a code in the ``SCP-OUTLET-6100..6101`` Protocol sub-range.
    """

    _default_code: str = "SCP-OUTLET-6100"


class InvalidGrant(ProtocolError):
    """A stream-credit grant value outside the valid ``u32`` range (§5.4.5).

    Raised at :class:`~scp_sdk.outlets.Credit` construction — ``Credit(0)``,
    ``Credit(-1)``, and ``Credit(2**32)`` all raise this UNIFORMLY (never a bare
    ``TypeError`` / ``ValueError`` / ``RangeError``), matching the SCP-OUT-031
    round-6 uniform ``InvalidGrant`` rule across all four SDKs. The valid range
    is the non-zero ``u32`` interval ``[1, 2**32)``.
    """

    _default_code: str = "SCP-OUTLET-6100"


class StreamAlreadyClosed(ProtocolError):
    """A control-plane call on a handle whose stream already reached a terminal.

    Raised by :meth:`~scp_sdk.outlets.InvocationHandle.grant_credit` and
    :meth:`~scp_sdk.outlets.InvocationHandle.cancel` when the handle's stream
    has already delivered a terminal chunk (an ``End`` or a terminal
    ``Error``) — the §5.4.5 InvocationHandle lifecycle guard (SCP-OUT-038,
    API MAJOR 24). Sits at the same inheritance depth as its protocol-class
    siblings under :class:`ProtocolError`.
    """

    _default_code: str = "SCP-OUTLET-6100"


class StreamGap(ProtocolError):
    """A gap (missing sequence) in an outlet stream's chunk sequence (§5.4.5).

    Sequence values are strictly monotonic per ``request_id``; a receiver that
    observes a gap (a missing or regressed sequence) MUST cancel the stream and
    surface this error (spec §5.4.5 "Ordering and gaps",
    ``OutletErrorClass::Execution::StreamGap``). The SDK ``InvocationHandle``
    drain is that receiver: it tracks the expected next sequence and, on any
    non-contiguous chunk, signs an ``OutletCancel`` through the bridge and raises
    this error. A same-context stream flows over a lossless ordered channel so a
    gap never occurs in production — this is a defense-in-depth monotonicity
    check mirroring the §5.4.5 receiver-side recheck posture.

    Sits at the same inheritance depth as its protocol-class siblings
    (:class:`InvalidGrant`, :class:`StreamAlreadyClosed`) under
    :class:`ProtocolError`. Carries the execution-class code ``SCP-OUTLET-6131``
    (``execution.stream-gap``).
    """

    _default_code: str = "SCP-OUTLET-6131"


class ValidationError(ScpError):
    """Input validation failure (schema, parameters)."""

    _default_code: str = "SCP-VALID-7000"


# ---------------------------------------------------------------------------
# Cross-context outlet-invocation saga (§6.2.4 / ADR-049 §3a) terminal errors.
# ---------------------------------------------------------------------------
#
# These three subclasses surface the typed terminal space of the §6.2.4
# cross-context outlet-invocation saga. Each carries the structured terminal
# datum the contract makes load-bearing as a NAMED attribute, read
# structurally from the bridge exception's ``args`` (never re-parsed from
# the message text). The bridge (``_scp_core``) raises exception classes
# that share these names; :func:`_saga_terminal_from_bridge` translates a
# bridge terminal into the matching SDK class below, preserving the datum.


class SagaAbortedError(OutletError):
    """A §6.2.4 saga aborted at a Prepare phase (authorization, freshness,
    rate limit, co-residency, or a transiently-unavailable participant actor).

    An ``Aborted`` terminal may be a PERMANENT rejection the caller must not
    blindly retry, OR a RETRYABLE transient (rate limit / participant-actor
    unavailable); the two are distinguished by the ``SCP-SAGA-*`` code.

    Attributes:
        retry_after_ms: Rate-limit back-off hint in milliseconds when the
            tripped limiter can compute one, or ``None`` when no precise
            back-off instant exists. NEVER ``0`` — ``0`` would read as
            "retry immediately" and re-trip the same hard limit.
    """

    _default_code: str = "SCP-SAGA-13067"

    def __init__(
        self,
        message: str,
        code: str | None = None,
        retry_after_ms: int | None = None,
    ) -> None:
        super().__init__(message, code)
        #: Rate-limit back-off hint in ms, or ``None`` (never ``0``).
        self.retry_after_ms: int | None = retry_after_ms


class SagaNeedsRepairError(OutletError):
    """A §6.2.4 saga exhausted its Commit retries and may have diverged
    (a partial commit requiring operator repair).

    Attributes:
        saga_id: The durable operator-repair handle for the diverged saga.
    """

    _default_code: str = "SCP-SAGA-13065"

    def __init__(
        self,
        message: str,
        code: str | None = None,
        saga_id: str = "",
    ) -> None:
        super().__init__(message, code)
        #: Durable operator-repair handle for the diverged saga.
        self.saga_id: str = saga_id


class SagaBusyError(OutletError):
    """A §6.2.4 saga's participant context set overlapped an in-flight saga
    (per-participant-context-set gating, §5.15.4).

    Attributes:
        contended_context: The shared context id that overlapped an
            in-flight saga.
    """

    _default_code: str = "SCP-SAGA-13066"

    def __init__(
        self,
        message: str,
        code: str | None = None,
        contended_context: str = "",
    ) -> None:
        super().__init__(message, code)
        #: The shared context id that overlapped an in-flight saga.
        self.contended_context: str = contended_context


def _saga_terminal_from_bridge(exc: BaseException) -> ScpError | None:
    """Translate a bridge saga terminal exception into its SDK class.

    Dispatches on the bridge exception's class *name* (so a mocked bridge
    works without the native extension) and reads the structured terminal
    datum positionally from ``exc.args`` — ``args[0]`` is the message,
    ``args[1]`` the ``SCP-SAGA-13xxx`` code, and ``args[2]`` the typed
    datum (``retry_after_ms`` / ``saga_id`` / ``contended_context``). The
    datum is read STRUCTURALLY, never parsed from the message string.

    Returns the matching SDK exception, or ``None`` if ``exc`` is not one
    of the three saga terminals (so the caller re-raises it unchanged).
    """
    args = exc.args
    message = str(args[0]) if len(args) > 0 else str(exc)
    code = args[1] if len(args) > 1 and isinstance(args[1], str) else None
    datum = args[2] if len(args) > 2 else None

    name = type(exc).__name__
    if name == "SagaAbortedError":
        # retry_after_ms is an int of milliseconds or None (never 0).
        retry_after_ms = datum if isinstance(datum, int) and not isinstance(datum, bool) else None
        return SagaAbortedError(message, code=code, retry_after_ms=retry_after_ms)
    if name == "SagaNeedsRepairError":
        return SagaNeedsRepairError(
            message, code=code, saga_id=str(datum) if datum is not None else ""
        )
    if name == "SagaBusyError":
        return SagaBusyError(
            message, code=code, contended_context=str(datum) if datum is not None else ""
        )
    return None


# ---------------------------------------------------------------------------
# Mapping from bridge error variant names to SDK exceptions.
# ---------------------------------------------------------------------------

#: Maps ``ScpPyError`` variant names (from ``_scp_core``) to SDK exception
#: classes.  Used by bridge integration code to translate Rust-side errors
#: into the correct Python exception.
BRIDGE_ERROR_MAP: dict[str, type[ScpError]] = {
    "IdentityError": IdentityError,
    "ContextError": ContextError,
    "UcanError": UcanPermissionError,
    "CryptoError": CryptoError,
    "TransportError": TransportError,
    "OutletError": OutletError,
    "ValidationError": ValidationError,
}


#: Extracts a ``[SCP-CAT-NNNN]`` code from a bridge exception's string form. The
#: PyO3 bridge formats native exceptions as ``[{code}] {category} error: ...``.
#: Anchored to the start so a code-like substring embedded in {message} cannot
#: masquerade as the real code (same discipline as the TS mapBridgeError anchor).
_SCP_CODE_RE = re.compile(r"^\s*\[(SCP-[A-Z]+-\d+)\]")


def _coded_bridge_error(exc: Exception) -> ScpError:
    """Translate a native ``_scp_core`` exception into a coded SDK exception.

    Looks up the SDK class by the bridge exception's class name (via
    :data:`BRIDGE_ERROR_MAP`, defaulting to :class:`ContextError`) and
    recovers the structured ``SCP-CAT-NNNN`` code from the message so
    callers can branch on ``exc.code`` rather than parsing prose. An
    already-typed :class:`ScpError` is returned unchanged.
    """
    if isinstance(exc, ScpError):
        return exc
    sdk_cls = BRIDGE_ERROR_MAP.get(type(exc).__name__, ContextError)
    match = _SCP_CODE_RE.search(str(exc))
    code = match.group(1) if match is not None else None
    return sdk_cls(str(exc), code=code)


__all__ = [
    "BRIDGE_ERROR_MAP",
    "ContextError",
    "CryptoError",
    "IdentityError",
    "InvalidGrant",
    "OutletError",
    "ProtocolError",
    "SagaAbortedError",
    "SagaBusyError",
    "SagaNeedsRepairError",
    "ScpError",
    "StreamAlreadyClosed",
    "StreamGap",
    "TransportError",
    "UcanPermissionError",
    "ValidationError",
]
