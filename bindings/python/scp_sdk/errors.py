"""SCP exception hierarchy.

All SCP SDK exceptions are rooted at :class:`ScpError`. Each subclass
corresponds to a specific error domain and carries a human-readable
``message`` and a machine-readable ``code`` following the format
``SCP-{CATEGORY}-{NUMBER}`` (see ``.docs/standards/sdk-common.md``).

Outlet-specific §5.4.4 sealed hierarchy
---------------------------------------

The §5.4.4 ``OutletError`` envelope is rendered as a sealed Python class
hierarchy rooted at :class:`OutletError` (abstract). Each
``OutletErrorClass`` variant maps to one of eight concrete subclasses
under it:

* :class:`OutletProtocolError` (named to avoid colliding with the MLS
  ``ProtocolError`` symbol elsewhere in the SDK).
* :class:`AuthorizationError`
* :class:`InputError`
* :class:`ExecutionError`
* :class:`OutputError`
* :class:`EconomicError`
* :class:`TransportError`
* :class:`GovernanceError`

Each concrete class carries a ``class_`` discriminator (the
``OutletErrorClass`` wire form) and the typed ``code``, ``slug``,
``retry``, ``detail``, ``source_chain``, ``pad_nonce``,
``registration_event_id`` envelope fields per §5.4.4. Construction goes
through :func:`OutletError.new` (keyword-only) so the ``outlet_id`` and
``catalog_key`` adjacent string arguments cannot be swapped at the call
site (round-6 swap-risk fix).

Newtypes
~~~~~~~~

* :class:`Credit` — newtype over ``int`` with a zero-rejection factory
  that raises :class:`InvalidGrant` on ``raw <= 0`` or
  ``raw > 2**32 - 1``.
* :class:`CatalogKey` — newtype over ``str`` with a regex-validating
  factory matching the §5.4.4 catalog-key regex
  ``^[a-z][a-z0-9-]{0,63}(\\.[a-z][a-z0-9-]{0,63})*$``.

Both newtypes are ``NewType`` aliases so static type-checkers reject
passing a raw ``int`` / ``str`` where ``Credit`` / ``CatalogKey`` is
expected.

PII redaction
~~~~~~~~~~~~~

Resolved catalog templates and operator-supplied messages MUST be
redacted before surfacing to developer-facing logs:

* email regex ``[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}`` →
  ``"[redacted]"``;
* DID regex ``did:(dht|web|key):[A-Za-z0-9._-]+`` → ``"[redacted]"``.

:func:`redact_pii` performs both passes; SDK logging helpers MUST call
it before emitting the ``message`` field.

Note: the permission error is named :class:`UcanPermissionError` to
avoid shadowing Python's built-in :class:`PermissionError`. The
error-code prefix ``SCP-TOOL-*`` is retained per §9.18 — error codes
are a registered namespace.
"""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass
from typing import Any, NewType

# ---------------------------------------------------------------------------
# Root SCP exception
# ---------------------------------------------------------------------------


class ScpError(Exception):
    """Base exception for all SCP errors."""

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
    """UCAN capability validation failure."""

    _default_code: str = "SCP-PERM-3000"


class CryptoError(ScpError):
    """Encryption, decryption, or signature failure."""

    _default_code: str = "SCP-CRYPTO-4000"


class TransportError(ScpError):
    """Network or relay transport failure (SCP-TRANS-* range).

    Distinct from the §5.4.4 outlet ``OutletTransportError`` which surfaces
    ``SCP-TOOL-6160`` rate-limit / cross-context-bridge failures under the
    sealed outlet hierarchy. This top-level class is the legacy SCP-TRANS-*
    category retained verbatim for back-compat.
    """

    _default_code: str = "SCP-TRANS-5000"


class ValidationError(ScpError):
    """Input validation failure (schema, parameters)."""

    _default_code: str = "SCP-VALID-7000"


# ---------------------------------------------------------------------------
# §5.4.4 Outlet error sealed hierarchy
# ---------------------------------------------------------------------------


# Catalog-key / slug regex per §5.4.4.
_CATALOG_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$")
_CATALOG_KEY_MAX_BYTES = 256

# Eight wire-form OutletErrorClass discriminants.
OUTLET_ERROR_CLASSES: frozenset[str] = frozenset(
    {
        "protocol",
        "authorization",
        "input",
        "execution",
        "output",
        "economic",
        "transport",
        "governance",
    }
)


# --- CatalogKey newtype ---------------------------------------------------

CatalogKey = NewType("CatalogKey", str)


def make_catalog_key(raw: str) -> CatalogKey:
    """Validates ``raw`` against the §5.4.4 regex and returns a typed
    :data:`CatalogKey` newtype.

    Raises :class:`OutletProtocolError` (slug
    ``protocol.malformed-catalog-key``) on regex/length failure so all
    construction errors live under the :class:`OutletError` hierarchy
    (round-6: uniform error type across SDKs).
    """
    if not isinstance(raw, str):
        raise OutletProtocolError(
            message=f"catalog key must be str, got {type(raw).__name__}",
            code="SCP-TOOL-6100",
            slug="protocol.malformed-catalog-key",
            retry=RetryPolicy.never(),
        )
    if not raw or len(raw.encode("utf-8")) > _CATALOG_KEY_MAX_BYTES:
        raise OutletProtocolError(
            message=f"catalog key length out of range: {len(raw)}",
            code="SCP-TOOL-6100",
            slug="protocol.malformed-catalog-key",
            retry=RetryPolicy.never(),
        )
    if not _CATALOG_KEY_RE.match(raw):
        raise OutletProtocolError(
            message=f"malformed catalog key: {raw!r}",
            code="SCP-TOOL-6100",
            slug="protocol.malformed-catalog-key",
            retry=RetryPolicy.never(),
        )
    return CatalogKey(raw)


# --- OutletId alias used by OutletError.new -------------------------------

OutletId = NewType("OutletId", str)


# --- Credit newtype --------------------------------------------------------

Credit = NewType("Credit", int)

_CREDIT_MAX = 2**32 - 1


def make_credit(raw: int) -> Credit:
    """Validates ``raw`` falls in ``(0, 2**32 - 1]`` and returns a typed
    :data:`Credit` newtype.

    Raises :class:`InvalidGrant` (under the :class:`OutletError`
    hierarchy) on out-of-range input. Round-5 used :class:`ValueError`
    here; round-6 unified the error type so all four SDKs surface the
    same exception class for the same condition.
    """
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise InvalidGrant(grant=raw if isinstance(raw, int) else 0)
    if raw <= 0 or raw > _CREDIT_MAX:
        raise InvalidGrant(grant=raw)
    return Credit(raw)


# --- RetryPolicy -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """§5.4.4 tag-5 retry guidance — sealed enum-like dataclass."""

    policy: str
    delay_ms: int | None = None
    min_ms: int | None = None
    max_ms: int | None = None

    @staticmethod
    def never() -> RetryPolicy:
        return RetryPolicy(policy="never")

    @staticmethod
    def immediate() -> RetryPolicy:
        return RetryPolicy(policy="immediate")

    @staticmethod
    def after(delay_ms: int) -> RetryPolicy:
        if delay_ms <= 0:
            raise ValidationError("after delay must be > 0", "SCP-VALID-7000")
        return RetryPolicy(policy="after", delay_ms=delay_ms)

    @staticmethod
    def with_backoff(min_ms: int, max_ms: int) -> RetryPolicy:
        if min_ms <= 0 or max_ms < min_ms:
            raise ValidationError("invalid backoff window", "SCP-VALID-7000")
        return RetryPolicy(policy="with-backoff", min_ms=min_ms, max_ms=max_ms)

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"policy": self.policy}
        if self.policy == "after" and self.delay_ms is not None:
            out["delay_ms"] = self.delay_ms
        elif self.policy == "with-backoff":
            out["min_ms"] = self.min_ms
            out["max_ms"] = self.max_ms
        return out

    @staticmethod
    def from_wire(value: dict[str, Any]) -> RetryPolicy:
        policy = value.get("policy")
        if policy == "never":
            return RetryPolicy.never()
        if policy == "immediate":
            return RetryPolicy.immediate()
        if policy == "after":
            return RetryPolicy.after(int(value["delay_ms"]))
        if policy == "with-backoff":
            return RetryPolicy.with_backoff(int(value["min_ms"]), int(value["max_ms"]))
        raise ValidationError(f"unknown retry policy: {policy!r}", "SCP-VALID-7000")


# --- ContextHop ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContextHop:
    """§5.4.4 tag-8 ``source_chain`` entry."""

    context_id: str
    hop_index: int
    wrapped_code: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "hop_index": self.hop_index,
            "wrapped_code": self.wrapped_code,
        }

    @staticmethod
    def from_wire(value: dict[str, Any]) -> ContextHop:
        return ContextHop(
            context_id=str(value["context_id"]),
            hop_index=int(value["hop_index"]),
            wrapped_code=str(value["wrapped_code"]),
        )


# --- Per-class detail-shape validators ------------------------------------

# Per-class detail-shape schemas — keys are the cross-SDK camelCase wire
# convention (matches TypeScript / Swift / Kotlin). Round-tripping a fixture
# preserves the exact camelCase keys.
_DETAIL_SCHEMAS: dict[str, frozenset[str]] = {
    "protocol": frozenset({"rule"}),
    "authorization": frozenset({"capability"}),
    "input": frozenset({"fieldPath", "violation"}),
    "output": frozenset({"fieldPath", "violation"}),
    "execution": frozenset(),  # accepts {}, {elapsedMs}, or {panicLocationHash}
    "economic": frozenset(),  # accepts {needed,currency} or {adapterId}
    "transport": frozenset(),  # accepts {retryAfterSecs} or {relayUrlKind}
    "governance": frozenset({"action"}),
}


def _validate_detail_shape(class_: str, detail: dict[str, Any] | None) -> None:
    """Per §5.4.4 — reject a detail dict whose shape is not legal for
    ``class_``. Wire-layer rejection (raises :class:`ValidationError`).
    """
    if detail is None:
        return
    if not isinstance(detail, dict):
        raise ValidationError(
            f"OutletError.detail must be dict or None for class {class_!r}",
            "SCP-VALID-7000",
        )
    keys = set(detail.keys())
    if class_ in {"protocol", "authorization", "governance"}:
        expected = _DETAIL_SCHEMAS[class_]
        if keys != expected:
            raise ValidationError(
                f"OutletError.detail for class {class_!r} expects keys "
                f"{sorted(expected)}, got {sorted(keys)}",
                "SCP-VALID-7000",
            )
    elif class_ in {"input", "output"}:
        if keys != _DETAIL_SCHEMAS[class_]:
            raise ValidationError(
                f"OutletError.detail for class {class_!r} expects keys "
                f"{sorted(_DETAIL_SCHEMAS[class_])}, got {sorted(keys)}",
                "SCP-VALID-7000",
            )
    elif class_ == "execution":
        valid = keys == set() or keys == {"elapsedMs"} or keys == {"panicLocationHash"}
        if not valid:
            raise ValidationError(
                "OutletError.detail for execution accepts {}, {elapsedMs}, or {panicLocationHash}",
                "SCP-VALID-7000",
            )
    elif class_ == "economic":
        valid = keys == {"needed", "currency"} or keys == {"adapterId"}
        if not valid:
            raise ValidationError(
                "OutletError.detail for economic accepts {needed,currency} or {adapterId}",
                "SCP-VALID-7000",
            )
    elif class_ == "transport":
        valid = keys == {"retryAfterSecs"} or keys == {"relayUrlKind"}
        if not valid:
            raise ValidationError(
                "OutletError.detail for transport accepts {retryAfterSecs} or {relayUrlKind}",
                "SCP-VALID-7000",
            )
    else:
        raise ValidationError(
            f"unknown OutletErrorClass: {class_!r}",
            "SCP-VALID-7000",
        )


# --- PII redaction ---------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DID_RE = re.compile(r"did:(dht|web|key):[A-Za-z0-9._-]+")


def redact_pii(message: str) -> str:
    """Redact emails and DIDs from ``message`` per §5.4.4.

    Returns the redacted string. Stable across SDKs (matches the same
    regex set in TypeScript/Swift/Kotlin).
    """
    if not isinstance(message, str):
        return message
    redacted = _EMAIL_RE.sub("[redacted]", message)
    redacted = _DID_RE.sub("[redacted]", redacted)
    return redacted


# --- OutletError abstract base + concrete subclasses ----------------------


class OutletError(ScpError, abc.ABC):
    """Abstract base for the §5.4.4 sealed outlet-error hierarchy.

    The eight concrete subclasses (one per ``OutletErrorClass``) all
    inherit from this base. Use :meth:`OutletError.new` (keyword-only)
    to construct an instance — direct construction is allowed but the
    ``class_`` discriminant must match the subclass.

    Legacy callers that construct ``OutletError(message, code)``
    directly receive a :class:`OutletErrorLegacy` shim — preserved so
    pre-§5.4.4 outlet code keeps compiling. New code should use the
    typed subclasses.
    """

    #: ``OutletErrorClass`` wire-form discriminant carried by every
    #: concrete subclass. The abstract base sets ``""`` so legacy
    #: ``OutletError(message, code)`` construction continues to work.
    class_wire: str = ""

    # Pre-OUT-031 default code for the legacy `OutletError(message)`
    # constructor — preserved verbatim so call sites that rely on the
    # implicit ``SCP-TOOL-6000`` default (e.g. tests/test_types.py)
    # continue to compile.
    _default_code: str = "SCP-TOOL-6000"

    def __init__(
        self,
        message: str,
        code: str | None = None,
        *,
        slug: str | None = None,
        retry: RetryPolicy | None = None,
        detail: dict[str, Any] | None = None,
        source_chain: list[ContextHop] | None = None,
        pad_nonce: bytes | None = None,
        registration_event_id: bytes | None = None,
    ) -> None:
        super().__init__(redact_pii(message), code)
        self.slug: str | None = slug
        self.retry: RetryPolicy | None = retry
        self.detail: dict[str, Any] | None = detail
        # `source_chain or []` is intentional — `None` and an empty list
        # are equivalent for the §5.4.4 envelope (an empty trail and an
        # absent trail both render as "no cross-context hops").
        self.source_chain: list[ContextHop] = list(
            source_chain or []
        )  # falsy-ok: empty and absent are equivalent for §5.4.4 source_chain
        self.pad_nonce: bytes | None = pad_nonce
        self.registration_event_id: bytes | None = registration_event_id

    # ----- Static keyword-only constructor (round-6 swap-risk fix) ----

    @staticmethod
    def new(
        *,
        outlet_id: OutletId,
        catalog_key: CatalogKey,
        class_: str,
        code: str | None = None,
        slug: str | None = None,
        retry: RetryPolicy | None = None,
        detail: dict[str, Any] | None = None,
        source_chain: list[ContextHop] | None = None,
        pad_nonce: bytes | None = None,
        registration_event_id: bytes | None = None,
        context_id: str | None = None,
    ) -> OutletError:
        """Construct a typed :class:`OutletError` subclass.

        ``outlet_id`` and ``catalog_key`` are adjacent string arguments
        and would be swappable in a positional call — the leading ``*``
        forces keyword-only invocation so a positional call fails at
        type-check / runtime.

        SCP-OUT-041d: when ``context_id`` AND ``registration_event_id``
        are both provided, this delegates to the PyO3 ``outlet_error_new``
        FFI export which performs the §5.4.4 wire-message HMAC at the
        bridge boundary using the pinned ``outlet_message_key`` — the
        SDK never sees the raw key. When omitted, fall back to the
        local-only path that does NOT compute a wire HMAC (used by tests
        and pre-OUT-041 callers).
        """
        if class_ not in OUTLET_ERROR_CLASSES:
            raise ValidationError(f"unknown OutletErrorClass: {class_!r}", "SCP-VALID-7000")
        # CatalogKey runtime check — raises OutletProtocolError on bad
        # input (round-6 unified error type).
        if not isinstance(catalog_key, str) or not _CATALOG_KEY_RE.match(catalog_key):
            raise OutletProtocolError(
                message=f"catalog_key {catalog_key!r} is not a valid CatalogKey",
                code="SCP-TOOL-6100",
                slug="protocol.malformed-catalog-key",
                retry=RetryPolicy.never(),
            )
        if not isinstance(outlet_id, str) or not outlet_id:
            raise ValidationError("outlet_id must be a non-empty string", "SCP-VALID-7000")

        # SCP-OUT-041d FFI path — delegate to outlet_error_new (PyO3) so
        # the bridge HMACs the catalog_key with the pinned per-outlet
        # outlet_message_key. SDK callers never see the raw key.
        if context_id is not None and registration_event_id is not None:
            return OutletError._new_via_ffi(
                context_id=context_id,
                outlet_id=outlet_id,
                registration_event_id=registration_event_id,
                catalog_key=catalog_key,
                class_=class_,
                code=code,
                slug=slug,
                retry=retry,
                detail=detail,
                source_chain=source_chain,
                pad_nonce=pad_nonce,
            )

        cls = _CLASS_TO_SUBCLASS[class_]
        msg = redact_pii(str(catalog_key))
        return cls(
            message=msg,
            code=code or cls._default_code,
            slug=slug or str(catalog_key),
            retry=retry or RetryPolicy.never(),
            detail=detail,
            source_chain=source_chain,
            pad_nonce=pad_nonce,
            registration_event_id=registration_event_id,
        )

    @staticmethod
    def _new_via_ffi(
        *,
        context_id: str,
        outlet_id: OutletId,
        registration_event_id: bytes,
        catalog_key: CatalogKey,
        class_: str,
        code: str | None,
        slug: str | None,
        retry: RetryPolicy | None,
        detail: dict[str, Any] | None,
        source_chain: list[ContextHop] | None,
        pad_nonce: bytes | None,
    ) -> OutletError:
        """SCP-OUT-041d FFI path — calls PyO3 ``outlet_error_new``.

        Builds the input arguments in wire form, dispatches to the
        bridge, parses the returned JSON envelope back into a typed
        :class:`OutletError` subclass via :meth:`from_wire`. The bridge
        does the HMAC, catalog-membership check, and code/slug regex
        validation; this wrapper is purely a marshaling layer.
        """
        import os

        try:
            import _scp_core  # type: ignore[import-not-found]
        except ImportError as e:
            raise ContextError(
                "failed to import _scp_core -- is the Rust extension built?",
                "SCP-CTX-2000",
            ) from e

        cls = _CLASS_TO_SUBCLASS[class_]
        code_str = code or cls._default_code
        slug_str = slug or str(catalog_key)
        retry_policy = retry or RetryPolicy.never()
        retry_str = retry_policy.to_wire().get("policy", "never")
        if not isinstance(retry_str, str):
            retry_str = "never"
        pad_nonce_bytes = pad_nonce if pad_nonce is not None else os.urandom(16)
        if len(pad_nonce_bytes) != 16:
            raise ValidationError("pad_nonce must be 16 bytes", "SCP-VALID-7000")
        if len(registration_event_id) != 32:
            raise ValidationError("registration_event_id must be 32 bytes", "SCP-VALID-7000")
        import json as _json

        detail_json = _json.dumps(detail) if detail is not None else None
        source_chain_json = (
            _json.dumps([h.to_wire() for h in source_chain]) if source_chain is not None else None
        )

        envelope_json = _scp_core.outlet_error_new(
            context_id,
            str(outlet_id),
            registration_event_id.hex(),
            str(catalog_key),
            class_,
            code_str,
            slug_str,
            retry_str,
            pad_nonce_bytes.hex(),
            detail_json,
            source_chain_json,
        )
        # SCP-OUT-041d wire form: the bridge renders byte fields as hex
        # strings under named keys ("code", "slug", "class", "message",
        # "retry", "pad_nonce", "registration_event_id"), so from_wire
        # consumes the JSON directly.
        envelope = _json.loads(envelope_json)
        return OutletError.from_wire(envelope)

    # ----- Wire round-trip --------------------------------------------

    def to_wire(self) -> dict[str, Any]:
        """Serialize to a wire-form dict (the §5.4.4 envelope)."""
        out: dict[str, Any] = {
            "code": self.code,
            "slug": self.slug,
            "class": self.class_wire,
            "message": self.message,
            "retry": (self.retry or RetryPolicy.never()).to_wire(),
            "source_chain": [h.to_wire() for h in self.source_chain],
        }
        if self.detail is not None:
            out["detail"] = self.detail
        if self.pad_nonce is not None:
            out["pad_nonce"] = self.pad_nonce.hex()
        if self.registration_event_id is not None:
            out["registration_event_id"] = self.registration_event_id.hex()
        return out

    @staticmethod
    def from_wire(value: dict[str, Any]) -> OutletError:
        """Deserialize from a wire-form dict.

        Per-class detail-shape conformance is enforced — a malformed
        detail raises :class:`ValidationError` before the typed
        subclass is constructed.
        """
        class_ = str(value.get("class", "")).lower()
        if class_ not in OUTLET_ERROR_CLASSES:
            raise ValidationError(
                f"unknown OutletErrorClass on wire: {class_!r}",
                "SCP-VALID-7000",
            )
        detail = value.get("detail")
        _validate_detail_shape(class_, detail)
        retry = RetryPolicy.from_wire(value.get("retry") or {"policy": "never"})
        source_chain = [ContextHop.from_wire(h) for h in (value.get("source_chain") or [])]
        pad_nonce = value.get("pad_nonce")
        pad_nonce_bytes = bytes.fromhex(pad_nonce) if isinstance(pad_nonce, str) else None
        reg_id = value.get("registration_event_id")
        reg_id_bytes = bytes.fromhex(reg_id) if isinstance(reg_id, str) else None
        cls = _CLASS_TO_SUBCLASS[class_]
        message_text = str(value.get("message", ""))
        return cls(
            message=message_text,
            code=str(value.get("code", cls._default_code)),
            slug=str(value["slug"]) if value.get("slug") is not None else None,
            retry=retry,
            detail=detail,
            source_chain=source_chain,
            pad_nonce=pad_nonce_bytes,
            registration_event_id=reg_id_bytes,
        )


class OutletProtocolError(OutletError):
    """§5.4.4 ``Protocol`` class — registration / validation /
    classification violations.

    Named ``OutletProtocolError`` (not ``ProtocolError``) to avoid
    colliding with the MLS ``ProtocolError`` symbol elsewhere in the
    SDK (round-6 collision-fix).
    """

    class_wire = "protocol"
    _default_code = "SCP-TOOL-6100"


class AuthorizationError(OutletError):
    """§5.4.4 ``Authorization`` class — UCAN, caveat, role, capability,
    amplification."""

    class_wire = "authorization"
    _default_code = "SCP-TOOL-6110"


class InputError(OutletError):
    """§5.4.4 ``Input`` class — schema, size, type, enum, range."""

    class_wire = "input"
    _default_code = "SCP-TOOL-6120"


class ExecutionError(OutletError):
    """§5.4.4 ``Execution`` class — timeout, panic, resource-exhaustion,
    non-determinism."""

    class_wire = "execution"
    _default_code = "SCP-TOOL-6130"


class OutputError(OutletError):
    """§5.4.4 ``Output`` class — schema, size, non-serializable,
    redaction."""

    class_wire = "output"
    _default_code = "SCP-TOOL-6140"


class EconomicError(OutletError):
    """§5.4.4 ``Economic`` class — budget, insufficient funds, adapter
    failure, pricing."""

    class_wire = "economic"
    _default_code = "SCP-TOOL-6150"


class OutletTransportError(OutletError):
    """§5.4.4 ``Transport`` class — relay unavailable, cross-context
    bridge failure, rate limit, concurrent-streams cap.

    Suffixed ``Outlet`` to coexist with the legacy top-level
    :class:`TransportError` SCP-TRANS-* category class.
    """

    class_wire = "transport"
    _default_code = "SCP-TOOL-6160"


class OutletGovernanceError(OutletError):
    """§5.4.4 ``Governance`` class — deregistered, suspended, revoked,
    ceiling exceeded.

    Suffixed ``Outlet`` to disambiguate from any top-level governance
    category error.
    """

    class_wire = "governance"
    _default_code = "SCP-TOOL-6170"


# Round-6 cross-SDK alias: Kotlin and TypeScript expose the §5.4.4
# governance class as `OutletGovernanceError`; Python keeps a
# `GovernanceError` alias for backward-compat with pre-renamed call
# sites that imported the OUT-031 draft name.
GovernanceError = OutletGovernanceError


# Round-6 ``InvalidGrant`` lives under :class:`OutletProtocolError` so
# all four SDKs surface a uniform error type for the
# ``Credit`` zero-rejection rule (replaces per-SDK ``ValueError`` /
# ``RangeError`` / ``IllegalArgumentException`` divergence shipped in
# round-5).
class InvalidGrant(OutletProtocolError):
    """Raised when a :data:`Credit` is constructed with ``raw <= 0`` or
    ``raw > 2**32 - 1``.

    Surfaces with ``code = 'SCP-TOOL-6101'`` and slug
    ``protocol.invalid-grant``. ``isinstance(err, OutletError)`` and
    ``isinstance(err, OutletProtocolError)`` both return ``True``.
    """

    _default_code = "SCP-TOOL-6101"

    def __init__(self, *, grant: int) -> None:
        super().__init__(
            message=f"invalid grant {grant}: must be in (0, 2^32 - 1]",
            code="SCP-TOOL-6101",
            slug="protocol.invalid-grant",
            retry=RetryPolicy.never(),
        )
        self.grant = grant


# Class-discriminator → subclass dispatch table.
_CLASS_TO_SUBCLASS: dict[str, type[OutletError]] = {
    "protocol": OutletProtocolError,
    "authorization": AuthorizationError,
    "input": InputError,
    "execution": ExecutionError,
    "output": OutputError,
    "economic": EconomicError,
    "transport": OutletTransportError,
    "governance": OutletGovernanceError,
}


# ---------------------------------------------------------------------------
# Legacy compatibility — keeps pre-OUT-031 callers compiling.
# ---------------------------------------------------------------------------
#
# Pre-redesign code constructed ``OutletError(message, code)`` and named
# the leaf classes ``OutletNotFoundError`` / ``OutletExecutionError``.
# Both shapes survive: ``OutletNotFoundError`` and
# ``OutletExecutionError`` are now thin subclasses of
# :class:`OutletProtocolError` and :class:`ExecutionError` respectively
# with the same default codes pre-redesign code expects.


class OutletNotFoundError(OutletProtocolError):
    """Outlet does not exist in the registry (legacy alias).

    Pre-redesign default code ``SCP-TOOL-6100`` is preserved.
    """

    _default_code = "SCP-TOOL-6100"


class OutletExecutionError(ExecutionError):
    """Outlet invocation failed during execution (legacy alias).

    Pre-redesign default code ``SCP-TOOL-6200`` is preserved. The
    SCP-TOOL-6200 code lies outside the §5.4.4 6100-6199 sub-block;
    legacy code that instantiates this shim is exempt from the
    sub-block check (the §5.4.4 envelope constructor enforces the
    sub-block via :func:`OutletError.new` which routes to one of the
    eight typed subclasses).
    """

    _default_code = "SCP-TOOL-6200"


# ---------------------------------------------------------------------------
# Bridge error map — ToolError still resolves to OutletError-rooted classes.
# ---------------------------------------------------------------------------

BRIDGE_ERROR_MAP: dict[str, type[ScpError]] = {
    "IdentityError": IdentityError,
    "ContextError": ContextError,
    "UcanError": UcanPermissionError,
    "CryptoError": CryptoError,
    "TransportError": TransportError,
    "ToolError": OutletProtocolError,
    "OutletError": OutletProtocolError,
    "ValidationError": ValidationError,
}


__all__ = [
    "BRIDGE_ERROR_MAP",
    "OUTLET_ERROR_CLASSES",
    "AuthorizationError",
    "CatalogKey",
    "ContextError",
    "ContextHop",
    "Credit",
    "CryptoError",
    "EconomicError",
    "ExecutionError",
    "GovernanceError",
    "IdentityError",
    "InputError",
    "InvalidGrant",
    "OutletError",
    "OutletExecutionError",
    "OutletId",
    "OutletNotFoundError",
    "OutletProtocolError",
    "OutputError",
    "RetryPolicy",
    "ScpError",
    "TransportError",
    "UcanPermissionError",
    "ValidationError",
    "make_catalog_key",
    "make_credit",
    "redact_pii",
]
