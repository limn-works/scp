"""SDK-level :class:`SCP` entry point for the Python SDK.

See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate")
for the design rationale. The :class:`SCP` class is the only public way
to build against the SCP protocol from Python — each :class:`SCP`
instance owns an independent ``BridgeInstance`` (registries, transport,
context manager), so tests, multi-identity apps, and per-tenant services
can hold distinct instances without sharing state.

The free-function façade that used to delegate to a process-global
default instance was removed in Phase 4 PR 4 (#1549). Every SDK
function now requires an explicit :class:`SCP` argument.

Example usage::

    from scp_sdk import SCP

    # Storage selection is REQUIRED — there is no default (spec §17.6).
    # Construct a fresh instance with explicit in-memory state.
    with SCP(storage={"type": "in_memory"}) as scp:
        # scp.instance_id is a monotonic u64 unique per process.
        ...

    # Explicit in-memory storage config. `shutdown` is async
    # (PR #1690 retro Fix 6) — await it from a coroutine.
    scp = SCP(storage={"type": "in_memory"})
    await scp.shutdown(timeout=5.0)

    # SQLCipher-encrypted on-disk storage (Phase 4 PR 3, #1549).
    scp = SCP(storage={
        "type": "sqlite",
        "path": "/var/lib/my-app",
        "key": b"\\x00" * 32,
    })

    # `resume` and `shutdown` are async — they await the tokio runtime.
    scp.suspend()
    await scp.resume()
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    Protocol,
    TypeAlias,
    TypedDict,
    runtime_checkable,
)

from scp_sdk.errors import ScpError, _coded_bridge_error
from scp_sdk.types import CustodyType

if TYPE_CHECKING:
    from scp_sdk.outlets import OutletDefinition, SagaResult, StreamingSagaHandle

    # Imported under TYPE_CHECKING only to annotate ``ucan_evaluate`` /
    # ``participation_record`` return types without a runtime circular import
    # (trust.py imports SCP). With ``from __future__ import annotations`` the
    # annotation is a lazy string, so the name need only resolve for type
    # checkers, not at import time.
    from scp_sdk.trust import (
        AttestorInfo,
        BehavioralRecord,
        CachedAttestation,
        CapabilityValidation,
        ChallengeVerification,
        EventLogEntry,
        ThresholdRequirement,
        TrustEvaluation,
    )

logger = logging.getLogger("scp_sdk")

__all__ = [
    "SCP",
    "InMemoryStorage",
    "InviteMemberOutcome",
    "KeyCustodyProvider",
    "McpAllowlistState",
    "Sealed",
    "SealedInvitation",
    "SqliteStorage",
    "StorageConfig",
]


@runtime_checkable
class KeyCustodyProvider(Protocol):
    """Caller-supplied custody backend for :meth:`SCP.identity_create_with_custody`.

    Implement this protocol to back a DID's key material with a platform
    keystore (OS keychain, hardware token, HSM wrapper, etc.). The private
    key material never crosses into the Rust core — every cryptographic
    operation is delegated back to your implementation (ADR-006).

    Mirrors the UniFFI ``KeyCustodyProvider`` callback interface so Swift,
    Kotlin, and Python implementations share an identical contract. All
    methods are invoked synchronously by the bridge (the Rust side releases
    the GIL while orchestrating, then re-acquires it per call), so a method
    body may block on a keystore without stalling the asyncio event loop.

    Key identifiers are opaque, numeric-string handles your implementation
    assigns in :meth:`generate_keypair` and maps internally to real key
    material. Byte values are passed and returned as ``bytes``.
    """

    def generate_keypair(self, key_type: str) -> str:
        """Generate a keypair (``"ed25519"`` or ``"x25519"``); return its id."""
        ...

    def sign(self, key_id: str, message: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature of ``message`` under ``key_id``."""
        ...

    def get_public_key(self, key_id: str) -> bytes:
        """Return the 32 public-key bytes for ``key_id``."""
        ...

    def destroy_key(self, key_id: str) -> None:
        """Destroy key material for ``key_id``; subsequent ops must fail."""
        ...

    def dh_agree(self, key_id: str, peer_public: bytes) -> bytes:
        """Return the 32-byte X25519 shared secret with ``peer_public``."""
        ...

    def derive_pseudonym(self, key_id: str, context_id: bytes) -> bytes:
        """Derive a context-scoped pseudonym keypair (v1, static).

        Returns ``public_key_bytes (32) || key_id_utf8`` — the 32-byte
        pseudonym public key concatenated with the UTF-8 numeric id of the
        derived signing key.

        Canonical recipe (all custody backends MUST produce identical bytes)::

            pseudonym_secret = HKDF-SHA256(
                ikm=ed25519_private_seed, salt=b"scp-pseudonym-secret-v1",
                info=b"", length=32)
            seed = HMAC-SHA256(pseudonym_secret, context_id + b"scp-pseudonym")
            pseudonym_keypair = Ed25519_keygen(seed[:32])
        """
        ...

    def derive_rotatable_pseudonym(
        self, key_id: str, context_id: bytes, pseudonym_epoch: int
    ) -> bytes:
        """Derive a rotatable, epoch-scoped pseudonym keypair (v2).

        Returns the same ``public_key_bytes (32) || key_id_utf8`` shape as
        :meth:`derive_pseudonym`. Including the rotation epoch in the HMAC
        derivation produces a different pseudonym per epoch within the same
        context, mitigating relay-side pseudonym correlation.

        Canonical recipe (all custody backends MUST produce identical bytes)::

            pseudonym_secret = HKDF-SHA256(
                ikm=ed25519_private_seed, salt=b"scp-pseudonym-secret-v1",
                info=b"", length=32)
            seed = HMAC-SHA256(
                pseudonym_secret,
                context_id + pseudonym_epoch.to_bytes(8, "big")
                + b"scp-pseudonym-v2")
            pseudonym_keypair = Ed25519_keygen(seed[:32])

        The ``"scp-pseudonym-v2"`` domain separator differs from the v1
        ``"scp-pseudonym"`` so epoch 0 produces a distinct pseudonym from the
        static v1 derivation.
        """
        ...

    def export_signing_key_bytes(self, key_id: str) -> bytes:
        """Return the 32 raw Ed25519 private-seed bytes for ``key_id``.

        Hardware-bound / sign-only custody that cannot export raw bytes should
        raise an exception. The exception is handled per call site: best-effort
        callers (the §9.10.4 pseudonym announcement emitted on context
        join/import) catch it and skip the announcement — peers recover on the
        next explicit announcement — whereas callers that strictly require the
        raw key (governance vote signing via ``identity_create_with_custody``)
        surface a hard error.
        """
        ...

    def custody_type(self, key_id: str) -> str:
        """Return ``"hardware"``, ``"software"``, or ``"in_memory"``."""
        ...


class McpAllowlistState(TypedDict):
    """Snapshot of an :class:`SCP` instance's stdio allowlist state.

    Returned by :meth:`SCP.mcp_get_stdio_allowlist`. Mirrors the Rust
    :class:`scp_mcp::allowlist::AllowlistState` shape so consumers get
    IDE autocomplete on the snapshot fields.
    """

    #: Sorted list of allowed binary basenames.
    allowed: list[str]
    #: ``True`` if enforcement is disabled (unrestricted mode); ``False``
    #: if only :attr:`allowed` may be spawned.
    unrestricted: bool


class InMemoryStorage(TypedDict):
    """Storage config selecting ephemeral encrypted in-memory storage.

    The PyO3 bridge allocates a random AES-256-GCM key at construction
    and discards it on drop — nothing persists across instances.
    """

    type: Literal["in_memory"]


class SqliteStorage(TypedDict):
    """Storage config selecting `SQLCipher`-encrypted on-disk storage (raw key).

    ``path`` is the directory the bridge opens ``scp.db`` inside;
    ``key`` is raw encryption key material (32 bytes recommended) that
    the Rust side zeroizes after `SQLCipher` has consumed it. For the
    passphrase-derived variant, use :class:`SqlitePassphraseStorage`
    instead — supply exactly one of ``key`` or ``passphrase``. See
    :func:`SCP.with_storage`.
    """

    type: Literal["sqlite"]
    path: str
    key: bytes


class SqlitePassphraseStorage(TypedDict):
    """Storage config selecting `SQLCipher`-encrypted on-disk storage (passphrase).

    ``path`` is the directory the bridge opens ``scp.db`` inside;
    ``passphrase`` is a human-chosen secret from which the `SQLCipher`
    key is derived via Argon2id (spec §17.6) with a persisted per-database
    salt sidecar. The passphrase is held in zeroizing memory on the Rust
    side. For the raw-key variant, use :class:`SqliteStorage` instead —
    supply exactly one of ``key`` or ``passphrase``. See
    :func:`SCP.with_storage`.
    """

    type: Literal["sqlite"]
    path: str
    passphrase: str


# Discriminated union of supported storage configurations. The PyO3
# bridge's `SCP.with_storage` constructor dispatches on ``type`` and, for
# the ``sqlite`` type, on the presence of ``key`` vs ``passphrase`` (exactly
# one required); adding a new variant here requires a matching arm in
# `PyBridgeInstance::with_storage_py`.
StorageConfig = InMemoryStorage | SqliteStorage | SqlitePassphraseStorage


@dataclass(frozen=True)
class SealedInvitation:
    """A sealed, signed invitation bundle (ADR-049 Phase 2J; FFI-02 Option A).

    The wire artifact produced by :meth:`SCP.invite_member` on the creator
    side and consumed by :meth:`SCP.context_join_from_welcome` on the joiner
    side. The authoritative genesis params + MLS Welcome travel *inside* the
    signed bundle; the joiner does not supply them separately — the runtime
    opens the bundle under the joiner's key material and authenticates it.

    A flat, frozen, named-field object per the agent-first API tenet, mapping
    1:1 to the native ``_scp_core.PySealedInvitation`` and to the runtime wire
    type ``scp_core::context::invitation_helpers::SealedInvitation``.

    Attributes:
        context_id: Binding hint — the context id the bundle was sealed for.
        creator_did: Binding hint — the creator DID the bundle was sealed by.
        enc: RFC 9180 HPKE encapsulated key. Exactly 32 bytes (validated at
            the join boundary, fail-closed).
        ciphertext: RFC 9180 HPKE ciphertext (``ct = ciphertext || tag``) of
            the serialized, signed ``InvitationBundle``. Opaque bytes.
    """

    context_id: str
    creator_did: str
    enc: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class Sealed:
    """:meth:`SCP.invite_member` outcome — the invitation was sealed.

    The creator (or admin) sealed the context's genesis params + Welcome for
    the invitee under RFC 9180 HPKE, bound to the invitee's ``KeyPackage``.
    Pass :attr:`bundle` straight to the invitee's
    :meth:`SCP.context_join_from_welcome` (no re-assembly); the runtime may
    already have published it for delivery — see :attr:`delivered`.

    Attributes:
        bundle: The sealed :class:`SealedInvitation` — the SAME object the
            joiner passes to :meth:`SCP.context_join_from_welcome`.
        delivered: ``True`` if the runtime published the sealed bundle to the
            invitee's routing id; ``False`` if the caller must deliver it.
    """

    bundle: SealedInvitation
    delivered: bool


# The outcome of :meth:`SCP.invite_member`. Today the only outcome is a sealed
# bundle (:class:`Sealed`); a voting-governed context RAISES instead
# (governed-context invitations are not yet implemented). Kept as an alias
# (rather than bare ``Sealed``) so a future governed-invite outcome is added
# additively as a union member without breaking callers that annotate against
# :data:`InviteMemberOutcome`.
InviteMemberOutcome: TypeAlias = Sealed


def _native_mod() -> Any:
    """Return the ``_scp_core`` PyO3 extension module.

    Raised at call time (not import time) so that pure-Python environments
    — where the native extension isn't available — can still ``import
    scp_sdk`` without an ImportError. The caller sees a meaningful
    :class:`ScpError` the first time they actually use the bridge.

    Used by SDK wrappers that route to module-level free functions per
    ADR-048 §1 (pure helpers exposed as ``_scp_core.<name>``).
    """
    try:
        import _scp_core  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc
    return _scp_core


def _native_cls() -> Any:
    """Return the PyO3-native ``SCP`` class from the ``_scp_core`` extension.

    Raised at call time (not import time) so that pure-Python environments
    — where the native extension isn't available — can still ``import
    scp_sdk`` without an ImportError. The caller sees a meaningful
    :class:`ScpError` the first time they actually construct an instance.
    """
    mod = _native_mod()
    cls = getattr(mod, "SCP", None)
    if cls is None:
        raise ScpError(
            "_scp_core does not export the SCP class — rebuild the native "
            "extension with `maturin develop --release` from the Phase 4 "
            "PR 1 codebase.",
            code="SCP-UNKNOWN-0001",
        )
    return cls


def _to_native_sealed(sealed: SealedInvitation) -> Any:
    """Project an SDK :class:`SealedInvitation` into the native pyclass.

    The PyO3 :meth:`context_join_from_welcome` entry point extracts a typed
    ``_scp_core.PySealedInvitation`` argument (not a loose dict), so the wrapper
    reconstructs the native bundle from the SDK dataclass's four wire fields.
    """
    mod = _native_mod()
    return mod.PySealedInvitation(
        sealed.context_id,
        sealed.creator_did,
        sealed.enc,
        sealed.ciphertext,
    )


def _to_invite_outcome(raw: Any) -> InviteMemberOutcome:
    """Map the native ``PyInviteMemberOutcome`` to the SDK :class:`Sealed`.

    The native outcome carries a ``bundle`` (a native ``PySealedInvitation``)
    and a ``delivered`` flag. The bundle is projected into the SDK
    :class:`SealedInvitation` dataclass so it is directly usable as the
    ``sealed`` argument to :meth:`SCP.context_join_from_welcome`.
    """
    native_bundle = raw.bundle
    return Sealed(
        bundle=SealedInvitation(
            context_id=native_bundle.context_id,
            creator_did=native_bundle.creator_did,
            enc=native_bundle.enc,
            ciphertext=native_bundle.ciphertext,
        ),
        delivered=raw.delivered,
    )


class SCP:
    """Caller-owned SCP instance — the sole public SDK entry point.

    Each :class:`SCP` wraps an independent native ``BridgeInstance`` (with
    its own registries, transport state, and context manager). The wrapper
    exposes lifecycle controls (:meth:`suspend`, :meth:`resume`,
    :meth:`shutdown`) plus the monotonic :attr:`instance_id` used by the
    FFI handle-affinity check.

    Phase 4 PR 4 (#1549, ADR-048) removed the process-global default
    instance and the free-function façade that delegated to it. Phase 4
    PR 5 (ADR-048 §7) completed the Kotlin-parity collapse: the
    per-domain namespace classes (``Identity``, ``Context``, ``Relay``,
    ``Node``, etc.) are pure handle types with no methods — every
    stateful operation is now a method on :class:`SCP` itself
    (:meth:`identity_create`, :meth:`context_create`,
    :meth:`ucan_mint`, and ~160 more). Pure protocol helpers that touch
    no registry state remain module-level free functions.

    :class:`SCP` is a context manager: ``with SCP(storage={"type": "in_memory"}) as scp: ...`` calls
    :meth:`shutdown` with a 5-second timeout on exit.
    """

    # The native PyO3 SCP handle. `frozen=True` on the Rust side guarantees
    # we never mutate it from Python; all state mutation is through the
    # interior atomics/mutexes on `PyBridgeInstance`.
    _native: Any

    def __init__(
        self,
        storage: StorageConfig,
    ) -> None:
        """Construct a fresh :class:`SCP` instance.

        Storage selection is **mandatory** and fail-closed (spec §17.6):
        there is no default backend, so ``storage`` is a required argument.
        Calling ``SCP()`` with no argument raises ``TypeError``.

        :param storage: Storage configuration dict. Accepted shapes:

            * ``{"type": "in_memory"}`` — ephemeral encrypted in-memory
              storage (development/test only).
            * ``{"type": "sqlite", "path": str, "key": bytes}`` —
              SQLCipher-encrypted on-disk storage at ``{path}/scp.db``
              using raw key material. ``key`` is the raw encryption key
              (32 bytes recommended), zeroized on the Rust side once the
              database is opened.
            * ``{"type": "sqlite", "path": str, "passphrase": str}`` —
              SQLCipher-encrypted on-disk storage whose key is derived from
              a passphrase via Argon2id (spec §17.6), with a persisted
              per-database salt sidecar. The passphrase is held in zeroizing
              memory across the FFI boundary.

            For the ``sqlite`` type, supply exactly one of ``key`` or
            ``passphrase`` — providing both, or neither, is a
            ``ValidationError``. A failed SQLCipher open (bad key/passphrase,
            permission denied, corrupt file) also raises a
            ``ValidationError``: storage selection FAILS CLOSED (spec §17.6)
            and never silently degrades to in-memory.
        :raises ValidationError: If ``storage`` contains an unknown
            ``type``, is missing required fields for the selected variant,
            supplies both/neither of ``key``/``passphrase`` for ``sqlite``,
            or the durable backend cannot be opened.

        .. note::

           A standalone ``persistence`` parameter (injecting a custom
           :class:`ContextPersistence` impl across the FFI boundary)
           remains unexposed at the SDK surface. The SQLite storage
           variant above automatically constructs a real
           :class:`ContextPersistence` internally — opt in via the
           ``storage`` dict. A Python-accessible custom persistence
           trait is deferred; no tracking issue is open because SQLite
           covers the documented use cases.
        """
        cls = _native_cls()
        self._native = cls.with_storage(storage)

    @property
    def instance_id(self) -> int:
        """Monotonic u64 identifier for this bridge instance.

        Unique per process. Used by the FFI handle-affinity check — every
        handle minted by this instance stores this id, and FFI entry
        points reject handles whose id does not match the receiving
        instance's id.
        """
        return int(self._native.instance_id)

    def suspend(self) -> None:
        """Suspend the bridge for mobile/desktop backgrounding.

        Disconnects the transport (clears the relay connection) and marks
        the instance as suspended. Context state is preserved;
        transport-dependent operations will fail until :meth:`resume` is
        called.

        :raises TransportError: If transport cleanup fails
            (code ``SCP-TRANS-5001``).
        """
        # Lazy import avoids circular dep (errors -> scp -> errors).
        from scp_sdk.errors import TransportError

        try:
            self._native.suspend()
        except Exception as exc:  # PyO3 raises ScpTransportError
            raise TransportError(
                f"suspend failed: {exc}",
                code="SCP-TRANS-5001",
            ) from exc

    async def resume(self) -> None:
        """Resume a suspended bridge instance.

        Clears the suspended flag and — as of Phase 4 PR 3 (#1678) —
        automatically reconnects the transport to every relay URL the
        instance was subscribed to at suspend time. Callers no longer
        need to re-invoke :func:`scp_sdk.connect_relay` manually; the
        FFI layer replays the pending-URL list internally.

        This is an ``async`` coroutine because the underlying PyO3
        ``resume`` performs async work (transport reconnect, persisted
        context restoration) behind a blocking ``block_on`` at the FFI
        boundary. We wrap the blocking call in :func:`asyncio.to_thread`
        so the Python event loop remains responsive while the reconnect
        round-trips complete. Matches the async ``resume`` surface on
        the NAPI and UniFFI bridges (see #1549 PR 3 — commit
        ``refactor(ffi): make resume() async across bridge core + scp
        handles``).

        :raises ContextError: If the instance has been permanently shut
            down (code ``SCP-CTX-2000``).
        """
        # Lazy import avoids circular dep (errors -> scp -> errors).
        from scp_sdk.errors import ContextError

        try:
            await asyncio.to_thread(self._native.resume)
        except Exception as exc:  # PyO3 raises ScpContextError
            raise ContextError(
                f"resume failed: {exc}",
                code="SCP-CTX-2000",
            ) from exc

    @staticmethod
    def _shutdown_millis(timeout: float) -> int:
        """Clamp ``timeout`` (seconds, float) into a ``u64`` milliseconds
        value usable by the PyO3 bridge.

        Extracted so the sync ``__exit__`` path and the async ``shutdown``
        path share the same numeric contract without duplicating the
        NaN / infinity / overflow handling.
        """
        # u64::MAX milliseconds — matches the Rust-side PyO3 bridge type.
        u64_max = 0xFFFFFFFF_FFFFFFFF
        # Order matters: isinf(+) must be caught BEFORE !isfinite, otherwise
        # math.inf collapses to the NaN/negative abort branch. NaN is not
        # orderable, so explicitly testing isfinite()==False is the only
        # reliable way to trap it.
        if math.isinf(timeout) and timeout > 0:
            return u64_max
        if not math.isfinite(timeout) or timeout <= 0:
            # NaN, negative, negative-infinity, or zero → immediate abort.
            return 0
        if timeout * 1000 > u64_max:
            return u64_max
        return round(timeout * 1000)

    async def shutdown(self, timeout: float = 5.0) -> None:
        """Shut down this instance with a graceful deadline.

        Drains in-flight tasks within ``timeout`` seconds, aborts any
        stragglers, then runs typed-field cleanup. A second call is a
        no-op (the underlying :class:`ShutdownError::AlreadyShutDown` is
        swallowed at the SDK surface).

        ``timeout`` is clamped defensively: ``NaN`` and negative values
        map to ``0`` (abort immediately); ``math.inf`` or values that
        would overflow ``u64`` milliseconds map to ``0xFFFFFFFF_FFFFFFFF``
        (effectively unbounded). Finite in-range values are rounded to
        the nearest millisecond (``round()`` rather than ``int()``
        truncation — we were dropping up to 0.999 ms of caller budget
        per call before the round 2 review).

        This method is async — the underlying PyO3 bridge runs a
        ``block_on`` around the tokio runtime's graceful-shutdown path
        (it may wait up to ``timeout`` seconds for in-flight tasks), so
        we dispatch the blocking call to a worker thread via
        :func:`asyncio.to_thread`. Blocking this on the event loop would
        freeze every other coroutine for the shutdown window. Matches
        the async ``resume`` and ``suspend`` surfaces on the Python
        binding (PR #1690 retro, api-design MAJOR).

        :param timeout: Maximum seconds to wait for in-flight tasks
            (float — fractional seconds are preserved to millisecond
            resolution before crossing the FFI boundary).
        :raises ContextError: If the tokio runtime is unavailable.
        """
        millis = self._shutdown_millis(timeout)
        await asyncio.to_thread(self._native.shutdown, millis)

    def __enter__(self) -> SCP:
        """Enter the synchronous context-manager scope — returns ``self``."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Shut down synchronously on ``with``-scope exit.

        Calls ``_native.shutdown`` directly — the PyO3 bridge already
        runs ``block_on`` internally, so the sync path is correct here.
        Async callers should use :meth:`__aexit__` / ``async with``.
        """
        del exc_type, exc, tb
        self._native.shutdown(self._shutdown_millis(5.0))

    async def __aenter__(self) -> SCP:
        """Enter the asynchronous context-manager scope — returns ``self``."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Shut down asynchronously on ``async with`` scope exit.

        Awaits :meth:`shutdown` so the event loop keeps running while
        the tokio runtime drains in-flight tasks.
        """
        del exc_type, exc, tb
        await self.shutdown()

    # ------------------------------------------------------------------
    # Operation methods — 159 bridge delegators (PyO3 → asyncio.to_thread)
    # ------------------------------------------------------------------
    #
    # Every method below delegates to the same-named attribute on
    # ``self._native`` (the PyO3 ``_scp_core.SCP`` handle). PyO3 methods
    # are synchronous — they perform ``py.allow_threads(|| rt.block_on(..))``
    # internally — so each wrapper offloads to a worker thread via
    # :func:`asyncio.to_thread` to keep the asyncio event loop responsive.
    #
    # Grouped by domain under ``# region`` banners. Added in Phase 4 PR 5
    # (#1549) — the SDK surface collapse that replaced the module-level
    # free-function façade with method calls on :class:`SCP`.

    # region Identity

    async def create_identity_link_attestation(
        self,
        did: str,
        platform: str,
        handle: str,
        proof: str,
        verification_method: str,
        platform_id: str | None = None,
    ) -> Any:
        """Create an identity link attestation (§3.5).

        Returns an :class:`~scp_sdk.identity.IdentityAttestation` on success.
        Raises :class:`~scp_sdk.errors.AttestationError` when the bridge does
        not expose attestation creation (missing FFI feature).
        """
        import json

        from scp_sdk.errors import AttestationError
        from scp_sdk.identity import IdentityAttestation

        if not hasattr(self._native, "create_identity_link_attestation"):
            raise AttestationError(
                "Identity link attestation creation is not yet available in the bridge",
                "SCP-ATTEST-9010",
            )
        result_json = await asyncio.to_thread(
            self._native.create_identity_link_attestation,
            did,
            platform,
            handle,
            proof,
            verification_method,
            platform_id,
        )
        data = json.loads(result_json) if isinstance(result_json, str) else result_json
        return IdentityAttestation._from_dict(data)

    async def identity_add_agent_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_add_agent_key`` (returns :class:`Identity`)."""
        from scp_sdk.identity import Identity

        try:
            raw = await asyncio.to_thread(self._native.identity_add_agent_key, identity)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return Identity(raw)

    async def identity_attest_device(self, identity_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_attest_device``.

        On a shipped build this fails closed: no production device-attestation
        backend is wired yet (Apple App Attest / Google Play Integrity are
        hardware/platform-backed and are intentionally deferred with hardware
        keychain custody until an e2e-driven integration lands; spec §9:187).
        Raises :class:`~scp_sdk.errors.IdentityError` (``SCP-IDENT-1015``). See
        #2171.
        """
        from scp_sdk.errors import IdentityError

        if not hasattr(self._native, "identity_attest_device"):
            raise IdentityError(
                "device attestation unavailable: no production device-attestation "
                "backend is wired yet — Apple App Attest / Google Play Integrity are "
                "hardware/platform-backed and are intentionally deferred (with hardware "
                "keychain custody) until an e2e-driven integration lands (spec §9:187). "
                "See #2171.",
                "SCP-IDENT-1015",
            )
        return await asyncio.to_thread(self._native.identity_attest_device, identity_did)

    async def identity_create(self, custody: CustodyType | str = CustodyType.FILE) -> Any:
        """Delegate to ``_scp_core.SCP.identity_create`` (returns :class:`Identity`)."""
        from scp_sdk.identity import Identity

        custody_str = custody.value if isinstance(custody, CustodyType) else custody
        raw = await asyncio.to_thread(self._native.identity_create, custody_str)
        return Identity(raw)

    async def identity_create_with_agent_key(
        self, custody: CustodyType | str = CustodyType.FILE
    ) -> Any:
        """Delegate to ``_scp_core.SCP.identity_create_with_agent_key``.

        Returns an :class:`Identity` wrapper.
        """
        from scp_sdk.identity import Identity

        custody_str = custody.value if isinstance(custody, CustodyType) else custody
        raw = await asyncio.to_thread(self._native.identity_create_with_agent_key, custody_str)
        return Identity(raw)

    async def identity_create_with_custody(self, provider: KeyCustodyProvider) -> Any:
        """Create a DID whose key material lives in a caller-provided custody.

        Delegate to ``_scp_core.SCP.identity_create_with_custody``. The
        ``provider`` is any object implementing the
        :class:`KeyCustodyProvider` protocol — the private key material never
        crosses into the Rust core (ADR-006). Use this to back a DID with a
        platform keychain, hardware token, or HSM wrapper.

        The blocking bridge call runs in :func:`asyncio.to_thread` so the
        provider's (potentially blocking) keystore operations do not stall the
        asyncio event loop.

        :param provider: A :class:`KeyCustodyProvider` implementation.
        :returns: An :class:`Identity` wrapper.
        :raises ScpError: if the provider is missing required methods
            (``ValidationError``) or key/DID creation fails inside the
            provider (``IdentityError``).
        """
        from scp_sdk.identity import Identity

        raw = await asyncio.to_thread(self._native.identity_create_with_custody, provider)
        return Identity(raw)

    async def identity_execute_custody_migration(
        self, did: str, target: str, context_ids: list[str]
    ) -> dict[str, Any]:
        """Delegate to ``_scp_core.SCP.identity_execute_custody_migration``.

        Returns the migration outcome dict parsed from the bridge's JSON
        payload (§3.2.1).

        :param did: The DID whose custody is migrating. **Must be owned
            by this :class:`SCP` instance** — created or loaded via
            :meth:`identity_create` / :meth:`identity_load`. DIDs
            absent from the instance's identity registry are rejected
            with ``SCP-IDENT-1024`` (round-3 red-hat fix against
            realm-local callers driving unmetered orchestrator work on
            arbitrary DIDs).
        :param context_ids: The contexts to migrate. Capped at **1024**
            entries per call; over-cap requests return
            ``SCP-VALID-7120`` before the orchestrator runs. The
            recovery / migration orchestrator runs on ``crate::runtime``
            via ``block_on`` — the cap bounds per-call amplification.
            A per-bridge semaphore
            (``NapiBridgeInstance::recovery_semaphore``) composes with
            the cap to bound concurrent invocations; exhausted permits
            return ``SCP-VALID-7140`` non-blockingly (see ADR-048 §7
            round-2/3 hardening).
        """
        import json

        result_json = await asyncio.to_thread(
            self._native.identity_execute_custody_migration, did, target, context_ids
        )
        return json.loads(result_json) if isinstance(result_json, str) else result_json

    async def identity_execute_recovery(
        self, did: str, tier: str, context_ids: list[str]
    ) -> dict[str, Any]:
        """Delegate to ``_scp_core.SCP.identity_execute_recovery``.

        **Fails closed (#2240).** The §9.12 recovery WIRE (a real recovery
        backend plus step-1 key rotation) is not yet built — it is tracked as
        #2240 Part B and needs human design sign-off. Until it is wired, this
        surface raises a typed ``IdentityError`` ("recovery backend not
        configured — provide a real backend via SDK layer") rather than
        fabricating a success. It never reports a recovery that did not happen.

        :param did: The compromised DID. **Must be registered on this**
            :class:`SCP` **instance** — created here via
            :meth:`identity_create` (or :meth:`identity_migrate`); a DID
            that was only resolved via :meth:`identity_load` is not
            registered for recovery. DIDs absent from the instance's
            registry are rejected with ``SCP-IDENT-1020``.
        :param tier: Compromise tier: ``"agent"``, ``"active_signing"``, or
            ``"identity_key"``. An unknown tier is rejected with
            ``SCP-IDENT-1021`` (distinct from the ``SCP-IDENT-1020`` ownership
            rejection above).
        :param context_ids: Contexts to run the recovery protocol
            against. Accepted for signature symmetry with the wired
            backend (#2240 Part B); ignored on the current fail-closed
            path. The NAPI binding additionally enforces a 1024-entry
            length cap (``SCP-VALID-7120``) and a concurrency permit
            (``SCP-VALID-7140``); those DoS bounds are runtime-specific
            and land on this binding when the Part B orchestrator does.
        """
        import json

        try:
            result_json = await asyncio.to_thread(
                self._native.identity_execute_recovery, did, tier, context_ids
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return json.loads(result_json) if isinstance(result_json, str) else result_json

    async def identity_link_attestations(self, did: str) -> list[Any]:
        """List identity link attestations for *did* (§3.5).

        Returns a list of :class:`~scp_sdk.identity.IdentityAttestation`
        instances. Raises :class:`~scp_sdk.errors.AttestationError` when the
        bridge does not expose the endpoint.
        """
        import json

        from scp_sdk.errors import AttestationError
        from scp_sdk.identity import IdentityAttestation

        if not hasattr(self._native, "identity_link_attestations"):
            raise AttestationError(
                "Identity link attestation listing is not yet available in the bridge",
                "SCP-ATTEST-9011",
            )
        result_json = await asyncio.to_thread(self._native.identity_link_attestations, did)
        items = json.loads(result_json) if isinstance(result_json, str) else result_json
        return [IdentityAttestation._from_dict(item) for item in items]

    async def identity_load(self, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.identity_load`` (returns :class:`Identity`)."""
        from scp_sdk.identity import Identity

        raw = await asyncio.to_thread(self._native.identity_load, did)
        return Identity(raw)

    async def identity_migrate(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_migrate``.

        The bridge returns a tuple ``(PyIdentity, rotation_event_json)``
        — the JSON-serialized ``DidRotationEvent`` (spec §9.12,
        ADR-003 §4b) is attached to the returned :class:`Identity`
        wrapper as ``identity.rotation_event_json`` so SDK callers can
        distribute the event to active context members (spec §9.12,
        ADR-003 §4b).
        """
        from scp_sdk.identity import Identity

        try:
            raw_handle, rotation_event_json = await asyncio.to_thread(
                self._native.identity_migrate, identity
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return Identity(raw_handle, rotation_event_json=rotation_event_json)

    async def identity_remove_agent_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_remove_agent_key`` (returns :class:`Identity`)."""
        from scp_sdk.identity import Identity

        try:
            raw = await asyncio.to_thread(self._native.identity_remove_agent_key, identity)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return Identity(raw)

    async def identity_remove(self, did: str) -> None:
        """Remove a DID from this instance's SCP-side identity registry.

        Drops the retained identity state for ``did``. Idempotent — returns
        without error when the DID is not present. Delegates to
        ``_scp_core.SCP.identity_remove``.
        """

        try:
            await asyncio.to_thread(self._native.identity_remove, did)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def identity_remove_if_present(self, did: str) -> bool:
        """Remove a DID from the identity registry if present.

        Returns ``True`` if the identity was found and removed, ``False`` if
        the DID was not in the registry. Delegates to
        ``_scp_core.SCP.identity_remove_if_present``.
        """

        try:
            return await asyncio.to_thread(self._native.identity_remove_if_present, did)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def identity_renew_attestation(self, did: str, attestation_id: str) -> Any:
        """Renew an identity link attestation (§3.5.2).

        Returns an :class:`~scp_sdk.identity.IdentityAttestation` with a
        refreshed ``verified_at`` timestamp. Raises
        :class:`~scp_sdk.errors.AttestationError` when the bridge does not
        expose renewal.
        """
        import json

        from scp_sdk.errors import AttestationError
        from scp_sdk.identity import IdentityAttestation

        if not hasattr(self._native, "identity_renew_attestation"):
            raise AttestationError(
                "Identity link attestation renewal is not yet available in the bridge",
                "SCP-ATTEST-9013",
            )
        result_json = await asyncio.to_thread(
            self._native.identity_renew_attestation, did, attestation_id
        )
        data = json.loads(result_json) if isinstance(result_json, str) else result_json
        return IdentityAttestation._from_dict(data)

    async def identity_resolve(self, did: str) -> Any:
        """Resolve a DID to its DID Document (returns :class:`DIDDocument`)."""
        from scp_sdk.identity import _bridge_doc_to_dataclass

        raw = await asyncio.to_thread(self._native.identity_resolve, did)
        return _bridge_doc_to_dataclass(raw)

    async def identity_rotate_agent_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_rotate_agent_key`` (returns :class:`Identity`)."""
        from scp_sdk.identity import Identity

        try:
            raw = await asyncio.to_thread(self._native.identity_rotate_agent_key, identity)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return Identity(raw)

    async def identity_rotate_key(self, identity: Any) -> Any:
        """Delegate to ``_scp_core.SCP.identity_rotate_key`` (returns :class:`Identity`)."""
        from scp_sdk.identity import Identity

        try:
            raw = await asyncio.to_thread(self._native.identity_rotate_key, identity)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return Identity(raw)

    async def identity_verify_device_attestation(self, did: str, token_base64: str) -> Any:
        """Delegate to ``_scp_core.identity_verify_device_attestation``.

        ADR-048 §1: pure helper exposed as a module-level free function.

        On a shipped build this fails closed: no production device-attestation
        backend is wired yet (Apple App Attest / Google Play Integrity are
        hardware/platform-backed and are intentionally deferred with hardware
        keychain custody until an e2e-driven integration lands; spec §9:187).
        Raises :class:`~scp_sdk.errors.IdentityError` (``SCP-IDENT-1016``). See
        #2171.
        """
        from scp_sdk.errors import IdentityError

        mod = _native_mod()
        if not hasattr(mod, "identity_verify_device_attestation"):
            raise IdentityError(
                "device attestation verification unavailable: no production "
                "device-attestation backend is wired yet — Apple App Attest / Google "
                "Play Integrity are hardware/platform-backed and are intentionally "
                "deferred (with hardware keychain custody) until an e2e-driven "
                "integration lands (spec §9:187). See #2171.",
                "SCP-IDENT-1016",
            )
        return await asyncio.to_thread(mod.identity_verify_device_attestation, did, token_base64)

    async def remove_identity_link_attestation(self, did: str, attestation_id: str) -> bool:
        """Remove an identity link attestation.

        Returns ``True`` if the attestation existed and was removed,
        ``False`` if no attestation with that ID was present.
        """
        from scp_sdk.errors import AttestationError

        if not hasattr(self._native, "remove_identity_link_attestation"):
            raise AttestationError(
                "Identity link attestation removal is not yet available in the bridge",
                "SCP-ATTEST-9012",
            )
        return await asyncio.to_thread(
            self._native.remove_identity_link_attestation, did, attestation_id
        )

    async def verify_identity_link_attestation(
        self, attestation_json: str, issuer_public_key_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.py_verify_identity_link_attestation``.

        ADR-048 §1: pure helper exposed as a module-level free function.
        """
        mod = _native_mod()
        return await asyncio.to_thread(
            mod.py_verify_identity_link_attestation,
            attestation_json,
            issuer_public_key_hex,
        )

    # endregion Identity

    # region Context

    async def access_key_generate(self, context_id: str, member_did: str, caller_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.access_key_generate``."""
        return await asyncio.to_thread(
            self._native.access_key_generate, context_id, member_did, caller_did
        )

    async def access_key_restore(self, context_id: str, member_did: str, caller_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.access_key_restore``."""
        return await asyncio.to_thread(
            self._native.access_key_restore, context_id, member_did, caller_did
        )

    async def access_key_revoke(self, context_id: str, member_did: str, caller_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.access_key_revoke``."""
        return await asyncio.to_thread(
            self._native.access_key_revoke, context_id, member_did, caller_did
        )

    async def context_close(self, handle: Any, identity_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_close``."""
        return await asyncio.to_thread(self._native.context_close, handle, identity_did)

    async def context_create(self, identity_did: str, params: dict[str, Any]) -> Any:
        """Delegate to ``_scp_core.SCP.context_create`` (returns :class:`Context`)."""
        from scp_sdk.context import Context

        raw = await asyncio.to_thread(self._native.context_create, identity_did, params)
        return Context(raw, identity_did=identity_did, scp=self)

    async def context_drain_events(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_drain_events``."""
        return await asyncio.to_thread(self._native.context_drain_events, handle)

    async def context_export(self, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_export``."""
        return await asyncio.to_thread(self._native.context_export, context_id)

    async def context_handle_ttl_expiry(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_handle_ttl_expiry``."""
        return await asyncio.to_thread(self._native.context_handle_ttl_expiry, handle)

    async def context_import(self, data: Any, importer_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_import`` (returns :class:`Context`).

        ``importer_did`` is the DID of the identity importing the context; the
        bridge derives that identity's per-context pseudonym routing ID
        (§9.10.4) so the importer fans out under its own routing ID rather than
        inheriting the exporter's local-instance pseudonym.
        """
        from scp_sdk.context import Context

        raw = await asyncio.to_thread(self._native.context_import, data, importer_did)
        if raw is None:
            return None
        return Context(raw, identity_did=importer_did, scp=self)

    async def context_is_member(self, handle: Any, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_is_member``."""
        return await asyncio.to_thread(self._native.context_is_member, handle, did)

    async def context_join(
        self, handle: Any, identity_did: str, spending_ucan_jwt: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.context_join``."""
        return await asyncio.to_thread(
            self._native.context_join, handle, identity_did, spending_ucan_jwt
        )

    async def reserve_key_package(self, owning_did: str) -> tuple[str, bytes]:
        """Reserve a single-use MLS ``KeyPackage`` to be invited into a context.

        First step of the reserve -> Welcome -> join handshake (ADR-049 Phase
        2J). ``owning_did`` MUST be a locally-custodied identity — the same
        trust model as :meth:`context_create`. Only the PUBLIC ``KeyPackage``
        bytes cross the FFI boundary; the private signer state never leaves the
        node's ``KeyPackage`` actor.

        Hand the returned ``key_package_public`` bytes to the context creator
        (out of band). The creator mints an MLS Welcome addressed to that
        ``KeyPackage`` and returns it; complete the join by passing the Welcome
        and the returned ``reservation_id`` to
        :meth:`context_join_from_welcome`.

        Example::

            reservation_id, key_package_public = await scp.reserve_key_package(
                joiner.did
            )
            # ... hand key_package_public to the creator; the creator calls
            # invite_member(...) and returns the resulting SealedInvitation ...
            ctx = await scp.context_join_from_welcome(
                joiner.did, sealed, reservation_id
            )

        Args:
            owning_did: DID of the LOCAL identity reserving the ``KeyPackage``.

        Returns:
            A ``(reservation_id, key_package_public)`` tuple: the opaque
            reservation-id string to pass back to
            :meth:`context_join_from_welcome`, and the public MLS
            ``KeyPackage`` bytes to hand to the context creator.

        Raises:
            Exception: If ``owning_did`` is not a locally-custodied identity, or
                the reservation fails (providers not wired, empty pool).

        Delegates to ``_scp_core.SCP.reserve_key_package``.
        """
        return await asyncio.to_thread(self._native.reserve_key_package, owning_did)

    async def context_join_from_welcome(
        self,
        owning_did: str,
        sealed: SealedInvitation,
        reservation_id: str,
    ) -> Any:
        """Join a context from a sealed invitation bundle (returns :class:`Context`).

        Completes the reserve -> invite -> join handshake begun by
        :meth:`reserve_key_package` (ADR-049 Phase 2J; FFI-02 Option A): given
        the :class:`SealedInvitation` the creator produced via
        :meth:`invite_member` for the previously-reserved ``KeyPackage``, the
        runtime opens the sealed bundle under the joiner's key material,
        authenticates the creator's signature over the genesis params, installs
        the joined MLS group, derives the joiner's §9.10.4 routing pseudonym from
        its locally-custodied identity, and stands the local (joiner) identity up
        as a send-capable participant with an actor-backed handle. Without it a
        Welcome-joined node can DECRYPT but cannot SEND.

        The authoritative context params + MLS Welcome travel *inside* the signed
        bundle — the joiner no longer supplies loose ``params``/``welcome_bytes``.
        The returned handle reflects the params the creator actually signed, not
        caller input. ``creator_did`` and ``context_id`` are carried by
        :class:`SealedInvitation` as binding hints.

        Custody of the JOINER (``owning_did``) is enforced exactly as
        :meth:`context_create` enforces it for the creator: the routing pseudonym
        is DERIVED from the joiner's local custody, never caller-supplied, so a
        non-custodied joiner hard-fails before the single-use ``KeyPackage`` is
        consumed.

        Example::

            reservation_id, key_package_public = await scp.reserve_key_package(
                joiner.did
            )
            # ... creator calls invite_member(...) → Sealed(bundle, delivered);
            # hand `outcome.bundle` back to the joiner (no re-assembly) ...
            ctx = await scp.context_join_from_welcome(
                joiner.did, outcome.bundle, reservation_id
            )

        Args:
            owning_did: DID of the LOCAL (joiner) identity — its custody derives
                the routing pseudonym.
            sealed: The :class:`SealedInvitation` bundle (``context_id``,
                ``creator_did``, ``enc``, ``ciphertext``) produced by the
                creator's :meth:`invite_member`.
            reservation_id: The opaque reservation-id string returned by
                :meth:`reserve_key_package` for the ``KeyPackage`` this bundle's
                Welcome addresses.

        Returns:
            A :class:`~scp_sdk.context.Context` in the ``"active"`` state for the
            joined context, scoped to the joiner (``owning_did``).

        Raises:
            Exception: If the joiner is not locally custodied, the sealed bundle
                fails to open or authenticate, the ``enc`` is not 32 bytes, the
                reservation id is malformed, or the spawn fails (bad/duplicate
                Welcome, single-use replay, first-writer-wins collision, or
                fail-closed persist failure).

        Delegates to ``_scp_core.SCP.context_join_from_welcome``.
        """
        from scp_sdk.context import Context

        native_sealed = _to_native_sealed(sealed)
        raw = await asyncio.to_thread(
            self._native.context_join_from_welcome,
            owning_did,
            native_sealed,
            reservation_id,
        )
        return Context(raw, identity_did=owning_did, scp=self)

    async def invite_member(
        self,
        context_id: str,
        creator_did: str,
        invitee_did: str,
        invitee_key_package: bytes,
        relay_urls: list[str],
    ) -> InviteMemberOutcome:
        """Invite a member into a context (ADR-049 Phase 2J; FFI-02 Option A).

        The inviting member (``creator_did``, which MUST be locally custodied)
        seals the context's genesis params + MLS Welcome for the invitee under
        RFC 9180 HPKE, binding them to the invitee's ``KeyPackage``, and signs
        the bundle under its ``#active`` key. The invitee reserves its
        ``KeyPackage`` via :meth:`reserve_key_package` and hands the public bytes
        to the inviter out of band.

        Only a ``SingleAdmin`` context is supported today: the invite is
        unilateral and returns a :class:`Sealed` outcome whose :attr:`~Sealed.bundle`
        is the :class:`SealedInvitation` — pass it straight to the invitee's
        :meth:`context_join_from_welcome`. A voting-governed context RAISES
        (governed-context invitations are not yet implemented).

        The invite routes through the actor governance gate, which requires the
        inviter to hold the ``governance:propose`` capability. A normally-created
        ``SingleAdmin`` context grants its admin that capability at genesis, so it
        works out of the box; a context with a custom ceiling must grant
        ``governance:propose`` to the inviter.

        Example::

            reservation_id, invitee_kp = await joiner_scp.reserve_key_package(
                invitee.did
            )
            outcome = await scp.invite_member(
                context_id, creator.did, invitee.did, invitee_kp, []
            )
            # `outcome.bundle` is directly usable — no manual re-assembly:
            ctx = await joiner_scp.context_join_from_welcome(
                invitee.did, outcome.bundle, reservation_id
            )

        Args:
            context_id: The context to invite into.
            creator_did: The inviting member's DID (locally custodied; the invite
                is signed under its ``#active`` key).
            invitee_did: The DID being invited.
            invitee_key_package: The invitee's TLS-serialized MLS ``KeyPackage``
                (the public bytes from the invitee's :meth:`reserve_key_package`).
            relay_urls: Relay URLs to include for the invitee's first contact.

        Returns:
            A :class:`Sealed` outcome carrying the sealed
            :attr:`~Sealed.bundle` and the :attr:`~Sealed.delivered` flag.

        Raises:
            Exception: If the supervisor is not initialized, the inviter is not
                locally custodied / its signing key cannot be resolved, the
                context is unknown, the context is voting-governed (governed-context
                invitations are not yet implemented), the inviter is unauthorized,
                or the ``KeyPackage`` is invalid.

        Delegates to ``_scp_core.SCP.invite_member``.
        """
        raw = await asyncio.to_thread(
            self._native.invite_member,
            context_id,
            creator_did,
            invitee_did,
            invitee_key_package,
            relay_urls,
        )
        return _to_invite_outcome(raw)

    async def context_leave(self, handle: Any, identity_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_leave``."""
        return await asyncio.to_thread(self._native.context_leave, handle, identity_did)

    async def context_member_count(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_member_count``."""

        try:
            return await asyncio.to_thread(self._native.context_member_count, handle)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def context_member_dids(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_member_dids``."""
        return await asyncio.to_thread(self._native.context_member_dids, handle)

    async def context_member_role(self, handle: Any, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.context_member_role``."""
        return await asyncio.to_thread(self._native.context_member_role, handle, did)

    async def context_propose_ttl_extension(
        self, handle: Any, member_did: str, proposed_seconds: int
    ) -> Any:
        """Delegate to ``_scp_core.SCP.context_propose_ttl_extension``."""
        return await asyncio.to_thread(
            self._native.context_propose_ttl_extension, handle, member_did, proposed_seconds
        )

    async def context_receive(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.context_receive``."""
        return await asyncio.to_thread(self._native.context_receive, handle)

    async def context_reset_ttl_timer(self, handle: Any, new_seconds: int) -> Any:
        """Delegate to ``_scp_core.SCP.context_reset_ttl_timer``."""
        return await asyncio.to_thread(self._native.context_reset_ttl_timer, handle, new_seconds)

    async def reconnect(
        self,
        identity_did: str,
        context_ids: list[str],
        last_relay_contacts: dict[str, int] | None = None,
    ) -> Any:
        """Reconnect ``identity_did``'s contexts after an offline period.

        Runs the ADR-029 six-phase reconnection protocol for each context in
        ``context_ids`` flagged ``needs_reconnect`` (§23.11). The driver lives
        at the FFI relay-client layer: it pulls relay-buffered messages via the
        ``TransportManager`` and reaches actor-owned reconnection state (MLS
        epoch, Commit/Welcome processing, checkpoint build/compare, MLS update)
        through the ``Supervisor``. On success each context's
        ``needs_reconnect`` flag is cleared.

        ``last_relay_contacts`` maps ``context_id`` to the last-relay-contact
        Unix-seconds timestamp (used to classify the offline tier). Contexts
        absent from the map default to the most conservative tier.

        Requires an active relay connection (call ``transport_connect`` first).

        Key resolution: this backend (Python / NAPI) takes the
        ``identity_did`` **string** and resolves the local member's signing key
        from the bridge's identity registry. The Swift / Kotlin SDKs instead
        take the opaque ``Identity`` object directly — same protocol, only the
        argument shape differs per the UniFFI object-handle convention.

        Catch-up integrity (§9.9.3, §23.7): equivocation where a peer reports
        the **same** event count with a **different** Merkle root IS detected
        and surfaced (per-context ``equivocations_detected``). However,
        reconnection catch-up does NOT yet verify suffix integrity — the Merkle
        consistency proof confirming that fetched events genuinely extend this
        member's own history is specified separately. An equivocating relay
        that keeps a member perpetually *behind* (never reaching equal count)
        is therefore not yet detected on the catch-up path.

        Delegates to ``_scp_core.SCP.context_reconnect``.
        """
        return await asyncio.to_thread(
            self._native.context_reconnect,
            identity_did,
            context_ids,
            last_relay_contacts,
        )

    async def context_send(
        self,
        handle: Any,
        identity_did: str,
        payload: bytes | str,
        spending_ucan_jwt: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.context_send``.

        Raises a ``ContextError`` with code ``SCP-CTX-2095`` when this is a
        multi-member encrypted context and no peer has announced its routing ID
        yet (§9.10.4): the send fails closed and is rolled back (no charge, no
        event); retry once peers' pseudonym-announcement messages have arrived.
        A lone-member send is a no-op; broadcast contexts are unaffected.
        """

        try:
            return await asyncio.to_thread(
                self._native.context_send, handle, identity_did, payload, spending_ucan_jwt
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def get_economic_policy(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.get_economic_policy``."""
        return await asyncio.to_thread(self._native.get_economic_policy, handle)

    async def restore_all_contexts(self) -> Any:
        """Delegate to ``_scp_core.SCP.restore_all_contexts``."""
        return await asyncio.to_thread(self._native.restore_all_contexts)

    async def restore_context(self, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.restore_context``."""
        return await asyncio.to_thread(self._native.restore_context, context_id)

    async def set_economic_policy(self, handle: Any, policy_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.set_economic_policy``."""
        return await asyncio.to_thread(self._native.set_economic_policy, handle, policy_json)

    # endregion Context

    # region UCAN

    async def ucan_delegate(
        self,
        context_id: str,
        delegator_did: str,
        delegatee_did: str,
        parent_token: str,
        capabilities: list[str],
    ) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_delegate`` (returns :class:`UcanToken`)."""
        from scp_sdk.ucan import UcanToken

        raw = await asyncio.to_thread(
            self._native.ucan_delegate,
            context_id,
            delegator_did,
            delegatee_did,
            parent_token,
            capabilities,
        )
        return UcanToken._from_bridge(raw)

    async def ucan_mint(
        self,
        context_id: str,
        member_did: str,
        capabilities: list[str],
        proofs: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_mint`` (returns :class:`UcanToken`)."""
        from scp_sdk.ucan import UcanToken

        raw = await asyncio.to_thread(
            self._native.ucan_mint, context_id, member_did, capabilities, proofs
        )
        return UcanToken._from_bridge(raw)

    async def ucan_revoke(self, context_id: str, token: str, revoker_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.ucan_revoke``."""
        return await asyncio.to_thread(self._native.ucan_revoke, context_id, token, revoker_did)

    async def ucan_validate(
        self,
        context_id: str,
        token: str,
        capability: str,
        presenting_agent_did: str,
        proof_tokens: list[str] | None = None,
    ) -> None:
        """Delegate to ``_scp_core.SCP.ucan_validate``.

        ``presenting_agent_did`` is REQUIRED (no silent security default): the
        bridge rejects an absent or empty value rather than defaulting the
        presenting agent to the token's own ``aud`` (which would make the
        step-5 audience check the tautology ``aud == aud`` and inflate trust).
        Pass the DID the token must be addressed to.
        """

        try:
            return await asyncio.to_thread(
                self._native.ucan_validate,
                context_id,
                token,
                capability,
                presenting_agent_did,
                proof_tokens,
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def ucan_evaluate(
        self,
        context_id: str,
        token: str,
        presenting_agent_did: str,
        capability: str | None = None,
        proof_tokens: list[str] | None = None,
    ) -> CapabilityValidation:
        """Evaluate a UCAN token and return the structured per-stage result.

        Delegate to ``_scp_core.SCP.ucan_evaluate``, the read-only,
        side-effect-free diagnostic counterpart to :meth:`ucan_validate`
        (spec §7.2.4, ADR-059). It runs the same 11-step ADR-016 pipeline
        but returns a :class:`~scp_sdk.trust.CapabilityValidation` of six
        per-stage booleans instead of throwing at the first failure, and
        probes the nonce read-only (never recording it), so it is safe to
        call repeatedly on the same token. The result is a point-in-time
        diagnostic snapshot, not a promise that a later ``ucan_validate``
        will accept the token.

        NOT AN AUTHORIZATION DECISION: this is a diagnostic, never a gate.
        Only :meth:`ucan_validate` (with its mandatory challenge capability)
        authorizes an action. A no-capability (intrinsic-validity) result skips
        the invoked-capability grant-match, so an all-``True`` result does NOT
        establish the token grants any particular capability — re-run
        :meth:`ucan_validate` with the concrete capability to authorize.

        ``presenting_agent_did`` is REQUIRED (no silent security default): the
        bridge rejects an absent or empty value rather than defaulting the
        presenting agent to the token's own ``aud`` (which would make the
        step-5 audience check the tautology ``aud == aud`` and inflate trust).
        It precedes ``capability`` in the signature because it is mandatory
        while ``capability`` is optional. Pass the DID under assessment.

        ``capability`` is OPTIONAL. Omit it (or pass ``None``) to evaluate the
        token's INTRINSIC validity — signatures, ceiling, nonce, revocation,
        time bounds — with no invoked-capability grant-match challenge. This is
        the mode :func:`scp_sdk.trust.evaluate_trust` uses. Pass a concrete
        capability URI to additionally require the token grants it. (The
        enforcing :meth:`ucan_validate` gate keeps a mandatory capability.)

        Raises ``ValidationError`` only for malformed FFI input
        (e.g. an invalid ``context_id`` / ``token`` / ``capability`` /
        ``did``); capability/signature/expiry outcomes are reported via the
        returned booleans, never as exceptions.
        """
        from scp_sdk.trust import structured_to_capability_validation

        raw = await asyncio.to_thread(
            self._native.ucan_evaluate,
            context_id,
            token,
            capability,
            presenting_agent_did,
            proof_tokens,
        )
        # Shared six-field projection — pins the canonical CapabilityValidation
        # shape in one place (the same helper Layer 1 of ``evaluate_trust`` uses).
        return structured_to_capability_validation(raw)

    # endregion UCAN

    # region Broadcast

    async def broadcast_admission(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_admission``."""
        return await asyncio.to_thread(self._native.broadcast_admission, handle)

    async def broadcast_block_subscriber(
        self, handle: Any, subscriber_did: str, blocker_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_block_subscriber``."""
        return await asyncio.to_thread(
            self._native.broadcast_block_subscriber, handle, subscriber_did, blocker_did
        )

    async def broadcast_handle_key_request(
        self, handle: Any, author_did: str, requester_did: str, wrapping_pubkey: bytes
    ) -> str | None:
        """Delegate to ``_scp_core.SCP.broadcast_handle_key_request``.

        Seals the author's current broadcast key to the requester's 32-byte
        X25519 ``wrapping_pubkey`` (HPKE, spec §5.14.2). Returns the JSON of a
        sealed broadcast key on grant, or ``None`` on deny (§5.14.8 — a denied
        requester receives no key material). The subscriber opens the returned
        JSON with :meth:`broadcast_open_key`.
        """
        return await asyncio.to_thread(
            self._native.broadcast_handle_key_request,
            handle,
            author_did,
            requester_did,
            wrapping_pubkey,
        )

    async def broadcast_open_key(self, sealed_json: str, wrapping_secret: bytes) -> bytes:
        """Delegate to ``_scp_core.SCP.broadcast_open_key``.

        Opens an HPKE-sealed broadcast key (spec §5.14.2) using the
        subscriber's 32-byte X25519 ``wrapping_secret``, returning the raw
        32-byte AES-256 broadcast key. ``sealed_json`` is the JSON returned by
        :meth:`broadcast_handle_key_request` on grant. Pure crypto — invoked as
        a static method on the native ``SCP`` class via the instance handle.
        """
        return await asyncio.to_thread(
            self._native.broadcast_open_key, sealed_json, wrapping_secret
        )

    async def broadcast_is_subscriber(self, handle: Any, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_is_subscriber``."""
        return await asyncio.to_thread(self._native.broadcast_is_subscriber, handle, did)

    async def broadcast_publish(self, handle: Any, author_did: str, payload: bytes) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_publish``."""
        return await asyncio.to_thread(self._native.broadcast_publish, handle, author_did, payload)

    async def broadcast_publish_asset(
        self,
        handle: Any,
        author_did: str,
        path: str,
        content_type: str,
        body: bytes,
        deploy_id: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_publish_asset``."""
        return await asyncio.to_thread(
            self._native.broadcast_publish_asset,
            handle,
            author_did,
            path,
            content_type,
            body,
            deploy_id,
        )

    async def broadcast_publish_assets(
        self,
        handle: Any,
        author_did: str,
        assets: list[tuple[str, str, bytes]],
        deploy_id: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_publish_assets``."""
        return await asyncio.to_thread(
            self._native.broadcast_publish_assets, handle, author_did, assets, deploy_id
        )

    async def broadcast_subscribe(
        self, handle: Any, subscriber_did: str, messages_read_ucan_jwt: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_subscribe``.

        For a GATED broadcast context, ``messages_read_ucan_jwt`` must carry the
        ``messages:read`` UCAN JWT issued to ``subscriber_did`` by the context
        admin/creator (spec §5.14.4). It is unused for an OPEN context.
        """
        return await asyncio.to_thread(
            self._native.broadcast_subscribe, handle, subscriber_did, messages_read_ucan_jwt
        )

    async def broadcast_subscriber_count(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_subscriber_count``."""
        return await asyncio.to_thread(self._native.broadcast_subscriber_count, handle)

    async def broadcast_unblock_subscriber(
        self, handle: Any, subscriber_did: str, unblocker_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_unblock_subscriber``."""
        return await asyncio.to_thread(
            self._native.broadcast_unblock_subscriber, handle, subscriber_did, unblocker_did
        )

    async def broadcast_unsubscribe(
        self, handle: Any, subscriber_did: str, rotate_keys: bool = False
    ) -> Any:
        """Delegate to ``_scp_core.SCP.broadcast_unsubscribe``."""
        return await asyncio.to_thread(
            self._native.broadcast_unsubscribe, handle, subscriber_did, rotate_keys
        )

    # endregion Broadcast

    # region Governance

    async def add_checkpoint_cosignature(
        self, handle: Any, checkpoint_json: str, signer_did: str, signature_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.add_checkpoint_cosignature``."""
        return await asyncio.to_thread(
            self._native.add_checkpoint_cosignature,
            handle,
            checkpoint_json,
            signer_did,
            signature_hex,
        )

    async def apply_pending_ceiling_modification(self, handle: Any, current_timestamp: int) -> Any:
        """Delegate to ``_scp_core.SCP.apply_pending_ceiling_modification``."""
        return await asyncio.to_thread(
            self._native.apply_pending_ceiling_modification, handle, current_timestamp
        )

    async def create_governance_checkpoint(
        self,
        handle: Any,
        checkpoint_seq: int,
        merkle_root_hex: str,
        event_count: int,
        last_event_hash_hex: str,
        state_snapshot_hash_hex: str,
        creator_did: str,
        creator_signature_hex: str,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.create_governance_checkpoint``."""
        return await asyncio.to_thread(
            self._native.create_governance_checkpoint,
            handle,
            checkpoint_seq,
            merkle_root_hex,
            event_count,
            last_event_hash_hex,
            state_snapshot_hash_hex,
            creator_did,
            creator_signature_hex,
        )

    async def evaluate_invitation(
        self,
        params_json: str,
        inviter_did: str,
        identity_did: str,
        policy_json: str | None = None,
        spending_json: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.evaluate_invitation``.

        The ``known_did`` allowlist (the sole auto-accept trigger, §5.12.2)
        travels inside ``policy_json`` -- the policy's ``TrustRequirement``
        ``KnownDid`` variant. There is no separate trusted-DID parameter.
        """
        return await asyncio.to_thread(
            self._native.evaluate_invitation,
            params_json,
            inviter_did,
            identity_did,
            policy_json,
            spending_json,
        )

    async def finalize_close(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.finalize_close``."""
        return await asyncio.to_thread(self._native.finalize_close, handle)

    async def governance_approve(self, handle: Any, identity_did: str, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_approve``."""
        return await asyncio.to_thread(
            self._native.governance_approve, handle, identity_did, proposal_id_hex
        )

    async def governance_execute(self, handle: Any, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_execute``.

        Executes a previously-approved governance proposal *by id*. The runtime
        resolves the authoritative proposal from the context actor's own
        quorum-validated governance engine; the caller supplies no proposal,
        action, status, or identity. The executor and consequence subject are
        resolved from the tracked proposal's proposer.
        """
        return await asyncio.to_thread(self._native.governance_execute, handle, proposal_id_hex)

    async def governance_get_proposal(self, handle: Any, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_get_proposal``."""
        return await asyncio.to_thread(
            self._native.governance_get_proposal, handle, proposal_id_hex
        )

    async def governance_list_proposals(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.governance_list_proposals``."""
        return await asyncio.to_thread(self._native.governance_list_proposals, handle)

    async def governance_propose(self, handle: Any, identity_did: str, action_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_propose``."""

        try:
            return await asyncio.to_thread(
                self._native.governance_propose, handle, identity_did, action_json
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def governance_reject(self, handle: Any, identity_did: str, proposal_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.governance_reject``."""
        return await asyncio.to_thread(
            self._native.governance_reject, handle, identity_did, proposal_id_hex
        )

    async def governance_withdraw(
        self, handle: Any, identity_did: str, proposal_id_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.governance_withdraw``."""
        return await asyncio.to_thread(
            self._native.governance_withdraw, handle, identity_did, proposal_id_hex
        )

    async def migration_state(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.migration_state``."""
        return await asyncio.to_thread(self._native.migration_state, handle)

    async def tombstone_migrated_context(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.tombstone_migrated_context``."""
        return await asyncio.to_thread(self._native.tombstone_migrated_context, handle)

    # endregion Governance

    # region MCP

    async def mcp_client_connect_sse(self, url: str) -> Any:
        """Connect an MCP client via SSE transport (returns :class:`McpClient`)."""
        from scp_sdk.mcp import McpClient, validate_client_connect

        validate_client_connect("sse", url=url)
        raw = await asyncio.to_thread(self._native.py_mcp_client_connect_sse, url)
        return McpClient(raw)

    async def mcp_client_connect_stdio(self, command: list[str]) -> Any:
        """Connect an MCP client via stdio transport (returns :class:`McpClient`).

        Pre-flight allowlist check uses THIS instance's allowlist
        (ADR-048 §1, multi-instance neutrality). To permit a binary not
        in the default allowlist, call
        :meth:`mcp_configure_stdio_allowlist` first; to inspect the
        current per-instance state, use :meth:`mcp_get_stdio_allowlist`.
        """
        from scp_sdk.mcp import McpClient, validate_client_connect

        # Snapshot this instance's per-instance allowlist for defense-in-depth
        # validation before round-tripping into the FFI bridge.
        allowlist_state = self.mcp_get_stdio_allowlist()
        validate_client_connect("stdio", command=command, allowlist_state=allowlist_state)
        raw = await asyncio.to_thread(self._native.py_mcp_client_connect_stdio, command)
        return McpClient(raw)

    def mcp_configure_stdio_allowlist(
        self,
        additional_binaries: list[str] | None = None,
    ) -> None:
        """Add binary names to THIS instance's stdio allowlist.

        Operates on the per-instance allowlist (`CoreFields::mcp_allowlist`)
        — disabling enforcement or extending the allow set on one
        :class:`SCP` does NOT leak into another instance.

        Args:
            additional_binaries: Bare binary names to add (e.g.
                ``["my-custom-server"]``). Path separators, empty strings,
                and NUL bytes are rejected.

        Raises:
            ValidationError: If any entry is invalid.
        """
        if not additional_binaries:
            return
        self._native.mcp_configure_stdio_allowlist(additional_binaries)

    def mcp_disable_stdio_allowlist(
        self,
        *,
        i_trust_all_commands: bool = False,
    ) -> None:
        """Disable THIS instance's stdio allowlist (unrestricted mode).

        After calling this, **any** binary can be spawned as a subprocess
        by THIS instance. Other :class:`SCP` instances are unaffected.

        Args:
            i_trust_all_commands: Must be ``True`` to confirm the security
                bypass. Raises ``McpError`` if ``False``.

        Raises:
            McpError: If *i_trust_all_commands* is not ``True``.
        """
        from scp_sdk.errors import McpError

        if not i_trust_all_commands:
            raise McpError(
                "You must pass i_trust_all_commands=True to disable the "
                "stdio allowlist. This allows arbitrary command execution.",
                code="SCP-MCP-10007",
            )

        logger.warning(
            "MCP stdio allowlist DISABLED on SCP instance — arbitrary "
            "commands will be permitted by THIS instance only. Other "
            "SCP instances are unaffected."
        )

        self._native.mcp_disable_stdio_allowlist()

    def mcp_reset_stdio_allowlist(self) -> None:
        """Reset THIS instance's stdio allowlist to defaults.

        Restores the default binaries, removes any additions, and
        re-enables enforcement (clears unrestricted mode) for THIS
        instance only.
        """
        self._native.mcp_reset_stdio_allowlist()
        logger.info("MCP stdio allowlist reset to defaults on SCP instance")

    def mcp_get_stdio_allowlist(self) -> McpAllowlistState:
        """Return a snapshot of THIS instance's stdio allowlist state.

        Returns:
            A :class:`McpAllowlistState` ``TypedDict`` with keys:

            - ``"allowed"``: sorted list of allowed binary basenames.
            - ``"unrestricted"``: ``True`` if the allowlist is bypassed.
        """
        return self._native.mcp_get_stdio_allowlist()

    async def mcp_client_disconnect(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_disconnect``.

        Accepts an :class:`McpClient` instance (extracting the raw
        bridge handle via ``_raw_handle``) or a raw handle directly.
        """
        from scp_sdk.mcp import McpClient

        raw = handle._raw_handle if isinstance(handle, McpClient) else handle
        return await asyncio.to_thread(self._native.py_mcp_client_disconnect, raw)

    async def mcp_client_info(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_info``.

        Accepts an :class:`McpClient` instance (extracting the raw
        bridge handle via ``_raw_handle``) or a raw handle directly.
        """
        from scp_sdk.mcp import McpClient

        raw = handle._raw_handle if isinstance(handle, McpClient) else handle
        return await asyncio.to_thread(self._native.py_mcp_client_info, raw)

    async def mcp_client_invoke(
        self,
        handle: Any,
        outlet_name: str,
        input: dict[str, Any],
        context_id: str,
        identity_did: str,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_client_invoke``.

        Returns an :class:`~scp_sdk.mcp.McpToolResult` wrapping the raw
        bridge result with SCP provenance metadata.
        """
        from scp_sdk.mcp import McpClient, McpProvenance, McpToolResult

        raw_handle = handle._raw_handle if isinstance(handle, McpClient) else handle
        raw = await asyncio.to_thread(
            self._native.py_mcp_client_invoke,
            raw_handle,
            outlet_name,
            input,
            context_id,
            identity_did,
        )
        provenance = McpProvenance(
            source=raw["provenance"]["source"],
            invoked_by=raw["provenance"]["invoked_by"],
            context=raw["provenance"]["context"],
            timestamp=raw["provenance"]["timestamp"],
        )
        return McpToolResult(
            content=raw.get("content", []),
            is_error=raw.get("is_error", False),
            provenance=provenance,
        )

    async def mcp_client_list_tools(self, handle: Any) -> list[Any]:
        """Delegate to ``_scp_core.SCP.py_mcp_client_list_tools``.

        Returns a list of :class:`~scp_sdk.mcp.McpToolDefinition`.
        """
        from scp_sdk.mcp import McpClient, McpToolDefinition

        raw_handle = handle._raw_handle if isinstance(handle, McpClient) else handle
        raw_tools = await asyncio.to_thread(self._native.py_mcp_client_list_tools, raw_handle)
        return [
            McpToolDefinition(
                name=t["name"],
                description=t.get("description"),
                input_schema=t.get("inputSchema", {}),
            )
            for t in raw_tools
        ]

    async def mcp_load_contexts(self, identity_did: str, _relay_url: str) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_load_contexts``."""
        return await asyncio.to_thread(self._native.py_mcp_load_contexts, identity_did, _relay_url)

    async def mcp_register_outlet_handler(
        self, context_id: str, outlet_name: str, handler: Any
    ) -> Any:
        """Delegate to ``_scp_core.SCP.mcp_register_outlet_handler``."""
        return await asyncio.to_thread(
            self._native.mcp_register_outlet_handler, context_id, outlet_name, handler
        )

    async def mcp_serve(
        self,
        identity_did: str,
        context_ids: list[str],
        transport: str,
        ucan_token: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_serve`` (returns :class:`McpServer`)."""
        from scp_sdk.mcp import McpServer

        raw = await asyncio.to_thread(
            self._native.py_mcp_serve, identity_did, context_ids, transport, ucan_token
        )
        return McpServer(raw)

    async def mcp_server_info(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_server_info``.

        Accepts an :class:`McpServer` instance or a raw bridge handle.
        """
        from scp_sdk.mcp import McpServer

        raw = handle._raw_handle if isinstance(handle, McpServer) else handle
        return await asyncio.to_thread(self._native.py_mcp_server_info, raw)

    async def mcp_server_stop(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_server_stop``.

        Accepts an :class:`McpServer` instance or a raw bridge handle.
        """
        from scp_sdk.mcp import McpServer

        raw = handle._raw_handle if isinstance(handle, McpServer) else handle
        return await asyncio.to_thread(self._native.py_mcp_server_stop, raw)

    async def mcp_server_wait(self, handle: Any) -> Any:
        """Delegate to ``_scp_core.SCP.py_mcp_server_wait``.

        Accepts an :class:`McpServer` instance or a raw bridge handle.
        """
        from scp_sdk.mcp import McpServer

        raw = handle._raw_handle if isinstance(handle, McpServer) else handle
        return await asyncio.to_thread(self._native.py_mcp_server_wait, raw)

    async def registry_cleanup(self) -> Any:
        """Delegate to ``_scp_core.SCP.py_registry_cleanup``."""
        return await asyncio.to_thread(self._native.py_registry_cleanup)

    async def registry_stats(self) -> Any:
        """Delegate to ``_scp_core.SCP.py_registry_stats``."""
        return await asyncio.to_thread(self._native.py_registry_stats)

    # endregion MCP

    # region Transport

    async def configure_relay_transport(self, relay_url: str, local_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.configure_relay_transport``."""
        return await asyncio.to_thread(self._native.configure_relay_transport, relay_url, local_did)

    async def configure_local_transport(self, local_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.configure_local_transport``."""
        return await asyncio.to_thread(self._native.configure_local_transport, local_did)

    async def transport_adapter_count(self) -> Any:
        """Delegate to ``_scp_core.SCP.transport_adapter_count``."""
        return await asyncio.to_thread(self._native.transport_adapter_count)

    async def transport_add_relay(self, relay_url: str, source: str = "explicit") -> Any:
        """Delegate to ``_scp_core.SCP.transport_add_relay``."""
        return await asyncio.to_thread(self._native.transport_add_relay, relay_url, source)

    async def transport_assign_relay_set(self, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.transport_assign_relay_set``."""
        return await asyncio.to_thread(self._native.transport_assign_relay_set, context_id)

    async def transport_connect(self, relay_url: str, source: str = "explicit") -> Any:
        """Delegate to ``_scp_core.SCP.transport_connect``."""
        return await asyncio.to_thread(self._native.transport_connect, relay_url, source)

    async def transport_disconnect(self) -> Any:
        """Delegate to ``_scp_core.SCP.transport_disconnect``."""
        return await asyncio.to_thread(self._native.transport_disconnect)

    async def transport_reliability(self, adapter_index: int) -> Any:
        """Delegate to ``_scp_core.SCP.transport_reliability``."""
        return await asyncio.to_thread(self._native.transport_reliability, adapter_index)

    async def transport_status(self) -> Any:
        """Delegate to ``_scp_core.SCP.transport_status`` (returns :class:`TransportStatus`)."""
        from scp_sdk.transport import TransportStatus

        raw = await asyncio.to_thread(self._native.transport_status)
        return TransportStatus(
            connected=raw.connected,
            relay_url=raw.relay_url,
            latency_ms=raw.latency_ms,
        )

    # endregion Transport

    # region Event Log

    async def event_log_checkpoint(self, context_id: str, identity_did: str, epoch: int) -> Any:
        """Delegate to ``_scp_core.SCP.event_log_checkpoint``.

        Returns a :class:`~scp_sdk.event_log.SignedCheckpoint` with an
        Ed25519 signature over the canonical checkpoint fields.
        """
        from scp_sdk.event_log import SignedCheckpoint

        raw = await asyncio.to_thread(
            self._native.event_log_checkpoint, context_id, identity_did, epoch
        )
        return SignedCheckpoint(
            context_id=raw.context_id,
            sender_did=raw.sender_did,
            event_count=raw.event_count,
            merkle_root=raw.merkle_root,
            epoch=raw.epoch,
            timestamp=raw.timestamp,
            signature=raw.signature,
        )

    async def event_log_checkpoint_by_did(self, context_id: str, did: str, epoch: int) -> Any:
        """Delegate to ``_scp_core.SCP.event_log_checkpoint_by_did``.

        Generates a signed consistency checkpoint scoped to a member ``did``.
        The DID is looked up in this instance's identity registry for signing
        key material and recorded as the checkpoint's ``sender_did``. Returns a
        :class:`~scp_sdk.event_log.SignedCheckpoint` with an Ed25519 signature
        over the canonical checkpoint fields.
        """
        from scp_sdk.event_log import SignedCheckpoint

        raw = await asyncio.to_thread(
            self._native.event_log_checkpoint_by_did, context_id, did, epoch
        )
        return SignedCheckpoint(
            context_id=raw.context_id,
            sender_did=raw.sender_did,
            event_count=raw.event_count,
            merkle_root=raw.merkle_root,
            epoch=raw.epoch,
            timestamp=raw.timestamp,
            signature=raw.signature,
        )

    async def event_log_query(
        self, context_id: str, filter: dict[str, Any] | None = None
    ) -> list[Any]:
        """Delegate to ``_scp_core.SCP.event_log_query``.

        Returns a list of :class:`~scp_sdk.event_log.Event` dataclasses.
        """
        from scp_sdk.event_log import Event

        try:
            raw_events = await asyncio.to_thread(self._native.event_log_query, context_id, filter)
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return [
            Event(
                event_type=e.event_type,
                actor_did=e.actor_did,
                timestamp=e.timestamp,
                payload=e.payload,
                sequence=e.sequence,
            )
            for e in raw_events
        ]

    async def event_log_verify(self, context_id: str, claim: dict[str, Any]) -> Any:
        """Delegate to ``_scp_core.SCP.event_log_verify``.

        Returns a :class:`~scp_sdk.event_log.Proof` dataclass.
        """
        from scp_sdk.event_log import Proof

        raw = await asyncio.to_thread(self._native.event_log_verify, context_id, claim)
        return Proof(
            verified=raw.verified,
            proof_type=raw.proof_type,
            details=raw.details,
        )

    # endregion Event Log

    # region Economy

    async def economy_antispam_escalated_cost(
        self,
        context_id: str,
        sender_did: str,
        now: int,
        base_cost: int,
        thresholds_json: str,
        floor: int | None = None,
        cap: int | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.economy_antispam_escalated_cost``."""
        return await asyncio.to_thread(
            self._native.economy_antispam_escalated_cost,
            context_id,
            sender_did,
            now,
            base_cost,
            thresholds_json,
            floor,
            cap,
        )

    async def economy_antispam_record(
        self, context_id: str, sender_did: str, timestamp: int
    ) -> Any:
        """Delegate to ``_scp_core.SCP.economy_antispam_record``."""
        return await asyncio.to_thread(
            self._native.economy_antispam_record, context_id, sender_did, timestamp
        )

    async def economy_antispam_velocity(self, context_id: str, sender_did: str, now: int) -> Any:
        """Delegate to ``_scp_core.SCP.economy_antispam_velocity``."""
        return await asyncio.to_thread(
            self._native.economy_antispam_velocity, context_id, sender_did, now
        )

    async def economy_budget_grant(self, context_id: str, did: str, amount: int) -> Any:
        """Delegate to ``_scp_core.SCP.economy_budget_grant``."""
        return await asyncio.to_thread(self._native.economy_budget_grant, context_id, did, amount)

    async def economy_budget_record_spend(self, context_id: str, did: str, amount: int) -> Any:
        """Delegate to ``_scp_core.SCP.economy_budget_record_spend``."""
        return await asyncio.to_thread(
            self._native.economy_budget_record_spend, context_id, did, amount
        )

    async def economy_budget_remaining(self, context_id: str, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.economy_budget_remaining``."""
        return await asyncio.to_thread(self._native.economy_budget_remaining, context_id, did)

    async def economy_verify_payment_receipts(
        self, receipts: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Delegate to ``_scp_core.SCP.economy_verify_payment_receipts``.

        Verifies a batch of payment receipts against this instance's economy
        state. The result reports cryptographic validity via the top-level
        ``all_valid`` flag and a per-receipt ``valid`` flag. Note that an
        invalid-but-reachable receipt still carries ``ok == True`` — callers
        scanning for failures MUST inspect ``valid``/``all_valid``, not ``ok``.

        Args:
            receipts: List of payment receipt dicts to verify. Maximum
                10,000 receipts per call.

        Returns:
            A dict with keys ``all_valid`` (bool) and ``results`` (list of
            per-receipt dicts with ``receipt_id``, ``ok``, ``valid``, and
            ``result`` keys).

        Raises:
            ScpError: If the receipts are invalid or the supervisor is
                not initialized.
        """
        import json

        receipts_json = json.dumps(receipts)
        try:
            raw = await asyncio.to_thread(
                self._native.economy_verify_payment_receipts, receipts_json
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc
        return json.loads(raw)

    # endregion Economy

    # region Trust

    async def aggregate_trust_input(
        self,
        context_id: str,
        subject_did: str,
        events: list[EventLogEntry] | list[dict[str, Any]],
        merkle_root: list[int],
        consequence_rules: list[dict[str, Any]] | None = None,
        threshold_requirements: dict[str, ThresholdRequirement] | dict[str, Any] | None = None,
        attestor_sets: dict[str, list[AttestorInfo]] | dict[str, Any] | None = None,
        cached_attestations: list[CachedAttestation] | list[dict[str, Any]] | None = None,
        challenge_results: list[ChallengeVerification] | list[dict[str, Any]] | None = None,
    ) -> Any:
        """Aggregate all trust engine layers into a single ``TrustInput`` (§7.3).

        Typed counterpart to ``_scp_core.SCP.aggregate_trust_input``
        (ADR-058): takes the typed trust-aggregation inputs (the same shapes
        :func:`scp_sdk.trust.aggregate_trust_input` accepts) and serializes
        them to the serde wire JSON internally via the shared
        ``scp_sdk.trust._encode_aggregate_trust_wire`` before crossing FFI.

        Raises:
            ValueError: If ``merkle_root`` is not exactly 32 elements or a
                ``threshold_requirements`` / ``attestor_sets`` key is not a
                valid ``scp_sdk.trust.ATTESTATION_TYPES`` name.
        """
        from scp_sdk.trust import _encode_aggregate_trust_wire

        wire = _encode_aggregate_trust_wire(
            events,
            merkle_root,
            consequence_rules,
            threshold_requirements,
            attestor_sets,
            cached_attestations,
            challenge_results,
        )
        return await asyncio.to_thread(
            self._native.aggregate_trust_input,
            context_id,
            subject_did,
            *wire,
        )

    async def trust_query_score(self, did: str, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.trust_query_score``."""
        return await asyncio.to_thread(self._native.trust_query_score, did, context_id)

    async def evaluate_trust(
        self,
        context_id: str,
        subject_did: str,
        capability_tokens: list[str] | None = None,
    ) -> TrustEvaluation:
        """Evaluate the trustworthiness of a participant in a context.

        Delegates to :func:`scp_sdk.trust.evaluate_trust` (the canonical
        four-layer trust evaluation), so Python matches the TypeScript, Swift,
        and Kotlin SDKs, which all expose ``scp.evaluateTrust(...)``. The
        module-level function remains the implementation.

        SECURITY: the result is data for the caller's judgment, NEVER an
        authorization verdict. The behavioral record's ``attestation_count``
        (and any challenge results) are authentic-but-self-mintable and MUST
        NOT be a sole trust or admission factor (use the threshold/independence
        path, §7.3.5).
        """
        from scp_sdk.trust import evaluate_trust as _evaluate_trust

        return await _evaluate_trust(self, context_id, subject_did, capability_tokens)

    async def participation_record(
        self,
        context_id: str,
        subject_did: str,
        cached_attestations: list[CachedAttestation] | list[dict[str, Any]] | None = None,
    ) -> BehavioralRecord:
        """Compute the participation record (§7.3.2) for a subject in a context.

        Delegates to :func:`scp_sdk.trust.participation_record`, which calls the
        typed PyO3 ``participation_record`` op and returns a
        :class:`~scp_sdk.trust.BehavioralRecord` of the twelve flattened facts.
        The shared Rust core gathers the full event log and computes the record
        ONCE; the SDK RECEIVES it rather than recomputing Layer 2 client-side.
        ``attestation_count`` is a credential-layer fact (§7.4), verifier-
        relative; pass ``cached_attestations`` to populate it (default: none).
        """
        from scp_sdk.trust import participation_record as _participation_record

        return await asyncio.to_thread(
            _participation_record, self, context_id, subject_did, cached_attestations
        )

    # endregion Trust

    # region SCPID

    async def scpid_challenge(self, audience: str, ttl_seconds: int = 300) -> Any:
        """Delegate to ``_scp_core.scpid_challenge``.

        ADR-048 §1: pure helper exposed as a module-level free function.

        Returns an :class:`~scp_sdk.auth.ScpIdChallenge` parsed from the
        bridge's JSON payload.
        """
        from scp_sdk.auth import ScpIdChallenge

        mod = _native_mod()
        raw = await asyncio.to_thread(mod.scpid_challenge, audience, ttl_seconds)
        return ScpIdChallenge.from_json(raw) if isinstance(raw, str) else raw

    async def scpid_sign(self, did: str, signing_key_id: str, challenge_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.scpid_sign``.

        Returns an :class:`~scp_sdk.auth.ScpIdResponse` parsed from the
        bridge's JSON payload.
        """
        from scp_sdk.auth import ScpIdResponse

        raw = await asyncio.to_thread(self._native.scpid_sign, did, signing_key_id, challenge_json)
        return ScpIdResponse.from_json(raw) if isinstance(raw, str) else raw

    async def scpid_verify(self, response_json: str, challenge_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.scpid_verify``.

        Returns an :class:`~scp_sdk.auth.ScpIdAuthentication` when the
        bridge reports a successful verification. If the bridge returns
        a raw result dict, it is converted into the typed dataclass.
        """
        from scp_sdk.auth import ScpIdAuthentication

        raw = await asyncio.to_thread(self._native.scpid_verify, response_json, challenge_json)
        if isinstance(raw, str):
            import json as _json

            data = _json.loads(raw)
            return ScpIdAuthentication(
                did=data["did"],
                signing_key_id=data["signing_key_id"],
                signed_at=data["signed_at"],
            )
        if isinstance(raw, dict):
            return ScpIdAuthentication(
                did=raw["did"],
                signing_key_id=raw["signing_key_id"],
                signed_at=raw["signed_at"],
            )
        return raw

    # endregion SCPID

    # region Provenance

    async def evaluate_provenance_quality(
        self,
        source_context: str | None = None,
        source_type: str = "persistent",
        context_state: str = "unknown",
        counterparties: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.evaluate_provenance_quality``.

        ADR-048 §1: pure helper exposed as a module-level free function.
        """
        mod = _native_mod()
        return await asyncio.to_thread(
            mod.evaluate_provenance_quality,
            source_context,
            source_type,
            context_state,
            counterparties,
        )

    async def provenance_attach(
        self,
        source_context_id: str,
        source_type: str,
        memory_scope: str,
        members: list[str],
        target_context_id: str,
        actor_did: str,
        existing_chain_depth: int | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.provenance_attach``."""
        return await asyncio.to_thread(
            self._native.provenance_attach,
            source_context_id,
            source_type,
            memory_scope,
            members,
            target_context_id,
            actor_did,
            existing_chain_depth,
        )

    async def provenance_check_chain_depth(
        self, chain_depth: int, max_depth: int | None = None
    ) -> Any:
        """Delegate to ``_scp_core.provenance_check_chain_depth``.

        ADR-048 §1: pure helper exposed as a module-level free function.
        """
        mod = _native_mod()
        return await asyncio.to_thread(mod.provenance_check_chain_depth, chain_depth, max_depth)

    async def provenance_pseudonymize_counterparties(
        self, provenance_json: str, pseudonym_key_hex: str
    ) -> Any:
        """Delegate to ``_scp_core.provenance_pseudonymize_counterparties``.

        ADR-048 §1: pure helper exposed as a module-level free function.
        """
        mod = _native_mod()
        return await asyncio.to_thread(
            mod.provenance_pseudonymize_counterparties, provenance_json, pseudonym_key_hex
        )

    async def provenance_redact_counterparties(self, provenance_json: str) -> Any:
        """Delegate to ``_scp_core.provenance_redact_counterparties``.

        ADR-048 §1: pure helper exposed as a module-level free function.
        """
        mod = _native_mod()
        return await asyncio.to_thread(mod.provenance_redact_counterparties, provenance_json)

    async def provenance_update_source_type(self, provenance_json: str, new_state: str) -> Any:
        """Delegate to ``_scp_core.provenance_update_source_type``.

        ADR-048 §1: pure helper exposed as a module-level free function.
        """
        mod = _native_mod()
        return await asyncio.to_thread(
            mod.provenance_update_source_type, provenance_json, new_state
        )

    # endregion Provenance

    # region Outlets

    async def outlet_interface_accept(self, context_id: str, interface_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_interface_accept``."""
        return await asyncio.to_thread(
            self._native.outlet_interface_accept, context_id, interface_json
        )

    async def outlet_interface_expose(
        self,
        context_id: str,
        outlet_id: str,
        target_context_id: str,
        rate_limit_json: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_interface_expose``."""
        return await asyncio.to_thread(
            self._native.outlet_interface_expose,
            context_id,
            outlet_id,
            target_context_id,
            rate_limit_json,
        )

    async def outlet_interface_revoke(self, context_id: str, interface_id_hex: str) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_interface_revoke``."""
        return await asyncio.to_thread(
            self._native.outlet_interface_revoke, context_id, interface_id_hex
        )

    async def outlet_invoke(
        self,
        context_id: str,
        outlet_id: str,
        input: dict[str, Any],
        identity_did: str,
        ucan_token: str,
        proof_tokens: list[str] | None = None,
        spending_ucan: str | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_invoke``."""

        try:
            return await asyncio.to_thread(
                self._native.outlet_invoke,
                context_id,
                outlet_id,
                input,
                identity_did,
                ucan_token,
                proof_tokens,
                spending_ucan,
            )
        except Exception as exc:
            raise _coded_bridge_error(exc) from exc

    async def outlet_invoke_cross_context(
        self,
        source_context_id: str,
        target_context_id: str,
        outlet_id: str,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str,
        chain_depth: int = 0,
        proof_tokens: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_invoke_cross_context``.

        Validates ``chain_depth`` is an integer in the closed range
        ``0..255`` (u8 on the bridge side). Rejects ``bool`` (Python's
        ``bool`` passes ``isinstance(..., int)``) and floats, matching the
        pre-Phase-4 validation the free function performed before
        crossing FFI.
        """
        from scp_sdk.errors import ValidationError

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
        return await asyncio.to_thread(
            self._native.outlet_invoke_cross_context,
            source_context_id,
            target_context_id,
            outlet_id,
            input,
            invoker_did,
            ucan_token,
            chain_depth,
            proof_tokens,
        )

    async def outlet_invoke_cross_context_saga(
        self,
        caller_context_id: str,
        target_context_id: str,
        caller_did: str,
        outlet_registration_id: str,
        input: dict[str, Any],
        asserted_nonce_hex: str,
        timestamp_ms: int,
        chain_depth: int,
        ucan_proof_id: str | None = None,
    ) -> SagaResult:
        """Run the §6.2.4 atomic cross-context outlet-invocation saga.

        Delegates to ``_scp_core.SCP.outlet_invoke_cross_context_saga``. The
        saga either commits — returning a :class:`~scp_sdk.outlets.SagaResult`
        carrying the supervisor-minted ``saga_id`` plus the target's signed
        receipt and captured output bytes — or reaches a typed terminal,
        which is re-raised as one of the SDK saga exceptions:

        - :class:`~scp_sdk.errors.SagaAbortedError` — a Prepare-phase abort:
          a PERMANENT rejection OR a RETRYABLE transient (rate limit /
          participant actor unavailable), distinguished by the
          ``SCP-SAGA-*`` code; carries ``retry_after_ms`` (``None``, never
          ``0``, when no precise back-off exists).
        - :class:`~scp_sdk.errors.SagaNeedsRepairError` — Commit retries
          exhausted; carries the durable ``saga_id`` repair handle.
        - :class:`~scp_sdk.errors.SagaBusyError` — the participant context
          set overlapped an in-flight saga; carries ``contended_context``.

        Validates ``chain_depth`` is an integer in the closed range
        ``0..255`` (u8 on the bridge side) and ``timestamp_ms`` is a
        non-negative integer. Both reject ``bool`` (Python's ``bool``
        passes ``isinstance(..., int)``) and floats, matching the bridge's
        ``u8`` / ``u64`` boundaries. See spec §6.2.4 and ADR-049 §3a.
        """
        from scp_sdk.errors import ValidationError, _saga_terminal_from_bridge
        from scp_sdk.outlets import SagaResult

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
        if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int) or timestamp_ms < 0:
            raise ValidationError(
                f"timestamp_ms must be a non-negative integer, got {timestamp_ms!r}",
                code="SCP-VALID-7002",
            )

        try:
            native_result = await asyncio.to_thread(
                self._native.outlet_invoke_cross_context_saga,
                caller_context_id,
                target_context_id,
                caller_did,
                outlet_registration_id,
                input,
                asserted_nonce_hex,
                timestamp_ms,
                chain_depth,
                ucan_proof_id,
            )
        except Exception as exc:
            translated = _saga_terminal_from_bridge(exc)
            if translated is None:
                raise
            raise translated from exc

        return SagaResult(
            saga_id=native_result.saga_id,
            receipt=native_result.receipt,
            output=native_result.output,
        )

    def outlet_invoke_cross_context_streaming_saga(
        self,
        caller_context_id: str,
        target_context_id: str,
        caller_did: str,
        outlet_registration_id: str,
        input: dict[str, Any],
        asserted_nonce_hex: str,
        timestamp_ms: int,
        chain_depth: int,
        ucan_token: str,
        proof_tokens: list[str] | None = None,
        ucan_proof_id: str | None = None,
        timeout_ms: int | None = None,
        estimated_chunk_count: int | None = None,
    ) -> StreamingSagaHandle:
        """Open the §5.4.5 / §6.2.4 cross-context STREAMING outlet-invocation saga.

        The STREAMING sibling of :meth:`outlet_invoke_cross_context_saga`. Where
        the unary saga BLOCKS the FFI worker until ``Committed`` (≤~95s) and
        returns the result inline, the streaming saga returns its chunk receiver
        PROMPTLY at the Commit-transition and reaches ``Committed``
        ASYNCHRONOUSLY at seal-close (the ADR-049 §3a streaming wait-model
        amendment) — an LLM stream can exceed the unary bound, so the credit
        ceiling bounds chunk COUNT, not wall-clock.

        Returns a :class:`~scp_sdk.outlets.StreamingSagaHandle` — an
        async-iterable + awaitable handle whose FIRST pull opens the saga
        (``outlet_streaming_saga_open`` mints the durable ``saga_id`` at the
        Commit-transition) and whose iteration drains chunks via
        ``outlet_streaming_saga_poll_next``. This method performs NO I/O and
        does NOT block — the saga opens lazily on first ``await`` / iteration,
        matching the same-context :meth:`~scp_sdk.outlets.Outlets.invoke`.

        There is NO live control plane (grant_credit / cancel) for the
        cross-context saga stream — per §6.2.5 / SCP-OUT-046 the credit window
        is fixed at open via ``estimated_chunk_count`` (cancel_ack_ceiling =
        u64::MAX). An open rejection — the §6.2.4 caller-principal binding
        (a ``caller_did`` this instance does not host / not a member of
        ``caller_context_id``), a Prepare/Commit saga terminal, or an
        input/UCAN rejection — surfaces on the first ``await`` / iteration as
        the matching SDK type (:class:`~scp_sdk.errors.SagaAbortedError` /
        :class:`~scp_sdk.errors.SagaBusyError` /
        :class:`~scp_sdk.errors.SagaNeedsRepairError` /
        :class:`~scp_sdk.errors.ValidationError` /
        :class:`~scp_sdk.errors.UcanPermissionError`), and the receiver is
        never handed out.

        The parameters mirror :meth:`outlet_invoke_cross_context_saga`
        (``caller_context_id`` / ``target_context_id`` / ``caller_did`` /
        ``outlet_registration_id`` / ``input`` / the ``asserted_nonce_hex`` /
        ``timestamp_ms`` / ``chain_depth`` freshness triple / ``ucan_proof_id``)
        plus the streaming-open extras: the required invocation ``ucan_token``,
        optional ``proof_tokens`` delegation chain, per-stream ``timeout_ms``,
        and the invoker-declared ``estimated_chunk_count`` credit ceiling.

        Validates ``chain_depth`` is an integer in the closed range ``0..255``
        (u8 on the bridge side) and ``timestamp_ms`` is a non-negative integer;
        both reject ``bool`` and floats. See spec §6.2.4, §5.4.5, and
        ADR-049 §3a.
        """
        from scp_sdk.errors import ValidationError
        from scp_sdk.outlets import StreamingSagaHandle, _StreamingSagaOpenParams

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
        if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, int) or timestamp_ms < 0:
            raise ValidationError(
                f"timestamp_ms must be a non-negative integer, got {timestamp_ms!r}",
                code="SCP-VALID-7002",
            )

        params = _StreamingSagaOpenParams(
            caller_context_id=caller_context_id,
            target_context_id=target_context_id,
            caller_did=caller_did,
            outlet_registration_id=outlet_registration_id,
            input=input,
            asserted_nonce_hex=asserted_nonce_hex,
            timestamp_ms=timestamp_ms,
            chain_depth=chain_depth,
            ucan_token=ucan_token,
            proof_tokens=proof_tokens,
            ucan_proof_id=ucan_proof_id,
            timeout_ms=timeout_ms,
            estimated_chunk_count=estimated_chunk_count,
        )
        return StreamingSagaHandle(self._native, params)

    async def recover_streaming_saga_truncated_close(self, saga_id: str, caller_did: str) -> None:
        """Drive the key-bearing in-session reconnect/repair truncated-close for
        a cross-context streaming saga (SCP-OUT-046 #136 AC7, SCP-OUT-047).

        This is IN-SESSION reconnect/repair of a seal that stalled or went
        ``NeedsRepair`` while THIS bridge process is still alive (e.g. a client
        reconnects to the same live node). The saga registry is per-instance and
        in-memory, so this does NOT survive a process/node restart — cross-restart
        recovery replays the durable saga journal via a separate operator path,
        not this surface.

        On FFI reconnect this authenticates the caller, surfaces the target
        context's Active Signing Key (resolved per-call from custody, never
        envelope-asserted), and calls
        ``Supervisor::recover_streaming_saga_truncated_close`` to seal a
        witness-absent durable prefix and resolve the saga ``Committed`` —
        WITHOUT re-opening the stream or re-invoking the outlet executor. It
        returns ``None`` on a successful ``Committed`` resolution.

        ``caller_did`` MUST be an identity hosted by this bridge instance (the
        §6.2.4 channel-authenticated principal) AND the invoker pinned at open —
        recovery is money-moving (it bills the invoker / credits the operator
        over B's durable prefix), so a hosted-but-non-invoker caller is rejected
        with ``SCP-PERM-3001`` (the SAME invoker gate the same-context
        grant/cancel/terminate siblings enforce) BEFORE the signing key is
        resolved.

        Raises :class:`~scp_sdk.errors.ContextError` if ``caller_did`` is not
        hosted by this instance or ``saga_id`` is unknown, or — when
        ``caller_did`` is hosted but is not the pinned invoker — a
        :class:`~scp_sdk.errors.ContextError` whose structured ``.code`` is
        ``SCP-PERM-3001`` (a caller can branch on ``.code`` for this
        money-moving gate, not only substring-match the message);
        :class:`~scp_sdk.errors.SagaNeedsRepairError` if the seal cannot
        complete (the saga stays unresolved for a later retry).
        """
        from scp_sdk.errors import _saga_terminal_from_bridge
        from scp_sdk.outlets import _translate_bridge_error

        try:
            await asyncio.to_thread(
                self._native.outlet_streaming_saga_recover_truncated_close,
                saga_id,
                caller_did,
            )
        except Exception as exc:
            translated = _saga_terminal_from_bridge(exc)
            raise (translated if translated is not None else _translate_bridge_error(exc)) from exc

    async def outlet_register(
        self, context_id: str, registration: OutletDefinition | dict[str, Any]
    ) -> Any:
        """Register an outlet in a context via ``_scp_core.SCP.outlet_register``.

        Accepts a typed :class:`~scp_sdk.outlets.OutletDefinition` (converted to
        the bridge registration dict via
        :meth:`~scp_sdk.outlets.OutletDefinition.to_dict`, which emits the
        required §5.4.2 ``kind`` wire string) or a raw registration ``dict``
        (passed through unchanged, e.g. for the bridge-parity harness).
        """
        from scp_sdk.outlets import OutletDefinition

        payload = (
            registration.to_dict() if isinstance(registration, OutletDefinition) else registration
        )
        return await asyncio.to_thread(self._native.outlet_register, context_id, payload)

    async def outlet_session_close(self, context_id: str, session_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_session_close``."""
        return await asyncio.to_thread(self._native.outlet_session_close, context_id, session_id)

    async def outlet_session_create(
        self,
        context_id: str,
        outlet_id: str,
        source_context_id: str,
        ttl_seconds: int | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_session_create``.

        Validates ``ttl_seconds`` is a non-negative integer or ``None``.
        Rejects ``bool`` (which passes ``isinstance(..., int)``) and
        floats, matching the pre-Phase-4 validation the free function
        performed before crossing FFI.
        """
        from scp_sdk.errors import ValidationError

        if ttl_seconds is not None and (
            isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 0
        ):
            raise ValidationError(
                f"ttl_seconds must be a non-negative integer or None, got {ttl_seconds!r}",
                code="SCP-VALID-7002",
            )
        return await asyncio.to_thread(
            self._native.outlet_session_create,
            context_id,
            outlet_id,
            source_context_id,
            ttl_seconds,
        )

    async def outlet_session_invoke(
        self,
        context_id: str,
        session_id: str,
        input: dict[str, Any],
        invoker_did: str,
        ucan_token: str,
        proof_tokens: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_session_invoke``."""
        return await asyncio.to_thread(
            self._native.outlet_session_invoke,
            context_id,
            session_id,
            input,
            invoker_did,
            ucan_token,
            proof_tokens,
        )

    async def outlet_verify(self, context_id: str, outlet_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.outlet_verify``."""
        return await asyncio.to_thread(self._native.outlet_verify, context_id, outlet_id)

    # endregion Outlets

    # region Fullstack

    async def fullstack_add_member(self, node: Any, context_id: str, member_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_add_member``."""
        return await asyncio.to_thread(
            self._native.fullstack_add_member, node, context_id, member_did
        )

    async def fullstack_create_context(self, node: Any, context_id: str, ceiling_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_create_context``."""
        return await asyncio.to_thread(
            self._native.fullstack_create_context, node, context_id, ceiling_json
        )

    async def fullstack_create_node(self, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_create_node``."""
        return await asyncio.to_thread(self._native.fullstack_create_node, did)

    async def fullstack_decrypt_message(
        self, node: Any, context_id: str, ciphertext: Any, sender_did: str
    ) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_decrypt_message``."""
        return await asyncio.to_thread(
            self._native.fullstack_decrypt_message, node, context_id, ciphertext, sender_did
        )

    async def fullstack_join_from_welcome(self, node: Any, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_join_from_welcome``."""
        return await asyncio.to_thread(self._native.fullstack_join_from_welcome, node, context_id)

    async def fullstack_remove_member(self, node: Any, context_id: str, member_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_remove_member``."""
        return await asyncio.to_thread(
            self._native.fullstack_remove_member, node, context_id, member_did
        )

    async def fullstack_reset_network(self) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_reset_network``."""
        return await asyncio.to_thread(self._native.fullstack_reset_network)

    async def fullstack_send_message(self, node: Any, context_id: str, payload: Any) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_send_message``."""
        return await asyncio.to_thread(
            self._native.fullstack_send_message, node, context_id, payload
        )

    async def fullstack_sync_sender_keys(self, node_a: Any, node_b: Any, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.fullstack_sync_sender_keys``."""
        return await asyncio.to_thread(
            self._native.fullstack_sync_sender_keys, node_a, node_b, context_id
        )

    # endregion Fullstack

    # region Discovery

    async def address_resolve(
        self, owner_did: str, address: str, known_contexts_json: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.address_resolve``."""
        return await asyncio.to_thread(
            self._native.address_resolve, owner_did, address, known_contexts_json
        )

    async def handle_deregister(self, discovery_context_id: str, handle: str, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.handle_deregister``."""
        return await asyncio.to_thread(
            self._native.handle_deregister, discovery_context_id, handle, did
        )

    async def handle_lookup(
        self, discovery_context_id: str, handle: str, type_filter: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.handle_lookup``."""
        return await asyncio.to_thread(
            self._native.handle_lookup, discovery_context_id, handle, type_filter
        )

    async def handle_register(
        self,
        discovery_context_id: str,
        handle: str,
        target_json: str,
        registrant_did: str,
        description: str | None = None,
        tags: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.handle_register``."""
        return await asyncio.to_thread(
            self._native.handle_register,
            discovery_context_id,
            handle,
            target_json,
            registrant_did,
            description,
            tags,
        )

    async def petname_apply_event(self, owner_did: str, event_json: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_apply_event``."""
        return await asyncio.to_thread(self._native.petname_apply_event, owner_did, event_json)

    async def petname_context_count(self, owner_did: str) -> int:
        """Delegate to ``_scp_core.SCP.petname_context_count``."""
        return await asyncio.to_thread(self._native.petname_context_count, owner_did)

    async def petname_did_count(self, owner_did: str) -> int:
        """Delegate to ``_scp_core.SCP.petname_did_count``."""
        return await asyncio.to_thread(self._native.petname_did_count, owner_did)

    async def petname_get_for_context(self, owner_did: str, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_get_for_context``."""
        return await asyncio.to_thread(self._native.petname_get_for_context, owner_did, context_id)

    async def petname_get_for_did(self, owner_did: str, target_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_get_for_did``."""
        return await asyncio.to_thread(self._native.petname_get_for_did, owner_did, target_did)

    async def petname_remove(self, owner_did: str, target_did: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_remove``."""
        return await asyncio.to_thread(self._native.petname_remove, owner_did, target_did)

    async def petname_remove_context(self, owner_did: str, context_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_remove_context``."""
        return await asyncio.to_thread(self._native.petname_remove_context, owner_did, context_id)

    async def petname_resolve_context(self, owner_did: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_resolve_context``."""
        return await asyncio.to_thread(self._native.petname_resolve_context, owner_did, name)

    async def petname_resolve_did(self, owner_did: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_resolve_did``."""
        return await asyncio.to_thread(self._native.petname_resolve_did, owner_did, name)

    async def petname_set(self, owner_did: str, target_did: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_set``."""
        return await asyncio.to_thread(self._native.petname_set, owner_did, target_did, name)

    async def petname_set_context(self, owner_did: str, context_id: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.petname_set_context``."""
        return await asyncio.to_thread(
            self._native.petname_set_context, owner_did, context_id, name
        )

    async def scope_deregister(self, scope_context_id: str, name: str, did: str) -> Any:
        """Delegate to ``_scp_core.SCP.scope_deregister``."""
        return await asyncio.to_thread(self._native.scope_deregister, scope_context_id, name, did)

    async def scope_lookup(self, scope_context_id: str, name: str) -> Any:
        """Delegate to ``_scp_core.SCP.scope_lookup``."""
        return await asyncio.to_thread(self._native.scope_lookup, scope_context_id, name)

    async def scope_register(
        self,
        scope_context_id: str,
        name: str,
        target_context_id: str,
        relay_urls: list[str],
        registrant_did: str,
        description: str | None = None,
        tags: list[str] | None = None,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.scope_register``."""
        return await asyncio.to_thread(
            self._native.scope_register,
            scope_context_id,
            name,
            target_context_id,
            relay_urls,
            registrant_did,
            description,
            tags,
        )

    # endregion Discovery

    # region Server

    async def node_start_in_memory(self, identity_did: str | None = None) -> Any:
        """Delegate to ``_scp_core.SCP.node_start_in_memory`` (returns :class:`Node`).

        Passing ``identity_did=None`` requests auto-generation, which a shipped
        build refuses: the in-memory key custody, storage, and DHT client it
        needs compile only under the ``testing`` feature (ADR-062 Decision 1/6).
        The refusal arrives as ``RuntimeError`` carrying "auto-generated
        in-memory node identity is unavailable in this build". Pass an explicit
        ``identity_did`` on a production path.
        """
        from scp_sdk.server import Node

        raw = await asyncio.to_thread(self._native.node_start_in_memory, identity_did)
        return Node(raw)

    async def node_start_local(
        self, data_dir: str, identity_did: str | None = None, passphrase: str | None = None
    ) -> Any:
        """Delegate to ``_scp_core.SCP.node_start_local`` (returns :class:`Node`).

        Passing ``identity_did=None`` reloads a persistent identity and requires
        ``passphrase``. The identity record lives under the storage key
        ``scp/identity`` in ``<data_dir>/storage/``; ``<data_dir>/identity.key``
        holds only the custody key material, so copying it alone is not enough. CREATING one on a
        first run needs a pre-rotation custody backend that only a ``testing``
        build has, so a shipped build raises ``RuntimeError`` carrying
        the message "node startup failed" rather than mint a nullifier-backed
        identity. No error code reaches the caller on this path.
        Pass an explicit ``identity_did``, or point ``data_dir`` at a
        directory that already holds an identity.
        """
        from scp_sdk.server import Node

        raw = await asyncio.to_thread(
            self._native.node_start_local, data_dir, identity_did, passphrase
        )
        return Node(raw)

    async def relay_start_in_memory(self) -> Any:
        """Delegate to ``_scp_core.SCP.relay_start_in_memory`` (returns :class:`Relay`)."""
        from scp_sdk.server import Relay

        raw = await asyncio.to_thread(self._native.relay_start_in_memory)
        return Relay(raw)

    async def relay_start_local(self, data_dir: str) -> Any:
        """Delegate to ``_scp_core.SCP.relay_start_local`` (returns :class:`Relay`)."""
        from scp_sdk.server import Relay

        raw = await asyncio.to_thread(self._native.relay_start_local, data_dir)
        return Relay(raw)

    # endregion Server

    # region Bridge

    async def bridge_create_shadow(
        self, bridge_id: str, platform_handle: str, bridge_mode: str, context_id: str = "ctx-shadow"
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_create_shadow``."""
        return await asyncio.to_thread(
            self._native.bridge_create_shadow, bridge_id, platform_handle, bridge_mode, context_id
        )

    async def bridge_credential_delete_key(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_delete_key``."""
        return await asyncio.to_thread(self._native.bridge_credential_delete_key, bridge_id)

    async def bridge_credential_get_key(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_get_key``."""
        return await asyncio.to_thread(self._native.bridge_credential_get_key, bridge_id)

    async def bridge_credential_list(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_list``."""
        return await asyncio.to_thread(self._native.bridge_credential_list, bridge_id)

    async def bridge_credential_provision(
        self, bridge_id: str, credential_type: str, plaintext: bytes, bridge_credential_key: bytes
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_provision``."""
        return await asyncio.to_thread(
            self._native.bridge_credential_provision,
            bridge_id,
            credential_type,
            plaintext,
            bridge_credential_key,
        )

    async def bridge_credential_retrieve(
        self, bridge_id: str, credential_type: str, bridge_credential_key: bytes
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_retrieve``."""
        return await asyncio.to_thread(
            self._native.bridge_credential_retrieve,
            bridge_id,
            credential_type,
            bridge_credential_key,
        )

    async def bridge_credential_revoke(self, bridge_id: str) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_revoke``."""
        return await asyncio.to_thread(self._native.bridge_credential_revoke, bridge_id)

    async def bridge_credential_rotate(
        self,
        bridge_id: str,
        credential_type: str,
        new_plaintext: bytes,
        bridge_credential_key: bytes,
    ) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_rotate``."""
        return await asyncio.to_thread(
            self._native.bridge_credential_rotate,
            bridge_id,
            credential_type,
            new_plaintext,
            bridge_credential_key,
        )

    async def bridge_credential_store_key(self, bridge_id: str, key: bytes) -> Any:
        """Delegate to ``_scp_core.SCP.bridge_credential_store_key``."""
        return await asyncio.to_thread(self._native.bridge_credential_store_key, bridge_id, key)

    # endregion Bridge

    def __repr__(self) -> str:
        """Developer-facing repr including the native ``instance_id``."""
        return f"SCP(instance_id={self.instance_id})"
