"""SCP Identity management.

Provides the :class:`Identity` class (async-first with sync convenience
wrappers) and the :class:`DIDDocument` dataclass.  All operations
delegate to the ``_scp_core`` PyO3 bridge layer via an explicit
:class:`scp_sdk.SCP` instance.

After #1549 Phase 4 PR 4, every function and method that touches bridge
state requires an explicit :class:`scp_sdk.SCP` argument — the
process-wide default instance façade has been removed. Callers
construct one :class:`scp_sdk.SCP` per tenant/identity/test.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 1 for the
canonical API design and ADR-013 acceptance criterion 2 for the bridge
functions.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import IdentityError, ValidationError
from scp_sdk.sync import run_sync
from scp_sdk.types import CustodyType

if TYPE_CHECKING:
    from scp_sdk.scp import SCP


# ---------------------------------------------------------------------------
# DIDDocument
# ---------------------------------------------------------------------------


@dataclass
class DIDDocument:
    """A resolved DID Document.

    Mirrors the ``PyDIDDocument`` returned by the bridge's
    ``py_identity_resolve`` function.  Fields are extracted from the
    opaque bridge object into a pure-Python dataclass for ergonomic
    access.
    """

    #: The DID string this document describes.
    id: str

    #: Verification methods (list of dicts with ``id``, ``type``,
    #: ``controller``, ``public_key_multibase``).
    verification_methods: list[dict[str, Any]] = field(default_factory=list)

    #: Service entries (list of dicts with ``id``, ``type``,
    #: ``service_endpoint``).
    services: list[dict[str, Any]] = field(default_factory=list)

    #: Alternative identifiers for the DID subject.
    also_known_as: list[str] = field(default_factory=list)

    #: Authentication method references.
    authentication: list[str] = field(default_factory=list)

    #: Assertion method references.
    assertion_methods: list[str] = field(default_factory=list)


def _bridge_doc_to_dataclass(bridge_doc: Any) -> DIDDocument:
    """Convert a ``PyDIDDocument`` bridge object to a :class:`DIDDocument`."""
    return DIDDocument(
        id=bridge_doc.id,
        verification_methods=list(bridge_doc.verification_methods),
        services=list(bridge_doc.services),
        also_known_as=list(bridge_doc.also_known_as),
        authentication=list(bridge_doc.authentication),
        assertion_methods=list(bridge_doc.assertion_methods),
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class Identity:
    """An SCP identity backed by a DID.

    Async-first -- all network operations are ``async def`` methods.
    Synchronous convenience wrappers (:meth:`create_sync`,
    :meth:`load_sync`) are provided for scripts and REPL usage.

    The class wraps the ``_scp_core`` bridge layer.  Internal state is
    held in an opaque ``PyIdentity`` handle obtained from the bridge;
    only safe metadata (``.did``, ``.custody_type``) is exposed.

    Example::

        scp = SCP()
        identity = await Identity.create(scp)
        print(identity.did)           # "did:dht:z6Mk..."
        print(identity.custody_type)  # CustodyType.FILE

    See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 1.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle: Any) -> None:
        """Wrap a ``PyIdentity`` bridge handle.

        Users should not call this directly.  Use :meth:`create` or
        :meth:`load` instead.
        """
        self._handle = handle

    # -- Properties ----------------------------------------------------------

    @property
    def did(self) -> str:
        """The DID string for this identity (e.g. ``"did:dht:z6Mk..."``)."""
        return self._handle.did

    @property
    def custody_type(self) -> CustodyType | str:
        """The custody type used for this identity.

        Returns a :class:`~scp_sdk.types.CustodyType` enum member when
        the value matches a known variant, otherwise the raw string.
        """
        raw = self._handle.custody
        try:
            return CustodyType(raw)
        except ValueError:
            return raw

    # -- Async factory methods -----------------------------------------------

    @classmethod
    async def create(
        cls,
        scp: SCP,
        custody: CustodyType | str = CustodyType.FILE,
    ) -> Identity:
        """Create a new SCP identity with the specified key custody method.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            custody: Key custody type.  Accepts a
                :class:`~scp_sdk.types.CustodyType` enum member or a raw
                string.  Valid values:

                - :attr:`CustodyType.FILE` / ``"file"`` (default) --
                  encrypted file-backed key custody (Argon2id +
                  AES-256-GCM at ``$HOME/.scp/keys.bin``).  Requires
                  the ``SCP_KEY_PASSPHRASE`` environment variable.
                - :attr:`CustodyType.PLATFORM` / ``"platform"`` --
                  backward-compatible alias for ``"file"``.
                - :attr:`CustodyType.IN_MEMORY` / ``"in_memory"`` --
                  ephemeral in-memory key store, suitable for testing or
                  short-lived agents.

        Returns:
            A new :class:`Identity` instance.

        Raises:
            scp_sdk.IdentityError: If key generation or DID creation fails.
            scp_sdk.ValidationError: If *custody* is not a recognised
                value.
        """
        native = scp._native
        custody_str = custody.value if isinstance(custody, CustodyType) else custody
        handle = await asyncio.to_thread(native.identity_create, custody_str)
        return cls(handle)

    @classmethod
    async def load(cls, scp: SCP, did: str) -> Identity:
        """Load an existing identity from storage.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            did: The DID string to load (e.g. ``"did:dht:z6Mk..."``).

        Returns:
            The loaded :class:`Identity` instance.

        Raises:
            scp_sdk.IdentityError: If the DID format is unsupported or
                the identity cannot be found in storage.
        """
        native = scp._native
        handle = await asyncio.to_thread(native.identity_load, did)
        return cls(handle)

    # -- Sync convenience wrappers -------------------------------------------

    @classmethod
    def create_sync(
        cls,
        scp: SCP,
        custody: CustodyType | str = CustodyType.FILE,
    ) -> Identity:
        """Synchronous convenience wrapper for :meth:`create`.

        Uses :func:`scp_sdk.sync.run_sync` with a dedicated background
        event loop.  Safe in scripts, notebooks, and nested async
        contexts.
        """
        return run_sync(cls.create(scp, custody))

    @classmethod
    def load_sync(cls, scp: SCP, did: str) -> Identity:
        """Synchronous convenience wrapper for :meth:`load`.

        Uses :func:`scp_sdk.sync.run_sync` with a dedicated background
        event loop.  Safe in scripts, notebooks, and nested async
        contexts.
        """
        return run_sync(cls.load(scp, did))

    # -- Async instance methods ----------------------------------------------

    @classmethod
    async def create_with_agent_key(
        cls,
        scp: SCP,
        custody: CustodyType | str = CustodyType.FILE,
    ) -> Identity:
        """Create a new SCP identity with an agent signing key (ADR-039).

        Creates a DID identity with both the standard signing key and an
        ``#agent`` verification method in the DID document.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            custody: Key custody type.  Accepts a
                :class:`~scp_sdk.types.CustodyType` enum member or a
                raw string (``"file"``, ``"platform"``, ``"in_memory"``).

        Returns:
            A new :class:`Identity` instance with an agent key.

        Raises:
            scp_sdk.IdentityError: If key generation or DID creation fails.
        """
        native = scp._native
        custody_str = custody.value if isinstance(custody, CustodyType) else custody
        handle = await asyncio.to_thread(native.identity_create_with_agent_key, custody_str)
        return cls(handle)

    async def add_agent_key(self, scp: SCP) -> Identity:
        """Add an agent signing key to this identity (ADR-039).

        Generates a new Ed25519 keypair for the ``#agent`` verification
        method, updates the DID document, and publishes to the DHT.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            A new :class:`Identity` with the agent key added.

        Raises:
            scp_sdk.IdentityError: If the identity already has an agent key
                or key generation fails.
        """
        native = scp._native
        handle = await asyncio.to_thread(native.identity_add_agent_key, self._handle)
        return Identity(handle)

    async def rotate_agent_key(self, scp: SCP) -> Identity:
        """Rotate the agent signing key for this identity (ADR-039).

        Generates a new Ed25519 keypair, retires the old ``#agent`` key,
        and installs the new key as ``#agent``.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            A new :class:`Identity` with the rotated agent key.

        Raises:
            scp_sdk.IdentityError: If the identity has no agent key or
                key generation fails.
        """
        native = scp._native
        handle = await asyncio.to_thread(native.identity_rotate_agent_key, self._handle)
        return Identity(handle)

    async def remove_agent_key(self, scp: SCP) -> Identity:
        """Remove the agent signing key from this identity (ADR-039).

        Removes the ``#agent`` verification method from the DID document
        and publishes the update.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            A new :class:`Identity` with the agent key removed.

        Raises:
            scp_sdk.IdentityError: If the identity has no agent key.
        """
        native = scp._native
        handle = await asyncio.to_thread(native.identity_remove_agent_key, self._handle)
        return Identity(handle)

    async def migrate(self, scp: SCP) -> Identity:
        """Migrate this identity to a new DID (Layer 2 rotation).

        Creates a new DID using the pre-rotation key as the new
        Identity Key. The old DID document is updated with an
        ``alsoKnownAs`` pointing to the new DID.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            A new :class:`Identity` with the new DID string.

        Raises:
            scp_sdk.IdentityError: If the identity is not in the
                registry or migration fails.
        """
        native = scp._native
        handle = await asyncio.to_thread(native.identity_migrate, self._handle)
        return Identity(handle)

    async def attest_device(self, scp: SCP) -> str:
        """Generate a device attestation token for this identity.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            The attestation token as a base64-encoded string.

        Raises:
            scp_sdk.IdentityError: If attestation generation fails or the
                ``allow_in_memory_custody`` feature is not compiled in.
        """
        native = scp._native
        if not hasattr(native, "identity_attest_device"):
            raise IdentityError(
                "Device attestation requires the 'allow_in_memory_custody' feature",
                "SCP-IDENT-1050",
            )
        return await asyncio.to_thread(native.identity_attest_device, self.did)

    async def verify_device_attestation(self, scp: SCP, token_base64: str) -> bool:
        """Verify a device attestation token.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            token_base64: The base64-encoded attestation token to verify.

        Returns:
            ``True`` if the token is valid, ``False`` otherwise.

        Raises:
            scp_sdk.IdentityError: If verification fails or the
                ``allow_in_memory_custody`` feature is not compiled in.
        """
        native = scp._native
        if not hasattr(native, "identity_verify_device_attestation"):
            raise IdentityError(
                "Device attestation verification requires the 'allow_in_memory_custody' feature",
                "SCP-IDENT-1051",
            )
        return await asyncio.to_thread(
            native.identity_verify_device_attestation, self.did, token_base64
        )

    async def rotate_key(self, scp: SCP) -> Identity:
        """Rotate this identity's active signing key.

        Generates a new signing key and updates the DID document.  The
        DID string remains the same -- only the active signing key
        changes (Layer 1 rotation).

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            An updated :class:`Identity` with the rotated key.

        Raises:
            scp_sdk.IdentityError: If key rotation fails.
        """
        native = scp._native
        handle = await asyncio.to_thread(native.identity_rotate_key, self._handle)
        return Identity(handle)

    async def resolve(self, scp: SCP, did: str) -> DIDDocument:
        """Resolve a DID to its document.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            did: The DID string to resolve (e.g. ``"did:dht:z6Mk..."``).

        Returns:
            The resolved :class:`DIDDocument`.

        Raises:
            scp_sdk.IdentityError: If the DID cannot be resolved.
        """
        native = scp._native
        bridge_doc = await asyncio.to_thread(native.identity_resolve, did)
        return _bridge_doc_to_dataclass(bridge_doc)

    # -- Recovery and custody migration ---------------------------------------

    async def execute_recovery(
        self,
        scp: SCP,
        tier: str,
        context_ids: list[str] | None = None,
    ) -> dict:
        """Execute the compromise recovery protocol for this identity.

        Runs the 6-step recovery protocol from spec section 9.12:
        key rotation, MLS Update, UCAN revocation, KeyPackage rotation,
        contact notification, and PSK re-encryption.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            tier: Compromise tier. One of ``"agent"``,
                ``"active_signing"``, or ``"identity_key"``.
            context_ids: Context IDs where this DID is a member.
                Defaults to an empty list.

        Returns:
            A dict with recovery outcome fields including
            ``completed_contexts``, ``failed_contexts``,
            ``key_rotation_completed``, etc.

        Raises:
            scp_sdk.IdentityError: If recovery fails.
        """
        import json

        native = scp._native
        # Use `is not None` -- never the falsy form -- so callers can ratchet
        # the empty-vs-absent distinction at the FFI boundary later if needed.
        result_json = await asyncio.to_thread(
            native.identity_execute_recovery,
            self.did,
            tier,
            context_ids if context_ids is not None else [],
        )
        return json.loads(result_json)

    async def execute_custody_migration(
        self,
        scp: SCP,
        target: str,
        context_ids: list[str] | None = None,
    ) -> dict:
        """Execute the custody migration protocol for this identity.

        Runs the 5-step migration protocol from spec section 3.2.1:
        key generation, authorization, DID document rotation, UCAN
        reissuance, and old key destruction.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            target: Target custody type. One of
                ``"platform_managed"``, ``"hardware"``,
                ``"software"``, or ``"in_memory"``.
            context_ids: Context IDs where this DID is a member.
                Defaults to an empty list.

        Returns:
            A dict with migration outcome fields including
            ``key_generated``, ``authorized``,
            ``did_document_rotated``, ``ucans_reissued``,
            ``old_key_destroyed``, etc.

        Raises:
            scp_sdk.IdentityError: If migration fails.
        """
        import json

        native = scp._native
        # Use `is not None` -- never the falsy form -- so callers can ratchet
        # the empty-vs-absent distinction at the FFI boundary later if needed.
        result_json = await asyncio.to_thread(
            native.identity_execute_custody_migration,
            self.did,
            target,
            context_ids if context_ids is not None else [],
        )
        return json.loads(result_json)

    # -- Identity Link Attestations (§3.5) -----------------------------------

    async def create_attestation(
        self,
        scp: SCP,
        platform: str,
        handle: str,
        proof: str,
        platform_id: str | None = None,
    ) -> IdentityAttestation:
        """Create an identity link attestation for an external platform (§3.5).

        Cryptographically binds this DID to an external platform identity.
        The proof is platform-specific evidence of ownership (e.g., a
        signed challenge token, DNS TXT record value, or OAuth token).

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            platform: Platform identifier (e.g. ``"github.com"``,
                ``"x.com"``, ``"linkedin.com"``).
            handle: Platform-specific handle or username.
            proof: Platform-specific proof of ownership.
            platform_id: Optional platform-assigned unique identifier
                (e.g. numeric user ID). If not provided, only the
                handle is recorded.

        Returns:
            The created :class:`IdentityAttestation`.

        Raises:
            scp_sdk.IdentityError: If attestation creation fails or
                the bridge function is not available.
        """
        native = scp._native
        if not hasattr(native, "create_identity_link_attestation"):
            raise IdentityError(
                "Identity link attestation creation is not yet available in the bridge",
                "SCP-ATTEST-9010",
            )
        result_json = await asyncio.to_thread(
            native.create_identity_link_attestation,
            self.did,
            platform,
            handle,
            proof,
            platform_id,
        )
        import json

        data = json.loads(result_json)
        return IdentityAttestation._from_dict(data)

    async def list_attestations(self, scp: SCP) -> list[IdentityAttestation]:
        """List all identity link attestations for this identity (async).

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.

        Returns:
            A list of :class:`IdentityAttestation` objects.

        Raises:
            scp_sdk.IdentityError: If listing fails or the bridge
                function is not available.
        """
        native = scp._native
        if not hasattr(native, "identity_link_attestations"):
            raise IdentityError(
                "Identity link attestation listing is not yet available in the bridge",
                "SCP-ATTEST-9011",
            )
        import json

        result_json = await asyncio.to_thread(
            native.identity_link_attestations,
            self.did,
        )
        items = json.loads(result_json)
        return [IdentityAttestation._from_dict(item) for item in items]

    async def remove_attestation(self, scp: SCP, attestation_id: str) -> bool:
        """Remove an identity link attestation by ID.

        Revokes and removes the attestation from this identity's
        attestation set. The revocation is published so verifiers
        can detect stale attestations.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            attestation_id: The deterministic attestation ID to remove.

        Returns:
            ``True`` if the attestation was found and removed,
            ``False`` if no attestation with that ID exists.

        Raises:
            scp_sdk.IdentityError: If removal fails or the bridge
                function is not available.
        """
        native = scp._native
        if not hasattr(native, "remove_identity_link_attestation"):
            raise IdentityError(
                "Identity link attestation removal is not yet available in the bridge",
                "SCP-ATTEST-9012",
            )
        return await asyncio.to_thread(
            native.remove_identity_link_attestation,
            self.did,
            attestation_id,
        )

    async def renew_attestation(
        self,
        scp: SCP,
        attestation: IdentityAttestation,
    ) -> IdentityAttestation:
        """Renew an identity link attestation with a fresh ``verified_at``.

        Re-creates the attestation with a new verification timestamp,
        resetting the renewal interval countdown (§3.5.2). The proof
        must be re-verified by the platform.

        Args:
            scp: The :class:`scp_sdk.SCP` instance that owns this identity.
            attestation: The attestation to renew.

        Returns:
            A new :class:`IdentityAttestation` with updated
            ``verified_at`` timestamp.

        Raises:
            scp_sdk.IdentityError: If renewal fails or the bridge
                function is not available.
        """
        native = scp._native
        if not hasattr(native, "identity_renew_attestation"):
            raise IdentityError(
                "Identity link attestation renewal is not yet available in the bridge",
                "SCP-ATTEST-9013",
            )
        import json

        result_json = await asyncio.to_thread(
            native.identity_renew_attestation,
            self.did,
            attestation.id,
        )
        data = json.loads(result_json)
        return IdentityAttestation._from_dict(data)

    # -- Dunder methods ------------------------------------------------------

    def __repr__(self) -> str:
        return f"Identity(did={self.did!r}, custody_type={self.custody_type!r})"

    def __str__(self) -> str:
        return self.did


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_finite_int(value: object, field_name: str) -> int:
    """Coerce *value* to a non-negative integer, raising :class:`ValidationError` on:

    - ``bool`` (since ``isinstance(True, int)`` is ``True`` silently)
    - ``str`` (cross-SDK divergence: TypeScript ``Number.isFinite`` rejects strings)
    - non-integer ``float`` (silent truncation: ``1.5`` → ``1``)
    - NaN/Infinity floats (not representable as int)
    - negative integers (Unix timestamps are non-negative)

    Whole-number floats (e.g. ``1700000000.0``) are accepted and coerced to
    ``int`` because JSON parsers commonly deserialize integer fields as floats,
    and lossless coercion is correct behavior at a deserialization boundary.

    Raises ``ValidationError`` with code ``SCP-VALID-7005`` ("Invalid
    field value") to match the TypeScript SDK's behavior — both bridges
    parse the same wire format and should surface the same error type
    and code so cross-language consumers can handle them uniformly.
    """
    if isinstance(value, bool):
        raise ValidationError(
            f"{field_name} must be a finite integer, got bool",
            "SCP-VALID-7005",
        )
    if isinstance(value, str):
        raise ValidationError(
            f"{field_name} must be a number, got str",
            "SCP-VALID-7005",
        )
    if not isinstance(value, (int, float)):
        raise ValidationError(
            f"{field_name} must be a number, got {type(value).__name__}",
            "SCP-VALID-7005",
        )
    if isinstance(value, float):
        import math

        if not math.isfinite(value):
            raise ValidationError(
                f"{field_name} must be a finite integer: {value} is not finite",
                "SCP-VALID-7005",
            )
        if value != int(value):
            raise ValidationError(
                f"{field_name} must be an integer, got non-integer float {value!r}",
                "SCP-VALID-7005",
            )
    result = int(value)  # type: ignore[arg-type]
    if result < 0:
        raise ValidationError(
            f"{field_name} must be non-negative, got {result}",
            "SCP-VALID-7005",
        )
    return result


# ---------------------------------------------------------------------------
# RevocationStatus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevocationStatus:
    """Revocation status for an identity attestation (§3.5).

    Mirrors the Rust ``RevocationStatus`` enum:

    - ``Active`` -> ``RevocationStatus(status="active")``
    - ``Revoked { revoked_at, reason }`` ->
      ``RevocationStatus(status="revoked", revoked_at=..., reason=...)``
    """

    #: Status string: ``"active"`` or ``"revoked"``.
    status: str

    #: Unix timestamp (seconds) when the attestation was revoked.
    #: Only present when ``status == "revoked"``.
    revoked_at: int | None = None

    #: Optional human-readable revocation reason.
    #: Only present when ``status == "revoked"``.
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status == "revoked" and self.revoked_at is None:
            raise ValueError("RevocationStatus with status='revoked' requires revoked_at")
        if self.status not in ("active", "revoked"):
            raise ValueError(
                f"Invalid revocation status: {self.status!r} (expected 'active' or 'revoked')"
            )
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", _parse_finite_int(self.revoked_at, "revoked_at"))


# ---------------------------------------------------------------------------
# IdentityAttestation
# ---------------------------------------------------------------------------


@dataclass
class IdentityAttestation:
    """An identity link attestation binding a DID to an external platform (§3.5).

    Represents a cryptographically signed claim that the DID owner also
    controls an identity on an external platform (e.g. GitHub, X, LinkedIn).

    The ``id`` is deterministically derived as
    ``hex(SHA-256(issuer || platform || handle || issued_at))``.
    """

    #: Deterministic attestation ID.
    id: str

    #: Platform identifier (e.g. ``"github.com"``).
    platform: str

    #: Platform handle or username.
    platform_handle: str

    #: DID verification method that signed this attestation
    #: (e.g. ``"did:dht:z6Mk...#active"``).
    verification_method: str

    #: Unix timestamp (seconds) when the evidence was last verified.
    verified_at: int

    #: Revocation status (``"active"`` or ``"revoked"`` with metadata).
    revocation_status: RevocationStatus = field(
        default_factory=lambda: RevocationStatus(status="active")
    )

    #: Optional platform-assigned unique identifier.
    platform_id: str | None = None

    def __post_init__(self) -> None:
        self.verified_at = _parse_finite_int(self.verified_at, "verified_at")

    def _to_bridge_dict(self) -> dict[str, Any]:
        """Convert to a dict for bridge serialization."""
        rs = self.revocation_status
        if rs.status == "revoked":
            rs_value: dict[str, Any] = {"Revoked": {}}
            if rs.revoked_at is not None:
                rs_value["Revoked"]["revoked_at"] = rs.revoked_at
            if rs.reason is not None:
                rs_value["Revoked"]["reason"] = rs.reason
        else:
            rs_value = "Active"  # type: ignore[assignment]

        d: dict[str, Any] = {
            "id": self.id,
            "platform": self.platform,
            "platform_handle": self.platform_handle,
            "verification_method": self.verification_method,
            "verified_at": self.verified_at,
            "revocation_status": rs_value,
        }
        if self.platform_id is not None:
            d["platform_id"] = self.platform_id
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> IdentityAttestation:
        """Construct from a dict returned by the bridge."""
        raw_rs = data.get("revocation_status", "active")
        if isinstance(raw_rs, dict) and "Revoked" in raw_rs:
            revoked_data = raw_rs["Revoked"]
            revoked_at_raw = revoked_data.get("revoked_at")
            if revoked_at_raw is None:
                raise ValueError("Bridge returned Revoked status without revoked_at timestamp")
            rs = RevocationStatus(
                status="revoked",
                revoked_at=_parse_finite_int(revoked_at_raw, "revoked_at"),
                reason=revoked_data.get("reason"),
            )
        elif isinstance(raw_rs, str) and raw_rs.lower() == "active":
            rs = RevocationStatus(status="active")
        elif isinstance(raw_rs, str) and raw_rs.lower() == "revoked":
            raise ValueError("Bridge returned bare 'revoked' string without revocation metadata")
        else:
            raise ValueError(f"Unknown revocation status from bridge: {raw_rs!r}")

        return cls(
            id=data["id"],
            platform=data["platform"],
            platform_handle=data["platform_handle"],
            verification_method=data["verification_method"],
            verified_at=_parse_finite_int(data["verified_at"], "verified_at"),
            revocation_status=rs,
            platform_id=data.get("platform_id"),
        )

    def __repr__(self) -> str:
        return (
            f"IdentityAttestation(id={self.id!r}, platform={self.platform!r}, "
            f"handle={self.platform_handle!r}, status={self.revocation_status.status!r})"
        )


__all__ = [
    "DIDDocument",
    "Identity",
    "IdentityAttestation",
    "RevocationStatus",
]
