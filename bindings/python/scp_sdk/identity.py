"""SCP Identity management.

Provides the :class:`Identity` class (async-first with sync convenience
wrappers) and the :class:`DIDDocument` dataclass.  All operations
delegate to the ``_scp_core`` PyO3 bridge layer.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 1 for the
canonical API design and ADR-013 acceptance criterion 2 for the bridge
functions.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import IdentityError
from scp_sdk.sync import run_sync
from scp_sdk.types import CustodyType

if TYPE_CHECKING:
    import _scp_core  # noqa: F401


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

        identity = await Identity.create()
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
    async def create(cls, custody: CustodyType | str = CustodyType.FILE) -> Identity:
        """Create a new SCP identity with the specified key custody method.

        Args:
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
                - :attr:`CustodyType.SOFTWARE` / ``"software"`` --
                  software-backed file-based key store.

        Returns:
            A new :class:`Identity` instance.

        Raises:
            scp_sdk.IdentityError: If key generation or DID creation fails.
            scp_sdk.ValidationError: If *custody* is not a recognised
                value.
        """
        import _scp_core

        custody_str = custody.value if isinstance(custody, CustodyType) else custody
        handle = await asyncio.to_thread(_scp_core.py_identity_create, custody_str)
        return cls(handle)

    @classmethod
    async def load(cls, did: str) -> Identity:
        """Load an existing identity from storage.

        Args:
            did: The DID string to load (e.g. ``"did:dht:z6Mk..."``).

        Returns:
            The loaded :class:`Identity` instance.

        Raises:
            scp_sdk.IdentityError: If the DID format is unsupported or
                the identity cannot be found in storage.
        """
        import _scp_core

        handle = await asyncio.to_thread(_scp_core.py_identity_load, did)
        return cls(handle)

    # -- Sync convenience wrappers -------------------------------------------

    @classmethod
    def create_sync(cls, custody: CustodyType | str = CustodyType.FILE) -> Identity:
        """Synchronous convenience wrapper for :meth:`create`.

        Uses :func:`scp_sdk.sync.run_sync` with a dedicated background
        event loop.  Safe in scripts, notebooks, and nested async
        contexts.
        """
        return run_sync(cls.create(custody))

    @classmethod
    def load_sync(cls, did: str) -> Identity:
        """Synchronous convenience wrapper for :meth:`load`.

        Uses :func:`scp_sdk.sync.run_sync` with a dedicated background
        event loop.  Safe in scripts, notebooks, and nested async
        contexts.
        """
        return run_sync(cls.load(did))

    # -- Async instance methods ----------------------------------------------

    @classmethod
    async def create_with_agent_key(cls, custody: CustodyType | str = CustodyType.FILE) -> Identity:
        """Create a new SCP identity with an agent signing key (ADR-039).

        Creates a DID identity with both the standard signing key and an
        ``#agent`` verification method in the DID document.

        Args:
            custody: Key custody type.  Accepts a
                :class:`~scp_sdk.types.CustodyType` enum member or a
                raw string (``"file"``, ``"platform"``, ``"in_memory"``,
                ``"software"``).

        Returns:
            A new :class:`Identity` instance with an agent key.

        Raises:
            scp_sdk.IdentityError: If key generation or DID creation fails.
        """
        import _scp_core

        custody_str = custody.value if isinstance(custody, CustodyType) else custody
        handle = await asyncio.to_thread(_scp_core.py_identity_create_with_agent_key, custody_str)
        return cls(handle)

    async def add_agent_key(self) -> Identity:
        """Add an agent signing key to this identity (ADR-039).

        Generates a new Ed25519 keypair for the ``#agent`` verification
        method, updates the DID document, and publishes to the DHT.

        Returns:
            A new :class:`Identity` with the agent key added.

        Raises:
            scp_sdk.IdentityError: If the identity already has an agent key
                or key generation fails.
        """
        import _scp_core

        handle = await asyncio.to_thread(_scp_core.py_identity_add_agent_key, self._handle)
        return Identity(handle)

    async def rotate_agent_key(self) -> Identity:
        """Rotate the agent signing key for this identity (ADR-039).

        Generates a new Ed25519 keypair, retires the old ``#agent`` key,
        and installs the new key as ``#agent``.

        Returns:
            A new :class:`Identity` with the rotated agent key.

        Raises:
            scp_sdk.IdentityError: If the identity has no agent key or
                key generation fails.
        """
        import _scp_core

        handle = await asyncio.to_thread(_scp_core.py_identity_rotate_agent_key, self._handle)
        return Identity(handle)

    async def remove_agent_key(self) -> Identity:
        """Remove the agent signing key from this identity (ADR-039).

        Removes the ``#agent`` verification method from the DID document
        and publishes the update.

        Returns:
            A new :class:`Identity` with the agent key removed.

        Raises:
            scp_sdk.IdentityError: If the identity has no agent key.
        """
        import _scp_core

        handle = await asyncio.to_thread(_scp_core.py_identity_remove_agent_key, self._handle)
        return Identity(handle)

    async def migrate(self) -> Identity:
        """Migrate this identity to a new DID (Layer 2 rotation).

        Creates a new DID using the pre-rotation key as the new
        Identity Key. The old DID document is updated with an
        ``alsoKnownAs`` pointing to the new DID.

        Returns:
            A new :class:`Identity` with the new DID string.

        Raises:
            scp_sdk.IdentityError: If the identity is not in the
                registry or migration fails.
        """
        import _scp_core

        handle = await asyncio.to_thread(_scp_core.py_identity_migrate, self._handle)
        return Identity(handle)

    async def attest_device(self) -> str:
        """Generate a device attestation token for this identity.

        Returns:
            The attestation token as a base64-encoded string.

        Raises:
            scp_sdk.IdentityError: If attestation generation fails or the
                ``allow_in_memory_custody`` feature is not compiled in.
        """
        import _scp_core

        if not hasattr(_scp_core, "py_identity_attest_device"):
            raise IdentityError(
                "Device attestation requires the 'allow_in_memory_custody' feature",
                "SCP-IDENT-1050",
            )
        return await asyncio.to_thread(_scp_core.py_identity_attest_device, self.did)

    async def verify_device_attestation(self, token_base64: str) -> bool:
        """Verify a device attestation token.

        Args:
            token_base64: The base64-encoded attestation token to verify.

        Returns:
            ``True`` if the token is valid, ``False`` otherwise.

        Raises:
            scp_sdk.IdentityError: If verification fails or the
                ``allow_in_memory_custody`` feature is not compiled in.
        """
        import _scp_core

        if not hasattr(_scp_core, "py_identity_verify_device_attestation"):
            raise IdentityError(
                "Device attestation verification requires the 'allow_in_memory_custody' feature",
                "SCP-IDENT-1051",
            )
        return await asyncio.to_thread(
            _scp_core.py_identity_verify_device_attestation, self.did, token_base64
        )

    async def rotate_key(self) -> Identity:
        """Rotate this identity's active signing key.

        Generates a new signing key and updates the DID document.  The
        DID string remains the same -- only the active signing key
        changes (Layer 1 rotation).

        .. warning::

            This is a placeholder implementation that creates a fresh
            identity rather than performing true key rotation. True
            rotation (updating the DID document while preserving the
            DID) will be implemented when the Rust bridge supports it.

        Returns:
            An updated :class:`Identity` with the rotated key.

        Raises:
            scp_sdk.IdentityError: If key rotation fails.
        """
        import warnings

        warnings.warn(
            "rotate_key() currently creates a fresh identity instead of "
            "performing true key rotation. This is a placeholder.",
            stacklevel=2,
        )
        import _scp_core

        handle = await asyncio.to_thread(_scp_core.py_identity_rotate_key, self._handle)
        return Identity(handle)

    async def resolve(self, did: str) -> DIDDocument:
        """Resolve a DID to its document.

        Args:
            did: The DID string to resolve (e.g. ``"did:dht:z6Mk..."``).

        Returns:
            The resolved :class:`DIDDocument`.

        Raises:
            scp_sdk.IdentityError: If the DID cannot be resolved.
        """
        import _scp_core

        bridge_doc = await asyncio.to_thread(_scp_core.py_identity_resolve, did)
        return _bridge_doc_to_dataclass(bridge_doc)

    # -- Recovery and custody migration ---------------------------------------

    async def execute_recovery(
        self,
        tier: str,
        context_ids: list[str] | None = None,
    ) -> dict:
        """Execute the compromise recovery protocol for this identity.

        Runs the 6-step recovery protocol from spec section 9.12:
        key rotation, MLS Update, UCAN revocation, KeyPackage rotation,
        contact notification, and PSK re-encryption.

        Args:
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

        import _scp_core

        result_json = await asyncio.to_thread(
            _scp_core.identity_execute_recovery,
            self.did,
            tier,
            context_ids or [],
        )
        return json.loads(result_json)

    async def execute_custody_migration(
        self,
        target: str,
        context_ids: list[str] | None = None,
    ) -> dict:
        """Execute the custody migration protocol for this identity.

        Runs the 5-step migration protocol from spec section 3.2.1:
        key generation, authorization, DID document rotation, UCAN
        reissuance, and old key destruction.

        Args:
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

        import _scp_core

        result_json = await asyncio.to_thread(
            _scp_core.identity_execute_custody_migration,
            self.did,
            target,
            context_ids or [],
        )
        return json.loads(result_json)

    # -- Dunder methods ------------------------------------------------------

    def __repr__(self) -> str:
        return f"Identity(did={self.did!r}, custody_type={self.custody_type!r})"

    def __str__(self) -> str:
        return self.did


__all__ = [
    "DIDDocument",
    "Identity",
]
