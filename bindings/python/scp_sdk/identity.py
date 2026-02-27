"""SCP Identity management.

Provides the :class:`Identity` class (async-first with sync convenience
wrappers) and the :class:`DIDDocument` dataclass.  All operations
delegate to the ``_scp_core`` PyO3 bridge layer.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 1 for the
canonical API design and ADR-013 acceptance criterion 2 for the bridge
functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk.sync import run_sync

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
        print(identity.custody_type)  # "platform"

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
    def custody_type(self) -> str:
        """The custody type used for this identity (e.g. ``"platform"``)."""
        return self._handle.custody

    # -- Async factory methods -----------------------------------------------

    @classmethod
    async def create(cls, custody: str = "platform") -> Identity:
        """Create a new SCP identity with the specified key custody method.

        Args:
            custody: Key custody type.  ``"platform"`` (default) uses
                platform-native secure storage; ``"in_memory"`` uses an
                ephemeral in-memory key store.

        Returns:
            A new :class:`Identity` instance.

        Raises:
            scp_sdk.IdentityError: If key generation or DID creation fails.
            scp_sdk.ValidationError: If *custody* is not recognised.
        """
        import _scp_core

        handle = _scp_core.py_identity_create(custody)
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

        handle = _scp_core.py_identity_load(did)
        return cls(handle)

    # -- Sync convenience wrappers -------------------------------------------

    @classmethod
    def create_sync(cls, custody: str = "platform") -> Identity:
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

        handle = _scp_core.py_identity_rotate_key(self._handle)
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

        bridge_doc = _scp_core.py_identity_resolve(did)
        return _bridge_doc_to_dataclass(bridge_doc)

    # -- Dunder methods ------------------------------------------------------

    def __repr__(self) -> str:
        return f"Identity(did={self.did!r}, custody_type={self.custody_type!r})"

    def __str__(self) -> str:
        return self.did


__all__ = [
    "DIDDocument",
    "Identity",
]
