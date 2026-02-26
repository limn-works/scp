"""Type stubs for the ``_scp_core`` PyO3 extension module.

This file provides Python type annotations for all classes, functions, and
exceptions exposed by the Rust bridge layer (``crates/scp-ffi/src/``). It
enables IDE autocompletion (VS Code, PyCharm) and static analysis via
mypy/pyright.

Generated from the Rust source in ``crates/scp-ffi/src/``. See ADR-013
in ``.docs/adrs/phase-3.md`` for the full bridge specification.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------
# Mirrors the exception classes created via pyo3::create_exception! in
# crates/scp-ffi/src/error.rs.
#
# Hierarchy:
#   Exception
#   +-- ScpError
#       +-- IdentityError
#       +-- ContextError
#       +-- CryptoError
#       +-- TransportError
#       +-- UcanError
#       +-- ValidationError

class ScpError(Exception):
    """Base exception for all SCP protocol errors."""
    ...

class IdentityError(ScpError):
    """An identity operation failed (DID creation, resolution, key rotation)."""
    ...

class ContextError(ScpError):
    """A context lifecycle operation failed (create, join, leave, close, send)."""
    ...

class CryptoError(ScpError):
    """A cryptographic operation failed (MLS, sender keys, encryption, decryption)."""
    ...

class TransportError(ScpError):
    """A transport operation failed (connection, send, subscription)."""
    ...

class UcanError(ScpError):
    """A UCAN operation failed (validation, minting, revocation)."""
    ...

class ValidationError(ScpError):
    """Input validation failed (malformed data, schema mismatch, constraint violation)."""
    ...

# ---------------------------------------------------------------------------
# Identity types (crates/scp-ffi/src/identity.rs)
# ---------------------------------------------------------------------------

class PyIdentity:
    """An SCP identity handle.

    Stores the DID string and custody type as safe, cloneable metadata.
    Internal key material is not exposed to Python.
    """

    @property
    def did(self) -> str:
        """The DID string (e.g., ``"did:dht:z6Mk..."``)."""
        ...

    @property
    def custody(self) -> str:
        """The custody type (``"in_memory"`` or ``"platform"``)."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class PyDIDDocument:
    """A DID Document exposed to Python.

    Wraps the Rust ``DidDocument`` and provides getter methods for all
    public fields.
    """

    @property
    def id(self) -> str:
        """The DID string that this document describes."""
        ...

    @property
    def verification_methods(self) -> list[dict[str, str]]:
        """Verification methods as a list of dicts.

        Each dict contains ``id``, ``type``, ``controller``, and
        ``public_key_multibase``.
        """
        ...

    @property
    def services(self) -> list[dict[str, str]]:
        """Service entries as a list of dicts.

        Each dict contains ``id``, ``type``, and ``service_endpoint``.
        """
        ...

    @property
    def also_known_as(self) -> list[str]:
        """The ``alsoKnownAs`` entries as a list of strings."""
        ...

    @property
    def authentication(self) -> list[str]:
        """Authentication method references as a list of strings."""
        ...

    @property
    def assertion_methods(self) -> list[str]:
        """Assertion method references as a list of strings."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

# ---------------------------------------------------------------------------
# Context types (crates/scp-ffi/src/context.rs)
# ---------------------------------------------------------------------------

class PyContextHandle:
    """Opaque handle to an SCP context.

    Stores context metadata: unique ID, lifecycle state, and the DID
    of the context creator.
    """

    @property
    def context_id(self) -> str:
        """The context's unique identifier."""
        ...

    @property
    def state(self) -> str:
        """Current lifecycle state.

        One of: ``"creating"``, ``"active"``, ``"closing"``, ``"closed"``,
        ``"expired"``.
        """
        ...

    @property
    def creator_did(self) -> str:
        """The DID of the context creator."""
        ...

    def __repr__(self) -> str: ...

class PyContextParams:
    """Context creation parameters, constructed from a Python dict.

    Accepted dict keys (all optional): ``ceiling``, ``roles``, ``tools``,
    ``ttl``, ``memory_scope``, ``governance``.
    """

    def __init__(self, params: dict[str, Any]) -> None: ...

    @property
    def ceiling(self) -> list[str]:
        """Capability ceiling -- maximum capabilities any participant can hold."""
        ...

    @property
    def roles(self) -> dict[str, list[str]]:
        """Role definitions mapping role names to capability lists."""
        ...

    @property
    def tools(self) -> list[str]:
        """Initial tool registrations by name."""
        ...

    @property
    def ttl(self) -> float | None:
        """Optional time-to-live in seconds."""
        ...

    @property
    def memory_scope(self) -> str:
        """Memory scope: ``"ephemeral"``, ``"summary"``, or ``"full"``."""
        ...

    @property
    def governance(self) -> str:
        """Governance model (e.g., ``"single_admin"``)."""
        ...

    def __repr__(self) -> str: ...

class PyMessage:
    """A received message from an SCP context."""

    @property
    def sender_did(self) -> str:
        """DID of the message sender."""
        ...

    @property
    def payload(self) -> bytes:
        """Message payload as raw bytes."""
        ...

    @property
    def timestamp(self) -> float:
        """Message timestamp as seconds since Unix epoch."""
        ...

    @property
    def context_id(self) -> str:
        """Context ID this message belongs to."""
        ...

    def __repr__(self) -> str: ...

class PyMessageReceiver:
    """Async iterator over incoming messages from an SCP context.

    Implements Python's async iterator protocol. Iterate with::

        async for msg in receiver:
            ...
    """

    def __aiter__(self) -> PyMessageReceiver: ...
    def __anext__(self) -> PyMessage | None: ...

# ---------------------------------------------------------------------------
# Tool types (crates/scp-ffi/src/tools.rs)
# ---------------------------------------------------------------------------

class ToolRegistration:
    """Tool registration data.

    Contains the metadata needed to register a tool in an SCP context:
    name, description, JSON Schema, and test vectors.
    """

    name: str
    description: str
    schema: Any
    test_vectors: list[Any]

    def __init__(
        self,
        name: str,
        description: str,
        schema: Any,
        test_vectors: list[Any],
    ) -> None: ...

    def __repr__(self) -> str: ...

class ToolVerificationResult:
    """Result of verifying a tool against its test vectors."""

    tool_id: str
    passed: bool
    failures: list[str]

    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Transport types (crates/scp-ffi/src/transport.rs)
# ---------------------------------------------------------------------------

class TransportStatus:
    """Transport connection status."""

    connected: bool
    relay_url: str | None
    latency_ms: float | None

    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# UCAN types (crates/scp-ffi/src/ucan.rs)
# ---------------------------------------------------------------------------

class UcanToken:
    """UCAN token exposed to Python.

    Contains the token metadata: unique token ID, issuer DID, audience DID,
    granted capabilities, and optional expiry timestamp.
    """

    token_id: str
    issuer: str
    audience: str
    capabilities: list[str]
    expires_at: float | None

    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Event log types (crates/scp-ffi/src/event_log.rs)
# ---------------------------------------------------------------------------

class Event:
    """A protocol event from the context event log."""

    event_type: str
    actor_did: str
    timestamp: float
    payload: Any
    sequence: int

    def __repr__(self) -> str: ...

class Proof:
    """A verification proof from the event log."""

    verified: bool
    proof_type: str
    details: Any

    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Module-level functions (crates/scp-ffi/src/lib.rs)
# ---------------------------------------------------------------------------

def runtime_is_initialized() -> bool:
    """Returns ``True`` if the tokio runtime has been initialized."""
    ...

def version() -> str:
    """Returns the version string for the ``_scp_core`` extension module."""
    ...

def shutdown_runtime() -> None:
    """Signals the tokio runtime to begin graceful shutdown.

    Called automatically via ``atexit`` during Python interpreter exit.
    Idempotent -- safe to call multiple times.
    """
    ...

# ---------------------------------------------------------------------------
# Identity bridge functions (crates/scp-ffi/src/identity.rs)
# ---------------------------------------------------------------------------

def py_identity_create(custody: str) -> PyIdentity:
    """Create a new DID identity.

    Args:
        custody: The custody type -- ``"in_memory"`` or ``"platform"``.

    Returns:
        A ``PyIdentity`` containing the new DID string and custody type.

    Raises:
        IdentityError: If key generation or DID creation fails.
        ValidationError: If the custody string is invalid.
    """
    ...

def py_identity_load(did: str) -> PyIdentity:
    """Load an existing identity from storage.

    Args:
        did: The DID string to load (e.g., ``"did:dht:z6Mk..."``).

    Returns:
        A ``PyIdentity`` containing the loaded DID string.

    Raises:
        IdentityError: If the DID format is unsupported.
    """
    ...

def py_identity_resolve(did: str) -> PyDIDDocument:
    """Resolve a DID to its document.

    Args:
        did: The DID string to resolve (e.g., ``"did:dht:z6Mk..."``).

    Returns:
        A ``PyDIDDocument`` containing the resolved document.

    Raises:
        IdentityError: If the DID cannot be resolved.
    """
    ...

def py_identity_rotate_key(identity: PyIdentity) -> PyIdentity:
    """Rotate the active signing key for an identity.

    Generates a new Active Signing Key and updates the DID document.
    The DID string remains the same.

    Args:
        identity: The ``PyIdentity`` whose key should be rotated.

    Returns:
        A new ``PyIdentity`` with the same DID but a rotated key.

    Raises:
        IdentityError: If key rotation fails.
    """
    ...

# ---------------------------------------------------------------------------
# Context bridge functions (crates/scp-ffi/src/context.rs)
# ---------------------------------------------------------------------------

def py_context_create(
    identity_did: str,
    params: dict[str, Any],
) -> PyContextHandle:
    """Create a new SCP context.

    Args:
        identity_did: The DID string of the identity creating the context.
        params: A dict with context parameters (``ceiling``, ``roles``,
            ``tools``, ``ttl``, ``memory_scope``, ``governance``).

    Returns:
        A ``PyContextHandle`` in the ``"active"`` state.

    Raises:
        TypeError: If params contains invalid types.
        ValueError: If parameter values are out of range.
        RuntimeError: If context creation fails.
    """
    ...

def py_context_join(handle: PyContextHandle, identity_did: str) -> None:
    """Join an existing SCP context.

    Args:
        handle: The context to join.
        identity_did: The DID string of the identity joining.

    Raises:
        RuntimeError: If the context is not in ``"active"`` state.
    """
    ...

def py_context_leave(handle: PyContextHandle, identity_did: str) -> None:
    """Leave an SCP context.

    Args:
        handle: The context to leave.
        identity_did: The DID string of the identity leaving.

    Raises:
        RuntimeError: If the context is not in ``"active"`` state.
    """
    ...

def py_context_close(handle: PyContextHandle, identity_did: str) -> None:
    """Close an SCP context.

    Transitions the context from ``"active"`` to ``"closed"``.

    Args:
        handle: The context to close.
        identity_did: The DID of the identity initiating the close.

    Raises:
        RuntimeError: If the context is not in ``"active"`` state.
    """
    ...

def py_context_send(
    handle: PyContextHandle,
    identity_did: str,
    payload: bytes | str,
) -> None:
    """Send a message to an SCP context.

    Args:
        handle: The context to send to.
        identity_did: The DID of the sender.
        payload: The message payload (bytes or str).

    Raises:
        RuntimeError: If the context is not in ``"active"`` state.
        TypeError: If the payload is not bytes or str.
    """
    ...

def py_context_receive(handle: PyContextHandle) -> PyMessageReceiver:
    """Return an async iterator of incoming messages for a context.

    Args:
        handle: The context to receive messages from.

    Returns:
        A ``PyMessageReceiver`` implementing Python's async iterator protocol.

    Raises:
        RuntimeError: If the context is not in ``"active"`` state.
    """
    ...

# ---------------------------------------------------------------------------
# Tool bridge functions (crates/scp-ffi/src/tools.rs)
# ---------------------------------------------------------------------------

def tool_register(context_id: str, registration: dict[str, Any]) -> str:
    """Register a tool in an SCP context.

    Args:
        context_id: The ID of the context to register the tool in.
        registration: A dict containing tool registration data (``name``,
            ``description``, ``schema``, ``test_vectors``, ``operator_did``).

    Returns:
        The tool ID (string) assigned to the registered tool.

    Raises:
        ContextError: If registration fails.
    """
    ...

def tool_invoke(
    context_id: str,
    tool_id: str,
    input: dict[str, Any],
    identity_did: str,
) -> Any:
    """Invoke a tool within an SCP context.

    Args:
        context_id: The ID of the context containing the tool.
        tool_id: The ID of the tool to invoke.
        input: A dict of input parameters matching the tool's input schema.
        identity_did: The DID of the invoking identity.

    Returns:
        A dict containing the tool's JSON-compatible output.

    Raises:
        ContextError: If invocation fails.
    """
    ...

def tool_verify(context_id: str, tool_id: str) -> ToolVerificationResult:
    """Verify a tool against its registered test vectors.

    Args:
        context_id: The ID of the context containing the tool.
        tool_id: The ID of the tool to verify.

    Returns:
        A ``ToolVerificationResult`` with the tool ID, pass/fail status,
        and any failure messages.

    Raises:
        ContextError: If verification fails.
    """
    ...

# ---------------------------------------------------------------------------
# Transport bridge functions (crates/scp-ffi/src/transport.rs)
# ---------------------------------------------------------------------------

def transport_connect(relay_url: str) -> None:
    """Connect to an SCP relay.

    Args:
        relay_url: The URL of the SCP relay (e.g., ``"wss://relay.example.com"``).

    Raises:
        TransportError: If the connection fails.
    """
    ...

def transport_status() -> TransportStatus:
    """Return the current transport connection status.

    Returns:
        A ``TransportStatus`` with connection state, relay URL, and latency.

    Raises:
        TransportError: If querying the transport status fails.
    """
    ...

# ---------------------------------------------------------------------------
# UCAN bridge functions (crates/scp-ffi/src/ucan.rs)
# ---------------------------------------------------------------------------

def ucan_validate(context_id: str, token: str, capability: str) -> None:
    """Validate a UCAN token for a required capability.

    Performs full UCAN validation: signature verification, time bounds
    checking, delegation chain traversal, attenuation enforcement, nonce
    replay detection, and capability matching.

    Args:
        context_id: The ID of the context the token is presented in.
        token: The encoded UCAN token string (JWT format).
        capability: The required capability URI.

    Raises:
        UcanError: If validation fails for any reason.
    """
    ...

def ucan_mint(
    context_id: str,
    member_did: str,
    capabilities: list[str],
) -> UcanToken:
    """Mint a new UCAN token for a context member.

    Args:
        context_id: The ID of the context to mint the token for.
        member_did: The DID of the member receiving the token.
        capabilities: List of capability URIs to grant.

    Returns:
        A ``UcanToken`` with the minted token's metadata.

    Raises:
        UcanError: If minting fails.
    """
    ...

def ucan_revoke(context_id: str, token_id: str) -> None:
    """Revoke a UCAN token.

    Args:
        context_id: The ID of the context the token belongs to.
        token_id: The unique ID of the token to revoke.

    Raises:
        UcanError: If revocation fails.
    """
    ...

# ---------------------------------------------------------------------------
# Event log bridge functions (crates/scp-ffi/src/event_log.rs)
# ---------------------------------------------------------------------------

def event_log_query(
    context_id: str,
    filter: dict[str, Any] | None = None,
) -> list[Event]:
    """Query the context event log.

    Args:
        context_id: The ID of the context whose event log to query.
        filter: Optional dict with filter parameters (``event_type``,
            ``actor_did``, ``after_sequence``, ``before_sequence``,
            ``after_timestamp``, ``before_timestamp``, ``limit``).

    Returns:
        A list of ``Event`` objects matching the filter.

    Raises:
        ContextError: If the query fails.
    """
    ...

def event_log_verify(
    context_id: str,
    claim: dict[str, Any],
) -> Proof:
    """Verify a claim against the context event log.

    Generates and verifies a Merkle proof for the given claim. Supports
    both inclusion proofs and absence proofs.

    Args:
        context_id: The ID of the context whose event log to verify against.
        claim: A dict describing the claim (``type``, ``leaf_index``,
            ``event_hash``).

    Returns:
        A ``Proof`` with the verification result, proof type, and details.

    Raises:
        ContextError: If verification fails.
    """
    ...
