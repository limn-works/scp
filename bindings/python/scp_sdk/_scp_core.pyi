"""Type stubs for the ``_scp_core`` PyO3 extension module.

This file provides Python type annotations for all classes, functions, and
exceptions exposed by the Rust bridge layer (``crates/scp-ffi/src/``). It
enables IDE autocompletion (VS Code, PyCharm) and static analysis via
mypy/pyright.

Generated from the Rust source in ``crates/scp-ffi/src/``. See ADR-013
in ``.docs/adrs/phase-3.md`` for the full bridge specification.
"""

from __future__ import annotations

from asyncio import Future
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

    @property
    def min_protocol_version(self) -> tuple[int, int] | None:
        """Minimum protocol version as ``(major, minor)`` tuple (spec §13.4).

        ``None`` means no minimum set (defaults to SCP/1.0).
        """
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
    def __anext__(self) -> Future[PyMessage | None]: ...

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
    proofs: list[str]

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

class Checkpoint:
    """A signed consistency checkpoint from the event log.

    Contains a snapshot of the event log's Merkle root and event count,
    signed with the generating identity's Ed25519 key. Used for
    equivocation detection.
    """

    context_id: str
    sender_did: str
    event_count: int
    merkle_root: str
    epoch: int | None
    timestamp: int
    signature: str

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

def py_identity_migrate(identity: PyIdentity) -> PyIdentity:
    """Migrate an identity to a new DID (Layer 2 rotation).

    Creates a new DID using the pre-rotation key as the new Identity Key.
    The old DID document is updated with an ``alsoKnownAs`` pointing to the
    new DID. Both documents are published. The old identity registry entry
    is replaced with the new one.

    Args:
        identity: The ``PyIdentity`` to migrate.

    Returns:
        A new ``PyIdentity`` with the new DID string.

    Raises:
        IdentityError: If the identity is not in the registry, if key
            generation fails, or if DHT publishing fails.
    """
    ...

def py_init_storage(storage_type: str) -> None:
    """Initialize the global storage provider for identity persistence.

    Must be called before ``py_identity_create`` or ``py_identity_load``
    if storage persistence is desired.

    Args:
        storage_type: The storage backend type (``"in_memory"``).

    Raises:
        ValidationError: If the storage type is not recognized.
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
            ``description``, ``schema``, ``test_vectors``, ``operator_did``,
            and optional ``cost`` dict with ``amount`` (int), ``currency``
            (str), ``payee`` (str DID), and optional ``cost_formula`` (str)).

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
    ucan_token: str,
    proof_tokens: list[str] | None = None,
) -> Any:
    """Invoke a tool within an SCP context.

    Validates the UCAN token for tool invocation authorization before
    dispatching. The UCAN must contain a ``tool_invoke:{tool_id}`` or
    ``tool_invoke:*`` capability scoped to the context.

    Args:
        context_id: The ID of the context containing the tool.
        tool_id: The ID of the tool to invoke.
        input: A dict of input parameters matching the tool's input schema.
        identity_did: The DID of the invoking identity.
        ucan_token: JWT-encoded UCAN token authorizing the invocation.
            Must contain ``tool_invoke:{tool_id}`` or ``tool_invoke:*``
            capability.
        proof_tokens: Optional list of encoded parent UCAN token strings
            for delegation chain verification.

    Returns:
        A dict containing the tool's JSON-compatible output.

    Raises:
        UcanError: If the UCAN token is invalid, expired, revoked, or
            lacks the required tool invocation capability.
        ContextError: If the context is not connected, the tool is not
            found, or input/output validation fails.
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

def tool_invoke_cross_context(
    source_context_id: str,
    target_context_id: str,
    tool_id: str,
    input: dict[str, Any],
    invoker_did: str,
    ucan_token: str,
    chain_depth: int,
    proof_tokens: list[str] | None = None,
) -> Any:
    """Invoke a tool across context boundaries.

    The source context initiates the call and the target context contains
    the tool. Both contexts must have approved the interface before calls
    are permitted. Rate limits and chain depth are enforced per spec
    section 6.2.

    Args:
        source_context_id: The ID of the calling context.
        target_context_id: The ID of the context containing the tool.
        tool_id: The ID of the tool to invoke.
        input: A dict of input parameters matching the tool's input schema.
        invoker_did: The DID of the participant invoking the tool.
        ucan_token: JWT-encoded UCAN token authorizing the invocation.
            Must contain ``tool_invoke:{tool_id}`` or ``tool_invoke:*``
            capability. Validated against the target context's ceiling.
        chain_depth: Current cross-context chain depth (0 for first hop).
        proof_tokens: Optional list of encoded parent UCAN token strings
            for delegation chain verification.

    Returns:
        A dict containing the tool's JSON-compatible output.

    Raises:
        UcanError: If the UCAN token is invalid, expired, revoked, or
            lacks the required tool invocation capability.
        ContextError: If either context is not connected, the tool is not
            found, chain depth is exceeded, or the interface is not
            approved.
    """
    ...

def tool_session_create(
    context_id: str,
    tool_id: str,
    source_context_id: str,
    ttl_seconds: int | None = None,
) -> str:
    """Create a stateful tool session.

    Sessions enable multi-turn workflows with state preservation across
    invocations. Each session is subject to per-caller caps (default: 5
    concurrent sessions per caller, per spec section 6.2.1).

    Sessions without a TTL persist for the lifetime of the context
    (spec section 6.2.1).

    Args:
        context_id: The context containing the tool.
        tool_id: The tool to create a session for.
        source_context_id: The calling context (session cap tracked per
            caller).
        ttl_seconds: Optional time-to-live for the session, in seconds.
            ``None`` means the session persists for the lifetime of the
            context.

    Returns:
        The session ID (UUID string).

    Raises:
        ContextError: If the context is not connected, the tool is not
            found, or the per-caller session cap is exceeded.
    """
    ...

def tool_session_invoke(
    context_id: str,
    session_id: str,
    input: dict[str, Any],
    invoker_did: str,
    ucan_token: str,
    proof_tokens: list[str] | None = None,
) -> Any:
    """Invoke a tool within an active session.

    Each call is individually governed: the invoker must hold ``ToolInvoke``
    capability and present a valid UCAN token. Session state is carried
    forward across invocations.

    Args:
        context_id: The context containing the tool session.
        session_id: The session to invoke within.
        input: A dict of input parameters matching the tool's input schema.
        invoker_did: The DID of the invoker (capability checked per call).
        ucan_token: JWT-encoded UCAN token authorizing the invocation.
            Must contain ``tool_invoke:{tool_id}`` or ``tool_invoke:*``
            capability.
        proof_tokens: Optional list of encoded parent UCAN token strings
            for delegation chain verification.

    Returns:
        A dict containing the tool's JSON-compatible output.

    Raises:
        UcanError: If the UCAN token is invalid, expired, revoked, or
            lacks the required tool invocation capability.
        ContextError: If the session is not found, has expired, or the
            invoker lacks capability.
    """
    ...

def tool_session_close(context_id: str, session_id: str) -> None:
    """Close a stateful tool session.

    Removes the session from the store, releasing the caller's session
    slot. After closing, any further invocations with this session ID
    will fail.

    Args:
        context_id: The context containing the tool session.
        session_id: The session to close.

    Raises:
        ContextError: If the context is not connected or the session is
            not found.
    """
    ...

# ---------------------------------------------------------------------------
# Bidirectional consent protocol (crates/scp-ffi/src/tools.rs, §6.2.0.1)
# ---------------------------------------------------------------------------

def tool_interface_expose(
    context_id: str,
    tool_id: str,
    target_context_id: str,
    rate_limit_json: str | None = None,
) -> str:
    """Expose a tool interface for cross-context sharing (step 1).

    Args:
        context_id: The source context ID.
        tool_id: The ID of the tool to expose.
        target_context_id: The target context to expose the tool to.
        rate_limit_json: Optional per-interface rate limit as JSON.

    Returns:
        The ToolInterface as a JSON string.

    Raises:
        ToolError: If the caller is not an admin or the tool is not found.
        ValidationError: If rate_limit_json is malformed.
    """
    ...

def tool_interface_accept(
    context_id: str,
    interface_json: str,
) -> str:
    """Accept a cross-context tool interface (step 4).

    Args:
        context_id: The target context ID.
        interface_json: The ToolInterface JSON string to accept.

    Returns:
        The updated ToolInterface JSON string.

    Raises:
        ToolError: If the caller is not an admin or context mismatch.
        ValidationError: If interface_json is malformed.
    """
    ...

def tool_interface_revoke(
    context_id: str,
    interface_id_hex: str,
) -> str:
    """Revoke a cross-context tool interface (step 5).

    Args:
        context_id: The revoking context ID.
        interface_id_hex: The 32-byte interface/offer ID as hex.

    Returns:
        The InterfaceRevoked event as a JSON string.

    Raises:
        ValidationError: If interface_id_hex is invalid.
    """
    ...

# ---------------------------------------------------------------------------
# Transport bridge functions (crates/scp-ffi/src/transport.rs)
# ---------------------------------------------------------------------------

def transport_connect(relay_url: str, source: str = "explicit") -> None:
    """Connect to an SCP relay with provenance-based transport security
    validation (section 10.12.6).

    The ``source`` parameter specifies how the relay URL was discovered,
    which determines whether ``ws://`` (plaintext) is permitted:

    - ``"dht_resolved"`` -- resolved from a BEP44-signed DID document.
      ``ws://`` is permitted.
    - ``"well_known"`` -- discovered via ``.well-known/scp``. ``wss://`` only.
    - ``"explicit"`` (default) -- user/operator configured. ``wss://`` only.
    - ``"peer_discovered"`` -- discovered from a peer. ``wss://`` only.

    Args:
        relay_url: The URL of the SCP relay (e.g., ``"wss://relay.example.com"``).
        source: How the URL was discovered (default: ``"explicit"``).

    Raises:
        TransportError: If the URL scheme is not permitted for the given
            source or the connection fails.
    """
    ...

def transport_disconnect() -> None:
    """Disconnect from the current SCP relay.

    Clears the global relay connection state. After this call,
    ``py_mcp_load_contexts`` will fall back to local-only context discovery.

    This is a no-op if no relay connection is active.

    Raises:
        TransportError: If clearing the connection state fails.
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

def ucan_validate(
    context_id: str,
    token: str,
    capability: str,
    presenting_agent_did: str | None = None,
    proof_tokens: list[str] | None = None,
) -> None:
    """Validate a UCAN token for a required capability.

    Performs the full 11-step ADR-016 UCAN validation pipeline: signature
    verification, time bounds checking, delegation chain traversal,
    attenuation enforcement, nonce replay detection, and capability matching.

    Args:
        context_id: The ID of the context the token is presented in.
        token: The encoded UCAN token string (JWT format).
        capability: The required capability URI.
        presenting_agent_did: Optional DID of the agent presenting the token.
            If not provided, the token's ``aud`` field is used.
        proof_tokens: Optional list of encoded parent UCAN token strings for
            delegation chain verification. Required when validating delegated
            tokens with non-empty proof chains.

    Raises:
        UcanError: If validation fails for any reason.
    """
    ...

def ucan_mint(
    context_id: str,
    member_did: str,
    capabilities: list[str],
    proofs: list[str] | None = None,
) -> UcanToken:
    """Mint a new UCAN token for a context member.

    Args:
        context_id: The ID of the context to mint the token for.
        member_did: The DID of the member receiving the token.
        capabilities: List of capability URIs to grant.
        proofs: Optional list of parent UCAN token IDs forming the
            delegation proof chain.

    Returns:
        A ``UcanToken`` with the minted token's metadata.

    Raises:
        UcanError: If minting fails.
    """
    ...

def ucan_delegate(
    context_id: str,
    delegator_did: str,
    delegatee_did: str,
    parent_token: str,
    capabilities: list[str],
) -> UcanToken:
    """Delegate a UCAN token to another member.

    Creates a delegated UCAN from an existing parent token, signed with the
    delegator's Ed25519 key. Delegation enforces attenuation (capabilities
    can only narrow, never widen).

    Args:
        context_id: The ID of the context.
        delegator_did: The DID of the entity delegating (must match parent
            token's audience).
        delegatee_did: The DID of the entity receiving the delegation.
        parent_token: The encoded parent UCAN token (JWT format).
        capabilities: List of capability URI strings to delegate (must be
            subset of parent's capabilities).

    Returns:
        A ``UcanToken`` with the delegated token's metadata.

    Raises:
        UcanError: If delegation fails (delegator not matching parent
            audience, capabilities wider than parent, signing failure).
    """
    ...

def ucan_revoke(context_id: str, token: str, revoker_did: str) -> None:
    """Revoke a UCAN token using the full revocation pipeline.

    Performs authorization (revoker must be token issuer or context creator),
    adds the token to the context's revocation list, and appends a
    TokenRevoked event to the Merkle event log.

    Args:
        context_id: The ID of the context the token belongs to.
        token: The full encoded UCAN token string (JWT format).
        revoker_did: The DID of the entity requesting the revocation.
            Must be the token's issuer or the context creator.

    Raises:
        UcanError: If revocation fails (unauthorized, malformed token, etc.).
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

def event_log_checkpoint(
    context_id: str,
    identity_did: str,
    epoch: int,
) -> Checkpoint:
    """Generate a signed consistency checkpoint from the current event log.

    Creates a snapshot of the event log's Merkle root and event count,
    signs it with the caller's identity key. Checkpoints enable
    equivocation detection.

    Args:
        context_id: The ID of the context whose event log to checkpoint.
        identity_did: The DID of the identity generating the checkpoint
            (used for signing).
        epoch: The current MLS epoch (pass ``0`` for Broadcast contexts).

    Returns:
        A ``Checkpoint`` containing the signed checkpoint data.

    Raises:
        ContextError: If the context is not found or signing fails.
        IdentityError: If the identity is not found.
    """
    ...

# ---------------------------------------------------------------------------
# MCP bridge functions (crates/scp-ffi/src/mcp.rs)
# ---------------------------------------------------------------------------

def py_mcp_serve(
    identity_did: str,
    context_ids: list[str],
    transport: str,
    ucan_token: str | None = None,
) -> str:
    """Start an MCP server exposing SCP contexts.

    Creates and starts an MCP server that exposes the specified SCP
    contexts over the given transport (``"stdio"`` or ``"sse"``).

    Args:
        identity_did: The DID of the serving identity.
        context_ids: List of context IDs to expose via MCP.
        transport: Transport mode -- ``"stdio"`` or ``"sse"``.
        ucan_token: Optional UCAN token (JWT) authorizing the server
            to act on behalf of the identity. Passed through to the
            MCP server provider for tool invocation authorization.

    Returns:
        An opaque server handle string.

    Raises:
        ValidationError: If the transport mode is invalid.
        TransportError: If a referenced context is not registered.
    """
    ...

def py_mcp_server_stop(handle: str) -> None:
    """Stop a running MCP server.

    Sends the shutdown signal to the server identified by the handle.

    Args:
        handle: The server handle returned by ``py_mcp_serve``.

    Raises:
        TransportError: If the server is not found or already stopped.
    """
    ...

def py_mcp_server_wait(handle: str) -> None:
    """Block until an MCP server exits.

    Waits for the server's transport task to complete. Returns immediately
    if the server has already stopped.

    Args:
        handle: The server handle returned by ``py_mcp_serve``.

    Raises:
        TransportError: If the server handle is not found.
    """
    ...

def py_mcp_server_info(handle: str) -> dict[str, Any]:
    """Return metadata about a running MCP server.

    Args:
        handle: The server handle returned by ``py_mcp_serve``.

    Returns:
        A dict with keys: ``identity_did``, ``context_ids``,
        ``transport``, ``stopped``.

    Raises:
        TransportError: If the server handle is not found.
    """
    ...

def py_mcp_client_connect_stdio(command: list[str]) -> str:
    """Connect to an external MCP server via stdio transport.

    Spawns the given command as a subprocess and communicates via
    line-delimited JSON over stdin/stdout. Performs the MCP initialize
    handshake before returning.

    Args:
        command: The command and arguments to spawn (e.g.,
            ``["uvx", "some-mcp-server"]``).

    Returns:
        An opaque client handle string.

    Raises:
        ValidationError: If the command list is empty.
        TransportError: If the subprocess fails to start or the MCP
            initialize handshake fails.
    """
    ...

def py_mcp_client_connect_sse(url: str) -> str:
    """Connect to an external MCP server via SSE transport.

    Establishes an HTTP SSE connection to the given URL and performs
    the MCP initialize handshake before returning.

    Args:
        url: The SSE endpoint URL of the MCP server.

    Returns:
        An opaque client handle string.

    Raises:
        ValidationError: If the URL is empty.
        TransportError: If the connection or MCP handshake fails.
    """
    ...

def py_mcp_client_disconnect(handle: str) -> None:
    """Disconnect from an external MCP server.

    Removes the client from the registry and drops the transport
    connection. For stdio clients, the subprocess is killed.

    Args:
        handle: The client handle returned by ``py_mcp_client_connect_*``.

    Raises:
        TransportError: If the client handle is not found.
    """
    ...

def py_mcp_client_info(handle: str) -> dict[str, Any]:
    """Return metadata about an active MCP client connection.

    Args:
        handle: The client handle returned by ``py_mcp_client_connect_*``.

    Returns:
        A dict with keys: ``transport``, ``command`` (nullable),
        ``url`` (nullable).

    Raises:
        TransportError: If the client handle is not found.
    """
    ...

def py_mcp_client_list_tools(handle: str) -> Any:
    """List tools available on an external MCP server.

    Sends a ``tools/list`` JSON-RPC request to the connected server.

    Args:
        handle: The client handle returned by ``py_mcp_client_connect_*``.

    Returns:
        A list of tool definition dicts, each with ``name``,
        ``description``, and ``inputSchema`` keys.

    Raises:
        TransportError: If the client is not connected or the request fails.
    """
    ...

def py_mcp_client_invoke(
    handle: str,
    tool_name: str,
    input: dict[str, Any],
    context_id: str,
    identity_did: str,
) -> Any:
    """Invoke an external MCP tool with SCP provenance wrapping.

    Sends a ``tools/call`` JSON-RPC request to the external MCP server
    and wraps the result with provenance metadata.

    Args:
        handle: The client handle returned by ``py_mcp_client_connect_*``.
        tool_name: The name of the external tool to invoke.
        input: A dict of input parameters.
        context_id: The SCP context ID for provenance tracking.
        identity_did: The DID of the invoking identity.

    Returns:
        A dict with ``content``, ``is_error``, and ``provenance`` keys.

    Raises:
        TransportError: If the client is not connected or invocation fails.
    """
    ...

def py_mcp_load_contexts(
    identity_did: str,
    relay_url: str,
) -> list[Any]:
    """Load active contexts for a DID from local registry and relay.

    Combines local runtime contexts, known-contexts registry, and relay
    discovery. Results are deduplicated by context ID.

    Args:
        identity_did: The DID to look up contexts for.
        relay_url: The relay URL to query (hint; active transport connection
            is preferred if available).

    Returns:
        A list of context dicts, each with ``context_id``, ``source``,
        ``creator_did``, ``member_count``, ``tool_count``, and
        ``relay_active`` keys.

    Raises:
        TransportError: If the relay query fails fatally.
    """
    ...

def py_mcp_configure_stdio_allowlist(
    additional_binaries: list[str] = ...,
) -> None:
    """Configure the stdio subprocess allowlist.

    Sets up the allowlist with default safe binaries plus any additional
    ones provided.

    Args:
        additional_binaries: Binary basenames to add to the default
            allowlist.

    Raises:
        ValidationError: If any entry is invalid (path, NUL, empty).
        TransportError: If the allowlist lock is poisoned.
    """
    ...

def py_mcp_disable_stdio_allowlist() -> None:
    """Disable the stdio allowlist entirely (unrestricted mode).

    Allows any binary to be spawned as a subprocess. Only use when the
    command source is fully trusted.

    Raises:
        TransportError: If the allowlist lock is poisoned.
    """
    ...

def py_mcp_reset_stdio_allowlist() -> None:
    """Reset the stdio allowlist to its default state.

    Restores the default binaries and re-enables allowlist enforcement.

    Raises:
        TransportError: If the allowlist lock is poisoned.
    """
    ...

def py_mcp_get_stdio_allowlist() -> dict[str, Any]:
    """Return the current stdio allowlist state.

    Returns:
        A dict with ``allowed`` (sorted list of binary names) and
        ``unrestricted`` (bool) keys.

    Raises:
        TransportError: If the allowlist lock is poisoned.
    """
    ...

def mcp_register_tool_handler(
    context_id: str,
    tool_name: str,
    handler: Any,
) -> None:
    """Register a Python callable as the handler for a tool in a context.

    The handler is called when the tool is invoked via MCP. It receives
    the tool's validated JSON input as a Python dict and must return a
    Python dict representing the JSON output.

    The tool must already be registered in the context's tool registry
    (via ``tool_register``) before a handler can be attached.

    Args:
        context_id: The context containing the tool.
        tool_name: The tool ID to attach the handler to.
        handler: A Python callable ``(dict) -> dict``.

    Raises:
        ValidationError: If the handler is not callable.
        ContextError: If the context or tool is not found.
    """
    ...

# Bridge connector bridge functions (crates/scp-ffi/src/bridge_connector.rs)

def bridge_register(
    context_id: str,
    operator_did: str,
    governance_did: str,
    platform: str,
    mode: str,
) -> dict[str, str]:
    """Register a bridge connector with a context.

    Creates a registration request and immediately approves it using the
    provided governance DID.

    Args:
        context_id: Context to register the bridge in.
        operator_did: DID of the human operator accountable for the bridge.
        governance_did: DID of the governance authority approving the
            registration.  Must differ from ``operator_did`` (self-approval
            is forbidden per ADR-023).
        platform: External platform name (e.g., ``"discord"``).
        mode: Bridge mode: ``"relay"``, ``"puppet"``, ``"api"``, or
            ``"cooperative"``.

    Returns:
        A dict with ``bridge_id``, ``operator_did``, ``platform``,
        ``mode``, ``status``, ``context_id``.

    Raises:
        ValidationError: If *mode* is not recognized.
        ContextError: If registration or approval fails (including
            self-approval).
    """
    ...

def bridge_evaluate_trust(
    is_bridged: bool = False,
    is_native_transport: bool = True,
    shadow_status: str = "shadow",
) -> int:
    """Evaluate the trust level for an action based on bridge provenance.

    Returns an integer (0--3) representing the trust tier.

    Args:
        is_bridged: Whether the action has bridge provenance.
        is_native_transport: Whether the transport is native SCP.
        shadow_status: ``"shadow"`` or ``"claimed"``.

    Returns:
        Trust tier as an integer (0--3).

    Raises:
        ValidationError: If *shadow_status* is invalid.
    """
    ...

def bridge_create_shadow(
    bridge_id: str,
    platform_handle: str,
    bridge_mode: str,
    context_id: str = "ctx-shadow",
) -> dict[str, str]:
    """Create a shadow identity for an external platform participant.

    Args:
        bridge_id: The bridge connector ID that owns this shadow.
        platform_handle: External platform handle (e.g., ``"@user#1234"``).
        bridge_mode: Bridge mode: ``"relay"``, ``"puppet"``, ``"api"``, or
            ``"cooperative"``.
        context_id: Context the shadow is being created in.

    Returns:
        A dict with ``shadow_id``, ``platform_handle``, ``bridge_id``,
        ``attributed_role``, ``provenance_status``.

    Raises:
        ValidationError: If *bridge_mode* is invalid.
        ContextError: If shadow creation fails.
    """
    ...

# ---------------------------------------------------------------------------
# Media — session lifecycle and signaling (#597)
# ---------------------------------------------------------------------------

def media_check_capability(ceiling: list[str], capability: str) -> bool:
    """Check that a media capability is present in the context ceiling.

    Args:
        ceiling: List of capability name strings from the context ceiling.
        capability: Media capability: ``"voice"``, ``"video"``, or
            ``"screen_share"``.

    Returns:
        ``True`` if the capability is in the ceiling.

    Raises:
        ValidationError: If *capability* is invalid.
        ContextError: If the capability is not in the ceiling.
    """
    ...

def media_initiate_session(
    context_id: str,
    ceiling: list[str],
    capabilities: list[str],
    participants: list[str],
    timestamp: int,
) -> dict[str, Any]:
    """Initiate a media session after validating capabilities against the ceiling.

    Args:
        context_id: The context hosting this media session.
        ceiling: The context's capability ceiling as capability name strings.
        capabilities: Media capabilities to activate.
        participants: Initial participant DIDs.
        timestamp: Unix timestamp (seconds) for session creation.

    Returns:
        A dict with session fields.

    Raises:
        ValidationError: If any capability string is invalid.
        ContextError: If capabilities/participants are empty or capability
            missing from ceiling.
    """
    ...

def media_activate_session(session_json: str) -> dict[str, Any]:
    """Activate a media session (transition from Initiating to Active).

    Args:
        session_json: JSON string representing the session.

    Returns:
        A dict with the updated session fields.

    Raises:
        ContextError: If the session is not in the Initiating state.
    """
    ...

def media_join_session(session_json: str, participant_did: str) -> dict[str, Any]:
    """Add a participant to a media session.

    Args:
        session_json: JSON string representing the session.
        participant_did: DID of the participant to add.

    Returns:
        A dict with the updated session fields.

    Raises:
        ContextError: If the session has ended.
    """
    ...

def media_end_session(session_json: str, timestamp: int) -> dict[str, Any]:
    """End a media session and return metadata for event log recording.

    Args:
        session_json: JSON string representing the session.
        timestamp: Unix timestamp (seconds) when the session ended.

    Returns:
        A dict with ``session`` and ``metadata`` keys.

    Raises:
        ContextError: If the session has already ended.
    """
    ...

def media_create_offer(session_id: str, sdp: str, sender_did: str) -> dict[str, str]:
    """Create an SDP offer signaling message.

    Args:
        session_id: The media session ID.
        sdp: Raw SDP payload string.
        sender_did: DID of the participant creating the offer.

    Returns:
        A dict with ``session_id`` and ``message`` keys.
    """
    ...

def media_create_answer(session_id: str, sdp: str, sender_did: str) -> dict[str, str]:
    """Create an SDP answer signaling message.

    Args:
        session_id: The media session ID.
        sdp: Raw SDP payload string.
        sender_did: DID of the participant creating the answer.

    Returns:
        A dict with ``session_id`` and ``message`` keys.
    """
    ...

def media_create_ice_candidate(
    session_id: str,
    candidate: str,
    sender_did: str,
    sdp_mid: str | None = None,
    sdp_mline_index: int | None = None,
) -> dict[str, str]:
    """Create an ICE candidate signaling message.

    Args:
        session_id: The media session ID.
        candidate: ICE candidate attribute string.
        sender_did: DID of the participant who gathered the candidate.
        sdp_mid: Optional SDP media stream identification tag.
        sdp_mline_index: Optional zero-based media description index.

    Returns:
        A dict with ``session_id`` and ``message`` keys.
    """
    ...

def media_create_session_end(session_id: str, sender_did: str) -> dict[str, str]:
    """Create a session-end signaling message.

    Args:
        session_id: The media session ID.
        sender_did: DID of the participant ending the session.

    Returns:
        A dict with ``session_id`` and ``message`` keys.
    """
    ...

def media_send_signaling(signaling_json: str) -> dict[str, str]:
    """Serialize a signaling message for transport.

    Args:
        signaling_json: JSON string representing a signaling message.

    Returns:
        A dict with ``payload`` (base64) and ``message_type`` keys.

    Raises:
        ValidationError: If the JSON is not a valid signaling message.
    """
    ...

def media_verify_sender_attribution(
    signaling_json: str,
    envelope_sender_did: str,
) -> bool:
    """Verify that the sender DID in a signaling message matches the envelope.

    Args:
        signaling_json: JSON string representing a signaling message.
        envelope_sender_did: The DID from the authenticated SCP envelope.

    Returns:
        ``True`` if the sender attribution is valid.

    Raises:
        ValidationError: If the JSON is invalid.
        ContextError: If the sender DID does not match.
    """
    ...

# ---------------------------------------------------------------------------
# Discovery bridge functions (crates/scp-ffi/src/discovery.rs)
# ---------------------------------------------------------------------------

def discovery_parse_address(address: str) -> str:
    """Parse an SCP address string into its components.

    Returns a JSON string with the parsed address type and fields.

    Args:
        address: The address string to parse.

    Returns:
        JSON string with parsed address components.

    Raises:
        ValidationError: If the address is malformed.
    """
    ...

def discovery_create_query(
    capabilities: list[str] | None = None,
    keywords: list[str] | None = None,
    min_history_secs: int | None = None,
) -> str:
    """Create a discovery query as a JSON string.

    Args:
        capabilities: Optional list of required capabilities.
        keywords: Optional list of search keywords.
        min_history_secs: Optional minimum history age in seconds.

    Returns:
        JSON-encoded discovery query.
    """
    ...

def discovery_normalize_address(address: str) -> str:
    """Normalize an address string per SCP addressing rules.

    Lowercases and trims whitespace.

    Args:
        address: The address string to normalize.

    Returns:
        Normalized address string.
    """
    ...

def context_discover(query: str) -> str:
    """Discover contexts from a DID string or ``scp://`` URI.

    Args:
        query: A DID string or ``scp://`` URI.

    Returns:
        JSON string with an array of discovery results.

    Raises:
        ValidationError: If DID resolution or URI parsing fails.
    """
    ...

# -- Petname operations (section 22.4) --

def petname_set(owner_did: str, target_did: str, name: str) -> None:
    """Set a petname for a DID.

    Args:
        owner_did: DID of the identity owning this petname map.
        target_did: DID to assign the petname to.
        name: The petname string.

    Raises:
        ValidationError: If owner_did or target_did is empty.
    """
    ...

def petname_remove(owner_did: str, target_did: str) -> None:
    """Remove a petname from a DID.

    Args:
        owner_did: DID of the identity owning this petname map.
        target_did: DID to remove the petname from.

    Raises:
        ValidationError: If owner_did or target_did is empty.
    """
    ...

def petname_set_context(owner_did: str, context_id: str, name: str) -> None:
    """Set a petname for a context.

    Args:
        owner_did: DID of the identity owning this petname map.
        context_id: Context ID to assign the petname to.
        name: The petname string.

    Raises:
        ValidationError: If owner_did or context_id is empty.
    """
    ...

def petname_remove_context(owner_did: str, context_id: str) -> None:
    """Remove a petname from a context.

    Args:
        owner_did: DID of the identity owning this petname map.
        context_id: Context ID to remove the petname from.

    Raises:
        ValidationError: If owner_did or context_id is empty.
    """
    ...

def petname_resolve_did(owner_did: str, name: str) -> list[str]:
    """Resolve a petname to DIDs.

    Args:
        owner_did: DID of the identity owning this petname map.
        name: The petname to resolve.

    Returns:
        List of DID strings associated with the petname.

    Raises:
        ValidationError: If owner_did is empty.
    """
    ...

def petname_resolve_context(owner_did: str, name: str) -> list[str]:
    """Resolve a petname to context IDs.

    Args:
        owner_did: DID of the identity owning this petname map.
        name: The petname to resolve.

    Returns:
        List of context ID strings associated with the petname.

    Raises:
        ValidationError: If owner_did is empty.
    """
    ...

def petname_get_for_did(owner_did: str, target_did: str) -> str | None:
    """Get the petname assigned to a DID, if any.

    Args:
        owner_did: DID of the identity owning this petname map.
        target_did: DID to look up.

    Returns:
        The petname string, or ``None`` if no petname is assigned.

    Raises:
        ValidationError: If owner_did or target_did is empty.
    """
    ...

def petname_get_for_context(owner_did: str, context_id: str) -> str | None:
    """Get the petname assigned to a context, if any.

    Args:
        owner_did: DID of the identity owning this petname map.
        context_id: Context ID to look up.

    Returns:
        The petname string, or ``None`` if no petname is assigned.

    Raises:
        ValidationError: If owner_did or context_id is empty.
    """
    ...

# -- Handle registry operations (section 22.3.1) --

def handle_register(
    discovery_context_id: str,
    handle: str,
    target_json: str,
    registrant_did: str,
    description: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Register a handle in a discovery context.

    Args:
        discovery_context_id: ID of the discovery context.
        handle: The handle string to register.
        target_json: JSON describing the target (identity or context).
        registrant_did: DID of the registrant.
        description: Optional human-readable description.
        tags: Optional list of tag strings.

    Returns:
        JSON string with the registration result.

    Raises:
        ValidationError: If required fields are empty or target_json is invalid.
    """
    ...

def handle_lookup(
    discovery_context_id: str,
    handle: str,
    type_filter: str | None = None,
) -> str:
    """Look up a handle in a discovery context.

    Args:
        discovery_context_id: ID of the discovery context.
        handle: The handle string to look up.
        type_filter: Optional filter: ``"identity"`` or ``"context"``.

    Returns:
        JSON string with a results array of matching entries.

    Raises:
        ValidationError: If type_filter is not a recognized value.
    """
    ...

def handle_deregister(
    discovery_context_id: str,
    handle: str,
    did: str,
) -> str:
    """Deregister a handle from a discovery context.

    Args:
        discovery_context_id: ID of the discovery context.
        handle: The handle string to deregister.
        did: DID of the registrant requesting deregistration.

    Returns:
        JSON string with a ``removed`` boolean.

    Raises:
        ValidationError: If required fields are empty.
    """
    ...

# -- Address resolution (section 22.8) --

def address_resolve(
    owner_did: str,
    address: str,
    known_contexts_json: str | None = None,
) -> str:
    """Resolve a human-readable address via multi-path resolution.

    Args:
        owner_did: DID of the identity whose petname map to consult.
        address: The address string to resolve.
        known_contexts_json: Optional JSON object mapping context IDs
            to scope names.

    Returns:
        JSON string with an array of ``AddressResolution`` objects.

    Raises:
        ValidationError: If owner_did is empty or known_contexts_json
            is malformed.
    """
    ...
