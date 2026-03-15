"""UCAN token management for the SCP Python SDK.

Provides Pythonic wrappers around the ``_scp_core`` UCAN bridge functions:

- :func:`validate` -- Validate a UCAN token against a required capability.
- :func:`mint` -- Mint a new UCAN token.
- :func:`revoke` -- Revoke a UCAN token.
- :func:`delegate` -- Create a delegated (attenuated) UCAN from a parent token.

UCAN (User Controlled Authorization Networks) tokens are the capability
enforcement mechanism for SCP.  Every protocol action -- message send, tool
invocation, member management -- requires a valid UCAN token.  This module
exposes UCAN as both an explicit API for advanced use and an implicit
enforcement layer: ``Context.send()``, ``Context.invoke()``, and similar
methods validate capabilities internally before executing.

Validation failures surface as :class:`~scp_sdk.errors.UcanPermissionError`
with descriptive error messages.

See ``.docs/adrs/phase-3.md`` ADR-016 for the full UCAN validation
specification and ADR-013 section 6 for the bridge layer design.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field

from scp_sdk.errors import UcanPermissionError

try:
    import _scp_core  # type: ignore[import-not-found]
except ImportError:
    _scp_core = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# UcanToken wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UcanToken:
    """A UCAN token with metadata.

    Wraps the ``_scp_core.UcanToken`` (``PyUcanToken``) returned by the
    Rust bridge, exposing the same fields as a frozen Python dataclass.

    Attributes:
        token_id: Unique token identifier (derived from the UCAN nonce).
        issuer: Issuer DID -- the entity that created and signed this token.
        audience: Audience DID -- the entity this token is delegated to.
        capabilities: List of capability URIs granted by this token.
        expires_at: Expiry timestamp (seconds since Unix epoch), or ``None``
            if the token does not expire.
        proofs: Proof chain -- CIDs/IDs of parent UCAN tokens forming the
            delegation chain. Empty for root tokens.
    """

    #: Unique token identifier (derived from the UCAN nonce).
    token_id: str

    #: Issuer DID -- the entity that created and signed this token.
    issuer: str

    #: Audience DID -- the entity this token is delegated to.
    audience: str

    #: List of capability URIs granted by this token.
    capabilities: list[str] = field(default_factory=list)

    #: Expiry timestamp (seconds since Unix epoch), or ``None``.
    expires_at: float | None = None

    #: Proof chain -- CIDs/IDs of parent UCAN tokens forming the delegation
    #: chain. Empty for root tokens.
    proofs: list[str] = field(default_factory=list)

    @classmethod
    def _from_bridge(cls, bridge_token: object) -> UcanToken:
        """Construct a :class:`UcanToken` from a ``_scp_core.UcanToken``.

        Args:
            bridge_token: A ``PyUcanToken`` instance returned by the Rust
                bridge layer.

        Returns:
            A new :class:`UcanToken` with fields copied from the bridge
            object.
        """
        return cls(
            token_id=bridge_token.token_id,  # type: ignore[attr-defined]
            issuer=bridge_token.issuer,  # type: ignore[attr-defined]
            audience=bridge_token.audience,  # type: ignore[attr-defined]
            capabilities=list(bridge_token.capabilities),  # type: ignore[attr-defined]
            expires_at=bridge_token.expires_at,  # type: ignore[attr-defined]
            proofs=list(bridge_token.proofs),  # type: ignore[attr-defined]
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def validate(context: str, token: str, capability: str) -> None:
    """Validate a UCAN token against a required capability.

    Performs full UCAN validation: signature verification, time bounds,
    delegation chain traversal, attenuation enforcement, nonce replay
    detection, ceiling compliance, and revocation checking.

    This is the function called implicitly by ``Context.send()``,
    ``Context.invoke()``, and other context methods before executing
    an action.

    Args:
        context: The context ID the token is being presented in.
        token: The encoded UCAN token string (JWT format).
        capability: The required capability URI
            (e.g., ``"scp:ctx:abc123/messages:write"``).

    Raises:
        UcanPermissionError: If validation fails for any reason (malformed
            token, invalid signature, expired, insufficient capabilities,
            revoked, broken delegation chain, etc.).
    """
    try:
        await asyncio.to_thread(_scp_core.ucan_validate, context, token, capability)
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc


async def mint(
    audience: str,
    capabilities: Sequence[str],
    context: str,
    expiry: float | None = None,
    proofs: Sequence[str] | None = None,
) -> UcanToken:
    """Mint a new UCAN token.

    Creates a new UCAN token granting the specified capabilities to the
    audience DID, scoped to the given context.  The token is signed by
    the context creator's key (the issuer is determined automatically by
    the Rust bridge from the context's creator DID).

    Args:
        audience: DID of the entity receiving the token.
        capabilities: Capability URIs to grant
            (e.g., ``["messages:write", "tool_invoke:assistant"]``).
        context: The context ID to scope the token to.
        expiry: Token lifetime in seconds from now, or ``None`` for no
            expiry (not recommended).
        proofs: Optional list of parent UCAN token IDs forming the
            delegation proof chain.  Required when minting a delegated
            token (see :func:`delegate`).

    Returns:
        A :class:`UcanToken` containing the minted token's metadata.

    Raises:
        UcanPermissionError: If minting fails (capabilities outside the
            context ceiling, issuer not authorized, etc.).

    Note:
        The issuer is always the context creator. The Rust bridge
        (``_scp_core.ucan_mint``) derives the issuer from the context's
        ``creator_did`` and does not accept an explicit issuer parameter.
    """
    try:
        bridge_token = await asyncio.to_thread(
            _scp_core.ucan_mint,
            context,
            audience,
            list(capabilities),
            list(proofs) if proofs else None,
        )
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc
    return UcanToken._from_bridge(bridge_token)


async def revoke(context: str, token: str, revoker_did: str) -> None:
    """Revoke a UCAN token using the full revocation pipeline.

    Performs authorization checking (revoker must be the token's issuer or
    the context creator), adds the token to the context's revocation list,
    and appends a ``TokenRevoked`` event to the Merkle event log.

    Args:
        context: The context ID the token belongs to.
        token: The full encoded JWT string of the token to revoke.
        revoker_did: The DID of the entity requesting the revocation.
            Must be the token's issuer or the context creator.

    Raises:
        UcanPermissionError: If revocation fails (unauthorized revoker,
            malformed token, etc.).
    """
    try:
        await asyncio.to_thread(_scp_core.ucan_revoke, context, token, revoker_did)
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc


async def delegate(
    parent_token: UcanToken,
    delegator: str,
    delegatee: str,
    capabilities: Sequence[str],
    context: str,
    *,
    encoded_parent: str,
) -> UcanToken:
    """Create a delegated UCAN from a parent token.

    Delegates to ``_scp_core.ucan_delegate`` which performs real Ed25519
    signing via the delegator's retained ``KeyCustody`` and enforces
    attenuation (capabilities can only narrow, never widen).

    Args:
        parent_token: The parent :class:`UcanToken` to delegate from.
        delegator: DID of the entity delegating (must match
            ``parent_token.audience``).
        delegatee: DID of the entity receiving the delegation.
        capabilities: Capability URIs to grant (must be a subset of the
            parent token's capabilities).
        context: The context ID to scope the delegated token to.
        encoded_parent: The full encoded JWT string of the parent token.
            Required for the Rust bridge to parse and verify the parent's
            signature and delegation chain.

    Returns:
        A new :class:`UcanToken` representing the delegated token.

    Raises:
        UcanPermissionError: If delegation fails -- delegator does not
            match the parent's audience, capabilities exceed the parent's
            capabilities, signing fails, etc.
    """
    try:
        bridge_token = await asyncio.to_thread(
            _scp_core.ucan_delegate,
            context,
            delegator,
            delegatee,
            encoded_parent,
            list(capabilities),
        )
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc
    return UcanToken._from_bridge(bridge_token)


__all__ = [
    "UcanToken",
    "delegate",
    "mint",
    "revoke",
    "validate",
]
