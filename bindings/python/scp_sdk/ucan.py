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
from dataclasses import dataclass, field
from typing import Sequence

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
    issuer: str,
    audience: str,
    capabilities: Sequence[str],
    context: str,
    expiry: float | None = None,
) -> UcanToken:
    """Mint a new UCAN token.

    Creates a new UCAN token granting the specified capabilities to the
    audience DID, scoped to the given context.  The token is signed by
    the issuer's key.

    Args:
        issuer: DID of the entity minting (signing) the token.
        audience: DID of the entity receiving the token.
        capabilities: Capability URIs to grant
            (e.g., ``["messages:write", "tool_invoke:assistant"]``).
        context: The context ID to scope the token to.
        expiry: Token lifetime in seconds from now, or ``None`` for no
            expiry (not recommended).

    Returns:
        A :class:`UcanToken` containing the minted token's metadata.

    Raises:
        UcanPermissionError: If minting fails (capabilities outside the
            context ceiling, issuer not authorized, etc.).
    """
    try:
        bridge_token = await asyncio.to_thread(
            _scp_core.ucan_mint, context, audience, list(capabilities)
        )
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc
    return UcanToken._from_bridge(bridge_token)


async def revoke(context: str, token: str) -> None:
    """Revoke a UCAN token.

    Adds the token to the context's revocation list.  Revoked tokens are
    immediately rejected by subsequent :func:`validate` calls.  The
    revocation is distributed to all context members via MLS.

    Args:
        context: The context ID the token belongs to.
        token: The unique token ID (or CID) to revoke.

    Raises:
        UcanPermissionError: If revocation fails (token not found, revoker
            not authorized, etc.).
    """
    try:
        await asyncio.to_thread(_scp_core.ucan_revoke, context, token)
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc


async def delegate(
    parent_token: UcanToken,
    delegator: str,
    delegatee: str,
    capabilities: Sequence[str],
) -> UcanToken:
    """Create a delegated UCAN from a parent token.

    Verifies that the delegator matches the parent token's audience and
    that the requested capabilities are a subset of the parent's
    capabilities (attenuation -- never widening).  Mints a new token
    with the parent as proof.

    Args:
        parent_token: The parent :class:`UcanToken` to delegate from.
        delegator: DID of the entity delegating (must match
            ``parent_token.audience``).
        delegatee: DID of the entity receiving the delegation.
        capabilities: Capability URIs to grant (must be a subset of the
            parent token's capabilities).

    Returns:
        A new :class:`UcanToken` representing the delegated token.

    Raises:
        UcanPermissionError: If delegation fails -- delegator does not
            match the parent's audience, capabilities exceed the parent's
            capabilities, etc.
    """
    # Verify delegator matches the parent token's audience.
    if delegator != parent_token.audience:
        raise UcanPermissionError(
            f"Delegator DID {delegator!r} does not match parent token "
            f"audience {parent_token.audience!r}",
            code="SCP-PERM-3001",
        )

    # Verify attenuation: requested capabilities must be a subset of the
    # parent's capabilities (never widening).
    parent_caps = set(parent_token.capabilities)
    requested_caps = set(capabilities)
    excess = requested_caps - parent_caps
    if excess:
        raise UcanPermissionError(
            f"Cannot delegate capabilities not present in parent token: "
            f"{sorted(excess)}",
            code="SCP-PERM-3002",
        )

    # Delegate by minting a new token from the delegator to the delegatee
    # with the attenuated capabilities.  The bridge layer handles proof
    # chain construction and signing.
    return await mint(
        issuer=delegator,
        audience=delegatee,
        capabilities=list(capabilities),
        context=parent_token.token_id,
    )


__all__ = [
    "UcanToken",
    "delegate",
    "mint",
    "revoke",
    "validate",
]
