"""UCAN token management for the SCP Python SDK.

Provides Pythonic wrappers around the ``_scp_core`` UCAN bridge functions:

- :func:`validate` -- Validate a UCAN token against a required capability.
- :func:`mint` -- Mint a new UCAN token (optionally with §7.3.8 caveats).
- :func:`revoke` -- Revoke a UCAN token.
- :func:`delegate` -- Create a delegated (attenuated) UCAN from a parent token.
- :func:`narrow` -- Narrow a parent UCAN by attaching attenuated caveats
  (SCP-OUT-023, §7.3.8).

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
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scp_sdk._deprecation import deprecated_default_instance
from scp_sdk.errors import UcanPermissionError

if TYPE_CHECKING:
    from scp_sdk.outlets import InvocationCaveats

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

    #: Full encoded JWT string (SCP-OUT-023). Exposed so callers can decode
    #: the payload's ``nb`` field for caveat round-trip conformance.
    encoded: str = ""

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
            encoded=getattr(bridge_token, "encoded", ""),
        )


# ---------------------------------------------------------------------------
# Caveat marshalling — SDK snake_case <-> wire camelCase (§7.3.8).
# ---------------------------------------------------------------------------


# Mapping from SDK snake_case field to wire camelCase key (§7.3.8 vocabulary).
# Kept in lockstep with `bindings/python/scp_sdk/outlets.py::InvocationCaveats`
# and the Rust `scp_protocol::trust::caveats::InvocationCaveats` serde rename
# attributes.
_CAVEAT_WIRE_KEYS: dict[str, str] = {
    "amount_max_per_call": "amountMaxPerCall",
    "amount_max_cumulative": "amountMaxCumulative",
    "valid_from": "validFrom",
    "valid_until": "validUntil",
    "hours_of_day": "hoursOfDay",
    "days_of_week": "daysOfWeek",
    "max_calls": "maxCalls",
    "rate_window": "rateWindow",
    "input_schema": "inputSchema",
    "allowed_adapters": "allowedAdapters",
    "allowed_target_dids": "allowedTargetDids",
    "origin_kind": "originKind",
}


def _caveats_to_wire_dict(caveats: InvocationCaveats) -> dict[str, Any]:
    """Convert :class:`scp_sdk.outlets.InvocationCaveats` to wire JSON dict.

    Field names map snake_case → camelCase per §7.3.8. Absent fields are
    omitted (the Rust serde layer uses ``skip_serializing_if`` so wire bytes
    stay byte-stable across SDKs).

    For composite fields:

    * ``amount_max_per_call`` / ``amount_max_cumulative`` accept an ``int``
      (SDK convention) and are serialized as a u64 (matching the Rust
      ``Amount(u64)`` newtype).
    * ``rate_window`` accepts an ``int`` (the SDK builder helper passes
      ``window_secs`` directly) and is wrapped into the wire object form
      ``{"max": 1, "windowSecs": <int>}`` so the protocol-level
      ``RateWindow`` deserializer is satisfied. Callers who need a custom
      ``max`` should pass a ``dict`` directly.
    """
    wire: dict[str, Any] = {}
    for snake, camel in _CAVEAT_WIRE_KEYS.items():
        value = getattr(caveats, snake, None)
        if value is None:
            continue
        # Special-case rate_window int → dict (the SDK uses the seconds value
        # as the only knob; wire form requires both `max` and `windowSecs`).
        if snake == "rate_window" and isinstance(value, int):
            wire[camel] = {"max": 1, "windowSecs": value}
        else:
            wire[camel] = value
    return wire


def _caveats_to_json(caveats: InvocationCaveats | None) -> str | None:
    """Serialize :class:`scp_sdk.outlets.InvocationCaveats` to wire JSON, or ``None``."""
    if caveats is None:
        return None
    return json.dumps(_caveats_to_wire_dict(caveats), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@deprecated_default_instance
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


@deprecated_default_instance
async def mint(
    audience: str,
    capabilities: Sequence[str],
    context: str,
    expiry: float | None = None,
    proofs: Sequence[str] | None = None,
    caveats: InvocationCaveats | None = None,
) -> UcanToken:
    """Mint a new UCAN token, optionally with §7.3.8 invocation caveats.

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
        caveats: Optional :class:`scp_sdk.outlets.InvocationCaveats`
            (SCP-OUT-023, §7.3.8). Routed into the UCAN payload's ``nb``
            field. Mint-limit failures (more than 8 populated non-
            ``origin_kind`` fields, list overflows, schema overflows,
            etc.) surface as :class:`UcanPermissionError` carrying error
            code ``SCP-TOOL-6114`` (slug ``caveat-mint-limit-exceeded``).

    Returns:
        A :class:`UcanToken` containing the minted token's metadata.

    Raises:
        UcanPermissionError: If minting fails (capabilities outside the
            context ceiling, issuer not authorized, mint-limit exceeded,
            etc.).

    Note:
        The issuer is always the context creator. The Rust bridge
        (``_scp_core.ucan_mint``) derives the issuer from the context's
        ``creator_did`` and does not accept an explicit issuer parameter.
    """
    try:
        # Distinguish "no proofs param provided" (None -- root token) from
        # "explicit empty proof chain" (still root, but the caller asked for it).
        # Use `is not None` so the FFI layer can ratchet the distinction later
        # if needed; never the falsy form on Optional collections.
        bridge_token = await asyncio.to_thread(
            _scp_core.ucan_mint,
            context,
            audience,
            list(capabilities),
            list(proofs) if proofs is not None else None,
            _caveats_to_json(caveats),
        )
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc
    return UcanToken._from_bridge(bridge_token)


@deprecated_default_instance
async def narrow(
    parent_token: UcanToken,
    child_caveats: InvocationCaveats,
    context: str,
    *,
    encoded_parent: str | None = None,
) -> UcanToken:
    """Narrow a parent UCAN token by attenuating its caveats (SCP-OUT-023).

    Re-issues ``parent_token`` to the same audience with attenuated
    :class:`~scp_sdk.outlets.InvocationCaveats`. Each field's narrowing
    rule (§7.3.8) is enforced inside the Rust core: numeric ceilings
    tighten downward, validity windows shift inward, masks subset, lists
    subset, ``origin_kind`` is equality (no widening, no narrowing, no
    reset). Widening any field rejects with
    :class:`UcanPermissionError`.

    Args:
        parent_token: The parent :class:`UcanToken` to narrow. Its
            ``encoded`` field is forwarded to the bridge so the core
            ``narrow()`` rule can consult the parent's signed caveats.
        child_caveats: The attenuated caveats. MUST be a strict
            attenuation of the parent's caveats per §7.3.8.
        context: The context ID the token belongs to.
        encoded_parent: Optional override for the encoded JWT
            (defaults to ``parent_token.encoded``).

    Returns:
        A new :class:`UcanToken` carrying the narrowed caveats in its
        ``nb`` field.

    Raises:
        UcanPermissionError: If the narrow rule rejects (widening field,
            origin-kind mismatch, mask-width violation, mint-limit
            exceeded).
    """
    encoded = encoded_parent if encoded_parent is not None else parent_token.encoded
    if not encoded:
        raise UcanPermissionError(
            "narrow requires the parent token's encoded JWT — pass "
            "encoded_parent=… or use a UcanToken minted with "
            "ucan.mint(...) which populates `.encoded`",
        )
    try:
        wire_caveats = _caveats_to_json(child_caveats)
        if wire_caveats is None:  # narrow() requires concrete caveats
            wire_caveats = "{}"
        bridge_token = await asyncio.to_thread(
            _scp_core.ucan_narrow,
            context,
            encoded,
            wire_caveats,
        )
    except Exception as exc:
        raise UcanPermissionError(str(exc)) from exc
    return UcanToken._from_bridge(bridge_token)


@deprecated_default_instance
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


@deprecated_default_instance
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
    "narrow",
    "revoke",
    "validate",
]
