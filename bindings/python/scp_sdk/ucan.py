"""UCAN token data type for the SCP Python SDK.

Phase 4 PR 5 Agent B+C (#1549) reduced this module to the
:class:`UcanToken` dataclass — every UCAN operation (mint, revoke,
delegate, validate) now lives on :class:`scp_sdk.SCP` as
:meth:`~scp_sdk.SCP.ucan_mint`, :meth:`~scp_sdk.SCP.ucan_revoke`,
:meth:`~scp_sdk.SCP.ucan_delegate`, and
:meth:`~scp_sdk.SCP.ucan_validate`.

UCAN (User Controlled Authorization Networks) tokens are the capability
enforcement mechanism for SCP. Every protocol action — message send,
tool invocation, member management — requires a valid UCAN token.

See ``.docs/adrs/phase-3.md`` ADR-016 for the full UCAN validation
specification and ADR-048 for the façade consolidation rationale.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UcanToken:
    """A UCAN token with metadata.

    Mirrors the ``_scp_core.UcanToken`` (``PyUcanToken``) returned by
    :meth:`scp_sdk.SCP.ucan_mint` and
    :meth:`scp_sdk.SCP.ucan_delegate`. Holds the same fields exposed by
    the Rust bridge as a frozen Python dataclass — no :class:`SCP`
    reference is stored.

    Attributes:
        token_id: Unique token identifier (derived from the UCAN nonce).
        issuer: Issuer DID — the entity that created and signed this token.
        audience: Audience DID — the entity this token is delegated to.
        capabilities: List of capability URIs granted by this token.
        expires_at: Expiry timestamp (seconds since Unix epoch), or
            ``None`` if the token does not expire.
        proofs: Proof chain — CIDs/IDs of parent UCAN tokens forming the
            delegation chain. Empty for root tokens.
    """

    #: Unique token identifier (derived from the UCAN nonce).
    token_id: str

    #: Issuer DID — the entity that created and signed this token.
    issuer: str

    #: Audience DID — the entity this token is delegated to.
    audience: str

    #: List of capability URIs granted by this token.
    capabilities: list[str] = field(default_factory=list)

    #: Expiry timestamp (seconds since Unix epoch), or ``None``.
    expires_at: float | None = None

    #: Proof chain — CIDs/IDs of parent UCAN tokens forming the delegation
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


__all__ = [
    "UcanToken",
]
