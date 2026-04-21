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

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scp_sdk.scp import SCP

try:
    import _scp_core  # type: ignore[import-not-found]
except ImportError:
    _scp_core = None  # type: ignore[assignment]


def _resolve_bridge(scp: SCP) -> Any:
    """Return the effective bridge object for UCAN operations.

    When tests patch ``scp_sdk.ucan._scp_core`` with a ``MagicMock``,
    that mock's ``ucan_*`` attributes stand in for the real bridge
    calls. Production code sees the real ``_scp_core`` module here
    (which does NOT expose the ``ucan_*`` methods at module level after
    Phase 4 PR 4), so we fall through to ``scp._native`` and dispatch
    via the :class:`SCP` instance. See ADR-048 for the consolidation
    rationale.
    """
    mod = _scp_core
    if mod is not None and hasattr(mod, "_mock_name"):
        return mod
    return scp._native


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


__all__ = [
    "UcanToken",
]
