"""SCPID authentication for external services (spec section 3.11).

Provides challenge-response authentication so that SCP DID holders can
prove their identity to external services outside of SCP contexts.
Analogous to "Sign in with Ethereum" (EIP-4361) but simpler: no
blockchain state, no gas -- the DID document is the identity provider.

Functions:
    :func:`scpid_challenge` -- Generate a challenge for a relying party.
    :func:`scpid_sign` -- Sign a challenge with an identity's key.
    :func:`scpid_verify` -- Verify a signed response (relying-party side).

Dataclasses:
    :class:`ScpIdChallenge` -- Challenge issued by the relying party.
    :class:`ScpIdResponse` -- Signed response from the client.
    :class:`ScpIdAuthentication` -- Result of successful verification.

See ``.docs/specs/`` section 3.11 and ADR phase-3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ScpIdChallenge:
    """SCPID challenge issued by a relying party (section 3.11.2).

    Contains a CSPRNG nonce, audience binding, and validity window.
    """

    #: Protocol identifier and version: ``"scpid/1.0"``.
    protocol: str

    #: 32-byte CSPRNG nonce (hex-encoded string).
    nonce: str

    #: URI identifying the relying party.
    audience: str

    #: Unix timestamp (milliseconds) when the challenge was created.
    issued_at: int

    #: Unix timestamp (milliseconds) when the challenge expires.
    expires_at: int

    def to_json(self) -> str:
        """Serialize to a JSON string for transport to the bridge layer."""
        return json.dumps(
            {
                "protocol": self.protocol,
                "nonce": self.nonce,
                "audience": self.audience,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> ScpIdChallenge:
        """Deserialize from a JSON string returned by the bridge layer.

        Args:
            raw: JSON string with ``protocol``, ``nonce``, ``audience``,
                ``issued_at``, and ``expires_at`` fields.

        Returns:
            A new :class:`ScpIdChallenge` instance.
        """
        d: dict[str, Any] = json.loads(raw)
        return cls(
            protocol=d["protocol"],
            nonce=d["nonce"],
            audience=d["audience"],
            issued_at=d["issued_at"],
            expires_at=d["expires_at"],
        )


@dataclass
class ScpIdResponse:
    """SCPID response signed by the client (section 3.11.3).

    Contains the client's DID, signing key selection, echoed challenge
    fields, and the Ed25519 signature.
    """

    #: Protocol identifier and version: ``"scpid/1.0"``.
    protocol: str

    #: The signer's DID (e.g. ``"did:dht:z6Mk..."``).
    did: str

    #: Which verification method signed: ``"#active"`` or ``"#agent"``.
    signing_key_id: str

    #: Echo of the challenge nonce (hex-encoded string).
    nonce: str

    #: Echo of the challenge audience URI.
    audience: str

    #: Unix timestamp (milliseconds) when the client signed.
    signed_at: int

    #: Ed25519 signature (hex-encoded string).
    signature: str

    def to_json(self) -> str:
        """Serialize to a JSON string for transport to the bridge layer."""
        return json.dumps(
            {
                "protocol": self.protocol,
                "did": self.did,
                "signing_key_id": self.signing_key_id,
                "nonce": self.nonce,
                "audience": self.audience,
                "signed_at": self.signed_at,
                "signature": self.signature,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> ScpIdResponse:
        """Deserialize from a JSON string returned by the bridge layer.

        Args:
            raw: JSON string with all response fields.

        Returns:
            A new :class:`ScpIdResponse` instance.
        """
        d: dict[str, Any] = json.loads(raw)
        return cls(
            protocol=d["protocol"],
            did=d["did"],
            signing_key_id=d["signing_key_id"],
            nonce=d["nonce"],
            audience=d["audience"],
            signed_at=d["signed_at"],
            signature=d["signature"],
        )


@dataclass
class ScpIdAuthentication:
    """Result of a successful SCPID verification (section 3.11.4 step 11).

    Returned by :func:`scpid_verify` when all 11 verification steps pass.
    """

    #: The authenticated DID.
    did: str

    #: Which verification method produced the signature.
    signing_key_id: str

    #: Unix timestamp (milliseconds) when the client signed.
    signed_at: int


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "ScpIdAuthentication",
    "ScpIdChallenge",
    "ScpIdResponse",
]
