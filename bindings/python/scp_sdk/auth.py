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
from typing import Any

from scp_sdk._deprecation import deprecated_default_instance

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


@deprecated_default_instance
def scpid_challenge(audience: str, ttl_seconds: int = 300) -> ScpIdChallenge:
    """Generate an SCPID challenge for a relying party (section 3.11.8).

    Args:
        audience: URI identifying the relying party
            (e.g. ``"https://app.example.com"``).
        ttl_seconds: Challenge validity window in seconds (1--300).
            Defaults to 300.

    Returns:
        A new :class:`ScpIdChallenge`.

    Raises:
        scp_sdk.ValidationError: If *audience* is empty, exceeds 2048 bytes,
            or *ttl_seconds* is 0 or exceeds 300.
    """
    import _scp_core

    challenge_json = _scp_core.scpid_challenge(audience, ttl_seconds)
    return ScpIdChallenge.from_json(challenge_json)


@deprecated_default_instance
def scpid_sign(
    identity: Any,
    signing_key_id: str,
    challenge: ScpIdChallenge,
) -> ScpIdResponse:
    """Sign an SCPID challenge with a registered identity's key (section 3.11.3).

    Looks up the identity by DID in the global registry, selects the
    appropriate signing key, and produces a signed SCPID response.

    Args:
        identity: An :class:`~scp_sdk.identity.Identity` instance whose DID
            is registered in the bridge's identity registry.
        signing_key_id: ``"#active"`` or ``"#agent"``.
        challenge: The challenge to sign.

    Returns:
        A new :class:`ScpIdResponse`.

    Raises:
        scp_sdk.IdentityError: If the DID is not registered or signing fails.
        scp_sdk.ValidationError: If *signing_key_id* is invalid or the
            challenge is malformed.
    """
    import _scp_core

    response_json = _scp_core.scpid_sign(
        identity.did,
        signing_key_id,
        challenge.to_json(),
    )
    return ScpIdResponse.from_json(response_json)


@deprecated_default_instance
def scpid_verify(
    response: ScpIdResponse,
    challenge: ScpIdChallenge,
) -> ScpIdAuthentication:
    """Verify a signed SCPID response against the original challenge (section 3.11.4).

    Resolves the signer's DID document via the global DID resolver
    (initialized during identity creation), then runs the 11-step
    verification pipeline.

    Args:
        response: The signed response from the client.
        challenge: The original challenge issued by the relying party.

    Returns:
        An :class:`ScpIdAuthentication` on success.

    Raises:
        scp_sdk.IdentityError: If the DID resolver is not initialized,
            DID resolution fails, the signature is invalid, the challenge
            has expired, or any other verification step fails.
        scp_sdk.ValidationError: If either JSON structure is malformed.
    """
    import _scp_core

    auth_json = _scp_core.scpid_verify(
        response.to_json(),
        challenge.to_json(),
    )
    d: dict[str, Any] = json.loads(auth_json)
    return ScpIdAuthentication(
        did=d["did"],
        signing_key_id=d["signing_key_id"],
        signed_at=d["signed_at"],
    )


__all__ = [
    "ScpIdAuthentication",
    "ScpIdChallenge",
    "ScpIdResponse",
    "scpid_challenge",
    "scpid_sign",
    "scpid_verify",
]
