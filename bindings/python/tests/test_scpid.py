"""SCPID authentication integration tests through real FFI.

Tests the SCPID challenge-response authentication flow end-to-end
through the actual _scp_core PyO3 bridge via :class:`scp_sdk.SCP`
methods.

Phase 4 PR 5 Agent B+C (#1549) moved the free functions
``scpid_challenge`` / ``scpid_sign`` / ``scpid_verify`` onto
:class:`scp_sdk.SCP` as :meth:`SCP.scpid_challenge` /
:meth:`SCP.scpid_sign` / :meth:`SCP.scpid_verify`. This test exercises
them through the real bridge.

Requires: ``maturin develop --release --features allow_in_memory_custody``

Note: :meth:`SCP.scpid_verify` requires DID document resolution via a
real or in-memory DHT. In-memory identities created through the SDK
bridge publish their DID document into the per-instance resolver DHT at
creation time, so the full challenge → sign → verify roundtrip succeeds
without any external network. The Rust FFI test suite covers the same
roundtrip — see
``crates/scp-ffi/src/scpid.rs::sign_verify_roundtrip_via_identity_backed_resolver``.
"""

from __future__ import annotations

import asyncio

import pytest

# ---------------------------------------------------------------------------
# Skip entire module if the native extension is not available
# ---------------------------------------------------------------------------

try:
    from scp_sdk import _scp_core  # noqa: F401 — confirms native module is available
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

from scp_sdk import SCP
from scp_sdk.auth import ScpIdChallenge, ScpIdResponse
from scp_sdk.types import CustodyType


def _run(coro):  # type: ignore[no-untyped-def]
    """Run an async coroutine to completion in an isolated event loop."""
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Challenge generation
# ---------------------------------------------------------------------------


class TestScpIdChallenge:
    """Tests for SCPID challenge generation."""

    def test_challenge_returns_valid_structure(self, scp: SCP) -> None:
        challenge = _run(scp.scpid_challenge("https://example.com", 60))
        assert isinstance(challenge, ScpIdChallenge)
        assert challenge.protocol == "scpid/1.0"
        assert challenge.audience == "https://example.com"
        assert isinstance(challenge.nonce, str)
        assert len(challenge.nonce) > 0
        assert isinstance(challenge.issued_at, int)
        assert isinstance(challenge.expires_at, int)
        assert challenge.expires_at > challenge.issued_at

    def test_challenge_default_ttl(self, scp: SCP) -> None:
        challenge = _run(scp.scpid_challenge("https://example.com"))
        assert isinstance(challenge, ScpIdChallenge)

    def test_challenge_json_roundtrip(self, scp: SCP) -> None:
        challenge = _run(scp.scpid_challenge("https://example.com", 120))
        raw = challenge.to_json()
        restored = ScpIdChallenge.from_json(raw)
        assert restored.protocol == challenge.protocol
        assert restored.nonce == challenge.nonce
        assert restored.audience == challenge.audience
        assert restored.issued_at == challenge.issued_at
        assert restored.expires_at == challenge.expires_at

    def test_challenge_rejects_zero_ttl(self, scp: SCP) -> None:
        with pytest.raises(Exception):
            _run(scp.scpid_challenge("https://example.com", 0))

    def test_challenge_rejects_excessive_ttl(self, scp: SCP) -> None:
        with pytest.raises(Exception):
            _run(scp.scpid_challenge("https://example.com", 301))

    def test_challenge_rejects_empty_audience(self, scp: SCP) -> None:
        with pytest.raises(Exception):
            _run(scp.scpid_challenge("", 60))


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestScpIdSign:
    """Tests for SCPID challenge signing."""

    def test_sign_with_active_key(self, scp: SCP) -> None:
        identity = _run(scp.identity_create(CustodyType.IN_MEMORY))
        challenge = _run(scp.scpid_challenge("https://example.com", 120))

        response = _run(scp.scpid_sign(identity.did, "#active", challenge.to_json()))
        assert isinstance(response, ScpIdResponse)
        assert response.protocol == "scpid/1.0"
        assert response.did == identity.did
        assert response.audience == "https://example.com"
        assert response.nonce == challenge.nonce
        assert isinstance(response.signed_at, int)
        assert isinstance(response.signature, str)
        assert len(response.signature) > 0

    def test_sign_with_agent_key(self, scp: SCP) -> None:
        identity = _run(scp.identity_create_with_agent_key(CustodyType.IN_MEMORY))
        challenge = _run(scp.scpid_challenge("https://agent-service.example.com", 60))

        response = _run(scp.scpid_sign(identity.did, "#agent", challenge.to_json()))
        assert response.did == identity.did
        assert response.signing_key_id == "#agent"

    def test_sign_rejects_invalid_key_id(self, scp: SCP) -> None:
        identity = _run(scp.identity_create(CustodyType.IN_MEMORY))
        challenge = _run(scp.scpid_challenge("https://example.com", 60))

        with pytest.raises(Exception):
            _run(scp.scpid_sign(identity.did, "#owner", challenge.to_json()))

    def test_response_json_roundtrip(self, scp: SCP) -> None:
        identity = _run(scp.identity_create(CustodyType.IN_MEMORY))
        challenge = _run(scp.scpid_challenge("https://example.com", 120))

        response = _run(scp.scpid_sign(identity.did, "#active", challenge.to_json()))
        raw = response.to_json()
        restored = ScpIdResponse.from_json(raw)
        assert restored.protocol == response.protocol
        assert restored.did == response.did
        assert restored.signing_key_id == response.signing_key_id
        assert restored.nonce == response.nonce
        assert restored.audience == response.audience
        assert restored.signed_at == response.signed_at
        assert restored.signature == response.signature


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestScpIdVerify:
    """Tests for SCPID response verification.

    In-memory identities created through the SDK bridge publish their DID
    document into the per-instance resolver DHT at creation time, so the
    full challenge → sign → verify roundtrip resolves the signer's DID and
    succeeds with no external network. The Rust FFI test suite covers the
    same roundtrip with a shared ``InMemoryDhtClient``.
    """

    def test_verify_succeeds_for_in_memory_identity(self, scp: SCP) -> None:
        identity = _run(scp.identity_create(CustodyType.IN_MEMORY))
        challenge = _run(scp.scpid_challenge("https://example.com", 120))
        response = _run(scp.scpid_sign(identity.did, "#active", challenge.to_json()))

        auth = _run(scp.scpid_verify(response.to_json(), challenge.to_json()))

        assert auth.did == identity.did
        assert auth.signing_key_id == "#active"
        assert auth.signed_at == response.signed_at

    def test_verify_uses_rotated_active_key_not_stale(self, scp: SCP) -> None:
        """After ``identity_rotate_key``, the resolver must serve the NEW
        ``#active`` key.

        Rotation publishes a higher-sequence DID document into the SAME
        per-instance resolver DHT client that ``scpid_verify`` resolves
        against. If rotation published into a throwaway client (or at a
        non-advancing sequence), the resolver would keep serving the stale
        pre-rotation document: a fresh challenge signed by the NEW active key
        would then fail to verify against the OLD key, silently defeating the
        revocation purpose of rotation. This asserts the post-rotation
        signature verifies, which is only possible if the rotated document
        reached the shared resolver.
        """
        identity = _run(scp.identity_create(CustodyType.IN_MEMORY))

        # Baseline: pre-rotation active key signs and verifies.
        challenge = _run(scp.scpid_challenge("https://example.com", 120))
        response = _run(scp.scpid_sign(identity.did, "#active", challenge.to_json()))
        _run(scp.scpid_verify(response.to_json(), challenge.to_json()))

        # Rotate the active signing key (DID string is unchanged).
        rotated = _run(scp.identity_rotate_key(identity._raw_handle))
        assert rotated.did == identity.did

        # A fresh challenge signed with the NEW active key must verify, which
        # requires the resolver to serve the rotated document (FIX B).
        new_challenge = _run(scp.scpid_challenge("https://example.com", 120))
        new_response = _run(scp.scpid_sign(identity.did, "#active", new_challenge.to_json()))
        auth = _run(scp.scpid_verify(new_response.to_json(), new_challenge.to_json()))

        assert auth.did == identity.did
        assert auth.signing_key_id == "#active"
        assert auth.signed_at == new_response.signed_at
