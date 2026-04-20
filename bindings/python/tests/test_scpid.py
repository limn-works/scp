"""SCPID authentication integration tests through real FFI.

Tests the SCPID challenge-response authentication flow end-to-end
through the actual _scp_core PyO3 bridge.

Requires: ``maturin develop --release --features allow_in_memory_custody``

Run::

    PYTHONPATH=bindings/python pytest bindings/python/tests/test_scpid.py -v

Note: ``scpid_verify`` requires DID document resolution via a real or
in-memory DHT. In-memory identities created through the SDK bridge are
not published to the DHT, so the verify step fails with
``DidResolutionFailed``. The Rust FFI test suite validates the full
roundtrip using a shared ``InMemoryDhtClient`` -- see
``crates/scp-ffi/src/scpid.rs::sign_verify_roundtrip_via_identity_backed_resolver``.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Skip entire module if the native extension is not available
# ---------------------------------------------------------------------------

try:
    from scp_sdk import _scp_core
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

from scp_sdk import SCP
from scp_sdk.auth import (
    ScpIdChallenge,
    ScpIdResponse,
    scpid_challenge,
    scpid_sign,
    scpid_verify,
)
from scp_sdk.identity import Identity
from scp_sdk.sync import run_sync
from scp_sdk.types import CustodyType

# ---------------------------------------------------------------------------
# SCP fixture — overrides conftest to expose the raw bridge handle directly
# ---------------------------------------------------------------------------
#
# scpid_sign dispatches on the identity's DID via the bridge's identity
# registry; identities created via ``Identity.create*`` register into
# the same bridge instance, so a fresh ``SCP()`` per test gives each
# test an isolated registry. Phase 4 PR 4 (#1549) removed the
# process-global default instance; every caller owns its own bridge.


@pytest.fixture
def scp() -> SCP:
    wrapper = SCP.__new__(SCP)
    wrapper._native = _scp_core.SCP()
    return wrapper


# ---------------------------------------------------------------------------
# Challenge generation
# ---------------------------------------------------------------------------


class TestScpIdChallenge:
    """Tests for SCPID challenge generation."""

    def test_challenge_returns_valid_structure(self, scp: SCP) -> None:
        challenge = scpid_challenge(scp, "https://example.com", 60)
        assert isinstance(challenge, ScpIdChallenge)
        assert challenge.protocol == "scpid/1.0"
        assert challenge.audience == "https://example.com"
        assert isinstance(challenge.nonce, str)
        assert len(challenge.nonce) > 0
        assert isinstance(challenge.issued_at, int)
        assert isinstance(challenge.expires_at, int)
        assert challenge.expires_at > challenge.issued_at

    def test_challenge_default_ttl(self, scp: SCP) -> None:
        challenge = scpid_challenge(scp, "https://example.com")
        assert isinstance(challenge, ScpIdChallenge)

    def test_challenge_json_roundtrip(self, scp: SCP) -> None:
        challenge = scpid_challenge(scp, "https://example.com", 120)
        raw = challenge.to_json()
        restored = ScpIdChallenge.from_json(raw)
        assert restored.protocol == challenge.protocol
        assert restored.nonce == challenge.nonce
        assert restored.audience == challenge.audience
        assert restored.issued_at == challenge.issued_at
        assert restored.expires_at == challenge.expires_at

    def test_challenge_rejects_zero_ttl(self, scp: SCP) -> None:
        with pytest.raises(Exception):
            scpid_challenge(scp, "https://example.com", 0)

    def test_challenge_rejects_excessive_ttl(self, scp: SCP) -> None:
        with pytest.raises(Exception):
            scpid_challenge(scp, "https://example.com", 301)

    def test_challenge_rejects_empty_audience(self, scp: SCP) -> None:
        with pytest.raises(Exception):
            scpid_challenge(scp, "", 60)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestScpIdSign:
    """Tests for SCPID challenge signing."""

    def test_sign_with_active_key(self, scp: SCP) -> None:
        identity = Identity.create_sync(scp, CustodyType.IN_MEMORY)
        challenge = scpid_challenge(scp, "https://example.com", 120)

        response = scpid_sign(scp, identity, "#active", challenge)
        assert isinstance(response, ScpIdResponse)
        assert response.protocol == "scpid/1.0"
        assert response.did == identity.did
        assert response.audience == "https://example.com"
        assert response.nonce == challenge.nonce
        assert isinstance(response.signed_at, int)
        assert isinstance(response.signature, str)
        assert len(response.signature) > 0

    def test_sign_with_agent_key(self, scp: SCP) -> None:
        identity = run_sync(Identity.create_with_agent_key(scp, CustodyType.IN_MEMORY))
        challenge = scpid_challenge(scp, "https://agent-service.example.com", 60)

        response = scpid_sign(scp, identity, "#agent", challenge)
        assert response.did == identity.did
        assert response.signing_key_id == "#agent"

    def test_sign_rejects_invalid_key_id(self, scp: SCP) -> None:
        identity = Identity.create_sync(scp, CustodyType.IN_MEMORY)
        challenge = scpid_challenge(scp, "https://example.com", 60)

        with pytest.raises(Exception):
            scpid_sign(scp, identity, "#owner", challenge)

    def test_response_json_roundtrip(self, scp: SCP) -> None:
        identity = Identity.create_sync(scp, CustodyType.IN_MEMORY)
        challenge = scpid_challenge(scp, "https://example.com", 120)

        response = scpid_sign(scp, identity, "#active", challenge)
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

    Note: Full roundtrip verification (challenge -> sign -> verify) requires
    the identity's DID document to be published to a DHT that the global
    resolver can access. In-memory test identities are NOT published, so
    verify raises ``IdentityError`` with ``SCP-IDENT-1033`` (DID resolution
    failed). This is the expected and correct error — the Rust FFI test
    suite validates the full roundtrip with a shared InMemoryDhtClient.
    """

    def test_verify_raises_did_resolution_error(self, scp: SCP) -> None:
        """Verify raises IdentityError when the DID is not published to DHT."""
        identity = Identity.create_sync(scp, CustodyType.IN_MEMORY)
        challenge = scpid_challenge(scp, "https://example.com", 120)
        response = scpid_sign(scp, identity, "#active", challenge)

        with pytest.raises(Exception, match="SCP-IDENT-1033"):
            scpid_verify(scp, response, challenge)
