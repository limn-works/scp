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
bridge are not published to the DHT, so the verify step fails with
``SCP-IDENT-1033`` (``DidResolutionFailed``). The Rust FFI test suite
validates the full roundtrip using a shared ``InMemoryDhtClient`` — see
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

    Note: Full roundtrip verification (challenge → sign → verify) requires
    the identity's DID document to be published to a DHT that the global
    resolver can access. In-memory test identities are NOT published, so
    :meth:`SCP.scpid_verify` raises ``IdentityError`` with
    ``SCP-IDENT-1033`` (DID resolution failed). This is the expected and
    correct error — the Rust FFI test suite validates the full roundtrip
    with a shared ``InMemoryDhtClient``.
    """

    def test_verify_raises_did_resolution_error(self, scp: SCP) -> None:
        identity = _run(scp.identity_create(CustodyType.IN_MEMORY))
        challenge = _run(scp.scpid_challenge("https://example.com", 120))
        response = _run(scp.scpid_sign(identity.did, "#active", challenge.to_json()))

        with pytest.raises(Exception, match="SCP-IDENT-1033"):
            _run(scp.scpid_verify(response.to_json(), challenge.to_json()))
