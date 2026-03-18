"""Tests for SCP Python SDK identity link attestation wrappers (§3.5).

Covers:
- IdentityAttestation dataclass construction and serialization
- Identity.create_attestation bridge-not-available error
- Identity.list_attestations / attestations property bridge-not-available error
- Identity.remove_attestation bridge-not-available error
- Identity.renew_attestation bridge-not-available error
- IdentityAttestation.verify bridge-not-available error
- Round-trip _from_dict / _to_bridge_dict

See ``.docs/specs/03-identity.md`` section 3.5.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from scp_sdk.errors import IdentityError
from scp_sdk.identity import Identity, IdentityAttestation

# ---------------------------------------------------------------------------
# IdentityAttestation dataclass tests
# ---------------------------------------------------------------------------


class TestIdentityAttestationDataclass:
    """Tests for IdentityAttestation construction and serialization."""

    def test_construction_defaults(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000.0,
        )
        assert att.id == "abc123"
        assert att.platform == "github.com"
        assert att.platform_handle == "alice"
        assert att.verification_method == "did:dht:z6Mk...#active"
        assert att.verified_at == 1700000000.0
        assert att.revocation_status == "active"
        assert att.platform_id is None

    def test_construction_all_fields(self) -> None:
        att = IdentityAttestation(
            id="def456",
            platform="x.com",
            platform_handle="bob",
            verification_method="did:dht:z6Mk...#agent",
            verified_at=1700000000.0,
            revocation_status="revoked",
            platform_id="12345",
        )
        assert att.revocation_status == "revoked"
        assert att.platform_id == "12345"

    def test_from_dict(self) -> None:
        data: dict[str, Any] = {
            "id": "abc123",
            "platform": "github.com",
            "platform_handle": "alice",
            "verification_method": "did:dht:z6Mk...#active",
            "verified_at": 1700000000.0,
            "revocation_status": "active",
            "platform_id": "99",
        }
        att = IdentityAttestation._from_dict(data)
        assert att.id == "abc123"
        assert att.platform_id == "99"

    def test_from_dict_missing_optional(self) -> None:
        data: dict[str, Any] = {
            "id": "abc123",
            "platform": "github.com",
            "platform_handle": "alice",
            "verification_method": "did:dht:z6Mk...#active",
            "verified_at": 1700000000.0,
        }
        att = IdentityAttestation._from_dict(data)
        assert att.revocation_status == "active"
        assert att.platform_id is None

    def test_to_bridge_dict_roundtrip(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000.0,
            platform_id="42",
        )
        d = att._to_bridge_dict()
        assert d["id"] == "abc123"
        assert d["platform_id"] == "42"
        roundtrip = IdentityAttestation._from_dict(d)
        assert roundtrip == att

    def test_to_bridge_dict_no_platform_id(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000.0,
        )
        d = att._to_bridge_dict()
        assert "platform_id" not in d

    def test_repr(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000.0,
        )
        r = repr(att)
        assert "abc123" in r
        assert "github.com" in r
        assert "alice" in r
        assert "active" in r


# ---------------------------------------------------------------------------
# Identity attestation method tests (bridge not available)
# ---------------------------------------------------------------------------


def _make_identity() -> Identity:
    """Create a mock Identity for testing."""
    handle = MagicMock()
    handle.did = "did:dht:z6MkTest"
    handle.custody = "in_memory"
    return Identity(handle)


class TestIdentityCreateAttestation:
    """Tests for Identity.create_attestation when bridge is unavailable."""

    def test_raises_when_bridge_missing(self) -> None:
        identity = _make_identity()
        with pytest.raises(IdentityError, match="SCP-ATTEST-9001"):
            asyncio.get_event_loop().run_until_complete(
                identity.create_attestation("github.com", "alice", "proof123")
            )


class TestIdentityListAttestations:
    """Tests for Identity.list_attestations when bridge is unavailable."""

    def test_raises_when_bridge_missing(self) -> None:
        identity = _make_identity()
        with pytest.raises(IdentityError, match="SCP-ATTEST-9002"):
            asyncio.get_event_loop().run_until_complete(identity.list_attestations())


class TestIdentityRemoveAttestation:
    """Tests for Identity.remove_attestation when bridge is unavailable."""

    def test_raises_when_bridge_missing(self) -> None:
        identity = _make_identity()
        with pytest.raises(IdentityError, match="SCP-ATTEST-9003"):
            asyncio.get_event_loop().run_until_complete(identity.remove_attestation("att-id-123"))


class TestIdentityRenewAttestation:
    """Tests for Identity.renew_attestation when bridge is unavailable."""

    def test_raises_when_bridge_missing(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000.0,
        )
        identity = _make_identity()
        with pytest.raises(IdentityError, match="SCP-ATTEST-9004"):
            asyncio.get_event_loop().run_until_complete(identity.renew_attestation(att))


class TestIdentityAttestationVerify:
    """Tests for IdentityAttestation.verify when bridge is unavailable."""

    def test_raises_when_bridge_missing(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000.0,
        )
        with pytest.raises(IdentityError, match="SCP-ATTEST-9005"):
            asyncio.get_event_loop().run_until_complete(att.verify())
