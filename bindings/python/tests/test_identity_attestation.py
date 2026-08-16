"""Tests for SCP Python SDK identity link attestation wrappers (§3.5).

Covers:
- IdentityAttestation dataclass construction and serialization
- SCP.create_identity_link_attestation bridge-not-available error
- SCP.identity_link_attestations bridge-not-available error
- SCP.remove_identity_link_attestation bridge-not-available error
- SCP.identity_renew_attestation bridge-not-available error
- Round-trip _from_dict / _to_bridge_dict
- NaN / Infinity / bool / negative guards (SCP-VALID-7005)

Phase 4 PR 5 Agent B+C (#1549) moved attestation operations from
:class:`Identity` instance methods onto :class:`scp_sdk.SCP` methods.
:class:`IdentityAttestation` no longer has a ``verify`` instance method
(it was removed in #1458, Agent B+C reaffirms).

See ``.docs/specs/03-identity.md`` section 3.5.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from scp_sdk.errors import AttestationError, ValidationError
from scp_sdk.identity import IdentityAttestation, RevocationStatus, _parse_finite_int

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
            verified_at=1700000000,
        )
        assert att.id == "abc123"
        assert att.platform == "github.com"
        assert att.platform_handle == "alice"
        assert att.verification_method == "did:dht:z6Mk...#active"
        assert att.verified_at == 1700000000
        assert att.revocation_status == RevocationStatus(status="active")
        assert att.platform_id is None

    def test_construction_all_fields(self) -> None:
        att = IdentityAttestation(
            id="def456",
            platform="x.com",
            platform_handle="bob",
            verification_method="did:dht:z6Mk...#agent",
            verified_at=1700000000,
            revocation_status=RevocationStatus(status="revoked", revoked_at=1700000000),
            platform_id="12345",
        )
        assert att.revocation_status == RevocationStatus(status="revoked", revoked_at=1700000000)
        assert att.platform_id == "12345"

    def test_from_dict(self) -> None:
        data: dict[str, Any] = {
            "id": "abc123",
            "platform": "github.com",
            "platform_handle": "alice",
            "verification_method": "did:dht:z6Mk...#active",
            "verified_at": 1700000000,
            "revocation_status": "Active",
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
        assert att.revocation_status == RevocationStatus(status="active")
        assert att.platform_id is None
        # Float verified_at should be coerced to int at the deserialization boundary.
        assert isinstance(att.verified_at, int)
        assert att.verified_at == 1700000000

    def test_to_bridge_dict_roundtrip(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000,
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
            verified_at=1700000000,
        )
        d = att._to_bridge_dict()
        assert "platform_id" not in d

    def test_repr(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000,
        )
        r = repr(att)
        assert "abc123" in r
        assert "github.com" in r
        assert "alice" in r
        assert "active" in r


# ---------------------------------------------------------------------------
# SCP.* attestation method tests (bridge not available)
# ---------------------------------------------------------------------------


def _make_scp_without_attestation_methods(*, missing: tuple[str, ...]) -> MagicMock:
    """Build a mock SCP whose ``_native`` does not expose the listed methods.

    ``MagicMock(spec=...)`` restricts ``hasattr()`` to the spec list — so
    anything not in the spec reports ``hasattr == False``, triggering the
    SDK's attestation availability guards.
    """
    mock_scp = MagicMock()
    # Start with every attestation method present, then drop the ones
    # under test so hasattr() returns False for them specifically.
    # verify_identity_link_attestation is a per-instance bridge method again
    # (GitHub issue #2335 finding 2: spec §3.5.4 step 1 resolves an issuer's
    # DID document, which needs this instance's resolver). SCP.py calls it
    # directly with no hasattr guard, so no entry appears here.
    all_methods = {
        "create_identity_link_attestation",
        "identity_link_attestations",
        "remove_identity_link_attestation",
        "identity_renew_attestation",
    }
    present = tuple(all_methods - set(missing))
    mock_scp._native = MagicMock(spec=present)
    return mock_scp


class TestScpCreateAttestation:
    """Tests for :meth:`SCP.create_identity_link_attestation` bridge guard."""

    def test_raises_when_bridge_missing(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp_without_attestation_methods(missing=("create_identity_link_attestation",))
        with pytest.raises(AttestationError, match="SCP-ATTEST-9010"):
            asyncio.new_event_loop().run_until_complete(
                SCP.create_identity_link_attestation(
                    scp,  # type: ignore[arg-type]
                    "did:dht:z6MkTest",
                    "github.com",
                    "alice",
                    "proof123",
                    "did:dht:z6MkTest#active",
                )
            )


class TestScpListAttestations:
    """Tests for :meth:`SCP.identity_link_attestations` bridge guard."""

    def test_raises_when_bridge_missing(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp_without_attestation_methods(missing=("identity_link_attestations",))
        with pytest.raises(AttestationError, match="SCP-ATTEST-9011"):
            asyncio.new_event_loop().run_until_complete(
                SCP.identity_link_attestations(scp, "did:dht:z6MkTest")  # type: ignore[arg-type]
            )


class TestScpRemoveAttestation:
    """Tests for :meth:`SCP.remove_identity_link_attestation` bridge guard."""

    def test_raises_when_bridge_missing(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp_without_attestation_methods(missing=("remove_identity_link_attestation",))
        with pytest.raises(AttestationError, match="SCP-ATTEST-9012"):
            asyncio.new_event_loop().run_until_complete(
                SCP.remove_identity_link_attestation(  # type: ignore[arg-type]
                    scp, "did:dht:z6MkTest", "att-id-123"
                )
            )


class TestScpRenewAttestation:
    """Tests for :meth:`SCP.identity_renew_attestation` bridge guard."""

    def test_raises_when_bridge_missing(self) -> None:
        from scp_sdk.scp import SCP

        scp = _make_scp_without_attestation_methods(missing=("identity_renew_attestation",))
        with pytest.raises(AttestationError, match="SCP-ATTEST-9013"):
            asyncio.new_event_loop().run_until_complete(
                SCP.identity_renew_attestation(scp, "did:dht:z6MkTest", "abc123")  # type: ignore[arg-type]
            )


class TestIdentityAttestationVerifyRemoved:
    """Verify that verify() was removed from IdentityAttestation (see #1458).

    Post-Phase-4-PR-5 (#1549), verification of an attestation is a
    :class:`scp_sdk.SCP` method — :meth:`SCP.verify_identity_link_attestation`.
    The data class itself exposes no verification behavior.
    """

    def test_verify_method_does_not_exist(self) -> None:
        att = IdentityAttestation(
            id="abc123",
            platform="github.com",
            platform_handle="alice",
            verification_method="did:dht:z6Mk...#active",
            verified_at=1700000000,
        )
        assert not hasattr(att, "verify")


# ---------------------------------------------------------------------------
# NaN / Infinity guard tests (SCP-VALID-7005)
# ---------------------------------------------------------------------------


class TestNanInfinityGuards:
    """Validate that NaN, Infinity, and bool are rejected for timestamp fields."""

    def test_from_dict_nan_verified_at_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            IdentityAttestation._from_dict(
                {
                    "id": "abc123",
                    "platform": "github.com",
                    "platform_handle": "alice",
                    "verification_method": "did:dht:z6Mk...#active",
                    "verified_at": float("nan"),
                }
            )

    def test_from_dict_inf_verified_at_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            IdentityAttestation._from_dict(
                {
                    "id": "abc123",
                    "platform": "github.com",
                    "platform_handle": "alice",
                    "verification_method": "did:dht:z6Mk...#active",
                    "verified_at": float("inf"),
                }
            )

    def test_constructor_nan_verified_at_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            IdentityAttestation(
                id="abc123",
                platform="github.com",
                platform_handle="alice",
                verification_method="did:dht:z6Mk...#active",
                verified_at=float("nan"),
            )

    def test_constructor_bool_verified_at_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            IdentityAttestation(
                id="abc123",
                platform="github.com",
                platform_handle="alice",
                verification_method="did:dht:z6Mk...#active",
                verified_at=True,  # type: ignore[arg-type]
            )

    def test_parse_finite_int_bool_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            _parse_finite_int(True, "x")

    def test_parse_finite_int_nan_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            _parse_finite_int(float("nan"), "x")

    def test_parse_finite_int_inf_raises(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            _parse_finite_int(float("inf"), "x")

    def test_parse_finite_int_rejects_string(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            _parse_finite_int("1700000000", "verified_at")

    def test_parse_finite_int_rejects_negative(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            _parse_finite_int(-1, "verified_at")

    def test_parse_finite_int_rejects_float(self) -> None:
        with pytest.raises(ValidationError, match="SCP-VALID-7005"):
            _parse_finite_int(1.5, "verified_at")
