"""Tests for the ADR-049 Phase 2J invite / joiner handshake SDK wrappers.

Covers :meth:`scp_sdk.SCP.reserve_key_package` (step 1),
:meth:`scp_sdk.SCP.invite_member` (creator side; FFI-02 Option A), and
:meth:`scp_sdk.SCP.context_join_from_welcome` (joiner side, reshaped to take a
:class:`scp_sdk.SealedInvitation`):

- Mock-based delegation: the wrappers forward their arguments to the PyO3
  ``_native`` bridge in order, return the reservation tuple unchanged, project
  the invite outcome into the :data:`scp_sdk.InviteMemberOutcome` union, and wrap
  the joined handle in a :class:`~scp_sdk.context.Context` scoped to the joiner.
  No Rust extension required (the join wrapper's native-projection seam,
  ``_to_native_sealed``, is patched).
- Real-FFI (skips without the native module): ``reserve_key_package`` mints a
  real single-use MLS ``KeyPackage``; ``invite_member`` seals a real bundle for a
  SingleAdmin context (0xFF02-capable KeyPackage, §5.13.3 / valn0502, fixed in
  9fe3b4c9b); and the ops fail closed for a non-locally-custodied DID / unknown
  context (the same trust model as ``context_create``).

See ``.docs/adrs/ADR-049-actor-per-context.md`` §9 (Deferred Work 1) and
``crates/scp-ffi/CLAUDE.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.context import Context
from scp_sdk.scp import (
    RequiresGovernanceApproval,
    Sealed,
    SealedInvitation,
)

# ---------------------------------------------------------------------------
# Helpers — minimal bridge mocks (mirrors tests/test_context.py)
# ---------------------------------------------------------------------------


@dataclass
class _MockHandle:
    """Mock for the opaque bridge context handle."""

    context_id: str = "ctx-test-abc123"
    state: str = "active"


def _make_scp(native_mock: MagicMock | None = None) -> MagicMock:
    """Return a mock ``SCP`` wrapper with a ``_native`` attached.

    Tests call the real :meth:`SCP.<op>` methods via ``SCP.<op>(scp_mock, ...)``
    so the bound wrapper delegates to the mocked ``_native``.
    """
    scp = MagicMock()
    scp._native = native_mock if native_mock is not None else MagicMock()
    return scp


# A syntactically-valid 64-hex context id (ADR-056) for FFI-boundary validation.
_HEX_CTX_ID = "a" * 64
_CREATOR_DID = "did:dht:z6MkCreatorAbc"


def _sealed() -> SealedInvitation:
    """A representative SDK :class:`SealedInvitation` for delegation tests."""
    return SealedInvitation(
        context_id=_HEX_CTX_ID,
        creator_did=_CREATOR_DID,
        enc=b"\x00" * 32,
        ciphertext=b"sealed-bundle-ct",
    )


# ---------------------------------------------------------------------------
# SCP.reserve_key_package — mock delegation
# ---------------------------------------------------------------------------


class TestReserveKeyPackageDelegation:
    """Verify :meth:`SCP.reserve_key_package` parameter forwarding."""

    async def test_forwards_owning_did(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.reserve_key_package.return_value = ("res-id-1", b"\x01\x02\x03")
        scp = _make_scp(native)

        await SCP.reserve_key_package(scp, "did:dht:z6MkAlice")

        native.reserve_key_package.assert_called_once_with("did:dht:z6MkAlice")

    async def test_returns_reservation_tuple_unchanged(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.reserve_key_package.return_value = ("res-id-2", b"kp-public-bytes")
        scp = _make_scp(native)

        result = await SCP.reserve_key_package(scp, "did:dht:z6MkAlice")

        assert result == ("res-id-2", b"kp-public-bytes")
        reservation_id, key_package_public = result
        assert reservation_id == "res-id-2"
        assert key_package_public == b"kp-public-bytes"

    async def test_propagates_bridge_error(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.reserve_key_package.side_effect = RuntimeError(
            "reserve_key_package failed: not locally custodied"
        )
        scp = _make_scp(native)

        with pytest.raises(RuntimeError, match="not locally custodied"):
            await SCP.reserve_key_package(scp, "did:dht:z6MkStranger")


# ---------------------------------------------------------------------------
# SCP.context_join_from_welcome — mock delegation
# ---------------------------------------------------------------------------


class TestContextJoinFromWelcomeDelegation:
    """Verify :meth:`SCP.context_join_from_welcome` forwarding + wrapping.

    The wrapper projects the SDK :class:`SealedInvitation` into the native
    ``PySealedInvitation`` via ``scp_sdk.scp._to_native_sealed`` (which needs the
    extension). These pure-Python delegation tests patch that seam with an
    identity function so forwarding can be asserted against the SDK dataclass —
    the real projection is exercised by the real-FFI happy path below.
    """

    async def test_forwards_all_args_in_order(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_join_from_welcome.return_value = _MockHandle()
        scp = _make_scp(native)
        sealed = _sealed()

        with patch("scp_sdk.scp._to_native_sealed", side_effect=lambda s: s):
            await SCP.context_join_from_welcome(
                scp,
                "did:dht:z6MkJoiner",
                sealed,
                "res-id-3",
            )

        # Reshaped signature: (owning_did, sealed, reservation_id). The loose
        # creator_did/context_id/params/welcome_bytes are gone — they now travel
        # inside the sealed, authenticated bundle.
        native.context_join_from_welcome.assert_called_once_with(
            "did:dht:z6MkJoiner",
            sealed,
            "res-id-3",
        )

    async def test_returns_context_scoped_to_joiner(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_join_from_welcome.return_value = _MockHandle()
        scp = _make_scp(native)

        with patch("scp_sdk.scp._to_native_sealed", side_effect=lambda s: s):
            ctx = await SCP.context_join_from_welcome(
                scp,
                "did:dht:z6MkJoiner",
                _sealed(),
                "res-id-4",
            )

        assert isinstance(ctx, Context)
        assert ctx.context_id == "ctx-test-abc123"
        # The joined context is scoped to the JOINER, not the creator, so the
        # joiner fans out under its own derived §9.10.4 routing pseudonym.
        assert ctx.identity_did == "did:dht:z6MkJoiner"

    async def test_propagates_bridge_error(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_join_from_welcome.side_effect = RuntimeError(
            "context_join_from_welcome failed: joiner not locally custodied"
        )
        scp = _make_scp(native)

        with (
            patch("scp_sdk.scp._to_native_sealed", side_effect=lambda s: s),
            pytest.raises(RuntimeError, match="not locally custodied"),
        ):
            await SCP.context_join_from_welcome(
                scp,
                "did:dht:z6MkStranger",
                _sealed(),
                "res-id-5",
            )


# ---------------------------------------------------------------------------
# SCP.invite_member — mock delegation
# ---------------------------------------------------------------------------


class TestInviteMemberDelegation:
    """Verify :meth:`SCP.invite_member` forwarding + outcome projection.

    The wrapper forwards its five args in order to the native bridge and maps
    the returned ``PyInviteMemberOutcome`` (a ``kind`` discriminant plus
    optionals) into the SDK :data:`InviteMemberOutcome` union. Both outcome
    kinds are first-class SUCCESS results — ``requiresGovernanceApproval`` is
    NOT an error.
    """

    async def test_forwards_all_args_in_order(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.invite_member.return_value = SimpleNamespace(
            kind="sealed", enc=b"\x00" * 32, ciphertext=b"ct", delivered=True
        )
        scp = _make_scp(native)

        await SCP.invite_member(
            scp,
            _HEX_CTX_ID,
            _CREATOR_DID,
            "did:dht:z6MkInvitee",
            b"invitee-key-package",
            ["wss://relay.example"],
        )

        native.invite_member.assert_called_once_with(
            _HEX_CTX_ID,
            _CREATOR_DID,
            "did:dht:z6MkInvitee",
            b"invitee-key-package",
            ["wss://relay.example"],
        )

    async def test_maps_sealed_outcome(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.invite_member.return_value = SimpleNamespace(
            kind="sealed",
            enc=b"\x01" * 32,
            ciphertext=b"sealed-ct",
            delivered=False,
        )
        scp = _make_scp(native)

        outcome = await SCP.invite_member(
            scp, _HEX_CTX_ID, _CREATOR_DID, "did:dht:z6MkInvitee", b"kp", []
        )

        assert isinstance(outcome, Sealed)
        assert outcome.enc == b"\x01" * 32
        assert outcome.ciphertext == b"sealed-ct"
        assert outcome.delivered is False

    async def test_maps_requires_governance_approval_outcome(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.invite_member.return_value = SimpleNamespace(
            kind="requiresGovernanceApproval", proposal_id="deadbeef"
        )
        scp = _make_scp(native)

        outcome = await SCP.invite_member(
            scp, _HEX_CTX_ID, _CREATOR_DID, "did:dht:z6MkInvitee", b"kp", []
        )

        # A first-class SUCCESS outcome — NOT an exception.
        assert isinstance(outcome, RequiresGovernanceApproval)
        assert outcome.proposal_id == "deadbeef"

    async def test_unknown_kind_fails_closed(self) -> None:
        from scp_sdk.errors import ScpError
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.invite_member.return_value = SimpleNamespace(kind="somethingElse")
        scp = _make_scp(native)

        with pytest.raises(ScpError, match="unrecognized outcome kind"):
            await SCP.invite_member(
                scp, _HEX_CTX_ID, _CREATOR_DID, "did:dht:z6MkInvitee", b"kp", []
            )

    async def test_propagates_bridge_error(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.invite_member.side_effect = RuntimeError("invite_member failed: no live context")
        scp = _make_scp(native)

        with pytest.raises(RuntimeError, match="no live context"):
            await SCP.invite_member(
                scp, _HEX_CTX_ID, _CREATOR_DID, "did:dht:z6MkInvitee", b"kp", []
            )


# ---------------------------------------------------------------------------
# Real-FFI — skips without the native module (maturin develop first)
# ---------------------------------------------------------------------------

try:
    from scp_sdk import _scp_core  # noqa: F401  (installed as scp_sdk._scp_core)

    _HAS_NATIVE = True
except (ImportError, AttributeError):
    _HAS_NATIVE = False

pytestmark_native = pytest.mark.skipif(
    not _HAS_NATIVE,
    reason="Native _scp_core extension not available — run maturin develop first",
)


@pytestmark_native
class TestJoinerHandshakeRealFfi:
    """Joiner handshake through the real PyO3 bridge."""

    async def test_reserve_key_package_returns_reservation_and_public_bytes(self, scp) -> None:
        from scp_sdk.types import CustodyType

        identity = await scp.identity_create(CustodyType.IN_MEMORY)

        reservation_id, key_package_public = await scp.reserve_key_package(identity.did)

        assert isinstance(reservation_id, str)
        assert reservation_id
        # Only the PUBLIC KeyPackage bytes cross the FFI boundary.
        assert isinstance(key_package_public, (bytes, bytearray))
        assert len(key_package_public) > 0

    async def test_reserve_key_package_rejects_non_custodied_identity(self, scp) -> None:
        # A DID that was never created locally is not locally custodied — the
        # reservation must fail closed (same trust model as context_create).
        with pytest.raises(Exception):
            await scp.reserve_key_package("did:dht:z6MkNeverCustodiedHere")

    async def test_context_join_from_welcome_rejects_non_custodied_joiner(self, scp) -> None:
        # The joiner's routing pseudonym is DERIVED from its local custody. A
        # non-custodied joiner hard-fails at the derivation seam BEFORE the
        # single-use KeyPackage is consumed. `enc` is a valid 32-byte length so
        # the rejection is the custody gate, not the length precheck.
        sealed = SealedInvitation(
            context_id=_HEX_CTX_ID,
            creator_did=_CREATOR_DID,
            enc=b"\x00" * 32,
            ciphertext=b"not-a-real-sealed-bundle",
        )
        with pytest.raises(Exception):
            await scp.context_join_from_welcome(
                "did:dht:z6MkNeverCustodiedHere",
                sealed,
                "bogus-reservation-id",
            )


@pytestmark_native
class TestInviteMemberRealFfi:
    """`invite_member` through the real PyO3 bridge."""

    async def test_invite_member_rejects_unknown_context(self, scp) -> None:
        # A custodied inviter + a real context so the supervisor is attached and
        # signing-key resolution succeeds; then the live-context lookup for a
        # DIFFERENT (non-existent) context fails.
        from scp_sdk.types import CustodyType

        creator = await scp.identity_create(CustodyType.IN_MEMORY)
        await scp.context_create(creator.did, {"mode": "encrypted", "governance": "single_admin"})

        unknown_ctx = "d" * 64
        with pytest.raises(Exception, match="no live context"):
            await scp.invite_member(
                unknown_ctx,
                creator.did,
                "did:dht:z6MkInviteeUnknownCtx",
                b"bogus-key-package",
                [],
            )

    async def test_invite_member_rejects_non_custodied_inviter(self, scp) -> None:
        # A non-locally-custodied inviter fails at signing-key resolution, before
        # any context lookup.
        with pytest.raises(Exception):
            await scp.invite_member(
                "e" * 64,
                "did:dht:z6MkNoSuchInviterIdentity",
                "did:dht:z6MkInviteeUncustodied",
                b"bogus-key-package",
                [],
            )

    async def test_invite_member_seals_for_single_admin_context(self, scp) -> None:
        # Happy path: a SingleAdmin creator invites a real, KeyPackage-reserved
        # invitee. The invite is unilateral and returns a `Sealed` outcome. The
        # invitee's reserved KeyPackage declares the 0xFF02 context-binding
        # capability (§5.13.3, valn0502; fixed in 9fe3b4c9b), so the MLS add
        # succeeds instead of failing the group-context-extension round-trip.
        from scp_sdk.types import CustodyType

        creator = await scp.identity_create(CustodyType.IN_MEMORY)
        # The SingleAdmin creator must hold the invite-relevant capabilities in
        # the context ceiling (`member:invite` + `governance:propose`): the
        # add is routed through the actor's governance gate, which checks the
        # proposer's `governance:propose` capability before auto-executing.
        ctx = await scp.context_create(
            creator.did,
            {
                "mode": "encrypted",
                "governance": "single_admin",
                "ceiling": [
                    "messages:read",
                    "messages:write",
                    "role:assign",
                    "member:invite",
                    "member:remove",
                    "governance:propose",
                    "governance:vote",
                    "context:close",
                ],
            },
        )

        invitee = await scp.identity_create(CustodyType.IN_MEMORY)
        reservation_id, invitee_kp = await scp.reserve_key_package(invitee.did)
        assert reservation_id
        assert len(invitee_kp) > 0

        outcome = await scp.invite_member(ctx.context_id, creator.did, invitee.did, invitee_kp, [])

        assert isinstance(outcome, Sealed)
        # RFC 9180 HPKE encapsulated key is exactly 32 bytes.
        assert isinstance(outcome.enc, (bytes, bytearray))
        assert len(outcome.enc) == 32
        assert isinstance(outcome.ciphertext, (bytes, bytearray))
        assert len(outcome.ciphertext) > 0
        assert isinstance(outcome.delivered, bool)
