"""Tests for the ADR-049 Phase 2J joiner handshake SDK wrappers.

Covers :meth:`scp_sdk.SCP.reserve_key_package` (step 1) and
:meth:`scp_sdk.SCP.context_join_from_welcome` (step 2):

- Mock-based delegation: the wrappers forward their arguments to the PyO3
  ``_native`` bridge in order, return the reservation tuple unchanged, and wrap
  the joined handle in a :class:`~scp_sdk.context.Context` scoped to the joiner.
  No Rust extension required.
- Real-FFI (skips without the native module): ``reserve_key_package`` mints a
  real single-use MLS ``KeyPackage`` for a locally-custodied identity, and both
  ops fail closed for a non-locally-custodied DID (the same trust model as
  ``context_create``).

See ``.docs/adrs/ADR-049-actor-per-context.md`` §9 (Deferred Work 1) and
``crates/scp-ffi/CLAUDE.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from scp_sdk.context import Context

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
    """Verify :meth:`SCP.context_join_from_welcome` forwarding + wrapping."""

    async def test_forwards_all_args_in_order(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_join_from_welcome.return_value = _MockHandle()
        scp = _make_scp(native)

        params = {"ceiling": ["core:send_message"]}
        await SCP.context_join_from_welcome(
            scp,
            "did:dht:z6MkJoiner",
            _CREATOR_DID,
            _HEX_CTX_ID,
            params,
            "res-id-3",
            b"welcome-bytes",
        )

        native.context_join_from_welcome.assert_called_once_with(
            "did:dht:z6MkJoiner",
            _CREATOR_DID,
            _HEX_CTX_ID,
            params,
            "res-id-3",
            b"welcome-bytes",
        )

    async def test_returns_context_scoped_to_joiner(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_join_from_welcome.return_value = _MockHandle()
        scp = _make_scp(native)

        ctx = await SCP.context_join_from_welcome(
            scp,
            "did:dht:z6MkJoiner",
            _CREATOR_DID,
            _HEX_CTX_ID,
            {"ceiling": ["core:send_message"]},
            "res-id-4",
            b"welcome-bytes",
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

        with pytest.raises(RuntimeError, match="not locally custodied"):
            await SCP.context_join_from_welcome(
                scp,
                "did:dht:z6MkStranger",
                _CREATOR_DID,
                _HEX_CTX_ID,
                {"ceiling": ["core:send_message"]},
                "res-id-5",
                b"welcome-bytes",
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
        # single-use KeyPackage is consumed.
        with pytest.raises(Exception):
            await scp.context_join_from_welcome(
                "did:dht:z6MkNeverCustodiedHere",
                _CREATOR_DID,
                _HEX_CTX_ID,
                {"ceiling": ["core:send_message"]},
                "bogus-reservation-id",
                b"not-a-real-welcome",
            )
