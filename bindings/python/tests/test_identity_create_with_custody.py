"""Integration test for ``SCP.identity_create_with_custody`` (ADR-006).

Exercises the caller-provided :class:`~scp_sdk.scp.KeyCustodyProvider` path
end-to-end: a Python custody object generates a real Ed25519 keypair, the
bridge drives ``DidDht::create`` against it (signing the DID document via the
provider's ``sign`` callback), and the resulting :class:`Identity` carries a
``did:dht:`` value plus the provider-derived verifying key.

The provider is backed by a compact, dependency-free Ed25519 (RFC 8032)
implementation so the test runs against the stdlib alone — the CI Python
interpreter has neither PyNaCl nor ``cryptography`` installed. The numbers are
real Ed25519 keys: ``DidDht::create`` self-certifies the document, so a fake
signature would fail document validation. This proves the full delegation
contract (generate → public_key → sign), not just argument plumbing.

Requires the native extension built with ``testing``::

    maturin develop --release --features testing
"""

from __future__ import annotations

import hashlib
from typing import Literal

import pytest

from scp_sdk import (
    CustodyKeyRole,
    CustodyKeyType,
    CustodyPublicKey,
    p256_software_pseudonym_point,
)
from scp_sdk.errors import KeyNotFoundError

# ---------------------------------------------------------------------------
# Minimal pure-Python Ed25519 (RFC 8032) — stdlib only.
# Reference implementation (SUPERCOP-derived). Used solely to back the test
# custody provider with real keys; not exercised by production code.
# ---------------------------------------------------------------------------

_q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _h(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, p)
    return q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def ed25519_publickey(sk: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    h = _h(sk)
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    return _encodepoint(_scalarmult(_B, a))


def ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over ``msg`` with seed ``sk``."""
    h = _h(sk)
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    pub = _encodepoint(_scalarmult(_B, a))
    r = int.from_bytes(_h(h[32:64] + msg), "little") % _L
    big_r = _scalarmult(_B, r)
    s = (r + int.from_bytes(_h(_encodepoint(big_r) + pub + msg), "little") * a) % _L
    return _encodepoint(big_r) + _encodeint(s)


# ---------------------------------------------------------------------------
# Test custody provider
# ---------------------------------------------------------------------------


class _FakeKeychain:
    """In-memory :class:`KeyCustodyProvider` backed by real Ed25519 keys.

    Stands in for a platform keystore. Key ids are numeric strings; the seed
    bytes never leave this object except via ``export_signing_key_bytes`` /
    ``sign``, mirroring how a real keychain would behave.
    """

    def __init__(
        self,
        *,
        tuple_result: bool = False,
        fault: Literal["legacy32"] | None = None,
    ) -> None:
        # ``tuple_result`` makes both derive methods return the retired
        # ``(point, key_id)`` pair in place of the point bytes, the shape
        # mistake the bridge must name.
        self._tuple_result = tuple_result
        # ``fault="legacy32"`` makes the host return the retired 32-byte
        # Ed25519 pseudonym shape, which the bridge must reject (§9.10.4).
        self._fault = fault
        self._seeds: dict[str, bytes] = {}
        # Every (identity key id, context) a derivation received.
        self.derive_calls: list[tuple[str, bytes]] = []
        # Key id -> the role generate_keypair minted it in.
        self._roles: dict[str, CustodyKeyRole] = {}
        self._next = 1

    def generate_keypair(self, key_type: CustodyKeyType, role: CustodyKeyRole) -> str:
        kid = str(self._next)
        self._next += 1
        self._roles[kid] = role
        # Deterministic-per-id seed keeps the test reproducible while still
        # producing a valid Ed25519 key.
        self._seeds[kid] = hashlib.sha256(b"scp-test-custody/" + kid.encode()).digest()
        return kid

    def sign(self, key_id: str, message: bytes) -> bytes:
        return ed25519_sign(self._seeds[key_id], bytes(message))

    def get_public_key(self, key_id: str) -> CustodyPublicKey:
        if key_id not in self._seeds:
            raise KeyNotFoundError(f"unknown key id: {key_id}")
        return CustodyPublicKey(
            key_type="ed25519",
            public_key=ed25519_publickey(self._seeds[key_id]),
            role=self._roles[key_id],
        )

    def destroy_key(self, key_id: str) -> None:
        self._seeds.pop(key_id, None)
        self._roles.pop(key_id, None)

    def dh_agree(self, key_id: str, peer_public: bytes) -> bytes:
        # Not exercised by identity_create_with_custody; a deterministic
        # stand-in keeps the protocol surface complete.
        return hashlib.sha256(self._seeds[key_id] + bytes(peer_public)).digest()

    def _point(self, key_id: str, context_id: bytes, epoch: int | None = None) -> bytes:
        # The SDK's software helper derives the point from the Ed25519
        # identity seed (the native interim ikm until the identity key moves to
        # P-256, SCP-315). Nothing is stored.
        point = p256_software_pseudonym_point(self._seeds[key_id], bytes(context_id), epoch)
        if self._fault == "legacy32":
            point = point[1:]
        if self._tuple_result:
            return (point, "1")  # type: ignore[return-value]
        return point

    def derive_pseudonym(self, key_id: str, context_id: bytes) -> bytes:
        # The v1 recipe (§9.10.4.A).
        self.derive_calls.append((key_id, bytes(context_id)))
        return self._point(key_id, context_id)

    def derive_rotatable_pseudonym(
        self, key_id: str, context_id: bytes, pseudonym_epoch: int
    ) -> bytes:
        # The v2 recipe (§9.10.4.1) at the epoch. Same return shape as the v1
        # path.
        self.derive_calls.append((key_id, bytes(context_id)))
        return self._point(key_id, context_id, pseudonym_epoch)

    def export_signing_key_bytes(self, key_id: str) -> bytes:
        return self._seeds[key_id]

    def custody_type(self, key_id: str) -> str:
        return "software"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_identity_create_with_custody_produces_did(scp) -> None:
    """A satisfying provider yields a did:dht identity with a verifying key."""
    from scp_sdk.scp import KeyCustodyProvider

    provider = _FakeKeychain()
    # The provider object structurally satisfies the runtime-checkable
    # protocol — a quick sanity guard mirroring what callers would assert.
    assert isinstance(provider, KeyCustodyProvider)

    identity = await scp.identity_create_with_custody(provider)

    assert identity.did.startswith("did:dht:"), f"unexpected DID: {identity.did}"
    # Custody is reported as the callback path.
    assert identity.custody_type == "callback"
    # The #0 verifying key is snapshotted from the provider's public key.
    # Exposed on the raw bridge handle as `verifying_key` (32 raw bytes =
    # 64 hex chars).
    verifying_key = identity._raw_handle.verifying_key
    assert verifying_key is not None
    assert len(verifying_key) == 64, "verifying_key is 32 raw bytes = 64 hex chars"
    # The provider was actually driven: at least the identity key was generated.
    assert provider._seeds, "provider.generate_keypair was never called"


@pytest.mark.asyncio
async def test_identity_create_with_custody_rejects_incomplete_provider(scp) -> None:
    """A provider missing required methods is rejected before any crypto work.

    The bridge raises the native ``_scp_core.ValidationError`` (``SCP-VALID-7005``)
    up-front — identity creation siblings propagate native bridge exceptions
    unchanged, so we assert against the native type plus the actionable message.
    """
    from scp_sdk import _scp_core

    class Incomplete:
        def sign(self, key_id: str, message: bytes) -> bytes:
            return b""

    with pytest.raises(_scp_core.ValidationError, match="missing the required method"):
        await scp.identity_create_with_custody(Incomplete())


_ENCRYPTED_PARAMS = {"ceiling": ["messages:read"], "memory_scope": "ephemeral"}


@pytest.mark.asyncio
async def test_point_provider_derives_in_context_create(scp) -> None:
    """An encrypted ``context_create`` succeeds with a provider returning the
    pseudonym point, and it drives that provider to derive one."""
    provider = _FakeKeychain()
    identity = await scp.identity_create_with_custody(provider)
    before = len(provider.derive_calls)
    ctx = await scp.context_create(identity.did, _ENCRYPTED_PARAMS)

    assert ctx.context_id
    assert len(provider.derive_calls) > before, "context_create never derived a pseudonym"


@pytest.mark.asyncio
async def test_32_byte_host_pseudonym_fails_context_create_with_ident_1055(scp) -> None:
    """§9.10.4: the bridge fails closed with ``SCP-IDENT-1055`` on host
    pseudonym bytes that are not a compressed P-256 point, such as the retired
    32-byte Ed25519 key."""
    from scp_sdk import _scp_core

    provider = _FakeKeychain(fault="legacy32")
    identity = await scp.identity_create_with_custody(provider)
    with pytest.raises(_scp_core.ScpError, match="got 32 bytes") as excinfo:
        await scp.context_create(identity.did, _ENCRYPTED_PARAMS)
    assert str(excinfo.value).startswith("[SCP-IDENT-1055]"), excinfo.value


@pytest.mark.asyncio
async def test_tuple_pseudonym_result_fails_naming_the_expected_shape(scp) -> None:
    """A provider whose derive returns the retired ``(point, key_id)`` pair
    fails, and the error text names the expected bytes."""
    from scp_sdk import _scp_core

    provider = _FakeKeychain(tuple_result=True)
    identity = await scp.identity_create_with_custody(provider)

    expected = r"expected bytes: the 33-byte compressed P-256 pseudonym point"
    with pytest.raises(_scp_core.ScpError, match=expected) as excinfo:
        await scp.context_create(identity.did, _ENCRYPTED_PARAMS)
    assert str(excinfo.value).startswith("[SCP-CRYPTO-4060]"), excinfo.value


@pytest.mark.asyncio
async def test_coroutine_derive_fails_with_custody_error(scp) -> None:
    """A provider whose derive is an ``async def`` returns a coroutine, which is
    the wrong type: the operation fails with ``SCP-CRYPTO-4060``, not
    ``SCP-IDENT-1055``."""
    from scp_sdk import _scp_core

    class _AsyncDerive(_FakeKeychain):
        async def derive_pseudonym(  # type: ignore[override]
            self, key_id: str, context_id: bytes
        ) -> bytes:
            return super().derive_pseudonym(key_id, context_id)

    provider = _AsyncDerive()
    identity = await scp.identity_create_with_custody(provider)
    with pytest.raises(_scp_core.ScpError, match="coroutine") as excinfo:
        await scp.context_create(identity.did, _ENCRYPTED_PARAMS)
    assert str(excinfo.value).startswith("[SCP-CRYPTO-4060]"), excinfo.value


@pytest.mark.asyncio
async def test_key_not_found_error_from_the_host_reaches_the_caller_as_4006(scp) -> None:
    """A host that raises :class:`KeyNotFoundError` for a key id it does not
    hold fails the operation with key-not-found ``SCP-CRYPTO-4006``, not the
    custody error ``SCP-CRYPTO-4060``: the bridge reads the class's code."""
    from scp_sdk import _scp_core

    class _ForgetsEveryKey(_FakeKeychain):
        def get_public_key(self, key_id: str) -> CustodyPublicKey:
            raise KeyNotFoundError(f"unseen key id: {key_id}")

    with pytest.raises(_scp_core.ScpError) as excinfo:
        await scp.identity_create_with_custody(_ForgetsEveryKey())
    assert str(excinfo.value).startswith("[SCP-CRYPTO-4006]"), excinfo.value
