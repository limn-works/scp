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

import pytest

from scp_sdk.errors import KeyNotFoundError

from .pseudonym_recipe import (
    canonical_pseudonym_seed,
    canonical_rotatable_pseudonym_seed,
    p256_compressed,
    p256_sign_prehash,
    pseudonym_scalar,
)

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

    def __init__(self) -> None:
        self._seeds: dict[str, bytes] = {}
        # Pseudonym key id -> P-256 private scalar (§9.10.4).
        self._pseudonyms: dict[str, int] = {}
        # Pseudonym key id -> the identity key id it was derived from, so
        # destroying the identity destroys its pseudonyms (§9.10.4.A).
        self._pseudonym_owner: dict[str, str] = {}
        # Key id -> the role generate_keypair minted it in.
        self._roles: dict[str, str] = {}
        self._next = 1

    def generate_keypair(self, key_type: str, role: str) -> str:
        kid = str(self._next)
        self._next += 1
        self._roles[kid] = role
        # Deterministic-per-id seed keeps the test reproducible while still
        # producing a valid Ed25519 key.
        self._seeds[kid] = hashlib.sha256(b"scp-test-custody/" + kid.encode()).digest()
        return kid

    def sign(self, key_id: str, message: bytes) -> bytes:
        if key_id in self._pseudonyms:
            # A pseudonym key signs a 32-byte digest: 64-byte low-s r || s.
            return p256_sign_prehash(self._pseudonyms[key_id], bytes(message))
        return ed25519_sign(self._seeds[key_id], bytes(message))

    def get_public_key(self, key_id: str) -> tuple[str, bytes, str]:
        if key_id in self._pseudonyms:
            return "p256", p256_compressed(self._pseudonyms[key_id]), "operational"
        if key_id not in self._seeds:
            raise KeyNotFoundError(f"unknown key id: {key_id}")
        return "ed25519", ed25519_publickey(self._seeds[key_id]), self._roles[key_id]

    def destroy_key(self, key_id: str) -> None:
        self._seeds.pop(key_id, None)
        self._roles.pop(key_id, None)
        self._pseudonyms.pop(key_id, None)
        self._pseudonym_owner.pop(key_id, None)
        # A pseudonym dies with its identity (§9.10.4.A).
        owned = [kid for kid, owner in self._pseudonym_owner.items() if owner == key_id]
        for kid in owned:
            self._pseudonyms.pop(kid, None)
            del self._pseudonym_owner[kid]

    def dh_agree(self, key_id: str, peer_public: bytes) -> bytes:
        # Not exercised by identity_create_with_custody; a deterministic
        # stand-in keeps the protocol surface complete.
        return hashlib.sha256(self._seeds[key_id] + bytes(peer_public)).digest()

    @staticmethod
    def _pseudonym_key_id(identity: str, context_id: bytes, epoch: int | None) -> str:
        # The provider contract requires the same (identity, context, epoch) to
        # name the same key. The top bit keeps the id clear of the small
        # sequential identity ids.
        ident = identity.encode()
        h = hashlib.sha256(b"fake-keychain-pseudonym-id")
        h.update(len(ident).to_bytes(4, "big") + len(context_id).to_bytes(4, "big"))
        h.update(ident + bytes(context_id))
        if epoch is not None:
            h.update(epoch.to_bytes(8, "big"))
        return str(int.from_bytes(h.digest()[:8], "big") | (1 << 63))

    def _register_pseudonym(self, owner: str, seed: bytes, kid: str) -> tuple[bytes, str]:
        d = pseudonym_scalar(seed)
        self._pseudonyms[kid] = d
        self._pseudonym_owner[kid] = owner
        return p256_compressed(d), kid

    def derive_pseudonym(self, key_id: str, context_id: bytes) -> tuple[bytes, str]:
        # Canonical v1 recipe (§9.10.4.A) over the Ed25519 identity seed (the
        # native interim ikm until S12). Registers the P-256 pseudonym key under
        # its deterministic id and returns ``(public_key (33), key_id)``.
        return self._register_pseudonym(
            key_id,
            canonical_pseudonym_seed(self._seeds[key_id], context_id),
            self._pseudonym_key_id(key_id, context_id, None),
        )

    def derive_rotatable_pseudonym(
        self, key_id: str, context_id: bytes, pseudonym_epoch: int
    ) -> tuple[bytes, str]:
        # Canonical v2 recipe (§9.10.4.A): HMAC(context_id || epoch_BE ||
        # "scp-pseudonym-v2"). Same return shape as the v1 path.
        seed = canonical_rotatable_pseudonym_seed(self._seeds[key_id], context_id, pseudonym_epoch)
        return self._register_pseudonym(
            key_id, seed, self._pseudonym_key_id(key_id, context_id, pseudonym_epoch)
        )

    def export_signing_key_bytes(self, key_id: str) -> bytes:
        return self._seeds[key_id]

    def custody_type(self, key_id: str) -> str:
        return "software"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_destroying_an_identity_destroys_its_pseudonyms() -> None:
    """A pseudonym handle fails once its identity is destroyed (§9.10.4.A).

    Covers the v1 and the v2 derivation, and leaves another identity's
    pseudonym signing.
    """
    provider = _FakeKeychain()
    identity = provider.generate_keypair("ed25519")
    other = provider.generate_keypair("ed25519")
    _, v1 = provider.derive_pseudonym(identity, b"ctx")
    _, v2 = provider.derive_rotatable_pseudonym(identity, b"ctx", 3)
    _, kept = provider.derive_pseudonym(other, b"ctx")
    digest = hashlib.sha256(b"message").digest()
    assert len(provider.sign(v1, digest)) == 64
    assert len(provider.sign(v2, digest)) == 64

    provider.destroy_key(identity)

    for kid in (v1, v2):
        with pytest.raises(KeyError):
            provider.sign(kid, digest)
        with pytest.raises(KeyNotFoundError):
            provider.get_public_key(kid)
    assert len(provider.sign(kept, digest)) == 64


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
