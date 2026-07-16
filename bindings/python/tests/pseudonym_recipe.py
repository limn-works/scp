"""Canonical software-custody pseudonym derivation (spec §9.10.4.A, §25.19).

Pure-Python, stdlib-only reference implementation of the cross-platform
per-context pseudonym recipe that every SCP custody backend MUST reproduce
byte-for-byte (Rust ``crates/scp-crypto/src/pseudonym.rs`` plus the per-bridge
custody callbacks; the TypeScript, Swift, and Kotlin SDKs implement the same
recipe). It exists so the Python KAT and the Python custody test fixture share
one canonical algorithm rather than re-deriving it (and risking drift) in each.

The CI Python interpreter has neither PyNaCl nor ``cryptography`` installed, so
HKDF/HMAC come from :mod:`hashlib`/:mod:`hmac` and Ed25519 public-key derivation
is a compact RFC 8032 implementation. No native extension is required, so this
module — and any test that imports it — runs under plain ``pytest``.

Recipe (matching the Rust core)::

    pseudonym_secret = HKDF-SHA256(
        ikm=ed25519_private_seed (32 bytes),
        salt=b"scp-pseudonym-secret-v1", info=b"", length=32)
    seed_v1 = HMAC-SHA256(pseudonym_secret, context_id + b"scp-pseudonym")
    seed_v2 = HMAC-SHA256(
        pseudonym_secret,
        context_id + pseudonym_epoch.to_bytes(8, "big") + b"scp-pseudonym-v2")
    pseudonym_public_key = Ed25519_keygen(seed[:32]).public_key

The blob returned by the custody callbacks is ``public_key_bytes (32) ||
key_id_utf8``; the helpers here return the same shape so they can stand in for a
real custody backend.
"""

from __future__ import annotations

import hashlib
import hmac

# Domain-separation constants — byte-for-byte identical to the Rust core.
PSEUDONYM_SECRET_SALT = b"scp-pseudonym-secret-v1"
PSEUDONYM_V1_INFO = b"scp-pseudonym"
PSEUDONYM_V2_INFO = b"scp-pseudonym-v2"

# ---------------------------------------------------------------------------
# Minimal pure-Python Ed25519 (RFC 8032) public-key derivation — stdlib only.
# Reference implementation (SUPERCOP-derived). Used solely to turn a 32-byte
# context seed into its Ed25519 public key; not exercised by production code.
# ---------------------------------------------------------------------------

_q = 2**255 - 19
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_I = pow(2, (_q - 1) // 4, _q)


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


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte RFC 8032 seed."""
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    return _encodepoint(_scalarmult(_B, a))


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) — stdlib only.
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256: extract-then-expand to ``length`` bytes."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# ---------------------------------------------------------------------------
# Canonical pseudonym derivation.
# ---------------------------------------------------------------------------


def pseudonym_secret(ed25519_seed: bytes) -> bytes:
    """Derive the 32-byte ``pseudonym_secret`` from an Ed25519 private seed."""
    return hkdf_sha256(ed25519_seed, PSEUDONYM_SECRET_SALT, b"", 32)


def canonical_pseudonym_seed(ed25519_seed: bytes, context_id: bytes) -> bytes:
    """Return the v1 (static) 32-byte context seed for a context."""
    secret = pseudonym_secret(ed25519_seed)
    return hmac.new(secret, bytes(context_id) + PSEUDONYM_V1_INFO, hashlib.sha256).digest()


def canonical_rotatable_pseudonym_seed(
    ed25519_seed: bytes, context_id: bytes, pseudonym_epoch: int
) -> bytes:
    """Return the v2 (rotatable) 32-byte context seed for a context + epoch."""
    secret = pseudonym_secret(ed25519_seed)
    data = bytes(context_id) + pseudonym_epoch.to_bytes(8, "big") + PSEUDONYM_V2_INFO
    return hmac.new(secret, data, hashlib.sha256).digest()


def canonical_pseudonym_public_key(ed25519_seed: bytes, context_id: bytes) -> bytes:
    """Return the 32-byte v1 pseudonym public key (the §25.19 KAT target)."""
    return ed25519_public_key(canonical_pseudonym_seed(ed25519_seed, context_id))


def canonical_rotatable_pseudonym_public_key(
    ed25519_seed: bytes, context_id: bytes, pseudonym_epoch: int
) -> bytes:
    """Return the 32-byte v2 pseudonym public key (the §25.19 KAT target)."""
    return ed25519_public_key(
        canonical_rotatable_pseudonym_seed(ed25519_seed, context_id, pseudonym_epoch)
    )


def canonical_pseudonym_blob(ed25519_seed: bytes, context_id: bytes, key_id: str) -> bytes:
    """Return the v1 custody blob: ``public_key (32) || key_id_utf8``."""
    return canonical_pseudonym_public_key(ed25519_seed, context_id) + key_id.encode("utf-8")


def canonical_rotatable_pseudonym_blob(
    ed25519_seed: bytes, context_id: bytes, pseudonym_epoch: int, key_id: str
) -> bytes:
    """Return the v2 custody blob: ``public_key (32) || key_id_utf8``."""
    public_key = canonical_rotatable_pseudonym_public_key(ed25519_seed, context_id, pseudonym_epoch)
    return public_key + key_id.encode("utf-8")
