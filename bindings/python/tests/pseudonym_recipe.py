"""Canonical software-custody pseudonym derivation (spec §9.10.4.A, §25.19).

Pure-Python, stdlib-only reference implementation of the cross-platform
per-context pseudonym recipe that every SCP custody backend MUST reproduce
byte-for-byte (Rust ``crates/scp-crypto/src/pseudonym.rs`` plus the per-bridge
custody callbacks; the TypeScript, Swift, and Kotlin SDKs implement the same
recipe). It gives the Python custody test fixture the context seeds and the
P-256 helper test an independent prehash signer, so neither re-derives them.

The CI Python interpreter has neither PyNaCl nor ``cryptography`` installed, so
HKDF/HMAC come from :mod:`hashlib`/:mod:`hmac` and P-256 is a compact affine
implementation. No native extension is required, so this module — and any test
that imports it — runs under plain ``pytest``. It is test code: nothing here is
constant-time.

Recipe (matching the Rust core)::

    pseudonym_secret = HKDF-SHA256(
        ikm=identity_private_key_material (32 bytes),
        salt=b"scp-pseudonym-secret-v1", info=b"", length=32)
    seed_v1 = HMAC-SHA256(pseudonym_secret, context_id + b"scp-pseudonym")
    seed_v2 = HMAC-SHA256(
        pseudonym_secret,
        context_id + pseudonym_epoch.to_bytes(8, "big") + b"scp-pseudonym-v2")
    d = int.from_bytes(
        HKDF-Expand-SHA256(prk=seed, info=b"SCP-PSEUDONYM-P256-V1", L=48), "big")
        mod (n - 1) + 1
    public_key = SEC1-compressed(d * G)          # 33 bytes

This module computes the two seeds and signs with a given ``d``; ``d`` and
``public_key`` come from the production helpers ``scp_sdk.p256_pseudonym_scalar``
and ``scp_sdk.p256_public_key``.

Until slice S12 the native identity key is Ed25519, so the ikm is its 32-byte
private seed. A custody provider's ``derive_pseudonym`` and
``derive_rotatable_pseudonym`` return a ``scp_sdk.PseudonymResult`` carrying
``public_key`` and ``key_id``;
``get_public_key(key_id)`` must return the same 33 bytes, and
``sign(key_id, digest)`` returns the 64-byte low-s ``r || s`` of
:func:`p256_sign_prehash`.
"""

from __future__ import annotations

import hashlib
import hmac

# Domain-separation constants — byte-for-byte identical to the Rust core.
PSEUDONYM_SECRET_SALT = b"scp-pseudonym-secret-v1"
PSEUDONYM_V1_INFO = b"scp-pseudonym"
PSEUDONYM_V2_INFO = b"scp-pseudonym-v2"

# ---------------------------------------------------------------------------
# Minimal P-256 (SEC 2 secp256r1) — stdlib only, affine coordinates.
# ---------------------------------------------------------------------------

_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] - 3) * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return (x, (lam * (p[0] - x) - p[1]) % _P)


def _mul(k: int, p: tuple[int, int]) -> tuple[int, int]:
    acc: tuple[int, int] | None = None
    while k:
        if k & 1:
            acc = _add(acc, p)
        p = _add(p, p)  # type: ignore[assignment]
        k >>= 1
    assert acc is not None
    return acc


def _hmac256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _rfc6979_nonce(d: int, digest: bytes) -> int:
    """RFC 6979 §3.2 nonce for P-256 with HMAC-SHA-256 (qlen = hlen = 256)."""
    x = d.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % _N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = _hmac256(k, v + b"\x00" + x + h)
    v = _hmac256(k, v)
    k = _hmac256(k, v + b"\x01" + x + h)
    v = _hmac256(k, v)
    while True:
        v = _hmac256(k, v)
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < _N:
            return candidate
        k = _hmac256(k, v + b"\x00")
        v = _hmac256(k, v)


def p256_sign_prehash(d: int, digest: bytes) -> bytes:
    """Sign a 32-byte digest (no second hash): 64-byte low-s ``r || s`` (§9.5.1)."""
    assert len(digest) == 32
    z = int.from_bytes(digest, "big")
    k = _rfc6979_nonce(d, digest)
    r = _mul(k, _G)[0] % _N
    s = pow(k, -1, _N) * (z + r * d) % _N
    if s > _N // 2:
        s = _N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) — stdlib only.
# ---------------------------------------------------------------------------


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = _hmac256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return okm[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256: extract-then-expand to ``length`` bytes."""
    return hkdf_expand_sha256(_hmac256(salt, ikm), info, length)


# ---------------------------------------------------------------------------
# Canonical pseudonym derivation.
# ---------------------------------------------------------------------------


def pseudonym_secret(ikm: bytes) -> bytes:
    """Derive the 32-byte ``pseudonym_secret`` from the identity key material."""
    return hkdf_sha256(ikm, PSEUDONYM_SECRET_SALT, b"", 32)


def canonical_pseudonym_seed(ikm: bytes, context_id: bytes) -> bytes:
    """Return the v1 (static) 32-byte context seed for a context."""
    return _hmac256(pseudonym_secret(ikm), bytes(context_id) + PSEUDONYM_V1_INFO)


def canonical_rotatable_pseudonym_seed(
    ikm: bytes, context_id: bytes, pseudonym_epoch: int
) -> bytes:
    """Return the v2 (rotatable) 32-byte context seed for a context + epoch."""
    data = bytes(context_id) + pseudonym_epoch.to_bytes(8, "big") + PSEUDONYM_V2_INFO
    return _hmac256(pseudonym_secret(ikm), data)
