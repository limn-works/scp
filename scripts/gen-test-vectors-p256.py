#!/usr/bin/env python3.12
"""Regenerates every keyed value printed in `.docs/specs/25-test-vectors.md`.

SCP superseded Ed25519 with ECDSA on NIST P-256 on 2026-09-10
(`.docs/specs/09-security-model.md` §9.5). This script is the authority for
every byte §25 prints that depends on a key or a signature. It implements
P-256 field and point arithmetic, RFC 6979 deterministic ECDSA with SHA-256,
low-`s` normalization, SEC1 point encoding, HKDF-SHA256, HMAC-SHA256, the
§9.5.1 canonical hash construction, the RFC 6962 Merkle construction, and the
MessagePack subset the SCP structures serializes into.

The script depends on nothing outside the Python standard library. Every
public key it derives is computed twice, by two independent scalar
multiplications (a Jacobian ladder and an affine double-and-add), and a third
time through the `cryptography` package when that package imports. A mismatch
raises before anything is printed.

Run it from the repository root:

    python3.12 scripts/gen-test-vectors-p256.py

The output is deterministic: the same tree prints the same bytes on every run.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import sys

# ---------------------------------------------------------------------------
# NIST P-256 (secp256r1) domain parameters — FIPS 186-5 / SEC2 §2.4.2
# ---------------------------------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HALF_N = N // 2

Point = tuple[int, int] | None


# ---------------------------------------------------------------------------
# Implementation A — Jacobian coordinates, MSB-first double-and-add
# ---------------------------------------------------------------------------


def _jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = pt
    if y == 0 or z == 0:
        return (0, 0, 0)
    delta = (z * z) % P
    gamma = (y * y) % P
    beta = (x * gamma) % P
    alpha = (3 * (x - delta) * (x + delta)) % P
    x3 = (alpha * alpha - 8 * beta) % P
    z3 = ((y + z) * (y + z) - gamma - delta) % P
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % P
    return (x3, y3, z3)


def _jac_add(
    p1: tuple[int, int, int], p2: tuple[int, int, int]
) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1z1 = (z1 * z1) % P
    z2z2 = (z2 * z2) % P
    u1 = (x1 * z2z2) % P
    u2 = (x2 * z1z1) % P
    s1 = (y1 * z2 * z2z2) % P
    s2 = (y2 * z1 * z1z1) % P
    if u1 == u2:
        if s1 != s2:
            return (0, 0, 0)
        return _jac_double(p1)
    h = (u2 - u1) % P
    i = (2 * h) % P
    i = (i * i) % P
    j = (h * i) % P
    r = (2 * (s2 - s1)) % P
    v = (u1 * i) % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = (((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h) % P
    return (x3, y3, z3)


def _jac_to_affine(pt: tuple[int, int, int]) -> Point:
    x, y, z = pt
    if z == 0:
        return None
    zinv = pow(z, P - 2, P)
    zinv2 = (zinv * zinv) % P
    return ((x * zinv2) % P, (y * zinv2 * zinv) % P)


def scalar_mult_jacobian(k: int, point: Point) -> Point:
    """Scalar multiplication in Jacobian coordinates (implementation A)."""
    if point is None or k % N == 0:
        return None
    acc = (0, 0, 0)
    cur = (point[0], point[1], 1)
    for bit in bin(k)[2:]:
        acc = _jac_double(acc)
        if bit == "1":
            acc = _jac_add(acc, cur)
    return _jac_to_affine(acc)


# ---------------------------------------------------------------------------
# Implementation B — affine coordinates, LSB-first double-and-add
#
# B shares no line of arithmetic with A. Every public key below is computed by
# both, and the two results are compared before the key is used.
# ---------------------------------------------------------------------------


def _affine_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult_affine(k: int, point: Point) -> Point:
    """Scalar multiplication in affine coordinates (implementation B)."""
    if point is None or k % N == 0:
        return None
    result: Point = None
    addend = point
    k = k % N
    while k:
        if k & 1:
            result = _affine_add(result, addend)
        addend = _affine_add(addend, addend)
        k >>= 1
    return result


G: Point = (GX, GY)


def on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


# ---------------------------------------------------------------------------
# SEC1 point encoding (§9.5: 33-byte compressed for signature-verification
# keys, 65-byte uncompressed for MLS and DHKEM(P-256) keys)
# ---------------------------------------------------------------------------


def encode_compressed(point: Point) -> bytes:
    assert point is not None, "the point at infinity has no SEC1 encoding"
    x, y = point
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def encode_uncompressed(point: Point) -> bytes:
    assert point is not None, "the point at infinity has no SEC1 encoding"
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def decode_point(encoded: bytes) -> Point:
    if encoded[0] == 0x04:
        assert len(encoded) == 65
        return (
            int.from_bytes(encoded[1:33], "big"),
            int.from_bytes(encoded[33:65], "big"),
        )
    assert len(encoded) == 33 and encoded[0] in (0x02, 0x03)
    x = int.from_bytes(encoded[1:], "big")
    alpha = (x * x * x + A * x + B) % P
    y = pow(alpha, (P + 1) // 4, P)
    if y % 2 != encoded[0] & 1:
        y = P - y
    return (x, y)


# ---------------------------------------------------------------------------
# Hashes and key-derivation functions
# ---------------------------------------------------------------------------


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def seed_to_scalar(seed: bytes, label: bytes) -> int:
    """FIPS 186-5 Appendix A.2.1, the extra-random-bits method.

    §9.10.4 of the security-model spec states this rule in full: expand the
    seed to 48 bytes with HKDF-Expand-SHA256 under `label`, read those bytes
    as a big-endian integer, reduce modulo `n - 1`, and add one. The result
    lies in `[1, n - 1]`.
    """
    expanded = hkdf_expand(seed, label, 48)
    return (int.from_bytes(expanded, "big") % (N - 1)) + 1


# ---------------------------------------------------------------------------
# Keypairs, with the independent cross-checks C2 requires
# ---------------------------------------------------------------------------

try:  # pragma: no cover - the check is stronger when the package is present
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _ec = None
    _HAVE_CRYPTOGRAPHY = False


class KeyPair:
    """A P-256 keypair whose public point three implementations agree on."""

    def __init__(self, scalar: int, name: str) -> None:
        assert 1 <= scalar <= N - 1, f"{name}: scalar outside [1, n-1]"
        self.name = name
        self.d = scalar
        point_a = scalar_mult_jacobian(scalar, G)
        point_b = scalar_mult_affine(scalar, G)
        assert point_a == point_b, f"{name}: the two scalar multiplications disagree"
        assert on_curve(point_a), f"{name}: derived point is not on P-256"
        if _HAVE_CRYPTOGRAPHY:
            reference = (
                _ec.derive_private_key(scalar, _ec.SECP256R1())
                .public_key()
                .public_numbers()
            )
            assert point_a == (reference.x, reference.y), (
                f"{name}: the cryptography package computed a different public key"
            )
        self.point = point_a

    @property
    def compressed(self) -> bytes:
        return encode_compressed(self.point)

    @property
    def uncompressed(self) -> bytes:
        return encode_uncompressed(self.point)

    @property
    def private_bytes(self) -> bytes:
        return self.d.to_bytes(32, "big")


def keypair_from_seed(seed: bytes, label: bytes, name: str) -> KeyPair:
    return KeyPair(seed_to_scalar(seed, label), name)


# ---------------------------------------------------------------------------
# RFC 6979 deterministic ECDSA over a prehashed 32-byte digest
# ---------------------------------------------------------------------------


def _bits2int(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - N.bit_length()
    return value >> excess if excess > 0 else value


def _int2octets(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _bits2octets(data: bytes) -> bytes:
    z1 = _bits2int(data)
    z2 = z1 - N
    return _int2octets(z2 if z2 >= 0 else z1)


class Rfc6979Nonces:
    """RFC 6979 §3.2 with HMAC-SHA256, over an already-computed digest.

    RFC 6979 §3.2 step h continues the HMAC-DRBG from where the previous
    candidate left off, so a signer that rejects a candidate draws the NEXT
    one rather than re-running the derivation and drawing the same one again.
    This is an iterator for that reason: re-calling a plain function would not
    terminate on the r == 0 or s == 0 branches of `ecdsa_sign`.
    """

    def __init__(self, d: int, digest: bytes) -> None:
        v = b"\x01" * 32
        k = b"\x00" * 32
        m = _int2octets(d) + _bits2octets(digest)
        k = hmac_sha256(k, v + b"\x00" + m)
        v = hmac_sha256(k, v)
        k = hmac_sha256(k, v + b"\x01" + m)
        self._k = k
        self._v = hmac_sha256(k, v)

    def __next__(self) -> int:
        while True:
            self._v = hmac_sha256(self._k, self._v)
            candidate = _bits2int(self._v)
            if 1 <= candidate <= N - 1:
                return candidate
            self._k = hmac_sha256(self._k, self._v + b"\x00")
            self._v = hmac_sha256(self._k, self._v)


def rfc6979_nonce(d: int, digest: bytes) -> int:
    """The first RFC 6979 candidate, which is the one every vector here uses."""
    return next(Rfc6979Nonces(d, digest))


def ecdsa_sign(d: int, digest: bytes, *, low_s: bool = True) -> bytes:
    """Signs a 32-byte digest, returning the 64-byte raw `r || s` form (§9.5)."""
    e = _bits2int(digest)
    nonces = Rfc6979Nonces(d, digest)
    while True:
        k = next(nonces)
        point = scalar_mult_jacobian(k, G)
        assert point is not None
        r = point[0] % N
        if r == 0:
            continue
        s = (pow(k, N - 2, N) * (e + r * d)) % N
        if s == 0:
            continue
        if low_s and s > HALF_N:
            s = N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ecdsa_verify(public: Point, digest: bytes, signature: bytes) -> bool:
    """Verifies a 64-byte raw signature, rejecting high-`s` per §9.5."""
    if len(signature) != 64 or public is None:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r <= N - 1 and 1 <= s <= N - 1):
        return False
    if s > HALF_N:
        return False
    e = _bits2int(digest)
    w = pow(s, N - 2, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    point = _affine_add(scalar_mult_jacobian(u1, G), scalar_mult_jacobian(u2, public))
    if point is None:
        return False
    return point[0] % N == r


# ---------------------------------------------------------------------------
# §9.5.1 canonical hash construction
# ---------------------------------------------------------------------------

ABSENT_SENTINEL = sha256(b"\x00")


def var_field(value: bytes | str) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return len(raw).to_bytes(4, "big") + raw


def fixed_field(value: bytes) -> bytes:
    return value


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u8(value: int) -> bytes:
    return bytes([value])


def absent_var() -> bytes:
    """An absent optional whose present form carries a length prefix."""
    return u32(32) + ABSENT_SENTINEL


def absent_fixed() -> bytes:
    """An absent optional whose present form is fixed-length."""
    return ABSENT_SENTINEL


def canonical_preimage(domain: str, *fields: bytes) -> bytes:
    return domain.encode() + b"".join(fields)


# ---------------------------------------------------------------------------
# RFC 6962 Merkle construction (§9.5)
# ---------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00", data)


def interior_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01", left, right)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return interior_hash(merkle_root(leaves[:split]), merkle_root(leaves[split:]))


# ---------------------------------------------------------------------------
# Envelope padding (§9.10.3)
# ---------------------------------------------------------------------------

BUCKETS = [256, 1024, 4096, 16384, 65536, 262144]


def pad(payload: bytes) -> bytes:
    needed = len(payload) + 4
    for bucket in BUCKETS:
        if needed <= bucket:
            return payload + b"\x00" * (bucket - needed) + u32(len(payload))
    raise ValueError("PayloadTooLarge")


# ---------------------------------------------------------------------------
# MessagePack subset
#
# Three SCP structures reach MessagePack: the identity-link attestation's
# sub-structures (`rmp_serde::to_vec_named`, a name-keyed map), the event-log
# `Event` and its payloads (`rmp_serde::to_vec`, positional arrays), and the
# `DataProvenance` record (positional). rmp-serde writes a Rust unit enum
# variant as the variant's name, a fixed-size byte array as an array of
# integers, and a `serde_bytes` field as a MessagePack binary.
# ---------------------------------------------------------------------------


def mp_str(value: str) -> bytes:
    raw = value.encode()
    if len(raw) < 32:
        return bytes([0xA0 | len(raw)]) + raw
    if len(raw) < 256:
        return b"\xd9" + bytes([len(raw)]) + raw
    return b"\xda" + len(raw).to_bytes(2, "big") + raw


def mp_bin(raw: bytes) -> bytes:
    if len(raw) < 256:
        return b"\xc4" + bytes([len(raw)]) + raw
    return b"\xc5" + len(raw).to_bytes(2, "big") + raw


def mp_uint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return b"\xcc" + bytes([value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_array(items: list[bytes]) -> bytes:
    if len(items) < 16:
        head = bytes([0x90 | len(items)])
    else:
        head = b"\xdc" + len(items).to_bytes(2, "big")
    return head + b"".join(items)


def mp_map(pairs: list[tuple[str, bytes]]) -> bytes:
    if len(pairs) < 16:
        head = bytes([0x80 | len(pairs)])
    else:
        head = b"\xde" + len(pairs).to_bytes(2, "big")
    return head + b"".join(mp_str(key) + value for key, value in pairs)


def mp_byte_array(raw: bytes) -> bytes:
    """A Rust `[u8; N]` without `serde_bytes`: an array of N integers."""
    return mp_array([mp_uint(byte) for byte in raw])


def mp_none() -> bytes:
    return b"\xc0"


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def hexs(raw: bytes) -> str:
    return binascii.hexlify(raw).decode()


_LINES: list[str] = []


def emit(label: str, value: object) -> None:
    _LINES.append(f"{label} = {value}")


def emit_hex(label: str, raw: bytes) -> None:
    emit(label, "0x" + hexs(raw))


def section(title: str) -> None:
    _LINES.append("")
    _LINES.append(f"--- {title} ---")


# ---------------------------------------------------------------------------
# Self-tests. Every one of these runs before a single vector is emitted.
# ---------------------------------------------------------------------------


def self_test() -> None:
    # SHA-256 sanity (§25.17 step 1).
    assert (
        hexs(sha256(b""))
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    # RFC 6979 §A.2.5 — P-256, SHA-256, message "sample". The published
    # nonce, r, and s pin the deterministic-nonce construction end to end.
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    pair = KeyPair(d, "RFC 6979 A.2.5")
    assert (
        f"{pair.point[0]:064x}"
        == "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    ), "RFC 6979 A.2.5 public key mismatch"
    digest = sha256(b"sample")
    assert (
        f"{rfc6979_nonce(d, digest):064x}"
        == "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60"
    ), "RFC 6979 A.2.5 nonce mismatch"
    raw = ecdsa_sign(d, digest, low_s=False)
    assert hexs(raw[:32]) == (
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    ), "RFC 6979 A.2.5 r mismatch"
    assert hexs(raw[32:]) == (
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ), "RFC 6979 A.2.5 s mismatch"

    # The A.2.5 signature carries a high `s`, so §9.5's low-`s` rule rejects
    # it and accepts the normalized form of the same signature.
    assert not ecdsa_verify(pair.point, digest, raw), "high-`s` must be rejected"
    normalized = ecdsa_sign(d, digest, low_s=True)
    assert ecdsa_verify(pair.point, digest, normalized), "low-`s` must verify"

    # Point encoding round-trips.
    assert decode_point(encode_compressed(pair.point)) == pair.point
    assert decode_point(encode_uncompressed(pair.point)) == pair.point

    # HKDF-SHA256 — RFC 5869 §A.1 test case 1.
    okm = hkdf(
        ikm=bytes([0x0B] * 22),
        salt=bytes(range(0x0D)),
        info=bytes(range(0xF0, 0xFA)),
        length=42,
    )
    assert hexs(okm) == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), "RFC 5869 A.1 mismatch"

    # The MessagePack subset, against the §25.8 Vector 35 `DataProvenance`
    # hash, which is curve-independent and predates the P-256 change.
    assert hexs(sha256(data_provenance_bytes())) == (
        "12ea6cf53e3e2fe1c851214d6c9b1acf1338e835bcb91271c8bcdf04e553ce68"
    ), "DataProvenance MessagePack mismatch"


# ---------------------------------------------------------------------------
# §25.2 Reference key material
# ---------------------------------------------------------------------------

# The two 32-byte seeds SCP's test vectors have carried since the Ed25519 era.
# They are retained so the corpus's provenance stays legible; under P-256 they
# are inputs to the seed-to-scalar rule below and nothing more.
REF_SEED_1 = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
REF_SEED_2 = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
REF_SEED_3 = bytes.fromhex(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
)

# The HKDF-Expand label §25.2 defines for its own fixtures. It names no
# protocol object, so §9.18.2 registers no separator for it.
TEST_VECTOR_KEY_LABEL = b"SCP-TEST-VECTOR-KEY-V1"

REF_KEY_1 = keypair_from_seed(REF_SEED_1, TEST_VECTOR_KEY_LABEL, "reference key")
REF_KEY_2 = keypair_from_seed(REF_SEED_2, TEST_VECTOR_KEY_LABEL, "secondary key")
REF_KEY_3 = keypair_from_seed(REF_SEED_3, TEST_VECTOR_KEY_LABEL, "tertiary key")


def emit_reference_keys() -> None:
    section("§25.2 Reference key material")
    emit_hex("seed_1", REF_SEED_1)
    emit_hex("scalar_1", REF_KEY_1.private_bytes)
    emit_hex("public_1_compressed", REF_KEY_1.compressed)
    emit_hex("public_1_uncompressed", REF_KEY_1.uncompressed)
    emit_hex("seed_2", REF_SEED_2)
    emit_hex("scalar_2", REF_KEY_2.private_bytes)
    emit_hex("public_2_compressed", REF_KEY_2.compressed)
    emit_hex("public_2_uncompressed", REF_KEY_2.uncompressed)
    emit_hex("seed_3", REF_SEED_3)
    emit_hex("scalar_3", REF_KEY_3.private_bytes)
    emit_hex("public_3_compressed", REF_KEY_3.compressed)
    emit_hex("public_3_uncompressed", REF_KEY_3.uncompressed)


def sign_and_emit(label: str, preimage: bytes, key: KeyPair = REF_KEY_1) -> bytes:
    """Emits a preimage, its canonical hash, and the RFC 6979 signature."""
    digest = sha256(preimage)
    signature = ecdsa_sign(key.d, digest)
    assert ecdsa_verify(key.point, digest, signature), f"{label}: signature rejected"
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(key, digest, signature, label)
    emit(f"{label}.preimage_len", len(preimage))
    emit_hex(f"{label}.preimage", preimage)
    emit_hex(f"{label}.canonical_hash", digest)
    emit_hex(f"{label}.signature", signature)
    return digest


def _verify_with_cryptography(
    key: KeyPair, digest: bytes, signature: bytes, label: str
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import utils as _utils

    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    public = _ec.EllipticCurvePublicNumbers(
        key.point[0], key.point[1], _ec.SECP256R1()
    ).public_key()
    try:
        public.verify(
            _utils.encode_dss_signature(r, s),
            digest,
            _ec.ECDSA(_utils.Prehashed(_HASH_SHA256)),
        )
    except InvalidSignature as exc:  # pragma: no cover
        raise AssertionError(f"{label}: cryptography rejected the signature") from exc


if _HAVE_CRYPTOGRAPHY:
    from cryptography.hazmat.primitives import hashes as _hashes

    _HASH_SHA256 = _hashes.SHA256()


# ---------------------------------------------------------------------------
# §25.3 Canonical hash construction vectors 1-4
# ---------------------------------------------------------------------------


def emit_canonical_encoding() -> None:
    section("§25.3 Canonical hash construction")
    emit_hex("vector_1.domain_separator", b"SCP-INNER-ENVELOPE-V1:")
    emit_hex("vector_2.var_field", var_field("did:dht:z6MkTest"))
    emit_hex("vector_3.u64", u64(1_700_000_000))
    emit_hex("vector_4.absent_sentinel", ABSENT_SENTINEL)


# ---------------------------------------------------------------------------
# §25.4 InnerEnvelope, §25.5 vote, §25.6 reset request
# ---------------------------------------------------------------------------

PAYLOAD_HASH = sha256(b"hello world")
PROVENANCE_HASH = bytes.fromhex(
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)


def inner_envelope_preimage(provenance: bytes | None) -> bytes:
    return canonical_preimage(
        "SCP-INNER-ENVELOPE-V1:",
        u16(256),
        u8(0x00),
        var_field("test-context-01"),
        var_field("did:dht:z6MkTest"),
        u64(1),
        u64(0),
        u64(0),
        u64(1_700_000_000),
        var_field(PAYLOAD_HASH),
        var_field(provenance) if provenance is not None else absent_var(),
        var_field("#active"),
    )


VOTE_PROPOSAL_ID = bytes.fromhex(
    "0102030405060708091011121314151617181920212223242526272829303132"
)
RESET_NONCE = bytes.fromhex("01020304050607080910111213141516")


def emit_signing_vectors() -> None:
    section("§25.4 InnerEnvelope")
    emit_hex("vector_5.payload_hash", PAYLOAD_HASH)
    emit_hex("vector_6.provenance_hash", PROVENANCE_HASH)
    sign_and_emit("vector_5", inner_envelope_preimage(None))
    sign_and_emit("vector_6", inner_envelope_preimage(PROVENANCE_HASH))

    section("§25.5 Vote")
    emit_hex("vector_7.proposal_id", VOTE_PROPOSAL_ID)
    emit_hex("vector_8.nonce", RESET_NONCE)
    sign_and_emit(
        "vector_7",
        canonical_preimage(
            "SCP-VOTE-V1:",
            fixed_field(VOTE_PROPOSAL_ID),
            var_field("did:dht:z6MkVoter"),
            var_field('"Approve"'),
            u64(1_700_000_000),
        ),
    )

    section("§25.6 Reset request")
    sign_and_emit(
        "vector_8",
        canonical_preimage(
            "SCP-RESET-REQUEST-V1:",
            var_field("sync-test-context"),
            var_field("did:dht:z6MkSync"),
            u64(42),
            var_field("extended offline (8 days)"),
            fixed_field(RESET_NONCE),
            u64(1_700_000_000),
        ),
    )


# ---------------------------------------------------------------------------
# §25.7 Envelope padding
# ---------------------------------------------------------------------------


def emit_padding() -> None:
    section("§25.7 Envelope padding")
    cases = [
        ("vector_9", b""),
        ("vector_10", b"hello"),
        ("vector_11", b"\xab" * 252),
        ("vector_12", b"\xab" * 253),
        ("vector_13", b"\x42" * 262_140),
    ]
    for label, payload in cases:
        padded = pad(payload)
        emit(f"{label}.total_len", len(padded))
        emit_hex(f"{label}.trailing_length_field", padded[-4:])
    try:
        pad(b"\x00" * 262_141)
    except ValueError as exc:
        emit("vector_14.error", exc.args[0])
    else:  # pragma: no cover
        raise AssertionError("vector 14 must fail with PayloadTooLarge")


# ---------------------------------------------------------------------------
# §25.8 Merkle vectors
# ---------------------------------------------------------------------------


def emit_merkle() -> None:
    section("§25.8 Merkle tree")
    emit_hex("vector_15.empty_root", merkle_root([]))
    emit_hex("vector_16.root", merkle_root([leaf_hash(b"Hello")]))

    two = [leaf_hash(b"Event1"), leaf_hash(b"Event2")]
    emit_hex("vector_17.leaf_1", two[0])
    emit_hex("vector_17.leaf_2", two[1])
    emit_hex("vector_17.root", merkle_root(two))

    abc = [leaf_hash(b"A"), leaf_hash(b"B"), leaf_hash(b"C")]
    emit_hex("vector_18.leaf_1", abc[0])
    emit_hex("vector_18.leaf_2", abc[1])
    emit_hex("vector_18.leaf_3", abc[2])
    emit_hex("vector_18.interior_1", interior_hash(abc[0], abc[1]))
    emit_hex("vector_18.root", merkle_root(abc))

    abcd = abc + [leaf_hash(b"D")]
    emit_hex("vector_19.leaf_4", abcd[3])
    emit_hex("vector_19.interior_L", interior_hash(abcd[0], abcd[1]))
    emit_hex("vector_19.interior_R", interior_hash(abcd[2], abcd[3]))
    emit_hex("vector_19.root", merkle_root(abcd))


# ---------------------------------------------------------------------------
# §25.8 Vector 32/33 — typed event-log leaves
#
# Each leaf is SHA-256(0x00 || rmp_serde(Event)). `Event` serializes
# positionally: the `EventType` variant name, the actor DID string, the
# timestamp, the sequence, the `EventPayload` struct (one `serde_bytes`
# field), the 32-byte `prev_hash` as an array of integers, and the signature
# as a MessagePack binary.
# ---------------------------------------------------------------------------

KAT_CONTEXT_ID = "ctx-kat"
KAT_ACTOR_DID = "did:dht:z6MkEventLogKat"


def event_canonical_hash(
    tag: int, actor_did: str, timestamp: int, sequence: int, payload: bytes, prev: bytes
) -> bytes:
    return sha256(
        b"SCP-EVENT-V1:",
        u16(tag),
        var_field(actor_did),
        u64(timestamp),
        u64(sequence),
        var_field(payload),
        fixed_field(prev),
    )


def event_bytes(
    variant: str,
    actor_did: str,
    timestamp: int,
    sequence: int,
    payload: bytes,
    prev: bytes,
    signature: bytes,
) -> bytes:
    return mp_array(
        [
            mp_str(variant),
            mp_str(actor_did),
            mp_uint(timestamp),
            mp_uint(sequence),
            mp_array([mp_bin(payload)]),
            mp_byte_array(prev),
            mp_bin(signature),
        ]
    )


KAT_EVENTS = [
    (
        "AppBound",
        74,
        1_700_000_000,
        mp_array(
            [
                mp_str("did:key:app"),
                mp_str("Scheduler"),
                mp_str("1.0.0"),
                mp_array([mp_str("outlet:call:*")]),
            ]
        ),
    ),
    (
        "SpendApproved",
        65,
        1_700_000_001,
        mp_array([mp_str("did:key:agent"), mp_uint(5000), mp_str("inference")]),
    ),
    (
        "TtlExtended",
        62,
        1_700_000_002,
        mp_array(
            [
                mp_uint(1_700_000_000),
                mp_uint(1_800_000_000),
                mp_byte_array(b"\xab" * 32),
                mp_array([mp_str("did:key:a"), mp_str("did:key:b")]),
            ]
        ),
    ),
    (
        "RecoveryEpochAdvanced",
        73,
        1_700_000_003,
        mp_array([mp_uint(7), mp_uint(8)]),
    ),
    (
        "ContextTombstoned",
        60,
        1_700_000_004,
        mp_array([mp_str("ctx-dest"), mp_byte_array(b"\xcd" * 32)]),
    ),
    (
        "ConsequenceTriggered",
        67,
        1_700_000_005,
        b"member_did=did:key:m;rule_index=2;trigger_kind=absence;action_type=suspend",
    ),
    (
        "CommitBroadcastSucceeded",
        71,
        1_700_000_006,
        b"operation=join;attempts=3",
    ),
    (
        "RoleAssigned",
        6,
        1_700_000_007,
        mp_array([mp_str("did:key:carol"), mp_str("admin")]),
    ),
    (
        "MemberJoined",
        4,
        1_700_000_008,
        mp_array([mp_str("did:key:dave"), mp_str("member")]),
    ),
]


def emit_typed_leaves() -> None:
    section("§25.8 Vector 32/33 typed event-log leaves")
    prev = bytes(32)
    leaves: list[bytes] = []
    for sequence, (variant, tag, timestamp, payload) in enumerate(KAT_EVENTS):
        digest = event_canonical_hash(
            tag, KAT_ACTOR_DID, timestamp, sequence, payload, prev
        )
        signature = ecdsa_sign(REF_KEY_1.d, digest)
        assert ecdsa_verify(REF_KEY_1.point, digest, signature)
        leaf = leaf_hash(
            event_bytes(
                variant, KAT_ACTOR_DID, timestamp, sequence, payload, prev, signature
            )
        )
        emit_hex(f"vector_32.leaf_{sequence}_{variant}", leaf)
        leaves.append(leaf)
        prev = leaf
    root = merkle_root(leaves)
    emit_hex("vector_32.root", root)
    emit("vector_33.event_count", len(leaves))
    emit_hex("vector_33.checkpoint_merkle_root", root)


# ---------------------------------------------------------------------------
# §25.8 Vector 35 — DataProvenance provenance hash
# ---------------------------------------------------------------------------


def data_provenance_bytes() -> bytes:
    return mp_array(
        [
            mp_str("ctx-kat-provenance"),
            mp_str("Persistent"),
            mp_array([mp_str("did:key:alice"), mp_str("did:key:bob")]),
            mp_str("kat"),
            mp_map([("SharedContext", mp_str("ctx-shared"))]),
            mp_array([mp_uint(300), mp_uint(0)]),
            mp_str("Full"),
            mp_uint(1),
            mp_array([mp_str("ctx-hop-1")]),
            mp_uint(1000),
            mp_str("stripe"),
            mp_byte_array(b"\x11" * 32),
        ]
    )


def emit_provenance_hash() -> None:
    section("§25.8 Vector 35 provenance hash")
    emit_hex("vector_35.provenance_hash", sha256(data_provenance_bytes()))
    emit_hex("vector_35.absent_sentinel", ABSENT_SENTINEL)


# ---------------------------------------------------------------------------
# §25.9 Key-continuity fingerprint (§9.11)
# ---------------------------------------------------------------------------

IDENTIFIER_A = sha256(b"SCP test vector identifier A")
IDENTIFIER_B = sha256(b"SCP test vector identifier B")

ROOT_A_1 = keypair_from_seed(b"\x41" * 32, TEST_VECTOR_KEY_LABEL, "root A member 1")
ROOT_A_2 = keypair_from_seed(b"\x42" * 32, TEST_VECTOR_KEY_LABEL, "root A member 2")
ACTIVE_A = keypair_from_seed(b"\x43" * 32, TEST_VECTOR_KEY_LABEL, "active A")
ROOT_B_1 = keypair_from_seed(b"\x44" * 32, TEST_VECTOR_KEY_LABEL, "root B member 1")
ACTIVE_B = keypair_from_seed(b"\x45" * 32, TEST_VECTOR_KEY_LABEL, "active B")


def fingerprint(
    id_x: bytes,
    root_x: list[KeyPair],
    active_x: KeyPair,
    id_y: bytes,
    root_y: list[KeyPair],
    active_y: KeyPair,
) -> tuple[bytes, bytes]:
    """§9.11: the block for the lower identifier comes first."""
    first = (id_x, root_x, active_x)
    second = (id_y, root_y, active_y)
    if id_y < id_x:
        first, second = second, first
    parts = [b"SCP-KEY-CONTINUITY-V1:"]
    for identifier, root_set, active in (first, second):
        parts.append(fixed_field(identifier))
        parts.append(u32(len(root_set)))
        parts.extend(fixed_field(member.compressed) for member in root_set)
        parts.append(fixed_field(active.compressed))
    preimage = b"".join(parts)
    return preimage, sha256(preimage)


def emit_fingerprint() -> None:
    section("§25.9 Key-continuity fingerprint")
    emit_hex("fingerprint.identifier_a", IDENTIFIER_A)
    emit_hex("fingerprint.identifier_b", IDENTIFIER_B)
    emit_hex("fingerprint.root_a_member_1", ROOT_A_1.compressed)
    emit_hex("fingerprint.root_a_member_2", ROOT_A_2.compressed)
    emit_hex("fingerprint.active_a", ACTIVE_A.compressed)
    emit_hex("fingerprint.root_b_member_1", ROOT_B_1.compressed)
    emit_hex("fingerprint.active_b", ACTIVE_B.compressed)
    emit(
        "fingerprint.lower_identifier",
        "A" if IDENTIFIER_A < IDENTIFIER_B else "B",
    )

    preimage, digest = fingerprint(
        IDENTIFIER_A,
        [ROOT_A_1, ROOT_A_2],
        ACTIVE_A,
        IDENTIFIER_B,
        [ROOT_B_1],
        ACTIVE_B,
    )
    emit("vector_20.preimage_len", len(preimage))
    emit_hex("vector_20.preimage", preimage)
    emit_hex("vector_20.fingerprint", digest)

    swapped_preimage, swapped_digest = fingerprint(
        IDENTIFIER_B,
        [ROOT_B_1],
        ACTIVE_B,
        IDENTIFIER_A,
        [ROOT_A_1, ROOT_A_2],
        ACTIVE_A,
    )
    assert swapped_preimage == preimage, "§9.11 ordering is not argument-order stable"
    emit_hex("vector_38.fingerprint", swapped_digest)


# ---------------------------------------------------------------------------
# §25.10 claim hash, §25.11 proposal ID, §25.12 HPKE info strings
# ---------------------------------------------------------------------------


def emit_claim_and_proposal() -> None:
    section("§25.10 Shadow claim hash")
    claim_preimage = canonical_preimage(
        "SCP-CLAIM-V1:",
        var_field("shadow-alice-x-12345"),
        var_field("did:dht:z6MkClaim"),
        var_field("bridge-test-context"),
        u64(1_700_000_000),
    )
    emit("vector_22.preimage_len", len(claim_preimage))
    emit_hex("vector_22.preimage", claim_preimage)
    emit_hex("vector_22.claim_hash", sha256(claim_preimage))

    section("§25.11 Governance proposal ID")
    action_bytes = json.dumps(
        {"AddMember": {"did": "did:dht:z6MkNewMember", "role": "member"}},
        separators=(",", ":"),
        sort_keys=False,
    ).encode()
    emit("vector_23.action_bytes_len", len(action_bytes))
    emit("vector_23.action_bytes_utf8", action_bytes.decode())
    emit_hex("vector_23.action_bytes", action_bytes)
    proposal_preimage = canonical_preimage(
        "SCP-PROPOSAL-V1:",
        var_field("gov-proposal-context"),
        var_field("did:dht:z6MkProposer"),
        var_field(action_bytes),
        u64(1_700_000_000),
    )
    emit("vector_23.preimage_len", len(proposal_preimage))
    emit_hex("vector_23.preimage", proposal_preimage)
    emit_hex("vector_23.proposal_id", sha256(proposal_preimage))


def emit_hpke_info() -> None:
    section("§25.12 HPKE info strings")
    sender_info = (
        b"scp-sender-key-v1"
        + var_field("hpke-test-context")
        + var_field("did:dht:z6MkSender")
        + u64(42)
    )
    access_info = (
        b"scp-access-key-v1"
        + var_field("hpke-test-context")
        + var_field("did:dht:z6MkMember")
        + u64(42)
    )
    emit("vector_24.info_len", len(sender_info))
    emit_hex("vector_24.info", sender_info)
    emit("vector_25.info_len", len(access_info))
    emit_hex("vector_25.info", access_info)
    assert sender_info != access_info, "the two info strings must differ"


# ---------------------------------------------------------------------------
# §25.13 Identity-link attestation, §25.20 trust attestation
# ---------------------------------------------------------------------------


def emit_identity_link_attestation() -> None:
    section("§25.13 Identity-link attestation")
    claim = mp_map(
        [
            ("platform", mp_str("google.com")),
            ("platform_handle", mp_str("alice@gmail.com")),
            ("link_type", mp_str("self_attestation")),
        ]
    )
    evidence = mp_map(
        [
            ("method", mp_str("oauth")),
            (
                "proof",
                mp_str(
                    '{"provider":"google.com","subject_id":"12345",'
                    '"verified_at":1700000000}'
                ),
            ),
            ("verified_at", mp_uint(1_700_000_000)),
        ]
    )
    revocation = mp_str("Active")
    emit_hex("vector_26.claim_msgpack", claim)
    emit_hex("vector_26.evidence_msgpack", evidence)
    emit_hex("vector_26.revocation_status_msgpack", revocation)
    sign_and_emit(
        "vector_26",
        canonical_preimage(
            "SCP-IDENTITY-LINK-ATTESTATION-V1:",
            var_field("att-001"),
            var_field("identity_link"),
            var_field("did:dht:z6MkIssuer"),
            var_field("did:dht:z6MkIssuer"),
            u64(1_700_000_000),
            absent_fixed(),
            var_field(claim),
            var_field(evidence),
            var_field(revocation),
        ),
    )


def emit_trust_attestation() -> None:
    section("§25.20 Trust attestation")
    jcs_claim = b'{"level":"gold","score":42}'
    revocation = mp_str("Active")
    emit("vector_34.claim_jcs_len", len(jcs_claim))
    emit_hex("vector_34.revocation_status_msgpack", revocation)
    sign_and_emit(
        "vector_34",
        canonical_preimage(
            "SCP-ATTESTATION-V1:",
            var_field("att-trust-001"),
            u16(4),
            var_field("did:dht:z6MkIssuer"),
            var_field("did:dht:z6MkSubject"),
            var_field(jcs_claim),
            absent_fixed(),
            u64(1_700_000_000),
            absent_fixed(),
            var_field(revocation),
        ),
    )


# ---------------------------------------------------------------------------
# §25.14 pseudonymization, §25.15 offer ID, §25.16 attestation ID
# ---------------------------------------------------------------------------


def emit_hash_only_vectors() -> None:
    section("§25.14 DID pseudonymization")
    pseudonym_preimage = canonical_preimage(
        "SCP-PSEUDONYM-V1:",
        var_field(b"test-pseudonym-key"),
        var_field("test-context-01"),
        var_field("did:dht:z6MkTest"),
    )
    emit("vector_27.preimage_len", len(pseudonym_preimage))
    emit_hex("vector_27.pseudonym_hash", sha256(pseudonym_preimage))

    section("§25.15 Outlet interface offer ID")
    offer_preimage = canonical_preimage(
        "SCP-OFFER-ID-V1:",
        var_field("source-ctx-01"),
        var_field("outlet-abc123"),
        var_field("target-ctx-02"),
        u64(1_700_000_000),
    )
    emit("vector_28.preimage_len", len(offer_preimage))
    emit_hex("vector_28.offer_id", sha256(offer_preimage))

    section("§25.16 Attestation ID")
    attestation_id_preimage = canonical_preimage(
        "SCP-ATTESTATION-ID-V1:",
        var_field("did:dht:z6MkIssuer"),
        var_field("google.com"),
        var_field("alice@gmail.com"),
        u64(1_700_000_000),
    )
    emit("vector_29.preimage_len", len(attestation_id_preimage))
    emit_hex("vector_29.attestation_id", sha256(attestation_id_preimage))


# ---------------------------------------------------------------------------
# §25.19 Per-context pseudonym derivation (§9.10.4, §9.10.4.A, §9.10.4.1)
# ---------------------------------------------------------------------------

PSEUDONYM_SECRET_SALT = b"scp-pseudonym-secret-v1"
PSEUDONYM_SCALAR_LABEL = b"SCP-PSEUDONYM-P256-V1"

PSEUDONYM_SEEDS = [
    ("vector_30", bytes.fromhex("01" * 32)),
    (
        "vector_31",
        bytes.fromhex(
            "9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
    ),
]


def emit_pseudonym_derivation() -> None:
    section("§25.19 Per-context pseudonym derivation")
    context_id = "context-alpha"
    for label, seed in PSEUDONYM_SEEDS:
        identity = keypair_from_seed(seed, TEST_VECTOR_KEY_LABEL, f"{label} identity")
        secret = hkdf(
            ikm=identity.private_bytes,
            salt=PSEUDONYM_SECRET_SALT,
            info=b"",
            length=32,
        )
        seed_v1 = hmac_sha256(secret, context_id.encode() + b"scp-pseudonym")
        seed_v2 = hmac_sha256(
            secret, context_id.encode() + u64(1) + b"scp-pseudonym-v2"
        )
        key_v1 = KeyPair(
            seed_to_scalar(seed_v1, PSEUDONYM_SCALAR_LABEL), f"{label} pseudonym v1"
        )
        key_v2 = KeyPair(
            seed_to_scalar(seed_v2, PSEUDONYM_SCALAR_LABEL), f"{label} pseudonym v2"
        )
        emit_hex(f"{label}.identity_seed", seed)
        emit_hex(f"{label}.identity_scalar", identity.private_bytes)
        emit_hex(f"{label}.pseudonym_secret", secret)
        emit_hex(f"{label}.context_seed_v1", seed_v1)
        emit_hex(f"{label}.pseudonym_public_v1", key_v1.compressed)
        emit_hex(f"{label}.context_seed_v2", seed_v2)
        emit_hex(f"{label}.pseudonym_public_v2", key_v2.compressed)


def emit_pseudonym_announcement() -> None:
    section("§25.19 Vector 36 pseudonym announcement wire format")
    wire = mp_map(
        [
            ("tag", mp_str("\0scp:pseudonym-announce:v1")),
            (
                "member_did",
                mp_str("did:dht:z6MkPseudonymKatFixtureMemberAAAAAAAAAAAAAA"),
            ),
            ("pseudonym", mp_bin(b"\x42" * 32)),
        ]
    )
    emit_hex("vector_36.wire", wire)


# ---------------------------------------------------------------------------
# §25.23 KeyPackage attestation (§9.5.2, §9.18.7)
# ---------------------------------------------------------------------------

LEAF_ENCRYPTION_SEED = bytes.fromhex("33" * 32)
INIT_KEY_SEED = bytes.fromhex("11" * 32)
WRAPPING_KEY_SEED = bytes.fromhex("22" * 32)


def emit_keypackage_attestation() -> None:
    section("§25.23 KeyPackage attestation")
    leaf_signature_key = REF_KEY_2.uncompressed
    leaf_encryption = keypair_from_seed(
        LEAF_ENCRYPTION_SEED, TEST_VECTOR_KEY_LABEL, "leaf encryption key"
    )
    init = keypair_from_seed(INIT_KEY_SEED, TEST_VECTOR_KEY_LABEL, "init key")
    wrapping = keypair_from_seed(
        WRAPPING_KEY_SEED, TEST_VECTOR_KEY_LABEL, "wrapping key"
    )
    keys = [
        leaf_signature_key,
        leaf_encryption.uncompressed,
        init.uncompressed,
        wrapping.uncompressed,
    ]
    assert len(set(keys)) == 4, "the four bound leaf keys must be distinct"

    body_fields = (
        var_field("did:dht:z6MkLeafAttest")
        + b"".join(fixed_field(key) for key in keys)
        + var_field("#active")
        + u64(1_700_000_000)
        + u64(1_700_086_400)
    )
    preimage = b"SCP-KEYPACKAGE-ATTESTATION-V1:" + body_fields
    emit_hex("vector_37.leaf_signature_key", leaf_signature_key)
    emit_hex("vector_37.leaf_encryption_key", leaf_encryption.uncompressed)
    emit_hex("vector_37.init_key", init.uncompressed)
    emit_hex("vector_37.wrapping_key", wrapping.uncompressed)
    digest = sign_and_emit("vector_37", preimage)
    signature = ecdsa_sign(REF_KEY_1.d, digest)
    extension_body = body_fields + signature
    emit("vector_37.extension_body_len", len(extension_body))
    emit_hex("vector_37.extension_body", extension_body)


# ---------------------------------------------------------------------------
# §25.25 Custody violation and counter-attestation (§9.5.2, §9.18.2)
# ---------------------------------------------------------------------------

CUSTODY_SUBJECT_DID = "did:dht:z6MkCustodySubject"
CUSTODY_VERIFIER_DID = "did:dht:z6MkCustodyVerifier"
CUSTODY_ACTION = b"did_document_update"
CUSTODY_SIGNER_KEY_ID = "#agent"
COUNTER_EXPLANATION = "agent key compromised; rotated and republished"


# §25.25's custody-violation and counter-attestation vectors were deleted on 2026-09-10.
# The identity-substrate plan's §1 table marks both constructs CUT (Alec's 2026-08-25 Ruling 2,
# reconfirmed 2026-08-31), and Track U4 owns the teardown of the §9.5.2 preimage tables and the
# shipped code. Re-signing their preimages onto P-256 would have widened that teardown.


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# §25.26 Key-event signature slots, the cosigned head, and the relay proof
# (§9.7.4.2 definitions, §9.7.4.3, §9.18.2)
# ---------------------------------------------------------------------------

# The inception event's preimage is built here, in the field order §9.7.4.2's
# definitions fix. Vectors 41 and 42 pin its bytes, its digest, and the identifier
# that digest derives, then pin the slot each signature form produces over it.

KIND_INCEPTION = 0x01
ROLE_ROOT = 0x01
ROLE_ACTIVE = 0x02
CONDITION_CURRENT = 0x01
CUSTODY_PASSKEY = 0x01
KEY_ALGORITHM_ECDSA_P256_SHA256 = 0x01
CONTINUATION_COMMITMENT = 0x01
PREROTATION_SEPARATOR = b"SCP-PREROTATION-COMMITMENT-V1:"
KEL_EVENT_SEPARATOR = b"SCP-KEL-EVENT-V1:"
KEL_ID_SEPARATOR = b"SCP-KEL-ID-V1:"
ZERO32 = bytes(32)

# The vector identity: a 1-of-1 root (§25.2's reference key), one #active key
# (§25.2's secondary key), a 1-of-1 next set, one witness, and a one-hour
# witnessing interval.
VECTOR_WITNESS_OPERATOR = sha256(b"scp-25-witness-operator")
VECTOR_WITNESSING_INTERVAL = 3600
VECTOR_PREROTATION_POINT = REF_KEY_3.compressed


def key_state_entry(point: bytes, role: int, condition: int) -> bytes:
    """One 45-byte key-state entry, in §9.7.4.2's key-state snapshot order."""
    entry = (
        fixed_field(point)
        + u8(role)
        + u8(condition)
        + u64(0)
        + u8(CUSTODY_PASSKEY)
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
    )
    assert len(entry) == 45, len(entry)
    return entry


def vector_key_state() -> bytes:
    return (
        u32(1)  # root threshold
        + u32(2)  # key count
        + key_state_entry(REF_KEY_1.compressed, ROLE_ROOT, CONDITION_CURRENT)
        + key_state_entry(REF_KEY_2.compressed, ROLE_ACTIVE, CONDITION_CURRENT)
        + u32(1)  # next-set count
        + u8(CUSTODY_PASSKEY)  # the entry is custody_type then key_algorithm
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
        + u32(1)  # witness-set count
        + fixed_field(VECTOR_WITNESS_OPERATOR)
        + u32(VECTOR_WITNESSING_INTERVAL)
        + u8(ROLE_ACTIVE)  # service-key designation
        + fixed_field(ZERO32)  # delegator: non-delegated
    )


def inception_preimage(form: int) -> bytes:
    """The inception event's signed preimage, in §9.7.4.2's field order."""
    commitment = sha256(PREROTATION_SEPARATOR + VECTOR_PREROTATION_POINT)
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_INCEPTION)  # 1. event_type
        + fixed_field(ZERO32)  # 2. identifier placeholder
        + u64(0)  # 3. sequence
        + fixed_field(ZERO32)  # 4. predecessor placeholder
        # 5. standing_root: the RootRecovery kind alone carries it
        + u32(1)
        + u8(0)  # 6. signer index list of the one root group
        + u32(1)
        + u8(form)  # 7. signature-form list of that group
        # 8. revealed keys: the reveal-authorized kinds alone carry them
        + u32(1)
        + fixed_field(REF_KEY_1.compressed)
        + u32(1)  # 9. installed root set + threshold
        + vector_key_state()  # 10. key-state snapshot
        # 11. key-event seals: the KeyState kind alone carries them
        + u8(CONTINUATION_COMMITMENT)  # 12. continuation
        + u32(1)
        + fixed_field(commitment)
        + u32(1)
    )


def identifier_of(preimage: bytes) -> bytes:
    return sha256(KEL_ID_SEPARATOR + preimage)


# Set by emit_key_event_slots(); §25.27's objects name Vector 41's event and identifier.
INCEPTION_DIGEST = b""
INCEPTION_IDENTIFIER = b""

WEBAUTHN_CHALLENGE_PREFIX = b"SCP-KEY-EVENT-V1:"
WEBAUTHN_RP_ID = b"ctx.network"
# Synthesized authenticatorData, in WebAuthn's own layout for an assertion:
#   rpIdHash (32) || flags (1) || signCount (4 big-endian).
# flags 0x05 sets user present (0x01) and user verified (0x04). §9.7.4.2's
# definitions require the user-presence bit and read the user-verification bit
# as information, so a conforming slot may carry 0x01 here instead.
WEBAUTHN_FLAGS = 0x05
WEBAUTHN_SIGN_COUNT = 0
# Synthesized clientDataJSON: the exact byte string a browser serializes, with no
# whitespace and the member order a conforming client emits. A verifier parses it
# as RFC 8259 JSON and rejects a duplicate member name at any nesting level.
WEBAUTHN_ORIGIN = "https://ctx.network"


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def webauthn_authenticator_data() -> bytes:
    return (
        sha256(WEBAUTHN_RP_ID)
        + bytes([WEBAUTHN_FLAGS])
        + WEBAUTHN_SIGN_COUNT.to_bytes(4, "big")
    )


def webauthn_client_data_json(challenge: bytes) -> bytes:
    return (
        '{"type":"webauthn.get","challenge":"'
        + b64url_nopad(challenge)
        + '","origin":"'
        + WEBAUTHN_ORIGIN
        + '","crossOrigin":false}'
    ).encode()


def emit_key_event_slots() -> None:
    section("§25.26 Key-event preimage and signature slots")

    # --- Vector 41: an inception whose one root slot carries the raw form. ---
    preimage_41 = inception_preimage(0x01)
    digest_41 = sha256(preimage_41)
    identifier_41 = identifier_of(preimage_41)
    emit("vector_41.form", "0x01")
    emit_hex("vector_41.root_key_compressed", REF_KEY_1.compressed)
    emit_hex("vector_41.active_key_compressed", REF_KEY_2.compressed)
    emit_hex("vector_41.prerotation_key_compressed", VECTOR_PREROTATION_POINT)
    emit_hex(
        "vector_41.prerotation_commitment",
        sha256(PREROTATION_SEPARATOR + VECTOR_PREROTATION_POINT),
    )
    emit_hex("vector_41.witness_operator", VECTOR_WITNESS_OPERATOR)
    emit("vector_41.witnessing_interval", VECTOR_WITNESSING_INTERVAL)
    emit("vector_41.key_state_bytes", len(vector_key_state()))
    emit("vector_41.preimage_len", len(preimage_41))
    emit_hex("vector_41.preimage", preimage_41)
    emit_hex("vector_41.preimage_digest", digest_41)
    emit_hex("vector_41.identifier", identifier_41)
    emit_hex("vector_41.routing_id", sha256(b"scp:did:" + identifier_41))
    raw_sig = ecdsa_sign(REF_KEY_1.d, digest_41)
    assert ecdsa_verify(REF_KEY_1.point, digest_41, raw_sig)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(REF_KEY_1, digest_41, raw_sig, "vector_41")
    assert int.from_bytes(raw_sig[32:], "big") * 2 <= N, "vector_41: high-s"
    emit("vector_41.slot_len", len(raw_sig))
    emit_hex("vector_41.slot", raw_sig)

    # --- Vector 42: an inception whose one root slot carries the assertion form. ---
    preimage_42 = inception_preimage(0x02)
    digest_42 = sha256(preimage_42)
    identifier_42 = identifier_of(preimage_42)
    assert preimage_42 != preimage_41, "the form list sits in the preimage"
    challenge = WEBAUTHN_CHALLENGE_PREFIX + digest_42
    auth_data = webauthn_authenticator_data()
    client_data = webauthn_client_data_json(challenge)
    signed_message = auth_data + sha256(client_data)
    assertion_digest = sha256(signed_message)
    assertion_sig = ecdsa_sign(REF_KEY_1.d, assertion_digest)
    assert ecdsa_verify(REF_KEY_1.point, assertion_digest, assertion_sig)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(
            REF_KEY_1, assertion_digest, assertion_sig, "vector_42"
        )
    assert int.from_bytes(assertion_sig[32:], "big") * 2 <= N, "vector_42: high-s"
    slot = (
        u32(len(auth_data))
        + auth_data
        + u32(len(client_data))
        + client_data
        + assertion_sig
    )
    assert 37 <= len(auth_data) <= 256, "vector_42: authenticatorData bounds"
    assert 1 <= len(client_data) <= 512, "vector_42: MAX_CLIENT_DATA_JSON_BYTES"
    emit("vector_42.form", "0x02")
    emit("vector_42.preimage_len", len(preimage_42))
    emit_hex("vector_42.preimage", preimage_42)
    emit_hex("vector_42.preimage_digest", digest_42)
    emit_hex("vector_42.identifier", identifier_42)
    emit("vector_42.challenge_len", len(challenge))
    emit_hex("vector_42.challenge", challenge)
    emit("vector_42.challenge_b64url", b64url_nopad(challenge))
    emit_hex("vector_42.rp_id_hash", sha256(WEBAUTHN_RP_ID))
    emit("vector_42.authenticator_data_len", len(auth_data))
    emit_hex("vector_42.authenticator_data", auth_data)
    emit("vector_42.client_data_json_len", len(client_data))
    emit("vector_42.client_data_json", client_data.decode())
    emit_hex("vector_42.client_data_json_bytes", client_data)
    emit_hex("vector_42.client_data_hash", sha256(client_data))
    emit_hex("vector_42.signed_message", signed_message)
    emit_hex("vector_42.ecdsa_digest", assertion_digest)
    emit_hex("vector_42.signature", assertion_sig)
    emit("vector_42.slot_len", len(slot))
    emit_hex("vector_42.slot", slot)

    global INCEPTION_DIGEST, INCEPTION_IDENTIFIER
    INCEPTION_DIGEST = digest_41
    INCEPTION_IDENTIFIER = identifier_41


# --- §25.27 the cosigned head and the relay proof of control ---

WITNESS_ID = sha256(b"scp-25-witness-operator")
COSIGN_OBSERVED_AT = 1_700_000_000
RELAY_OPERATOR_ID = sha256(b"scp-25-relay-operator")
RESOLVER_NONCE = sha256(b"scp-25-resolver-nonce")
SERVED_BLOB_A = b"scp-25-served-blob-a"
SERVED_BLOB_B = b"scp-25-served-blob-bb"
# §9.7.4.2 definitions: a 4-byte blob count, then each blob under §9.5.1's
# variable-length rule, so one digest names one split of the bytes into blobs.
SERVED_VALUE_DIGEST = sha256(
    u32(2) + var_field(SERVED_BLOB_A) + var_field(SERVED_BLOB_B)
)


def emit_witness_and_relay_objects() -> None:
    section("§25.27 Cosigned head, conflict statement, fault proof, relay proof")

    subject = INCEPTION_IDENTIFIER
    designating_digest = INCEPTION_DIGEST

    def cosigned_head(
        label, sequence, event_digest, previous, observed_at, key=REF_KEY_2
    ):
        fields = (
            fixed_field(WITNESS_ID)
            + fixed_field(subject)
            + u64(sequence)
            + fixed_field(event_digest)
            + fixed_field(previous)
            + u64(observed_at)
        )
        assert len(fields) == 144, len(fields)
        assert previous != bytes(32), "previous_cosigned_digest is never zero"
        emit_hex(f"{label}.witness", WITNESS_ID)
        emit_hex(f"{label}.subject", subject)
        emit(f"{label}.sequence", sequence)
        emit_hex(f"{label}.event_digest", event_digest)
        emit_hex(f"{label}.previous_cosigned_digest", previous)
        emit(f"{label}.observed_at", observed_at)
        emit(f"{label}.field_bytes", len(fields))
        digest = sign_and_emit(
            label, canonical_preimage("SCP-COSIGNED-HEAD-V1:", fields), key
        )
        emit(f"{label}.object_bytes", len(fields) + 64)
        return digest

    # Vector 43: a witness's first cosigned head after seeding at the event that
    # designated it. previous_cosigned_digest names that event, never zero.
    cosigned_head(
        "vector_43", 0, designating_digest, designating_digest, COSIGN_OBSERVED_AT
    )

    # Vector 45: the conflict statement a witness emits when the one check fails.
    held_digest = sha256(b"scp-25-conflict-held-event")
    offered_digest = sha256(b"scp-25-conflict-offered-event")
    conflict_fields = (
        fixed_field(WITNESS_ID)
        + fixed_field(subject)
        + u64(7)
        + fixed_field(held_digest)
        + u64(7)
        + fixed_field(offered_digest)
        + u64(COSIGN_OBSERVED_AT)
    )
    assert len(conflict_fields) == 152, len(conflict_fields)
    emit_hex("vector_45.witness", WITNESS_ID)
    emit_hex("vector_45.subject", subject)
    emit("vector_45.held_sequence", 7)
    emit_hex("vector_45.held_digest", held_digest)
    emit("vector_45.offered_sequence", 7)
    emit_hex("vector_45.offered_digest", offered_digest)
    emit("vector_45.field_bytes", len(conflict_fields))
    sign_and_emit(
        "vector_45",
        canonical_preimage("SCP-WITNESS-CONFLICT-V1:", conflict_fields),
        REF_KEY_2,
    )
    emit("vector_45.object_bytes", len(conflict_fields) + 64)

    # Vector 46: the two-heads fault proof — one witness, one subject, one
    # non-zero previous_cosigned_digest, two different event_digests.
    baseline = sha256(b"scp-25-fault-proof-baseline-head")
    head_a = sha256(b"scp-25-fault-proof-successor-a")
    head_b = sha256(b"scp-25-fault-proof-successor-b")
    emit_hex("vector_46.shared_previous_cosigned_digest", baseline)
    cosigned_head("vector_46a", 21, head_a, baseline, COSIGN_OBSERVED_AT)
    cosigned_head("vector_46b", 21, head_b, baseline, COSIGN_OBSERVED_AT + 1)
    assert head_a != head_b, "vector_46: the two heads must differ"

    # Vector 44: the relay proof of control. It carries no key-state position:
    # §9.7.1's attestation class reads the operator's latest current #active.
    routing_id = sha256(b"scp:did:" + subject)
    proof_fields = (
        fixed_field(RELAY_OPERATOR_ID)
        + fixed_field(RESOLVER_NONCE)
        + fixed_field(routing_id)
        + fixed_field(SERVED_VALUE_DIGEST)
        + u64(COSIGN_OBSERVED_AT)
    )
    assert len(proof_fields) == 136, len(proof_fields)
    emit_hex("vector_44.operator", RELAY_OPERATOR_ID)
    emit_hex("vector_44.nonce", RESOLVER_NONCE)
    emit_hex("vector_44.routing_id", routing_id)
    emit_hex("vector_44.value_digest_input_blobs", SERVED_BLOB_A + SERVED_BLOB_B)
    emit_hex("vector_44.value_digest", SERVED_VALUE_DIGEST)
    emit("vector_44.observed_at", COSIGN_OBSERVED_AT)
    emit("vector_44.field_bytes", len(proof_fields))
    sign_and_emit(
        "vector_44",
        canonical_preimage("SCP-RELAY-PROOF-V1:", proof_fields),
        REF_KEY_1,
    )
    emit("vector_44.object_bytes", len(proof_fields) + 64)


# ---------------------------------------------------------------------------
# §25.28 The pre-rotation commitment and the service record
# (§9.7.4.2 definitions, `03-identity.md` §3.10.13, §9.18.2)
# ---------------------------------------------------------------------------

SERVICE_RECORD_SEPARATOR = "SCP-SERVICE-RECORD-V1:"
SERVICE_RECORD_SEQUENCE = 4
# Three entries in the order a record carries them. Each encodes as its three
# strings under §9.5.1's variable-length rule, in the order id, type,
# serviceEndpoint, and carries no type discriminator beside them.
SERVICE_RECORD_ENTRIES = [
    ("#scp-relay-1", "SCPRelay", "wss://relay.example.com/scp/v1"),
    ("#scp-relay-2", "SCPRelay", "wss://relay2.example.com/scp/v1"),
    ("#private-state-1", "IdentityPrivateState", "wss://relay.example.com/scp/v1"),
]


def service_record_entries_field() -> bytes:
    """The `entries` field: a 4-byte count, then each entry's three strings."""
    body = b"".join(
        var_field(entry_id) + var_field(entry_type) + var_field(endpoint)
        for entry_id, entry_type, endpoint in SERVICE_RECORD_ENTRIES
    )
    return u32(len(SERVICE_RECORD_ENTRIES)) + body


def emit_commitment_and_service_record() -> None:
    section("§25.28 Pre-rotation commitment and service record")

    # --- Vector 47: the pre-rotation commitment over two distinct points. ---
    # The commitment is SHA-256 over the separator and one 33-byte SEC1
    # compressed point carrying no length prefix (§9.7.4.2 definitions).
    for label, key in (("vector_47a", REF_KEY_3), ("vector_47b", REF_KEY_2)):
        point = key.compressed
        commitment = sha256(PREROTATION_SEPARATOR + point)
        emit(f"{label}.key_name", key.name)
        emit_hex(f"{label}.pre_rotation_public_key", point)
        emit(f"{label}.preimage_len", len(PREROTATION_SEPARATOR) + len(point))
        emit_hex(f"{label}.preimage", PREROTATION_SEPARATOR + point)
        emit_hex(f"{label}.commitment", commitment)
    assert sha256(PREROTATION_SEPARATOR + REF_KEY_3.compressed) != sha256(
        PREROTATION_SEPARATOR + REF_KEY_2.compressed
    ), "vector_47: two points must give two commitments"

    # --- Vector 48: a service record signed by the designated operational key. ---
    # The vector identity of §25.26 designates #active for the service-record
    # role, and §25.2's secondary key is that key.
    identifier = INCEPTION_IDENTIFIER
    entries = service_record_entries_field()
    fields = fixed_field(identifier) + u64(SERVICE_RECORD_SEQUENCE) + entries
    emit_hex("vector_48.identifier", identifier)
    emit("vector_48.sequence", SERVICE_RECORD_SEQUENCE)
    emit("vector_48.entry_count", len(SERVICE_RECORD_ENTRIES))
    for index, (entry_id, entry_type, endpoint) in enumerate(SERVICE_RECORD_ENTRIES):
        emit(f"vector_48.entry_{index}.id", entry_id)
        emit(f"vector_48.entry_{index}.type", entry_type)
        emit(f"vector_48.entry_{index}.serviceEndpoint", endpoint)
    emit("vector_48.entries_len", len(entries))
    emit_hex("vector_48.entries", entries)
    emit("vector_48.field_bytes", len(fields))
    emit_hex("vector_48.routing_id", sha256(b"scp:svc:" + identifier))
    sign_and_emit(
        "vector_48",
        canonical_preimage(SERVICE_RECORD_SEPARATOR, fields),
        REF_KEY_2,
    )
    emit("vector_48.object_bytes", len(fields) + 64)


def main() -> int:
    self_test()
    _LINES.append("SCP §25 test vectors — ECDSA on NIST P-256, RFC 6979, SHA-256")
    _LINES.append(
        "cryptography cross-check: "
        + ("enabled" if _HAVE_CRYPTOGRAPHY else "unavailable")
    )
    emit_reference_keys()
    emit_canonical_encoding()
    emit_signing_vectors()
    emit_padding()
    emit_merkle()
    emit_typed_leaves()
    emit_provenance_hash()
    emit_fingerprint()
    emit_claim_and_proposal()
    emit_hpke_info()
    emit_identity_link_attestation()
    emit_hash_only_vectors()
    emit_pseudonym_derivation()
    emit_pseudonym_announcement()
    emit_trust_attestation()
    emit_keypackage_attestation()
    emit_key_event_slots()
    emit_witness_and_relay_objects()
    emit_commitment_and_service_record()
    print("\n".join(_LINES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
