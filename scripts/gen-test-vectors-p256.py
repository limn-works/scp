#!/usr/bin/env python3.12
"""Regenerates every keyed value printed in `.docs/specs/25-test-vectors.md`.

`.docs/specs/09-security-model.md` §9.5 mandates ECDSA on NIST P-256 with
SHA-256 for every SCP signature, from 2026-09-10. This script is the authority for
every byte §25 prints that depends on a key or a signature. It implements
P-256 field and point arithmetic, RFC 6979 deterministic ECDSA with SHA-256,
low-`s` normalization, SEC1 point encoding, HKDF-SHA256, HMAC-SHA256, the
§9.5.1 canonical hash construction, the RFC 6962 Merkle construction, the
MessagePack subset the SCP structures serializes into, and AES-128-GCM with
the RFC 8291 WebPush message encryption and the RFC 9180 HPKE base-mode seal
built on it.

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


def scp_text_form(identifier: bytes) -> str:
    """§25.29 Vector 57: `scp:` plus lowercase unpadded base32, 56 characters."""
    return "scp:" + base64.b32encode(identifier).decode().rstrip("=").lower()


def fixture_identifier(role: str) -> str:
    """A fixture party's identifier in text form, following the §25.9
    precedent: the identifier is SHA-256 of a stated ASCII label, one label
    per role, so no fixture claims a binding to a key it does not hold."""
    return scp_text_form(sha256(f"SCP test vector identifier {role}".encode()))


ID_SENDER = fixture_identifier("sender")
ID_VOTER = fixture_identifier("voter")
ID_SYNC_MEMBER = fixture_identifier("sync member")
ID_EVENT_LOG_ACTOR = fixture_identifier("event-log actor")
ID_APP = fixture_identifier("app")
ID_AGENT = fixture_identifier("agent")
ID_TTL_MEMBER_A = fixture_identifier("a")
ID_TTL_MEMBER_B = fixture_identifier("b")
ID_CONSEQUENCE_MEMBER = fixture_identifier("m")
ID_CAROL = fixture_identifier("carol")
ID_DAVE = fixture_identifier("dave")
ID_ALICE = fixture_identifier("alice")
ID_BOB = fixture_identifier("bob")
ID_PROPOSER = fixture_identifier("proposer")
ID_NEW_MEMBER = fixture_identifier("new member")
ID_HPKE_SENDER = fixture_identifier("hpke sender")
ID_HPKE_MEMBER = fixture_identifier("hpke member")
ID_ISSUER = fixture_identifier("issuer")
ID_SUBJECT = fixture_identifier("subject")
ID_VERIFIER = fixture_identifier("verifier")
ID_DEFINER = fixture_identifier("definer")
ID_PSEUDONYMIZED_MEMBER = fixture_identifier("pseudonymized member")
ID_ANNOUNCING_MEMBER = fixture_identifier("announcing member")
ID_OTHER_MEMBER = fixture_identifier("other member")
ID_LEAF_ATTESTER = fixture_identifier("leaf attester")


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
    # hash. The scp-protocol KAT `vector_35_data_provenance_hash_kat` derives
    # the same value independently through `rmp_serde`, so this pins the
    # encoder here to the encoder production uses.
    assert hexs(sha256(data_provenance_bytes())) == (
        "fa9cbfad74121473e2df010ac3b39f74bc30912d9168bc2efc77a25077ad1c01"
    ), "DataProvenance MessagePack mismatch"

    # AES-128, GCM and RFC 8291 message encryption (§25.30).
    webpush_self_test()


# ---------------------------------------------------------------------------
# §25.2 Reference key material
# ---------------------------------------------------------------------------

# The two 32-byte seeds SCP's test vectors have carried since before the curve
# change of §9.5. They are retained so the corpus's provenance stays legible,
# and they are inputs to the seed-to-scalar rule below and nothing more.
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
    emit_hex("vector_2.var_field", var_field("#active"))
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
        var_field(ID_SENDER),
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
            var_field(ID_VOTER),
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
            var_field(ID_SYNC_MEMBER),
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
KAT_ACTOR_DID = ID_EVENT_LOG_ACTOR


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
                mp_str(ID_APP),
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
        mp_array([mp_str(ID_AGENT), mp_uint(5000), mp_str("inference")]),
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
                mp_array([mp_str(ID_TTL_MEMBER_A), mp_str(ID_TTL_MEMBER_B)]),
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
        (
            f"member_did={ID_CONSEQUENCE_MEMBER};rule_index=2;"
            "trigger_kind=absence;action_type=suspend"
        ).encode(),
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
        mp_array([mp_str(ID_CAROL), mp_str("admin")]),
    ),
    (
        "MemberJoined",
        4,
        1_700_000_008,
        mp_array([mp_str(ID_DAVE), mp_str("member")]),
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
            mp_array([mp_str(ID_ALICE), mp_str(ID_BOB)]),
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
# §25.11 proposal ID, §25.12 HPKE info strings
# ---------------------------------------------------------------------------


def emit_proposal() -> None:
    section("§25.11 Governance proposal ID")
    action_bytes = json.dumps(
        {"AddMember": {"did": ID_NEW_MEMBER, "role": "member"}},
        separators=(",", ":"),
        sort_keys=False,
    ).encode()
    emit("vector_23.action_bytes_len", len(action_bytes))
    emit("vector_23.action_bytes_utf8", action_bytes.decode())
    emit_hex("vector_23.action_bytes", action_bytes)
    proposal_preimage = canonical_preimage(
        "SCP-PROPOSAL-V1:",
        var_field("gov-proposal-context"),
        var_field(ID_PROPOSER),
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
        + var_field(ID_HPKE_SENDER)
        + u64(42)
    )
    access_info = (
        b"scp-access-key-v1"
        + var_field("hpke-test-context")
        + var_field(ID_HPKE_MEMBER)
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
            var_field(ID_ISSUER),
            var_field(ID_ISSUER),
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
            var_field(ID_ISSUER),
            var_field(ID_SUBJECT),
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
        var_field(ID_PSEUDONYMIZED_MEMBER),
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
        var_field(ID_ISSUER),
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
PSEUDONYM_ROUTING_PREFIX = b"scp-pseudonym-routing-v1:"

PSEUDONYM_SEEDS = [
    ("vector_30", bytes.fromhex("01" * 32)),
    (
        "vector_31",
        bytes.fromhex(
            "9d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
    ),
]


def pseudonym_v1_public(identity_seed: bytes, context_id: bytes, name: str) -> bytes:
    """Returns the compressed v1 pseudonym point for an identity seed and context.

    The identity scalar comes from `identity_seed` under the §25.2 test-vector
    label, and the point follows the §9.10.4.A static (v1) recipe.
    """
    identity = keypair_from_seed(
        identity_seed, TEST_VECTOR_KEY_LABEL, f"{name} identity"
    )
    secret = hkdf(
        ikm=identity.private_bytes,
        salt=PSEUDONYM_SECRET_SALT,
        info=b"",
        length=32,
    )
    seed_v1 = hmac_sha256(secret, context_id + b"scp-pseudonym")
    return KeyPair(
        seed_to_scalar(seed_v1, PSEUDONYM_SCALAR_LABEL), f"{name} pseudonym v1"
    ).compressed


# The scp-client-wasm cross-target determinism test runs the §9.10.4.A recipe
# on native and on wasm32 against one golden. Its seed and context differ from
# Vectors 30 and 31, so a target that reproduced only those vectors (for
# example, through a lookup) would still fail it.
CROSS_TARGET_PSEUDONYM_SEED = bytes.fromhex("07" * 32)
CROSS_TARGET_PSEUDONYM_CONTEXT = b"scp-transport-kat-ctx"


def emit_cross_target_pseudonym() -> None:
    section("scp-client-wasm cross-target pseudonym golden (§9.10.4.A, v1)")
    emit_hex("cross_target.identity_seed", CROSS_TARGET_PSEUDONYM_SEED)
    emit("cross_target.context_id", CROSS_TARGET_PSEUDONYM_CONTEXT.decode())
    emit_hex(
        "cross_target.pseudonym_public_v1",
        pseudonym_v1_public(
            CROSS_TARGET_PSEUDONYM_SEED, CROSS_TARGET_PSEUDONYM_CONTEXT, "cross_target"
        ),
    )


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
        if key_v1.compressed != pseudonym_v1_public(seed, context_id.encode(), label):
            raise AssertionError(
                f"{label}: pseudonym_v1_public diverges from the vector"
            )
        emit_hex(
            f"{label}.routing_id_v1",
            sha256(PSEUDONYM_ROUTING_PREFIX + key_v1.compressed),
        )
        emit_hex(f"{label}.context_seed_v2", seed_v2)
        emit_hex(f"{label}.pseudonym_public_v2", key_v2.compressed)
        emit_hex(
            f"{label}.routing_id_v2",
            sha256(PSEUDONYM_ROUTING_PREFIX + key_v2.compressed),
        )


def emit_pseudonym_announcement() -> None:
    section("§25.19 Vector 36 pseudonym announcement wire format")
    wire = mp_map(
        [
            ("tag", mp_str("\0scp:pseudonym-announce:v1")),
            (
                "member_did",
                mp_str(ID_ANNOUNCING_MEMBER),
            ),
            ("pseudonym", mp_bin(b"\x42" * 32)),
        ]
    )
    emit("vector_36.member_did", ID_ANNOUNCING_MEMBER)
    emit("vector_36.other_member_did", ID_OTHER_MEMBER)
    emit_hex("vector_36.wire", wire)


# ---------------------------------------------------------------------------
# §25.23 KeyPackage attestation (§9.5.2, §9.18.7)
# ---------------------------------------------------------------------------

LEAF_ENCRYPTION_SEED = bytes.fromhex("33" * 32)
INIT_KEY_SEED = bytes.fromhex("11" * 32)
WRAPPING_KEY_SEED = bytes.fromhex("22" * 32)


KEY_ALGORITHM_ECDSA_P256_SHA256_ATTESTATION = 0x01  # §9.5.2 field 8, §9.18.17


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

    # §9.5.2's ten fields: `active_key` (field 7) is the key that signs the
    # attestation, §25.2's reference key, compressed; field 8 is
    # KEY_ALGORITHM_ECDSA_P256_SHA256 (ADR-066 decision 40).
    body_fields = (
        var_field(ID_LEAF_ATTESTER)
        + b"".join(fixed_field(key) for key in keys)
        + var_field("#active")
        + fixed_field(REF_KEY_1.compressed)
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256_ATTESTATION)
        + u64(1_700_000_000)
        + u64(1_700_086_400)
    )
    preimage = b"SCP-KEYPACKAGE-ATTESTATION-V1:" + body_fields
    assert len(preimage) == 411, len(preimage)
    emit_hex("vector_37.leaf_signature_key", leaf_signature_key)
    emit_hex("vector_37.leaf_encryption_key", leaf_encryption.uncompressed)
    emit_hex("vector_37.init_key", init.uncompressed)
    emit_hex("vector_37.wrapping_key", wrapping.uncompressed)
    digest = sign_and_emit("vector_37", preimage)
    signature = ecdsa_sign(REF_KEY_1.d, digest)
    extension_body = body_fields + signature
    assert len(extension_body) == 445, len(extension_body)
    emit_hex("vector_37.active_key", REF_KEY_1.compressed)
    emit("vector_37.extension_body_len", len(extension_body))
    emit_hex("vector_37.extension_body", extension_body)

    # The eight-field bytes the shipped code asserts until SCP-315 lands the
    # ten-field attestation of ADR-066 decision 40. This section carries no §25
    # heading, so spec 25 does not print it; it keeps those Rust literals
    # traceable to this generator meanwhile.
    section("Pre-decision-40 Vector 37 bytes that current code asserts until SCP-315")
    legacy_fields = (
        var_field(ID_LEAF_ATTESTER)
        + b"".join(fixed_field(key) for key in keys)
        + var_field("#active")
        + u64(1_700_000_000)
        + u64(1_700_086_400)
    )
    legacy_digest = sign_and_emit(
        "legacy_vector_37", b"SCP-KEYPACKAGE-ATTESTATION-V1:" + legacy_fields
    )
    legacy_body = legacy_fields + ecdsa_sign(REF_KEY_1.d, legacy_digest)
    emit("legacy_vector_37.extension_body_len", len(legacy_body))
    emit_hex("legacy_vector_37.extension_body", legacy_body)


# ---------------------------------------------------------------------------
# §25.25 Custody violation and counter-attestation (§9.5.2, §9.18.2)
# ---------------------------------------------------------------------------

# §25.25's custody-violation and counter-attestation vectors were deleted on 2026-09-10.
# The identity-substrate plan's §1 table marks both constructs CUT (Alec's 2026-08-25 Ruling 2,
# reconfirmed 2026-08-31), and Track U4 owns the teardown of the §9.5.2 preimage tables and the
# shipped code. Re-signing their preimages onto P-256 would have widened that teardown.


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# §25.26 Key-event indexed signatures, the cosigned head, and the relay proof
# (§9.7.4.2 definitions, §9.7.4.3, §9.18.2)
# ---------------------------------------------------------------------------

# The inception event's preimage is built here, in the field order §9.7.4.2's
# definitions fix. Vectors 41 and 42 pin its bytes, its digest, and the identifier
# that digest derives, then pin the indexed signature each form produces over it.

KIND_INCEPTION = 0x01
KIND_KEY_STATE = 0x02
ROLE_ROOT = 0x01
ROLE_ACTIVE = 0x02
CONDITION_CURRENT = 0x01
CUSTODY_PASSKEY = 0x01
KEY_ALGORITHM_ECDSA_P256_SHA256 = 0x01
CONTINUATION_COMMITMENT = 0x01
PREROTATION_SEPARATOR = b"SCP-PREROTATION-COMMITMENT-V1:"
KEL_EVENT_SEPARATOR = b"SCP-KEL-EVENT-V1:"
KEL_SEAL_SEPARATOR = b"SCP-KEL-SEAL-V1:"
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


def vector_key_state(witnessing_interval: int = VECTOR_WITNESSING_INTERVAL) -> bytes:
    """The key-state snapshot, in the order §9.7.4.2's definitions fix.

    The snapshot carries no next-set entry: each committed member's custody
    type and key algorithm travel beside the commitment they describe, in the
    continuation field of the commitment-fixing event.
    """
    return (
        u32(1)  # root threshold
        + u32(2)  # key count
        + key_state_entry(REF_KEY_1.compressed, ROLE_ROOT, CONDITION_CURRENT)
        + key_state_entry(REF_KEY_2.compressed, ROLE_ACTIVE, CONDITION_CURRENT)
        + u32(1)  # witness-set count
        + fixed_field(VECTOR_WITNESS_OPERATOR)
        + u32(witnessing_interval)
        + u8(ROLE_ACTIVE)  # service-key role discriminator
        + fixed_field(ZERO32)  # delegator: non-delegated
    )


def inception_preimage(form: int) -> bytes:
    """The inception event's signed preimage, in §9.7.4.2's field order.

    Every kind carries all twelve fields. A field this kind does not carry is
    present with the sentinel §9.7.4.2's definitions fix: one `0x00` byte for
    `standing_root`, and `BE32(0)` for a count-prefixed list.
    """
    commitment = sha256(PREROTATION_SEPARATOR + VECTOR_PREROTATION_POINT)
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_INCEPTION)  # 1. event_type
        + fixed_field(ZERO32)  # 2. identifier placeholder
        + u64(0)  # 3. sequence
        + fixed_field(ZERO32)  # 4. predecessor placeholder
        + u8(0)  # 5. standing_root: sentinel, the RootRecovery kind carries it
        + u32(1)
        + u8(0)  # 6. signer index list of the one root group
        + u32(1)
        + u8(form)  # 7. signature-form list of that group
        + u32(0)  # 8. revealed keys: sentinel, a reveal carries them
        + u32(1)
        + fixed_field(REF_KEY_1.compressed)
        + u32(1)  # 9. installed root set + threshold
        + vector_key_state()  # 10. key-state snapshot
        + u32(0)  # 11. key-event seals: sentinel, a KeyState carries them
        + u8(CONTINUATION_COMMITMENT)  # 12. continuation
        + u32(1)
        + fixed_field(commitment)
        + u8(CUSTODY_PASSKEY)  # the committed member's custody type
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)  # and its key algorithm
        + u32(1)
    )


# The `KeyState` at sequence 1 of the same identity. It changes the witnessing
# interval and nothing else, so R3's "a snapshot identical to its predecessor's"
# defect does not fire. It is the vector that pins the two composite sentinels:
# field 9, the installed root set and its threshold, writes `BE32(0)` and no
# trailing threshold, so its sentinel is four bytes and not eight; and field 12,
# the continuation, writes `BE32(0)` and never the one-byte `0x00`, because
# `0x00` is the registered live value declaring abandonment.
KEY_STATE_WITNESSING_INTERVAL = 7200
SEALED_EVENT_DIGEST = sha256(b"scp-25-sealed-delegate-event")


def key_state_preimage(identifier: bytes, predecessor_digest: bytes) -> bytes:
    """The `KeyState` event's signed preimage, in §9.7.4.2's field order."""
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_KEY_STATE)  # 1. event_type
        + fixed_field(identifier)  # 2. identifier
        + u64(1)  # 3. sequence
        + fixed_field(predecessor_digest)  # 4. predecessor_digest
        + u8(0)  # 5. standing_root: sentinel, one 0x00 byte
        + u32(1)
        + u8(0)  # 6. signer index list of the one root group
        + u32(1)
        + u8(0x01)  # 7. signature-form list of that group: the raw form
        + u32(0)  # 8. revealed keys: sentinel, a reveal carries them
        + u32(0)  # 9. installed root set + threshold: composite sentinel, 4 bytes
        + vector_key_state(KEY_STATE_WITNESSING_INTERVAL)  # 10. key-state snapshot
        + u32(1)  # 11. key-event seals, carried in substance
        + fixed_field(sha256(KEL_SEAL_SEPARATOR + SEALED_EVENT_DIGEST))
        + u32(0)  # 12. continuation: composite sentinel, 4 bytes, never 0x00
    )


def identifier_of(preimage: bytes) -> bytes:
    return sha256(KEL_ID_SEPARATOR + preimage)


# Set by emit_key_event_signatures(); §25.27's objects name Vector 41's event and identifier.
INCEPTION_DIGEST = b""
INCEPTION_IDENTIFIER = b""

WEBAUTHN_CHALLENGE_PREFIX = b"SCP-KEY-EVENT-V1:"
WEBAUTHN_RP_ID = b"ctx.network"
# Synthesized authenticatorData, in WebAuthn's own layout for an assertion:
#   rpIdHash (32) || flags (1) || signCount (4 big-endian).
# flags 0x05 sets user present (0x01) and user verified (0x04). §9.7.4.2's
# definitions require the user-presence bit and state no rule about the
# user-verification bit, so a conforming indexed signature may carry 0x01 here instead.
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


def emit_key_event_signatures() -> None:
    section("§25.26 Key-event preimage and indexed signatures")

    # --- Vector 41: an inception whose one root signature takes the raw form. ---
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
    # The other three routing derivations of §9.7.4.2 R13 over the same identifier.
    emit_hex("vector_41.routing_id_wit", sha256(b"scp:wit:" + identifier_41))
    emit_hex("vector_41.routing_id_wcf", sha256(b"scp:wcf:" + identifier_41))
    emit_hex("vector_41.routing_id_svc", sha256(b"scp:svc:" + identifier_41))
    raw_sig = ecdsa_sign(REF_KEY_1.d, digest_41)
    assert ecdsa_verify(REF_KEY_1.point, digest_41, raw_sig)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(REF_KEY_1, digest_41, raw_sig, "vector_41")
    assert int.from_bytes(raw_sig[32:], "big") * 2 <= N, "vector_41: high-s"
    emit("vector_41.indexed_signature_len", len(raw_sig))
    emit_hex("vector_41.indexed_signature", raw_sig)

    # --- Vector 42: an inception whose one root signature takes the assertion form. ---
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
    indexed_signature = (
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
    emit("vector_42.indexed_signature_len", len(indexed_signature))
    emit_hex("vector_42.indexed_signature", indexed_signature)

    # --- Vector 50: a `KeyState` that pins both composite sentinels. ---
    preimage_50 = key_state_preimage(identifier_41, digest_41)
    digest_50 = sha256(preimage_50)
    emit("vector_50.kind", "0x02")
    emit("vector_50.sequence", 1)
    emit_hex("vector_50.identifier", identifier_41)
    emit_hex("vector_50.predecessor_digest", digest_41)
    emit("vector_50.witnessing_interval", KEY_STATE_WITNESSING_INTERVAL)
    emit_hex("vector_50.sealed_event_digest", SEALED_EVENT_DIGEST)
    emit_hex(
        "vector_50.key_event_seal",
        sha256(KEL_SEAL_SEPARATOR + SEALED_EVENT_DIGEST),
    )
    emit("vector_50.field_9_sentinel", "00000000")
    emit("vector_50.field_12_sentinel", "00000000")
    emit(
        "vector_50.key_state_bytes",
        len(vector_key_state(KEY_STATE_WITNESSING_INTERVAL)),
    )
    emit("vector_50.preimage_len", len(preimage_50))
    emit_hex("vector_50.preimage", preimage_50)
    emit_hex("vector_50.preimage_digest", digest_50)
    # Field 9's sentinel is four bytes and never eight, and field 12's is four
    # bytes and never the one-byte `0x00`, which is the live abandonment value.
    assert preimage_50.count(b"\x00\x00\x00\x00") >= 2
    sig_50 = ecdsa_sign(REF_KEY_1.d, digest_50)
    assert ecdsa_verify(REF_KEY_1.point, digest_50, sig_50)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(REF_KEY_1, digest_50, sig_50, "vector_50")
    assert int.from_bytes(sig_50[32:], "big") * 2 <= N, "vector_50: high-s"
    emit("vector_50.indexed_signature_len", len(sig_50))
    emit_hex("vector_50.indexed_signature", sig_50)

    global INCEPTION_DIGEST, INCEPTION_IDENTIFIER
    INCEPTION_DIGEST = digest_41
    INCEPTION_IDENTIFIER = identifier_41


# --- §25.26 Vector 51: one key-state entry per registered `CustodyType` value ---
#
# Every other one-byte discriminator of the key-event preimage is registered
# with its value, and `CustodyType`'s nine are too (§9.7.4.2 definitions). The
# byte rides in every 45-byte key entry of the key-state snapshot, so it sits
# inside the inception preimage the identifier digests: two bindings numbering
# the nine differently derive two identifiers for one identity and each rejects
# every identity the other created. This fixture identity carries a 1-of-8 root
# and one `#active` key, so its snapshot's nine entries carry the nine values
# `0x01` through `0x09`, one each, and pin every byte.

CUSTODY_VALUES = (
    ("Passkey", 0x01),
    ("Fido2Token", 0x02),
    ("Hsm", 0x03),
    ("SecureEnclave", 0x04),
    ("AndroidKeystore", 0x05),
    ("EncryptedOfflineBackup", 0x06),
    ("ShamirShares", 0x07),
    ("PaperBackup", 0x08),
    ("Software", 0x09),
)

CUSTODY_ROOT_KEYS = tuple(
    keypair_from_seed(
        sha256(b"scp-25-custody-root-" + bytes([i])),
        TEST_VECTOR_KEY_LABEL,
        f"custody-registry root member {i}",
    )
    for i in range(8)
)
CUSTODY_ACTIVE_KEY = keypair_from_seed(
    sha256(b"scp-25-custody-active"), TEST_VECTOR_KEY_LABEL, "custody-registry #active"
)
CUSTODY_PREROTATION_KEY = keypair_from_seed(
    sha256(b"scp-25-custody-prerotation"),
    TEST_VECTOR_KEY_LABEL,
    "custody-registry pre-rotation",
)
CUSTODY_WITNESS_OPERATOR = sha256(b"scp-25-custody-witness-operator")
CUSTODY_INTERVAL_INCEPTION = 3600
CUSTODY_INTERVAL_KEY_STATE = 7200


def custody_key_state(witnessing_interval: int) -> bytes:
    """The custody-registry identity's snapshot: nine entries, nine custody bytes."""
    entries = b""
    for index, key in enumerate(CUSTODY_ROOT_KEYS):
        entries += (
            fixed_field(key.compressed)
            + u8(ROLE_ROOT)
            + u8(CONDITION_CURRENT)
            + u64(0)
            + u8(CUSTODY_VALUES[index][1])
            + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
        )
    entries += (
        fixed_field(CUSTODY_ACTIVE_KEY.compressed)
        + u8(ROLE_ACTIVE)
        + u8(CONDITION_CURRENT)
        + u64(0)
        + u8(CUSTODY_VALUES[8][1])
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
    )
    assert len(entries) == 9 * 45, len(entries)
    return (
        u32(1)  # root threshold: 1 of 8
        + u32(9)  # key count
        + entries
        + u32(1)  # witness-set count
        + fixed_field(CUSTODY_WITNESS_OPERATOR)
        + u32(witnessing_interval)
        + u8(ROLE_ACTIVE)  # service-key role discriminator
        + fixed_field(ZERO32)  # delegator: non-delegated
    )


def custody_inception_preimage() -> bytes:
    commitment = sha256(PREROTATION_SEPARATOR + CUSTODY_PREROTATION_KEY.compressed)
    installed_root = u32(8)
    for key in CUSTODY_ROOT_KEYS:
        installed_root += fixed_field(key.compressed)
    installed_root += u32(1)
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_INCEPTION)
        + fixed_field(ZERO32)
        + u64(0)
        + fixed_field(ZERO32)
        + u8(0)
        + u32(1)
        + u8(0)  # the root group names member 0
        + u32(1)
        + u8(0x01)  # the raw form
        + u32(0)
        + installed_root
        + custody_key_state(CUSTODY_INTERVAL_INCEPTION)
        + u32(0)
        + u8(CONTINUATION_COMMITMENT)
        + u32(1)
        + fixed_field(commitment)
        + u8(CUSTODY_PASSKEY)
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
        + u32(1)
    )


def custody_key_state_preimage(identifier: bytes, predecessor_digest: bytes) -> bytes:
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_KEY_STATE)
        + fixed_field(identifier)
        + u64(1)
        + fixed_field(predecessor_digest)
        + u8(0)
        + u32(1)
        + u8(0)
        + u32(1)
        + u8(0x01)
        + u32(0)
        + u32(0)  # field 9: composite sentinel
        + custody_key_state(CUSTODY_INTERVAL_KEY_STATE)
        + u32(0)  # field 11: no seal
        + u32(0)  # field 12: composite sentinel
    )


def emit_custody_registry_key_state() -> None:
    inception = custody_inception_preimage()
    inception_digest = sha256(inception)
    identifier = identifier_of(inception)
    preimage = custody_key_state_preimage(identifier, inception_digest)
    digest = sha256(preimage)

    emit("vector_51.root_set_size", len(CUSTODY_ROOT_KEYS))
    emit("vector_51.root_threshold", 1)
    for index, (name, value) in enumerate(CUSTODY_VALUES):
        key = CUSTODY_ROOT_KEYS[index] if index < 8 else CUSTODY_ACTIVE_KEY
        emit(f"vector_51.custody.{name}", f"0x{value:02x}")
        emit_hex(f"vector_51.key.{name}", key.compressed)
    emit_hex("vector_51.prerotation_key_compressed", CUSTODY_PREROTATION_KEY.compressed)
    emit_hex("vector_51.witness_operator", CUSTODY_WITNESS_OPERATOR)
    emit("vector_51.inception_commitment_custody", f"0x{CUSTODY_PASSKEY:02x}")
    emit("vector_51.inception_commitment_key_algorithm", f"0x{KEY_ALGORITHM_ECDSA_P256_SHA256:02x}")
    emit("vector_51.inception_preimage_len", len(inception))
    emit_hex("vector_51.inception_preimage", inception)
    emit_hex("vector_51.inception_preimage_digest", inception_digest)
    emit_hex("vector_51.identifier", identifier)
    emit_hex("vector_51.routing_id", sha256(b"scp:did:" + identifier))
    # The inception's root group names member 0 in the raw form, so its
    # signature field is one 64-byte r || s over the inception digest.
    inception_sig = ecdsa_sign(CUSTODY_ROOT_KEYS[0].d, inception_digest)
    assert ecdsa_verify(CUSTODY_ROOT_KEYS[0].point, inception_digest, inception_sig)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(
            CUSTODY_ROOT_KEYS[0], inception_digest, inception_sig, "vector_51.inception"
        )
    assert int.from_bytes(inception_sig[32:], "big") * 2 <= N, "vector_51.inception: high-s"
    emit("vector_51.inception_indexed_signature_len", len(inception_sig))
    emit_hex("vector_51.inception_indexed_signature", inception_sig)
    emit(
        "vector_51.key_state_bytes", len(custody_key_state(CUSTODY_INTERVAL_KEY_STATE))
    )
    emit("vector_51.preimage_len", len(preimage))
    emit_hex("vector_51.preimage", preimage)
    emit_hex("vector_51.preimage_digest", digest)
    # Every registered custody byte appears exactly once in the snapshot.
    snapshot = custody_key_state(CUSTODY_INTERVAL_KEY_STATE)
    for index, (_name, value) in enumerate(CUSTODY_VALUES):
        offset = 8 + index * 45 + 33 + 1 + 1 + 8
        assert snapshot[offset] == value, (index, snapshot[offset], value)
    sig = ecdsa_sign(CUSTODY_ROOT_KEYS[0].d, digest)
    assert ecdsa_verify(CUSTODY_ROOT_KEYS[0].point, digest, sig)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(CUSTODY_ROOT_KEYS[0], digest, sig, "vector_51")
    assert int.from_bytes(sig[32:], "big") * 2 <= N, "vector_51: high-s"
    emit("vector_51.indexed_signature_len", len(sig))
    emit_hex("vector_51.indexed_signature", sig)


# --- §25.26 Vector 52: the context-export signature preimage ---
#
# `23-sync-and-offline-strategy.md` §23.16.8 fixes the preimage as the
# separator, the one-byte scope tag, the 32-byte `key_state_head` written raw,
# and `JCS(ContextSnapshot)` under §9.5.1's variable-length rule, which is a
# 4-byte big-endian length prefix. Without the prefix pinned here a producer
# that read the displayed formula literally wrote the JCS bytes bare, and every
# export it signed failed at a producer that read the rule.

EXPORT_SEPARATOR = b"SCP-CONTEXT-EXPORT-V3:"
EXPORT_SCOPE_FULL = 0x00
EXPORT_SNAPSHOT = {
    "context_id": "b0e0d2ec6d9d4d2f9c4e7a1b3f5c8d90",
    "created_at": 1700000000,
    "creator_did": "<scp-identifier:creator>",
    "event_log_merkle_root": "00" * 32,
    "key_boundaries": [],
    "schema_version": 3,
}


def jcs(value: object) -> bytes:
    """RFC 8785 canonical JSON over the ASCII fixture above.

    Members sort by key, no insignificant whitespace, integers as integers.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def emit_context_export_preimage() -> None:
    snapshot_jcs = jcs(EXPORT_SNAPSHOT)
    key_state_head = sha256(custody_inception_preimage())
    preimage = (
        EXPORT_SEPARATOR
        + u8(EXPORT_SCOPE_FULL)
        + fixed_field(key_state_head)
        + var_field(snapshot_jcs)
    )
    digest = sha256(preimage)
    emit("vector_52.scope_tag", "0x00")
    emit_hex("vector_52.key_state_head", key_state_head)
    emit("vector_52.jcs_len", len(snapshot_jcs))
    emit("vector_52.jcs", snapshot_jcs.decode("utf-8"))
    emit("vector_52.preimage_len", len(preimage))
    emit_hex("vector_52.preimage", preimage)
    emit_hex("vector_52.preimage_digest", digest)
    # The JCS field carries the 4-byte prefix and never runs bare.
    assert var_field(snapshot_jcs)[:4] == u32(len(snapshot_jcs))
    sig = ecdsa_sign(REF_KEY_2.d, digest)
    assert ecdsa_verify(REF_KEY_2.point, digest, sig)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(REF_KEY_2, digest, sig, "vector_52")
    assert int.from_bytes(sig[32:], "big") * 2 <= N, "vector_52: high-s"
    emit_hex("vector_52.signature", sig)


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
    section("§25.27 Witness objects, relay proof, relay-list record")

    subject = INCEPTION_IDENTIFIER
    designating_digest = INCEPTION_DIGEST

    def cosigned_head(
        label,
        sequence,
        event_digest,
        previous,
        observed_at,
        seed,
        seed_event=designating_digest,
        seed_observed_at=COSIGN_OBSERVED_AT,
        key=REF_KEY_2,
    ):
        # §9.7.4.3: `seed` is 0x01 on the first head a witness cosigns for a
        # subject after a designation or a store loss, and 0x00 on every later
        # head. A head carrying 0x01 makes no fault proof, which is what
        # separates a declared re-seed from an equivocation. `seed_event` is the
        # preimage digest of the event the witness last seeded at, so two heads
        # from two seed epochs carry two values.
        assert seed in (0x00, 0x01), seed
        fields = (
            fixed_field(WITNESS_ID)
            + fixed_field(subject)
            + u64(sequence)
            + fixed_field(event_digest)
            + fixed_field(previous)
            + fixed_field(seed_event)
            + u64(seed_observed_at)
            + bytes([seed])
            + u64(observed_at)
        )
        assert len(fields) == 185, len(fields)
        assert previous != bytes(32), "previous_cosigned_digest is never zero"
        emit_hex(f"{label}.witness", WITNESS_ID)
        emit_hex(f"{label}.subject", subject)
        emit(f"{label}.sequence", sequence)
        emit_hex(f"{label}.event_digest", event_digest)
        emit_hex(f"{label}.previous_cosigned_digest", previous)
        emit_hex(f"{label}.seed_event", seed_event)
        emit(f"{label}.seed_observed_at", seed_observed_at)
        emit(f"{label}.seed", seed)
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
        "vector_43",
        0,
        designating_digest,
        designating_digest,
        COSIGN_OBSERVED_AT,
        seed=0x01,
    )

    # Vector 44: the relay proof of control. It carries no key-state position:
    # a non-transferable operator key has no position to name.
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
    # shared previous_cosigned_digest, two different event_digests, and `seed`
    # clear on both heads, and one shared seed (`seed_event`, `seed_observed_at`). Those are the six
    # conditions §9.7.4.3 states.
    baseline = sha256(b"scp-25-fault-proof-baseline-head")
    head_a = sha256(b"scp-25-fault-proof-successor-a")
    head_b = sha256(b"scp-25-fault-proof-successor-b")
    emit_hex("vector_46.shared_previous_cosigned_digest", baseline)
    cosigned_head("vector_46a", 21, head_a, baseline, COSIGN_OBSERVED_AT, seed=0x00)
    cosigned_head("vector_46b", 21, head_b, baseline, COSIGN_OBSERVED_AT + 1, seed=0x00)
    assert head_a != head_b, "vector_46: the two heads must differ"

    emit_community_relay_list()


# --- §25.27 Vector 49: the relay-list record ---

# `18-addressability-and-deployment.md` §18.5.1: the SDK ships a pointer to a
# relay-list context, and that context's `relay_list` outlet returns a record
# whose `entries` member is one JSON array of entries, each an object with four
# members — `operator`, `key`, `url` and `free`. The governor's `#active` key
# signs the record over
# SHA-256("SCP-RELAY-LIST-V1:" || context_id || sequence || governor || SHA-256(entries)).
# The two entries below are a fixture: the operators are digests of stated ASCII
# labels and the keys are §25.2's reference and secondary keys. The governor is
# Vector 41's identity, whose `#active` key is §25.2's secondary key.
RELAY_LIST_SEPARATOR = "SCP-RELAY-LIST-V1:"
RELAY_LIST_CONTEXT_ID = sha256(b"scp-25-relay-list-context")
RELAY_LIST_SEQUENCE = 1
RELAY_LIST_ENTRIES = [
    (
        sha256(b"scp-25-relay-operator"),
        REF_KEY_1.compressed,
        "wss://relay.example.com/scp/v1",
        True,
    ),
    (
        sha256(b"scp-25-witness-operator"),
        REF_KEY_2.compressed,
        "wss://relay2.example.com/scp/v1",
        False,
    ),
]


def community_relay_list_bytes() -> bytes:
    """The entries document's bytes: one JSON array, no insignificant whitespace.

    Member order is the order §18.5.1 lists: `operator`, `key`, `url`, `free`.
    A 32-byte identifier and a 33-byte SEC1 compressed point each print as
    lowercase hexadecimal, which §18.5.1 fixes for both.
    """
    entries = ",".join(
        '{{"operator":"{}","key":"{}","url":"{}","free":{}}}'.format(
            operator.hex(), key.hex(), url, "true" if free else "false"
        )
        for operator, key, url, free in RELAY_LIST_ENTRIES
    )
    return ("[" + entries + "]").encode()


def emit_community_relay_list() -> None:
    document = community_relay_list_bytes()
    emit("vector_49.entry_count", len(RELAY_LIST_ENTRIES))
    for index, (operator, key, url, free) in enumerate(RELAY_LIST_ENTRIES):
        emit_hex(f"vector_49.entry_{index}.operator", operator)
        emit_hex(f"vector_49.entry_{index}.key", key)
        emit(f"vector_49.entry_{index}.url", url)
        emit(f"vector_49.entry_{index}.free", "true" if free else "false")
    assert len({key for _, key, *_ in RELAY_LIST_ENTRIES}) == len(RELAY_LIST_ENTRIES), (
        "§18.5.1: two entries whose `key` bytes are equal are one operator"
    )
    emit("vector_49.document_len", len(document))
    emit("vector_49.document", document.decode())
    emit_hex("vector_49.document_bytes", document)
    entries_digest = sha256(document)
    emit_hex("vector_49.document_sha256", entries_digest)

    governor = INCEPTION_IDENTIFIER
    assert len(governor) == 32, "the governor is Vector 41's 32-byte identifier"
    record_fields = (
        fixed_field(RELAY_LIST_CONTEXT_ID)
        + u64(RELAY_LIST_SEQUENCE)
        + fixed_field(governor)
        + fixed_field(entries_digest)
    )
    assert len(record_fields) == 104, len(record_fields)
    emit_hex("vector_49.context_id", RELAY_LIST_CONTEXT_ID)
    emit("vector_49.sequence", RELAY_LIST_SEQUENCE)
    emit_hex("vector_49.governor", governor)
    emit("vector_49.field_bytes", len(record_fields))
    sign_and_emit(
        "vector_49",
        canonical_preimage(RELAY_LIST_SEPARATOR, record_fields),
        REF_KEY_2,
    )


# ---------------------------------------------------------------------------
# §25.28 The pre-rotation commitment and the service record
# (§9.7.4.2 definitions, `03-identity.md` §3.10.13, §9.18.2)
# ---------------------------------------------------------------------------

SERVICE_RECORD_SEPARATOR = "SCP-SERVICE-RECORD-V1:"
SERVICE_RECORD_SEQUENCE = 4
SERVICE_RECORD_RELAY_TYPE = "SCPRelay"
# The absent `bridgeTarget` of an SCPRelay entry: §9.5.1's absent-optional
# value for a fixed-length field, bare.
SERVICE_RECORD_ABSENT_BRIDGE_TARGET = sha256(b"\x00")
# The absent `wrappingKey` of an SCPRelay entry: §9.5.1's absent-optional
# value for a variable-length field, SHA-256(0x00) under a 4-byte length.
SERVICE_RECORD_ABSENT_WRAPPING_KEY = sha256(b"\x00")
# The bridge entry's `wrappingKey`: a fixture key standing for the wrapping-key
# entry of the node's device (`18-addressability-and-deployment.md` §18.2.1).
# Vector 41's key state carries no wrapping-key entry, so the vector pins the
# encoding and not a key-state lookup.
SERVICE_RECORD_WRAPPING_KEY = keypair_from_seed(
    sha256(b"scp-25-service-record-wrapping-key"),
    TEST_VECTOR_KEY_LABEL,
    "node device wrapping key",
)


def service_record_bridge_target(identifier: bytes) -> bytes:
    """The bridge entry's target: the identity routing ID of §10.12.4.1,
    SHA-256("scp:did:" || identifier) over Vector 41's 32 raw identifier bytes.

    It reads the identifier as an argument, never at import, because
    INCEPTION_IDENTIFIER is empty until Vector 41's emitter runs."""
    assert len(identifier) == 32, (
        f"vector_48: the bridgeTarget hashes Vector 41's 32-byte identifier, got {len(identifier)} bytes"
    )
    target = sha256(b"scp:did:" + identifier)
    assert target != SERVICE_RECORD_ABSENT_BRIDGE_TARGET, (
        "vector_48: a present bridgeTarget must differ from the absent sentinel"
    )
    return target


ServiceRecordEntry = tuple[str, str, str, bytes | None, bytes | None]


def service_record_entries(identifier: bytes) -> list[ServiceRecordEntry]:
    """Four entries in the order a record carries them, as (id, type,
    serviceEndpoint, bridgeTarget, wrappingKey).

    Each encodes its three strings under §9.5.1's variable-length rule, in the
    order id, type, serviceEndpoint, and carries no type discriminator beside
    them; an SCPRelay entry then encodes bridgeTarget as 32 bare bytes, where
    SHA-256(0x00) means "no target", and wrappingKey under the variable-length
    rule, where the 32 bytes SHA-256(0x00) mean "no key" (`03-identity.md`
    §3.10.13)."""
    return [
        ("#scp-relay-1", "SCPRelay", "wss://relay.example.com/scp/v1", None, None),
        ("#scp-relay-2", "SCPRelay", "wss://relay2.example.com/scp/v1", None, None),
        (
            "#private-state-1",
            "IdentityPrivateState",
            "wss://relay.example.com/scp/v1",
            None,
            None,
        ),
        (
            "#scp-relay-3",
            "SCPRelay",
            "wss://bridge.example.com/scp/v1",
            service_record_bridge_target(identifier),
            SERVICE_RECORD_WRAPPING_KEY.compressed,
        ),
    ]


def service_record_entry_bridge_target(entry_type: str, bridge_target: bytes | None) -> bytes:
    """The 32 bytes an SCPRelay entry signs after its strings; empty for any other type."""
    if entry_type != SERVICE_RECORD_RELAY_TYPE:
        assert bridge_target is None, "only an SCPRelay entry carries bridgeTarget"
        return b""
    if bridge_target is None:
        return SERVICE_RECORD_ABSENT_BRIDGE_TARGET
    assert len(bridge_target) == 32, len(bridge_target)
    return bridge_target


def service_record_entry_wrapping_key(
    entry_type: str, bridge_target: bytes | None, wrapping_key: bytes | None
) -> bytes:
    """The value an SCPRelay entry signs as wrappingKey, before its length
    prefix: the 33-byte compressed key, or SHA-256(0x00) when absent; empty for
    any other type."""
    if entry_type != SERVICE_RECORD_RELAY_TYPE:
        assert wrapping_key is None, "only an SCPRelay entry carries wrappingKey"
        return b""
    if wrapping_key is None:
        return SERVICE_RECORD_ABSENT_WRAPPING_KEY
    assert bridge_target is not None, "only a bridge entry carries wrappingKey"
    assert len(wrapping_key) == 33 and wrapping_key[0] in (2, 3), wrapping_key.hex()
    return wrapping_key


def service_record_entries_field(entries: list[ServiceRecordEntry]) -> bytes:
    """The `entries` field: a 4-byte count, then each entry under its type's layout."""
    body = b""
    for entry_id, entry_type, endpoint, bridge_target, wrapping_key in entries:
        body += var_field(entry_id) + var_field(entry_type) + var_field(endpoint)
        if entry_type == SERVICE_RECORD_RELAY_TYPE:
            body += service_record_entry_bridge_target(entry_type, bridge_target)
            body += var_field(
                service_record_entry_wrapping_key(entry_type, bridge_target, wrapping_key)
            )
        else:
            assert bridge_target is None and wrapping_key is None, entry_type
    return u32(len(entries)) + body


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
    assert len(identifier) == 32, "vector_48 runs after Vector 41 fixes the identifier"
    record_entries = service_record_entries(identifier)
    entries = service_record_entries_field(record_entries)
    fields = fixed_field(identifier) + u64(SERVICE_RECORD_SEQUENCE) + entries
    emit_hex("vector_48.identifier", identifier)
    emit("vector_48.sequence", SERVICE_RECORD_SEQUENCE)
    emit("vector_48.entry_count", len(record_entries))
    for index, (entry_id, entry_type, endpoint, bridge_target, wrapping_key) in enumerate(
        record_entries
    ):
        emit(f"vector_48.entry_{index}.id", entry_id)
        emit(f"vector_48.entry_{index}.type", entry_type)
        emit(f"vector_48.entry_{index}.serviceEndpoint", endpoint)
        signed_target = service_record_entry_bridge_target(entry_type, bridge_target)
        if signed_target:
            emit_hex(f"vector_48.entry_{index}.bridgeTarget", signed_target)
        signed_key = service_record_entry_wrapping_key(entry_type, bridge_target, wrapping_key)
        if signed_key:
            emit_hex(f"vector_48.entry_{index}.wrappingKey", signed_key)
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


# --- §25.29 reveal-authorized events, one R6 ranking, and the text form ---
#
# Every event below extends Vector 41's identity at sequence 1, so the standing
# commitment each reveal consumes is the one Vector 41's inception fixed, over
# the tertiary reference key (§25.2), and the standing root at each event's
# predecessor is Vector 41's one-member root, the reference key.

KIND_COMMITMENT_ROLLOVER = 0x03
KIND_ROOT_RECOVERY = 0x04
STANDING_ROOT_COSIGNS = 0x01
STANDING_ROOT_LOST = 0x02
CONDITION_SUPERSEDED = 0x02
FORM_RAW = 0x01

ROLLOVER_NEXT_KEY = keypair_from_seed(
    sha256(b"scp-25-rollover-next"), TEST_VECTOR_KEY_LABEL, "rollover next member"
)
COSIGNS_ROOT_KEY = keypair_from_seed(
    sha256(b"scp-25-recovery-cosigns-root"), TEST_VECTOR_KEY_LABEL, "CoSigns K' member"
)
COSIGNS_ACTIVE_KEY = keypair_from_seed(
    sha256(b"scp-25-recovery-cosigns-active"), TEST_VECTOR_KEY_LABEL, "CoSigns #active"
)
COSIGNS_NEXT_KEY = keypair_from_seed(
    sha256(b"scp-25-recovery-cosigns-next"),
    TEST_VECTOR_KEY_LABEL,
    "CoSigns next member",
)
LOST_ROOT_KEY = keypair_from_seed(
    sha256(b"scp-25-recovery-lost-root"), TEST_VECTOR_KEY_LABEL, "Lost K' member"
)
LOST_ACTIVE_KEY = keypair_from_seed(
    sha256(b"scp-25-recovery-lost-active"), TEST_VECTOR_KEY_LABEL, "Lost #active"
)
LOST_NEXT_KEY = keypair_from_seed(
    sha256(b"scp-25-recovery-lost-next"), TEST_VECTOR_KEY_LABEL, "Lost next member"
)


def one_member_group() -> bytes:
    """A signer index list naming member 0, or a form list naming the raw form."""
    return u32(1) + u8(0)


def one_raw_form() -> bytes:
    return u32(1) + u8(FORM_RAW)


def commitment_continuation(next_key: KeyPair) -> bytes:
    return (
        u8(CONTINUATION_COMMITMENT)
        + u32(1)
        + fixed_field(sha256(PREROTATION_SEPARATOR + next_key.compressed))
        + u8(CUSTODY_PASSKEY)
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
        + u32(1)
    )


def rollover_preimage(identifier: bytes, predecessor: bytes) -> bytes:
    """A `CommitmentRollover`: the reveal group, then the standing-root group."""
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_COMMITMENT_ROLLOVER)  # 1
        + fixed_field(identifier)  # 2
        + u64(1)  # 3
        + fixed_field(predecessor)  # 4
        + u8(0)  # 5. standing_root: sentinel
        + one_member_group()  # 6. reveal group's index list
        + one_member_group()  # 6. standing-root group's index list
        + one_raw_form()  # 7. reveal group's form list
        + one_raw_form()  # 7. standing-root group's form list
        + u32(1)
        + fixed_field(REF_KEY_3.compressed)  # 8. the revealed key
        + u32(0)  # 9. installed root set: composite sentinel
        + u32(0)  # 10. key-state snapshot: sentinel
        + u32(0)  # 11. key-event seals: sentinel
        + commitment_continuation(ROLLOVER_NEXT_KEY)  # 12
    )


CONTINUATION_ABANDONS = 0x00
CONDITION_COMPROMISED = 0x04
# Vector 69's `Compromised{from: N}` position: the event's own sequence, the
# largest N R8 admits on an event at sequence 1.
COMPROMISED_FROM = 1
COMPROMISE_ACTIVE_KEY = keypair_from_seed(
    sha256(b"scp-25-compromise-active"), TEST_VECTOR_KEY_LABEL, "post-compromise #active"
)


def abandoning_rollover_preimage(identifier: bytes, predecessor: bytes) -> bytes:
    """Vector 68: Vector 53's `CommitmentRollover` with field 12 declaring
    abandonment, the one-byte `0x00` and nothing after it."""
    pre = rollover_preimage(identifier, predecessor)
    fixed = commitment_continuation(ROLLOVER_NEXT_KEY)
    assert pre.endswith(fixed)
    return pre[: -len(fixed)] + u8(CONTINUATION_ABANDONS)


def compromised_key_state() -> bytes:
    """Vector 69's snapshot: the kept root first, then the `#active` key the event
    installs, then the dropped `#active` key as `Compromised{from: 1}`."""
    compromised = (
        fixed_field(REF_KEY_2.compressed)
        + u8(ROLE_ACTIVE)
        + u8(CONDITION_COMPROMISED)
        + u64(COMPROMISED_FROM)
        + u8(CUSTODY_PASSKEY)
        + u8(KEY_ALGORITHM_ECDSA_P256_SHA256)
    )
    assert len(compromised) == 45
    return (
        u32(1)  # root threshold
        + u32(3)  # key count
        + key_state_entry(REF_KEY_1.compressed, ROLE_ROOT, CONDITION_CURRENT)
        + key_state_entry(COMPROMISE_ACTIVE_KEY.compressed, ROLE_ACTIVE, CONDITION_CURRENT)
        + compromised
        + u32(1)
        + fixed_field(VECTOR_WITNESS_OPERATOR)
        + u32(VECTOR_WITNESSING_INTERVAL)
        + u8(ROLE_ACTIVE)
        + fixed_field(ZERO32)
    )


def compromised_key_state_preimage(identifier: bytes, predecessor: bytes) -> bytes:
    """Vector 69: a `KeyState` at sequence 1 over Vector 41, root-signed, no seals."""
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_KEY_STATE)  # 1
        + fixed_field(identifier)  # 2
        + u64(1)  # 3
        + fixed_field(predecessor)  # 4
        + u8(0)  # 5. standing_root: sentinel
        + one_member_group()  # 6. the root group's index list
        + one_raw_form()  # 7. the root group's form list
        + u32(0)  # 8. revealed keys: sentinel
        + u32(0)  # 9. installed root set: composite sentinel
        + compromised_key_state()  # 10
        + u32(0)  # 11. key-event seals: an empty list
        + u32(0)  # 12. continuation: composite sentinel
    )


def recovery_key_state(root: KeyPair, active: KeyPair) -> bytes:
    """The post-recovery snapshot: the current entries first, then one entry
    per key the event drops, each `Superseded` because a successor takes its role."""
    return (
        u32(1)  # root threshold
        + u32(4)  # key count
        + key_state_entry(root.compressed, ROLE_ROOT, CONDITION_CURRENT)
        + key_state_entry(active.compressed, ROLE_ACTIVE, CONDITION_CURRENT)
        + key_state_entry(REF_KEY_1.compressed, ROLE_ROOT, CONDITION_SUPERSEDED)
        + key_state_entry(REF_KEY_2.compressed, ROLE_ACTIVE, CONDITION_SUPERSEDED)
        + u32(1)
        + fixed_field(VECTOR_WITNESS_OPERATOR)
        + u32(VECTOR_WITNESSING_INTERVAL)
        + u8(ROLE_ACTIVE)
        + fixed_field(ZERO32)
    )


def recovery_preimage(
    identifier: bytes,
    predecessor: bytes,
    standing_root: int,
    root: KeyPair,
    active: KeyPair,
    next_key: KeyPair,
) -> bytes:
    """A `RootRecovery`: the reveal group, the K' group, and under `CoSigns`
    the standing-root group."""
    groups = 3 if standing_root == STANDING_ROOT_COSIGNS else 2
    return (
        KEL_EVENT_SEPARATOR
        + u8(KIND_ROOT_RECOVERY)  # 1
        + fixed_field(identifier)  # 2
        + u64(1)  # 3
        + fixed_field(predecessor)  # 4
        + u8(standing_root)  # 5
        + one_member_group() * groups  # 6. one index list per group
        + one_raw_form() * groups  # 7. one form list per group
        + u32(1)
        + fixed_field(REF_KEY_3.compressed)  # 8. the revealed key
        + u32(1)
        + fixed_field(root.compressed)
        + u32(1)  # 9. installed root set K' and its threshold
        + recovery_key_state(root, active)  # 10
        + u32(0)  # 11. key-event seals: sentinel
        + commitment_continuation(next_key)  # 12
    )


def sign_group(key: KeyPair, digest: bytes, label: str) -> bytes:
    sig = ecdsa_sign(key.d, digest)
    assert ecdsa_verify(key.point, digest, sig), label
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(key, digest, sig, label)
    assert int.from_bytes(sig[32:], "big") * 2 <= N, f"{label}: high-s"
    return sig


def rank_first_reveal(
    digest: bytes, signatures: list[bytes], root_group_index: int | None
) -> int:
    """R6 over a suffix whose first event reveals the standing commitment: rank 1
    where that event carries a root signature verifying against the root standing
    at its predecessor, which is Vector 41's reference key, and rank 2 otherwise."""
    if root_group_index is None:
        return 2
    return (
        1 if ecdsa_verify(REF_KEY_1.point, digest, signatures[root_group_index]) else 2
    )


def emit_reveal_ranking_and_text_form() -> None:
    section(
        "§25.29 Reveal-authorized events, an R6 ranking, and the identifier's text form"
    )
    identifier = INCEPTION_IDENTIFIER
    predecessor = INCEPTION_DIGEST
    standing = sha256(PREROTATION_SEPARATOR + REF_KEY_3.compressed)

    # --- Vector 53: a `CommitmentRollover`. ---
    pre53 = rollover_preimage(identifier, predecessor)
    d53 = sha256(pre53)
    reveal53 = sign_group(REF_KEY_3, d53, "vector_53.reveal")
    root53 = sign_group(REF_KEY_1, d53, "vector_53.standing_root")
    emit_hex("vector_53.identifier", identifier)
    emit_hex("vector_53.predecessor_digest", predecessor)
    emit_hex("vector_53.consumed_commitment", standing)
    emit_hex("vector_53.revealed_key", REF_KEY_3.compressed)
    emit_hex("vector_53.next_key", ROLLOVER_NEXT_KEY.compressed)
    emit_hex(
        "vector_53.next_commitment",
        sha256(PREROTATION_SEPARATOR + ROLLOVER_NEXT_KEY.compressed),
    )
    emit("vector_53.preimage_len", len(pre53))
    emit_hex("vector_53.preimage", pre53)
    emit_hex("vector_53.preimage_digest", d53)
    emit_hex("vector_53.reveal_signature", reveal53)
    emit_hex("vector_53.standing_root_signature", root53)
    emit("vector_53.signature_field_len", len(reveal53 + root53))
    emit_hex("vector_53.signature_field", reveal53 + root53)

    # --- Vector 54: a `RootRecovery{CoSigns}`. ---
    pre54 = recovery_preimage(
        identifier,
        predecessor,
        STANDING_ROOT_COSIGNS,
        COSIGNS_ROOT_KEY,
        COSIGNS_ACTIVE_KEY,
        COSIGNS_NEXT_KEY,
    )
    d54 = sha256(pre54)
    sigs54 = [
        sign_group(REF_KEY_3, d54, "vector_54.reveal"),
        sign_group(COSIGNS_ROOT_KEY, d54, "vector_54.installed_root"),
        sign_group(REF_KEY_1, d54, "vector_54.standing_root"),
    ]
    emit_hex("vector_54.installed_root_key", COSIGNS_ROOT_KEY.compressed)
    emit_hex("vector_54.active_key", COSIGNS_ACTIVE_KEY.compressed)
    emit_hex("vector_54.next_key", COSIGNS_NEXT_KEY.compressed)
    emit_hex(
        "vector_54.next_commitment",
        sha256(PREROTATION_SEPARATOR + COSIGNS_NEXT_KEY.compressed),
    )
    emit(
        "vector_54.key_state_bytes",
        len(recovery_key_state(COSIGNS_ROOT_KEY, COSIGNS_ACTIVE_KEY)),
    )
    emit("vector_54.preimage_len", len(pre54))
    emit_hex("vector_54.preimage", pre54)
    emit_hex("vector_54.preimage_digest", d54)
    emit_hex("vector_54.reveal_signature", sigs54[0])
    emit_hex("vector_54.installed_root_signature", sigs54[1])
    emit_hex("vector_54.standing_root_signature", sigs54[2])
    emit("vector_54.signature_field_len", len(b"".join(sigs54)))
    emit_hex("vector_54.signature_field", b"".join(sigs54))

    # --- Vector 55: a `RootRecovery{Lost}`. ---
    pre55 = recovery_preimage(
        identifier,
        predecessor,
        STANDING_ROOT_LOST,
        LOST_ROOT_KEY,
        LOST_ACTIVE_KEY,
        LOST_NEXT_KEY,
    )
    d55 = sha256(pre55)
    sigs55 = [
        sign_group(REF_KEY_3, d55, "vector_55.reveal"),
        sign_group(LOST_ROOT_KEY, d55, "vector_55.installed_root"),
    ]
    emit_hex("vector_55.installed_root_key", LOST_ROOT_KEY.compressed)
    emit_hex("vector_55.active_key", LOST_ACTIVE_KEY.compressed)
    emit_hex("vector_55.next_key", LOST_NEXT_KEY.compressed)
    emit_hex(
        "vector_55.next_commitment",
        sha256(PREROTATION_SEPARATOR + LOST_NEXT_KEY.compressed),
    )
    emit("vector_55.preimage_len", len(pre55))
    emit_hex("vector_55.preimage", pre55)
    emit_hex("vector_55.preimage_digest", d55)
    emit_hex("vector_55.reveal_signature", sigs55[0])
    emit_hex("vector_55.installed_root_signature", sigs55[1])
    emit("vector_55.signature_field_len", len(b"".join(sigs55)))
    emit_hex("vector_55.signature_field", b"".join(sigs55))

    # --- Vector 56: R6 ranks Vector 54's suffix 1 and Vector 55's suffix 2. ---
    rank54 = rank_first_reveal(d54, sigs54, 2)
    rank55 = rank_first_reveal(d55, sigs55, None)
    assert (rank54, rank55) == (1, 2), (rank54, rank55)
    emit_hex("vector_56.shared_prefix_head", predecessor)
    emit_hex("vector_56.standing_commitment", standing)
    emit_hex("vector_56.suffix_a_head", d54)
    emit("vector_56.suffix_a_rank", rank54)
    emit_hex("vector_56.suffix_b_head", d55)
    emit("vector_56.suffix_b_rank", rank55)
    emit_hex("vector_56.winner", d54)

    # --- Vector 57: the identifier's text form. ---
    text = scp_text_form(identifier)
    assert len(text) == 56 and text == text.lower() and "=" not in text
    assert base64.b32decode(text[4:].upper() + "====") == identifier
    emit_hex("vector_57.identifier", identifier)
    emit("vector_57.text_form", text)
    emit("vector_57.text_form_len", len(text))
    emit("vector_57.rejected_uppercase", "scp:" + text[4:].upper())
    emit("vector_57.rejected_padded", text + "====")

    # --- Vector 68: a root-co-signed `CommitmentRollover` that abandons. ---
    pre68 = abandoning_rollover_preimage(identifier, predecessor)
    d68 = sha256(pre68)
    reveal68 = sign_group(REF_KEY_3, d68, "vector_68.reveal")
    root68 = sign_group(REF_KEY_1, d68, "vector_68.standing_root")
    emit_hex("vector_68.consumed_commitment", standing)
    emit("vector_68.continuation", f"0x{CONTINUATION_ABANDONS:02x}")
    emit("vector_68.preimage_len", len(pre68))
    emit_hex("vector_68.preimage", pre68)
    emit_hex("vector_68.preimage_digest", d68)
    emit_hex("vector_68.reveal_signature", reveal68)
    emit_hex("vector_68.standing_root_signature", root68)
    emit("vector_68.signature_field_len", len(reveal68 + root68))
    emit_hex("vector_68.signature_field", reveal68 + root68)

    # --- Vector 69: a `KeyState` carrying `Compromised{from: 1}`. ---
    pre69 = compromised_key_state_preimage(identifier, predecessor)
    d69 = sha256(pre69)
    root69 = sign_group(REF_KEY_1, d69, "vector_69.root")
    emit_hex("vector_69.installed_active_key", COMPROMISE_ACTIVE_KEY.compressed)
    emit_hex("vector_69.compromised_key", REF_KEY_2.compressed)
    emit("vector_69.compromised_from", COMPROMISED_FROM)
    emit("vector_69.key_state_bytes", len(compromised_key_state()))
    emit("vector_69.preimage_len", len(pre69))
    emit_hex("vector_69.preimage", pre69)
    emit_hex("vector_69.preimage_digest", d69)
    emit_hex("vector_69.root_signature", root69)


# ---------------------------------------------------------------------------
# §25.30 WebPush vectors 59-60 (`10-infrastructure-and-self-hosting.md`
# §10.7.1, `22-human-readable-addressing.md` §22.11.4)
#
# AES-128 (FIPS 197) and GCM (NIST SP 800-38D) in pure Python, so the RFC 8291
# message encryption below needs nothing outside the standard library. The
# self-test reproduces FIPS 197 Appendix C.1, the GCM test case with a zero
# key and one zero block, and RFC 8291 Appendix A end to end, and checks
# against the `cryptography` package's AESGCM where that package imports.
# ---------------------------------------------------------------------------


def _aes_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        # p walks GF(2^8)* by multiplying by 3; q tracks the inverse of p.
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q
        for shift in (1, 2, 3, 4):
            x ^= ((q << shift) | (q >> (8 - shift))) & 0xFF
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_AES_SBOX = _aes_sbox()


def _xtime(b: int) -> int:
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else b << 1


def _aes128_expand(key: bytes) -> list[list[int]]:
    assert len(key) == 16
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = [_AES_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], t)])
    return [[b for w in words[r * 4 : r * 4 + 4] for b in w] for r in range(11)]


def aes128_encrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 11):
        s = [_AES_SBOX[b] for b in s]
        # ShiftRows on the column-major state.
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if rnd != 10:
            mixed = []
            for c in range(4):
                a = s[4 * c : 4 * c + 4]
                total = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [
                    a[j] ^ total ^ _xtime(a[j] ^ a[(j + 1) % 4]) for j in range(4)
                ]
            s = mixed
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]
    return bytes(s)


def _gf128_mul(x: int, y: int) -> int:
    r = 0xE1 << 120
    z = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= x
        x = (x >> 1) ^ r if x & 1 else x >> 1
    return z


def aes128_gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""
) -> bytes:
    """AES-128-GCM, 96-bit nonce, optional associated data; returns C || tag."""
    assert len(nonce) == 12
    rk = _aes128_expand(key)
    h = int.from_bytes(aes128_encrypt_block(rk, bytes(16)), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        counter = nonce + (2 + i // 16).to_bytes(4, "big")
        stream = aes128_encrypt_block(rk, counter)
        out += bytes(a ^ b for a, b in zip(plaintext[i : i + 16], stream))
    ghash = 0
    padded = (
        aad + bytes(-len(aad) % 16) + bytes(out) + bytes(-len(out) % 16)
    )
    for i in range(0, len(padded), 16):
        ghash = _gf128_mul(ghash ^ int.from_bytes(padded[i : i + 16], "big"), h)
    lengths = (8 * len(aad)).to_bytes(8, "big") + (8 * len(out)).to_bytes(8, "big")
    ghash = _gf128_mul(ghash ^ int.from_bytes(lengths, "big"), h)
    tag = bytes(
        a ^ b for a, b in zip(aes128_encrypt_block(rk, j0), ghash.to_bytes(16, "big"))
    )
    if _HAVE_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        assert AESGCM(key).encrypt(nonce, plaintext, aad or None) == bytes(out) + tag, (
            "the cryptography package computed a different AES-128-GCM output"
        )
    return bytes(out) + tag


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def ecdh_p256(private: int, public: Point) -> bytes:
    assert on_curve(public), "RFC 8291 §7: the peer key must lie on P-256"
    shared = scalar_mult_jacobian(private, public)
    assert shared == scalar_mult_affine(private, public)
    return shared[0].to_bytes(32, "big")


WEBPUSH_RECORD_SIZE = 4096


def webpush_encrypt(
    plaintext: bytes,
    ua_public: bytes,
    auth: bytes,
    as_private: int,
    salt: bytes,
    rs: int = WEBPUSH_RECORD_SIZE,
) -> dict[str, bytes]:
    """RFC 8291 §3.4 and RFC 8188 §2: one aes128gcm record, no padding."""
    assert len(ua_public) == 65 and ua_public[0] == 0x04
    assert len(auth) == 16 and len(salt) == 16
    as_public = encode_uncompressed(scalar_mult_jacobian(as_private, G))
    ecdh_secret = ecdh_p256(as_private, decode_point(ua_public))
    prk_key = hmac_sha256(auth, ecdh_secret)
    key_info = b"WebPush: info\x00" + ua_public + as_public
    ikm = hmac_sha256(prk_key, key_info + b"\x01")
    prk = hmac_sha256(salt, ikm)
    cek = hmac_sha256(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = hmac_sha256(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    record = plaintext + b"\x02"  # last-record delimiter, zero padding octets
    assert rs >= len(record) + 16 + 1, "RFC 8188 §2: the record must fit rs"
    ciphertext = aes128_gcm_encrypt(cek, nonce, record)
    header = salt + u32(rs) + bytes([len(as_public)]) + as_public
    return {
        "as_public": as_public,
        "ecdh_secret": ecdh_secret,
        "prk_key": prk_key,
        "ikm": ikm,
        "prk": prk,
        "cek": cek,
        "nonce": nonce,
        "header": header,
        "ciphertext": ciphertext,
        "body": header + ciphertext,
    }


# RFC 8291 Appendix A, verbatim.
RFC8291_PLAINTEXT = b"When I grow up, I want to be a watermelon"
RFC8291_AS_PRIVATE = b64url_decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
RFC8291_AS_PUBLIC = b64url_decode(
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
)
RFC8291_UA_PUBLIC = b64url_decode(
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
)
RFC8291_SALT = b64url_decode("DGv6ra1nlYgDCS1FRnbzlw")
RFC8291_AUTH = b64url_decode("BTBZMqHH6r4Tts7J_aSIgg")


def webpush_self_test() -> None:
    # FIPS 197 Appendix C.1.
    rk = _aes128_expand(bytes(range(16)))
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert hexs(aes128_encrypt_block(rk, block)) == (
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    ), "FIPS 197 C.1 mismatch"
    # GCM test case 2 of the GCM specification (zero key, zero IV, one zero
    # block).
    assert hexs(aes128_gcm_encrypt(bytes(16), bytes(12), bytes(16))) == (
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    ), "GCM test case 2 mismatch"
    # RFC 8291 Appendix A end to end.
    out = webpush_encrypt(
        RFC8291_PLAINTEXT,
        RFC8291_UA_PUBLIC,
        RFC8291_AUTH,
        int.from_bytes(RFC8291_AS_PRIVATE, "big"),
        RFC8291_SALT,
    )
    assert out["as_public"] == RFC8291_AS_PUBLIC, "RFC 8291 A as_public mismatch"
    assert b64url(out["cek"]) == "oIhVW04MRdy2XN9CiKLxTg", "RFC 8291 A CEK mismatch"
    assert b64url(out["nonce"]) == "4h_95klXJ5E_qnoN", "RFC 8291 A NONCE mismatch"
    assert b64url(out["body"]) == (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg"
        "Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVB"
        "St2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    ), "RFC 8291 A body mismatch"


WEBPUSH_ENDPOINT_MAX = 2048


def webpush_token(endpoint: str, p256dh: bytes, auth: bytes) -> bytes:
    """§22.11.4: BE32(len(endpoint)) || endpoint || p256dh (65) || auth (16)."""
    raw = endpoint.encode("ascii")
    assert 1 <= len(raw) <= WEBPUSH_ENDPOINT_MAX
    assert all(0x21 <= b <= 0x7E for b in raw)
    assert len(p256dh) == 65 and p256dh[0] == 0x04
    assert on_curve(decode_point(p256dh))
    assert len(auth) == 16
    return u32(len(raw)) + raw + p256dh + auth


def vapid_audience(endpoint: str) -> str:
    """RFC 8292 §2 and RFC 6454 §6.1: the push resource's origin."""
    from urllib.parse import urlsplit

    parts = urlsplit(endpoint)
    assert parts.scheme == "https" and parts.hostname
    host = parts.hostname
    if parts.port in (None, 443):
        return f"https://{host}"
    return f"https://{host}:{parts.port}"


WEBPUSH_ENDPOINT = "https://push.example.net/p/LBhhw0OohO-Wl4Oi971UGsB7sdQGUibx"
WEBPUSH_PORT_ENDPOINT = (
    "https://push.example.net:8443/p/LBhhw0OohO-Wl4Oi971UGsB7sdQGUibx"
)
WEBPUSH_PLAINTEXT = b'{"scp":"1"}'
WEBPUSH_JWT_EXP = 1_700_043_200
WEBPUSH_SUBJECT = "mailto:operator@relay.example"


def emit_webpush() -> None:
    section("§25.30 WebPush token, request body and VAPID JWT (vectors 59-60)")

    # --- Vector 59: the WebPush PushRegistration.token encoding. ---
    token = webpush_token(WEBPUSH_ENDPOINT, RFC8291_UA_PUBLIC, RFC8291_AUTH)
    assert len(token) == 4 + len(WEBPUSH_ENDPOINT) + 65 + 16
    emit("vector_59.endpoint", WEBPUSH_ENDPOINT)
    emit("vector_59.endpoint_len", len(WEBPUSH_ENDPOINT))
    emit_hex("vector_59.p256dh", RFC8291_UA_PUBLIC)
    emit_hex("vector_59.auth", RFC8291_AUTH)
    emit("vector_59.token_len", len(token))
    emit_hex("vector_59.token", token)
    emit("vector_59.max_token_len", 4 + WEBPUSH_ENDPOINT_MAX + 65 + 16)

    # --- Vector 60: the wake body and the VAPID Authorization header. ---
    out = webpush_encrypt(
        WEBPUSH_PLAINTEXT,
        RFC8291_UA_PUBLIC,
        RFC8291_AUTH,
        int.from_bytes(RFC8291_AS_PRIVATE, "big"),
        RFC8291_SALT,
    )
    assert len(out["body"]) == 86 + len(WEBPUSH_PLAINTEXT) + 1 + 16 == 114
    emit("vector_60.plaintext", WEBPUSH_PLAINTEXT.decode())
    emit_hex("vector_60.plaintext_hex", WEBPUSH_PLAINTEXT)
    emit_hex("vector_60.as_private", RFC8291_AS_PRIVATE)
    emit_hex("vector_60.as_public", out["as_public"])
    emit_hex("vector_60.salt", RFC8291_SALT)
    emit("vector_60.rs", WEBPUSH_RECORD_SIZE)
    emit_hex("vector_60.ecdh_secret", out["ecdh_secret"])
    emit_hex("vector_60.prk_key", out["prk_key"])
    emit_hex("vector_60.ikm", out["ikm"])
    emit_hex("vector_60.prk", out["prk"])
    emit_hex("vector_60.cek", out["cek"])
    emit_hex("vector_60.nonce", out["nonce"])
    emit_hex("vector_60.header", out["header"])
    emit_hex("vector_60.ciphertext", out["ciphertext"])
    emit("vector_60.body_len", len(out["body"]))
    emit_hex("vector_60.body", out["body"])

    aud = vapid_audience(WEBPUSH_ENDPOINT)
    assert aud == "https://push.example.net"
    assert vapid_audience(WEBPUSH_PORT_ENDPOINT) == "https://push.example.net:8443"
    jwt_header = b64url(b'{"typ":"JWT","alg":"ES256"}')
    claims = json.dumps(
        {"aud": aud, "exp": WEBPUSH_JWT_EXP, "sub": WEBPUSH_SUBJECT},
        separators=(",", ":"),
    ).encode()
    signing_input = (jwt_header + "." + b64url(claims)).encode("ascii")
    digest = sha256(signing_input)
    signature = ecdsa_sign(REF_KEY_1.d, digest)
    assert ecdsa_verify(REF_KEY_1.point, digest, signature)
    if _HAVE_CRYPTOGRAPHY:
        _verify_with_cryptography(REF_KEY_1, digest, signature, "vector_60.jwt")
    jwt = signing_input.decode("ascii") + "." + b64url(signature)
    k = b64url(REF_KEY_1.uncompressed)
    emit("vector_60.aud", aud)
    emit("vector_60.aud_non_default_port", vapid_audience(WEBPUSH_PORT_ENDPOINT))
    emit("vector_60.jwt_claims", claims.decode())
    emit("vector_60.jwt_signing_input", signing_input.decode("ascii"))
    emit_hex("vector_60.jwt_digest", digest)
    emit_hex("vector_60.jwt_signature", signature)
    emit("vector_60.jwt", jwt)
    emit("vector_60.vapid_k", k)
    emit("vector_60.authorization", f"vapid t={jwt}, k={k}")


def challenge_verification_id(
    verifier: str,
    subject: str,
    capability_uri: str,
    challenge_id: bytes,
    attempt: int,
    timestamp: int,
) -> tuple[bytes, bytes]:
    """`07-trust-validation-and-capabilities.md` §7.3.4: the preimage and the
    value of `verification_id`."""
    pre = (
        var_field(verifier)
        + var_field(subject)
        + var_field(capability_uri)
        + fixed_field(challenge_id)
        + u32(attempt)
        + u64(timestamp)
    )
    return pre, sha256(pre)


def challenge_verification_preimage(
    verification_id: bytes,
    verifier: str,
    subject: str,
    capability_uri: str,
    definition_digest: bytes,
    suite_digest: bytes,
    challenge_id: bytes,
    attempt: int,
    response_digest: bytes,
    max_retries: int,
    cooldown_secs: int,
    pass_threshold_bps: int,
    min_category_cases: int,
    passed: bool,
    score: int,
    test_count: int,
    pass_count: int,
    challenge_created_at: int,
    challenge_expires_at: int,
    timestamp: int,
    expires_at: int,
    context_id: str,
) -> bytes:
    """§7.3.4's `R_v`: 22 signed fields, none optional."""
    return canonical_preimage(
        "SCP-CHALLENGE-VERIFY-V1:",
        fixed_field(verification_id),
        var_field(verifier),
        var_field(subject),
        var_field(capability_uri),
        fixed_field(definition_digest),
        fixed_field(suite_digest),
        fixed_field(challenge_id),
        u32(attempt),
        fixed_field(response_digest),
        u32(max_retries),
        u32(cooldown_secs),
        u32(pass_threshold_bps),
        u32(min_category_cases),
        u8(1 if passed else 0),
        u32(score),
        u32(test_count),
        u32(pass_count),
        u64(challenge_created_at),
        u64(challenge_expires_at),
        u64(timestamp),
        u64(expires_at),
        var_field(context_id),
    )


def capability_definition_preimage(
    capability_uri: str,
    min_cases_tag: int,
    min_cases: int,
    pass_threshold_bps: int,
    max_retries: int,
    cooldown_secs: int,
    description: str,
) -> bytes:
    """§7.3.4.6's `Def`. The tag is 0 for `Total` and 1 for `PerCategory`."""
    return canonical_preimage(
        "SCP-CAPABILITY-DEFINITION-V1:",
        var_field(capability_uri),
        u8(min_cases_tag),
        u32(min_cases),
        u32(pass_threshold_bps),
        u32(max_retries),
        u32(cooldown_secs),
        var_field(description),
    )


def emit_challenge_vectors() -> None:
    section("§25.31 Trust challenge request, response, record and definition (§7.3.4)")
    # An identifier-scoped URI: a protocol URI with one case is a request a
    # conforming SDK refuses, because `schema-validation/v1` sets a minimum of
    # 20 cases (§7.3.4.3).
    capability_uri = ID_DEFINER + ":capability:schema-validation/v1"
    context_id = "test-context-01"
    created_at, expires_at = 1700000000, 1700086400
    max_retries, cooldown_secs, threshold = 2, 3600, 8000

    # --- Vector 65: the capability definition the fixture URI follows. ---
    pre65 = capability_definition_preimage(
        capability_uri,
        0,
        1,
        threshold,
        max_retries,
        cooldown_secs,
        "Fixture definition for spec 25 vectors 59-62.",
    )
    definition_digest = sha256(pre65)
    emit("vector_65.preimage_len", len(pre65))
    emit_hex("vector_65.preimage", pre65)
    emit_hex("vector_65.definition_digest", definition_digest)

    # --- Vector 61: the challenge request. ---
    challenge_id = bytes(range(1, 33))
    test_input = {"name": "widget", "count": 3}
    expected = {
        "SchemaMatch": {"schema": {"type": "object", "required": ["name", "count"]}}
    }
    input_jcs = jcs(test_input)
    expected_jcs = jcs(expected)
    test_case = (
        var_field("schema-validation-001")
        + var_field(input_jcs)
        + var_field("schema")
        + u32(10000)
    )
    test_cases_field = u32(1) + test_case
    suite_digest = sha256(test_cases_field)
    pre61 = canonical_preimage(
        "SCP-CHALLENGE-REQ-V1:",
        fixed_field(challenge_id),
        var_field(capability_uri),
        fixed_field(definition_digest),
        test_cases_field,
        u64(created_at),
        u64(expires_at),
        u32(max_retries),
        u32(cooldown_secs),
        u32(threshold),
        var_field(context_id),
        var_field(ID_VERIFIER),
        var_field(ID_SUBJECT),
    )
    request_digest = sha256(pre61)
    emit_hex("vector_61.challenge_id", challenge_id)
    emit("vector_61.verifier", ID_VERIFIER)
    emit("vector_61.definer", ID_DEFINER)
    emit("vector_61.capability_uri", capability_uri)
    emit("vector_61.subject", ID_SUBJECT)
    emit("vector_61.input_jcs", input_jcs.decode())
    emit("vector_61.expected_jcs", expected_jcs.decode())
    emit("vector_61.test_case_field_len", len(test_cases_field))
    emit_hex("vector_61.test_case_field", test_cases_field)
    emit_hex("vector_61.suite_digest", suite_digest)
    emit("vector_61.preimage_len", len(pre61))
    emit_hex("vector_61.preimage", pre61)
    emit_hex("vector_61.digest", request_digest)
    # No byte of the request derives from the expected output (§7.3.4).
    assert expected_jcs not in pre61

    # --- Responses: attempt 1 (fails the schema) and Vector 64 (attempt 2). ---
    response_digests = {}
    for label, attempt, output in (
        ("vector_62.response", 1, {"name": "widget"}),
        ("vector_64", 2, {"count": 3, "name": "widget"}),
    ):
        pre = canonical_preimage(
            "SCP-CHALLENGE-RESP-V1:",
            fixed_field(challenge_id),
            fixed_field(request_digest),
            var_field(ID_SUBJECT),
            u32(attempt),
            u32(1),
            var_field("schema-validation-001"),
            var_field(jcs(output)),
        )
        response_digests[attempt] = sha256(pre)
        emit(f"{label}.output_jcs", jcs(output).decode())
        emit(f"{label}.preimage_len", len(pre))
        emit_hex(f"{label}.preimage", pre)
        emit_hex(f"{label}.digest", response_digests[attempt])

    # --- Vectors 62 and 63: the verification records of attempts 1 and 2. ---
    # Vector 63 is graded exactly `cooldown_secs` after Vector 62, the
    # cooldown boundary (§7.3.4 step 3).
    for label, attempt, ts, passed, score, pass_count in (
        ("vector_62", 1, 1700000600, False, 0, 0),
        ("vector_63", 2, 1700000600 + cooldown_secs, True, 10000, 1),
    ):
        record_expires_at = ts + 7776000
        vid_pre, vid = challenge_verification_id(
            ID_VERIFIER, ID_SUBJECT, capability_uri, challenge_id, attempt, ts
        )
        pre = challenge_verification_preimage(
            vid,
            ID_VERIFIER,
            ID_SUBJECT,
            capability_uri,
            definition_digest,
            suite_digest,
            challenge_id,
            attempt,
            response_digests[attempt],
            max_retries,
            cooldown_secs,
            threshold,
            1,
            passed,
            score,
            1,
            pass_count,
            created_at,
            expires_at,
            ts,
            record_expires_at,
            context_id,
        )
        emit(f"{label}.attempt", attempt)
        emit(f"{label}.timestamp", ts)
        emit(f"{label}.expires_at", record_expires_at)
        emit(f"{label}.verification_id_preimage_len", len(vid_pre))
        emit_hex(f"{label}.verification_id_preimage", vid_pre)
        emit_hex(f"{label}.verification_id", vid)
        emit(f"{label}.preimage_len", len(pre))
        emit_hex(f"{label}.preimage", pre)
        emit_hex(f"{label}.digest", sha256(pre))
        assert ABSENT_SENTINEL not in pre, label


# ---------------------------------------------------------------------------
# §25.28 Vector 70: push signing bytes (`09-security-model.md` §9.5.2) and
# push routing ids (§9.18.2), including a tier 3 bridge entry's. The bridge
# entry is Vector 48's entry 3, so this emitter runs after Vector 41 sets
# INCEPTION_IDENTIFIER.
# ---------------------------------------------------------------------------

PUSH_TOKEN = bytes.fromhex("0123456789abcdef")
PUSH_TIMESTAMP = 1_700_000_000
PUSH_DEREGISTER_TIMESTAMP = 1_700_000_300
PUSH_RELAYS = ("wss://relay.example", "wss://relay.example/scp/v1")
PUSH_PLATFORM_APNS = 0x01
PUSH_PLATFORM_FCM = 0x02
PUSH_ROUTING_PREFIX = b"scp-push-registration"
PUSH_BRIDGE_ROUTING_PREFIX = b"scp-push-bridge:"


def push_bridge_target(bridge_target: bytes | None) -> bytes:
    """§9.5.2 `bridge_target`: 32 bare bytes, the target or SHA-256(0x00)."""
    if bridge_target is None:
        return SERVICE_RECORD_ABSENT_BRIDGE_TARGET
    assert len(bridge_target) == 32, len(bridge_target)
    assert bridge_target != SERVICE_RECORD_ABSENT_BRIDGE_TARGET
    return bridge_target


def push_register_bytes(relay_url: str, bridge_target: bytes | None = None) -> bytes:
    """§9.5.2 `PushRegistration`: registrant, platform, token, routing ids,
    timestamp, relay URL, bridge target."""
    assert len(ID_SENDER) == 56
    routing_ids = [
        sha256(b"SCP test vector push routing id 1"),
        sha256(b"SCP test vector push routing id 2"),
    ]
    return canonical_preimage(
        "SCP-PUSH-REGISTER-V1:",
        var_field(ID_SENDER),
        u8(PUSH_PLATFORM_APNS),
        var_field(PUSH_TOKEN),
        u32(len(routing_ids)),
        *routing_ids,
        u64(PUSH_TIMESTAMP),
        var_field(relay_url),
        push_bridge_target(bridge_target),
    )


def push_deregister_bytes(relay_url: str, bridge_target: bytes | None = None) -> bytes:
    """§9.5.2 `PushDeregistration`: registrant, platform, token, timestamp,
    relay URL, bridge target."""
    return canonical_preimage(
        "SCP-PUSH-DEREGISTER-V1:",
        var_field(ID_SENDER),
        u8(PUSH_PLATFORM_FCM),
        var_field(PUSH_TOKEN),
        u64(PUSH_DEREGISTER_TIMESTAMP),
        var_field(relay_url),
        push_bridge_target(bridge_target),
    )


def emit_push_signing_bytes() -> None:
    section("§25.28 Vector 70 push signing bytes and push routing ids")
    for tag, relay in zip(("a", "b"), PUSH_RELAYS, strict=True):
        register = push_register_bytes(relay)
        deregister = push_deregister_bytes(relay)
        emit("push.relay_" + tag, relay)
        emit_hex("push.register_" + tag, register)
        emit_hex("push.deregister_" + tag, deregister)
        emit_hex("push.routing_id_" + tag, sha256(PUSH_ROUTING_PREFIX + relay.encode()))
    assert len(push_register_bytes(PUSH_RELAYS[0])) == 225
    assert len(push_deregister_bytes(PUSH_RELAYS[0])) == 159
    assert push_register_bytes(PUSH_RELAYS[0])[-32:] == SERVICE_RECORD_ABSENT_BRIDGE_TARGET

    # Vector 48's entry 3, the tier 3 bridge entry.
    _id, entry_type, bridge_url, target, _key = service_record_entries(INCEPTION_IDENTIFIER)[3]
    assert entry_type == SERVICE_RECORD_RELAY_TYPE and target is not None
    emit("push.bridge_url", bridge_url)
    emit_hex("push.bridge_target", target)
    register = push_register_bytes(bridge_url, target)
    deregister = push_deregister_bytes(bridge_url, target)
    emit_hex("push.register_bridge", register)
    emit_hex("push.deregister_bridge", deregister)
    assert register[-32:] == target and deregister[-32:] == target
    assert register[:-32] == push_register_bytes(bridge_url)[:-32]
    tier3_preimage = PUSH_BRIDGE_ROUTING_PREFIX + bridge_url.encode() + target
    assert len(tier3_preimage) == 79, len(tier3_preimage)
    tier3 = sha256(tier3_preimage)
    direct = sha256(PUSH_ROUTING_PREFIX + bridge_url.encode())
    emit("push.tier3_preimage_len", len(tier3_preimage))
    emit_hex("push.tier3_preimage", tier3_preimage)
    emit_hex("push.tier3_routing_id", tier3)
    emit_hex("push.bridge_relay_routing_id", direct)
    assert tier3 != direct
    # The two prefixes differ at their tenth byte ("b" in "scp-push-bridge:"
    # against "r" in "scp-push-registration"), so the two hash inputs differ
    # whatever URL and target follow. A tier 3 ID therefore never equals the
    # "scp-push-registration" ID of the bridge URL extended by the target.
    assert PUSH_BRIDGE_ROUTING_PREFIX[9:10] == b"b" and PUSH_ROUTING_PREFIX[9:10] == b"r"
    assert tier3 != sha256(PUSH_ROUTING_PREFIX + bridge_url.encode() + target)


# ---------------------------------------------------------------------------
# §25.32 participation signer vectors 66-67
# (`07-trust-validation-and-capabilities.md` §7.3.2.1)
#
# Vector 66 derives the participation signing keypair from a seed and a
# context id. Vector 67 seals that seed with RFC 9180 HPKE base mode,
# DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM, to the reference
# key, with the secondary scalar fixed as the ephemeral key so the bytes
# reproduce. The AAD is empty, which is what `aes128_gcm_encrypt` computes.
# ---------------------------------------------------------------------------

PARTICIPATION_SEED = bytes(range(32))
PARTICIPATION_CONTEXT_ID = b"context-alpha"
PARTICIPATION_SIGNER_SALT_LABEL = b"SCP-PARTICIPATION-SIGNER-V1"
PARTICIPATION_SIGNER_INFO_PREFIX = b"scp-participation-signer:"
PARTICIPATION_SEED_WRAP_INFO_PREFIX = b"scp-participation-seed-wrap:"
HPKE_SUITE_KEM = b"KEM" + u16(0x0010)
HPKE_SUITE = b"HPKE" + u16(0x0010) + u16(0x0001) + u16(0x0001)


def hpke_labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def hpke_labeled_expand(
    suite: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    return hkdf_expand(prk, u16(length) + b"HPKE-v1" + suite + label + info, length)


def participation_signer(
    seed: bytes, context_id: bytes
) -> tuple[bytes, bytes, KeyPair]:
    salt = sha256(PARTICIPATION_SIGNER_SALT_LABEL)
    prk = hkdf_extract(salt, seed)
    okm = hkdf_expand(prk, PARTICIPATION_SIGNER_INFO_PREFIX + context_id, 48)
    scalar = (int.from_bytes(okm, "big") % (N - 1)) + 1
    return prk, okm, KeyPair(scalar, "participation signer")


def emit_participation_seed() -> None:
    section("§25.32 Participation signer derivation and seed wrap")
    salt = sha256(PARTICIPATION_SIGNER_SALT_LABEL)
    info = PARTICIPATION_SIGNER_INFO_PREFIX + PARTICIPATION_CONTEXT_ID
    prk, okm, signer = participation_signer(
        PARTICIPATION_SEED, PARTICIPATION_CONTEXT_ID
    )
    assert len(info) == 38
    emit_hex("vector_66.seed", PARTICIPATION_SEED)
    emit_hex("vector_66.salt", salt)
    emit_hex("vector_66.info", info)
    emit_hex("vector_66.prk", prk)
    emit_hex("vector_66.okm", okm)
    emit_hex("vector_66.scalar", signer.private_bytes)
    emit_hex("vector_66.signer_public_key_compressed", signer.compressed)
    emit_hex("vector_66.signer_public_key_uncompressed", signer.uncompressed)

    wrap_info = PARTICIPATION_SEED_WRAP_INFO_PREFIX + PARTICIPATION_CONTEXT_ID
    assert len(wrap_info) == 41
    enc = REF_KEY_2.uncompressed
    dh = ecdh_p256(REF_KEY_2.d, REF_KEY_1.point)
    assert dh == ecdh_p256(REF_KEY_1.d, REF_KEY_2.point)
    eae_prk = hpke_labeled_extract(HPKE_SUITE_KEM, b"", b"eae_prk", dh)
    shared_secret = hpke_labeled_expand(
        HPKE_SUITE_KEM, eae_prk, b"shared_secret", enc + REF_KEY_1.uncompressed, 32
    )
    psk_id_hash = hpke_labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = hpke_labeled_extract(HPKE_SUITE, b"", b"info_hash", wrap_info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = hpke_labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    key = hpke_labeled_expand(HPKE_SUITE, secret, b"key", context, 16)
    base_nonce = hpke_labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12)
    ciphertext = aes128_gcm_encrypt(key, base_nonce, PARTICIPATION_SEED)
    assert len(ciphertext) == 48
    emit_hex("vector_67.recipient_public_key", REF_KEY_1.uncompressed)
    emit_hex("vector_67.ephemeral_scalar", REF_KEY_2.private_bytes)
    emit_hex("vector_67.info", wrap_info)
    emit_hex("vector_67.dh", dh)
    emit_hex("vector_67.enc", enc)
    emit_hex("vector_67.shared_secret", shared_secret)
    emit_hex("vector_67.key", key)
    emit_hex("vector_67.base_nonce", base_nonce)
    emit_hex("vector_67.ciphertext", ciphertext)


# ---------------------------------------------------------------------------
# §25.33 concurrent-commit fork-merge vectors 71-79
# (`09-security-model.md` §9.5.2, §9.7.2, `07-trust-validation-and-capabilities.md`
# §7.3.1.1 "Concurrent Commits and fork merge", ADR-067)
#
# None of these vectors carries a signature. Vectors 71 and 72 are canonical
# preimages under the §9.5.1 construction; Vector 73 is a MessagePack fork
# record; Vector 75 is the child-secret PPRF over RFC 9420 ExpandWithLabel.
# Vectors 73 and 79 also compute the admission bound and the ranks spec 25
# tabulates, so a changed rule fails here and not only in the spec text.
# ---------------------------------------------------------------------------

FORK_CONTEXT_ID = b"context-alpha"
FORK_NOTICE_DOMAIN = "SCP-FORK-NOTICE-V1:"
DEPARTURE_DOMAIN = "SCP-DEPARTURE-V1:"
MERGE_CARRY_ITEMS = 8
PPRF_DEPTH = 256


def fork_commit_hash(label: str) -> bytes:
    return sha256(f"SCP test vector commit {label}".encode())


def fork_notice_preimage(
    member: str,
    member_since: int,
    reset_counter: int,
    epoch: int,
    own_child: bytes,
    other_child: bytes,
    kind: int,
) -> bytes:
    return canonical_preimage(
        FORK_NOTICE_DOMAIN,
        var_field(FORK_CONTEXT_ID),
        var_field(member),
        u64(member_since),
        u64(reset_counter),
        u64(epoch),
        fixed_field(own_child),
        fixed_field(other_child),
        u8(kind),
    )


def departure_preimage(member: str, member_since: int, leaf_key_hash: bytes) -> bytes:
    return canonical_preimage(
        DEPARTURE_DOMAIN,
        var_field(FORK_CONTEXT_ID),
        var_field(member),
        u64(member_since),
        fixed_field(leaf_key_hash),
    )


def msgpack_uint(value: int) -> bytes:
    """The shortest MessagePack header for a non-negative integer."""
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + u8(value)
    if value <= 0xFFFF:
        return b"\xcd" + u16(value)
    if value <= 0xFFFFFFFF:
        return b"\xce" + u32(value)
    return b"\xcf" + u64(value)


def fork_record(fork_count: int, end_count: int, end_leaf_hash: bytes) -> bytes:
    assert fork_count >= 1 and len(end_leaf_hash) == 32
    return (
        b"\x93"
        + msgpack_uint(fork_count)
        + msgpack_uint(end_count)
        + b"\xc4\x20"
        + end_leaf_hash
    )


def merge_depth_bound(members: int) -> int:
    """K(e) = 2·n_e + 8."""
    return 2 * members + 8


def fork_record_admitted(
    depth: int, fork_count: int, end_count: int, members: int
) -> bool:
    k = merge_depth_bound(members)
    return (
        fork_count >= 1
        and depth <= k
        and end_count - fork_count <= k * MERGE_CARRY_ITEMS
    )


def mls_kdf_label(label: str, context: bytes, length: int) -> bytes:
    """RFC 9420 §8 KDFLabel; every vector here is shorter than 64 bytes, so
    each `<V>` length is one byte."""
    full = b"MLS 1.0 " + label.encode()
    assert len(full) < 64 and len(context) < 64
    return u16(length) + u8(len(full)) + full + u8(len(context)) + context


def pprf_child(node: bytes, right: bool) -> bytes:
    info = mls_kdf_label("tree", b"right" if right else b"left", 32)
    child = hkdf_expand(node, info, 32)
    if _HAVE_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

        check = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(node)
        assert check == child, "PPRF node expansion disagrees with cryptography"
    return child


def pprf_bits(x: bytes) -> list[bool]:
    """x read most significant bit first; True is the right child."""
    return [bool((byte >> (7 - i)) & 1) for byte in x for i in range(8)]


def pprf_path(root: bytes, x: bytes) -> tuple[list[bytes], list[bytes]]:
    """Returns the path nodes from the root to the leaf at x, and the copath
    nodes a punctured tree keeps, root side first."""
    path = [root]
    copath = []
    node = root
    for bit in pprf_bits(x):
        copath.append(pprf_child(node, not bit))
        node = pprf_child(node, bit)
        path.append(node)
    return path, copath


def merge_rank(position: int, epoch: int, members: int) -> int:
    """rank(C) = (pos(I) − e) mod n_e."""
    return (position - epoch) % members


def emit_fork_merge() -> None:
    section("§25.33 Concurrent-commit fork-merge vectors")
    own = fork_commit_hash("own")
    other = fork_commit_hash("other")
    emit_hex("fork.context_id", FORK_CONTEXT_ID)
    emit("fork.alice", ID_ALICE)
    emit("fork.bob", ID_BOB)
    emit("fork.carol", ID_CAROL)
    emit_hex("fork.own", own)
    emit_hex("fork.other", other)

    notice = fork_notice_preimage(ID_ALICE, 3, 2, 7, own, other, 0)
    assert len(notice) == 185
    emit_hex("vector_71.preimage", notice)
    emit_hex("vector_71.canonical_hash", sha256(notice))
    diverged = fork_notice_preimage(ID_ALICE, 3, 2, 7, own, other, 1)
    emit_hex("vector_71.canonical_hash_kind_1", sha256(diverged))

    leaf_key_hash = sha256(REF_KEY_1.uncompressed)
    departure = departure_preimage(ID_BOB, 4, leaf_key_hash)
    assert len(departure) == 134
    emit_hex("vector_72.leaf_key_hash", leaf_key_hash)
    emit_hex("vector_72.preimage", departure)
    emit_hex("vector_72.canonical_hash", sha256(departure))

    end_leaf_hash = sha256(b"SCP test vector leaf L end")
    small = fork_record(5, 9, end_leaf_hash)
    large = fork_record(300, 305, end_leaf_hash)
    assert len(small) == 37 and len(large) == 41
    emit_hex("vector_73.end_leaf_hash", end_leaf_hash)
    emit_hex("vector_73.record_5_9", small)
    emit_hex("vector_73.record_300_305", large)
    members = 3
    k = merge_depth_bound(members)
    assert k == 14
    emit("vector_73.k_10", k)
    emit("vector_73.end_count_bound", k * MERGE_CARRY_ITEMS)
    for c in (24, 25):
        emit(
            f"vector_73.admitted_at_c_{c}", fork_record_admitted(c - 10, 5, 9, members)
        )
    assert fork_record_admitted(14, 5, 9, members)
    assert not fork_record_admitted(15, 5, 9, members)
    assert fork_record_admitted(14, 5, 117, members)
    assert not fork_record_admitted(14, 5, 118, members)
    assert not fork_record_admitted(14, 0, 9, members)

    approvers = sorted([ID_CAROL, ID_ALICE, ID_BOB], key=str.encode)
    assert approvers == [ID_BOB, ID_CAROL, ID_ALICE]
    emit("vector_74.approvers", json.dumps(approvers))

    root = bytes(range(32))
    x = sha256(b"SCP test vector pprf input")
    path, copath = pprf_path(root, x)
    assert len(path) == PPRF_DEPTH + 1 and len(copath) == PPRF_DEPTH
    assert format(x[0], "08b") == "00000111"
    assert copath[0] == pprf_child(root, True)
    emit_hex("vector_75.root", root)
    emit_hex("vector_75.kdf_label_left", mls_kdf_label("tree", b"left", 32))
    emit_hex("vector_75.left_child", pprf_child(root, False))
    emit_hex("vector_75.right_child", pprf_child(root, True))
    emit_hex("vector_75.x", x)
    emit("vector_75.x_first_byte_bits", format(x[0], "08b"))
    emit_hex("vector_75.node_after_two_steps", path[2])
    emit_hex("vector_75.leaf", path[-1])
    emit_hex("vector_75.first_copath_node", copath[0])
    emit_hex("vector_75.last_copath_node", copath[-1])

    order = sorted([ID_ALICE, ID_BOB, ID_CAROL], key=str.encode)
    assert order == [ID_BOB, ID_CAROL, ID_ALICE]
    names = {ID_BOB: "bob", ID_CAROL: "carol", ID_ALICE: "alice"}
    for epoch in (7, 8, 9):
        for position, identifier in enumerate(order):
            emit(
                f"vector_79.rank_{epoch}_{names[identifier]}",
                merge_rank(position, epoch, len(order)),
            )
    cth1 = sha256(b"SCP test vector cth one")
    cth2 = sha256(b"SCP test vector cth two")
    assert cth1 < cth2
    emit_hex("vector_79.cth1", cth1)
    emit_hex("vector_79.cth2", cth2)


# ---------------------------------------------------------------------------
# §25.23 Vectors 80-82: key positions, the re-seat request and answer, and the
# three re-seat seals (`09-security-model.md` §9.7.1, §9.10.12, §9.18;
# `05-contexts.md` §5.13.3 "Key positions", §5.12.3.4, §5.12.3.5;
# `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6 and
# "Carried re-seat").
#
# The two branch events of the Contested position are §25.29's Vector 53
# (`CommitmentRollover`) and Vector 54 (`RootRecovery{CoSigns}`), both at
# sequence 1 after Vector 41's inception, which is the shared fork point.
# ---------------------------------------------------------------------------

KEY_EVENT_FRAME_VERSION = 0x02
RESEAT_CONTEXT_ID = "context-alpha"
RESEAT_REQUEST_DOMAIN = "SCP-RESEAT-REQUEST-V1:"
RESEAT_GROUPINFO_DOMAIN = "SCP-RESEAT-GROUPINFO-V1:"
KEY_POSITION_NAMES = ("contested", "linear", "unheld", "displaced")


def key_event_frame(identifier: bytes, events: list[tuple[int, bytes, bytes]]) -> bytes:
    """§9.10.12: version 2, the 32-byte identifier, then `value`: first and last
    sequence, the event count, and each event as BE32(len(preimage)) || preimage
    || its indexed signature field."""
    assert len(identifier) == 32 and events
    value = (
        u64(events[0][0])
        + u64(events[-1][0])
        + u32(len(events))
        + b"".join(var_field(pre) + sigs for _, pre, sigs in events)
    )
    return u8(KEY_EVENT_FRAME_VERSION) + identifier + value


def key_history_advance(frame: bytes, confirmation: bytes) -> bytes:
    """§9.7.1: two length-prefixed fields (§9.5.1), at least one non-empty."""
    assert frame or confirmation
    return var_field(frame) + var_field(confirmation)


def repeated_field(items: list[bytes]) -> bytes:
    """§9.5.1's repeated-field rule: BE32(count), then each element length-prefixed."""
    return u32(len(items)) + b"".join(var_field(item) for item in items)


def position_element(
    identifier: str,
    heads: list[tuple[int, bytes]],
    contested_since: int | None = None,
    presented: tuple[tuple[int, bytes], ...] = (),
    pending_since: int | None = None,
    staged_by: str | None = None,
    displaced: tuple[int, int] | None = None,
    recovered_at: tuple[int, int, bytes] | None = None,
) -> list:
    """`05-contexts.md` §5.13.3 "Key positions": one element of `positions`.
    No fixture position records a `confirmed` pair, so it is null throughout."""
    assert (len(heads) > 1) == (contested_since is not None)
    assert (pending_since is None) == (staged_by is None)

    def pairs(items) -> list:
        ordered = sorted(items, key=lambda pair: pair[1])
        return [[seq, digest.hex()] for seq, digest in ordered]

    return [
        identifier,
        pairs(heads),
        contested_since,
        pairs(presented),
        pending_since,
        None,
        staged_by,
        None if displaced is None else displaced[0],
        None if displaced is None else displaced[1],
        None
        if recovered_at is None
        else [recovered_at[0], recovered_at[1], recovered_at[2].hex()],
    ]


def key_positions_hash(relay_list_sequence: int, positions: list[list]) -> bytes:
    ordered = sorted(positions, key=lambda element: element[0].encode())
    return sha256(jcs([relay_list_sequence, ordered]))


def mp_opt_uint(value: int | None) -> bytes:
    return mp_none() if value is None else mp_uint(value)


def key_position_recorded_payload(element: list) -> bytes:
    """The leaf payload: the positional `rmp_serde` array of
    `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6, nine items,
    every identifier in text form, each `[seq, event_digest]` pair a two-item
    array whose digest is a 32-byte bin."""

    def pairs(items: list) -> bytes:
        return mp_array(
            [mp_array([mp_uint(seq), mp_bin(bytes.fromhex(d))]) for seq, d in items]
        )

    identifier, heads, contested, presented, pending, confirmed, staged, at, top, _ = (
        element
    )
    assert confirmed is None
    return mp_array(
        [
            mp_str(identifier),
            pairs(heads),
            mp_opt_uint(contested),
            pairs(presented),
            mp_opt_uint(pending),
            mp_none(),
            mp_none() if staged is None else mp_str(staged),
            mp_opt_uint(at),
            mp_opt_uint(top),
        ]
    )


def fixture_digest(label: str) -> bytes:
    return sha256(f"SCP test vector {label}".encode())


def fixture_bytes(label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(f"SCP test vector {label} {counter}".encode())
        counter += 1
    return out[:length]


def mp_header(item: bytes) -> bytes:
    """The MessagePack header of one encoded item: a fixint or nil is its own
    header; a fixstr has one byte; str8 and bin8 two; bin16 three; a uint8 one."""
    first = item[0]
    if first < 0x80 or first == 0xC0:
        return item[:1]
    if 0xA0 <= first <= 0xBF or first == 0xCC:
        return item[:1]
    if first in (0xD9, 0xC4):
        return item[:2]
    if first in (0xDA, 0xC5):
        return item[:3]
    raise AssertionError(f"no header rule for 0x{first:02x}")


def hpke_seal_base(
    recipient: KeyPair, ephemeral: KeyPair, info: bytes, aad: bytes, plaintext: bytes
) -> dict[str, bytes]:
    """RFC 9180 single-shot Seal in mode base under DHKEM(P-256, HKDF-SHA256),
    HKDF-SHA256 and AES-128-GCM, the suite §5.12.3.1 seals an `InvitationBundle`
    under (§9.5). The ephemeral key is a fixture, so the bytes are reproducible."""
    enc = ephemeral.uncompressed
    dh = ecdh_p256(ephemeral.d, recipient.point)
    assert dh == ecdh_p256(recipient.d, ephemeral.point)
    eae_prk = hpke_labeled_extract(HPKE_SUITE_KEM, b"", b"eae_prk", dh)
    shared_secret = hpke_labeled_expand(
        HPKE_SUITE_KEM, eae_prk, b"shared_secret", enc + recipient.uncompressed, 32
    )
    psk_id_hash = hpke_labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = hpke_labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = hpke_labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    key = hpke_labeled_expand(HPKE_SUITE, secret, b"key", context, 16)
    base_nonce = hpke_labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12)
    return {
        "enc": enc,
        "shared_secret": shared_secret,
        "key": key,
        "base_nonce": base_nonce,
        "ciphertext": aes128_gcm_encrypt(key, base_nonce, plaintext, aad),
    }


def reseat_seal_label(label: str, context_id: str, request_digest: bytes) -> bytes:
    """`09-security-model.md` §9.18's HPKE rows for the re-seat seals:
    label || BE32(len(context_id)) || context_id || request_digest."""
    assert len(request_digest) == 32
    return label.encode() + var_field(context_id) + request_digest


def emit_key_positions_and_reseat() -> None:
    section("§25.23 Vectors 80-82 key positions, re-seat request and answer, seals")
    identifier = INCEPTION_IDENTIFIER
    identifier_text = scp_text_form(identifier)
    fork_point = INCEPTION_DIGEST

    # --- Vector 80: the two branch events and their frames. ---
    pre53 = rollover_preimage(identifier, fork_point)
    d53 = sha256(pre53)
    sigs53 = [
        sign_group(REF_KEY_3, d53, "vector_80.rollover.reveal"),
        sign_group(REF_KEY_1, d53, "vector_80.rollover.standing_root"),
    ]
    pre54 = recovery_preimage(
        identifier,
        fork_point,
        STANDING_ROOT_COSIGNS,
        COSIGNS_ROOT_KEY,
        COSIGNS_ACTIVE_KEY,
        COSIGNS_NEXT_KEY,
    )
    d54 = sha256(pre54)
    sigs54 = [
        sign_group(REF_KEY_3, d54, "vector_80.recovery.reveal"),
        sign_group(COSIGNS_ROOT_KEY, d54, "vector_80.recovery.installed_root"),
        sign_group(REF_KEY_1, d54, "vector_80.recovery.standing_root"),
    ]
    # R6 ties the two branches: each first event after the fork point carries a
    # root signature under the root standing there, so both rank 1 and the
    # position holds both heads.
    assert rank_first_reveal(d53, sigs53, 1) == 1
    assert rank_first_reveal(d54, sigs54, 2) == 1
    frame53 = key_event_frame(identifier, [(1, pre53, b"".join(sigs53))])
    frame54 = key_event_frame(identifier, [(1, pre54, b"".join(sigs54))])
    emit("vector_80.identifier_text", identifier_text)
    emit_hex("vector_80.fork_point_digest", fork_point)
    emit_hex("vector_80.branch_rollover_digest", d53)
    emit_hex("vector_80.branch_recovery_digest", d54)
    emit("vector_80.frame_rollover_len", len(frame53))
    emit_hex("vector_80.frame_rollover", frame53)
    emit("vector_80.frame_recovery_len", len(frame54))
    emit_hex("vector_80.frame_recovery", frame54)

    # A KeyHistoryAdvance with a frame and an empty confirmation.
    body_frame = key_history_advance(frame53, b"")
    assert body_frame == u32(len(frame53)) + frame53 + u32(0)
    emit("vector_80.advance_frame_only_len", len(body_frame))
    emit_hex("vector_80.advance_frame_only_sha256", sha256(body_frame))

    # A KeyHistoryAdvance with an empty frame and a FallbackConfirmation. The
    # record reuses Vector 49's context, governor and entries at sequence 3; the
    # operator is Vector 49's entry 0, whose key is §25.2's reference key.
    entries = community_relay_list_bytes()
    record_sequence = 3
    record_fields = (
        fixed_field(RELAY_LIST_CONTEXT_ID)
        + u64(record_sequence)
        + fixed_field(identifier)
        + fixed_field(sha256(entries))
    )
    record_digest = sha256(canonical_preimage(RELAY_LIST_SEPARATOR, record_fields))
    record_signature = sign_group(REF_KEY_2, record_digest, "vector_80.list_record")
    list_record = jcs(
        {
            "context_id": RELAY_LIST_CONTEXT_ID.hex(),
            "entries": entries.decode(),
            "governor": identifier.hex(),
            "sequence": record_sequence,
            "signature": record_signature.hex(),
        }
    )
    operator, operator_key, _, _ = RELAY_LIST_ENTRIES[0]
    assert operator_key == REF_KEY_1.compressed
    response = repeated_field([frame54])
    proof_nonce = fixture_digest("confirmation proof nonce")
    routing_id = sha256(b"scp:did:" + identifier)
    proof_fields = (
        fixed_field(operator)
        + fixed_field(proof_nonce)
        + fixed_field(routing_id)
        + fixed_field(sha256(response))
        + u64(COSIGN_OBSERVED_AT)
    )
    proof_digest = sha256(canonical_preimage("SCP-RELAY-PROOF-V1:", proof_fields))
    relay_proof = proof_fields + sign_group(REF_KEY_1, proof_digest, "vector_80.proof")
    assert len(relay_proof) == 200
    confirmation = (
        var_field(list_record)
        + fixed_field(operator)
        + var_field(b"")
        + response
        + fixed_field(relay_proof)
    )
    body_confirmation = key_history_advance(b"", confirmation)
    emit("vector_80.list_record_sequence", record_sequence)
    emit_hex("vector_80.list_record_canonical_hash", record_digest)
    emit_hex("vector_80.list_record_signature", record_signature)
    emit("vector_80.list_record_len", len(list_record))
    emit_hex("vector_80.list_record_sha256", sha256(list_record))
    emit_hex("vector_80.proof_nonce", proof_nonce)
    emit_hex("vector_80.response_value_digest", sha256(response))
    emit_hex("vector_80.relay_proof", relay_proof)
    emit("vector_80.confirmation_len", len(confirmation))
    emit_hex("vector_80.confirmation_sha256", sha256(confirmation))
    emit("vector_80.advance_confirmation_only_len", len(body_confirmation))
    emit_hex("vector_80.advance_confirmation_only_sha256", sha256(body_confirmation))

    # key_positions_hash over four positions and relay_list_sequence 3. The
    # Contested position held the recovery's triple from epoch 5, when it was
    # Linear; the contest recorded at epoch 12 left it unchanged.
    contested = position_element(
        identifier_text,
        [(1, d53), (1, d54)],
        contested_since=12,
        recovered_at=(5, 1, d54),
    )
    linear = position_element(
        fixture_identifier("key position linear"),
        [(2, fixture_digest("key position linear head"))],
        recovered_at=(9, 1, fixture_digest("key position linear recovery")),
    )
    unheld = position_element(
        fixture_identifier("key position unheld"),
        [(4, fixture_digest("key position unheld head"))],
        presented=(
            (7, fixture_digest("key position unheld tip b")),
            (6, fixture_digest("key position unheld tip a")),
        ),
        pending_since=10,
        staged_by=ID_CAROL,
    )
    displaced = position_element(
        fixture_identifier("key position displaced"),
        [(8, fixture_digest("key position displaced head"))],
        displaced=(3, 7),
    )
    positions = [contested, linear, unheld, displaced]
    for name, element in zip(KEY_POSITION_NAMES, positions):
        emit(f"vector_80.position_{name}", jcs(element).decode())
    emit(
        "vector_80.position_order",
        ",".join(
            name
            for name, element in sorted(
                zip(KEY_POSITION_NAMES, positions), key=lambda p: p[1][0].encode()
            )
        ),
    )
    emit_hex("vector_80.key_positions_hash", key_positions_hash(3, positions))

    leaf = key_position_recorded_payload(unheld)
    assert len(leaf) <= 903
    emit("vector_80.leaf_unheld_len", len(leaf))
    emit_hex("vector_80.leaf_unheld", leaf)

    # The contest resolves to the rollover branch, whose chain holds no
    # RootRecovery. The advance leaves the position Linear, so `recovered_at`
    # becomes null and `contested_since` clears.
    resolved = position_element(identifier_text, [(1, d53)])
    emit("vector_80.position_contested_resolved", jcs(resolved).decode())
    emit_hex(
        "vector_80.key_positions_hash_resolved",
        key_positions_hash(3, [resolved, linear, unheld, displaced]),
    )

    # --- Vector 82: the re-seat request, signed by Vector 41's #active key. ---
    request_nonce = fixture_digest("re-seat request nonce")[:16]
    anchor_digest = fixture_digest("re-seat anchor")
    head_digest = fixture_digest("re-seat head")
    key_package = fixture_bytes("re-seat key package", 96)
    key_package_hash = sha256(key_package)
    assert len(RESEAT_REQUEST_DOMAIN) == 22
    request_preimage = canonical_preimage(
        RESEAT_REQUEST_DOMAIN,
        var_field(RESEAT_CONTEXT_ID),
        var_field(identifier_text),
        fixed_field(request_nonce),
        u64(11),
        fixed_field(anchor_digest),
        u64(12),
        fixed_field(head_digest),
        fixed_field(key_package_hash),
    )
    request_digest = sha256(request_preimage)
    request_signature = sign_group(REF_KEY_2, request_digest, "vector_82")
    request_items = [
        mp_str(RESEAT_CONTEXT_ID),
        mp_str(identifier_text),
        mp_bin(request_nonce),
        mp_uint(11),
        mp_bin(anchor_digest),
        mp_uint(12),
        mp_bin(head_digest),
        mp_bin(key_package),
        mp_bin(request_signature),
    ]
    request = mp_array(request_items)
    assert request[0] == 0x99
    emit("vector_82.context_id", RESEAT_CONTEXT_ID)
    emit("vector_82.identifier", identifier_text)
    emit_hex("vector_82.request_nonce", request_nonce)
    emit_hex("vector_82.anchor_digest", anchor_digest)
    emit_hex("vector_82.head_digest", head_digest)
    emit_hex("vector_82.key_package", key_package)
    emit_hex("vector_82.key_package_hash", key_package_hash)
    emit("vector_82.preimage_len", len(request_preimage))
    emit_hex("vector_82.preimage", request_preimage)
    emit_hex("vector_82.request_digest", request_digest)
    emit_hex("vector_82.signature", request_signature)
    emit(
        "vector_82.item_headers",
        " ".join(hexs(mp_header(item)) for item in request_items),
    )
    emit("vector_82.request_len", len(request))
    emit_hex("vector_82.request", request)
    ten_items = b"\x9a" + request[1:] + mp_uint(41)
    emit("vector_82.rejected_ten_items_len", len(ten_items))
    emit_hex("vector_82.rejected_ten_items_tail", ten_items[-(2 + 64 + 1) :])
    long_signature = mp_bin(request_signature + b"\x00")
    emit_hex("vector_82.rejected_65_byte_signature_item", long_signature)
    emit_hex("vector_82.info", b"scp-reseat-request-v1" + var_field(RESEAT_CONTEXT_ID))
    emit_hex(
        "vector_82.aad", b"scp-reseat-request-aad-v1" + var_field(RESEAT_CONTEXT_ID)
    )
    end_leaf_hash = fixture_digest("re-seat end leaf")
    carried = mp_array([mp_uint(12), mp_bin(end_leaf_hash), mp_bin(request)])
    emit_hex("vector_82.end_leaf_hash", end_leaf_hash)
    emit("vector_82.carried_item_len", len(carried))
    emit_hex("vector_82.carried_item_prefix", carried[: 1 + 1 + 2 + 32 + 3])

    # --- Vector 81: the re-seat answer, published by carol for epoch 7. ---
    group_info = fixture_bytes("re-seat group info", 300)
    wrap_key = fixture_digest("re-seat wrap key")[:16]
    key_material = jcs(
        {
            "context_metadata_key": fixture_digest("re-seat metadata key").hex(),
            "sender_key_seed": None,
        }
    )
    context_params = jcs(
        {"governance": "SingleAdmin", "mode": "Encrypted", "ttl": None}
    )
    reordered_params = b'{"mode":"Encrypted","governance":"SingleAdmin","ttl":null}'
    assert json.loads(reordered_params) == json.loads(context_params)
    assert reordered_params != context_params
    publisher = ID_CAROL
    assert len(RESEAT_GROUPINFO_DOMAIN) == 24
    answer_preimage = canonical_preimage(
        RESEAT_GROUPINFO_DOMAIN,
        var_field(RESEAT_CONTEXT_ID),
        u64(7),
        fixed_field(request_digest),
        var_field(identifier_text),
        fixed_field(sha256(group_info)),
        fixed_field(sha256(wrap_key)),
        fixed_field(sha256(key_material)),
        fixed_field(sha256(context_params)),
        var_field(publisher),
    )
    answer_digest = sha256(answer_preimage)
    answer_signature = sign_group(REF_KEY_1, answer_digest, "vector_81")
    answer_items = [
        mp_str(RESEAT_CONTEXT_ID),
        mp_uint(7),
        mp_bin(request_digest),
        mp_bin(group_info),
        mp_bin(wrap_key),
        mp_bin(key_material),
        mp_bin(context_params),
        mp_str(publisher),
        mp_bin(answer_signature),
    ]
    answer = mp_array(answer_items)
    emit_hex("vector_81.group_info", group_info)
    emit_hex("vector_81.wrap_key", wrap_key)
    emit("vector_81.key_material", key_material.decode())
    emit("vector_81.context_params", context_params.decode())
    emit("vector_81.context_params_rejected", reordered_params.decode())
    emit("vector_81.publisher_did", publisher)
    emit("vector_81.preimage_len", len(answer_preimage))
    emit_hex("vector_81.preimage", answer_preimage)
    emit_hex("vector_81.canonical_hash", answer_digest)
    emit_hex("vector_81.signature", answer_signature)
    emit(
        "vector_81.item_headers",
        " ".join(hexs(mp_header(item)) for item in answer_items),
    )
    emit("vector_81.answer_len", len(answer))
    emit_hex("vector_81.answer_sha256", sha256(answer))

    # --- The three re-seat seals, each binding request_digest in info and aad.
    # The recipient key is Vector 37's wrapping key; the ephemeral key is
    # §25.2's tertiary key.
    recipient = keypair_from_seed(
        WRAPPING_KEY_SEED, TEST_VECTOR_KEY_LABEL, "wrapping key"
    )
    welcome = fixture_bytes("re-seat welcome", 64)
    notice = mp_array([mp_str(RESEAT_CONTEXT_ID), mp_bin(key_package_hash)])
    emit_hex("vector_81.carried_welcome", welcome)
    emit_hex("vector_81.expired_notice", notice)
    for name, label, plaintext in (
        ("groupinfo", "scp-reseat-groupinfo", answer),
        ("welcome", "scp-reseat-welcome", welcome),
        ("expired", "scp-reseat-expired", notice),
    ):
        info = reseat_seal_label(label + "-v1", RESEAT_CONTEXT_ID, request_digest)
        aad = reseat_seal_label(label + "-aad-v1", RESEAT_CONTEXT_ID, request_digest)
        sealed = hpke_seal_base(recipient, REF_KEY_3, info, aad, plaintext)
        emit_hex(f"vector_81.seal_{name}.info", info)
        emit_hex(f"vector_81.seal_{name}.aad", aad)
        emit_hex(f"vector_81.seal_{name}.shared_secret", sealed["shared_secret"])
        emit_hex(f"vector_81.seal_{name}.key", sealed["key"])
        emit_hex(f"vector_81.seal_{name}.base_nonce", sealed["base_nonce"])
        emit(f"vector_81.seal_{name}.ciphertext_len", len(sealed["ciphertext"]))
        emit_hex(
            f"vector_81.seal_{name}.ciphertext_sha256", sha256(sealed["ciphertext"])
        )


# --- §25.34 Vector 83: the custody-reachability probe ---
#
# 09-security-model.md §9.7.4.1 item 5, step d: the raw arm signs
# SHA-256("SCP-CUSTODY-PROBE-V1:" || nonce), and the assertion arm's WebAuthn
# challenge is the 53 bytes "SCP-CUSTODY-PROBE-V1:" || nonce, unhashed.
CUSTODY_PROBE_SEPARATOR = b"SCP-CUSTODY-PROBE-V1:"


def emit_custody_probe() -> None:
    section("§25.34 Vector 83 custody-reachability probe")
    assert len(CUSTODY_PROBE_SEPARATOR) == 21, "vector_83: separator length"
    for separator in (KEL_EVENT_SEPARATOR, WEBAUTHN_CHALLENGE_PREFIX):
        assert not CUSTODY_PROBE_SEPARATOR.startswith(separator), separator
        assert not separator.startswith(CUSTODY_PROBE_SEPARATOR), separator
    for label, nonce in (
        ("vector_83a", bytes(range(32))),
        ("vector_83b", bytes([0x5A]) * 32),
    ):
        challenge = CUSTODY_PROBE_SEPARATOR + nonce
        assert len(challenge) == 53, f"{label}: challenge length"
        emit_hex(f"{label}.nonce", nonce)
        emit_hex(f"{label}.assertion_challenge", challenge)
        emit_hex(f"{label}.raw_digest", sha256(challenge))
    # §25.2's reference key signs Vector 83a's raw digest.
    digest = sha256(CUSTODY_PROBE_SEPARATOR + bytes(range(32)))
    emit_hex("vector_83a.signature", sign_group(REF_KEY_1, digest, "vector_83a"))


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
    emit_proposal()
    emit_hpke_info()
    emit_identity_link_attestation()
    emit_hash_only_vectors()
    emit_pseudonym_derivation()
    emit_cross_target_pseudonym()
    emit_pseudonym_announcement()
    emit_trust_attestation()
    emit_keypackage_attestation()
    emit_key_event_signatures()
    emit_custody_registry_key_state()
    emit_context_export_preimage()
    emit_witness_and_relay_objects()
    emit_commitment_and_service_record()
    emit_reveal_ranking_and_text_form()
    emit_webpush()
    emit_challenge_vectors()
    emit_participation_seed()
    emit_push_signing_bytes()
    emit_fork_merge()
    emit_key_positions_and_reseat()
    emit_custody_probe()
    print("\n".join(_LINES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
