"""The SDK's P-256 custody-host helpers against pinned outputs.

``scp_sdk.p256_pseudonym_point``, ``scp_sdk.p256_software_pseudonym_point``,
``scp_sdk.p256_pseudonym_scalar``, ``scp_sdk.p256_public_key`` and
``scp_sdk.p256_sign_prehash_rfc6979``:

- spec §25.19 Vectors 30 and 31: each ``identity_scalar`` over
  "context-alpha" gives the v1 point, and at epoch 1 the v2 point; each
  context seed gives its point directly;
- spec §25.19 Vectors 30 and 31: each ``context_seed_v1`` and
  ``context_seed_v2`` maps to the spec's v1 and v2 points;
- RFC 6979 A.2.5 (P-256, SHA-256, "sample"): the RFC's ``r``, and the low-s
  form of the RFC's ``s`` (the two sum to ``n``, §9.5);
- the independent recipe in :mod:`tests.pseudonym_recipe` signs the same bytes
  for the same scalar and digest;
- malformed input is rejected with ``SCP-VALID-7005`` or ``SCP-CRYPTO-4001``.

Skips when the native extension is not built.
"""

from __future__ import annotations

import hashlib
import sys

import pytest

pytest.importorskip("scp_sdk._scp_core")

from scp_sdk import (
    CryptoError,
    ValidationError,
    p256_pseudonym_point,
    p256_pseudonym_scalar,
    p256_public_key,
    p256_sign_prehash_rfc6979,
    p256_software_pseudonym_point,
)

from .pseudonym_recipe import p256_sign_prehash

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# §25.19 values, copied verbatim from the spec.
VECTORS = [
    (
        "Vector 30",
        "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
        "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
        "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
        "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
    ),
    (
        "Vector 31",
        "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
        "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
        "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
        "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
    ),
]


# §25.19 identity_scalar of each vector, the ikm of the software recipe.
IDENTITY_SCALARS = {
    "Vector 30": "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
    "Vector 31": "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
}


@pytest.mark.parametrize(
    ("name", "seed_v1", "v1", "seed_v2", "v2"), VECTORS, ids=[v[0] for v in VECTORS]
)
def test_software_pseudonym_point_reproduces_spec_25_19(
    name: str, seed_v1: str, v1: str, seed_v2: str, v2: str
) -> None:
    ikm = bytes.fromhex(IDENTITY_SCALARS[name])
    assert p256_software_pseudonym_point(ikm, b"context-alpha").hex() == v1
    assert p256_software_pseudonym_point(bytearray(ikm), b"context-alpha", 1).hex() == v2


@pytest.mark.parametrize(
    ("name", "seed_v1", "v1", "seed_v2", "v2"), VECTORS, ids=[v[0] for v in VECTORS]
)
def test_pseudonym_point_reproduces_spec_25_19(
    name: str, seed_v1: str, v1: str, seed_v2: str, v2: str
) -> None:
    assert p256_pseudonym_point(bytes.fromhex(seed_v1)).hex() == v1
    assert p256_pseudonym_point(bytearray.fromhex(seed_v2)).hex() == v2


@pytest.mark.parametrize("size", [0, 31, 33])
def test_point_helpers_reject_a_wrong_length_seed(size: int) -> None:
    for call in (
        lambda: p256_pseudonym_point(bytes(size)),
        lambda: p256_software_pseudonym_point(bytes(size), b"context-alpha"),
    ):
        with pytest.raises(ValidationError) as info:
            call()
        assert info.value.code == "SCP-VALID-7005"


@pytest.mark.parametrize(
    ("name", "seed_v1", "v1", "seed_v2", "v2"), VECTORS, ids=[v[0] for v in VECTORS]
)
def test_context_seeds_map_to_spec_points(
    name: str, seed_v1: str, v1: str, seed_v2: str, v2: str
) -> None:
    d1 = p256_pseudonym_scalar(bytes.fromhex(seed_v1))
    assert len(d1) == 32
    assert p256_public_key(d1).hex() == v1
    assert p256_public_key(p256_pseudonym_scalar(bytes.fromhex(seed_v2))).hex() == v2


def test_native_scalar_is_a_bytearray_and_bytearray_inputs_are_accepted() -> None:
    # The host wipes the scalar when it destroys the key, so the native
    # helper returns a mutable bytearray, and bytearray seeds and scalars are
    # accepted.
    from scp_sdk import _scp_core

    seed = bytearray.fromhex(VECTORS[0][1])
    assert type(_scp_core.p256_pseudonym_scalar(seed)) is bytearray
    d = p256_pseudonym_scalar(seed)
    assert d == p256_pseudonym_scalar(bytes(seed))
    assert p256_public_key(d).hex() == VECTORS[0][2]
    digest = hashlib.sha256(b"wipe").digest()
    assert p256_sign_prehash_rfc6979(d, digest) == p256_sign_prehash_rfc6979(bytes(d), digest)


def test_wrapper_returns_the_native_scalar_object_uncopied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A wrapper copy would leave a second copy of the scalar that the host's
    # wipe of the returned array cannot reach.
    sentinel = bytearray(32)

    class _Native:
        @staticmethod
        def p256_pseudonym_scalar(seed: bytes | bytearray) -> bytearray:
            return sentinel

    monkeypatch.setattr(sys.modules["scp_sdk.scp"], "_native_mod", lambda: _Native)
    assert p256_pseudonym_scalar(bytes(32)) is sentinel


def test_rfc6979_a25_signature_is_low_s() -> None:
    x = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    digest = hashlib.sha256(b"sample").digest()
    sig = p256_sign_prehash_rfc6979(x, digest)
    assert len(sig) == 64
    assert sig[:32].hex() == "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    rfc_s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    assert int.from_bytes(sig[32:], "big") + rfc_s == N
    assert p256_sign_prehash_rfc6979(x, digest) == sig


def test_signatures_equal_the_independent_recipe() -> None:
    d = p256_pseudonym_scalar(bytes.fromhex(VECTORS[0][1]))
    for i in range(8):
        digest = hashlib.sha256(b"msg-%d" % i).digest()
        assert p256_sign_prehash_rfc6979(d, digest) == p256_sign_prehash(
            int.from_bytes(d, "big"), digest
        )


@pytest.mark.parametrize(
    ("call", "error", "code"),
    [
        (lambda: p256_pseudonym_scalar(bytes(31)), ValidationError, "SCP-VALID-7005"),
        (lambda: p256_public_key(b"\x01" * 33), ValidationError, "SCP-VALID-7005"),
        (lambda: p256_public_key(bytes(32)), CryptoError, "SCP-CRYPTO-4001"),
        (lambda: p256_public_key(b"\xff" * 32), CryptoError, "SCP-CRYPTO-4001"),
        (
            lambda: p256_sign_prehash_rfc6979(b"\x01" * 32, bytes(12)),
            ValidationError,
            "SCP-VALID-7005",
        ),
    ],
    ids=["short-seed", "long-scalar", "zero-scalar", "scalar-above-n", "short-digest"],
)
def test_malformed_input_is_rejected_with_its_code(call, error, code) -> None:
    with pytest.raises(error) as info:
        call()
    assert info.value.code == code
