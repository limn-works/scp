"""Byte-level Known-Answer Test (KAT) for per-context pseudonym derivation.

Spec §9.10.4.A (algorithm) and §25.19 vectors 30 & 31 (pinned outputs).

Software-custody pseudonym derivation is cross-platform deterministic: every
SDK (Rust, Swift, Kotlin, TypeScript, Python) MUST reproduce the exact
public-key bytes the spec pins for a given identity seed, ``context_id``, and
epoch. This test exercises the pure-Python canonical recipe in
:mod:`tests.pseudonym_recipe` and asserts the resulting bytes equal the spec
literals — both the static (v1) and rotatable (v2, epoch 1) keys, plus a
v1-vs-v2 distinctness check.

The recipe is stdlib-only (HKDF/HMAC via :mod:`hashlib`/:mod:`hmac`, Ed25519 via
a compact RFC 8032 implementation), so this KAT runs under plain ``pytest`` with
no native extension built.
"""

from __future__ import annotations

import pytest

from .pseudonym_recipe import (
    canonical_pseudonym_public_key,
    canonical_rotatable_pseudonym_public_key,
)

# §25.19 context_id, shared by both vectors.
CONTEXT_ALPHA = b"context-alpha"

# §25.19 vectors. Seeds and expected public keys taken verbatim from the spec.
# Each entry: (name, ed25519_seed, v1_pubkey_hex, v2_epoch1_pubkey_hex).
VECTORS = [
    (
        "Vector 30 (seed 0x01 x 32)",
        bytes([0x01] * 32),
        "fddc04882a48aa39888f6dbec622f9c5aa6f06b2e40820a69a2e0e89b5f09ac2",
        "43e50a947c4b2be44f871e309c7edc64afaf4207b9a589c9b01f61c01158090f",
    ),
    (
        "Vector 31 (seed 0x9d,0x01..0x1f)",
        bytes([0x9D]) + bytes(range(0x01, 0x20)),
        "ff6e2e909a008318f97bb2c26c1d787ceb9aa2996f746766335e10ba7e2213cc",
        "edd47319719e2350d1db9488e0189f2405267d7dc243489cfd9aa6f3ac3fc639",
    ),
]


@pytest.mark.parametrize(("name", "seed", "v1_hex", "v2_hex"), VECTORS)
def test_v1_static_pseudonym_matches_spec(name: str, seed: bytes, v1_hex: str, v2_hex: str) -> None:
    """The v1 (static) pseudonym public key matches the §25.19 literal."""
    public_key = canonical_pseudonym_public_key(seed, CONTEXT_ALPHA)
    assert public_key.hex() == v1_hex, name


@pytest.mark.parametrize(("name", "seed", "v1_hex", "v2_hex"), VECTORS)
def test_v2_rotatable_pseudonym_matches_spec(
    name: str, seed: bytes, v1_hex: str, v2_hex: str
) -> None:
    """The v2 (rotatable, epoch 1) pseudonym public key matches §25.19."""
    public_key = canonical_rotatable_pseudonym_public_key(seed, CONTEXT_ALPHA, 1)
    assert public_key.hex() == v2_hex, name


@pytest.mark.parametrize(("name", "seed", "v1_hex", "v2_hex"), VECTORS)
def test_v1_and_v2_derive_distinct_keys(name: str, seed: bytes, v1_hex: str, v2_hex: str) -> None:
    """The v1 and v2 derivations yield distinct keys (domain separation)."""
    v1 = canonical_pseudonym_public_key(seed, CONTEXT_ALPHA)
    v2 = canonical_rotatable_pseudonym_public_key(seed, CONTEXT_ALPHA, 1)
    assert v1 != v2, name


def test_both_spec_vectors_present_and_well_formed() -> None:
    """Both §25.19 vectors are present and produce 32-byte public keys."""
    assert len(VECTORS) == 2
    for _name, seed, _v1, _v2 in VECTORS:
        assert len(seed) == 32
        assert len(canonical_pseudonym_public_key(seed, CONTEXT_ALPHA)) == 32
        assert len(canonical_rotatable_pseudonym_public_key(seed, CONTEXT_ALPHA, 1)) == 32
