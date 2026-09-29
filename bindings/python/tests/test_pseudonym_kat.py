"""Byte-level Known-Answer Test (KAT) for per-context pseudonym derivation.

Spec §9.10.4.A (algorithm) and §25.19 vectors 30 & 31 (pinned outputs).

Software-custody pseudonym derivation is cross-platform deterministic (§9.10.4.A).
This file checks two things:

- The §25.19 recipe end to end: the pure-Python recipe in
  :mod:`tests.pseudonym_recipe` gives the identity scalar, ``pseudonym_secret``
  and both context seeds as setup, and the production helpers
  :func:`scp_sdk.p256_pseudonym_scalar` and :func:`scp_sdk.p256_public_key`
  (the PyO3 exports of ``scp_ffi_common::p256_host``) map each seed to the
  33-byte compressed public key. Both public keys and both routing ids are
  compared to the literal §25.19 bytes, so a label or reduction change in the
  production helper fails these tests. They skip when the native extension is
  not built.
- The production bridge path: each vector's identity scalar, installed as the
  native custody's Ed25519 seed (the §9.10.4.A native interim ikm), derives on
  ``context-alpha`` to the spec's v1 routing id through the PyO3 bridge. That
  test skips when the extension is not built with the ``testing`` feature. No
  bridge path derives a v2 pseudonym in production; scp-crypto's §25.19 KAT
  covers v2.
"""

from __future__ import annotations

import pytest

from scp_sdk import p256_pseudonym_scalar, p256_public_key

from .pseudonym_recipe import (
    canonical_pseudonym_seed,
    canonical_rotatable_pseudonym_seed,
    pseudonym_routing_id,
    pseudonym_secret,
    seed_to_scalar,
)

# §25.19 context_id, shared by both vectors.
CONTEXT_ALPHA = b"context-alpha"

# §25.2 label that maps a vector's identity seed to its identity scalar.
IDENTITY_LABEL = b"SCP-TEST-VECTOR-KEY-V1"

# §25.19 vectors, every value copied verbatim from the spec.
VECTORS = [
    {
        "name": "Vector 30 (seed 0x01 x 32)",
        "seed": bytes([0x01] * 32),
        "scalar": "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
        "secret": "b88e781bb954a6681abc9016f8f69939f0e624311aeaa7e8f1b145857f58de82",
        "seed_v1": "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
        "v1": "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
        "rid_v1": "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
        "seed_v2": "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
        "v2": "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
        "rid_v2": "b19754a5e88c993683f99e48646ba518cba80dec0693f920c5671263650b6ae9",
    },
    {
        "name": "Vector 31 (seed 0x9d,0x01..0x1f)",
        "seed": bytes([0x9D]) + bytes(range(0x01, 0x20)),
        "scalar": "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
        "secret": "17ef25ad3e5be8adad38c4c5a1c68d3daca80015e81bdcae2ae8940645774739",
        "seed_v1": "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
        "v1": "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
        "rid_v1": "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
        "seed_v2": "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
        "v2": "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
        "rid_v2": "3c0ac4dec86c0dafe38195a7b66cdfec6b0ae0d44834c6e8b6b6129e097b5e27",
    },
]

IDS = [v["name"] for v in VECTORS]


def _ikm(vector: dict) -> bytes:
    return seed_to_scalar(IDENTITY_LABEL, vector["seed"]).to_bytes(32, "big")


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_identity_scalar_and_secret_match_spec(vector: dict) -> None:
    """The §25.2 identity scalar and the pseudonym_secret match §25.19."""
    ikm = _ikm(vector)
    assert ikm.hex() == vector["scalar"]
    assert pseudonym_secret(ikm).hex() == vector["secret"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_v1_static_pseudonym_matches_spec(vector: dict) -> None:
    """The v1 context seed, production public key, and routing id match §25.19."""
    pytest.importorskip("scp_sdk._scp_core")
    ikm = _ikm(vector)
    seed = canonical_pseudonym_seed(ikm, CONTEXT_ALPHA)
    assert seed.hex() == vector["seed_v1"]
    public_key = p256_public_key(p256_pseudonym_scalar(seed))
    assert public_key.hex() == vector["v1"]
    assert pseudonym_routing_id(public_key).hex() == vector["rid_v1"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_v2_rotatable_pseudonym_matches_spec(vector: dict) -> None:
    """The v2 (epoch 1) context seed, production public key, and routing id match §25.19."""
    pytest.importorskip("scp_sdk._scp_core")
    ikm = _ikm(vector)
    seed = canonical_rotatable_pseudonym_seed(ikm, CONTEXT_ALPHA, 1)
    assert seed.hex() == vector["seed_v2"]
    public_key = p256_public_key(p256_pseudonym_scalar(seed))
    assert public_key.hex() == vector["v2"]
    assert pseudonym_routing_id(public_key).hex() == vector["rid_v2"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_bridge_derives_spec_v1_routing_id(vector: dict) -> None:
    """§25.19 ``rid_v1`` through the PyO3 bridge's pseudonym derivation."""
    core = pytest.importorskip("scp_sdk._scp_core")
    # A `testing` build exposes the fullstack methods (see test_e2e_fullstack.py);
    # only a build without that feature may skip. In a `testing` build a missing
    # hook is a failure, not a skip.
    if not hasattr(core.SCP({"type": "in_memory"}), "fullstack_create_node"):
        pytest.skip("extension built without the `testing` feature")
    hook = getattr(core, "testing_pseudonym_routing_id_from_seed", None)
    assert hook is not None, "a `testing` build must export testing_pseudonym_routing_id_from_seed"
    routing_id = hook(bytes.fromhex(vector["scalar"]), CONTEXT_ALPHA.decode())
    assert bytes(routing_id).hex() == vector["rid_v1"]
