"""Byte-level Known-Answer Test (KAT) for per-context pseudonym derivation.

Spec §9.10.4.A (algorithm) and §25.19 vectors 30 & 31 (pinned outputs).

Each assertion here runs production code against literal §25.19 bytes:

- The v1 and v2 (epoch 1) tests feed each vector's literal ``seed_v1`` or
  ``seed_v2`` to :func:`scp_sdk.p256_pseudonym_scalar` and
  :func:`scp_sdk.p256_public_key` (the PyO3 exports of
  ``scp_ffi_common::p256_host``) and compare the 33-byte compressed point to
  the spec's ``v1`` or ``v2``. A label or reduction change in that helper fails
  them. They skip when the native extension is not built.
- The bridge test installs each vector's identity scalar as the native
  custody's Ed25519 seed (the §9.10.4.A native interim ikm), derives on
  ``context-alpha`` through the PyO3 bridge, and compares the routing id to the
  spec's ``rid_v1``. It skips when the extension is not built with the
  ``testing`` feature. No bridge path derives a v2 pseudonym in production;
  scp-crypto's §25.19 KAT covers v2.

No test here checks the ``pseudonym_secret`` or context-seed step on its own;
the bridge test covers both for v1 through the routing id.
"""

from __future__ import annotations

import pytest

from scp_sdk import p256_pseudonym_scalar, p256_public_key

# §25.19 context_id, shared by both vectors.
CONTEXT_ALPHA = b"context-alpha"

# §25.19 vectors, every value copied verbatim from the spec.
VECTORS = [
    {
        "name": "Vector 30 (seed 0x01 x 32)",
        "scalar": "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
        "seed_v1": "47ea801c24e8a4d577f04837eca0674fbbf160127fa2d1a4bb1420150b0a048b",
        "v1": "0367e9d3809d6f9bc6854132aff27c2a399463bb516db76f844d79a7b0453c8f72",
        "rid_v1": "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
        "seed_v2": "6ab63aa150992ff032f6963c31dc9f5a8bd4e9518516f9fbd3bea7bc07f64b38",
        "v2": "0276c50b92dacbe6ae1a3761d007b7fe75016a4c076f214694c95d13162ff24479",
    },
    {
        "name": "Vector 31 (seed 0x9d,0x01..0x1f)",
        "scalar": "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
        "seed_v1": "5157d14a2362044199ba88d66d6a52a4bfbe0598ebe921c5fb9c362d3bebaedd",
        "v1": "0239f7c3213f3567183fd2fcf7aec6c884bc70e0e694c42053284a4b5ebef4fe2d",
        "rid_v1": "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
        "seed_v2": "8133a9d716dcbe729b1f447ac0efccf3795e8bf28da2db4744090d0316ead730",
        "v2": "037967cfe8d3111cdd72288ea3f444c15b710300323162fec63ca9036af73754e3",
    },
]

IDS = [v["name"] for v in VECTORS]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_v1_static_pseudonym_point_matches_spec(vector: dict) -> None:
    """The production helpers map the §25.19 ``seed_v1`` to the spec's ``v1`` point."""
    pytest.importorskip("scp_sdk._scp_core")
    seed = bytes.fromhex(vector["seed_v1"])
    assert p256_public_key(p256_pseudonym_scalar(seed)).hex() == vector["v1"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_v2_rotatable_pseudonym_point_matches_spec(vector: dict) -> None:
    """The production helpers map the §25.19 ``seed_v2`` (epoch 1) to the spec's ``v2`` point."""
    pytest.importorskip("scp_sdk._scp_core")
    seed = bytes.fromhex(vector["seed_v2"])
    assert p256_public_key(p256_pseudonym_scalar(seed)).hex() == vector["v2"]


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
