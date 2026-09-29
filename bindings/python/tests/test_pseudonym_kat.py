"""Known-Answer Test (KAT) for the PyO3 bridge's per-context pseudonym derivation.

Spec §9.10.4.A (algorithm) and §25.19 Vectors 30 and 31 (pinned outputs).

The test installs each vector's identity scalar as the native custody's
Ed25519 seed (the §9.10.4.A native interim ikm), derives on ``context-alpha``
through the PyO3 bridge, and compares the routing id to the spec's ``rid_v1``.
The routing id covers the ``pseudonym_secret``, context-seed, and P-256 scalar
steps for v1. It skips when the extension is not built with the ``testing``
feature. No bridge path derives a v2 pseudonym in production; scp-crypto's
§25.19 KAT covers v2. The v1 and v2 points for each vector's context seeds are
checked in ``test_p256_host_helpers.py``.
"""

from __future__ import annotations

import pytest

# §25.19 context_id, shared by both vectors.
CONTEXT_ALPHA = b"context-alpha"

# §25.19 vectors, every value copied verbatim from the spec.
VECTORS = [
    {
        "name": "Vector 30 (seed 0x01 x 32)",
        "scalar": "32c69e4a096fadd1a8d0a21e0a97f124d5c4c8c5b15b96027beadb91c2f3ec64",
        "rid_v1": "b7faa05dea2cef1b7aff6a48fa5b7b9ffe217b25f3152d78d597bb9078e98307",
    },
    {
        "name": "Vector 31 (seed 0x9d,0x01..0x1f)",
        "scalar": "65d56a863d03d31ea15ade82f677058d5bbe53afedc6ff7d2b8846aa25a1bc2b",
        "rid_v1": "cab5ff45d21b6d0425fa7657e89fc68514965cbb4ca2b9549f4ccf430d581e7c",
    },
]

IDS = [v["name"] for v in VECTORS]


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
