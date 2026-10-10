"""The SDK's P-256 pseudonym point helpers against spec §25.19.

``scp_sdk.p256_pseudonym_point`` and ``scp_sdk.p256_software_pseudonym_point``:

- Vectors 30 and 31: each ``identity_scalar`` over "context-alpha" gives the
  v1 point, and at epoch 1 the v2 point; each context seed gives its point
  directly;
- a wrong-length input is rejected with ``SCP-VALID-7005``.

Skips when the native extension is not built.
"""

from __future__ import annotations

import pytest

from tests.conftest import skip_reason_if_extension_absent

try:
    from scp_sdk import _scp_core  # noqa: F401
except Exception as _exc:
    pytest.skip(skip_reason_if_extension_absent(_exc), allow_module_level=True)

from scp_sdk import (
    ValidationError,
    p256_pseudonym_point,
    p256_software_pseudonym_point,
)

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
