"""SCP-OUT-023 conformance: InvocationCaveats round-trip through the FFI layer.

Builds an :class:`~scp_sdk.outlets.InvocationCaveats` in the SDK, passes it
to :func:`scp_sdk.ucan.mint`, decodes the returned JWT, and asserts the
``nb`` field matches the input caveats verbatim (§7.3.8 wire vocabulary).

The test exercises the full marshalling chain:

1. SDK ``InvocationCaveats`` (snake_case) → wire JSON (camelCase) via
   ``ucan._caveats_to_json``.
2. PyO3 bridge :func:`_scp_core.ucan_mint` accepts ``caveats_json`` and
   decodes it via ``scp_ffi_common::caveats::caveats_from_json``.
3. Rust core ``mint_ucan`` validates via ``InvocationCaveats::try_new`` and
   embeds the caveats in the UCAN payload's ``nb`` field.
4. The returned ``UcanToken.encoded`` JWT is decoded; the payload's ``nb``
   field must match the wire-form input.

Mint-limit failures surface as :class:`UcanPermissionError` carrying the
``caveat-mint-limit-exceeded`` slug (matching ``SCP-TOOL-6114``).
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import pytest

pytestmark = pytest.mark.asyncio


def _decode_jwt_payload(encoded: str) -> dict[str, Any]:
    """Decode a UCAN JWT's payload (middle base64url segment)."""
    parts = encoded.split(".")
    if len(parts) != 3:
        raise ValueError(f"invalid JWT: expected 3 segments, got {len(parts)}")
    # base64url-decode with padding fixup
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    decoded = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(decoded)


@pytest.mark.skipif(
    os.environ.get("SCP_FFI_AVAILABLE") != "1",
    reason="requires _scp_core extension (set SCP_FFI_AVAILABLE=1 to run)",
)
async def test_caveats_round_trip_through_jwt_nb_field() -> None:
    """SCP-OUT-023 AC-7: SDK caveats survive marshal-unmarshal through FFI."""
    import scp_sdk
    from scp_sdk.outlets import InvocationCaveats

    # Set up a context with creator identity.
    creator = await scp_sdk.identity.create()
    ctx = await scp_sdk.context.create(creator.did, governance="creator-only")

    caveats = InvocationCaveats(
        amount_max_per_call=100,
        max_calls=42,
        valid_from=1_700_000_000,
        valid_until=1_700_003_600,
    )

    audience = "did:dht:zMember"
    # Marshalling parity test — exercises the SDK-caveats -> wire-JSON ->
    # PyO3 bridge -> Rust mint_ucan -> JWT `nb` chain through ucan.mint.
    # SCP-DEFAULT-INSTANCE-OK: bridge-level mint; no per-instance SCP equivalent yet
    token = await scp_sdk.ucan.mint(
        audience=audience,
        capabilities=["messages:write"],
        context=ctx.id,
        caveats=caveats,
    )

    # The PyUcanToken now exposes `encoded` (SCP-OUT-023). Decode payload.
    assert token.encoded, "ucan.mint must populate UcanToken.encoded for SCP-OUT-023"
    payload = _decode_jwt_payload(token.encoded)

    # AC-7: `nb` field MUST match the input caveats wire form.
    assert "nb" in payload, "JWT payload missing `nb` field"
    nb = payload["nb"]
    assert nb["amountMaxPerCall"] == 100
    assert nb["maxCalls"] == 42
    assert nb["validFrom"] == 1_700_000_000
    assert nb["validUntil"] == 1_700_003_600
    # Absent fields must be omitted, not serialized as null.
    assert "originKind" not in nb
    assert "rateWindow" not in nb


@pytest.mark.skipif(
    os.environ.get("SCP_FFI_AVAILABLE") != "1",
    reason="requires _scp_core extension (set SCP_FFI_AVAILABLE=1 to run)",
)
async def test_mint_limit_violation_surfaces_slug() -> None:
    """SCP-OUT-023 AC-6: mint-limit violation returns SCP-TOOL-6114 slug."""
    import scp_sdk
    from scp_sdk.errors import UcanPermissionError
    from scp_sdk.outlets import InvocationCaveats

    creator = await scp_sdk.identity.create()
    ctx = await scp_sdk.context.create(creator.did, governance="creator-only")

    # 9 populated non-origin_kind caveats — exceeds MAX_POPULATED_CAVEATS = 8.
    over_cap = InvocationCaveats(
        amount_max_per_call=1,
        amount_max_cumulative=2,
        valid_from=3,
        valid_until=4,
        hours_of_day=0x00FFFFFF,
        days_of_week=0x7F,
        max_calls=5,
        rate_window=60,
        input_schema={"type": "object"},  # 9th populated field
    )

    with pytest.raises(UcanPermissionError) as exc_info:
        # Verifies the mint-limit (SCP-TOOL-6114) slug surfaces through ucan.mint.
        # SCP-DEFAULT-INSTANCE-OK: bridge-level mint; no per-instance SCP equivalent yet
        await scp_sdk.ucan.mint(
            audience="did:dht:zMember",
            capabilities=["messages:write"],
            context=ctx.id,
            caveats=over_cap,
        )

    # The slug must appear in the error message; bridge-side mapping wraps it.
    assert "caveat-mint-limit-exceeded" in str(exc_info.value)
