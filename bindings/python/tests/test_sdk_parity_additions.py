"""Unit tests for SDK-parity wrapper additions.

Covers the two Python wrappers added to close cross-SDK capability-matrix
gaps surfaced by ``scripts/check-sdk-coverage.py``:

  * ``scp_sdk.discovery.discover_contexts`` — wraps the module-level
    ``_bridge().context_discover`` bridge function (Discovery/discover).
    Unlike the TypeScript counterpart ``discoverContexts(scp, query)``,
    this function takes no SCP instance — ``context_discover`` is a
    module-level ``#[pyfunction]`` that requires no per-instance bridge.
  * ``SCP.economy_verify_payment_receipts`` — wraps the per-instance
    ``economy_verify_payment_receipts`` bridge method (Economy/...).

Both are exercised through their bridge/native seams with mocks, so the
tests run without the compiled ``_scp_core`` extension.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scp_sdk import SCP, discovery
from scp_sdk.errors import ScpError


def test_discover_contexts_dispatches_and_wraps_results_as_dicts() -> None:
    mock_bridge = MagicMock()
    mock_bridge.context_discover.return_value = [{"context_id": "abc", "name": "cooking"}]

    with patch("scp_sdk.discovery._bridge", return_value=mock_bridge):
        result = discovery.discover_contexts("did:dht:z6Mkexample")

    assert result == [{"context_id": "abc", "name": "cooking"}]
    mock_bridge.context_discover.assert_called_once_with("did:dht:z6Mkexample")


def test_discover_contexts_returns_empty_list_when_nothing_advertised() -> None:
    mock_bridge = MagicMock()
    mock_bridge.context_discover.return_value = []

    with patch("scp_sdk.discovery._bridge", return_value=mock_bridge):
        result = discovery.discover_contexts("scp://example/ctx")

    assert result == []


def test_discover_contexts_is_exported_from_package() -> None:
    import scp_sdk

    assert "discover_contexts" in scp_sdk.__all__
    assert scp_sdk.discover_contexts is discovery.discover_contexts


@pytest.mark.asyncio
async def test_economy_verify_payment_receipts_parses_json_result() -> None:
    # Build an SCP without invoking the native constructor (no addon needed).
    scp = SCP.__new__(SCP)
    scp._native = MagicMock()
    scp._native.economy_verify_payment_receipts.return_value = (
        '{"all_valid": false, "results": [{"receipt_id": "r1", "ok": true, "valid": false}]}'
    )

    result = await scp.economy_verify_payment_receipts([])

    assert result["all_valid"] is False
    # An invalid-but-reachable receipt keeps ok==true; callers must read valid.
    assert result["results"][0].get("valid") is False
    assert result["results"][0]["ok"] is True
    scp._native.economy_verify_payment_receipts.assert_called_once_with("[]")


@pytest.mark.asyncio
async def test_identity_migrate_propagates_scperror() -> None:
    """identity_migrate must propagate ScpError raised by the native bridge."""
    scp = SCP.__new__(SCP)
    scp._native = MagicMock()
    scp._native.identity_migrate.side_effect = ScpError(
        "custody migration failed", code="SCP-IDENTITY-0001"
    )

    with pytest.raises(ScpError, match="custody migration failed"):
        await scp.identity_migrate(MagicMock())


@pytest.mark.asyncio
async def test_economy_verify_payment_receipts_propagates_scperror() -> None:
    """economy_verify_payment_receipts must propagate ScpError raised by the native bridge."""
    scp = SCP.__new__(SCP)
    scp._native = MagicMock()
    scp._native.economy_verify_payment_receipts.side_effect = ScpError(
        "receipt verification failed", code="SCP-ECONOMY-0001"
    )

    with pytest.raises(ScpError, match="receipt verification failed"):
        await scp.economy_verify_payment_receipts([])


@pytest.mark.asyncio
async def test_evaluate_trust_reraises_perm_3030_handle_affinity_error() -> None:
    """evaluate_trust must re-raise PERM-3030 rather than collapsing it to a
    false all-False CapabilityValidation.  PERM-3030 is a programmer error
    (handle belongs to a different SCP instance) that must be visible to the
    caller — not silently absorbed.  Mirrors TypeScript trust.ts behaviour:
    ``if (/^\\[SCP-PERM-3030\\]/.test(msg)) throw error;``
    """
    from scp_sdk.trust import evaluate_trust

    # Construct the error message in the format emitted by the Rust bridge:
    # "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance — ..."
    perm3030_msg = "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance"

    mock_bridge = MagicMock()
    # evaluate_trust routes through mock_bridge.ucan_evaluate (ADR-059 typed path).
    # MagicMock already carries _mock_name, so the test seam in trust.py
    # routes through mock_bridge without any extra setup.
    mock_bridge.ucan_evaluate.side_effect = Exception(perm3030_msg)

    scp = SCP.__new__(SCP)
    scp._native = MagicMock()

    # evaluate_trust passes all tokens directly to ucan_evaluate (ADR-059),
    # so any non-empty token string causes the side_effect to fire.
    with patch("scp_sdk.trust._bridge", return_value=mock_bridge):
        with pytest.raises(Exception, match=r"\[SCP-PERM-3030\]"):
            await evaluate_trust(
                scp,
                subject_did="did:dht:z6Mkexample",
                context_id="ctx-1",
                capability_tokens=["header.payload.sig"],
            )
