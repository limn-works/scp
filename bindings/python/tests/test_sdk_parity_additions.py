"""Unit tests for SDK-parity wrapper additions.

Covers the two Python wrappers added to close cross-SDK capability-matrix
gaps surfaced by ``scripts/check-sdk-coverage.py``:

  * ``scp_sdk.discovery.discover_contexts`` — wraps the per-instance
    ``context_discover`` bridge method (Discovery/discover). Takes an
    explicit ``scp`` argument for cross-SDK consistency with
    ``discoverContexts(scp, query)`` in TypeScript.
  * ``SCP.economy_verify_payment_receipts`` — wraps the per-instance
    ``economy_verify_payment_receipts`` bridge method (Economy/...).

Both are exercised through their bridge/native seams with mocks, so the
tests run without the compiled ``_scp_core`` extension.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scp_sdk import SCP, discovery


def _make_mock_scp(context_discover_return: object) -> SCP:
    """Build a minimal mock SCP whose _native.context_discover returns the given value."""
    scp = SCP.__new__(SCP)
    scp._native = MagicMock()
    scp._native.context_discover.return_value = context_discover_return
    return scp


@pytest.mark.asyncio
async def test_discover_contexts_dispatches_and_wraps_results_as_dicts() -> None:
    scp = _make_mock_scp([{"context_id": "abc", "name": "cooking"}])
    result = await discovery.discover_contexts(scp, "did:dht:z6Mkexample")

    assert result == [{"context_id": "abc", "name": "cooking"}]
    scp._native.context_discover.assert_called_once_with("did:dht:z6Mkexample")


@pytest.mark.asyncio
async def test_discover_contexts_returns_empty_list_when_nothing_advertised() -> None:
    scp = _make_mock_scp([])
    result = await discovery.discover_contexts(scp, "scp://example/ctx")

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
    assert result["results"][0]["valid"] is False
    assert result["results"][0]["ok"] is True
    scp._native.economy_verify_payment_receipts.assert_called_once_with("[]")
