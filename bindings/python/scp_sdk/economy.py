"""Economic governance for the SCP Python SDK.

Provides cost estimation, budget tracking, antispam velocity checking, and
pricing policy evaluation. All monetary values are in the smallest currency
unit (e.g., cents for USD, satoshis for BTC).

See ``.docs/specs/`` section 19 (Economic Governance) and ADR-033.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ScpError

if TYPE_CHECKING:
    from scp_sdk.scp import SCP

logger = logging.getLogger("scp_sdk")


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily.

    Used for pure economy helpers (policy parsing, formula evaluation)
    that do not require an :class:`SCP` instance. Stateful budget and
    antispam tracking take an explicit :class:`scp_sdk.SCP` and dispatch
    on its ``_native`` handle.
    """
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


# ---------------------------------------------------------------------------
# Amount display formatting (ADR-060 SDK display surface)
# ---------------------------------------------------------------------------

# Number of decimal places for well-known currencies, keyed by uppercase
# currency code. The SCP protocol does NOT store per-currency decimals -- the
# wire form is always a smallest-unit integer -- so this table lives entirely
# in the SDK for display purposes. The same values are used across every SDK
# (TypeScript, Swift, Kotlin) for cross-binding consistency.
_KNOWN_CURRENCY_DECIMALS: dict[str, int] = {
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "BTC": 8,
    "SAT": 0,
    "SOL": 9,
    "USDC": 6,
    "ETH": 18,
}


def _format_with_decimals(amount: int, decimals: int) -> str:
    if amount < 0:
        raise ScpError(
            f"amount must be non-negative, got {amount}",
            code="SCP-ECON-12070",
        )
    if decimals < 0 or decimals > 100:
        raise ScpError(
            f"decimals must be in 0..=100, got {decimals}",
            code="SCP-ECON-12070",
        )
    if decimals == 0:
        # The amount is already expressed in whole display units -- no fraction.
        return str(amount)
    divisor = 10**decimals
    whole, fraction = divmod(amount, divisor)
    return f"{whole}.{fraction:0{decimals}d}"


def format_amount(
    amount: int,
    currency: str | None = None,
    *,
    decimals: int | None = None,
) -> str:
    """Format a smallest-unit monetary amount as a human-readable decimal string.

    Applies the currency's decimal scale using pure integer/string arithmetic
    (no floating point), so amounts far beyond ``2**53`` format exactly.

    Examples:
        >>> format_amount(150, "USD")
        '1.50'
        >>> format_amount(100_000_000, "BTC")
        '1.00000000'
        >>> format_amount(1500, decimals=3)
        '1.500'

    Args:
        amount: Smallest-unit amount (e.g. cents, satoshis). Must be non-negative.
        currency: A known currency code (case-insensitive). Mutually exclusive
            with ``decimals``.
        decimals: An explicit decimal-scale override for unknown/custom
            currencies. Mutually exclusive with ``currency``.

    Returns:
        The human-decimal representation as a string.

    Raises:
        ScpError: If neither/both of ``currency`` and ``decimals`` are given, if
            the currency is unknown and no ``decimals`` override is supplied, or
            if ``amount``/``decimals`` are out of range.
    """
    if (currency is None) == (decimals is None):
        raise ScpError(
            "exactly one of 'currency' or 'decimals' must be supplied",
            code="SCP-ECON-12070",
        )
    if decimals is not None:
        return _format_with_decimals(amount, decimals)
    assert currency is not None  # narrowed by the exclusivity check above
    known = _KNOWN_CURRENCY_DECIMALS.get(currency.upper())
    if known is None:
        raise ScpError(
            f"unknown currency {currency!r} has no known decimals; "
            "pass an explicit decimals= override",
            code="SCP-ECON-12070",
        )
    return _format_with_decimals(amount, known)


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def estimate_cost(
    policy_json: str,
    action_type: str,
    metrics: dict[str, int] | None = None,
) -> int | None:
    """Estimate the cost for an action in a context.

    Args:
        policy_json: The context's economic policy as a JSON string.
            Pass empty string or ``"null"`` for free contexts.
        action_type: One of ``"MessageSend"``, ``"OutletCall"``,
            ``"ContextJoin"``, ``"SubscriptionPeriod"``, ``"ByteStored"``.
        metrics: Observable metrics dict with optional keys:
            ``context_message_rate``, ``member_count``, ``relay_queue_depth``,
            ``time_of_day``, ``sender_velocity``, ``storage_usage``.
            All default to 0.

    Returns:
        Estimated cost (smallest currency unit), or ``None`` on overflow.
    """
    bridge = _bridge()
    # The bridge takes a non-Optional dict and defaults all observable metric
    # keys to 0 internally, so `metrics={}` and `metrics=None` are
    # observationally identical for this call. Normalise to `{}` rather than
    # `is not None` because there is no semantic difference at the boundary;
    # both branches produce the same Rust input. Do NOT generalise this
    # pattern -- callers operating on Optional collections at FFI boundaries
    # MUST use `is not None` (see trust.py).
    m = metrics if metrics is not None else {}
    return bridge.economy_estimate_cost(policy_json, action_type, m)


def policy_requires_payment(policy_json: str) -> bool:
    """Check whether an economic policy requires payment for any action.

    Args:
        policy_json: Economic policy JSON string (or empty/``"null"`` for free).

    Returns:
        ``True`` if payment is required for at least one action type.
    """
    bridge = _bridge()
    return bridge.economy_policy_requires_payment(policy_json)


def auto_accept_blocked(policy_json: str) -> bool:
    """Check whether auto-accept is blocked by the economic policy.

    Contexts with payment requirements must never auto-accept invitations.

    Args:
        policy_json: Economic policy JSON string.

    Returns:
        ``True`` if auto-accept is blocked.
    """
    bridge = _bridge()
    return bridge.economy_auto_accept_blocked(policy_json)


def check_policy_lock(policy_json: str) -> bool:
    """Check whether an economic policy is locked (immutable).

    Args:
        policy_json: Economic policy JSON string.

    Returns:
        ``True`` if the policy is locked and cannot be changed.
    """
    bridge = _bridge()
    return bridge.economy_check_policy_lock(policy_json)


def validate_policy_change(current_json: str, proposed_json: str) -> bool:
    """Validate a proposed economic policy change.

    Args:
        current_json: Current economic policy JSON string.
        proposed_json: Proposed new policy JSON string.

    Returns:
        ``True`` if the change is valid.

    Raises:
        ValueError: If the policy is locked or the JSON is invalid.
    """
    bridge = _bridge()
    return bridge.economy_validate_policy_change(current_json, proposed_json)


def evaluate_formula(formula_json: str, metrics: dict[str, int] | None = None) -> int | None:
    """Evaluate a pricing formula against observable metrics.

    Args:
        formula_json: Pricing formula as a JSON string.
        metrics: Observable metrics dict (same keys as :func:`estimate_cost`).

    Returns:
        Computed cost (smallest currency unit), or ``None`` on overflow.
    """
    bridge = _bridge()
    # See estimate_cost above: empty/None are observationally identical at
    # the bridge but use `is not None` to keep the FFI-boundary discipline
    # consistent across the SDK.
    m = metrics if metrics is not None else {}
    return bridge.economy_evaluate_formula(formula_json, m)


# ---------------------------------------------------------------------------
# Payment receipt verification
# ---------------------------------------------------------------------------


async def verify_payment_receipts(
    scp: SCP,
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Verify a batch of payment receipts against the configured adapter.

    Dispatches to the ``economy_verify_payment_receipts`` bridge op on the
    :class:`~scp_sdk.SCP` instance, which routes through the runtime payment
    adapter (per receipt). At most 10,000 receipts per call.

    The result distinguishes adapter reachability from payment validity:
    ``all_valid`` is ``True`` iff every receipt both reached the adapter
    (``ok``) *and* the adapter reported it valid (``valid``); it is
    vacuously ``True`` for an empty batch. A caller scanning for failures
    MUST inspect ``valid`` / ``all_valid`` -- an invalid-but-reachable
    receipt has ``ok == True``, ``valid == False``.

    Args:
        scp: The :class:`~scp_sdk.SCP` instance to dispatch on.
        receipts: A list of ``PaymentReceipt`` dicts (serialized to JSON
            for the bridge).

    Returns:
        A dict ``{"all_valid": bool, "results": [...]}``. Each ``results``
        entry is either ``{"receipt_id": str, "ok": True, "valid": bool,
        "result": {...}}`` on success or ``{"ok": False, "error": str}``
        on failure.

    Raises:
        ValueError: If the receipts cannot be serialized, the batch
            exceeds the maximum, or the JSON is invalid.
        RuntimeError: If the supervisor is not initialized.
    """
    instance = scp._native
    receipts_json = json.dumps(receipts)
    result = await asyncio.to_thread(
        instance.economy_verify_payment_receipts,
        receipts_json,
    )
    if isinstance(result, str):
        return json.loads(result)
    return result


# ---------------------------------------------------------------------------
# Budget tracking
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Antispam velocity tracking
# ---------------------------------------------------------------------------


__all__ = [
    "auto_accept_blocked",
    "check_policy_lock",
    "estimate_cost",
    "evaluate_formula",
    "format_amount",
    "policy_requires_payment",
    "validate_policy_change",
    "verify_payment_receipts",
]
