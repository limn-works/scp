"""Economic governance for the SCP Python SDK.

Provides cost estimation, budget tracking, antispam velocity checking, and
pricing policy evaluation. All monetary values are in the smallest currency
unit (e.g., cents for USD, satoshis for BTC).

See ``.docs/specs/`` section 19 (Economic Governance) and ADR-033.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from scp_sdk.errors import ScpError

logger = logging.getLogger("scp_sdk")


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
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
        action_type: One of ``"MessageSend"``, ``"ToolInvoke"``,
            ``"ContextJoin"``, ``"SubscriptionPeriod"``, ``"ByteStored"``.
        metrics: Observable metrics dict with optional keys:
            ``context_message_rate``, ``member_count``, ``relay_queue_depth``,
            ``time_of_day``, ``sender_velocity``, ``storage_usage``.
            All default to 0.

    Returns:
        Estimated cost (smallest currency unit), or ``None`` on overflow.
    """
    bridge = _bridge()
    m = metrics or {}
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
    m = metrics or {}
    return bridge.economy_evaluate_formula(formula_json, m)


# ---------------------------------------------------------------------------
# Relay pricing
# ---------------------------------------------------------------------------


@dataclass
class RelayPriceAdjustment:
    """Result of an EIP-1559-style relay price adjustment."""

    #: New base price (smallest currency unit).
    new_base_price: int

    #: Previous base price before adjustment.
    previous_base_price: int

    #: Direction: ``"Increased"``, ``"Decreased"``, or ``"Unchanged"``.
    direction: str


def adjust_relay_price(config_json: str, utilization_pct: int) -> RelayPriceAdjustment:
    """Compute an EIP-1559-style relay price adjustment.

    Args:
        config_json: Relay pricing config as JSON string with fields:
            ``target_utilization_pct``, ``current_base_price``,
            ``max_change_per_mille``, ``floor``, ``cap``.
        utilization_pct: Current utilization percentage (0-100).

    Returns:
        A :class:`RelayPriceAdjustment` with the new price and direction.
    """
    bridge = _bridge()
    result = bridge.economy_adjust_relay_price(config_json, utilization_pct)
    return RelayPriceAdjustment(
        new_base_price=result["new_base_price"],
        previous_base_price=result["previous_base_price"],
        direction=result["direction"],
    )


# ---------------------------------------------------------------------------
# Budget tracking
# ---------------------------------------------------------------------------


def budget_remaining(context_id: str, did: str) -> int:
    """Query the remaining budget for a member in a context.

    Args:
        context_id: The context ID.
        did: The member's DID.

    Returns:
        Remaining budget (smallest currency unit). Returns 0 if no budget
        has been granted.
    """
    bridge = _bridge()
    return bridge.economy_budget_remaining(context_id, did)


def budget_grant(context_id: str, did: str, amount: int) -> None:
    """Grant spending budget to a member.

    Grants are additive: granting 100 twice gives a total limit of 200.

    Args:
        context_id: The context ID.
        did: The member's DID.
        amount: Budget to grant (smallest currency unit).
    """
    bridge = _bridge()
    bridge.economy_budget_grant(context_id, did, amount)


def budget_record_spend(context_id: str, did: str, amount: int) -> None:
    """Record a spend against a member's budget.

    Args:
        context_id: The context ID.
        did: The member's DID.
        amount: Amount spent (smallest currency unit).

    Raises:
        ValueError: If no budget exists or the spend exceeds remaining budget.
    """
    bridge = _bridge()
    bridge.economy_budget_record_spend(context_id, did, amount)


# ---------------------------------------------------------------------------
# Antispam velocity tracking
# ---------------------------------------------------------------------------


def antispam_record(context_id: str, sender_did: str, timestamp: int) -> None:
    """Record a message for antispam velocity tracking.

    Args:
        context_id: The context ID.
        sender_did: The sender's DID.
        timestamp: Unix timestamp in seconds.
    """
    bridge = _bridge()
    bridge.economy_antispam_record(context_id, sender_did, timestamp)


def antispam_velocity(context_id: str, sender_did: str, now: int) -> int:
    """Query the sender's message velocity within the sliding window.

    Args:
        context_id: The context ID.
        sender_did: The sender's DID.
        now: Current Unix timestamp in seconds.

    Returns:
        Number of messages within the sliding window.
    """
    bridge = _bridge()
    return bridge.economy_antispam_velocity(context_id, sender_did, now)


def antispam_escalated_cost(
    context_id: str,
    sender_did: str,
    now: int,
    base_cost: int,
    thresholds: list[tuple[int, int]],
    floor: int | None = None,
    cap: int | None = None,
) -> int:
    """Compute the escalated cost for a sender based on antispam velocity.

    Args:
        context_id: The context ID.
        sender_did: The sender's DID.
        now: Current Unix timestamp in seconds.
        base_cost: Base cost (smallest currency unit).
        thresholds: List of ``(velocity_threshold, additional_cost)`` pairs.
        floor: Optional minimum cost.
        cap: Optional maximum cost.

    Returns:
        Escalated cost (smallest currency unit).
    """
    bridge = _bridge()
    thresholds_json = json.dumps(thresholds)
    return bridge.economy_antispam_escalated_cost(
        context_id, sender_did, now, base_cost, thresholds_json, floor, cap
    )


__all__ = [
    "RelayPriceAdjustment",
    "adjust_relay_price",
    "antispam_escalated_cost",
    "antispam_record",
    "antispam_velocity",
    "auto_accept_blocked",
    "budget_grant",
    "budget_record_spend",
    "budget_remaining",
    "check_policy_lock",
    "estimate_cost",
    "evaluate_formula",
    "policy_requires_payment",
    "validate_policy_change",
]
