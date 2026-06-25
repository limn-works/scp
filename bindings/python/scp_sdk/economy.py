"""Economic governance for the SCP Python SDK.

Provides cost estimation, budget tracking, antispam velocity checking, and
pricing policy evaluation. All monetary values are in the smallest currency
unit (e.g., cents for USD, satoshis for BTC).

See ``.docs/specs/`` section 19 (Economic Governance) and ADR-033.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import ScpError

if TYPE_CHECKING:
    pass

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
    "policy_requires_payment",
    "validate_policy_change",
]
