"""SCP Governance wrappers.

Provides idiomatic Python access to context governance operations exposed
by the ``_scp_core`` PyO3 bridge.  All governance actions are delegated
to ``ContextManager::execute_governance_action`` in the Rust engine.

See ``.docs/specs/05-contexts.md`` section 5.9 and ADR-031.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from scp_sdk.errors import ContextError

if TYPE_CHECKING:
    from scp_sdk.context import Context


# ---------------------------------------------------------------------------
# GovernanceActionResult enum
# ---------------------------------------------------------------------------


class GovernanceActionResult(enum.Enum):
    """Result of executing a governance action (ADR-031).

    Each variant corresponds to one of the 24+ governance action outcomes
    from ``scp_core::context::manager::GovernanceActionResult``.
    """

    MEMBER_ADDED = "MemberAdded"
    MEMBER_REMOVED = "MemberRemoved"
    ROLE_CHANGED = "RoleChanged"
    TOOL_REGISTERED = "ToolRegistered"
    TOOL_REMOVED = "ToolRemoved"
    CEILING_MODIFIED = "CeilingModified"
    CONTEXT_CLOSED = "ContextClosed"
    TTL_EXTENDED = "TtlExtended"
    PRUNING_POLICY_MODIFIED = "PruningPolicyModified"
    ADMIN_TRANSFERRED = "AdminTransferred"
    SIGNER_ADDED = "SignerAdded"
    SIGNER_REMOVED = "SignerRemoved"
    THRESHOLD_MODIFIED = "ThresholdModified"
    CHILD_CONTEXT_CREATED = "ChildContextCreated"
    TOOL_INTERFACE_ESTABLISHED = "ToolInterfaceEstablished"
    MEMBER_RESET = "MemberReset"
    CONFLICT_RESOLVED = "ConflictResolved"
    CONTEXT_PROMOTED = "ContextPromoted"
    READ_ACCESS_REVOKED = "ReadAccessRevoked"
    READ_ACCESS_RESTORED = "ReadAccessRestored"
    WRITE_ACCESS_REVOKED = "WriteAccessRevoked"
    WRITE_ACCESS_RESTORED = "WriteAccessRestored"
    CONTENT_KEYS_ROTATED = "ContentKeysRotated"
    GOVERNANCE_RECONFIGURED = "GovernanceReconfigured"
    AUTHOR_BLOCKED = "AuthorBlocked"
    SUBSCRIBER_BANNED = "SubscriberBanned"
    SUBSCRIBER_UNBANNED = "SubscriberUnbanned"
    EXECUTED = "Executed"

    @classmethod
    def from_bridge(cls, raw: str) -> GovernanceActionResult:
        """Parse a bridge-layer result string into a typed enum member.

        Falls back to :attr:`EXECUTED` for unrecognised strings.
        """
        stripped = raw.strip()
        for member in cls:
            if stripped == member.value:
                return member
        return cls.EXECUTED


# ---------------------------------------------------------------------------
# Governance wrapper functions
# ---------------------------------------------------------------------------


async def execute_governance_action(
    context: Context,
    proposal_json: str,
) -> GovernanceActionResult:
    """Execute a governance action on a context.

    Delegates to ``_scp_core.py_governance_execute``.

    Args:
        context: The context to execute the action on.
        proposal_json: JSON-serialized ``GovernanceProposal``.

    Returns:
        A :class:`GovernanceActionResult` describing the outcome.

    Raises:
        ContextError: If the bridge is unavailable.
        ValueError: If the proposal JSON is invalid.
        RuntimeError: If governance execution fails.
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    raw = _scp_core.py_governance_execute(context._handle, proposal_json)
    return GovernanceActionResult.from_bridge(raw)


async def propose_ttl_extension(
    context: Context,
    additional_seconds: float,
) -> GovernanceActionResult:
    """Propose a TTL extension for a context.

    Convenience wrapper that builds a ``TtlExtend`` governance proposal
    and executes it.

    Args:
        context: The context to extend.
        additional_seconds: Additional time-to-live in seconds.

    Returns:
        A :class:`GovernanceActionResult` (expected ``TTL_EXTENDED``).

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If governance execution fails.
    """
    import json

    proposal = json.dumps({"action": {"TtlExtend": {"additional_seconds": additional_seconds}}})
    return await execute_governance_action(context, proposal)


async def handle_ttl_expiry(context: Context) -> GovernanceActionResult:
    """Handle TTL expiry by executing a context close action.

    Convenience wrapper that builds a ``ContextClose`` governance proposal.

    Args:
        context: The expired context.

    Returns:
        A :class:`GovernanceActionResult` (expected ``CONTEXT_CLOSED``).

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If governance execution fails.
    """
    import json

    proposal = json.dumps({"action": "ContextClose"})
    return await execute_governance_action(context, proposal)


async def reset_ttl_timer(
    context: Context,
    ttl_seconds: float,
) -> GovernanceActionResult:
    """Reset the TTL timer for a context.

    Convenience wrapper that builds a ``TtlExtend`` governance proposal
    with the full TTL duration, effectively resetting the timer.

    Args:
        context: The context to reset the timer for.
        ttl_seconds: The full TTL duration in seconds.

    Returns:
        A :class:`GovernanceActionResult` (expected ``TTL_EXTENDED``).

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If governance execution fails.
    """
    return await propose_ttl_extension(context, ttl_seconds)


# ---------------------------------------------------------------------------
# Governance proposal lifecycle (#621)
# ---------------------------------------------------------------------------


async def propose_governance_action(
    context: Context,
    action_json: str,
    *,
    identity_did: str | None = None,
) -> str:
    """Propose a governance action for voting.

    For ``SingleAdmin`` contexts, the proposal is auto-approved and executed
    immediately.  For multi-admin models (Threshold, Majority, Unanimity),
    the proposal enters ``Pending`` status and must accumulate votes.

    Delegates to ``_scp_core.py_governance_propose``.

    Args:
        context: The context to propose the action on.
        action_json: JSON-serialized ``GovernanceAction``.
        identity_did: DID of the proposer.  Defaults to the context creator.

    Returns:
        JSON string with ``proposal_id``, ``status``, and
        ``execution_result`` (null when pending).

    Raises:
        ContextError: If the bridge is unavailable.
        ValueError: If the action JSON is invalid.
        RuntimeError: If the proposal fails (SCP-CTX-2041).
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    did = identity_did or context._creator_did
    return _scp_core.py_governance_propose(context._handle, did, action_json)


async def approve_governance_proposal(
    context: Context,
    proposal_id_hex: str,
    *,
    identity_did: str | None = None,
) -> str:
    """Cast an approval vote on a pending governance proposal.

    If the vote pushes the proposal past quorum, the action is auto-executed.

    Delegates to ``_scp_core.py_governance_approve``.

    Args:
        context: The context containing the proposal.
        proposal_id_hex: Hex-encoded 32-byte proposal ID.
        identity_did: DID of the voter.  Defaults to the context creator.

    Returns:
        JSON string with ``status`` (Pending, Approved, Rejected, etc.).

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If the vote fails (SCP-CTX-2042).
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    did = identity_did or context._creator_did
    return _scp_core.py_governance_approve(context._handle, did, proposal_id_hex)


async def reject_governance_proposal(
    context: Context,
    proposal_id_hex: str,
    *,
    identity_did: str | None = None,
) -> str:
    """Cast a rejection vote on a pending governance proposal.

    Delegates to ``_scp_core.py_governance_reject``.

    Args:
        context: The context containing the proposal.
        proposal_id_hex: Hex-encoded 32-byte proposal ID.
        identity_did: DID of the voter.  Defaults to the context creator.

    Returns:
        JSON string with ``status``.

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If the vote fails (SCP-CTX-2043).
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    did = identity_did or context._creator_did
    return _scp_core.py_governance_reject(context._handle, did, proposal_id_hex)


async def withdraw_governance_vote(
    context: Context,
    proposal_id_hex: str,
    *,
    identity_did: str | None = None,
) -> str:
    """Withdraw a previously cast vote on a pending governance proposal.

    No signing key is required -- withdrawal is the voter's privileged
    operation on their own vote.

    Delegates to ``_scp_core.py_governance_withdraw``.

    Args:
        context: The context containing the proposal.
        proposal_id_hex: Hex-encoded 32-byte proposal ID.
        identity_did: DID of the voter.  Defaults to the context creator.

    Returns:
        JSON string with ``status``.

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If the withdrawal fails (SCP-CTX-2044).
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    did = identity_did or context._creator_did
    return _scp_core.py_governance_withdraw(context._handle, did, proposal_id_hex)


async def get_governance_proposal(
    context: Context,
    proposal_id_hex: str,
) -> str:
    """Retrieve a single governance proposal by hex-encoded ID.

    Delegates to ``_scp_core.py_governance_get_proposal``.

    Args:
        context: The context containing the proposal.
        proposal_id_hex: Hex-encoded 32-byte proposal ID.

    Returns:
        JSON string with the full proposal details.

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If the proposal is not found (SCP-CTX-2045).
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    return _scp_core.py_governance_get_proposal(context._handle, proposal_id_hex)


async def list_governance_proposals(context: Context) -> str:
    """List all governance proposals for a context.

    Delegates to ``_scp_core.py_governance_list_proposals``.

    Args:
        context: The context to list proposals for.

    Returns:
        JSON array of proposals.

    Raises:
        ContextError: If the bridge is unavailable.
        RuntimeError: If listing fails (SCP-CTX-2046).
    """
    try:
        import _scp_core
    except ImportError as exc:
        raise ContextError(
            "failed to import _scp_core -- is the Rust extension built?",
            code="SCP-CTX-2001",
        ) from exc

    return _scp_core.py_governance_list_proposals(context._handle)


__all__ = [
    "GovernanceActionResult",
    "approve_governance_proposal",
    "execute_governance_action",
    "get_governance_proposal",
    "handle_ttl_expiry",
    "list_governance_proposals",
    "propose_governance_action",
    "propose_ttl_extension",
    "reject_governance_proposal",
    "reset_ttl_timer",
    "withdraw_governance_vote",
]
