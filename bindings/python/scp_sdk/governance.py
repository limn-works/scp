"""SCP Governance wrappers.

Provides idiomatic Python access to context governance operations exposed
by the ``_scp_core`` PyO3 bridge.  All governance actions are delegated
to ``ContextManager::execute_governance_action`` in the Rust engine.

See ``.docs/specs/05-contexts.md`` section 5.9 and ADR-031.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


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
    MEMBER_SUSPENDED = "MemberSuspended"
    ACCESS_REVOKED = "AccessRevoked"
    ACCESS_RESTORED = "AccessRestored"
    CONTENT_KEYS_ROTATED = "ContentKeysRotated"
    GOVERNANCE_RECONFIGURED = "GovernanceReconfigured"
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


# ---------------------------------------------------------------------------
# Governance proposal lifecycle (#621)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Ceiling modification, close, checkpoint, restore (#559)
# ---------------------------------------------------------------------------


__all__ = [
    "GovernanceActionResult",
]
