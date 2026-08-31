"""SCP Governance wrappers.

Provides idiomatic Python access to context governance operations exposed
by the ``_scp_core`` PyO3 bridge.  All governance actions are delegated
to ``ContextManager::execute_governance_action`` in the Rust engine.

See ``.docs/specs/05-contexts.md`` section 5.9 and ADR-031.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from scp_sdk.errors import UnknownGovernanceOutcomeError

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# GovernanceActionResult enum
# ---------------------------------------------------------------------------


class GovernanceActionResult(enum.Enum):
    """Result of executing a governance action (ADR-031).

    Each variant corresponds to one of 29 governance action outcomes
    ``scp_core::context::state::GovernanceActionResult`` defines. A PyO3
    bridge maps every one of those Rust variants onto a string this enum
    stores as its value (``crates/scp-ffi/src/context.rs``).
    """

    MEMBER_ADDED = "MemberAdded"
    MEMBER_REMOVED = "MemberRemoved"
    ROLE_CHANGED = "RoleChanged"
    OUTLET_REGISTERED = "OutletRegistered"
    OUTLET_REMOVED = "OutletRemoved"
    CEILING_MODIFIED = "CeilingModified"
    CONTEXT_CLOSED = "ContextClosed"
    TTL_EXTENDED = "TtlExtended"
    PRUNING_POLICY_MODIFIED = "PruningPolicyModified"
    ADMIN_TRANSFERRED = "AdminTransferred"
    SIGNER_ADDED = "SignerAdded"
    SIGNER_REMOVED = "SignerRemoved"
    THRESHOLD_MODIFIED = "ThresholdModified"
    CHILD_CONTEXT_CREATED = "ChildContextCreated"
    OUTLET_INTERFACE_ESTABLISHED = "OutletInterfaceEstablished"
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
    MIGRATION_PROPOSED = "MigrationProposed"
    MIGRATION_CANCELLED = "MigrationCancelled"
    CONTEXT_TOMBSTONED = "ContextTombstoned"

    @classmethod
    def from_bridge(cls, raw: str) -> GovernanceActionResult:
        """Parse a bridge-layer result string into a typed enum member.

        Raises :class:`~scp_sdk.errors.UnknownGovernanceOutcomeError` for a
        string that matches no member. Governance decides authorization, so a
        caller that reads an outcome it cannot name sees an error rather than
        :attr:`EXECUTED`: reporting an unnamed outcome as an executed action
        tells that caller a governance action succeeded while this SDK does not
        know which action ran. That error carries ``raw_outcome``, so a caller
        still learns what a bridge reported.

        Args:
            raw: Outcome string a bridge returned.

        Returns:
            Enum member whose value equals ``raw`` after stripping surrounding
            whitespace.

        Raises:
            UnknownGovernanceOutcomeError: ``raw`` matches no member of this
                enum. A subclass of
                :class:`~scp_sdk.errors.GovernanceError`, so a caller catching
                that category still catches this.
        """
        stripped = raw.strip()
        for member in cls:
            if stripped == member.value:
                return member
        known = ", ".join(member.value for member in cls)
        msg = (
            f"governance action executed, and its outcome {stripped!r} has no name in this "
            f"SDK version; this SDK knows: {known}. Upgrade scp-python to match whichever bridge "
            f"it calls."
        )
        raise UnknownGovernanceOutcomeError(msg, raw_outcome=stripped)


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
