"""SCP Governance wrappers.

Provides idiomatic Python access to context governance operations exposed
by the ``_scp_core`` PyO3 bridge.  All governance actions are delegated
to ``ContextManager::execute_governance_action`` in the Rust engine.

Every bridge names a governance outcome, a proposal status, and a rejection
reason through the exhaustive name functions in
``crates/scp-ffi/common/src/governance_result.rs``. The three enums below carry
exactly those names, and each ``from_bridge`` raises
:class:`~scp_sdk.errors.UnknownGovernanceOutcomeError` (``SCP-GOV-11040``) for a
name it does not carry. ``crates/scp-testing/tests/governance_outcome_parity.rs``
fails when an enum here and its Rust name function list different names.

See ``.docs/specs/05-contexts.md`` section 5.9 and ADR-031.
"""

from __future__ import annotations

import enum
import json
from typing import Any

from scp_sdk.errors import UnknownGovernanceOutcomeError


def _unknown(kind: str, raw: str, known: type[enum.Enum]) -> UnknownGovernanceOutcomeError:
    names = ", ".join(str(member.value) for member in known)
    return UnknownGovernanceOutcomeError(
        f"bridge reported {kind} {raw!r}, which this SDK version does not name; "
        f"known names: {names}. Upgrade scp-sdk to the version of the bridge it calls.",
        raw_outcome=raw,
    )


# ---------------------------------------------------------------------------
# GovernanceActionResult enum
# ---------------------------------------------------------------------------


class GovernanceActionResult(enum.Enum):
    """Result of executing a governance action (ADR-031).

    Each value is the name ``governance_action_result_name`` gives one variant
    of ``scp_core::context::state::GovernanceActionResult``.
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
        """Return the member whose value equals ``raw``.

        Raises:
            UnknownGovernanceOutcomeError: ``raw`` names no member
                (``SCP-GOV-11040``). The action ran, and this SDK cannot say
                which action it was, so it never reports :attr:`EXECUTED` in
                its place.
        """
        for member in cls:
            if raw == member.value:
                return member
        raise _unknown("governance outcome", raw, cls)


class ProposalStatus(enum.Enum):
    """Lifecycle status of a governance proposal (ADR-031).

    Each value is the name ``proposal_status_name`` gives one variant of
    ``scp_core::context::governance::ProposalStatus``.
    """

    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    EXPIRED = "Expired"
    CANCELLED = "Cancelled"
    INVALIDATED = "Invalidated"

    @classmethod
    def from_bridge(cls, raw: str) -> ProposalStatus:
        """Return the member whose value equals ``raw``.

        Raises:
            UnknownGovernanceOutcomeError: ``raw`` names no member
                (``SCP-GOV-11040``).
        """
        for member in cls:
            if raw == member.value:
                return member
        raise _unknown("proposal status", raw, cls)


class RejectionReason(enum.Enum):
    """Reason a governance proposal was rejected (ADR-031).

    Each value is the name ``rejection_reason_name`` gives one variant of
    ``scp_core::context::governance::RejectionReason``.
    """

    ADMIN_REJECTED = "AdminRejected"
    MAJORITY_REJECTED = "MajorityRejected"
    UNANIMITY_BROKEN = "UnanimityBroken"
    APPROVAL_IMPOSSIBLE = "ApprovalImpossible"
    INSUFFICIENT_PARTICIPATION = "InsufficientParticipation"

    @classmethod
    def from_bridge(cls, raw: str) -> RejectionReason:
        """Return the member whose value equals ``raw``.

        Raises:
            UnknownGovernanceOutcomeError: ``raw`` names no member
                (``SCP-GOV-11040``).
        """
        for member in cls:
            if raw == member.value:
                return member
        raise _unknown("rejection reason", raw, cls)


def check_proposal_response(raw: Any) -> Any:
    """Check every name in a governance proposal response and return ``raw``.

    ``governance_propose``, ``governance_approve``, ``governance_reject``, and
    ``governance_withdraw`` each return a JSON object
    ``{status, reason?, rejector?}``; ``governance_propose`` adds
    ``proposal_id`` and ``execution_result``. This function parses ``status``
    into :class:`ProposalStatus`, a ``Rejected`` status's ``reason`` into
    :class:`RejectionReason`, and a non-null ``execution_result`` into
    :class:`GovernanceActionResult`.

    Raises:
        UnknownGovernanceOutcomeError: ``raw`` is not a JSON object, a
            required name is missing or is not a string, or a name matches no
            member of its enum (``SCP-GOV-11040``).
    """
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        parsed = None
    if not isinstance(parsed, dict):
        raise UnknownGovernanceOutcomeError(
            "governance proposal response is not a JSON object, so this SDK cannot read its status",
            raw_outcome=str(raw),
        )
    status_raw = parsed.get("status")
    if not isinstance(status_raw, str):
        raise UnknownGovernanceOutcomeError(
            "governance proposal response carries no string status",
            raw_outcome=str(raw),
        )
    status = ProposalStatus.from_bridge(status_raw)
    reason = parsed.get("reason")
    if status is ProposalStatus.REJECTED:
        if not isinstance(reason, str):
            raise UnknownGovernanceOutcomeError(
                "governance proposal response has status Rejected and no string reason",
                raw_outcome=str(raw),
            )
        RejectionReason.from_bridge(reason)
    elif status is ProposalStatus.INVALIDATED and not isinstance(reason, str):
        raise UnknownGovernanceOutcomeError(
            "governance proposal response has status Invalidated and no string reason",
            raw_outcome=str(raw),
        )
    execution_result = parsed.get("execution_result")
    if execution_result is not None:
        if not isinstance(execution_result, str):
            raise UnknownGovernanceOutcomeError(
                "governance proposal response carries an execution_result that is neither "
                "a string nor null",
                raw_outcome=str(raw),
            )
        GovernanceActionResult.from_bridge(execution_result)
    return raw


__all__ = [
    "GovernanceActionResult",
    "ProposalStatus",
    "RejectionReason",
    "check_proposal_response",
]
