//! Items the governance domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state::CommitFaultMarker;
use crate::context::state::PendingCommit;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::GovernanceAction;
use scp_protocol::context::governance::GovernanceProposal;
use scp_protocol::context::governance::ProposalId;
use scp_protocol::context::governance::ProposalStatus;
use scp_protocol::trust::consequence::ConsequenceRule;
use scp_protocol::trust::consequence::TriggeredConsequence;

/// Field-disjoint variant of `check_commit_fault` used by both the
/// legacy [`crate::context::state::PerContextState`] and the
/// actor-shape
/// [`crate::context::actor::state::PerContextState`].
///
/// ADR-049 Phase 2A.7 — added so the actor-shape `messaging_helpers`
/// can drive the same fail-closed gate without going through the
/// legacy state struct.
///
/// # Errors
///
/// Returns [`ContextError::CommitBroadcastFault`] if the marker is `Some`.
pub fn check_commit_fault_marker(marker: Option<&CommitFaultMarker>) -> Result<(), ContextError> {
    if let Some(marker) = marker {
        return Err(ContextError::CommitBroadcastFault {
            operation: marker.operation.label(),
            reason: marker.reason.clone(),
            attempts: marker.retry_count,
        });
    }
    Ok(())
}

/// Returns `Err(CommitBroadcastFault)` if the actor-shape state has an
/// active commit fault marker (PR #1606 C6), otherwise `Ok(())`.
///
/// # Errors
///
/// [`ContextError::CommitBroadcastFault`] when the marker is set.
pub fn check_commit_fault(state: &PerContextState) -> Result<(), ContextError> {
    check_commit_fault_marker(state.commit_fault.as_ref())
}

/// Commit-provenance for a governance-action leaf: the approved proposal id,
/// the acting DID, and the committer-assigned leaf timestamp.
///
/// The timestamp is `proposal.created_at` — a value bound into the SIGNED
/// proposal, so it is identical and tamper-evident for every member that
/// processes the proposal (convergent-by-construction). The leaf carrying it,
/// however, is currently appended ONLY by the committing member: the
/// receive-side append path is dormant, so governance leaves are not yet
/// replicated cross-member. Cross-member leaf replication is the forward step
/// under ADR-051 (§7.3.1, §9.9.3).
///
/// Bundled so the per-action `execute_*` helpers carry one provenance value
/// instead of three loose trailing parameters (keeps each helper within the
/// argument budget and groups the "who/what/when committed this" triplet).
#[derive(Clone, Copy)]
pub struct CommitMeta<'a> {
    /// The approved proposal whose execution mints this leaf.
    pub pid: ProposalId,
    /// The acting DID recorded as the leaf actor.
    pub actor_did: &'a str,
    /// The convergent committer-assigned leaf timestamp (Unix seconds).
    pub timestamp_secs: u64,
}

/// The destination context id of the migration that `proposal_id` proposes
/// for `context_id`: the hex SHA-256 of `"SCP-MIGRATION-DEST:"`, the source
/// context id and the proposal id.
#[must_use]
pub fn migration_destination_id(context_id: &str, proposal_id: &ProposalId) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-MIGRATION-DEST:");
    hasher.update(context_id.as_bytes());
    hasher.update(proposal_id);
    hex::encode(hasher.finalize())
}

/// What a context migration's destination create runs under:
/// `bootstrap_spawn_lock` and the first-state claim of the destination id
/// (ADR-049 Decision 9).
///
/// The governance call that executes the migration reserves both before its
/// first record, so their retryable [`ContextError::ActorBusy`] leaves
/// nothing behind and a retry of the same call can succeed. After that first
/// record the call never returns `ActorBusy`: the migration holds the guard
/// through its destination create and its rollback
/// (`scp_runtime_governance::helpers::execute_propose_context_migration` takes this as a required argument).
pub struct MigrationBootstrap {
    /// The held `bootstrap_spawn_lock`.
    guard: tokio::sync::OwnedMutexGuard<()>,
    /// The first-state guard that holds the destination id's claim.
    pub(crate) first_state: crate::context::shared::lifecycle::FirstStateRollback,
    /// The destination context id the claim covers.
    pub(crate) destination_context_id: String,
}

/// A [`MigrationBootstrap`] split by [`MigrationBootstrap::into_parts`].
///
/// Holding one proves nothing: only the unsplit `MigrationBootstrap` proves
/// the lock is held, so no function takes this as an argument.
pub struct MigrationBootstrapParts {
    /// The held `bootstrap_spawn_lock`.
    pub guard: tokio::sync::OwnedMutexGuard<()>,
    /// The first-state guard that holds the destination id's claim.
    pub first_state: crate::context::shared::lifecycle::FirstStateRollback,
    /// The destination context id the claim covers.
    pub destination_context_id: String,
}

impl MigrationBootstrap {
    /// Splits the reservation into the held `bootstrap_spawn_lock` guard, the
    /// destination's first-state claim, and the destination id. The guard field
    /// stays private so only [`Self::reserve`], which takes `&ActorDeps`, can
    /// build a `MigrationBootstrap`; a holder therefore proves the lock is held
    /// (ADR-070 §4).
    #[must_use]
    pub fn into_parts(self) -> MigrationBootstrapParts {
        MigrationBootstrapParts {
            guard: self.guard,
            first_state: self.first_state,
            destination_context_id: self.destination_context_id,
        }
    }

    scp_runtime_types::pub_under_testing! {
        /// Try-locks `bootstrap_spawn_lock`, then claims the destination id of
        /// `proposal_id`'s migration. The caller is an actor turn, and the
        /// lock's holders wait on actor mailboxes, so it never waits for the
        /// lock. It takes `&ActorDeps`, so only a domain crate running an actor
        /// turn core lent it can call it (ADR-070 §4).
        ///
        /// # Errors
        ///
        /// - [`ContextError::ActorBusy`] while another bootstrap holds the lock,
        ///   or another operation's first state of the destination is unsettled;
        ///   both are retryable.
        /// - [`ContextError::SupervisorShutDown`] when the Supervisor has dropped.
        ///
        /// Core-internal; `pub` under `testing` for the runtime crates' tests (ADR-070 §5).
        pub(crate) fn reserve(
            deps: &ActorDeps,
            context_id: &str,
            proposal_id: &ProposalId,
        ) -> Result<Self, ContextError> {
            let destination_context_id = migration_destination_id(context_id, proposal_id);
            let guard = deps.supervisor.try_lock_bootstrap_spawn()?;
            let first_state = crate::context::shared::lifecycle::FirstStateRollback::new(
                deps,
                &destination_context_id,
            )?;
            Ok(Self {
                guard,
                first_state,
                destination_context_id,
            })
        }
    }

    /// The bootstrap of `proposal`: `reserved` when the caller already
    /// reserved it, else a new reservation when `proposal` is a context
    /// migration, else `None`.
    ///
    /// # Errors
    ///
    /// As for [`Self::reserve`].
    pub fn for_migration(
        reserved: Option<Self>,
        deps: &ActorDeps,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<Option<Self>, ContextError> {
        if reserved.is_some() {
            Ok(reserved)
        } else if matches!(
            proposal.action,
            GovernanceAction::ProposeContextMigration { .. }
        ) {
            Self::reserve(deps, context_id, &proposal.proposal_id).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The bootstrap of `proposal`, as the propose or vote call about to
    /// record it would leave it, when that call goes on to execute it: the
    /// action is a migration, the proposal is `Approved` and not yet
    /// executed, no governance freeze stands, and no approved conflicting
    /// proposal makes it lose or freezes governance
    /// (`scp_runtime_governance::helpers::detect_and_handle_conflicts`). Decided with reads only, before
    /// the call's first record. `freeze_expires` says the call clears the
    /// standing freeze as expired before it records the proposal.
    ///
    /// # Errors
    ///
    /// As for [`Self::reserve`].
    pub fn if_executed(
        cell: &crate::context::actor::class_s::ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        proposal: &GovernanceProposal,
        freeze_expires: bool,
    ) -> Result<Option<Self>, ContextError> {
        let governance = &cell.governance;
        let cleared = governance
            .freeze
            .filter(|_| freeze_expires)
            .map(|(a, b, _)| [a, b]);
        let executes = proposal.status == ProposalStatus::Approved
            && !governance
                .class_s
                .executed_proposals
                .contains_key(&proposal.proposal_id)
            && (governance.freeze.is_none() || freeze_expires)
            // The new proposal takes `next_proposal_seq`: an equal sequence
            // freezes governance and a greater one loses, so either skips the
            // execution.
            && !conflicting_approved(cell, proposal).any(|(id, (_, seq, _))| {
                !cleared.is_some_and(|pair| pair.contains(id))
                    && governance.next_proposal_seq >= *seq
            });
        if executes {
            Self::for_migration(None, deps, context_id, proposal)
        } else {
            Ok(None)
        }
    }
}

/// The retry-queue bookkeeping a failed MLS-Commit broadcast requires.
///
/// `scp_runtime_governance::helpers::try_broadcast_commit` returns it when the transport send FAILS, so the
/// CALLER applies it (via `scp_runtime_governance::helpers::apply_broadcast_failure`) in the correct
/// durability class.
///
/// Splitting the failure bookkeeping OUT of the async transport send is what
/// lets the safety-gated Class-S sites — `execute_remove_member`,
/// `execute_rotate_content_keys` (this module) and `leave_context`
/// (`lifecycle_helpers`) — persist the `commit_fault` marker + `pending_commits`
/// enqueue FAIL-CLOSED even though the broadcast itself, being async under
/// ADR-049 Decision 7, cannot run inside their synchronous `commit_class_s_keep`
/// closure. The best-effort sites (`execute_add_member`, `execute_reset_member`)
/// apply the identical value coalesced through a `ClassCMut` view.
///
/// Why fail-closed matters here: `commit_fault` is a SAFETY GATE
/// ([`check_commit_fault`] blocks send/lifecycle/governance) and the
/// `pending_commits` entry is the ONLY re-delivery of the epoch-advancing
/// Commit. If a crash lands between a broadcast failure and the ≤50 ms coalesced
/// persist tick, a coalesced-only write loses BOTH — the context respawns
/// "healthy" while members are stuck on a stale MLS epoch with no retry queued:
/// silent, permanent group desync (ADR-049 §9 / §9.9.3).
pub struct BroadcastFailure {
    /// The retry record to enqueue (or, when the queue is full at apply time,
    /// the source of the fail-close [`CommitFaultMarker`]).
    pub pending: PendingCommit,
    /// Operation label for the surfaced local `ContextEvent`.
    pub label: String,
    /// Transport error string for the surfaced local `ContextEvent`.
    pub error: String,
}

impl BroadcastFailure {
    /// The transport error the failed first publish returned.
    #[must_use]
    pub fn error(&self) -> &str {
        &self.error
    }
}

/// Borrowed inputs for `enforce_triggered_consequences`.
///
/// Bundling the providers, scope identifiers, and pre-evaluated rule data into
/// one struct keeps the public function signature within the
/// `clippy::too_many_arguments` budget while preserving the explicit names that
/// callers (`messaging.rs`, `outlets.rs`, `governance.rs`, the periodic timer)
/// need at construction time.
pub struct EnforceConsequencesCtx<'a> {
    /// The context the consequences apply in.
    pub context_id: &'a str,
    /// The member the consequences apply to.
    pub member_did: &'a DID,
    /// The enforcement instant, in Unix seconds.
    pub now: u64,
    /// The consequences the rule evaluation triggered.
    pub triggered: &'a [TriggeredConsequence],
    /// The context's consequence rules.
    pub rules: &'a [ConsequenceRule],
    /// The clock enforcement stamps records with.
    pub clock: &'a dyn scp_clock::Clock,
    /// The event log the enforcement records are appended to.
    pub event_log: &'a dyn crate::context::builder::ContextEventLogProvider,
    /// Optional broadcast channel for event propagation from free
    /// functions that lack `&self` access to `ContextManager`.
    pub event_tx: Option<
        &'a tokio::sync::broadcast::Sender<(
            String,
            scp_protocol::context::membership::ContextEvent,
        )>,
    >,
}

/// The approved proposals whose actions conflict with `proposal`'s
/// (ADR-031 §7).
pub fn conflicting_approved<'c>(
    cell: &'c crate::context::actor::class_s::ClassSCell,
    proposal: &'c GovernanceProposal,
) -> impl Iterator<Item = (&'c ProposalId, &'c (GovernanceProposal, u64, u64))> + 'c {
    cell.governance
        .approved_proposals
        .iter()
        .filter(move |(_, (existing, _, _))| {
            scp_protocol::context::governance::actions_conflict(
                &proposal.action,
                &proposal.proposer_did,
                &existing.action,
                &existing.proposer_did,
            )
        })
}
