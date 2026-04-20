//! Per-context actor module — owns `&mut PerContextState` by move.
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan sections in quoted form (§"ContextActor", etc.).
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Introduced by commit 5 of the actor-per-context refactor (ADR-049 §1).
//! Commit 6 extends this module with the full actor skeleton
//! ([`ContextActor`], [`ContextActorHandle`], [`ActorDeps`], the
//! `handlers/` dispatch tree, and the command + state shapes the
//! dispatch loop consumes).
//!
//! # Commit-5 foundations
//!
//! - [`outcome::Outcome`] — handler return type. Carries `mutated: bool`
//!   so the actor knows when to mark its state dirty for coalesced
//!   persistence.
//! - [`sequence::SequenceReservation`] — RAII guard around a reserved
//!   send-sequence number. Drop rolls back; explicit `commit()` makes
//!   the reservation durable.
//! - [`sequence::SendSequenceTracker`] — minimal monotonic counter the
//!   reservation guards.
//!
//! # Commit-6 additions
//!
//! - [`ContextActor`] — the actor struct and its `run()` dispatch loop.
//! - [`commands::ContextCommand`] — outer enum + 12 sub-enums carrying
//!   the domain-grouped handler routes.
//! - [`handle::ContextActorHandle`] — the caller-side send-with-timeout
//!   mailbox wrapper.
//! - [`deps::ActorDeps`] — capability-reduced dependency bundle.
//! - [`state::PerContextState`] — the owned state payload.
//! - [`handlers`] — per-domain dispatch stubs (commits 7-11 migrate the
//!   real handlers off `ContextManager`).

pub mod commands;
pub mod deps;
pub mod handle;
pub mod handlers;
pub(crate) mod mutation_state_view;
pub mod outcome;
pub(crate) mod query_state_view;
pub mod sequence;
pub mod state;

pub use commands::{
    BroadcastCommand, ContextCommand, EconomyCommand, GovernanceCommand, LifecycleCommand,
    LifecycleControlCommand, MessagingCommand, QueriesCommand, SagaPhaseMessage, StandingCommand,
    ToolsCommand, TrustRecoveryCommand, TtlCloseCommand,
};
pub use deps::ActorDeps;
pub use handle::{ContextActorHandle, SEND_TIMEOUT};
pub use outcome::Outcome;
pub use sequence::{SendSequenceTracker, SequenceReservation};
pub use state::{
    AuthorKeyEntry, BroadcastRecvTracker, BroadcastState, ContextCryptoState, ContextEventLog,
    ContextLifecycleState, ContextModeState, PerContextState, RecvSequenceTracker,
    WelcomeProcessing, WrappingKeyPair,
};

/// Re-export of [`scp_protocol::context::ContextError`] for handler-side
/// use. `Outcome<T>` carries `Result<T, ContextError>`; handlers use this
/// re-export rather than a deep path.
pub use scp_protocol::context::ContextError;

// ---------------------------------------------------------------------------
// ContextActor — the per-context dispatch loop
// ---------------------------------------------------------------------------

use tokio::sync::mpsc;

/// Per-context actor. Owns one [`PerContextState`] by move and processes
/// commands from its inbox one at a time.
///
/// See plan §"ContextActor" for the full shape. Commit 6 lands the
/// skeleton — the `run()` loop compiles and dispatches to the handler
/// stubs; the real timer arms, persistence coalescing, and governance
/// timeout fire-and-forget work lands alongside the handler migrations
/// in commits 7-11.
pub struct ContextActor {
    /// Stable context identifier. Kept as a `String` alongside
    /// [`PerContextState::context_id`] for tracing / logging — the
    /// `state.context_id` is the canonical `[u8; 32]` hash.
    #[allow(dead_code)] // read into log events when the watchdog lands
    context_id: String,
    /// Command inbox. Paired with the `Sender` held by
    /// [`ContextActorHandle`].
    inbox: mpsc::Receiver<ContextCommand>,
    // NOTE — deliberately omitted until the migration commits wire real
    // construction sites (plan §"Commit ladder" commits 7-11):
    //
    //   state: PerContextState,
    //   deps: ActorDeps,
    //   ttl_timer: Option<tokio::time::Interval>,
    //   governance_timeout: Option<tokio::time::Sleep>,
    //   last_persisted_at: std::time::Instant,
    //   dirty: bool,
    //
    // The skeleton's `run()` loop only drives the inbox arm; landing
    // these fields now with `Default::default()` would violate the
    // "no hardcoded None in place of wired state" failure mode
    // explicitly called out in plan §"Known failure modes". They land
    // with the handlers that exercise them.
}

impl ContextActor {
    /// Construct a fresh actor. `inbox` is paired with a
    /// `Sender<ContextCommand>` held by one or more
    /// [`ContextActorHandle`]s. The actor's `run()` loop exits when
    /// either (a) every sender drops, making `inbox.recv()` return
    /// `None`, or (b) a `LifecycleControlCommand::Shutdown` is received.
    ///
    /// Visibility is `pub(in crate::context)` — only
    /// `crate::context::supervisor::supervisor` constructs actors
    /// (commit 6's `Supervisor::spawn_actor`).
    ///
    /// `dead_code` allow: the only production caller is
    /// `Supervisor::spawn_actor`, which is itself only exercised in
    /// `#[cfg(test)]` until the lifecycle handler migrates in commit 9.
    /// The non-test build sees `new` as uncalled because no production
    /// path yet invokes `spawn_actor` — the allow is removed when that
    /// path wires up.
    #[allow(dead_code)]
    pub(in crate::context) const fn new(
        context_id: String,
        inbox: mpsc::Receiver<ContextCommand>,
    ) -> Self {
        Self { context_id, inbox }
    }

    /// Dispatch loop. See plan §"ContextActor" for the full
    /// four-arm `select!` shape that commits 7-11 build out. Commit 6's
    /// loop is a single-arm variant: drain the inbox until it closes or
    /// a terminal command arrives.
    ///
    /// The commit-6 loop is NOT yet wired to state-owning handlers
    /// (`ContextActor` does not hold `state` / `deps` yet — see the
    /// struct's field list). Received commands are matched to detect
    /// the terminal `Shutdown` variant; all other variants receive an
    /// immediate
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
    /// reply via the command's embedded `oneshot::Sender`. This keeps
    /// callers unblocked while the migration commits land.
    pub async fn run(mut self) {
        while let Some(cmd) = self.inbox.recv().await {
            let is_shutdown = cmd.is_shutdown();
            Self::skeleton_dispatch(cmd);
            if is_shutdown {
                break;
            }
        }
    }

    /// Skeleton dispatch — matches every variant and ACKs via the
    /// embedded `oneshot::Sender`. Commits 7-11 replace this with the
    /// real four-arm `tokio::select!` dispatch described in plan
    /// §"ContextActor".
    ///
    /// The function body is a flat `match` on the outer
    /// [`ContextCommand`] variants. Each arm routes to the matching
    /// handler stub's dispatch path, which replies `NotImplemented` and
    /// returns `Outcome::err`. Taking `Outcome` and ignoring it is fine
    /// for the skeleton — the real actor (commits 7-11) uses the
    /// `Outcome::mutated` flag to flip `self.dirty`.
    ///
    /// Lifecycle-control commands use a dedicated fast path that acks
    /// with `Ok(())` so the bridge's `BridgeInstanceCore::suspend()`
    /// default body can complete its pause/persist/shutdown sequence
    /// without each actor returning `NotImplemented` on the control
    /// channel (see `handlers/lifecycle_control.rs`).
    #[allow(clippy::needless_pass_by_value)] // consumed by the dispatch
    fn skeleton_dispatch(cmd: ContextCommand) {
        // Route every variant to its matching handler's oneshot-ack so
        // callers learn the outcome even while the real state is owned
        // by the legacy `ContextManager`. We MUST route the oneshot
        // sender out of the variant — synchronously, in this function
        // — because the real handler modules take a
        // `&mut PerContextState` which the skeleton actor does not
        // carry yet. Reproducing the ack shape inline keeps the
        // skeleton's mailbox contract (`send -> ack`) intact.
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        fn ack_ok(reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>) {
            let _ = reply.send(Ok(()));
        }

        match cmd {
            ContextCommand::Messaging(MessagingCommand::Placeholder { reply }) => {
                ack_not_impl(reply, "messaging");
            }
            ContextCommand::Messaging(MessagingCommand::SendMessage { reply, .. }) => {
                // Skeleton dispatch does NOT own a ContextManager to
                // delegate to — the shim routes messaging through
                // [`Supervisor::dispatch_command`] (commit 8). Any
                // caller that mistakenly routes a SendMessage through
                // the actor mailbox during the migration window gets a
                // typed error rather than a hang.
                ack_not_impl(
                    reply,
                    "messaging::send_message (use Supervisor::dispatch_command during commits 8-11)",
                );
            }
            ContextCommand::Messaging(MessagingCommand::DeliverIncoming { reply, .. }) => {
                ack_not_impl(
                    reply,
                    "messaging::deliver_incoming (use Supervisor::dispatch_command during commits 8-11)",
                );
            }
            ContextCommand::Lifecycle(sub) => Self::skeleton_dispatch_lifecycle(sub),
            ContextCommand::Governance(sub) => Self::skeleton_dispatch_governance(sub),
            ContextCommand::Broadcast(BroadcastCommand::Placeholder { reply }) => {
                ack_not_impl(reply, "broadcast");
            }
            ContextCommand::Economy(sub) => Self::skeleton_dispatch_economy(sub),
            ContextCommand::TrustRecovery(sub) => Self::skeleton_dispatch_trust_recovery(sub),
            ContextCommand::Standing(StandingCommand::Placeholder { reply }) => {
                ack_not_impl(reply, "standing");
            }
            ContextCommand::TtlClose(sub) => Self::skeleton_dispatch_ttl_close(sub),
            ContextCommand::Tools(ToolsCommand::Placeholder { reply }) => {
                ack_not_impl(reply, "tools");
            }
            // Queries variants — skeleton dispatch acks each typed
            // oneshot with `Err(NotImplemented)` so the caller learns
            // immediately that the actor did not own the state to
            // answer. The real answer path lives on
            // `Supervisor::dispatch_query`, which bypasses this skeleton
            // by talking to the legacy `ContextManager` under the query
            // shim. The skeleton only sees query commands if a caller
            // mistakenly routes through the actor's mailbox — the real
            // FFI dispatch goes through `Supervisor::dispatch_query`.
            ContextCommand::Queries(q) => Self::skeleton_dispatch_queries(q),
            ContextCommand::SagaPhase(SagaPhaseMessage::Placeholder { reply }) => {
                ack_not_impl(reply, "saga_phase");
            }
            ContextCommand::LifecycleControl(LifecycleControlCommand::Pause { reply }) => {
                // Ack Ok — the bridge's `suspend()` default body sends
                // `Pause` and expects an Ok reply to proceed to
                // `PersistSync`. Commit 11's real handler keeps the
                // same Ok-on-pause contract.
                ack_ok(reply);
            }
            ContextCommand::LifecycleControl(LifecycleControlCommand::PersistSync { reply }) => {
                // Ack Ok — nothing to persist through the actor path
                // yet (the legacy `ContextManager` still owns mutating
                // paths until commit 12). Semantically equivalent to
                // "flush buffer is empty, nothing to write".
                ack_ok(reply);
            }
            ContextCommand::LifecycleControl(LifecycleControlCommand::Shutdown { reply }) => {
                // Ack Ok and let the outer `run()` loop exit after this
                // dispatch returns (the caller detected `is_shutdown`
                // before invoking us).
                ack_ok(reply);
            }
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Queries`]. Extracted
    /// from [`Self::skeleton_dispatch`] so the outer function stays below
    /// the `too_many_lines` clippy threshold. The body is a flat match on
    /// every [`QueriesCommand`] variant; each arm acks with
    /// `Err(NotImplemented)` via the variant's embedded oneshot sender.
    ///
    /// Shim-routed query dispatch does not go through this function — see
    /// the comment on the sole call site in [`Self::skeleton_dispatch`].
    fn skeleton_dispatch_queries(q: QueriesCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match q {
            QueriesCommand::LocalPseudonym { reply, .. } => {
                ack_not_impl(reply, "queries::local_pseudonym");
            }
            QueriesCommand::GetBroadcastKeyForLocalAuthor { reply, .. } => {
                ack_not_impl(reply, "queries::get_broadcast_key_for_local_author");
            }
            QueriesCommand::MemberCount { reply, .. } => {
                ack_not_impl(reply, "queries::member_count");
            }
            QueriesCommand::IsMember { reply, .. } => {
                ack_not_impl(reply, "queries::is_member");
            }
            QueriesCommand::MemberDids { reply, .. } => {
                ack_not_impl(reply, "queries::member_dids");
            }
            QueriesCommand::MemberRole { reply, .. } => {
                ack_not_impl(reply, "queries::member_role");
            }
            QueriesCommand::ContextParams { reply, .. } => {
                ack_not_impl(reply, "queries::context_params");
            }
            QueriesCommand::GetRoleState { reply, .. } => {
                ack_not_impl(reply, "queries::get_role_state");
            }
            QueriesCommand::PendingCommits { reply, .. } => {
                ack_not_impl(reply, "queries::pending_commits");
            }
            QueriesCommand::CommitFault { reply, .. } => {
                ack_not_impl(reply, "queries::commit_fault");
            }
            QueriesCommand::EventLogEntries { reply, .. } => {
                ack_not_impl(reply, "queries::event_log_entries");
            }
            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { reply, .. } => {
                ack_not_impl(reply, "queries::get_access_key");
            }
            #[cfg(feature = "testing")]
            QueriesCommand::GetAllAccessKeys { reply, .. } => {
                ack_not_impl(reply, "queries::get_all_access_keys");
            }
            #[cfg(feature = "testing")]
            QueriesCommand::RemainingBudgetForTest { reply, .. } => {
                ack_not_impl(reply, "queries::remaining_budget_for_test");
            }
            #[cfg(feature = "testing")]
            QueriesCommand::VelocityForTest { reply, .. } => {
                ack_not_impl(reply, "queries::velocity_for_test");
            }
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Lifecycle`].
    /// Extracted from [`Self::skeleton_dispatch`] so the outer function
    /// stays below the `too_many_lines` clippy threshold.
    ///
    /// Shim-routed lifecycle dispatch does not go through this
    /// function — the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_lifecycle_command`]
    /// (ADR-049 commit 9). Any caller that mistakenly routes a
    /// lifecycle operation through the actor mailbox during the
    /// migration window gets a typed error rather than a hang.
    fn skeleton_dispatch_lifecycle(sub: LifecycleCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            LifecycleCommand::Placeholder { reply } => ack_not_impl(reply, "lifecycle"),
            // `CreateContext` carries a `ContextCreationError` reply
            // (not `ContextError`); surface an equivalent
            // `CreationFailed` stub so the typed result's error
            // category is preserved.
            LifecycleCommand::CreateContext { reply, .. } => {
                let _ = reply.send(Err(
                    scp_protocol::context::builder::ContextCreationError::CreationFailed(
                        "lifecycle::create_context (use Supervisor::dispatch_lifecycle_command during commits 9-11) \
                         — migrates in the matching handler commit of ADR-049"
                            .to_owned(),
                    ),
                ));
            }
            LifecycleCommand::JoinContext { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::join_context (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::LeaveContext { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::leave_context (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::CloseContext { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::close_context (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::ExportContext { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::export_context (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::ImportContext { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::import_context (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Governance`].
    /// Extracted from [`Self::skeleton_dispatch`] so the outer function
    /// stays below the `too_many_lines` clippy threshold.
    ///
    /// Shim-routed governance dispatch does not go through this
    /// function — the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_governance_command`]
    /// (ADR-049 commit 10).
    fn skeleton_dispatch_governance(sub: GovernanceCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            GovernanceCommand::Placeholder { reply } => ack_not_impl(reply, "governance"),
            GovernanceCommand::ProposeGovernanceAction { reply, .. } => ack_not_impl(
                reply,
                "governance::propose_governance_action (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::ProposeGovernanceActionChecked { reply, .. } => ack_not_impl(
                reply,
                "governance::propose_governance_action_checked (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::VoteOnProposal { reply, .. } => ack_not_impl(
                reply,
                "governance::vote_on_proposal (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::ApproveGovernanceProposal { reply, .. } => ack_not_impl(
                reply,
                "governance::approve_governance_proposal (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::RejectGovernanceProposal { reply, .. } => ack_not_impl(
                reply,
                "governance::reject_governance_proposal (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::WithdrawGovernanceVote { reply, .. } => ack_not_impl(
                reply,
                "governance::withdraw_governance_vote (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::ExecuteGovernanceAction { reply, .. } => ack_not_impl(
                reply,
                "governance::execute_governance_action (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::GetProposal { reply, .. } => ack_not_impl(
                reply,
                "governance::get_proposal (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::ListProposals { reply, .. } => ack_not_impl(
                reply,
                "governance::list_proposals (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::ApplyPendingCeilingModification { reply, .. } => ack_not_impl(
                reply,
                "governance::apply_pending_ceiling_modification (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::ApplyPendingEconomicPolicyChange { reply, .. } => ack_not_impl(
                reply,
                "governance::apply_pending_economic_policy_change (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::TombstoneMigratedContext { reply, .. } => ack_not_impl(
                reply,
                "governance::tombstone_migrated_context (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::MigrationState { reply, .. } => ack_not_impl(
                reply,
                "governance::migration_state (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
            GovernanceCommand::AcknowledgeCommitFault { reply, .. } => ack_not_impl(
                reply,
                "governance::acknowledge_commit_fault (use Supervisor::dispatch_governance_command during commits 10-11)",
            ),
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Economy`].
    /// Extracted from [`Self::skeleton_dispatch`] so the outer function
    /// stays below the `too_many_lines` clippy threshold.
    ///
    /// Shim-routed economy dispatch does not go through this
    /// function — the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_economy_command`]
    /// (ADR-049 commit 10).
    fn skeleton_dispatch_economy(sub: EconomyCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            EconomyCommand::Placeholder { reply } => ack_not_impl(reply, "economy"),
            // `VerifyPaymentReceipts` carries a `Vec<Result<..>>` reply
            // (not `Result<.., ContextError>`); synthesize an empty
            // reply so the mailbox contract is preserved even for the
            // skeleton. Callers that mistakenly route through the
            // skeleton observe an empty verification vector (the
            // timeout/error semantics are defined in the real
            // handler).
            EconomyCommand::VerifyPaymentReceipts { reply, .. } => {
                let _ = reply.send(Vec::new());
            }
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::TrustRecovery`].
    /// Extracted from [`Self::skeleton_dispatch`] so the outer function
    /// stays below the `too_many_lines` clippy threshold.
    ///
    /// Shim-routed trust-recovery dispatch does not go through this
    /// function — the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_trust_recovery_command`]
    /// (ADR-049 commit 10).
    fn skeleton_dispatch_trust_recovery(sub: TrustRecoveryCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            TrustRecoveryCommand::Placeholder { reply } => ack_not_impl(reply, "trust_recovery"),
            TrustRecoveryCommand::CreateGovernanceCheckpoint { reply, .. } => ack_not_impl(
                reply,
                "trust_recovery::create_governance_checkpoint (use Supervisor::dispatch_trust_recovery_command during commits 10-11)",
            ),
            TrustRecoveryCommand::AddCheckpointCosignature { reply, .. } => ack_not_impl(
                reply,
                "trust_recovery::add_checkpoint_cosignature (use Supervisor::dispatch_trust_recovery_command during commits 10-11)",
            ),
            TrustRecoveryCommand::RecoveryAdvanceEpoch { reply, .. } => ack_not_impl(
                reply,
                "trust_recovery::recovery_advance_epoch (use Supervisor::dispatch_trust_recovery_command during commits 10-11)",
            ),
            TrustRecoveryCommand::RecoverySendNotification { reply, .. } => ack_not_impl(
                reply,
                "trust_recovery::recovery_send_notification (use Supervisor::dispatch_trust_recovery_command during commits 10-11)",
            ),
            TrustRecoveryCommand::RecoveryNotifyContact { reply, .. } => ack_not_impl(
                reply,
                "trust_recovery::recovery_notify_contact (use Supervisor::dispatch_trust_recovery_command during commits 10-11)",
            ),
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::TtlClose`].
    /// Extracted from [`Self::skeleton_dispatch`] so the outer function
    /// stays below the `too_many_lines` clippy threshold.
    ///
    /// Shim-routed TTL-close dispatch does not go through this
    /// function — the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_ttl_close_command`]
    /// (ADR-049 commit 9).
    fn skeleton_dispatch_ttl_close(sub: TtlCloseCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            TtlCloseCommand::Placeholder { reply } => ack_not_impl(reply, "ttl_close"),
            TtlCloseCommand::StartTtlTimer { reply, .. } => ack_not_impl(
                reply,
                "ttl_close::start_ttl_timer (use Supervisor::dispatch_ttl_close_command during commits 9-11)",
            ),
            TtlCloseCommand::ExtendTtl { reply, .. } => ack_not_impl(
                reply,
                "ttl_close::extend_ttl (use Supervisor::dispatch_ttl_close_command during commits 9-11)",
            ),
            TtlCloseCommand::ResetTtlTimer { reply, .. } => ack_not_impl(
                reply,
                "ttl_close::reset_ttl_timer (use Supervisor::dispatch_ttl_close_command during commits 9-11)",
            ),
            TtlCloseCommand::ExecuteTtlClose { reply, .. } => ack_not_impl(
                reply,
                "ttl_close::execute_ttl_close (use Supervisor::dispatch_ttl_close_command during commits 9-11)",
            ),
            TtlCloseCommand::FinalizeClose { reply, .. } => ack_not_impl(
                reply,
                "ttl_close::finalize_close (use Supervisor::dispatch_ttl_close_command during commits 9-11)",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn actor_acks_placeholder_command_with_not_implemented() {
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new("ctx-42".to_owned(), rx);
        let actor_handle = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        let err = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));

        // Send a shutdown and let the actor exit cleanly.
        handle.send_shutdown().await.unwrap();
        actor_handle.await.unwrap();
    }

    #[tokio::test]
    async fn actor_exits_on_inbox_close() {
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new("ctx-1".to_owned(), rx);
        let actor_handle = tokio::spawn(actor.run());

        // Drop every sender; actor should observe `None` on recv and
        // exit without a Shutdown command.
        drop(tx);

        // Bound the wait so a regression that fails to exit is caught.
        tokio::time::timeout(std::time::Duration::from_secs(2), actor_handle)
            .await
            .expect("actor must exit when every sender drops")
            .unwrap();
    }

    #[tokio::test]
    async fn actor_pause_acks_ok_and_keeps_running() {
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new("ctx-1".to_owned(), rx);
        let actor_handle = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        handle.send_pause().await.unwrap();
        // Actor is still running; a subsequent command is processed.
        let err = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));

        handle.send_shutdown().await.unwrap();
        actor_handle.await.unwrap();
    }

    #[tokio::test]
    async fn actor_shutdown_command_exits_loop_promptly() {
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new("ctx-1".to_owned(), rx);
        let actor_handle = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        handle.send_shutdown().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), actor_handle)
            .await
            .expect("actor must exit promptly after Shutdown")
            .unwrap();
    }
}
