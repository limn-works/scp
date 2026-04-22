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
pub mod outcome;
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
    ContextLifecycleState, ContextModeState, PendingBroadcastKeyRotation, PerContextState,
    RecvSequenceTracker, WelcomeProcessing, WrappingKeyPair,
};

/// Re-export of [`scp_protocol::context::ContextError`] for handler-side
/// use. `Outcome<T>` carries `Result<T, ContextError>`; handlers use this
/// re-export rather than a deep path.
pub use scp_protocol::context::ContextError;

// ---------------------------------------------------------------------------
// ContextActor — the per-context dispatch loop
// ---------------------------------------------------------------------------

use tokio::sync::mpsc;

/// Encode a 32-byte context ID as lowercase hex. Matches the string
/// form used throughout the legacy `ContextManager` shim so the
/// actor's `context_id` field is interchangeable with the shim's
/// `ctx_id: &str` parameter.
fn hex_encode_context_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write;
        // Infallible for `u8` inputs written into `String`.
        let _ = write!(s, "{byte:02x}");
    }
    s
}

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
    /// Owned per-context state. `Some` for actors constructed via
    /// [`Self::new`] with a full state payload (12b.2a infrastructure
    /// path, exercised by 12b.2b handlers). `None` for skeleton actors
    /// constructed via [`Self::new_skeleton`] — these are the pre-
    /// 12b.2a test fixtures and the shim-era `spawn_actor` path whose
    /// dispatch continues to route through
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_command`]
    /// against the legacy `ContextManager`.
    ///
    /// Two-mode is bounded: once 12b.2b flips all handler dispatch to
    /// the actor path, every spawn carries `Some(state)` and this
    /// field becomes non-`Option`.
    ///
    /// Read into handler bodies as `&mut self.state` in 12b.2b+. The
    /// 12b.2a dispatch loop does not yet consume the state — it still
    /// ACKs with `Err(NotImplemented)` via the skeleton dispatch —
    /// because migrating one handler without the others silently
    /// breaks the nine remaining shim handlers (see
    /// `.docs/adrs/ADR-049-actor-per-context.md` §Commit ladder
    /// row 12b.2a rationale).
    #[allow(dead_code)] // read by 12b.2b handler bodies
    state: Option<state::PerContextState>,
    /// Owned dependency bundle. `Some` / `None` mirrors [`Self::state`]
    /// — the two are always both `Some` or both `None`. Two-mode is
    /// bounded identically.
    #[allow(dead_code)] // read by 12b.2b handler bodies
    deps: Option<deps::ActorDeps>,
    /// TTL expiry interval timer. Armed at actor construction when the
    /// context's TTL configuration demands it; `None` for contexts
    /// without TTL and for skeleton-mode actors. Drives the
    /// `handlers/ttl_close.rs` expiry path once the run-loop grows a
    /// `select!` TTL arm in 12b.2b+.
    #[allow(dead_code)] // read by 12b.2b+ run-loop
    ttl_timer: Option<tokio::time::Interval>,
    /// Governance proposal timeout deadline. Armed on governance
    /// proposal creation; fires once and is rearmed if a subsequent
    /// proposal lands. Driven by the handler migration in 12b.2b+.
    ///
    /// Note — `tokio::time::Sleep` is `!Unpin` so the field holds a
    /// pinned box. Constructing the future upfront (even unused)
    /// keeps the run-loop's `select!` arm shape stable as the
    /// migration lands.
    #[allow(dead_code)] // read by 12b.2b+ run-loop
    governance_timeout: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    /// Unix-ms instant of the last successful coalesced persist. The
    /// run-loop's persistence arm compares `now() - last_persisted_at`
    /// against the coalescing window (250 ms per plan
    /// §"Persistence coalescing") before issuing a snapshot write.
    /// Initialized to "now" at actor construction.
    #[allow(dead_code)] // read by 12b.2b+ run-loop
    last_persisted_at: std::time::Instant,
    /// Dirty flag set when any handler's [`outcome::Outcome`] carries
    /// `mutated: true`. Cleared after a successful coalesced persist.
    /// Initialized `false` at actor construction.
    #[allow(dead_code)] // read by 12b.2b+ run-loop
    dirty: bool,
}

impl ContextActor {
    /// Construct a fresh actor that owns [`PerContextState`] and
    /// [`ActorDeps`] directly (ADR-049 commit 12b.2a infrastructure
    /// path).
    ///
    /// This is the production constructor — every
    /// [`crate::context::supervisor::supervisor::Supervisor::spawn_actor`]
    /// call that migrates state out of the legacy `ContextManager` /
    /// `MlsCryptoProvider` uses this constructor to hand the drained
    /// state into the actor task.
    ///
    /// Visibility is `pub(in crate::context)` — only
    /// `crate::context::supervisor::supervisor` constructs actors
    /// (the test-only [`Self::new_skeleton`] is also `pub(in
    /// crate::context)` for the same reason).
    ///
    /// # Construction of auxiliary fields
    ///
    /// - `ttl_timer`, `governance_timeout` start as `None`. Handler
    ///   migrations arm them lazily on first use (TTL config present,
    ///   governance proposal landed).
    /// - `last_persisted_at` starts at `Instant::now()` so a fresh
    ///   actor's first coalescing window runs for the full duration
    ///   before the first persist.
    /// - `dirty` starts `false` — no mutations yet.
    ///
    /// # `context_id` derivation
    ///
    /// The canonical context ID lives on `state.context_id` as
    /// `[u8; 32]`. The actor's `String` copy is derived at
    /// construction-time by hex-encoding the 32-byte hash, which
    /// matches the string form `ContextManager` uses throughout the
    /// shim. Callers therefore do not need to pass `context_id`
    /// separately — it is sourced from the state payload.
    #[allow(dead_code)] // first production caller is 12b.2b
    pub(in crate::context) fn new(
        state: state::PerContextState,
        deps: deps::ActorDeps,
        inbox: mpsc::Receiver<ContextCommand>,
    ) -> Self {
        let context_id = hex_encode_context_id(&state.context_id);
        Self {
            context_id,
            inbox,
            state: Some(state),
            deps: Some(deps),
            ttl_timer: None,
            governance_timeout: None,
            last_persisted_at: std::time::Instant::now(),
            dirty: false,
        }
    }

    /// Construct a skeleton actor without state or deps. Used by the
    /// pre-12b.2a test fixtures and by
    /// [`crate::context::supervisor::supervisor::Supervisor::spawn_actor`]
    /// for contexts whose state still lives on the legacy
    /// `ContextManager` (every production context during the
    /// 12b.2a → 12b.2b window).
    ///
    /// The skeleton's `run()` loop drains commands from the inbox and
    /// ACKs each with the same `Err(NotImplemented)` response the
    /// pre-12b.2a dispatch produced. This is deliberate: flipping the
    /// dispatch path for one handler while state still lives on the
    /// manager would silently break the other nine shim handlers. See
    /// `.docs/adrs/ADR-049-actor-per-context.md` §Commit ladder row
    /// 12b.2b for the atomic migration plan.
    ///
    /// Visibility matches [`Self::new`]: `pub(in crate::context)`.
    ///
    /// `dead_code` allow: the first production caller is 12b.2b's
    /// atomic messaging migration, which deletes the skeleton path
    /// and routes every spawn through [`Self::new`] with real state.
    /// Until then this constructor is test-only for the module's
    /// existing unit tests.
    #[allow(dead_code)]
    pub(in crate::context) fn new_skeleton(
        context_id: String,
        inbox: mpsc::Receiver<ContextCommand>,
    ) -> Self {
        Self {
            context_id,
            inbox,
            state: None,
            deps: None,
            ttl_timer: None,
            governance_timeout: None,
            // `Instant::now()` initializes the coalescing window even
            // though the skeleton dispatch never reads it — avoids
            // carrying a magic-value sentinel. When 12b.2b removes the
            // skeleton path this field is populated identically via
            // [`Self::new`].
            last_persisted_at: std::time::Instant::now(),
            dirty: false,
        }
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
            ContextCommand::Broadcast(sub) => Self::skeleton_dispatch_broadcast(sub),
            ContextCommand::Economy(sub) => Self::skeleton_dispatch_economy(sub),
            ContextCommand::TrustRecovery(sub) => Self::skeleton_dispatch_trust_recovery(sub),
            ContextCommand::Standing(sub) => Self::skeleton_dispatch_standing(sub),
            ContextCommand::TtlClose(sub) => Self::skeleton_dispatch_ttl_close(sub),
            ContextCommand::Tools(sub) => Self::skeleton_dispatch_tools(sub),
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

    /// Skeleton-dispatch helper for [`ContextCommand::Standing`].
    /// Extracted for the same reason as the other sibling helpers.
    ///
    /// Shim-routed standing dispatch does not go through this function —
    /// the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_standing_command`]
    /// (ADR-049 commit 11).
    fn skeleton_dispatch_standing(sub: StandingCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            StandingCommand::Placeholder { reply } => ack_not_impl(reply, "standing"),
            StandingCommand::StandingContext { reply, .. } => ack_not_impl(
                reply,
                "standing::standing_context (use Supervisor::dispatch_standing_command during commit 11)",
            ),
            StandingCommand::StandingContextCount { reply, .. } => ack_not_impl(
                reply,
                "standing::standing_context_count (use Supervisor::dispatch_standing_command during commit 11)",
            ),
            StandingCommand::HasStandingContext { reply, .. } => ack_not_impl(
                reply,
                "standing::has_standing_context (use Supervisor::dispatch_standing_command during commit 11)",
            ),
            StandingCommand::RegisterStandingContext { reply, .. } => ack_not_impl(
                reply,
                "standing::register_standing_context (use Supervisor::dispatch_standing_command during commit 11)",
            ),
            StandingCommand::ReconnectAllStanding { reply, .. } => ack_not_impl(
                reply,
                "standing::reconnect_all_standing (use Supervisor::dispatch_standing_command during commit 11)",
            ),
            StandingCommand::InitiateStandingPairCreate { reply, .. } => ack_not_impl(
                reply,
                "standing::initiate_standing_pair_create (saga wiring deferred to commit 11.5 — see DEFERRED-commit-11-saga-use-cases.md)",
            ),
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Tools`].
    ///
    /// Shim-routed tools dispatch does not go through this function —
    /// the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_tools_command`]
    /// (ADR-049 commit 11).
    fn skeleton_dispatch_tools(sub: ToolsCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            ToolsCommand::Placeholder { reply } => ack_not_impl(reply, "tools"),
            ToolsCommand::TryConsumeHardRateLimit { reply, .. } => ack_not_impl(
                reply,
                "tools::try_consume_hard_rate_limit (use Supervisor::dispatch_tools_command during commit 11)",
            ),
            ToolsCommand::RefundHardRateLimit { reply, .. } => ack_not_impl(
                reply,
                "tools::refund_hard_rate_limit (use Supervisor::dispatch_tools_command during commit 11)",
            ),
            ToolsCommand::InitiateCrossContextToolInvocation { reply, .. } => ack_not_impl(
                reply,
                "tools::initiate_cross_context_tool_invocation (saga wiring deferred to commit 11.5 — see DEFERRED-commit-11-saga-use-cases.md)",
            ),
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Broadcast`].
    ///
    /// Shim-routed broadcast dispatch does not go through this function —
    /// the real production path is
    /// [`crate::context::supervisor::supervisor::Supervisor::dispatch_broadcast_command`]
    /// (ADR-049 commit 11).
    fn skeleton_dispatch_broadcast(sub: BroadcastCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            BroadcastCommand::Placeholder { reply } => ack_not_impl(reply, "broadcast"),
            BroadcastCommand::SubscribeBroadcast { reply, .. } => ack_not_impl(
                reply,
                "broadcast::subscribe_broadcast (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::UnsubscribeBroadcast { reply, .. } => ack_not_impl(
                reply,
                "broadcast::unsubscribe_broadcast (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::PublishBroadcast { reply, .. } => ack_not_impl(
                reply,
                "broadcast::publish_broadcast (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::PublishBroadcastContent { reply, .. } => ack_not_impl(
                reply,
                "broadcast::publish_broadcast_content (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::BlockBroadcastSubscriber { reply, .. } => ack_not_impl(
                reply,
                "broadcast::block_broadcast_subscriber (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::UnblockBroadcastSubscriber { reply, .. } => ack_not_impl(
                reply,
                "broadcast::unblock_broadcast_subscriber (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::HandleBroadcastKeyRequest { reply, .. } => ack_not_impl(
                reply,
                "broadcast::handle_broadcast_key_request (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::BroadcastSubscriberCount { reply, .. } => ack_not_impl(
                reply,
                "broadcast::broadcast_subscriber_count (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::IsBroadcastSubscriber { reply, .. } => ack_not_impl(
                reply,
                "broadcast::is_broadcast_subscriber (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::BroadcastAdmission { reply, .. } => ack_not_impl(
                reply,
                "broadcast::broadcast_admission (use Supervisor::dispatch_broadcast_command during commit 11)",
            ),
            BroadcastCommand::InitiateBroadcastHostingHandshake { reply, .. } => ack_not_impl(
                reply,
                "broadcast::initiate_broadcast_hosting_handshake (saga wiring deferred to commit 11.5 — see DEFERRED-commit-11-saga-use-cases.md)",
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
        let actor = ContextActor::new_skeleton("ctx-42".to_owned(), rx);
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
        let actor = ContextActor::new_skeleton("ctx-1".to_owned(), rx);
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
        let actor = ContextActor::new_skeleton("ctx-1".to_owned(), rx);
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
        let actor = ContextActor::new_skeleton("ctx-1".to_owned(), rx);
        let actor_handle = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        handle.send_shutdown().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), actor_handle)
            .await
            .expect("actor must exit promptly after Shutdown")
            .unwrap();
    }

    // -----------------------------------------------------------------
    // ADR-049 commit 12b.2a — state-carrying `ContextActor::new` tests
    // -----------------------------------------------------------------

    /// Minimal event log provider for the `ContextActor::new` test.
    /// Accepts every call, returns OK for every append, never appends
    /// anything to a real log — the 12b.2a dispatch does not exercise
    /// the event-log path, so the stub is never actually touched.
    struct TestEventLog;
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Minimal persistence stub for the `ContextActor::new` test.
    /// Returns empty reads and silently accepts every write.
    struct TestPersistence;
    impl crate::context::manager::ContextPersistence for TestPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::manager::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::manager::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _: &str,
            _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _: &str,
        ) -> Result<
            Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Assemble a supervisor-backed `ActorDeps` bundle for the
    /// `actor_with_state_acks_placeholder_with_not_implemented` test.
    /// Extracted so the test function stays below the `too_many_lines`
    /// clippy threshold.
    fn new_test_deps() -> deps::ActorDeps {
        use crate::context::supervisor::supervisor::{Supervisor, SupervisorConfig};
        use crate::context::supervisor::{ProtocolRepositorySagaJournal, SagaJournal};
        use scp_identity::DID;
        use scp_platform::testing::InMemoryStorage;
        use std::sync::Arc;

        let crypto: Box<dyn scp_protocol::context::builder::ContextCryptoProvider> =
            Box::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
                "did:dht:z6MktestActorNew".to_owned(),
            ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let manager = Arc::new(crate::context::manager::ContextManager::new(
            crypto,
            transport,
            event_log,
            Arc::new(|_| None),
        ));

        let persistence: Arc<dyn crate::context::manager::ContextPersistence> =
            Arc::new(TestPersistence);
        let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
            InMemoryStorage::new(),
        )));
        let supervisor = Arc::new(Supervisor::new(
            persistence.clone(),
            journal,
            SupervisorConfig::default(),
        ));
        supervisor.attach_context_manager(&manager).unwrap();

        let mls: Arc<dyn crate::crypto::mls::backend::MlsBackend> =
            Arc::new(crate::crypto::mls::production_backend::ProductionMlsBackend::new());
        let hpke: Arc<dyn crate::crypto::hpke_backend::HpkeBackend> =
            Arc::new(crate::crypto::hpke_backend::ProductionHpkeBackend::new());
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let kp_store = crate::context::supervisor::key_package_actor::KeyPackageStoreActor::spawn(
            DID("did:example:actor-with-state-test".to_owned()),
        );
        supervisor
            .build_actor_deps_from_attached(persistence, mls, hpke, mls_storage, kp_store)
            .expect("build_actor_deps_from_attached")
    }

    /// `ContextActor::new` constructs an actor that owns `PerContextState`
    /// + `ActorDeps` directly (12b.2a infrastructure path). The dispatch
    /// loop's behaviour is unchanged in 12b.2a (still ACKs
    /// `NotImplemented`); this test just asserts the struct is
    /// constructible and the run-loop processes commands.
    ///
    /// Integration-level coverage of the full
    /// `build_actor_deps_from_attached` path lives in
    /// `crates/scp-runtime/tests/actor_deps_complete.rs` +
    /// `spawn_actor_with_state` unit tests in
    /// `crates/scp-runtime/src/context/supervisor/supervisor.rs`; this
    /// unit test focuses on the actor struct's constructor + run-loop.
    #[tokio::test]
    async fn actor_with_state_acks_placeholder_with_not_implemented() {
        let deps = new_test_deps();
        let state = state::PerContextState::new_for_test_encrypted(
            [0x42u8; 32],
            1_700_000_000,
            scp_identity::DID("did:example:admin".to_owned()),
        );

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        // Skeleton dispatch still fires in 12b.2a — actor owns state
        // + deps, but the run loop has not yet been rewired to read
        // them. Assert the `NotImplemented` ACK proves the loop picks
        // up commands from the inbox.
        let err = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));

        handle.send_shutdown().await.unwrap();
        actor_task.await.unwrap();
    }
}
