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
//! - [`handlers`] — per-domain dispatch handlers. Each owns the real
//!   actor-shape dispatch for its domain, operating on the actor's owned
//!   state (`&mut ClassSCell`) and capability-reduced [`deps::ActorDeps`].

pub mod class_s;
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
    ContextLifecycleState, ContextModeState, ContextRouting, PendingBroadcastKeyRotation,
    PerContextState, RecvSequenceTracker, WelcomeProcessing, WrappingKeyPair,
};

/// Re-export of [`scp_protocol::context::ContextError`] for handler-side
/// use. `Outcome<T>` carries `Result<T, ContextError>`; handlers use this
/// re-export rather than a deep path.
pub use scp_protocol::context::ContextError;

// ---------------------------------------------------------------------------
// ContextActor — the per-context dispatch loop
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

/// Coalesced-persistence interval. ADR-049 §Decision 9 (50 ms): a
/// burst of mutations that all complete within this window collapse to
/// a single durable snapshot write. The actor's `run()` loop wakes on
/// this interval iff `dirty == true` and writes the latest snapshot.
const COALESCE_INTERVAL: Duration = Duration::from_millis(50);

/// Encode a 32-byte context ID as lowercase hex. Matches the string
/// form used throughout the supervisor-side dispatch shim
/// (`Supervisor::dispatch_*_command`) so the actor's `context_id`
/// field is interchangeable with the shim's `ctx_id: &str` argument.
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
/// See plan §"ContextActor" for the full shape. The `run()` loop
/// dispatches state-bearing commands through `dispatch_state` to the
/// real per-domain handlers. Some run-loop arms remain no-ops pending
/// the Phase 2 finalization sub-chunks that retire the supervisor-side
/// timer/persistence paths — TTL expiry and governance timeouts are
/// driven by the supervisor's timer `task_set`, and persistence flows
/// through the per-handler persistence helpers, until those paths
/// migrate onto the actor's owned state.
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
    /// [`Self::new`] with a full state payload — the production path:
    /// every production spawn
    /// ([`crate::context::supervisor::supervisor::Supervisor::spawn_actor_with_state`])
    /// carries `Some(state)`. `None` only for skeleton actors
    /// constructed via the test-only [`Self::new_skeleton`].
    ///
    /// State-owning actors consume the state on every command: the
    /// run-loop's `dispatch` threads it as `&mut ClassSCell` through
    /// `dispatch_state` into the real per-domain handler. Only
    /// skeleton actors (state = `None`) fall through to
    /// `skeleton_dispatch`, the sole surviving `NotImplemented`
    /// producer.
    ///
    /// Two-mode is bounded: this field becomes non-`Option` when the
    /// test-only skeleton apparatus is retired in a follow-on chunk.
    // read by the run-loop's dispatch/dispatch_state path
    state: Option<class_s::ClassSCell>,
    /// Owned dependency bundle. `Some` / `None` mirrors [`Self::state`]
    /// — the two are always both `Some` or both `None`. Two-mode is
    /// bounded identically.
    // read by the run-loop's dispatch/dispatch_state path
    deps: Option<deps::ActorDeps>,
    /// TTL expiry interval timer. `None` until the supervisor-side TTL
    /// timer path (`task_set`-spawned timers that mailbox
    /// `TtlCloseCommand::FireTimer`) migrates onto the run-loop's
    /// `select!` TTL arm in a follow-on Phase 2 sub-chunk; the arm and
    /// its no-op `on_ttl_tick` body exist so that migration is purely
    /// additive.
    // read by the run-loop's TTL select! arm
    ttl_timer: Option<tokio::time::Interval>,
    /// Governance proposal timeout deadline. `None` until the
    /// supervisor-side governance timeout path migrates onto the
    /// run-loop's `select!` arm in a follow-on Phase 2 sub-chunk (the
    /// arm and its no-op `on_governance_timeout` body exist so that
    /// migration is purely additive).
    ///
    /// Note — `tokio::time::Sleep` is `!Unpin` so the field holds a
    /// pinned box. Constructing the future upfront (even unused)
    /// keeps the run-loop's `select!` arm shape stable as the
    /// migration lands.
    // read by the run-loop's governance select! arm
    governance_timeout: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    /// Unix-ms instant of the last successful coalesced persist. The
    /// run-loop's persistence arm compares `now() - last_persisted_at`
    /// against the coalescing window (250 ms per plan
    /// §"Persistence coalescing") before issuing a snapshot write.
    /// Initialized to "now" at actor construction.
    // read by the run-loop's persistence coalesce arm
    last_persisted_at: std::time::Instant,
    /// Dirty flag set when any handler's [`outcome::Outcome`] carries
    /// `mutated: true`. Cleared after a successful coalesced persist.
    /// Initialized `false` at actor construction.
    // read by the run-loop's persistence coalesce arm
    dirty: bool,
    /// Full-supervisor pointer captured at construction. Today its
    /// only read is the `dispatch` pre-check that partitions
    /// state-owning actors from skeleton actors — handler bodies reach
    /// the supervisor through the capability-reduced
    /// [`deps::ActorDeps::supervisor`] handle instead. Removed when
    /// the test-only skeleton apparatus is retired in a follow-on
    /// chunk.
    ///
    /// Sourced from [`deps::ActorDeps::supervisor`] via
    /// [`crate::context::supervisor::SupervisorHandle::shim_supervisor`]
    /// at actor construction time. `None` for skeleton-mode actors
    /// constructed via [`Self::new_skeleton`] (those route through
    /// the actor's terminal-NotImplemented fallback because they have
    /// no state/deps to operate on).
    shim_supervisor: Option<Arc<crate::context::supervisor::Supervisor>>,
}

impl ContextActor {
    /// Construct a fresh actor that owns [`PerContextState`] and
    /// [`ActorDeps`] directly (introduced by ADR-049 commit 12b.2a).
    ///
    /// This is the production constructor. The owned-state spawn path
    /// [`crate::context::supervisor::supervisor::Supervisor::spawn_actor_with_state`]
    /// uses it to hand drained `PerContextState` + `ActorDeps` into the
    /// actor task, making the actor their sole owner.
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
    /// matches the string form used throughout the supervisor-side
    /// dispatch shim. Callers therefore do not need to pass `context_id`
    /// separately — it is sourced from the state payload.
    #[allow(dead_code)] // production caller: Supervisor::spawn_actor_with_state
    pub(in crate::context) fn new(
        state: state::PerContextState,
        deps: deps::ActorDeps,
        inbox: mpsc::Receiver<ContextCommand>,
    ) -> Self {
        let context_id = hex_encode_context_id(&state.context_id);
        // Capture the shim-supervisor pointer before moving `deps` into
        // the actor: `dispatch` reads its presence to partition
        // state-owning actors from skeleton actors.
        let shim_supervisor = Some(deps.supervisor.shim_supervisor());
        Self {
            context_id,
            inbox,
            // Wrap the owned state in the Class-S fail-closed-persist cell. The
            // cell hands out no whole `&mut PerContextState` (no `DerefMut`, no
            // `state_mut`); every handler mutates through the cell's persist-on-
            // commit combinators or the airtight `class_c_view()` (ADR-049 §9).
            state: Some(class_s::ClassSCell::new(state)),
            deps: Some(deps),
            ttl_timer: None,
            governance_timeout: None,
            last_persisted_at: Instant::now(),
            dirty: false,
            shim_supervisor,
        }
    }

    /// Construct a skeleton actor without state or deps. Used by the
    /// module's unit-test fixtures and by the dead-code / test-only
    /// [`crate::context::supervisor::supervisor::Supervisor::spawn_actor`]
    /// path. No production context uses the skeleton — production spawns
    /// state-owning actors via [`Self::new`].
    ///
    /// The skeleton's `run()` loop drains commands from the inbox and
    /// ACKs each with `Err(NotImplemented)` via `skeleton_dispatch` —
    /// the sole surviving `NotImplemented` producer, since a skeleton
    /// actor carries no state for the real handlers to operate on.
    ///
    /// Visibility matches [`Self::new`]: `pub(in crate::context)`.
    ///
    /// `dead_code` allow: no production caller. Production spawns
    /// state-owning actors via [`Self::new`]; this skeleton constructor
    /// is exercised only by the module's existing unit tests, pending
    /// removal of the skeleton apparatus in a follow-on chunk.
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
            // carrying a magic-value sentinel. State-owning actors
            // populate this field identically via [`Self::new`].
            last_persisted_at: Instant::now(),
            dirty: false,
            shim_supervisor: None,
        }
    }

    /// Dispatch loop. See plan §"ContextActor" — the operational
    /// four-arm `tokio::select!`:
    ///
    /// 1. **Inbox** — `mpsc::Receiver::recv` for [`ContextCommand`]s.
    ///    Shutdown commands dispatch and then break the loop.
    /// 2. **TTL timer** — only when `ttl_timer.is_some()`.
    /// 3. **Governance timeout** — only when `governance_timeout.is_some()`.
    /// 4. **Persistence coalesce** — only when `dirty == true`.
    ///
    /// `biased;` ordering keeps shutdown priority and gives deterministic
    /// dispatch under test reproducers.
    ///
    /// # State-owning vs. skeleton-mode actors
    ///
    /// State-owning actors (constructed via [`Self::new`] — the
    /// production shape) carry both `state` and `deps`. The dispatch
    /// routes each command through `dispatch_state` into the matching
    /// handler module's actor-shape `dispatch` entry point, which
    /// operates on the actor-owned state cell and the
    /// capability-reduced deps.
    ///
    /// Skeleton-mode actors (constructed via the test-only
    /// [`Self::new_skeleton`]) carry no state or deps — they fall
    /// through to the synchronous `skeleton_dispatch` path that ACKs
    /// every command with `NotImplemented`. This preserves the
    /// pre-Phase-2A test fixtures' behaviour; no production spawn uses
    /// it.
    pub async fn run(mut self) {
        // Kick the persistence coalesce timer off the floor: the first
        // mutation will set `dirty = true`, then the `select!` arm
        // computes the deadline as `last_persisted_at + COALESCE_INTERVAL`
        // — which is in the future relative to actor-spawn `now()`.
        loop {
            tokio::select! {
                biased;

                // --- Arm 1: inbox ----------------------------------
                maybe_cmd = self.inbox.recv() => {
                    match maybe_cmd {
                        Some(cmd) => {
                            // Shutdown is unconditionally terminal: the
                            // actor always exits after dispatch.
                            let is_shutdown = matches!(
                                cmd,
                                ContextCommand::LifecycleControl(
                                    LifecycleControlCommand::Shutdown { .. }
                                )
                            );
                            // PrepareForReplace is terminal ONLY when it
                            // succeeds (makes way for an imported context).
                            // On reject — a live context (the import
                            // security invariant), an already-claimed slot,
                            // or a crypto failure — the context is still
                            // live, so the actor must keep running. The
                            // handler signals success by transitioning its
                            // own `lifecycle_state` to `Closed`; we honor
                            // that AFTER dispatch rather than breaking by
                            // command variant.
                            let is_prepare_replace = matches!(
                                cmd,
                                ContextCommand::LifecycleControl(
                                    LifecycleControlCommand::PrepareForReplace { .. }
                                )
                            );
                            self.dispatch(cmd).await;
                            if is_shutdown {
                                break;
                            }
                            if is_prepare_replace {
                                // Claimed terminal iff the handler set
                                // `lifecycle_state == Closed`. A skeleton
                                // actor (no owned state) trivially succeeds.
                                let claimed = self.state.as_ref().is_none_or(|s| {
                                    matches!(
                                        s.lifecycle_state,
                                        state::ContextLifecycleState::Closed
                                    )
                                });
                                if claimed {
                                    break;
                                }
                            }
                        }
                        // Inbox closed — every sender dropped. Exit
                        // gracefully (a final coalesced persist runs
                        // below in the post-loop drain).
                        None => break,
                    }
                }

                // --- Arm 2: TTL timer ------------------------------
                () = async {
                    match self.ttl_timer.as_mut() {
                        Some(timer) => {
                            let _ = timer.tick().await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                }, if self.ttl_timer.is_some() => {
                    self.on_ttl_tick().await;
                }

                // --- Arm 3: governance timeout ---------------------
                () = async {
                    match self.governance_timeout.as_mut() {
                        Some(pinned) => pinned.as_mut().await,
                        None => std::future::pending::<()>().await,
                    }
                }, if self.governance_timeout.is_some() => {
                    self.on_governance_timeout().await;
                    self.governance_timeout = None;
                }

                // --- Arm 4: persistence coalesce -------------------
                () = tokio::time::sleep_until(
                    tokio::time::Instant::from_std(
                        self.last_persisted_at + COALESCE_INTERVAL
                    )
                ), if self.dirty => {
                    self.persist_snapshot().await;
                    self.last_persisted_at = Instant::now();
                    self.dirty = false;
                }
            }
        }
        // Final drain: write any pending state before the actor exits
        // so callers observing the shutdown ack can rely on durability.
        if self.dirty {
            self.persist_snapshot().await;
        }
    }

    /// Dispatch a single command to its matching handler: takes the
    /// actor-owned state/deps and threads them through
    /// `dispatch_state` into the per-domain actor-shape `dispatch`
    /// entry points.
    ///
    /// Skeleton-mode actors (no state/deps) fall through to
    /// `skeleton_dispatch` and ACK every variant with
    /// `NotImplemented`.
    async fn dispatch(&mut self, cmd: ContextCommand) {
        // Skeleton path: no state, no deps. Fall through to the
        // synchronous ACK helper that replies `NotImplemented` to every
        // variant. Used by the pre-Phase-2A test fixtures.
        if self.state.is_none() || self.deps.is_none() || self.shim_supervisor.is_none() {
            Self::skeleton_dispatch(cmd);
            return;
        }

        // Take the state/deps out so we can pass them as exclusive
        // borrows without re-borrow conflicts. The pre-check above
        // partitions skeleton actors from state-bearing actors; any
        // missing field after that point is an internal invariant
        // violation and should fail loudly, not degrade to skeleton
        // dispatch. The `shim_supervisor` field is not consumed here —
        // its presence was checked above, and every handler reaches
        // the supervisor through `deps.supervisor` (the
        // capability-reduced
        // [`SupervisorHandle`](crate::context::supervisor::SupervisorHandle)).
        let (mut cell, deps) = {
            #[allow(clippy::expect_used)]
            (
                self.state.take().expect("state-bearing actor lost state"),
                self.deps.take().expect("state-bearing actor lost deps"),
            )
        };

        // `dispatch_state` receives the `&mut ClassSCell` directly and threads
        // it into every domain handler. Every domain mutates through the cell's
        // combinators — the fail-closed `commit_class_s_*` / `ClassSCommitToken`
        // for Class-S transitions, and the airtight `class_c_view()` /
        // `commit_class_c_best_effort` for Class-C / structural state. There is
        // no `state_mut()` escape hatch (deleted), and the broadcast member-
        // removal in `unsubscribe_broadcast` routes through the restricted
        // `MembershipClassCMut::remove_subscriber` (a public-content subscriber
        // unsubscribe is best-effort-acceptable; see its doc, ADR-049 §9).
        let outcome = Self::dispatch_state(&mut cell, &deps, cmd).await;
        if outcome.mutated {
            self.dirty = true;
        }

        // Restore.
        self.state = Some(cell);
        self.deps = Some(deps);
    }

    /// State-owning dispatch. Routes each `ContextCommand` variant to
    /// the matching handler's entry point. Every Phase 2A handler reaches
    /// any required cross-actor state through
    /// [`deps::ActorDeps::supervisor`] (the capability-reduced
    /// [`SupervisorHandle`](crate::context::supervisor::SupervisorHandle))
    /// rather than through a separate `&Supervisor` parameter — the
    /// final `&Supervisor` consumer (the queries shim path) was removed
    /// in Phase 2A.10 when the queries domain migrated to the actor-shape
    /// handler.
    ///
    /// Returns the handler's [`Outcome`]; the run-loop reads
    /// `outcome.mutated` to decide whether to set `self.dirty`.
    async fn dispatch_state(
        cell: &mut class_s::ClassSCell,
        deps: &deps::ActorDeps,
        cmd: ContextCommand,
    ) -> Outcome<()> {
        match cmd {
            ContextCommand::Messaging(sub) => {
                // Phase 2A.7 — messaging domain migrated to the
                // actor-shape handler. `Supervisor::dispatch_command`
                // is mailbox-only: a missing actor surfaces a typed
                // lookup-miss error. The send-sequence tracker
                // (`state.send_tracker`) is reserved internally inside
                // the handler.
                handlers::messaging::dispatch(cell, deps, sub).await
            }
            ContextCommand::Lifecycle(sub) => {
                // Phase 2A.9 — lifecycle domain migrated to actor-shape
                // for per-context commands (`JoinContext`,
                // `LeaveContext`, `CloseContext`, `ExportContext`) and
                // access-key commands (actor-shape helpers in
                // queries_helpers). Bootstrap commands (`CreateContext`,
                // `RestoreContext`, `ImportContext`) construct fresh
                // state and are handled supervisor-side by
                // `Supervisor::dispatch_lifecycle_direct` before any
                // actor exists; reaching this arm with one (an actor
                // already registered — a re-create attempt) surfaces a
                // typed `InvalidState` inside the handler.
                Box::pin(handlers::lifecycle::dispatch(cell, deps, sub)).await
            }
            ContextCommand::Governance(sub) => {
                // Phase 2A.8 — governance domain fully migrated to
                // actor-shape: every variant reads/mutates
                // `state.governance` through the actor-shape helpers.
                // `Supervisor::dispatch_governance_command` is
                // mailbox-only (typed `ContextNotRegistered` when no
                // actor is registered).
                Box::pin(handlers::governance::dispatch(cell, deps, sub)).await
            }
            ContextCommand::Broadcast(sub) => {
                // Phase 2A.5 — broadcast domain migrated to the
                // actor-shape handler for non-publish commands.
                // Publish variants still require the custody-generic
                // supervisor shim because `KeyCustody` is not dyn-safe.
                Box::pin(handlers::broadcast::dispatch(cell, deps, sub)).await
            }
            ContextCommand::Economy(sub) => {
                // Phase 2A.3 — economy domain migrated to the
                // actor-shape handler. Supervisor dispatch falls
                // through to its supervisor-side
                // `dispatch_economy_direct` when a receipt batch has
                // no single owning context actor.
                handlers::economy::dispatch(cell, deps, sub).await
            }
            ContextCommand::TrustRecovery(sub) => {
                // Phase 2A.1 — trust_recovery domain migrated to
                // state-owning shape. Per-context variants flow through
                // `handlers::trust_recovery::dispatch(state, deps, sub)`;
                // the cross-context `RecoveryNotifyContact` variant is
                // intercepted on the supervisor before this arm
                // executes (it never reaches the per-context actor
                // mailbox).
                Box::pin(handlers::trust_recovery::dispatch(cell, deps, sub)).await
            }
            ContextCommand::Standing(sub) => {
                // Phase 2A.2 — standing domain migrated to the
                // actor-shape handler. Supervisor-scoped variants (and
                // commands with no registered target actor) route
                // through the supervisor-side
                // `dispatch_standing_direct` instead of this arm.
                Box::pin(handlers::standing::dispatch(deps, sub)).await
            }
            ContextCommand::TtlClose(sub) => {
                // Phase 2A.6 — TTL-close domain migrated to the
                // actor-shape handler.
                // `Supervisor::dispatch_ttl_close_command` is
                // mailbox-only: a missing actor surfaces a typed
                // lookup-miss error.
                handlers::ttl_close::dispatch(cell, deps, sub).await
            }
            ContextCommand::Tools(sub) => {
                // Phase 2A.4 -- tools domain migrated to the
                // actor-shape handler for mailbox-routed hard-rate
                // helpers. `Supervisor::dispatch_tools_command` is
                // mailbox-first: a missing actor surfaces a typed
                // error on the command's reply oneshot.
                handlers::tools::dispatch(cell, deps, sub).await
            }
            // Phase 2A.10 — queries domain migrated to the actor-shape
            // handler. The actor's owned `state` + `deps.event_log` +
            // `deps.local_dids` are sufficient for every read variant;
            // no supervisor shim is needed on the actor path. The
            // supervisor's `dispatch_query` continues to route callers
            // through this mailbox when an actor is registered, and
            // surfaces the variant's legacy unknown-context default via
            // [`Supervisor::dispatch_queries_direct`] when no actor
            // exists (the prior locked-DashMap shim was deleted in the
            // Phase 2A finalization queries+lifecycle session).
            ContextCommand::Queries(sub) => handlers::queries::dispatch(cell, deps, sub).await,
            // SagaPhase + LifecycleControl already migrated to the
            // state-owning signature.
            ContextCommand::SagaPhase(msg) => handlers::saga::dispatch(cell, deps, msg).await,
            // Test-only fault injection (ADR-049 §10 watchdog tests). The
            // `panic!` lives here in `actor/mod.rs` — deliberately NOT in
            // any `handlers/*.rs` module — so the production handler
            // panic-ban gate (`scripts/check-handler-no-panic.sh`) stays
            // green while still letting the watchdog crash/poison/respawn
            // and payload-redaction paths be exercised deterministically.
            // Gated behind the `testing` feature so it cannot exist in a
            // production build.
            #[cfg(feature = "testing")]
            ContextCommand::LifecycleControl(LifecycleControlCommand::TestInducePanic {
                sentinel,
            }) => {
                #[allow(clippy::panic)]
                {
                    panic!("{sentinel}");
                }
            }
            ContextCommand::LifecycleControl(sub) => {
                handlers::lifecycle_control::dispatch(cell, deps, sub).await
            }
        }
    }

    /// Drive the TTL-timer arm. Phase 2A leaves the body empty: TTL
    /// expiry is driven by the supervisor's timer `task_set`, which
    /// spawns a per-context TTL timer that mailboxes
    /// `TtlCloseCommand::FireTimer` to this actor — until a future
    /// Phase 2 sub-chunk moves the timer onto the actor's own
    /// `ttl_timer` arm. The arm exists here so that migration is purely
    /// additive.
    ///
    /// `_state`/`_deps` allow: future migrations read them; for now the
    /// method is a no-op.
    #[allow(clippy::unused_async, clippy::needless_pass_by_ref_mut)]
    async fn on_ttl_tick(&mut self) {
        // No-op until the TTL handler migrates to the actor's owned
        // state in a follow-on Phase 2 sub-chunk.
    }

    /// Drive the governance-timeout arm. Same migration shape as
    /// `on_ttl_tick`: the legacy supervisor still drives governance
    /// timeouts; the arm here is a no-op until the migration lands.
    #[allow(clippy::unused_async, clippy::needless_pass_by_ref_mut)]
    async fn on_governance_timeout(&mut self) {
        // No-op until the governance timeout handler migrates to the
        // actor's owned state in a follow-on Phase 2 sub-chunk.
    }

    /// Persistence coalesce arm. Phase 2A no-op: durable writes still
    /// flow through the per-handler persistence helpers, so this arm
    /// only clears the `dirty` flag (see body).
    #[allow(clippy::unused_async, clippy::needless_pass_by_ref_mut)]
    async fn persist_snapshot(&mut self) {
        // The state-owning persist path is wired in a follow-on Phase 2
        // sub-chunk together with the snapshot-shape contract on
        // `PerContextState`. For Phase 2A the run loop's coalesce arm
        // simply clears `dirty` so the loop does not spin; durable
        // writes flow through the per-handler persistence helpers
        // (writing to the injected `ContextPersistence` provider
        // synchronously within each handler) until the migration
        // completes.
    }

    /// Skeleton dispatch — the test-only path for state-less skeleton
    /// actors. Matches every variant and ACKs via the embedded
    /// `oneshot::Sender`. The real, state-owning actor does not use this:
    /// its `run()` loop routes commands through `dispatch_state` to the
    /// per-domain handlers described in plan §"ContextActor".
    ///
    /// The function body is a flat `match` on the outer
    /// [`ContextCommand`] variants. Each arm replies `NotImplemented` and
    /// returns `Outcome::err`, since a skeleton actor carries no
    /// `&mut PerContextState` for the real handlers to operate on.
    /// Discarding the `Outcome` is fine for the skeleton — only the real
    /// `dispatch_state` path reads the `Outcome::mutated` flag to flip
    /// `self.dirty`.
    ///
    /// Lifecycle-control commands use a dedicated fast path that acks
    /// with `Ok(())` so the bridge's `BridgeInstanceCore::suspend()`
    /// default body can complete its pause/persist/shutdown sequence
    /// without each actor returning `NotImplemented` on the control
    /// channel (see `handlers/lifecycle_control.rs`).
    #[allow(clippy::needless_pass_by_value)] // consumed by the dispatch
    fn skeleton_dispatch(cmd: ContextCommand) {
        // Route every variant to its matching handler's oneshot-ack so
        // callers learn the outcome even though a skeleton actor owns no
        // state (commands for such contexts are handled by the
        // supervisor-side dispatch shim, not the actor). We MUST route
        // the oneshot sender out of the variant — synchronously, in
        // this function — because the real handler modules take a
        // `&mut PerContextState` which the skeleton actor does not
        // carry. Reproducing the ack shape inline keeps the
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
            ContextCommand::Messaging(sub) => Self::skeleton_dispatch_messaging(sub),
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
            // and resolves the query on the supervisor side under the
            // query shim. The skeleton only sees query commands if a caller
            // mistakenly routes through the actor's mailbox — the real
            // FFI dispatch goes through `Supervisor::dispatch_query`.
            ContextCommand::Queries(q) => Self::skeleton_dispatch_queries(q),
            // The skeleton actor owns no state, so every saga-phase variant
            // acks its typed oneshot with `Err(NotImplemented)` — the real
            // Prepare-A/Prepare-B bodies run only on a stateful actor via
            // `dispatch_state` → `handlers::saga::dispatch`. PrepareA replies a
            // `PrepareAOutcome` and PrepareB a `PrepareBOutcome` (each carrying a
            // §6.2.4 policy reject on the SUCCESS channel as a `SagaReject`); the
            // skeleton routes them through the unchanged `Err(ContextError)`
            // channel, so each phase arm acks separately.
            ContextCommand::SagaPhase(SagaPhaseMessage::PrepareA { reply, .. }) => {
                ack_not_impl(reply, "saga_phase");
            }
            ContextCommand::SagaPhase(SagaPhaseMessage::PrepareB { reply, .. }) => {
                ack_not_impl(reply, "saga_phase");
            }
            // CommitBReserve / CommitBSettle reply distinct outcome shapes, so
            // they are acked separately from the unit-reply phase arms.
            ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve { reply, .. }) => {
                ack_not_impl(reply, "saga_phase");
            }
            ContextCommand::SagaPhase(SagaPhaseMessage::CommitBSettle { reply, .. }) => {
                ack_not_impl(reply, "saga_phase");
            }
            // CommitACheckWitness replies a distinct `bool` outcome shape, so it
            // is acked separately from the unit-reply phase arms.
            ContextCommand::SagaPhase(SagaPhaseMessage::CommitACheckWitness { reply, .. }) => {
                ack_not_impl(reply, "saga_phase");
            }
            ContextCommand::SagaPhase(
                SagaPhaseMessage::CommitA { reply, .. }
                | SagaPhaseMessage::Abort { reply, .. }
                | SagaPhaseMessage::EmitDivergenceMarker { reply, .. },
            ) => {
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
                // Ack Ok — a skeleton actor owns no state, so there is
                // nothing to persist. Semantically equivalent to
                // "flush buffer is empty, nothing to write".
                ack_ok(reply);
            }
            ContextCommand::LifecycleControl(LifecycleControlCommand::Shutdown { reply }) => {
                // Ack Ok and let the outer `run()` loop exit after this
                // dispatch returns (the caller detected `is_terminal`
                // before invoking us).
                ack_ok(reply);
            }
            ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                reply,
                ..
            }) => {
                // Defensive: import only ever sends PrepareForReplace to
                // a looked-up real (stateful) actor, never a skeleton. A
                // skeleton owns no crypto/state, so teardown is a no-op
                // success; ack Ok and let `run()` exit (`is_terminal`).
                ack_ok(reply);
            }
            // The test-only fault-injection variant carries no reply and is
            // only meaningful for a state-bearing actor (the watchdog tests
            // spawn one). A skeleton actor owns no state — make it a no-op.
            #[cfg(feature = "testing")]
            ContextCommand::LifecycleControl(LifecycleControlCommand::TestInducePanic {
                ..
            }) => {}
        }
    }

    /// Skeleton-dispatch helper for [`ContextCommand::Messaging`].
    /// Extracted from [`Self::skeleton_dispatch`] so the outer function
    /// stays below the `too_many_lines` clippy threshold (mirrors the
    /// per-domain `skeleton_dispatch_*` helpers). Each arm acks the
    /// variant's embedded oneshot with `Err(NotImplemented)`: the real
    /// messaging path runs through `Supervisor::dispatch_command` /
    /// `Supervisor::drain_*`, not the actor's skeleton mailbox.
    fn skeleton_dispatch_messaging(sub: MessagingCommand) {
        fn ack_not_impl<T>(
            reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
            which: &'static str,
        ) {
            let _ = reply.send(Err(ContextError::NotImplemented(format!(
                "{which} — migrates in the matching handler commit of ADR-049"
            ))));
        }
        match sub {
            MessagingCommand::SendMessage { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::send_message (use Supervisor::dispatch_command)",
                );
            }
            MessagingCommand::DeliverIncoming { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::deliver_incoming (use Supervisor::dispatch_command)",
                );
            }
            MessagingCommand::DrainEvents { reply, .. }
            | MessagingCommand::DrainEquivocationAlerts { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::drain_* (use Supervisor::drain_events / drain_equivocation_alerts)",
                );
            }
            MessagingCommand::SendPseudonymAnnouncement { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::send_pseudonym_announcement (use Supervisor::dispatch_command)",
                );
            }
            MessagingCommand::ReportDegradedMode { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::report_degraded_mode (use Supervisor::dispatch_command)",
                );
            }
            MessagingCommand::BuildLocalCheckpoint { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::build_local_checkpoint (use Supervisor — actor mailbox)",
                );
            }
            MessagingCommand::CompareRemoteCheckpoint { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::compare_remote_checkpoint (use Supervisor — actor mailbox)",
                );
            }
            MessagingCommand::SendHeartbeat { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::send_heartbeat (use Supervisor::send_heartbeat — actor mailbox)",
                );
            }
            #[cfg(feature = "testing")]
            MessagingCommand::SeedPeerPseudonym { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::seed_peer_pseudonym (test-only — use Supervisor::dispatch_command)",
                );
            }
            #[cfg(feature = "testing")]
            MessagingCommand::TestInsertMember { reply, .. } => {
                ack_not_impl(
                    reply,
                    "messaging::test_insert_member (test-only — use Supervisor::dispatch_command)",
                );
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
            QueriesCommand::ReadContextState { reply, .. } => {
                ack_not_impl(reply, "queries::read_context_state");
            }
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
            QueriesCommand::HasEstablishedToolInterface { reply, .. } => {
                ack_not_impl(reply, "queries::has_established_tool_interface");
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
            QueriesCommand::LocalMlsEpoch { reply, .. } => {
                ack_not_impl(reply, "queries::local_mls_epoch");
            }
            QueriesCommand::NeedsReconnect { reply, .. } => {
                ack_not_impl(reply, "queries::needs_reconnect");
            }
            QueriesCommand::PaymentHistory { reply, .. } => {
                ack_not_impl(reply, "queries::payment_history");
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
            LifecycleCommand::RestoreContext { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::restore_context (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::GenerateContextAccessKey { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::generate_context_access_key (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::RevokeContextAccessKey { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::revoke_context_access_key (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            LifecycleCommand::RestoreContextAccessKey { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::restore_context_access_key (use Supervisor::dispatch_lifecycle_command during commits 9-11)",
            ),
            // Sweep variants — the skeleton dispatch is the legacy
            // mailbox-test stub; real sweep dispatch goes via
            // `handlers::lifecycle::dispatch` against an actor's owned
            // `&mut state`. The skeleton path returns NotImplemented so
            // a misrouted sweep surfaces a typed error rather than
            // silently completing.
            LifecycleCommand::FlushSnapshot { reply } => ack_not_impl(
                reply,
                "lifecycle::flush_snapshot (sweep — use lifecycle_helpers::flush_all_contexts iterator)",
            ),
            LifecycleCommand::ShutdownSelf { reply } => ack_not_impl(
                reply,
                "lifecycle::shutdown_self (sweep — use lifecycle_helpers::shutdown_all_contexts iterator)",
            ),
            // Read-only gauge sweep: a skeleton actor owns no
            // receive-buffer state, so report 0. The reply channel
            // carries a bare `usize` (not a `Result`), so it cannot use
            // `ack_not_impl`.
            LifecycleCommand::ReportBufferLen { reply } => {
                let _ = reply.send(0);
            }
            LifecycleCommand::ClearNeedsReconnect { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::clear_needs_reconnect (use Supervisor::clear_needs_reconnect — actor mailbox)",
            ),
            LifecycleCommand::IssueMlsUpdate { reply, .. } => ack_not_impl(
                reply,
                "lifecycle::issue_mls_update (use Supervisor::issue_mls_update — actor mailbox)",
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
            // Sweep variants — the skeleton dispatch is the legacy
            // mailbox-test stub; real sweep dispatch goes via
            // `handlers::governance::dispatch` against an actor's owned
            // `&mut state`. The skeleton path returns NotImplemented so
            // a misrouted sweep surfaces a typed error rather than
            // silently completing.
            GovernanceCommand::EvaluatePeriodicConsequences { reply } => ack_not_impl(
                reply,
                "governance::evaluate_periodic_consequences (sweep — use governance_helpers::evaluate_periodic_consequences iterator)",
            ),
            GovernanceCommand::ProcessPendingCommits { reply } => ack_not_impl(
                reply,
                "governance::process_pending_commits (sweep — use governance_helpers::process_pending_commits iterator)",
            ),
            GovernanceCommand::EvaluateTimeouts { reply } => ack_not_impl(
                reply,
                "governance::evaluate_timeouts (sweep — use governance_helpers::start_governance_timeout_task iterator)",
            ),
            GovernanceCommand::StartTimeoutTask { reply } => ack_not_impl(
                reply,
                "governance::start_timeout_task (timer install — use governance_helpers::start_governance_timeout_task)",
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
        match sub {
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
            TtlCloseCommand::FireTimer { reply } => ack_not_impl(
                reply,
                "ttl_close::fire_timer (use Supervisor::dispatch_ttl_close_command)",
            ),
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
            ToolsCommand::TryConsumeHardRateLimit { reply, .. } => ack_not_impl(
                reply,
                "tools::try_consume_hard_rate_limit (use Supervisor::dispatch_tools_command during commit 11)",
            ),
            ToolsCommand::RefundHardRateLimit { reply, .. } => ack_not_impl(
                reply,
                "tools::refund_hard_rate_limit (use Supervisor::dispatch_tools_command during commit 11)",
            ),
            ToolsCommand::ReserveToolEconomy { reply, .. } => ack_not_impl(
                reply,
                "tools::reserve_tool_economy (use Supervisor::invoke_tool_with_economy / dispatch_tools_command)",
            ),
            ToolsCommand::SettleToolEconomy { reply, .. } => ack_not_impl(
                reply,
                "tools::settle_tool_economy (use Supervisor::invoke_tool_with_economy / dispatch_tools_command)",
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
            BroadcastCommand::ReserveBroadcastPublish { reply, .. } => ack_not_impl(
                reply,
                "broadcast::reserve_broadcast_publish (use Supervisor::dispatch_broadcast_command_with_custody)",
            ),
            BroadcastCommand::ApplyBroadcastPublish { reply, .. } => ack_not_impl(
                reply,
                "broadcast::apply_broadcast_publish (use Supervisor::dispatch_broadcast_command_with_custody)",
            ),
            BroadcastCommand::ReleaseBroadcastReservation { reply, .. } => ack_not_impl(
                reply,
                "broadcast::release_broadcast_reservation (use Supervisor::dispatch_broadcast_command_with_custody)",
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
    async fn skeleton_actor_acks_query_with_not_implemented() {
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new_skeleton("ctx-42".to_owned(), rx);
        let actor_handle = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        // A skeleton actor owns no state, so every command — including a
        // read-only query — acks `NotImplemented` through the synchronous
        // skeleton-dispatch path.
        let err = handle
            .send(|reply| {
                ContextCommand::Queries(QueriesCommand::MemberCount {
                    context_id: "ctx-42".to_owned(),
                    reply,
                })
            })
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
            .send(|reply| {
                ContextCommand::Queries(QueriesCommand::MemberCount {
                    context_id: "ctx-1".to_owned(),
                    reply,
                })
            })
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
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
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
    impl crate::context::persistence::ContextPersistence for TestPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
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

    /// Assemble a supervisor-backed `ActorDeps` bundle shared by the
    /// state-bearing actor tests (the four `direct_*` announcement tests
    /// and `actor_with_state_answers_read_query`). Extracted so each test
    /// function stays below the `too_many_lines` clippy threshold.
    async fn new_test_deps() -> deps::ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_identity::DID;
        use scp_platform::testing::InMemoryStorage;
        use std::sync::Arc;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestActorNew".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_: &scp_identity::DID, _: scp_protocol::identity::SigningKeyId| None);
        let persistence: Box<dyn crate::context::persistence::ContextPersistence> =
            Box::new(TestPersistence);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );

        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(persistence),
            None,
            None,
            None,
            mls_storage,
        );

        // `build_actor_deps` self-sources crypto/transport/event_log/clock/
        // key_resolver/mls_storage/persistence from the supervisor and the
        // MLS/HPKE backends transitively through `crypto`; only the owning
        // DID is supplied (resolves this identity's KeyPackageStoreActor).
        supervisor
            .build_actor_deps(&DID("did:example:actor-with-state-test".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    // -----------------------------------------------------------------------
    // §9.10.4 direct-ingest-site behavioral tests.
    //
    // `deliver_message_and_drain_buffered` is the IN-ORDER ingest entry point.
    // It delegates the four-step pseudonym-announcement validation to the shared
    // `ingest_pseudonym_announcement` core (the same boundary the buffered site
    // uses) and maps the outcome to its OWN convention: `Recorded` → `Ok(true)`
    // (after advancing the sequence tracker + draining the reorder buffer),
    // `Rejected` → `Err(PermissionDenied)`. These tests drive a real
    // `PseudonymAnnouncement` through that function against a real
    // `PerContextState` + `ActorDeps`, asserting both the registry state and the
    // direct-site return convention.
    // -----------------------------------------------------------------------

    const DIRECT_ALICE: &str = "did:dht:z6MkAliceDirect";
    const DIRECT_BOB: &str = "did:dht:z6MkBobDirect";

    /// Build an encrypted test state where `member` is a writable context
    /// member (so the direct ingest path's membership + capability gates pass)
    /// and the handle is `Active` (so `require_active` passes).
    async fn writable_encrypted_state(ctx_byte: u8, member: &str) -> state::PerContextState {
        use scp_protocol::context::roles::Capability;
        use std::collections::HashSet;

        let st = state::PerContextState::new_for_test_encrypted(
            [ctx_byte; 32],
            1_700_000_000,
            scp_identity::DID(member.to_owned()),
        );
        // The in-order ingest path requires the context to be Active.
        st.handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("transition test handle to Active");
        let mut st = st;
        st.membership.add_member(
            scp_identity::DID(member.to_owned()),
            "member".to_owned(),
            Vec::new(),
        );
        st.members.insert(scp_identity::DID(member.to_owned()));
        st.role_state.members.insert(member.to_owned());
        let mut caps = HashSet::new();
        caps.insert(Capability::MessagesWrite);
        st.role_state
            .member_capabilities
            .insert(member.to_owned(), caps);
        st
    }

    /// Lowercase-hex of a repeated byte — the context-id string the test state's
    /// delivery path uses.
    fn ctx_hex(byte: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            use std::fmt::Write;
            let _ = write!(s, "{byte:02x}");
        }
        s
    }

    /// Minimal `InnerEnvelope` — `deliver_message_and_drain_buffered` reads only
    /// `sequence` + `timestamp` off it (the message body is the `plaintext`
    /// argument; the signature is verified upstream of this helper). All
    /// `InnerEnvelope` fields are `pub`, so a struct literal is the simplest
    /// faithful fixture.
    fn minimal_inner(
        ctx: &str,
        sender: &str,
        sequence: u64,
    ) -> scp_protocol::envelope::inner::InnerEnvelope {
        scp_protocol::envelope::inner::InnerEnvelope {
            version: scp_protocol::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: ctx.to_owned(),
            sender_did: sender.to_owned(),
            epoch: 0,
            generation: 0,
            sequence,
            timestamp: 1_700_000_000,
            message_type: scp_protocol::envelope::inner::MessageType::Content,
            payload_hash: [0u8; 32],
            payload: Vec::new(),
            provenance: None,
            provenance_hash: [0u8; 32],
            signing_key_id: scp_protocol::identity::SigningKeyId::Active,
            signature: [0u8; 64],
            extensions: std::collections::HashMap::new(),
        }
    }

    fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
        use crate::context::state::{PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement};
        let ann = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: member_did.to_owned(),
            pseudonym,
        };
        rmp_serde::to_vec_named(&ann).expect("serialize announcement")
    }

    #[tokio::test]
    async fn direct_legitimate_announcement_records_and_returns_consumed() {
        let deps = new_test_deps().await;
        let mut state = writable_encrypted_state(0x31, DIRECT_ALICE).await;
        let ctx = ctx_hex(0x31);
        let ctx_bytes = [0x31u8; 32];
        let pseudonym = [0x42u8; 32];
        let inner = minimal_inner(&ctx, DIRECT_ALICE, 1);

        let mut downward_auth_applied: Option<crate::context::actor::class_s::ClassSCommitToken> =
            None;
        let consumed = crate::context::messaging_helpers::deliver_message_and_drain_buffered(
            &mut crate::context::actor::class_s::ClassCMut::from_state(&mut state),
            &deps,
            &ctx,
            &ctx_bytes,
            DIRECT_ALICE,
            &inner,
            &announcement_bytes(DIRECT_ALICE, pseudonym),
            true,
            &mut downward_auth_applied,
        )
        .expect("a legitimate announcement is consumed, not an error");
        assert!(consumed, "an announcement is reported as consumed (true)");
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(
            reg.get(&scp_identity::DID(DIRECT_ALICE.to_owned())),
            Some(&pseudonym)
        );
    }

    #[tokio::test]
    async fn direct_forged_did_announcement_errors_permission_denied() {
        let deps = new_test_deps().await;
        let mut state = writable_encrypted_state(0x32, DIRECT_ALICE).await;
        let ctx = ctx_hex(0x32);
        let ctx_bytes = [0x32u8; 32];
        // Authenticated sender is ALICE, but the announcement claims BOB.
        let inner = minimal_inner(&ctx, DIRECT_ALICE, 1);

        let mut downward_auth_applied: Option<crate::context::actor::class_s::ClassSCommitToken> =
            None;
        let result = crate::context::messaging_helpers::deliver_message_and_drain_buffered(
            &mut crate::context::actor::class_s::ClassCMut::from_state(&mut state),
            &deps,
            &ctx,
            &ctx_bytes,
            DIRECT_ALICE,
            &inner,
            &announcement_bytes(DIRECT_BOB, [0x42u8; 32]),
            true,
            &mut downward_auth_applied,
        );
        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "the direct ingest site maps a rejection to PermissionDenied; got {result:?}"
        );
        assert!(
            state
                .routing
                .peer_registry()
                .expect("encrypted ⇒ registry")
                .is_empty(),
            "a rejected announcement must not touch the registry"
        );
    }

    #[tokio::test]
    async fn direct_reserved_value_announcement_errors_permission_denied() {
        let deps = new_test_deps().await;
        let mut state = writable_encrypted_state(0x33, DIRECT_ALICE).await;
        let ctx = ctx_hex(0x33);
        let ctx_bytes = [0x33u8; 32];
        let inner = minimal_inner(&ctx, DIRECT_ALICE, 1);

        let mut downward_auth_applied: Option<crate::context::actor::class_s::ClassSCommitToken> =
            None;
        let result = crate::context::messaging_helpers::deliver_message_and_drain_buffered(
            &mut crate::context::actor::class_s::ClassCMut::from_state(&mut state),
            &deps,
            &ctx,
            &ctx_bytes,
            DIRECT_ALICE,
            &inner,
            &announcement_bytes(DIRECT_ALICE, [0u8; 32]), // zero sentinel = reserved
            true,
            &mut downward_auth_applied,
        );
        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "a reserved routing-ID value is rejected on the direct path; got {result:?}"
        );
    }

    #[tokio::test]
    async fn direct_same_did_reannounce_succeeds_and_updates_registry() {
        let deps = new_test_deps().await;
        let mut state = writable_encrypted_state(0x34, DIRECT_ALICE).await;
        let ctx = ctx_hex(0x34);
        let ctx_bytes = [0x34u8; 32];

        for (seq, rid) in [(1u64, [0x42u8; 32]), (2u64, [0x43u8; 32])] {
            let inner = minimal_inner(&ctx, DIRECT_ALICE, seq);
            let mut downward_auth_applied: Option<
                crate::context::actor::class_s::ClassSCommitToken,
            > = None;
            let consumed = crate::context::messaging_helpers::deliver_message_and_drain_buffered(
                &mut crate::context::actor::class_s::ClassCMut::from_state(&mut state),
                &deps,
                &ctx,
                &ctx_bytes,
                DIRECT_ALICE,
                &inner,
                &announcement_bytes(DIRECT_ALICE, rid),
                true,
                &mut downward_auth_applied,
            )
            .expect("same-DID re-announce must succeed");
            assert!(consumed);
        }
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(
            reg.get(&scp_identity::DID(DIRECT_ALICE.to_owned())),
            Some(&[0x43u8; 32]),
            "a same-DID re-announce updates the registry to the rotated routing ID"
        );
    }

    /// `ContextActor::new` constructs an actor that owns `PerContextState`
    /// + `ActorDeps` directly and routes commands through the state-owning
    /// `dispatch_state` path. This test asserts the struct is constructible
    /// and the run-loop processes commands by round-tripping a read-only
    /// member-count query and observing a concrete answer.
    ///
    /// Integration-level coverage of the full
    /// `build_actor_deps_from_attached` path lives in
    /// `crates/scp-runtime/tests/actor_deps_complete.rs` +
    /// `spawn_actor_with_state` unit tests in
    /// `crates/scp-runtime/src/context/supervisor/supervisor.rs`; this
    /// unit test focuses on the actor struct's constructor + run-loop.
    #[tokio::test]
    async fn actor_with_state_answers_read_query() {
        let deps = new_test_deps().await;
        let state = state::PerContextState::new_for_test_encrypted(
            [0x42u8; 32],
            1_700_000_000,
            scp_identity::DID("did:example:admin".to_owned()),
        );

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        // The state-owning actor answers a read-only query on owned state,
        // proving the run loop picks commands up from the inbox and routes
        // them through the actor-shape queries handler.
        let count = handle
            .send(|reply| {
                ContextCommand::Queries(QueriesCommand::MemberCount {
                    context_id: hex_encode_context_id(&[0x42u8; 32]),
                    reply,
                })
            })
            .await
            .expect("member-count query round-trips through the state-owning actor");
        // The test fixture (`new_for_test_encrypted`) seeds the admin DID into
        // `governance`, not into `membership`, so the roster is empty and
        // `MemberCount` (which reads `state.membership.count()`) answers the
        // exact count 0 — not merely "some" count.
        assert_eq!(
            count,
            Some(0),
            "the owning actor answers MemberCount with the exact roster count \
             (empty test fixture ⇒ 0)"
        );

        handle.send_shutdown().await.unwrap();
        actor_task.await.unwrap();
    }
}
