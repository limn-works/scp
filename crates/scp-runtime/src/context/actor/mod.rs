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
    LifecycleControlCommand, MessagingCommand, OutletsCommand, QueriesCommand, SagaPhaseMessage,
    StandingCommand, TrustRecoveryCommand, TtlCloseCommand,
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
    // read by `persist_snapshot` (the coalesced-persist key) and tracing
    context_id: String,
    /// Command inbox. Paired with the `Sender` held by
    /// [`ContextActorHandle`].
    inbox: mpsc::Receiver<ContextCommand>,
    /// Owned per-context state, wrapped in the Class-S fail-closed-persist
    /// cell. Every actor is constructed via [`Self::new`] with a full state
    /// payload — the sole spawn path
    /// ([`crate::context::supervisor::supervisor::Supervisor::spawn_actor_with_state`])
    /// carries it.
    ///
    /// The actor consumes the state on every command: the run-loop's
    /// `dispatch` threads it as `&mut ClassSCell` through `dispatch_state`
    /// into the real per-domain handler.
    // read by the run-loop's dispatch/dispatch_state path
    state: class_s::ClassSCell,
    /// Owned dependency bundle, sourced alongside [`Self::state`] at
    /// construction time.
    // read by the run-loop's dispatch/dispatch_state path
    deps: deps::ActorDeps,
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
    /// against the coalescing window (50 ms — ADR-049 §Decision 9,
    /// "Default: 50ms write-coalescing per actor") before issuing a
    /// snapshot write. Initialized to "now" at actor construction.
    // read by the run-loop's persistence coalesce arm
    last_persisted_at: std::time::Instant,
    /// Dirty flag set when any handler's [`outcome::Outcome`] carries
    /// `mutated: true`. Cleared after a successful coalesced persist.
    /// Initialized `false` at actor construction.
    // read by the run-loop's persistence coalesce arm
    dirty: bool,
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
    /// `crate::context::supervisor::supervisor` constructs actors.
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
        Self {
            context_id,
            inbox,
            // Wrap the owned state in the Class-S fail-closed-persist cell. The
            // cell hands out no whole `&mut PerContextState` (no `DerefMut`, no
            // `state_mut`); every handler mutates through the cell's persist-on-
            // commit combinators or the airtight `class_c_view()` (ADR-049 §9).
            state: class_s::ClassSCell::new(state),
            deps,
            ttl_timer: None,
            governance_timeout: None,
            last_persisted_at: Instant::now(),
            dirty: false,
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
    /// The actor owns both `state` and `deps`; the dispatch routes each
    /// command through `dispatch_state` into the matching handler
    /// module's actor-shape `dispatch` entry point, which operates on the
    /// actor-owned state cell and the capability-reduced deps.
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
                                // `lifecycle_state == Closed`.
                                let claimed = matches!(
                                    self.state.lifecycle_state,
                                    state::ContextLifecycleState::Closed
                                );
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

    /// Dispatch a single command to its matching handler: threads the
    /// actor-owned state/deps through `dispatch_state` into the
    /// per-domain actor-shape `dispatch` entry points.
    async fn dispatch(&mut self, cmd: ContextCommand) {
        // `dispatch_state` receives the `&mut ClassSCell` directly and threads
        // it into every domain handler. Every domain mutates through the cell's
        // combinators — the fail-closed `commit_class_s_*` / `ClassSCommitToken`
        // for Class-S transitions, and the airtight `class_c_view()` /
        // `commit_class_c_best_effort` for Class-C / structural state. There is
        // no `state_mut()` escape hatch (deleted), and the broadcast member-
        // removal in `unsubscribe_broadcast` routes through the restricted
        // `MembershipClassCMut::remove_subscriber` (a public-content subscriber
        // unsubscribe is best-effort-acceptable; see its doc, ADR-049 §9).
        //
        // `state` and `deps` are disjoint fields of `self`, so the
        // borrow checker permits the simultaneous `&mut`/`&` borrows.
        let outcome = Self::dispatch_state(&mut self.state, &self.deps, cmd).await;
        if outcome.mutated {
            self.dirty = true;
        }
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
            ContextCommand::Outlets(sub) => {
                // Phase 2A.4 -- outlets domain migrated to the
                // actor-shape handler for mailbox-routed hard-rate
                // helpers. `Supervisor::dispatch_outlets_command` is
                // mailbox-first: a missing actor surfaces a typed
                // error on the command's reply oneshot.
                handlers::outlets::dispatch(cell, deps, sub).await
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

    /// Coalesced-persistence writer. Invoked by the run loop's Arm-4
    /// coalesce tick (`dirty && deadline reached`) and by the post-loop
    /// final drain (`dirty` at shutdown / inbox-close) to make a burst of
    /// coalesced Class-C mutations durable as a single snapshot write
    /// (ADR-049 §Decision 9, "Default: 50ms write-coalescing per actor").
    ///
    /// Reads the actor's `PerContextState` READ-ONLY through the
    /// [`ClassSCell`](class_s::ClassSCell)'s `Deref` — the persist never
    /// mutates Class-S state (the cell exposes no `DerefMut`). The `&mut self`
    /// receiver is a `Send` requirement, NOT a mutation one: the actor's
    /// spawned `run()` future must be `Send`, and `ContextActor` is `Send` but
    /// not `Sync` (it transitively holds a `Send`-only `FnMut`), so a
    /// `&ContextActor` held across the `.await` would NOT be `Send`, whereas a
    /// `&mut ContextActor` is (`&mut T: Send` needs only `T: Send`). This
    /// mirrors the actor's other borrow-then-await methods (`dispatch`).
    /// Delegates to
    /// [`persist_state_best_effort`](crate::context::messaging_helpers::persist_state_best_effort),
    /// the same best-effort path every coalesced Class-C site uses: it
    /// builds the owned
    /// [`ContextSnapshot`](crate::context::state::ContextSnapshot) in a
    /// synchronous prelude BEFORE the `.await` (Decision-7 `Send`
    /// discipline — the returned future borrows only `deps` and the
    /// context-id, never Class-S state) and records + warns on a persist
    /// failure internally rather than surfacing it (a ≤50 ms coalesce-
    /// window rollback of Class-C state is acceptable per §Decision 9). No
    /// Class-S transition *depends on* this path for durability — each
    /// persists fail-closed at its own mutation site — but the coalesced
    /// snapshot still serializes the whole `PerContextState` (Class-S values
    /// included), so this write is a redundant re-persist for Class-S state
    /// and is authoritative only for Class-C.
    #[allow(clippy::needless_pass_by_ref_mut)] // `&mut self` is a `Send` requirement (see doc)
    async fn persist_snapshot(&mut self) {
        // Read-only `Deref`; the returned future captures only `deps`/`context_id`
        // (`use<'d, 'c>`), never Class-S state.
        let state: &state::PerContextState = &self.state;
        let deps: &deps::ActorDeps = &self.deps;
        let context_id: &str = &self.context_id;
        crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id).await;
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
    async fn actor_exits_on_inbox_close() {
        // Run-loop invariant: when every sender drops, `recv()` yields
        // `None` and the actor exits — no Shutdown command needed. This
        // holds for the (sole) state-owning actor shape.
        let deps = new_test_deps().await;
        let state = state::PerContextState::new_for_test_encrypted(
            [0x11u8; 32],
            1_700_000_000,
            scp_did::DID("did:example:admin".to_owned()),
        );
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new(state, deps, rx);
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
        // `Pause` is non-terminal: the actor acks `Ok(())` and keeps
        // running, so a subsequent query is still answered off its owned
        // state.
        let deps = new_test_deps().await;
        let state = state::PerContextState::new_for_test_encrypted(
            [0x12u8; 32],
            1_700_000_000,
            scp_did::DID("did:example:admin".to_owned()),
        );
        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_handle = tokio::spawn(actor.run());

        let handle = ContextActorHandle::from_sender(tx);
        handle.send_pause().await.unwrap();
        // Actor is still running; a subsequent read query answers off
        // owned state (empty test fixture ⇒ exact roster count 0).
        let count = handle
            .send(|reply| {
                ContextCommand::Queries(QueriesCommand::MemberCount {
                    context_id: hex_encode_context_id(&[0x12u8; 32]),
                    reply,
                })
            })
            .await
            .expect("member-count query round-trips after a Pause");
        assert_eq!(count, Some(0));

        handle.send_shutdown().await.unwrap();
        actor_handle.await.unwrap();
    }

    #[tokio::test]
    async fn actor_shutdown_command_exits_loop_promptly() {
        // `Shutdown` is unconditionally terminal: the run loop breaks
        // after dispatching it. Bound the wait so a regression that fails
        // to exit is caught rather than hanging CI.
        let deps = new_test_deps().await;
        let state = state::PerContextState::new_for_test_encrypted(
            [0x13u8; 32],
            1_700_000_000,
            scp_did::DID("did:example:admin".to_owned()),
        );
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        let actor = ContextActor::new(state, deps, rx);
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
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        async fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _id: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Minimal persistence stub for the `ContextActor::new` test.
    /// Returns empty reads and silently accepts every write.
    struct TestPersistence;
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for TestPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
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
        new_test_deps_with_persistence(Box::new(TestPersistence)).await
    }

    /// Same as [`new_test_deps`] but with a caller-supplied persistence
    /// backend. Lets a test inject a recording backend and assert that a
    /// coalesced Class-C mutation actually reaches durable storage via the
    /// run loop's coalesced flush (ADR-049 §Decision 9; see
    /// `coalesced_class_c_mutation_is_durable_*`).
    async fn new_test_deps_with_persistence(
        persistence: Box<dyn crate::context::persistence::ContextPersistence>,
    ) -> deps::ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_did::DID;
        use scp_platform::testing::InMemoryStorage;
        use std::sync::Arc;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestActorNew".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None);
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
    fn writable_encrypted_state(ctx_byte: u8, member: &str) -> state::PerContextState {
        use scp_protocol::context::roles::Capability;
        use std::collections::HashSet;

        let st = state::PerContextState::new_for_test_encrypted(
            [ctx_byte; 32],
            1_700_000_000,
            scp_did::DID(member.to_owned()),
        );
        // The in-order ingest path requires the context to be Active.
        st.handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("transition test handle to Active");
        let mut st = st;
        st.membership.add_member(
            scp_did::DID(member.to_owned()),
            "member".to_owned(),
            Vec::new(),
        );
        st.members.insert(scp_did::DID(member.to_owned()));
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
            signing_key_id: scp_did::SigningKeyId::Active,
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
        let mut state = writable_encrypted_state(0x31, DIRECT_ALICE);
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
        .await
        .expect("a legitimate announcement is consumed, not an error");
        assert!(consumed, "an announcement is reported as consumed (true)");
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(
            reg.get(&scp_did::DID(DIRECT_ALICE.to_owned())),
            Some(&pseudonym)
        );
    }

    #[tokio::test]
    async fn direct_forged_did_announcement_errors_permission_denied() {
        let deps = new_test_deps().await;
        let mut state = writable_encrypted_state(0x32, DIRECT_ALICE);
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
        )
        .await;
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
        let mut state = writable_encrypted_state(0x33, DIRECT_ALICE);
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
        )
        .await;
        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "a reserved routing-ID value is rejected on the direct path; got {result:?}"
        );
    }

    #[tokio::test]
    async fn direct_same_did_reannounce_succeeds_and_updates_registry() {
        let deps = new_test_deps().await;
        let mut state = writable_encrypted_state(0x34, DIRECT_ALICE);
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
            .await
            .expect("same-DID re-announce must succeed");
            assert!(consumed);
        }
        let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
        assert_eq!(
            reg.get(&scp_did::DID(DIRECT_ALICE.to_owned())),
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
            scp_did::DID("did:example:admin".to_owned()),
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

    // -----------------------------------------------------------------
    // ADR-049 §Decision 9 — coalesced Class-C persistence durability.
    //
    // A `class_c_view()` mutation performs NO persist at the mutation
    // site (that is its documented contract; see
    // `ClassSCell::class_c_view`) — durability rides ENTIRELY on the run
    // loop's coalesced flush (`persist_snapshot`, invoked by the Arm-4
    // coalesce tick and the post-loop final drain). These regression
    // tests drive a real coalesced Class-C mutation through the mailbox
    // and prove the flush actually writes it to durable storage. Before
    // `persist_snapshot` was wired, the flush was a no-op and any
    // mutation made only via `class_c_view()` was silently lost on
    // shutdown/crash.
    // -----------------------------------------------------------------

    /// Persistence that RECORDS every `persist_context` snapshot, so a test
    /// can prove a coalesced Class-C mutation reached durable storage
    /// (ADR-049 §Decision 9). `load_context` returns the most-recent
    /// recorded snapshot, so a respawn/restore reads the coalesced state
    /// back. `persisted` fires once per write, letting a test await the
    /// coalesce flush deterministically under paused tokio time.
    #[cfg(feature = "testing")]
    #[derive(Clone)]
    struct RecordingPersistence {
        // Lock-free per ADR-049 §Decision 12 (`std::sync`/`tokio::sync` mutexes
        // are banned in this crate): the last-written snapshot lives in an
        // `ArcSwapOption`, swapped on each write and loaded on read.
        last: std::sync::Arc<arc_swap::ArcSwapOption<crate::context::state::ContextSnapshot>>,
        persisted: std::sync::Arc<tokio::sync::Notify>,
    }

    #[cfg(feature = "testing")]
    impl RecordingPersistence {
        fn new() -> Self {
            Self {
                last: std::sync::Arc::new(arc_swap::ArcSwapOption::empty()),
                persisted: std::sync::Arc::new(tokio::sync::Notify::new()),
            }
        }

        /// The most-recent persisted snapshot, or `None` if nothing was
        /// written — exactly the bytes a respawn/restore would rehydrate.
        fn last_snapshot(&self) -> Option<std::sync::Arc<crate::context::state::ContextSnapshot>> {
            self.last.load_full()
        }
    }

    #[cfg(feature = "testing")]
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for RecordingPersistence {
        async fn persist_context(
            &self,
            _context_id: &str,
            snapshot: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.last.store(Some(std::sync::Arc::new(snapshot.clone())));
            self.persisted.notify_one();
            Ok(())
        }
        async fn load_context(
            &self,
            _context_id: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(self.last_snapshot().map(|s| (*s).clone()))
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self
                .last_snapshot()
                .map(|s| vec![s.context_id.clone()])
                .unwrap_or_default())
        }
    }

    /// Send a `TestInstallAccessKey` command to `handle` for `(ctx, member)`.
    /// The handler mutates the persisted `access_key_store` through
    /// `class_c_view()` and reports `Outcome::ok_mutated` — a coalesced
    /// Class-C mutation with NO co-located persist, so its durability rides
    /// only the run loop's coalesced flush.
    #[cfg(feature = "testing")]
    async fn install_access_key_via_mailbox(handle: &ContextActorHandle, ctx: &str, member: &str) {
        handle
            .send(|reply| {
                ContextCommand::Messaging(MessagingCommand::TestInstallAccessKey {
                    context_id: ctx.to_owned(),
                    member_did: member.to_owned(),
                    key: scp_protocol::crypto::access_keys::generate_access_key(ctx, member),
                    reply,
                })
            })
            .await
            .expect("access-key install round-trips through the state-owning actor");
    }

    /// The post-loop **final drain** persists a pending coalesced Class-C
    /// mutation: after installing an access key (a `class_c_view()` mutation
    /// with no co-located persist) and shutting the actor down, the drained
    /// snapshot must carry the key, so a respawn/restore reads it back.
    /// Regression guard for ADR-049 §Decision 9 — with `persist_snapshot` a
    /// no-op, the drain wrote nothing and the mutation was lost on shutdown.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn coalesced_class_c_mutation_is_durable_across_final_drain() {
        let recorder = RecordingPersistence::new();
        let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
        let ctx = ctx_hex(0x51);
        let member = "did:example:coalesced-drain-member";
        let state = writable_encrypted_state(0x51, member);

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        install_access_key_via_mailbox(&handle, &ctx, member).await;

        // Shutdown drives the run loop to exit; the post-loop final drain
        // (`if self.dirty { persist_snapshot().await }`) flushes the pending
        // snapshot. Awaiting the actor task guarantees the drain completed.
        handle.send_shutdown().await.expect("shutdown acks");
        actor_task.await.expect("actor task joins");

        let snapshot = recorder
            .last_snapshot()
            .expect("final drain must have persisted a snapshot (ADR-049 §Decision 9)");
        assert!(
            snapshot.access_key_store.contains(&ctx, member),
            "the coalesced access-key mutation must be durable in the drained snapshot"
        );
    }

    /// The run loop's **Arm-4 coalesce tick** (`dirty && deadline reached`)
    /// flushes the same pending mutation while the actor is still live —
    /// the same `persist_snapshot` the final drain uses, reached on the
    /// ≤50 ms `COALESCE_INTERVAL` (ADR-049 §Decision 9). Paused tokio time
    /// advances the window deterministically, never racing the wall clock.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn coalesced_class_c_mutation_is_durable_across_coalesce_tick() {
        let recorder = RecordingPersistence::new();
        let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
        // Pause AFTER building deps so `build_actor_deps` runs under real
        // time; the actor's `last_persisted_at` is captured (in
        // `ContextActor::new`) against the now-frozen clock.
        tokio::time::pause();
        let ctx = ctx_hex(0x52);
        let member = "did:example:coalesced-tick-member";
        let state = writable_encrypted_state(0x52, member);

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        install_access_key_via_mailbox(&handle, &ctx, member).await;

        // Advance virtual time past the coalescing window so Arm-4 fires while
        // the actor is still running (no Shutdown / drain involved). Determinism
        // comes from tokio's current-thread paused clock auto-advancing to the
        // next timer once both tasks park — NOT from the exact `advance` amount;
        // the `+1ms` only steps strictly past the deadline. `notify_one` stores a
        // permit, so `notified()` below cannot miss the wakeup even if the persist
        // lands during `advance`.
        tokio::time::advance(COALESCE_INTERVAL + std::time::Duration::from_millis(1)).await;
        // Bound the wait so a `persist_snapshot` regression to a no-op (no
        // `notify_one`) fails this test in bounded VIRTUAL time instead of
        // hanging forever (`#[tokio::test]` has no wall-clock timeout): under
        // paused time the timeout auto-advances and returns `Err`, turning the
        // hang into a legible assertion failure.
        tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
            .await
            .expect("Arm-4 coalesce tick must persist within the coalesce window");

        let snapshot = recorder
            .last_snapshot()
            .expect("the coalesce tick must have persisted a snapshot (ADR-049 §Decision 9)");
        assert!(
            snapshot.access_key_store.contains(&ctx, member),
            "the coalesced access-key mutation must be durable after the Arm-4 tick"
        );

        handle.send_shutdown().await.expect("shutdown acks");
        actor_task.await.expect("actor task joins");
    }

    /// Regression guard for ADR-049 finding **N1** (PR-2 caller audit): a handler
    /// that mutates Class-C via `class_c_view()` but reports `Outcome::ok`
    /// (`mutated:false`) leaves `dirty` clear, so the run loop's Arm-4 coalesce
    /// tick never fires and the mutation is lost on crash.
    ///
    /// `SeedPeerPseudonym` was exactly such a handler: it records a peer routing
    /// pseudonym into the `Pseudonymous` registry through `class_c_view()` (NO
    /// co-located persist) and used to return `Outcome::ok`. The PR-2 fix makes it
    /// report `Outcome::ok_mutated` on a successful insert.
    ///
    /// This uses the **coalesce-tick** model (like
    /// [`coalesced_class_c_mutation_is_durable_across_coalesce_tick`]), NOT a
    /// shutdown drain: the drain cannot validate a handler's `mutated` flag,
    /// because the `Shutdown` handler ITSELF reports `mutated` and dirties the
    /// actor, so the drain fires (persisting the whole live state, which already
    /// carries the in-memory insert) regardless of the seed handler's flag. Here
    /// the assertion runs while the actor is STILL LIVE, off the Arm-4 tick that
    /// fires only when `dirty` is set — so with the pre-fix `Outcome::ok` handler
    /// `dirty` stays false, the tick never fires, and `persisted.notified()` times
    /// out in bounded virtual time (a genuine failure, empirically verified).
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn coalesced_seed_peer_pseudonym_is_durable_across_coalesce_tick() {
        let recorder = RecordingPersistence::new();
        let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
        // Pause AFTER building deps so `build_actor_deps` runs under real time and
        // the actor's `last_persisted_at` is captured against the now-frozen clock.
        tokio::time::pause();
        let ctx = ctx_hex(0x53);
        let member = "did:example:coalesced-seed-peer-member";
        let pseudonym = [0x77u8; 32];
        let state = writable_encrypted_state(0x53, member);

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        // Record a peer pseudonym — a coalesced Class-C mutation with NO co-located
        // persist (routes through `class_c_view`). Awaiting the reply also proves
        // the live in-memory insert succeeded.
        handle
            .send(|reply| {
                ContextCommand::Messaging(MessagingCommand::SeedPeerPseudonym {
                    context_id: ctx.clone(),
                    member_did: scp_did::DID(member.to_owned()),
                    pseudonym,
                    reply,
                })
            })
            .await
            .expect("seed-peer-pseudonym round-trips through the state-owning actor");

        // Advance past the coalescing window so Arm-4 fires while the actor is still
        // running (NO shutdown/drain). With the pre-fix `Outcome::ok` handler
        // `dirty` stays false, Arm-4 never fires, and this `notified()` times out.
        tokio::time::advance(COALESCE_INTERVAL + std::time::Duration::from_millis(1)).await;
        tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
            .await
            .expect("Arm-4 coalesce tick must persist the seeded pseudonym within the window");

        let snapshot = recorder
            .last_snapshot()
            .expect("the coalesce tick must have persisted a snapshot (ADR-049 §Decision 9 / N1)");
        let registry = snapshot
            .routing
            .peer_registry()
            .expect("the encrypted test context must persist a Pseudonymous peer registry");
        assert_eq!(
            registry.get(&scp_did::DID(member.to_owned())),
            Some(&pseudonym),
            "the coalesced peer-pseudonym mutation must be durable after the Arm-4 tick",
        );

        handle.send_shutdown().await.expect("shutdown acks");
        actor_task.await.expect("actor task joins");
    }

    /// Regression guard for ADR-049 finding **N1** (PR-2): `TestInsertMember`
    /// records a member — roster insert, `system_assign_role`, and membership add —
    /// through `class_c_view()` with NO co-located persist, and used to return
    /// `Outcome::ok` (`mutated:false`), so a `<=50ms` crash silently lost the
    /// member. The PR-2 fix reports `Outcome::ok_mutated` on a successful insert.
    ///
    /// Same **coalesce-tick** model as the sibling pseudonym test (the assertion
    /// runs while the actor is live, so the shutdown drain cannot mask a false
    /// flag): with the pre-fix `Outcome::ok` handler `dirty` stays false, Arm-4
    /// never fires, and `persisted.notified()` times out (empirically verified).
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn coalesced_test_insert_member_is_durable_across_coalesce_tick() {
        use scp_protocol::context::roles::{builtin_roles, default_ceiling};

        let recorder = RecordingPersistence::new();
        let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
        tokio::time::pause();
        let ctx = ctx_hex(0x54);
        let admin = "did:example:coalesced-insert-admin";
        let new_member = "did:example:coalesced-insert-member";
        let mut state = writable_encrypted_state(0x54, admin);
        // `TestInsertMember` calls `system_assign_role("member")`, which requires
        // that role to be DEFINED within the context ceiling. The bare test fixture
        // starts with an empty ceiling / no role definitions, so seed the standard
        // ceiling + built-in roles (the same "member" role a real `create_context`
        // installs) before driving the insert.
        let ceiling = default_ceiling();
        state
            .role_state
            .set_ceiling(ceiling.clone())
            .expect("seed the default ceiling for the member role definition");
        for role in builtin_roles(&ceiling) {
            state
                .role_state
                .role_definitions
                .insert(role.name.clone(), role);
        }

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        // Insert a second member — a coalesced Class-C structural mutation with NO
        // co-located persist. Awaiting the reply proves the live insert succeeded.
        handle
            .send(|reply| {
                ContextCommand::Messaging(MessagingCommand::TestInsertMember {
                    context_id: ctx.clone(),
                    member_did: scp_did::DID(new_member.to_owned()),
                    role: "member".to_owned(),
                    reply,
                })
            })
            .await
            .expect("test-insert-member round-trips through the state-owning actor");

        tokio::time::advance(COALESCE_INTERVAL + std::time::Duration::from_millis(1)).await;
        tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
            .await
            .expect("Arm-4 coalesce tick must persist the inserted member within the window");

        let snapshot = recorder
            .last_snapshot()
            .expect("the coalesce tick must have persisted a snapshot (ADR-049 §Decision 9 / N1)");
        assert!(
            snapshot.role_state.members.contains(new_member),
            "the coalesced role-state member insert must be durable after the Arm-4 tick",
        );
        assert!(
            snapshot.membership.contains(new_member),
            "the coalesced membership add must be durable after the Arm-4 tick",
        );

        handle.send_shutdown().await.expect("shutdown acks");
        actor_task.await.expect("actor task joins");
    }
}
