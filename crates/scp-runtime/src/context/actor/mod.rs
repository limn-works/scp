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

use std::pin::Pin;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::{Interval, MissedTickBehavior, Sleep};

/// Coalesced-persistence interval. ADR-049 §Decision 9 (50 ms): a
/// burst of mutations that all complete within this window collapse to
/// a single durable snapshot write. The actor's `run()` loop wakes on
/// this interval iff `dirty == true` and writes the latest snapshot.
const COALESCE_INTERVAL: Duration = Duration::from_millis(50);

/// BASE backoff before retrying an INCOMPLETE TTL expiry (SEC-1 / ADR-049 §9
/// amendment; M2). When [`ContextActor::on_ttl_tick`] leaves the context
/// terminal (`Expired`) but a cleanup step (key destruction, event-log append)
/// or the fail-closed terminal persist did not complete, the actor stays alive
/// and re-arms [`ContextActor::ttl_expiry_retry`], then re-runs the expiry
/// carrying the prior `completed_steps` so only the failed step re-executes.
///
/// The delay grows EXPONENTIALLY from this base —
/// `TTL_EXPIRY_RETRY_BASE · 2^(n−1)` for the n-th consecutive incomplete
/// attempt — capped at [`TTL_EXPIRY_RETRY_CAP`], so a persistently-failing
/// dependency (a wedged storage/event-log backend) does not spin the
/// single-threaded actor at a fixed 5 s forever. This is genuinely bounded
/// backoff (pre-M2 it was a fixed, uncapped 5 s that the comment nonetheless
/// called "bounded backoff").
const TTL_EXPIRY_RETRY_BASE: Duration = Duration::from_secs(5);

/// Upper bound on the exponential TTL-expiry retry backoff (M2). Caps
/// `TTL_EXPIRY_RETRY_BASE · 2^(n−1)` so the retry cadence settles at a modest
/// steady-state interval rather than growing without bound.
const TTL_EXPIRY_RETRY_CAP: Duration = Duration::from_mins(5);

/// Number of consecutive incomplete TTL-expiry attempts after which the actor
/// emits an operator-visible, rate-limited `error!` signal (M2). A terminal
/// actor stuck retrying this long indicates a genuinely-wedged local dependency
/// (event log / storage) — an OPERATIONAL fault that must be observable, not
/// silently spun. Fail-closed is preserved: the actor still never despawns with
/// an undurable terminal state.
const TTL_EXPIRY_STUCK_THRESHOLD: u32 = 12;

/// Bounded exponential backoff for the n-th (1-based) consecutive incomplete
/// TTL-expiry attempt (M2): `TTL_EXPIRY_RETRY_BASE · 2^(n−1)`, saturating at
/// `TTL_EXPIRY_RETRY_CAP`. `retries == 0` is treated as the first attempt.
fn ttl_expiry_retry_backoff(retries: u32) -> Duration {
    // Cap the shift well under 64 so `1u64 << shift` cannot overflow; the `.min`
    // against the cap below makes any shift past the cap-crossing point a no-op.
    let shift = retries.saturating_sub(1).min(32);
    let secs = TTL_EXPIRY_RETRY_BASE
        .as_secs()
        .saturating_mul(1u64 << shift)
        .min(TTL_EXPIRY_RETRY_CAP.as_secs());
    Duration::from_secs(secs)
}

/// Governance-timeout evaluation cadence (60 s). Re-exported from
/// [`crate::context::governance::timeout::TIMEOUT_CHECK_INTERVAL_SECS`]
/// so the actor-owned `governance_timeout` interval fires on the exact
/// cadence the retired supervisor-driven timer task used (ADR-049
/// Decision-1 / finding A3 — the timer becomes an actor-owned arm).
const GOVERNANCE_TIMEOUT_SECS: u64 =
    crate::context::governance::timeout::TIMEOUT_CHECK_INTERVAL_SECS;

/// Fairness bound (ADR-049 §10 liveness defense-in-depth): the run loop's
/// `select!` is `biased` (inbox first for shutdown determinism), so a
/// saturated inbox would otherwise starve the actor-owned TTL / governance /
/// persist arms — a member flooding messages could delay THAT context's own
/// TTL close or governance-consequence (e.g. their own demotion). After this
/// many back-to-back inbox dispatches the loop disables the inbox arm for one
/// iteration so the timer/persist arms get a guaranteed poll (see `run()`).
/// Not a correctness crutch for tokio's coop budget — an explicit,
/// documented bound on a security-liveness property.
const MAX_CONSECUTIVE_INBOX: u32 = 32;

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
/// See plan §"ContextActor" for the full shape. The `run()` loop dispatches
/// state-bearing commands through `dispatch_state` to the real per-domain
/// handlers, and drives the ACTOR-OWNED timer arms directly off owned state
/// (ADR-049 finding A3): the TTL-expiry arm and the governance-timeout arm each
/// reconcile a one-shot / interval sleep against the deadlines recorded on
/// `PerContextState` and run their pipeline on wake — there is no
/// supervisor-side timer `task_set` and no mailbox hop. Persistence flows
/// through the Class-S / Class-C combinators on the actor's owned `ClassSCell`.
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
    /// One-shot TTL-expiry timer, ACTOR-OWNED (ADR-049 Decision-1 /
    /// finding A3). Armed by [`Self::reconcile_timers`] from the
    /// convergent `state.ttl.timer.deadline_unix_secs`; `None` when the
    /// context has no pending TTL deadline. Fires exactly once —
    /// [`Self::on_ttl_tick`] runs the best-effort expiry pipeline and the
    /// actor exits on the resulting terminal (`Expired`) state (anti-
    /// resurrection only respawns `Active` snapshots, so a re-derive from
    /// the convergent deadline on any later restore re-fires idempotently).
    ///
    /// A derived cache of owned state: [`Self::reconcile_timers`] re-arms
    /// only when the deadline changes (tracked by [`Self::ttl_armed_deadline`]),
    /// so repeated reconciles are cheap no-ops. `tokio::time::Sleep` is
    /// `!Unpin`, so the field holds a pinned box.
    // read by the run-loop's TTL select! arm; armed by reconcile_timers
    ttl_timer: Option<Pin<Box<Sleep>>>,
    /// Governance-timeout interval (60 s), ACTOR-OWNED (ADR-049
    /// Decision-1 / finding A3). Armed by [`Self::reconcile_timers`]
    /// while the context is `Active`; each tick runs the governance
    /// timeout / consequence sweep on owned state via
    /// [`Self::on_governance_timeout`], which nulls the interval when the
    /// sweep signals stop (context no longer `Active`). Re-armed by a
    /// later reconcile if the context returns to `Active`.
    // read by the run-loop's governance select! arm; armed by reconcile_timers
    governance_timeout: Option<Interval>,
    /// The `state.ttl.timer.deadline_unix_secs` value the current
    /// [`Self::ttl_timer`] arm was derived from. [`Self::reconcile_timers`]
    /// compares this against the live deadline and re-arms the one-shot
    /// sleep only when it changes — the idempotence guard that keeps
    /// per-turn reconciliation from resetting an already-correct arm.
    // read + written by reconcile_timers
    ttl_armed_deadline: Option<u64>,
    /// The `completed_steps` bitmask of the in-progress TTL expiry, carried
    /// across on-actor retries (SEC-1 / ADR-049 §9 amendment). When
    /// [`Self::on_ttl_tick`] cannot finish the terminal cleanup (a transient
    /// key-destruction failure, an event-log stall, or a fail-closed persist
    /// failure), the actor is kept alive and this bitmask records which steps
    /// DID land so the retry re-runs ONLY the failed step. `0` until the first
    /// expiry attempt; reset only implicitly by actor teardown on completion.
    // read + written by on_ttl_tick
    ttl_expiry_completed: u8,
    /// Bounded retry arm for an INCOMPLETE TTL expiry (SEC-1). Set by
    /// [`Self::on_ttl_tick`] when the expiry left the context terminal
    /// (`Expired`) but the cleanup did not fully complete or the terminal
    /// persist failed — the actor must NOT despawn (else a destroyed-but-
    /// unrecorded key or an undurable terminal state is lost). Independent of
    /// the `is_active`-gated [`Self::ttl_timer`] (which `reconcile_timers`
    /// clears once the context leaves `Active`); `reconcile_timers` never
    /// touches this arm. `tokio::time::Sleep` is `!Unpin`, so a pinned box.
    // read by the run-loop's TTL-expiry-retry select! arm; armed by on_ttl_tick
    ttl_expiry_retry: Option<Pin<Box<Sleep>>>,
    /// Count of CONSECUTIVE incomplete TTL-expiry attempts (M2). Drives the
    /// bounded exponential backoff for [`Self::ttl_expiry_retry`]
    /// (`TTL_EXPIRY_RETRY_BASE · 2^(n−1)`, capped at `TTL_EXPIRY_RETRY_CAP`) and
    /// the operator-visible stuck-actor signal once it crosses
    /// [`TTL_EXPIRY_STUCK_THRESHOLD`]. Incremented each time `on_ttl_tick`
    /// re-arms the retry; reset to `0` when the expiry completes. Fail-closed is
    /// preserved — the actor NEVER despawns with an undurable terminal state; a
    /// permanently-wedged local event log is surfaced, not silently dropped.
    // read + written by on_ttl_tick
    ttl_expiry_retries: u32,
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
    /// Count of consecutive inbox dispatches since a timer/persist arm last
    /// got a turn. The `biased` `select!` prioritizes the inbox; this counter
    /// bounds that priority so a saturated inbox cannot starve the timer arms
    /// (see [`MAX_CONSECUTIVE_INBOX`] + the fairness fall-through arm in
    /// `run()`). Reset to 0 whenever a non-inbox arm fires.
    // read + written by the run-loop's fairness bound
    consecutive_inbox: u32,
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
    /// - `ttl_timer`, `governance_timeout`, `ttl_armed_deadline` start as
    ///   `None`. The run loop's [`Self::reconcile_timers`] arms them from
    ///   owned state at the top of every turn (TTL from
    ///   `state.ttl.timer.deadline_unix_secs`, governance while `Active`).
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
            ttl_armed_deadline: None,
            ttl_expiry_completed: 0,
            ttl_expiry_retry: None,
            ttl_expiry_retries: 0,
            last_persisted_at: Instant::now(),
            dirty: false,
            consecutive_inbox: 0,
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
            // Reconcile the ACTOR-OWNED timer arms from owned state before
            // every select (top of run() + after each dispatch, since a
            // dispatch loops back to here). Cheap: re-arms only when the
            // convergent TTL deadline changes or the `Active` state flips
            // (ADR-049 Decision-1 / finding A3).
            self.reconcile_timers();

            tokio::select! {
                biased;

                // --- Arm 1: inbox ----------------------------------
                // Fairness: disable the inbox arm for one iteration once it
                // has monopolized `MAX_CONSECUTIVE_INBOX` turns, so the timer
                // / persist arms below get a guaranteed poll (see the
                // fall-through Arm 5). `biased` shutdown priority is preserved
                // whenever the inbox is enabled.
                maybe_cmd = self.inbox.recv(), if self.consecutive_inbox < MAX_CONSECUTIVE_INBOX => {
                    match maybe_cmd {
                        Some(cmd) => {
                            self.consecutive_inbox += 1;
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

                // --- Arm 2: TTL timer (one-shot) -------------------
                () = async {
                    match self.ttl_timer.as_mut() {
                        // `Pin<Box<Sleep>>` is a one-shot future: awaiting
                        // the pinned mutable reference resolves once the
                        // convergent deadline elapses.
                        Some(sleep) => sleep.as_mut().await,
                        None => std::future::pending::<()>().await,
                    }
                }, if self.ttl_timer.is_some() => {
                    self.consecutive_inbox = 0;
                    // Run the best-effort expiry pipeline; break the run loop
                    // when it lands the context in a terminal state so the
                    // actor task exits (anti-resurrection prevents re-spawn).
                    if self.on_ttl_tick().await {
                        // Despawn our OWN registry handle before exiting.
                        // Nothing else will: the watchdog deliberately leaves
                        // clean `Ok(())` exits registered (supervisor.rs
                        // `actor_watchdog`) to avoid racing an in-flight
                        // PrepareForReplace, and — unlike the Shutdown /
                        // PrepareForReplace breaks, which have an external
                        // caller that despawns/replaces — an internal TTL exit
                        // has none. Without this the dead-but-registered handle
                        // lingers in `actors`, so `read_context_state` reports
                        // `None` (closed mailbox) instead of the persisted
                        // `Expired`, and the context id cannot be re-created.
                        // `despawn_actor` removes our OWN registry entry
                        // (`&self.context_id`) under the supervisor write lock;
                        // safe to call from here — the actor holds no lock, and
                        // the removal has no `.await` while the lock is held.
                        self.deps.supervisor.despawn_actor(&self.context_id).await;
                        break;
                    }
                }

                // --- Arm 2b: TTL expiry retry (bounded exponential backoff) ----
                // Fires only when a prior `on_ttl_tick` left the context terminal
                // but the cleanup did not fully complete or the fail-closed
                // terminal persist failed (SEC-1). Re-runs the expiry carrying
                // the prior `completed_steps` so ONLY the failed step re-executes;
                // despawns once the expiry is complete AND durable. The backoff
                // grows exponentially (base 5 s, capped at 300 s) per consecutive
                // incomplete attempt, and a stuck actor is surfaced via an
                // operator-visible signal (M2). Independent of the `is_active`-
                // gated `ttl_timer` (disarmed once the FSM leaves `Active`), so
                // `reconcile_timers` cannot clobber this arm.
                () = async {
                    match self.ttl_expiry_retry.as_mut() {
                        Some(sleep) => sleep.as_mut().await,
                        None => std::future::pending::<()>().await,
                    }
                }, if self.ttl_expiry_retry.is_some() => {
                    self.consecutive_inbox = 0;
                    // Clear the fired retry arm; `on_ttl_tick` re-arms it if the
                    // expiry is still incomplete.
                    self.ttl_expiry_retry = None;
                    if self.on_ttl_tick().await {
                        // Same internal-TTL-exit despawn as Arm 2: no external
                        // despawner for a timer-driven terminal exit.
                        self.deps.supervisor.despawn_actor(&self.context_id).await;
                        break;
                    }
                }

                // --- Arm 3: governance timeout (60s interval) ------
                () = async {
                    match self.governance_timeout.as_mut() {
                        Some(interval) => {
                            let _ = interval.tick().await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                }, if self.governance_timeout.is_some() => {
                    self.consecutive_inbox = 0;
                    // The interval auto-refires every 60 s;
                    // `on_governance_timeout` nulls it only when the sweep
                    // signals stop (context no longer `Active`).
                    self.on_governance_timeout().await;
                }

                // --- Arm 4: persistence coalesce -------------------
                () = tokio::time::sleep_until(
                    tokio::time::Instant::from_std(
                        self.last_persisted_at + COALESCE_INTERVAL
                    )
                ), if self.dirty => {
                    self.consecutive_inbox = 0;
                    self.persist_snapshot().await;
                    self.last_persisted_at = Instant::now();
                    self.dirty = false;
                }

                // --- Arm 5: fairness fall-through ------------------
                // Reached only when the inbox arm is disabled for its fairness
                // iteration AND no timer/persist arm was ready. Immediately
                // resets the budget so normal inbox-first dispatch resumes
                // next turn — this is the fall-through that prevents a
                // deadlock (with the inbox disabled and nothing else ready the
                // loop would otherwise block forever).
                () = std::future::ready(()),
                    if self.consecutive_inbox >= MAX_CONSECUTIVE_INBOX => {
                    self.consecutive_inbox = 0;
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

    /// Reconcile the ACTOR-OWNED timer arms from owned state (ADR-049
    /// Decision-1 / finding A3). The arms are a derived cache of owned
    /// state, reconciled at the top of every `run()` turn:
    ///
    /// - **TTL**: while the context is `Active`, arms a one-shot `sleep` for the
    ///   remaining time to the convergent `state.ttl.timer.deadline_unix_secs`.
    ///   Re-arms only when that deadline changes (guarded by
    ///   [`Self::ttl_armed_deadline`]), so per-turn reconciliation never resets
    ///   an already-correct arm. A `None` deadline clears the arm; a past
    ///   deadline arms `sleep(0)` (fires immediately — a restore past the
    ///   deadline re-closes idempotently). Once the context leaves `Active`
    ///   (close / tombstone / promote / expiry), the arm is unconditionally
    ///   cleared so a stale deadline cannot fire against a terminal context and
    ///   despawn it (BUG-1) — symmetric to the governance interval's gate.
    /// - **Governance**: arms a 60 s interval while the context is
    ///   `Active`; clears it once the context is not `Active`. The
    ///   `is_none()` guard keeps a frequently-dispatched actor from
    ///   continually resetting (and thus never firing) the interval.
    ///
    /// `reconcile_timers` only re-runs when a `select!` arm fires (top of
    /// each loop turn), so an off-actor `Active` transition with no subsequent
    /// command won't arm the governance interval until the next arm/command.
    /// That is harmless: governance work arrives as commands (a vote/proposal
    /// wakes the inbox arm, which loops back through here), so the interval is
    /// armed before any timeout-relevant work can accrue.
    fn reconcile_timers(&mut self) {
        // `Copy` snapshot so the immutable borrow of `state` ends before the
        // timer-field writes below.
        let desired_deadline = self.state.ttl.timer.deadline_unix_secs;
        // Lock-free atomic load of the lifecycle FSM (ADR-049 §10 — the
        // handle caches state in an `ArcSwap`, so this read never blocks).
        let is_active = self.state.handle.state() == scp_protocol::context::ContextState::Active;

        // TTL one-shot arm — armed ONLY while the context is `Active`, mirroring
        // the governance interval's `is_active` gate below (BUG-1). A close /
        // tombstone / promote clears `deadline_unix_secs` inside its
        // fail-closed commit, but a stale arm could otherwise still fire against
        // an already-terminal context and despawn it — re-opening the
        // `close_context_with_key` window and defeating tombstone finality. When
        // NOT `Active`, unconditionally disarm. When `Active`, re-derive only
        // when the convergent deadline changes (StartTtlTimer / ResetTtlTimer /
        // ExtendTtl rewrote it); the clock read lives INSIDE the re-arm branch,
        // needed only on a re-arm, not on the common per-turn no-op path.
        if is_active {
            if desired_deadline != self.ttl_armed_deadline {
                self.ttl_armed_deadline = desired_deadline;
                let now_secs = self.deps.clock.now_secs();
                self.ttl_timer = desired_deadline.map(|deadline| {
                    let remaining = deadline.saturating_sub(now_secs);
                    Box::pin(tokio::time::sleep(Duration::from_secs(remaining)))
                });
            }
        } else {
            self.ttl_timer = None;
            self.ttl_armed_deadline = None;
        }

        // Governance 60 s interval — armed only while Active.
        if is_active {
            if self.governance_timeout.is_none() {
                // First tick after a full interval (not immediately),
                // matching the retired supervisor timer's initial sleep.
                let mut interval = tokio::time::interval_at(
                    tokio::time::Instant::now() + Duration::from_secs(GOVERNANCE_TIMEOUT_SECS),
                    Duration::from_secs(GOVERNANCE_TIMEOUT_SECS),
                );
                // A stalled actor must not accrue a burst of catch-up ticks.
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                self.governance_timeout = Some(interval);
            }
        } else {
            self.governance_timeout = None;
        }
    }

    /// Drive the TTL expiry (SEC-1 / ADR-049 §9 amendment): run the
    /// fail-closed-before-teardown expiry pipeline on owned state, clear the
    /// fired arm, and report whether the actor may DESPAWN — i.e. the context
    /// reached a terminal lifecycle state, the cleanup fully completed, AND the
    /// terminal `Expired` state is durably persisted.
    ///
    /// Called from BOTH the one-shot TTL arm (Arm 2) and the bounded
    /// [`Self::ttl_expiry_retry`] arm (Arm 2b). The TTL terminal transition +
    /// key destruction are Class-S fail-closed (persisted BEFORE this can return
    /// `true` → despawn), so a hostile-relay stall cannot cancel the durable
    /// terminal state and re-open a resurrection window. The relay/event-log I/O
    /// is bounded inside `handle_ttl_expiry`; the fail-closed persist runs
    /// outside that bound.
    ///
    /// # Retry (SEC-1)
    ///
    /// On an INCOMPLETE expiry (a transient key-destruction failure, an
    /// event-log stall, or a fail-closed persist failure) the context is still
    /// terminal but the actor must NOT despawn — a destroyed-but-unrecorded key
    /// or an undurable terminal state would be lost. The actor keeps itself
    /// alive, stores the partial `completed_steps` in
    /// [`Self::ttl_expiry_completed`], and re-arms [`Self::ttl_expiry_retry`] so
    /// a later tick re-runs ONLY the failed step. The prior code silently
    /// discarded the inner error and despawned unconditionally on `Expired`.
    async fn on_ttl_tick(&mut self) -> bool {
        // Clone the handle first so the `&state.handle` read does not
        // overlap the `&mut state` expiry borrow. `state`/`deps` are
        // disjoint fields, so the simultaneous borrows below are allowed.
        let handle = self.state.handle.clone();

        // Run the fail-closed expiry, carrying the completed-steps bitmask from
        // any prior attempt so only the failed step re-runs. `handle_ttl_expiry`
        // wraps ONLY the relay/event-log I/O in `timeout(HANDLER_TIMEOUT)`; the
        // fail-closed terminal persist runs OUTSIDE that bound (SEC-1), so NO
        // outer timeout here (an outer wrap would re-expose the persist to
        // relay-stall cancellation — the exact bug this pass fixes).
        let outcome = crate::context::ttl_close_helpers::handle_ttl_expiry(
            &mut self.state,
            &self.deps,
            &handle,
            self.ttl_expiry_completed,
        )
        .await;

        // Persist the running completed-steps bitmask so a retry re-runs only
        // the failed step.
        self.ttl_expiry_completed = outcome.result.completed_steps();

        // The one-shot arm has fired. Clear it. (A retry, if needed, is armed on
        // the dedicated `ttl_expiry_retry` arm below — the `is_active`-gated
        // `ttl_timer` is disarmed by `reconcile_timers` once the FSM leaves
        // `Active`.)
        self.ttl_timer = None;
        self.dirty = true;

        // Surface the inner errors that the prior code silently discarded
        // (SEC-1): a fail-closed terminal-persist failure and/or an incomplete
        // cleanup. `error!`-level so a stuck expiry is visible in production.
        if let Err(ref persist_err) = outcome.persist_result {
            tracing::error!(
                context_id = %self.context_id,
                error = %persist_err,
                "TTL terminal Expired persist failed (fail-closed, keep-direction); \
                 keeping actor alive to retry — FSM NOT rolled back (SEC-1)"
            );
        }
        if outcome.result.is_aborted() {
            // A3: the single-source deadline was None (promotion / no-TTL /
            // absent-genesis log) — a DELIBERATE benign no-op, NOT a failed
            // cleanup. `handle_ttl_expiry` already logged the abort and cleared
            // the stale deadline; do not emit the misleading "retrying" error
            // below (nothing failed and no retry is armed — the FSM stays
            // Active/non-terminal, so the else-branch disarms).
        } else if outcome.result.has_failures() {
            tracing::error!(
                context_id = %self.context_id,
                result = %outcome.result,
                "TTL expiry cleanup incomplete; keeping actor alive to retry the \
                 failed step (SEC-1)"
            );
        }

        // Terminal-exit signal: TTL expiry transitions the context to the
        // terminal `Expired` state. `state()` is a lock-free atomic load
        // (ADR-049 §10). `ContextState::is_terminal()` is the closed-by-
        // construction permanent-terminal predicate (`Expired | Closed |
        // Tombstoned`; N5) — an exhaustive match, so a future variant forces a
        // terminality decision here rather than silently falling outside an
        // ad-hoc set.
        let terminal = handle.state().is_terminal();

        // DESPAWN only when the context is terminal AND the cleanup fully
        // completed AND the terminal `Expired` state is DURABLE (persist ok).
        // Any weaker condition would either lose an undestroyed key (incomplete
        // cleanup) or let a crash resurrect the context as `Active` against a
        // stale snapshot (undurable terminal state) — the SEC-1 window.
        if terminal && outcome.result.is_complete() && outcome.persist_result.is_ok() {
            // Clear the retry arm (a prior incomplete attempt may have armed it)
            // before reporting terminal so `run()` despawns cleanly. Reset the
            // retry counter — the expiry converged.
            self.ttl_expiry_retry = None;
            self.ttl_expiry_retries = 0;
            return true;
        }

        if terminal {
            // Terminal but not fully durable/complete: KEEP the actor alive and
            // re-arm a bounded retry so a later tick re-runs the failed step
            // (SEC-1). Independent of the `is_active`-gated `ttl_timer`
            // (disarmed now the FSM is terminal); `reconcile_timers` never
            // touches this arm.
            //
            // Bounded EXPONENTIAL backoff (M2): the delay grows
            // `TTL_EXPIRY_RETRY_BASE · 2^(n−1)` capped at `TTL_EXPIRY_RETRY_CAP`,
            // so a permanently-wedged local dependency does not spin the actor
            // at a fixed 5 s forever. Fail-closed direction is preserved — the
            // actor still never despawns with an undurable terminal state.
            //
            // ACCEPTED crash-window residuals at this pending-retry point
            // (ADR-049 §9 TTL carve-out; NOT resurrection or an access-control
            // bypass — the persisted snapshot is already TERMINAL, restore skips
            // non-`Active` contexts, and B8 refuses re-create):
            //  - L2 (black-hat P3-005): the retry state (that a `ContextExpired`
            //    leaf append is still pending) lives only in this resident
            //    actor's `ttl_expiry_completed` bitmask, not the persisted
            //    snapshot. A crash DURING the pending retry drops the
            //    not-yet-appended leaf — a missing PROVENANCE leaf only; the
            //    context stays terminal for good.
            //  - L4 (security): when key destruction itself is the still-failing
            //    step, a crash here can leave that context's key material
            //    ORPHANED in MLS storage. This is a STORAGE-HYGIENE residual —
            //    the ciphertext is already unreadable to non-holders and the
            //    context is terminal, so no access-control property is broken.
            // Both are accepted this pass; a restore-path reconciliation
            // (re-append the terminal leaf / re-destroy orphaned terminal-snapshot
            // keys) is possible FUTURE hardening, not built here.
            self.ttl_expiry_retries = self.ttl_expiry_retries.saturating_add(1);
            let backoff = ttl_expiry_retry_backoff(self.ttl_expiry_retries);

            // Operator-visible stuck signal (M2): once the actor has retried this
            // many times without converging, the terminal cleanup is wedged on a
            // genuinely-failing local dependency (event log / storage) — an
            // OPERATIONAL fault that must be observable, not silently spun. Emit
            // a rate-limited `error!` (only at the threshold and every
            // `TTL_EXPIRY_STUCK_THRESHOLD` retries thereafter) so it is loud but
            // not log-spam.
            if self.ttl_expiry_retries >= TTL_EXPIRY_STUCK_THRESHOLD
                && self
                    .ttl_expiry_retries
                    .is_multiple_of(TTL_EXPIRY_STUCK_THRESHOLD)
            {
                tracing::error!(
                    context_id = %self.context_id,
                    retries = self.ttl_expiry_retries,
                    backoff = ?backoff,
                    result = %outcome.result,
                    "TTL expiry terminal cleanup STUCK: {} consecutive incomplete \
                     attempts — a local dependency (event log / storage) is wedged. \
                     The actor stays alive fail-closed and keeps retrying; operator \
                     intervention required (M2)",
                    self.ttl_expiry_retries,
                );
            }

            self.ttl_expiry_retry = Some(Box::pin(tokio::time::sleep(backoff)));
        } else {
            // Non-terminal fire (a Closing / MigratingOut context whose expiry
            // did NOT reach a terminal leaf): drop `ttl_armed_deadline` so the
            // next `reconcile_timers` re-evaluates the arm from live state
            // rather than treating the (unchanged) deadline as already-armed and
            // never re-firing (SEC-2). Belt-and-suspenders — the `is_active`
            // gate in `reconcile_timers` already disarms a non-`Active` context.
            self.ttl_armed_deadline = None;
        }

        false
    }

    /// Drive the governance-timeout interval: run one sweep of the timeout
    /// / consequence pipeline on owned state and null the interval when the
    /// sweep signals stop (context no longer `Active`). A later reconcile
    /// re-arms it if the context returns to `Active`.
    async fn on_governance_timeout(&mut self) {
        // `state`/`deps` are disjoint fields — simultaneous borrows are ok.
        let outcome =
            handlers::governance::evaluate_governance_timeouts(&mut self.state, &self.deps).await;
        if outcome.mutated {
            self.dirty = true;
        }
        // `Ok(false)` (context closing / not Active) stops the interval;
        // `Ok(true)` keeps the 60 s cadence auto-refiring. The actor owns its
        // state exclusively, so there is no lock contention to retry — the
        // sweep either records progress (`Ok(true)`) or signals stop
        // (`Ok(false)`).
        if !matches!(outcome.result, Ok(true)) {
            self.governance_timeout = None;
        }
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
    /// The convergent creation instant the TTL-expiry actor tests use — matches
    /// the `1_700_000_000` passed to `new_for_test_encrypted` / the past-deadline
    /// helper. Post pass-4e (E1) the create base is the PRUNE-IMMUNE snapshot
    /// `creation_timestamp_secs + params.ttl`; the test states set
    /// `creation_timestamp_secs` to this value via `new_for_test_encrypted`, so
    /// `convergent_ttl_deadline` yields `T0 + params.ttl` (not `None`, which would
    /// ABORT the expiry per A3). The seeded genesis leaf below is realistic history
    /// but is no longer read for the base.
    #[cfg(feature = "testing")]
    const TTL_TEST_CREATION_TS: u64 = 1_700_000_000;

    /// A genesis `ContextCreated` leaf at [`TTL_TEST_CREATION_TS`], returned by the
    /// expiry-test event-log doubles' `event_log_entries`. Post pass-4e the
    /// derivation does NOT read this leaf for the base (the base is the prune-immune
    /// snapshot `creation_timestamp_secs + params.ttl`); it is retained so the test
    /// histories stay realistic.
    #[cfg(feature = "testing")]
    fn ttl_seed_created_leaf() -> scp_event_log::Event {
        scp_event_log::Event {
            event_type: scp_event_log::EventType::ContextCreated,
            actor_did: scp_did::DID("did:example:ttl-test-creator".to_owned()),
            timestamp: TTL_TEST_CREATION_TS,
            sequence: 0,
            payload: scp_event_log::EventPayload::default(),
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        }
    }

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
        #[cfg(feature = "testing")]
        fn event_log_entries(
            &self,
            _id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError>
        {
            Ok(Some(vec![ttl_seed_created_leaf()]))
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

    // -----------------------------------------------------------------
    // SEC-1 / ADR-049 §9 amendment — fail-closed TTL expiry before teardown.
    //
    // These drive the actor's real run loop through a TTL fire and assert the
    // SEC-1 properties: the terminal `Expired` state is persisted FAIL-CLOSED
    // OUTSIDE the relay/event-log transport timeout (so a hostile-relay stall
    // cannot cancel the durable transition and re-open a resurrection window),
    // and an INCOMPLETE expiry keeps the actor alive to retry (carrying the
    // completed-steps bitmask) rather than despawning with unfinished cleanup.
    // -----------------------------------------------------------------

    /// Build `ActorDeps` with caller-supplied transport + event-log providers
    /// (the SEC-1 tests inject a stalling / flaky event log) plus persistence.
    /// Mirrors [`new_test_deps_with_persistence`].
    #[cfg(feature = "testing")]
    async fn new_test_deps_with_providers(
        persistence: Box<dyn crate::context::persistence::ContextPersistence>,
        transport: Box<dyn crate::context::builder::ContextTransportProvider>,
        event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
    ) -> deps::ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_did::DID;
        use scp_platform::testing::InMemoryStorage;
        use std::sync::Arc;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestSec1Ttl".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
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

        supervisor
            .build_actor_deps(&DID("did:example:sec1-ttl-test".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// Event log whose `append_event` STALLS forever — models a hostile relay /
    /// wedged event-log sink that a `timeout(HANDLER_TIMEOUT)` must bound.
    #[cfg(feature = "testing")]
    struct StallingEventLog;
    #[cfg(feature = "testing")]
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for StallingEventLog {
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
            std::future::pending::<()>().await;
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        // Reading is fast (a seeded genesis leaf) even though `append` stalls; the
        // deadline base comes from the prune-immune snapshot so expiry proceeds
        // (A3). The STALL is exercised on `append_event`, the op under test.
        fn event_log_entries(
            &self,
            _id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError>
        {
            Ok(Some(vec![ttl_seed_created_leaf()]))
        }
    }

    /// Event log whose `append_event` FAILS on the first attempt then succeeds —
    /// a transient cleanup-step failure the actor must retry. (Key destruction
    /// itself is not independently injectable: `MlsCryptoProvider::destroy_*`
    /// are inherent DashMap ops that always return `Ok`; a transient event-log
    /// failure exercises the IDENTICAL incomplete-cleanup → keep-alive → retry
    /// path SEC-1ii guards.)
    #[cfg(feature = "testing")]
    #[derive(Clone, Default)]
    struct FlakyEventLog {
        // `Arc`-shared so the test keeps a handle to read the counters while the
        // deps own a `Box<dyn …>` clone.
        attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        successes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    #[cfg(feature = "testing")]
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for FlakyEventLog {
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
            use std::sync::atomic::Ordering;
            let n = self.attempts.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Err(
                    scp_protocol::context::builder::ContextCreationError::EventLogFailed(
                        "fixture: transient event-log append failure (first attempt)".to_owned(),
                    ),
                );
            }
            self.successes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        // Reading returns a seeded genesis leaf (realistic history); the deadline
        // base comes from the prune-immune snapshot so expiry proceeds (A3). The
        // transient FAILURE under test is on `append_event`, not the read.
        fn event_log_entries(
            &self,
            _id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError>
        {
            Ok(Some(vec![ttl_seed_created_leaf()]))
        }
    }

    /// Build an `Active` encrypted test state with the TTL deadline already in
    /// the past, so `reconcile_timers` arms a `sleep(0)` that fires the TTL
    /// expiry on the actor's first loop turn (no `advance` needed to fire it).
    #[cfg(feature = "testing")]
    fn active_state_with_past_ttl(ctx_byte: u8, now_secs: u64) -> state::PerContextState {
        let context_id_hex = hex_encode_context_id(&[ctx_byte; 32]);
        let mut state = state::PerContextState::new_for_test_encrypted(
            [ctx_byte; 32],
            TTL_TEST_CREATION_TS,
            scp_did::DID("did:example:sec1-admin".to_owned()),
        );
        // A finite params.ttl so the single-source `convergent_ttl_deadline`
        // (prune-immune snapshot `creation_timestamp_secs + params.ttl`) yields a
        // real base. Without
        // a finite ttl AND a genesis leaf the derivation is `None` and
        // `handle_ttl_expiry` ABORTS (A3), so the scalar-armed expiry never fires.
        state.handle = crate::context::ContextHandle::new(
            context_id_hex,
            scp_protocol::context::params::ContextParams {
                ttl: Some(std::time::Duration::from_hours(1)),
                ..Default::default()
            },
        );
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("transition test handle to Active");
        // Deadline in the past ⇒ `reconcile_timers` derives `remaining = 0`.
        state.ttl.timer.deadline_unix_secs = Some(now_secs.saturating_sub(1));
        state
    }

    /// SEC-1i (MUST FAIL pre-fix): with the event-log I/O stalling past
    /// `HANDLER_TIMEOUT`, the terminal `Expired` state is persisted FAIL-CLOSED
    /// BEFORE the actor could tear down, and the actor stays alive to retry the
    /// unfinished cleanup. Pre-fix, the terminal persist was best-effort AFTER
    /// the timed-out I/O (so a relay stall cancelled it, leaving only a
    /// post-despawn coalesce drain to record `Expired` — a resurrection window)
    /// AND the actor despawned unconditionally on `Expired` (mailbox closed).
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn ttl_expiry_persists_before_despawn_with_stalling_transport() {
        let recorder = RecordingPersistence::new();
        let deps = new_test_deps_with_providers(
            Box::new(recorder.clone()),
            Box::new(crate::context::builder::NotConfiguredTransportProvider),
            Box::new(StallingEventLog),
        )
        .await;
        tokio::time::pause();

        let now = deps.clock.now_secs();
        let state = active_state_with_past_ttl(0x71, now);
        let ctx = hex_encode_context_id(&[0x71u8; 32]);

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        // The fail-closed Phase-1 persist runs BEFORE (and outside) the stalling
        // I/O, so it lands without any `advance`. A bounded virtual guard turns a
        // regression (no fail-closed persist) into a legible failure, not a hang.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            recorder.persisted.notified(),
        )
        .await
        .expect("the terminal Expired state must be persisted fail-closed (SEC-1)");

        let snap = recorder
            .last_snapshot()
            .expect("fail-closed persist recorded a snapshot");
        assert_eq!(
            snap.state,
            scp_protocol::context::ContextState::Expired,
            "the durable snapshot must be Expired BEFORE any teardown — anti-resurrection \
             keys off this (a stale Active snapshot would resurrect on respawn)"
        );

        // Advance past the I/O transport budget so the stalled event-log append
        // times out. Post-fix: cleanup is incomplete ⇒ the actor keeps itself
        // alive and re-arms a retry (it does NOT despawn). Pre-fix: the actor
        // despawned here (mailbox closed).
        tokio::time::advance(
            handlers::ttl_close::HANDLER_TIMEOUT + std::time::Duration::from_secs(1),
        )
        .await;

        let state_after = handle
            .send(|reply| {
                ContextCommand::Queries(QueriesCommand::ReadContextState {
                    context_id: ctx.clone(),
                    reply,
                })
            })
            .await
            .expect("actor is still alive after an INCOMPLETE expiry (SEC-1 keep-alive)");
        assert_eq!(
            state_after,
            scp_protocol::context::ContextState::Expired,
            "the still-alive actor reports the terminal Expired state"
        );

        drop(handle);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), actor_task).await;
    }

    /// M2 (bounded exponential TTL-expiry backoff): the retry delay grows
    /// `base · 2^(n−1)` and saturates at the cap — it is genuinely bounded, not
    /// the pre-fix fixed-5 s/uncapped schedule the comment mislabelled "bounded
    /// backoff". A pure-function test — NOT gated on `testing` (it needs no
    /// testing-only helpers).
    #[test]
    fn ttl_expiry_retry_backoff_is_bounded_exponential() {
        // 0 and 1 both map to the base (first attempt).
        assert_eq!(ttl_expiry_retry_backoff(0), TTL_EXPIRY_RETRY_BASE);
        assert_eq!(ttl_expiry_retry_backoff(1), TTL_EXPIRY_RETRY_BASE);
        // Doubles each attempt: 5, 10, 20, 40, 80, 160 s.
        assert_eq!(ttl_expiry_retry_backoff(2), Duration::from_secs(10));
        assert_eq!(ttl_expiry_retry_backoff(3), Duration::from_secs(20));
        assert_eq!(ttl_expiry_retry_backoff(4), Duration::from_secs(40));
        assert_eq!(ttl_expiry_retry_backoff(5), Duration::from_secs(80));
        assert_eq!(ttl_expiry_retry_backoff(6), Duration::from_secs(160));
        // Saturates at the cap and NEVER exceeds it, even for pathological n.
        assert_eq!(ttl_expiry_retry_backoff(7), TTL_EXPIRY_RETRY_CAP);
        assert_eq!(ttl_expiry_retry_backoff(100), TTL_EXPIRY_RETRY_CAP);
        assert_eq!(ttl_expiry_retry_backoff(u32::MAX), TTL_EXPIRY_RETRY_CAP);
        assert!(ttl_expiry_retry_backoff(u32::MAX) <= TTL_EXPIRY_RETRY_CAP);
    }

    /// M2 companion (multi-round backoff across two incomplete retries): two
    /// consecutive retries grow the delay `base → 2·base` — asserting
    /// `backoff(2) == 10 s` (double the 5 s base) so the exponential schedule is
    /// exercised across MORE than one round, not just the first.
    #[test]
    fn ttl_expiry_retry_backoff_grows_across_two_rounds() {
        // Round 1 (retry #1) uses the base; round 2 (retry #2) doubles it.
        assert_eq!(ttl_expiry_retry_backoff(1), TTL_EXPIRY_RETRY_BASE);
        assert_eq!(ttl_expiry_retry_backoff(2), TTL_EXPIRY_RETRY_BASE * 2);
        assert_eq!(ttl_expiry_retry_backoff(2), Duration::from_secs(10));
        // Strictly increasing across the two rounds (genuinely exponential).
        assert!(ttl_expiry_retry_backoff(2) > ttl_expiry_retry_backoff(1));
    }

    /// SEC-1ii (MUST FAIL pre-fix): an INCOMPLETE cleanup (a transient event-log
    /// append failure) keeps the actor alive; a bounded retry re-runs ONLY the
    /// failed step (carrying `prior_completed`) until the expiry is complete and
    /// durable, and only THEN despawns. Pre-fix, `on_ttl_tick` discarded the
    /// inner error and despawned on `Expired` after ONE attempt — the append
    /// never succeeded (0 successful appends).
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn incomplete_cleanup_keeps_actor_alive_and_retries() {
        use std::sync::atomic::Ordering;

        let recorder = RecordingPersistence::new();
        // `FlakyEventLog` is `Arc`-shared internally, so a clone handed to the
        // deps and the clone kept here observe the SAME counters.
        let flaky = FlakyEventLog::default();
        let deps = new_test_deps_with_providers(
            Box::new(recorder.clone()),
            Box::new(crate::context::builder::NotConfiguredTransportProvider),
            Box::new(flaky.clone()),
        )
        .await;
        tokio::time::pause();

        let now = deps.clock.now_secs();
        let state = active_state_with_past_ttl(0x72, now);

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        // First attempt fires immediately: transition Expired + fail-closed
        // persist land, but the event-log append fails ⇒ incomplete ⇒ retry
        // armed, actor stays alive.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            recorder.persisted.notified(),
        )
        .await
        .expect("first attempt persists the terminal state fail-closed");

        // Drive the bounded retry: it re-runs ONLY the failed event-log append
        // (transition + key destruction were carried in `prior_completed`), which
        // now succeeds ⇒ complete + durable ⇒ despawn. The handle is held across
        // this so the actor does NOT exit early via inbox-close (a dropped handle
        // makes `biased` Arm 1 `recv()→None→break` win over the retry arm); the
        // retry's own despawn is what ends the task.
        // The FIRST retry uses the base backoff (`ttl_expiry_retry_backoff(1)`).
        tokio::time::advance(ttl_expiry_retry_backoff(1) + std::time::Duration::from_secs(1)).await;

        // The actor despawns once the retry completes — its task joins.
        tokio::time::timeout(std::time::Duration::from_secs(2), actor_task)
            .await
            .expect("the actor task exits after a COMPLETE + durable expiry")
            .expect("actor task joins cleanly");
        drop(handle);

        assert_eq!(
            flaky.successes.load(Ordering::SeqCst),
            1,
            "the failed event-log append must be RETRIED to exactly one success \
             (SEC-1ii); pre-fix the actor despawned after the first failure (0 successes)"
        );
        assert_eq!(
            flaky.attempts.load(Ordering::SeqCst),
            2,
            "exactly two append attempts: the transient failure + the single retry \
             (retry re-runs ONLY the failed step)"
        );
    }

    /// B10 (MUST FAIL pre-fix): the FFI `ExecuteTtlClose` path must transition
    /// and FAIL-CLOSED persist the ACTOR's OWN state to `Expired`. Pre-fix,
    /// `handle_execute_ttl_close` built a THROWAWAY `ContextHandle`, transitioned
    /// IT, and left the actor's real `cell.handle` (and persisted snapshot)
    /// `Active`.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn execute_ttl_close_transitions_real_context_state() {
        let recorder = RecordingPersistence::new();
        let deps = new_test_deps_with_providers(
            Box::new(recorder.clone()),
            Box::new(crate::context::builder::NotConfiguredTransportProvider),
            Box::new(TestEventLog),
        )
        .await;

        let ctx = hex_encode_context_id(&[0x74u8; 32]);
        let mut state = state::PerContextState::new_for_test_encrypted(
            [0x74u8; 32],
            TTL_TEST_CREATION_TS,
            scp_did::DID("did:example:sec1-admin".to_owned()),
        );
        // Finite params.ttl so the single-source `convergent_ttl_deadline`
        // (prune-immune snapshot `creation_timestamp_secs + ttl`) yields a real
        // deadline; otherwise `handle_ttl_expiry` ABORTS (A3) and the FFI
        // ExecuteTtlClose would no-op instead of transitioning to Expired.
        state.handle = crate::context::ContextHandle::new(
            ctx.clone(),
            scp_protocol::context::params::ContextParams {
                ttl: Some(std::time::Duration::from_hours(1)),
                ..Default::default()
            },
        );
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("transition to Active");

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        handle
            .send(|reply| {
                ContextCommand::TtlClose(
                    crate::context::actor::commands::TtlCloseCommand::ExecuteTtlClose {
                        payload: Box::new(crate::context::actor::commands::TtlContextPayload {
                            context_id: ctx.clone(),
                            params: scp_protocol::context::params::ContextParams::default(),
                        }),
                        reply,
                    },
                )
            })
            .await
            .expect("ExecuteTtlClose replies Ok on the real handle");

        // The actor's REAL lifecycle state is now Expired (pre-fix: still Active,
        // because only a throwaway handle was transitioned).
        let live_state = handle
            .send(|reply| {
                ContextCommand::Queries(QueriesCommand::ReadContextState {
                    context_id: ctx.clone(),
                    reply,
                })
            })
            .await
            .expect("read the actor's real lifecycle state");
        assert_eq!(
            live_state,
            scp_protocol::context::ContextState::Expired,
            "ExecuteTtlClose must transition the ACTOR's real handle to Expired (B10)"
        );

        // ...and the fail-closed persist recorded that Expired state durably.
        let snap = recorder
            .last_snapshot()
            .expect("ExecuteTtlClose fail-closed persist recorded a snapshot");
        assert_eq!(
            snap.state,
            scp_protocol::context::ContextState::Expired,
            "ExecuteTtlClose must FAIL-CLOSED persist the actor's Expired state (B10 + SEC-1)"
        );

        handle.send_shutdown().await.expect("shutdown acks");
        actor_task.await.expect("actor task joins");
    }

    /// Persistence double that FAILS the FIRST fail-closed persist of a terminal
    /// `Expired` snapshot, then succeeds — so a test can exercise the Phase-1
    /// persist-failure branch of `handle_ttl_expiry` (L1). Non-`Expired`
    /// persists (e.g. any coalesced pre-expiry write) always succeed, so the
    /// injected failure targets exactly the terminal fail-closed persist.
    #[cfg(feature = "testing")]
    #[derive(Clone, Default)]
    struct FailFirstExpiredPersist {
        expired_attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        first_fail_observed: std::sync::Arc<tokio::sync::Notify>,
        last: std::sync::Arc<arc_swap::ArcSwapOption<crate::context::state::ContextSnapshot>>,
    }
    #[cfg(feature = "testing")]
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for FailFirstExpiredPersist {
        async fn persist_context(
            &self,
            _context_id: &str,
            snapshot: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            use std::sync::atomic::Ordering;
            if snapshot.state == scp_protocol::context::ContextState::Expired {
                let n = self.expired_attempts.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // The FIRST terminal Expired persist fails fail-closed.
                    self.first_fail_observed.notify_one();
                    return Err("fixture: first terminal Expired persist fails".into());
                }
            }
            self.last.store(Some(std::sync::Arc::new(snapshot.clone())));
            Ok(())
        }
        async fn load_context(
            &self,
            _context_id: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(self.last.load_full().map(|s| (*s).clone()))
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
                .last
                .load_full()
                .map(|s| vec![s.context_id.clone()])
                .unwrap_or_default())
        }
    }

    /// Event-log double that always succeeds and COUNTS `ContextExpired` append
    /// attempts — the observable leaf whose gating L1 asserts.
    #[cfg(feature = "testing")]
    #[derive(Clone, Default)]
    struct ContextExpiredAppendCounter {
        context_expired_appends: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    #[cfg(feature = "testing")]
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for ContextExpiredAppendCounter {
        async fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _id: &[u8; 32],
            event_type: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            if event_type == scp_event_log::EventType::ContextExpired {
                self.context_expired_appends
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        // Seed a genesis leaf (realistic history); the deadline base comes from the
        // prune-immune snapshot so expiry proceeds (A3) rather than aborting — the
        // L1 gating under test is the persist→leaf ordering, not the derivation.
        fn event_log_entries(
            &self,
            _id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError>
        {
            Ok(Some(vec![ttl_seed_created_leaf()]))
        }
    }

    /// L1 (leaf append gated on the fail-closed persist succeeding): a Phase-1
    /// terminal-`Expired` persist FAILURE must NOT append the observable
    /// `ContextExpired` leaf that round — the leaf must announce only a DURABLE
    /// terminal state. The actor stays alive (keep-direction) and the bounded
    /// retry re-runs persist + append; once the persist succeeds the leaf appears
    /// exactly once. Pre-fix, Phase 2 ran unconditionally, so the leaf was
    /// appended ahead of the durable terminal snapshot.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn phase1_persist_failure_defers_leaf_append_until_durable() {
        use std::sync::atomic::Ordering;

        let persistence = FailFirstExpiredPersist::default();
        let counter = ContextExpiredAppendCounter::default();
        let deps = new_test_deps_with_providers(
            Box::new(persistence.clone()),
            Box::new(crate::context::builder::NotConfiguredTransportProvider),
            Box::new(counter.clone()),
        )
        .await;
        tokio::time::pause();

        let now = deps.clock.now_secs();
        let state = active_state_with_past_ttl(0x77, now);

        let (tx, rx) = mpsc::channel::<ContextCommand>(4);
        let actor = ContextActor::new(state, deps, rx);
        let actor_task = tokio::spawn(actor.run());
        let handle = ContextActorHandle::from_sender(tx);

        // First attempt fires immediately: transition Expired + key destruction
        // land, but the fail-closed Expired persist FAILS ⇒ Phase 2 (leaf append)
        // is skipped this round ⇒ actor stays alive with a retry armed.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            persistence.first_fail_observed.notified(),
        )
        .await
        .expect("the first terminal Expired persist is attempted (and fails)");

        assert_eq!(
            counter.context_expired_appends.load(Ordering::SeqCst),
            0,
            "no ContextExpired leaf may be appended while the terminal Expired \
             persist is not durable (L1)"
        );

        // Drive the bounded retry: the persist now succeeds ⇒ Phase 2 runs ⇒ the
        // leaf appends (exactly once) ⇒ complete + durable ⇒ despawn.
        tokio::time::advance(ttl_expiry_retry_backoff(1) + std::time::Duration::from_secs(1)).await;

        tokio::time::timeout(std::time::Duration::from_secs(2), actor_task)
            .await
            .expect("the actor task exits after a COMPLETE + durable expiry")
            .expect("actor task joins cleanly");
        drop(handle);

        assert_eq!(
            counter.context_expired_appends.load(Ordering::SeqCst),
            1,
            "the ContextExpired leaf must appear EXACTLY ONCE, only after a retry \
             whose fail-closed persist succeeded (L1)"
        );
        assert!(
            persistence.expired_attempts.load(Ordering::SeqCst) >= 2,
            "the terminal Expired persist must have been retried after its first \
             failure (L1)"
        );
    }
}
