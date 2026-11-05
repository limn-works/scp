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
//! - [`scp_runtime_types::context::actor::sequence::SequenceReservation`] — RAII guard around a reserved
//!   send-sequence number. Drop rolls back; explicit `commit()` makes
//!   the reservation durable.
//! - [`scp_runtime_types::context::actor::sequence::SendSequenceTracker`] — minimal monotonic counter the
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
//! - [`crate::context::domains::DomainHandlers`] — the per-domain dispatch
//!   handlers, one `Arc<dyn ...>` per domain crate (ADR-070). Each domain
//!   crate's `src/handler.rs` owns the real actor-shape dispatch for its
//!   domain, operating on the actor's owned state (`&mut ClassSCell`) and
//!   capability-reduced [`deps::ActorDeps`].

pub mod class_s;
#[cfg(any(test, feature = "testing"))]
mod class_s_testing_access;
pub mod commands;
pub mod deps;
pub mod handle;
pub mod outcome;
pub mod pseudonym_rotation;
pub mod signer;
pub mod state;

pub use commands::{
    BroadcastCommand, ContextCommand, EconomyCommand, GovernanceCommand, LifecycleCommand,
    LifecycleControlCommand, MessagingCommand, OutletsCommand, QueriesCommand, SagaPhaseMessage,
    StandingCommand, TrustRecoveryCommand, TtlCloseCommand,
};
pub use deps::ActorDeps;
pub use handle::{ContextActorHandle, HANDLER_TIMEOUT, REPLY_TIMEOUT, SEND_TIMEOUT};
// Bounded reply-await mechanics: the supervisor reply-await sites and the `?Send`
// recovery path (`crate::identity::recovery`) route through the single helper.
pub(crate) use handle::bounded_reply_await;
scp_runtime_types::pub_under_testing! {
    pub(crate) use handle::BoundedReplyError;
}
pub use outcome::Outcome;
pub use signer::{CommandSigner, SIGN_TIMEOUT};
pub use state::{
    AuthorKeyEntry, BroadcastRecvTracker, BroadcastState, ContextCryptoState, ContextEventLog,
    ContextLifecycleState, ContextModeState, ContextRouting, PendingBroadcastKeyRotation,
    PerContextState, RecvSequenceTracker, WelcomeProcessing,
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

scp_runtime_types::pub_under_testing! {
    /// Coalesced-persistence interval. ADR-049 §Decision 9 (50 ms): a
    /// burst of mutations that all complete within this window collapse to
    /// a single durable snapshot write. The actor's `run()` loop wakes on
    /// this interval iff `dirty == true` and writes the latest snapshot.
    ///
    /// Core-internal; `pub` under `testing` for the runtime crates' tests (ADR-070 §5).
    pub(crate) const COALESCE_INTERVAL: Duration = Duration::from_millis(50);
}

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

/// Test-only reach into [`ttl_expiry_retry_backoff`] for tests outside this crate. Compiled only
/// under `testing`, so no production or bridge build reaches it (ADR-070 §4).
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn ttl_expiry_retry_backoff_for_test(retries: u32) -> Duration {
    ttl_expiry_retry_backoff(retries)
}

/// Bounded exponential backoff for the n-th (1-based) consecutive incomplete
/// TTL-expiry attempt (M2): `TTL_EXPIRY_RETRY_BASE · 2^(n−1)`, saturating at
/// `TTL_EXPIRY_RETRY_CAP`. `retries == 0` is treated as the first attempt.
#[must_use]
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

/// BASE interval at which the rotation arm repeats an unanswered
/// `PseudonymRotationDue` or `PseudonymAnnouncementPending` signal (spec 09
/// §9.10.4.1). The signal travels on a channel that drops events when no
/// receiver listens or a receiver lags, so the arm repeats it, doubling the
/// interval per consecutive repeat up to [`PSEUDONYM_SIGNAL_RETRY_CAP`], until
/// the rotation state changes.
const PSEUDONYM_SIGNAL_RETRY_BASE: Duration = Duration::from_secs(30);

/// CAP on the rotation-signal backoff: one repeat every
/// 15 min while a signal stays unanswered.
const PSEUDONYM_SIGNAL_RETRY_CAP: Duration = Duration::from_mins(15);

/// Backoff before the n-th (1-based) consecutive repeat of a rotation signal:
/// `PSEUDONYM_SIGNAL_RETRY_BASE · 2^(n−1)`, saturating at
/// [`PSEUDONYM_SIGNAL_RETRY_CAP`].
fn pseudonym_signal_backoff(repeats: u32) -> Duration {
    let shift = repeats.saturating_sub(1).min(32);
    let secs = PSEUDONYM_SIGNAL_RETRY_BASE
        .as_secs()
        .saturating_mul(1u64 << shift)
        .min(PSEUDONYM_SIGNAL_RETRY_CAP.as_secs());
    Duration::from_secs(secs)
}

/// The inputs the rotation arm was last armed from: the persisted rotation
/// state and the context's rotation policy. A change to either re-arms the arm
/// and resets its backoff.
type RotationArmKey = (
    pseudonym_rotation::PseudonymRotationState,
    Option<scp_protocol::context::params::PseudonymRotationPolicy>,
);

/// Governance-timeout evaluation cadence (60 s). Re-exported from
/// [`scp_runtime_types::context::governance::timeout::TIMEOUT_CHECK_INTERVAL_SECS`]
/// so the actor-owned `governance_timeout` interval fires on the exact
/// cadence the retired supervisor-driven timer task used (ADR-049
/// Decision-1 / finding A3 — the timer becomes an actor-owned arm).
const GOVERNANCE_TIMEOUT_SECS: u64 =
    scp_runtime_types::context::governance::timeout::TIMEOUT_CHECK_INTERVAL_SECS;

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
    /// Shared with the paired [`ContextActorHandle`]: `run()` records why it
    /// ended on purpose here before the inbox drops.
    exit: handle::ExitRecord,
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
    /// Instant of the last snapshot write attempt, by a coalesce tick or a
    /// flush, whether or not it landed. The run-loop's persistence arm writes
    /// one coalescing window (50 ms — ADR-049 §Decision 9, "Default: 50ms
    /// write-coalescing per actor") after it, so a failed write is retried
    /// after that window and never in a tight loop. Initialized to "now" at
    /// actor construction.
    // read by the run-loop's persistence coalesce arm
    last_persist_attempt_at: std::time::Instant,
    /// Dirty flag set when any handler's [`outcome::Outcome`] carries
    /// `mutated: true` and when a flush's write fails. Cleared only when a
    /// coalesced write or a flush lands (ADR-049 §Decision 9). Initialized
    /// `false` at actor construction.
    // read by the run-loop's persistence coalesce arm
    dirty: bool,
    /// Count of consecutive inbox dispatches since a timer/persist arm last
    /// got a turn. The `biased` `select!` prioritizes the inbox; this counter
    /// bounds that priority so a saturated inbox cannot starve the timer arms
    /// (see [`MAX_CONSECUTIVE_INBOX`] + the fairness fall-through arm in
    /// `run()`). Reset to 0 whenever a non-inbox arm fires.
    // read + written by the run-loop's fairness bound
    consecutive_inbox: u32,
    /// One-shot pseudonym-rotation arm (spec 09 §9.10.4.1). Armed by
    /// [`Self::reconcile_timers`] while the context is `Active`, uses
    /// pseudonymous routing, and lists the local member: it fires at once when
    /// an announcement is pending or a rotation is due, else at the next
    /// interval boundary. [`Self::on_rotation_tick`] signals and re-arms with
    /// backoff.
    rotation_timer: Option<Pin<Box<Sleep>>>,
    /// The inputs [`Self::rotation_timer`] was armed from; `None` while the
    /// arm is gated off.
    rotation_armed_key: Option<RotationArmKey>,
    /// Consecutive signals the rotation arm sent for the current
    /// [`Self::rotation_armed_key`]; drives [`pseudonym_signal_backoff`].
    rotation_signals: u32,
    /// The push routes ([`crate::context::push_routes::push_routes`]) last observed at the
    /// top of the run loop. A turn that changes them wakes the Supervisor's
    /// push-route watch (`10-infrastructure-and-self-hosting.md` §10.7.1
    /// **Re-registration**), whatever command or timer changed them.
    push_routes_seen: Option<crate::context::push_routes::ContextPushRoutes>,
}

impl ContextActor {
    scp_runtime_types::pub_under_testing! {
        /// Construct a fresh actor that owns [`PerContextState`] and
        /// [`ActorDeps`] directly (introduced by ADR-049 §15).
        ///
        /// This is the production constructor. The owned-state spawn path
        /// `crate::context::supervisor::supervisor::Supervisor::spawn_actor_with_state`
        /// uses it to hand drained `PerContextState` + `ActorDeps` into the
        /// actor task, making the actor their sole owner.
        ///
        /// # Construction of auxiliary fields
        ///
        /// - `ttl_timer`, `governance_timeout`, `ttl_armed_deadline` start as
        ///   `None`. The run loop's `Self::reconcile_timers` arms them from
        ///   owned state at the top of every turn (TTL from
        ///   `state.ttl.timer.deadline_unix_secs`, governance while `Active`).
        /// - `last_persist_attempt_at` starts at `Instant::now()` so a fresh
        ///   actor's first coalescing window runs for the full duration
        ///   before the first persist.
        /// - `dirty` starts `false` — no mutations yet.
        ///
        /// # `context_id` derivation
        ///
        /// The actor's `String` id is the state's handle id: the key the
        /// supervisor registers the actor under, persists its snapshot under,
        /// and tags its events with. It is not re-derived from the 32-byte
        /// `state.context_id`: that hash is the SHA-256 of any id that is not
        /// lowercase hex, so its hex differs from the key, and a snapshot the
        /// actor wrote under it would be a second persisted context that no
        /// restore can reach. Callers therefore do not pass `context_id`
        /// separately — it is sourced from the state payload.
        ///
        /// `pub(crate)`: only `Supervisor::spawn_actor_with_state` constructs actors.
        /// `pub` under `testing`, because `scp-runtime`'s actor tests build one directly.
        pub(crate) fn new(
            state: state::PerContextState,
            deps: deps::ActorDeps,
            inbox: mpsc::Receiver<ContextCommand>,
            exit: handle::ExitRecord,
        ) -> Self {
            let context_id = state.handle.context_id().to_owned();
            let push_routes_seen = crate::context::push_routes::push_routes(&state);
            Self {
                context_id,
                inbox,
                exit,
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
                last_persist_attempt_at: Instant::now(),
                dirty: false,
                consecutive_inbox: 0,
                rotation_timer: None,
                rotation_armed_key: None,
                rotation_signals: 0,
                push_routes_seen,
            }
        }
    }

    /// Dispatch loop. See plan §"ContextActor" — the operational
    /// `tokio::select!`:
    ///
    /// 1. **Inbox** — `mpsc::Receiver::recv` for [`ContextCommand`]s.
    ///    Shutdown commands dispatch and then break the loop.
    /// 2. **TTL timer** — only when `ttl_timer.is_some()`.
    /// 3. **Governance timeout** — only when `governance_timeout.is_some()`.
    /// 4. **Pseudonym rotation** (Arm 3b) — only when
    ///    `rotation_timer.is_some()`.
    /// 5. **Persistence coalesce** (Arm 4) — only when `dirty == true`.
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
        // computes the deadline as `last_persist_attempt_at + COALESCE_INTERVAL`
        // — which is in the future relative to actor-spawn `now()`.
        loop {
            // Reconcile the ACTOR-OWNED timer arms and the push-route watch
            // from owned state before every select (top of run() + after each
            // dispatch, since a dispatch loops back to here). Cheap: re-arms
            // only when the convergent TTL deadline changes or the `Active`
            // state flips (ADR-049 Decision-1 / finding A3), and wakes the
            // watch only when the push routes changed.
            self.reconcile_timers();
            self.note_push_route_change();

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
                            // A flush writes the whole current state, the
                            // write a pending coalesce tick would make. A
                            // flush whose write lands therefore leaves the
                            // actor clean, so no write of the state as it
                            // stood at the flush follows it; one whose write
                            // fails leaves it dirty, so the next coalesce
                            // tick writes again (ADR-049 §Decision 9).
                            let is_flush = matches!(
                                cmd,
                                ContextCommand::Lifecycle(LifecycleCommand::FlushSnapshot { .. })
                            );
                            // `Box::pin` the dispatch future so the large per-command
                            // handler frame lives on the heap, keeping the actor
                            // run-loop future under the `clippy::large_futures`
                            // threshold (the streaming-saga seal handlers added
                            // large stack frames held across `.await`).
                            let succeeded = Box::pin(self.dispatch(cmd)).await;
                            if is_flush {
                                self.record_persist_attempt(succeeded);
                            }
                            if is_shutdown {
                                self.exit.record(handle::DeliberateExit::Shutdown);
                                break;
                            }
                            if is_prepare_replace {
                                // Claimed terminal iff the handler set
                                // `lifecycle_state == Closed`.
                                if matches!(
                                    self.state.lifecycle_state,
                                    state::ContextLifecycleState::Closed
                                ) {
                                    self.exit.record(handle::DeliberateExit::Replaced);
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
                () = one_shot(self.ttl_timer.as_mut()), if self.ttl_timer.is_some() => {
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
                        // lingers in `actors` with a closed mailbox, so a
                        // lifecycle read reaches no actor (the checked read
                        // reports `ActorBusy`, the Option form `None`) instead
                        // of the absent answer a completed expiry gives, and
                        // the context id cannot be re-created.
                        // `despawn_actor` removes our OWN registry entry
                        // (`&self.context_id`) under the supervisor write lock;
                        // safe to call from here — the actor holds no lock, and
                        // the removal has no `.await` while the lock is held.
                        despawn_self_after_ttl_exit(&self.deps.supervisor, &self.context_id).await;
                        self.exit.record(handle::DeliberateExit::Expired);
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
                () = one_shot(self.ttl_expiry_retry.as_mut()), if self.ttl_expiry_retry.is_some() => {
                    self.consecutive_inbox = 0;
                    // Clear the fired retry arm; `on_ttl_tick` re-arms it if the
                    // expiry is still incomplete.
                    self.ttl_expiry_retry = None;
                    if self.on_ttl_tick().await {
                        // Same internal-TTL-exit despawn as Arm 2: no external
                        // despawner for a timer-driven terminal exit.
                        despawn_self_after_ttl_exit(&self.deps.supervisor, &self.context_id).await;
                        self.exit.record(handle::DeliberateExit::Expired);
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

                // --- Arm 3b: pseudonym rotation (one-shot, re-armed) ---
                () = one_shot(self.rotation_timer.as_mut()), if self.rotation_timer.is_some() => {
                    self.consecutive_inbox = 0;
                    self.on_rotation_tick();
                }

                // --- Arm 4: persistence coalesce -------------------
                () = tokio::time::sleep_until(
                    tokio::time::Instant::from_std(
                        self.last_persist_attempt_at + COALESCE_INTERVAL
                    )
                ), if self.dirty => {
                    self.consecutive_inbox = 0;
                    let landed = self.persist_snapshot().await.is_ok();
                    self.record_persist_attempt(landed);
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
        self.final_drain().await;
    }

    /// Records a snapshot write attempt by a coalesce tick or a flush: the
    /// next tick is one coalescing window away, and the actor stays dirty
    /// unless the write `landed`, so a failed write is retried by that tick
    /// (ADR-049 §Decision 9).
    fn record_persist_attempt(&mut self, landed: bool) {
        self.last_persist_attempt_at = Instant::now();
        self.dirty = !landed;
    }

    /// Final drain: writes any pending state before the actor exits. It runs
    /// after the `Shutdown` ack and after every sender dropped, so a caller
    /// that must order work after this write waits for the inbox receiver to
    /// drop (`ContextActorHandle::shutdown_and_await_exit`). No later write
    /// can follow, so a failure is logged at error level.
    async fn final_drain(&mut self) {
        if self.dirty
            && let Err(e) = self.persist_snapshot().await
        {
            tracing::error!(
                context_id = %self.context_id,
                error = %e,
                "the final snapshot write before the actor exits failed; the store \
                 holds the state of the last write that landed"
            );
        }
    }

    /// Dispatch a single command to its matching handler: threads the
    /// actor-owned state/deps through `dispatch_state` into the
    /// per-domain actor-shape `dispatch` entry points. Returns whether the
    /// handler's [`Outcome`] carries `Ok`; the run loop reads it to tell
    /// whether a flush's write landed.
    async fn dispatch(&mut self, cmd: ContextCommand) -> bool {
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
        // Boxed: the routed handler futures carry `ContextParams` across
        // awaits, which puts the inline future above the `large_futures`
        // bound.
        let outcome = Box::pin(Self::dispatch_state(&mut self.state, &self.deps, cmd)).await;
        if outcome.mutated {
            self.dirty = true;
        }
        outcome.result.is_ok()
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
                deps.domains.messaging.dispatch(cell, deps, sub).await
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
                deps.domains.lifecycle.dispatch(cell, deps, sub).await
            }
            ContextCommand::Governance(sub) => {
                // Phase 2A.8 — governance domain fully migrated to
                // actor-shape: every variant reads/mutates
                // `state.governance` through the actor-shape helpers.
                // `Supervisor::dispatch_governance_command` is
                // mailbox-only (typed `ContextNotRegistered` when no
                // actor is registered).
                deps.domains.governance.dispatch(cell, deps, sub).await
            }
            ContextCommand::Broadcast(sub) => {
                // Phase 2A.5 — broadcast domain migrated to the
                // actor-shape handler for non-publish commands.
                // Publish variants still require the custody-generic
                // supervisor shim because `KeyCustody` is not dyn-safe.
                deps.domains.broadcast.dispatch(cell, deps, sub).await
            }
            ContextCommand::Economy(sub) => {
                // Phase 2A.3 — economy domain migrated to the
                // actor-shape handler. Supervisor dispatch falls
                // through to its supervisor-side
                // `dispatch_economy_direct` when a receipt batch has
                // no single owning context actor.
                deps.domains.economy.dispatch(cell, deps, sub).await
            }
            ContextCommand::TrustRecovery(sub) => {
                // Phase 2A.1 — trust_recovery domain migrated to
                // state-owning shape. Per-context variants flow through
                // `deps.domains.trust_recovery.dispatch(cell, deps, sub)`;
                // the cross-context `RecoveryNotifyContact` variant is
                // intercepted on the supervisor before this arm
                // executes (it never reaches the per-context actor
                // mailbox).
                deps.domains.trust_recovery.dispatch(cell, deps, sub).await
            }
            ContextCommand::Standing(sub) => {
                // Phase 2A.2 — standing domain migrated to the
                // actor-shape handler. Supervisor-scoped variants (and
                // commands with no registered target actor) route
                // through the supervisor-side
                // `dispatch_standing_direct` instead of this arm.
                deps.domains.standing.dispatch(deps, sub).await
            }
            ContextCommand::TtlClose(sub) => {
                // Phase 2A.6 — TTL-close domain migrated to the
                // actor-shape handler.
                // `Supervisor::dispatch_ttl_close_command` is
                // mailbox-only: a missing actor surfaces a typed
                // lookup-miss error.
                deps.domains.ttl_close.dispatch(cell, deps, sub).await
            }
            ContextCommand::Outlets(sub) => {
                // Phase 2A.4 -- outlets domain migrated to the
                // actor-shape handler for mailbox-routed hard-rate
                // helpers. `Supervisor::dispatch_outlets_command` is
                // mailbox-first: a missing actor surfaces a typed
                // error on the command's reply oneshot.
                deps.domains.outlets.dispatch(cell, deps, sub).await
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
            ContextCommand::Queries(sub) => deps.domains.queries.dispatch(cell, deps, sub).await,
            // Push domain (§10.7.1): read-only, answered from owned state.
            ContextCommand::Push(sub) => deps.domains.push.dispatch(cell, sub),
            // SagaPhase + LifecycleControl already migrated to the
            // state-owning signature.
            ContextCommand::SagaPhase(msg) => deps.domains.saga.dispatch(cell, deps, msg).await,
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
                deps.domains
                    .lifecycle_control
                    .dispatch(cell, deps, sub)
                    .await
            }
        }
    }

    /// Wakes the Supervisor's push-route watch when the context's push routes
    /// differ from the ones the last turn saw. Every arm loops back to the
    /// top of the run loop, so a join, leave, pseudonym rotation, close,
    /// expiry or tombstone reaches the push registrar through this one check
    /// (`10-infrastructure-and-self-hosting.md` §10.7.1 **Re-registration**).
    fn note_push_route_change(&mut self) {
        let current = crate::context::push_routes::push_routes(&self.state);
        if current != self.push_routes_seen {
            self.push_routes_seen = current;
            self.deps.supervisor.note_push_routes_changed();
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

        self.reconcile_pseudonym_timers(is_active);
    }

    /// Reconciles the pseudonym rotation arm (spec 09 §9.10.4.1) from owned
    /// state; see [`Self::reconcile_timers`]. Armed only while the context is
    /// `Active`, uses pseudonymous routing, and lists the local member, so a
    /// member that left, or a closed or expired context, signals nothing. It
    /// re-arms, resetting the backoff, only when the persisted rotation state
    /// or the policy changes; a committed rotation, a membership trigger, a
    /// policy change, or a cleared announcement flag each change it.
    fn reconcile_pseudonym_timers(&mut self, is_active: bool) {
        let eligible = is_active
            && self.state.routing.local_pseudonym().is_some()
            && self.state.membership.contains(self.deps.crypto.local_did());
        if eligible {
            let key: RotationArmKey = (
                self.state.class_s.pseudonym_rotation.clone(),
                self.state.handle.params().pseudonym_rotation,
            );
            if self.rotation_armed_key.as_ref() != Some(&key) {
                let now_secs = self.deps.clock.now_secs();
                let wake = key.0.wake(key.1.as_ref(), now_secs);
                self.rotation_armed_key = Some(key);
                self.rotation_signals = 0;
                self.rotation_timer = match wake {
                    pseudonym_rotation::RotationWake::AnnouncementPending { .. }
                    | pseudonym_rotation::RotationWake::RotationDue { .. } => {
                        Some(Box::pin(tokio::time::sleep(Duration::ZERO)))
                    }
                    pseudonym_rotation::RotationWake::SleepUntil { boundary_secs } => {
                        Some(Box::pin(tokio::time::sleep(Duration::from_secs(
                            boundary_secs.saturating_sub(now_secs),
                        ))))
                    }
                    pseudonym_rotation::RotationWake::Idle => None,
                };
            }
        } else {
            self.rotation_timer = None;
            self.rotation_armed_key = None;
            self.rotation_signals = 0;
        }
    }

    /// Drives the pseudonym rotation arm (spec 09 §9.10.4.1). Re-reads the
    /// rotation state at the wall clock and:
    ///
    /// - sends `PseudonymAnnouncementPending` or `PseudonymRotationDue` on the
    ///   event channel and re-arms after [`pseudonym_signal_backoff`], so the
    ///   signal repeats until the bridge driver's rotation or re-announcement
    ///   changes the state (which re-arms through
    ///   [`Self::reconcile_pseudonym_timers`]);
    /// - re-arms at the next boundary when nothing is due yet;
    /// - stays disarmed when nothing is scheduled.
    ///
    /// The signals go on the lossy `event_tx` channel only, never into the
    /// receive buffer, so repeats cannot crowd application events out of it.
    /// A send with no receiver is not an error here: the repeat delivers the
    /// signal once a receiver subscribes.
    fn on_rotation_tick(&mut self) {
        self.rotation_timer = None;
        let now_secs = self.deps.clock.now_secs();
        let policy = self.state.handle.params().pseudonym_rotation;
        let wake = self
            .state
            .class_s
            .pseudonym_rotation
            .wake(policy.as_ref(), now_secs);
        let event = match wake {
            pseudonym_rotation::RotationWake::AnnouncementPending { pseudonym_epoch } => {
                scp_protocol::context::membership::ContextEvent::PseudonymAnnouncementPending {
                    pseudonym_epoch,
                }
            }
            pseudonym_rotation::RotationWake::RotationDue { pseudonym_epoch } => {
                scp_protocol::context::membership::ContextEvent::PseudonymRotationDue {
                    pseudonym_epoch,
                }
            }
            pseudonym_rotation::RotationWake::SleepUntil { boundary_secs } => {
                self.rotation_timer = Some(Box::pin(tokio::time::sleep(Duration::from_secs(
                    boundary_secs.saturating_sub(now_secs),
                ))));
                return;
            }
            pseudonym_rotation::RotationWake::Idle => return,
        };
        if let Some(tx) = self.deps.event_tx.as_ref()
            && tx.send((self.context_id.clone(), event)).is_err()
        {
            tracing::debug!(
                context_id = %self.context_id,
                "pseudonym rotation signal has no receiver; it repeats after the backoff"
            );
        }
        self.rotation_signals = self.rotation_signals.saturating_add(1);
        self.rotation_timer = Some(Box::pin(tokio::time::sleep(pseudonym_signal_backoff(
            self.rotation_signals,
        ))));
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
        let outcome = self
            .deps
            .domains
            .ttl_close
            .handle_ttl_expiry(
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
        let outcome = self
            .deps
            .domains
            .governance
            .evaluate_governance_timeouts(&mut self.state, &self.deps)
            .await;
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
    /// [`persist_state_fail_closed`](crate::context::snapshot::persist_state_fail_closed):
    /// it builds the owned
    /// [`ContextSnapshot`](crate::context::state::ContextSnapshot) in a
    /// synchronous prelude BEFORE the `.await` (Decision-7 `Send`
    /// discipline — the returned future borrows only `deps` and the
    /// context-id, never Class-S state), records and warns on a persist
    /// failure, and returns it, so the run loop leaves the actor dirty and
    /// writes again one coalescing window later (§Decision 9). No
    /// Class-S transition *depends on* this path for durability — each
    /// persists fail-closed at its own mutation site — but the coalesced
    /// snapshot still serializes the whole `PerContextState` (Class-S values
    /// included), so this write is a redundant re-persist for Class-S state
    /// and is authoritative only for Class-C.
    #[allow(clippy::needless_pass_by_ref_mut)] // `&mut self` is a `Send` requirement (see doc)
    async fn persist_snapshot(&mut self) -> Result<(), ContextError> {
        // Read-only `Deref`; the returned future captures only `deps`/`context_id`
        // (`use<'d, 'c>`), never Class-S state.
        let state: &state::PerContextState = &self.state;
        let deps: &deps::ActorDeps = &self.deps;
        let context_id: &str = &self.context_id;
        crate::context::snapshot::persist_state_fail_closed(state, deps, context_id).await
    }
}

/// Resolves once `timer` elapses; pending forever when no timer is armed. Each
/// one-shot arm of the actor's `select!` awaits it, guarded by `is_some()`.
/// `Pin<Box<Sleep>>` is a one-shot future: awaiting the pinned mutable
/// reference resolves once the deadline elapses.
async fn one_shot(timer: Option<&mut Pin<Box<Sleep>>>) {
    match timer {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending::<()>().await,
    }
}

/// Removes an actor's own registry entry after a timer-driven terminal exit.
/// When the Supervisor has dropped (ADR-049 Decision 16) its registry dropped
/// with it, so no entry remains to remove; that case logs at debug.
///
/// A free function over the two fields, not a `&self` method: `ContextActor` is
/// `!Sync`, so a `&self` held across the `.await` would make the actor future
/// `!Send`.
async fn despawn_self_after_ttl_exit(
    supervisor: &crate::context::supervisor::handle::SupervisorHandle,
    context_id: &str,
) {
    if let Err(e) = supervisor.despawn_actor(context_id).await {
        tracing::debug!(
            context_id,
            error = %e,
            "TTL exit despawn skipped: supervisor dropped, registry already gone"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
}
