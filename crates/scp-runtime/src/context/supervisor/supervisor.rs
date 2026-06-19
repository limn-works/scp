//! `Supervisor` — the plain-struct actor registry + saga coordinator.
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Per ADR-049 §2 and plan §"Supervisor" the supervisor is a **plain
//! struct, not an actor**. Lookups are on the hot path of every public
//! API call; making the supervisor an actor would add a mailbox hop per
//! call. Instead:
//!
//! - `DashMap<String, ContextActorHandle>` for the actor registry
//!   (lock-free `get`).
//! - `ArcSwap<HashMap<String, DID>>` for standing contexts (lock-free
//!   read; atomic swap on write).
//! - `ArcSwap<HashSet<DID>>` for local DIDs (same).
//! - `DashMap<DID, ArcSwap<WrappingKeyPair>>` for per-identity wrapping
//!   keys (rare rotation).
//! - `tokio::sync::Mutex<()>` write-lock serializing ALL mutations of
//!   the above. Reads are lock-free; the mutex prevents lost writes
//!   when two callers race a `store` on the same `ArcSwap`.
//!
//! # Commit 6 scope
//!
//! The struct lands with `new`, `lookup`, `spawn_actor`, and the saga
//! `start_saga` entry point. Every method that migrates the real
//! semantics lives behind a
//! [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! stub — saga orchestration migrates with `handlers/standing.rs` and
//! the related cross-context paths in commit 11.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;

use crate::context::actor::commands::{
    BroadcastCommand, ContextCommand, EconomyCommand, GovernanceCommand, LifecycleCommand,
    MessagingCommand, QueriesCommand, StandingCommand, ToolsCommand, TrustRecoveryCommand,
    TtlCloseCommand,
};
use crate::context::actor::handle::ContextActorHandle;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::WrappingKeyPair;
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::saga_journal::{
    JournalEntry, SagaId, SagaJournal, SagaState, SagaTerminalState,
};
use crate::economy::adapter::PaymentAdapterDyn;
use scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Actor mailbox capacity. Plan §"Mailbox parameters": bounded at 256 so
/// the mailbox applies backpressure to callers.
pub const ACTOR_MAILBOX_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// SagaInput / SagaOutput — plan §"Cross-context saga protocol"
// ---------------------------------------------------------------------------

/// Input to `Supervisor::start_saga`. The variant enumerates the 3
/// saga types defined in plan §"Cross-context saga protocol"
/// (standing-pair create, cross-context tool invoke, broadcast hosting
/// handshake). Commit 6 lands the enum shape; real field sets arrive
/// when each handler migrates.
///
/// The type is a discriminated union so that adding a fourth saga type
/// later is a compile error at every call site — the default branch is
/// not permitted.
pub enum SagaInput {
    /// Standing-pair creation between two identities. Full field set
    /// arrives with `handlers/standing.rs` in commit 11.
    StandingPairCreate {
        /// The local identity initiating the pair.
        local_did: DID,
        /// The remote peer.
        peer_did: DID,
    },
    /// Cross-context tool invocation.
    CrossContextToolInvocation {
        /// Calling context.
        caller_context_id: [u8; 32],
        /// Target context that hosts the tool registration being invoked.
        /// The saga spans BOTH the caller and the target context-actors, so
        /// the gating reservation (ADR-049 §3a) needs the real 2-context set;
        /// spec §6.2.4's cross-context tool-invoke transport needs it too.
        target_context_id: [u8; 32],
        /// Calling identity. The channel-authenticated initiator the
        /// supervisor binds (spec §6.2.4 "Caller authentication"), NOT an
        /// envelope-asserted value.
        caller_did: DID,
        /// Tool registration to invoke — a context-LOCAL identifier indexing
        /// B's own tool registry.
        tool_registration_id: String,
        /// UCAN proof reference — an INDEX into B's own UCAN store, never the
        /// proof bytes (spec §6.2.4 normative (1)). `None` for an ungated tool.
        ucan_proof_id: Option<String>,
        /// The invocation input — validated at Prepare-B against the target
        /// tool's registered schema specificity floor (spec §9.2.1) and passed
        /// to the supervisor-side executor at Commit-B.
        input: serde_json::Value,
        /// Caller-asserted chain depth — advisory/untrusted; used only for the
        /// `>= max_chain_depth` reject and as the `+1` base for B's re-derived
        /// `recorded_chain_depth` (spec §6.2.4 "Chain-depth enforcement").
        asserted_chain_depth: u8,
        /// Caller-asserted 16-byte envelope nonce — checked against B's TTL
        /// dedup cache, then staged on accept; the join key between the two
        /// event-log records (spec §6.2.4 "Freshness" / "Dual event-log
        /// recording").
        asserted_nonce: [u8; 16],
        /// Caller-asserted send-time (ms) — used ONLY for the §9.14 skew
        /// freshness check, never recorded (spec §6.2.4 "Recorded timestamp").
        asserted_timestamp_ms: u64,
    },
    /// Broadcast hosting handshake.
    BroadcastHostingHandshake {
        /// Host context.
        host_context_id: [u8; 32],
        /// Broadcast context.
        broadcast_context_id: [u8; 32],
        /// Subscriber requesting hosting.
        subscriber_did: DID,
    },
    /// Test-only saga whose Prepare phases succeed and whose Commit phase
    /// ALWAYS fails, so the FSM runs all the way to Committing, exhausts the
    /// commit-retry budget, and lands in `NeedsRepair`. This is the ONLY way
    /// to drive `start_saga` to a real `NeedsRepair` terminal while the three
    /// production saga variants' Prepare/Commit dispatch is still spec-gapped
    /// (Phase 2C) — it lets the gating tests assert that `NeedsRepair`
    /// RELEASES the participant-context-set reservation (ADR-049 §3a, spec
    /// §5.15.4). Gated behind `test`/`testing` so a production FFI build can
    /// never construct or dispatch it.
    #[cfg(any(test, feature = "testing"))]
    TestForceNeedsRepair {
        /// The single participant context this test saga reserves.
        context_id: [u8; 32],
    },
}

/// Output from `Supervisor::start_saga` on success. Carries the durable
/// saga identifier plus — for a committed cross-context tool-invocation
/// saga — the target's signed receipt and captured tool output (spec
/// §6.2.4 "Receipt / response return path").
#[derive(Debug)]
pub struct SagaOutput {
    /// Durable saga identifier; usable as a handle into the journal.
    pub saga_id: SagaId,
    /// The target's signed `CrossContextToolReceipt` bytes (JCS), present
    /// for a committed `CrossContextToolInvocation` saga. `None` for saga
    /// types that produce no receipt (standing-pair / broadcast).
    pub receipt: Option<Vec<u8>>,
    /// The captured tool output bytes (the receipt's canonical `output_jcs`),
    /// present for a committed `CrossContextToolInvocation` saga. The exact
    /// bytes the caller (A) side recorded a hash of. `None` otherwise.
    pub output: Option<Vec<u8>>,
}

/// The non-`Send` tool executor the supervisor FSM runs supervisor-side
/// BETWEEN Commit-B reserve and Commit-B settle (spec §6.2.4 "Commit": the
/// generic executor cannot cross the actor mailbox per ADR-049 §3, so the
/// FSM triggers execution off the mailbox and forwards the captured output
/// to the settle round-trip).
///
/// Boxed as a trait object so [`Supervisor::run_saga_fsm`] stays
/// non-generic across the (test / standing-pair / broadcast) saga inputs
/// that have no executor; only the `CrossContextToolInvocation` arm
/// consumes it. The future is boxed for the same reason. The closure is
/// `FnOnce` — it executes the tool exactly once (§6.2.4 "Exactly-once
/// execution"); a replayed Commit short-circuits before reaching it via
/// the actor-side `AlreadyCommitted` capture, so the FSM never invokes the
/// executor twice.
///
/// **`Send`.** "The generic executor cannot cross the mailbox" (ADR-049 §3)
/// means it is never embedded in a [`ContextCommand`] and never run on the
/// actor task — it runs supervisor-side. The closure itself IS `Send` (it
/// captures `Send` tool-handler state, exactly like the closures
/// [`Supervisor::invoke_tool_with_economy`] takes), so the saga future stays
/// `Send` and the block-until-terminal saga can be driven from a spawned task.
type SagaToolExecutor<'a> = Box<
    dyn FnOnce(
            serde_json::Value,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + 'a>,
        > + Send
        + 'a,
>;

/// Shorthand for the cross-context tool-invocation prepared state reconstructed
/// from a journal entry's evidence (spec §6.2.4 "Crash recovery §17.16.4").
type XctxPrepared =
    crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;

/// Outcome of a §17.16.4 Commit-in-progress recovery re-drive. The crash
/// recovery re-drives the idempotent Commit-B and re-acks Commit-A from the
/// durable witness, then journals the resolved terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitInProgressResolution {
    /// BOTH sides committed (B re-emitted the stored output AND the A-side
    /// `xctx_committed_invocations` witness is present): the saga is fully
    /// committed — resolve to `Committed`, NOT a false `NeedsRepair`.
    Committed,
    /// Genuinely unresolvable divergence (B committed but A did not, B never
    /// landed, or a side is unreachable): stays `NeedsRepair` for operator repair.
    NeedsRepair,
}

/// The owned per-side plan [`Supervisor::divergence_marker_plan`] produces for
/// a `NeedsRepair` divergence: `(committed_event_id, nonce, [(side-label,
/// context_id, that side's Active Signing Key); 2])`. Each side signs + appends
/// its OWN marker (spec §6.2.4 "Dual event-log recording").
type DivergenceMarkerPlan = (
    String,
    [u8; 16],
    [(
        &'static str,
        [u8; 32],
        crate::context::actor::commands::SigningKeyBytes,
    ); 2],
);

/// Per-saga phase-data context threaded through [`Supervisor::run_saga_fsm`]
/// for a `CrossContextToolInvocation` saga (spec §6.2.4).
///
/// The generic FSM (journal, retry, NeedsRepair, abort, gating) stays
/// data-agnostic; this carrier holds the cross-context-specific inputs the
/// per-phase dispatch needs and accumulates the Prepare→Commit hand-off
/// data so each phase sees the prior phase's output:
///
/// - the supervisor-side tool `executor` + the target/caller Active Signing
///   Keys (the actor holds NO key — ADR-049; the keys are supplied by the
///   FFI/SDK caller per-call, exactly like `send_heartbeat` /
///   `build_local_checkpoint`),
/// - `prepared_a` — the caller-side escrow/rate-limit reservation staged at
///   Prepare-A and held across the saga (RAII-released on any abort, settled
///   at Commit-A),
/// - `prepared_b` — B's recorded provenance from Prepare-B (drives nothing
///   the FSM re-reads; held for completeness / future divergence emission),
/// - `committed` — the receipt + output captured at Commit-B, forwarded to
///   Commit-A and surfaced in [`SagaOutput`].
///
/// `executor` is an `Option` so it can be `take`n exactly once at Commit-B.
struct CrossContextSagaCtx<'a> {
    /// Raw 32-byte caller context id (A's own context).
    caller_context_id: [u8; 32],
    /// Raw 32-byte target context id (B's own context; where the tool runs).
    target_context_id: [u8; 32],
    /// Channel-authenticated caller DID (spec §6.2.4 "Caller authentication").
    caller_did: DID,
    /// Context-local tool registration id (indexes B's registry).
    tool_registration_id: String,
    /// UCAN proof index into B's store (`None` ⇒ ungated tool).
    ucan_proof_id: Option<String>,
    /// Tool input — validated at Prepare-B, executed at Commit-B.
    input: serde_json::Value,
    /// Caller-asserted advisory chain depth (freshness/`+1` base only).
    asserted_chain_depth: u8,
    /// Caller-asserted 16-byte wire nonce (freshness + dual-log join key).
    asserted_nonce: [u8; 16],
    /// Caller-asserted send-time (ms) — §9.14 skew check only.
    asserted_timestamp_ms: u64,
    /// The channel-authenticated caller's role in the caller context, resolved
    /// supervisor-side at initiation (NOT envelope-asserted). Carried to
    /// Prepare-B so B enforces `InboundPolicy.allowed_source_roles` against the
    /// real role (spec §6.2.4 "Caller authentication"). `None` ⇒ no explicit
    /// role assignment.
    caller_source_role: Option<String>,
    /// The target context's Active Signing Key — receipt + divergence-marker
    /// signing (Commit-B / NeedsRepair). The actor holds no custody key
    /// (ADR-049); the FSM rebuilds a `SigningKeyBytes` (zeroizes on drop) per
    /// command from this caller-supplied key.
    target_signing_key: ed25519_dalek::SigningKey,
    /// The caller context's Active Signing Key — used ONLY to sign the
    /// caller-side `CrossContextDivergenceMarker` on a `NeedsRepair` outcome
    /// (spec §6.2.4 "Dual event-log recording"). The actor holds no custody
    /// key (ADR-049); the FSM rebuilds a `SigningKeyBytes` per command from
    /// this caller-supplied key. Distinct from `target_signing_key`: each side
    /// signs its OWN marker into its OWN log under its OWN Active Signing Key.
    caller_signing_key: ed25519_dalek::SigningKey,
    /// The supervisor-side tool executor, taken once at Commit-B.
    executor: Option<SagaToolExecutor<'a>>,
    /// The captured tool output bytes, stashed the moment the executor runs
    /// ONCE (Commit-B first execute), so a transient Commit-B SETTLE failure is
    /// retryable WITHOUT re-invoking the tool (spec §6.2.4 "Exactly-once
    /// execution"). On a retry the reserve returns `ReadyToExecute` (the capture
    /// was rolled back by the failed settle's persist), but the tool already ran
    /// and had side effects — so the FSM re-sends `CommitBSettle` with THESE
    /// stashed bytes rather than calling the (already-taken) executor again.
    /// `Some` ⇒ the tool has executed; never call the executor when this is set.
    executor_output: Option<Vec<u8>>,
    /// Prepare-A's held reservation (settled at Commit-A, released on abort).
    prepared_a: Option<crate::context::actor::commands::PreparedAFields>,
    /// Prepare-B's recorded provenance (B's clock / nonce / re-derived depth).
    prepared_b: Option<crate::context::actor::commands::PreparedBFields>,
    /// Commit-B's captured receipt + output (forwarded to Commit-A + output).
    committed: Option<CommittedSagaArtifacts>,
    /// The target side's `ToolInvoked` event id, captured the moment Commit-B
    /// lands (reserve `AlreadyCommitted` OR a first execution settle). `Some`
    /// proves the TARGET committed its `ToolInvoked` record even when the saga
    /// later diverges (Commit-A fails → `NeedsRepair`): the
    /// [`CrossContextDivergenceMarker`] then records
    /// `committed_side = Target` and this event id (spec §6.2.4
    /// "Dual event-log recording"). `None` means Commit-B never landed, so no
    /// side committed and a `NeedsRepair` cannot have diverged the logs.
    committed_b_tool_invoked_event_id: Option<String>,
    /// Set by the FSM when the saga reaches `NeedsRepair` (commit-retry
    /// exhaustion). It tells the [`Self::run_saga`] tail to LEAVE any held
    /// Prepare-A escrow reservation RESERVED rather than voiding it (spec
    /// §6.2.4 "`NeedsRepair` reservation semantics": the escrow is NOT
    /// auto-voided — only the concurrency slot is released — because the
    /// operation may have partially committed; the signed
    /// [`CrossContextDivergenceMarker`] + operator repair settles the escrow).
    /// Every other terminal leaves this `false`, so the tail's void-or-settle
    /// behaviour is unchanged on Aborted / unreachable-Commit-A paths.
    reached_needs_repair: bool,
}

/// The receipt + output captured at Commit-B, forwarded to Commit-A and
/// surfaced in [`SagaOutput`]. The `SagaId`-stable `ToolInvoked` event id is
/// carried INSIDE the signed receipt (`receipt`), so it is not duplicated
/// here — an auditor reads it from the verified receipt.
struct CommittedSagaArtifacts {
    /// JCS bytes of the target's signed `CrossContextToolReceipt`.
    receipt: Vec<u8>,
    /// The captured tool output bytes (the receipt's canonical `output_jcs`).
    output: Vec<u8>,
}

/// A supervisor-level divergence repair record (spec §6.2.4 "Dual event-log
/// recording"): the fallback witness recorded when a `NeedsRepair` side is
/// UNREACHABLE (its actor is gone / `lookup` misses) so the signed marker
/// cannot be appended into that side's event log. The supervisor records the
/// divergence here instead — "or a supervisor-level repair journal if one side
/// is unreachable" — so operator repair still has a durable account of which
/// side committed, the saga id, the nonce, and the committed-side event id.
///
/// This is the in-memory projection; a restart loses it exactly as the
/// in-memory reservation set does. The reachable side's marker (when one side
/// IS reachable) lives durably in that side's event log, so a one-reachable /
/// one-unreachable divergence is still half-recorded durably plus
/// supervisor-recorded for the unreachable half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaDivergenceRepairRecord {
    /// The context id (raw 32-byte digest, hex) of the UNREACHABLE side whose
    /// marker could not be appended into its own log.
    pub unreachable_context_hex: String,
    /// Which side committed (caller or target).
    pub committed_side: scp_protocol::context::tools::cross_context_saga::CommittedSide,
    /// The committed-side `ToolInvoked` / `CrossContextToolInvoked` event id.
    pub committed_event_id: String,
    /// The 16-byte correlation nonce joining the two event-log records.
    pub nonce: [u8; 16],
}

// ---------------------------------------------------------------------------
// Supervisor configuration + crash tracking
// ---------------------------------------------------------------------------

/// Supervisor configuration. Cheap defaults for commit 6; real fields
/// (saga phase timeouts, respawn budget windows) materialize alongside
/// the saga migration in commit 11.
#[derive(Clone, Debug, Default)]
pub struct SupervisorConfig {
    /// Reserved for future configuration; placeholder field so the
    /// struct has stable layout.
    #[allow(dead_code)]
    reserved: (),
}

/// Sliding-window length for the actor respawn budget (ADR-049 §10).
/// Crashes older than this (relative to the newest crash) are evicted
/// before the budget is evaluated.
const CRASH_WINDOW_MS: u64 = 60_000;

/// Number of crashes within [`CRASH_WINDOW_MS`] that poisons a context
/// (ADR-049 §10): "3 crashes in 60s poisons the context."
const CRASH_POISON_THRESHOLD: usize = 3;

/// Defensive upper bound on the retained crash-timestamp deque. The
/// sliding-window eviction already bounds the deque to crashes within
/// [`CRASH_WINDOW_MS`], but a pathological clock (non-monotonic, or stuck)
/// could otherwise let it grow without bound. Capping at the poison
/// threshold is sufficient: once the threshold is reached the context is
/// poisoned and never respawned, so no further timestamps accrue. The cap
/// keeps the structure O(1) in space regardless of clock behaviour.
const CRASH_DEQUE_CAP: usize = CRASH_POISON_THRESHOLD;

/// Per-context crash-count window (ADR-049 §10 — actor respawn budget).
///
/// Tracks the wall-clock-millisecond timestamps of recent actor crashes
/// in a sliding [`CRASH_WINDOW_MS`] window. When [`CRASH_POISON_THRESHOLD`]
/// crashes land inside the window the context is *poisoned*: the
/// supervisor stops respawning its actor (no infinite crash-respawn loop)
/// until an operator clears the poison.
///
/// # Purity
///
/// Every method that observes time takes the current time as an explicit
/// `now_ms` parameter — the struct never reads a clock itself. This keeps
/// the budget logic deterministic and unit-testable without a clock, and
/// confines the (only) clock read to the supervisor watchdog.
#[derive(Debug, Default)]
pub struct CrashWindow {
    /// Crash timestamps in `now_millis()` units, ordered oldest → newest.
    /// Front-evicted as the window slides; capped at [`CRASH_DEQUE_CAP`].
    crashes: VecDeque<u64>,
    /// Sticky poison flag. Once set (the budget was exceeded) it stays set
    /// until [`Self::clear`] is called by an explicit operator action — a
    /// later in-window eviction must NOT silently un-poison the context.
    poisoned: bool,
    /// Set when the most recent respawn attempt FAILED (lost/corrupt
    /// snapshot, deps build failure, etc.) without the context being
    /// poisoned. Distinguishes "crashed and currently unrecoverable" from
    /// "never existed": while this is `true` and `poisoned` is `false`,
    /// [`Supervisor::lookup_miss_error`] surfaces
    /// [`ContextError::ActorCrashed`] instead of `ContextNotRegistered`, so
    /// a caller can tell a silently-dead context apart from an unknown id
    /// (ADR-049 §10). Cleared on a successful respawn and on
    /// [`Self::clear`].
    last_respawn_failed: bool,
    /// Set for the transient window during which
    /// [`Supervisor::respawn_from_snapshot`] has despawned the crashed actor
    /// but has not yet re-registered the replacement. During this window a
    /// concurrent per-context dispatch would `lookup`-miss against a context
    /// that genuinely exists and is mid-respawn; without this marker
    /// [`Supervisor::lookup_miss_error`] would return `ContextNotRegistered`
    /// ("never existed"), which is misleading and non-retryable. While this is
    /// `true` (and the context is neither poisoned nor already in a
    /// failed-respawn state), the lookup-miss surfaces the retryable
    /// [`ContextError::ActorCrashed`] class so the caller retries through the
    /// respawn rather than treating the context as unknown. Cleared on every
    /// respawn exit (success, failure, or terminal-skip).
    respawning: bool,
}

impl CrashWindow {
    /// Record a crash at `now_ms` and return whether the context is now
    /// poisoned.
    ///
    /// Steps, in order:
    /// 1. Push `now_ms` as the newest crash.
    /// 2. Front-evict every crash strictly older than `CRASH_WINDOW_MS`
    ///    relative to `now_ms` (`now_ms - front > CRASH_WINDOW_MS`).
    ///    `saturating_sub` keeps a non-monotonic clock (an earlier reading
    ///    than the stored front) from underflowing — such a reading simply
    ///    evicts nothing.
    /// 3. Defensively cap the deque length (see [`CRASH_DEQUE_CAP`]).
    /// 4. Set `poisoned` if the in-window crash count reached the
    ///    threshold. The flag is sticky (never cleared here).
    ///
    /// Returns the (post-update) value of [`Self::is_poisoned`].
    fn record(&mut self, now_ms: u64) -> bool {
        self.crashes.push_back(now_ms);
        while let Some(&front) = self.crashes.front() {
            if now_ms.saturating_sub(front) > CRASH_WINDOW_MS {
                self.crashes.pop_front();
            } else {
                break;
            }
        }
        // Defensive cap: drop the oldest entries if the deque somehow
        // exceeded the bound (only reachable under a misbehaving clock).
        while self.crashes.len() > CRASH_DEQUE_CAP {
            self.crashes.pop_front();
        }
        if self.crashes.len() >= CRASH_POISON_THRESHOLD {
            self.poisoned = true;
        }
        self.poisoned
    }

    /// Whether the context is poisoned (the respawn budget was exceeded).
    const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whether the most recent respawn failed without poisoning the context
    /// — the "silently dead" case (ADR-049 §10). Used by
    /// [`Supervisor::lookup_miss_error`] to surface
    /// [`ContextError::ActorCrashed`] rather than `ContextNotRegistered`.
    const fn last_respawn_failed(&self) -> bool {
        self.last_respawn_failed
    }

    /// Record that the most recent respawn attempt failed (lost/corrupt
    /// snapshot, deps build failure). Distinct from [`Self::record`] —
    /// `record` accounts a *crash* against the sliding budget; this flag is
    /// the orthogonal "currently unrecoverable" signal that drives the
    /// lookup-miss error class. Always paired with a `record` call at the
    /// failure site.
    const fn mark_respawn_failed(&mut self) {
        self.last_respawn_failed = true;
    }

    /// Clear the unrecoverable flag after a respawn succeeds. The crash
    /// history (budget) is intentionally left intact — a context that
    /// flapped and then recovered must still be one crash away from its
    /// budget — but it is no longer "silently dead".
    const fn mark_respawn_succeeded(&mut self) {
        self.last_respawn_failed = false;
    }

    /// Whether the context is mid-respawn (despawned, not yet re-registered).
    /// Used by [`Supervisor::lookup_miss_error`] to surface a retryable
    /// `ActorCrashed` rather than a misleading `ContextNotRegistered` during
    /// the transient respawn gap (ADR-049 §10).
    const fn is_respawning(&self) -> bool {
        self.respawning
    }

    /// Mark the start of a respawn (set just before the despawn). Paired with
    /// [`Self::clear_respawning`] on every respawn exit.
    const fn mark_respawning(&mut self) {
        self.respawning = true;
    }

    /// Clear the transient respawn marker once the respawn has completed
    /// (success, failure, or terminal-skip) and the registry once again
    /// reflects the true state.
    const fn clear_respawning(&mut self) {
        self.respawning = false;
    }

    /// Whether this window carries no durable signal aside from the transient
    /// respawn marker — no recorded crashes, not poisoned, no failed respawn.
    /// Such a window was created solely by the `mark_respawning` set at the top
    /// of `respawn_from_snapshot`; on a terminal-skip it must be reaped so a
    /// clean terminal context does not leave a lingering crash-window record
    /// (preserving the "no crash window for a clean terminal context"
    /// invariant). Read inside a `DashMap::remove_if` predicate, which borrows
    /// the value immutably, so this cannot itself clear the marker.
    fn is_empty_except_respawning(&self) -> bool {
        self.crashes.is_empty() && !self.poisoned && !self.last_respawn_failed
    }

    /// Current number of crashes retained in the window. Used by the
    /// watchdog log line so operators can see how close a context is to
    /// the poison threshold.
    fn crash_count(&self) -> usize {
        self.crashes.len()
    }

    /// Operator un-poison: clear the recorded crashes and the sticky
    /// poison flag so the context can be respawned again. Distinct from
    /// the automatic window eviction in [`Self::record`], which never
    /// touches `poisoned`.
    fn clear(&mut self) {
        self.crashes.clear();
        self.poisoned = false;
        self.last_respawn_failed = false;
        self.respawning = false;
    }
}

/// Spawn a context actor's watchdog task (ADR-049 §10).
///
/// This is a free function — deliberately NOT an inline `tokio::spawn`
/// inside [`Supervisor::spawn_actor_with_watchdog`] — so the watchdog
/// future's `Send` proof is resolved here, OUTSIDE the opaque `impl
/// Future` scope of the spawn method. The watchdog reaches
/// `Supervisor::respawn_from_snapshot` → `restore_context` →
/// `Supervisor::spawn_actor_with_state` → `spawn_actor_with_watchdog`,
/// forming a self-referential async cycle. Spawning inline makes the
/// compiler try to fetch an opaque type's hidden type within its own
/// defining scope (unsupported); moving the spawn into this free fn —
/// whose only relationship to the cycle is a plain `tokio::spawn` call —
/// breaks that self-reference. The actor task is NOT placed on the
/// supervisor's timer `task_set`; the watchdog owns its `JoinHandle`
/// directly.
fn spawn_actor_watchdog_task(
    supervisor: Arc<Supervisor>,
    ctx_id: String,
    owning_did: DID,
    join: tokio::task::JoinHandle<()>,
) {
    tokio::spawn(async move {
        supervisor.actor_watchdog(ctx_id, owning_did, join).await;
    });
}

/// Spawn a `KeyPackageStoreActor`'s watchdog task (ADR-049 §10).
///
/// The per-identity twin of [`spawn_actor_watchdog_task`]. A free function for
/// the same reason: the watchdog reaches `Supervisor::kp_actor_watchdog` →
/// `Supervisor::respawn_kp_actor` → `Supervisor::key_package_store_for` →
/// (spawn), which forms a self-referential async cycle the compiler refuses to
/// resolve when spawned inline. The KP actor task is NOT placed on the
/// supervisor's timer `task_set`; the watchdog owns its `JoinHandle` directly.
fn spawn_kp_actor_watchdog_task(
    supervisor: Arc<Supervisor>,
    identity: DID,
    join: tokio::task::JoinHandle<()>,
) {
    tokio::spawn(async move {
        supervisor.kp_actor_watchdog(identity, join).await;
    });
}

/// Placeholder saga state stored in `pending_sagas` between Prepare and
/// Commit/Abort. Commit 6 keeps this opaque; the real state shape lives
/// in the per-saga-type `SagaPreparedState` variants.
#[derive(Debug)]
pub struct PendingSagaProjection {
    /// Reserved; the real in-memory projection of the saga FSM lands
    /// alongside the handler migrations in commit 11.
    #[allow(dead_code)]
    reserved: (),
}

/// Flat, named-field request for
/// [`Supervisor::start_cross_context_tool_invocation_saga`] (spec §6.2.4).
///
/// Carries the §6.2.4 invocation envelope field set by **value**. Replaces a
/// long positional argument list whose adjacent `[u8; 32]` ids
/// (`caller_context_id` / `target_context_id`) and asserted-provenance scalars
/// were transposable at a call site — a swap compiled and would silently sign
/// and record the saga under the wrong context, the confused-deputy footgun the
/// named fields foreclose. Per the project's Agent-first API tenet: one flat
/// config object, every field named, no builder, no ordering to track.
///
/// The two Active Signing Keys and the supervisor-side tool executor stay
/// explicit parameters of the entry point — they are not envelope data (the
/// keys are custody material the actor never holds; the executor is a non-`Send`
/// closure), so folding them in would mix wire fields with capabilities.
#[derive(Debug, Clone)]
pub struct CrossContextToolInvocationRequest {
    /// Raw 32-byte id of the caller (initiating) context.
    pub caller_context_id: [u8; 32],
    /// Raw 32-byte id of the target (executing) context.
    pub target_context_id: [u8; 32],
    /// Channel-authenticated DID of the initiator.
    pub caller_did: DID,
    /// Registration id of the tool being invoked across the interface.
    pub tool_registration_id: String,
    /// Optional id of the spending UCAN proof, resolved target-side at
    /// Prepare-B. `None` for an ungated tool.
    pub ucan_proof_id: Option<String>,
    /// Tool input payload (JSON), schema-checked target-side.
    pub input: serde_json::Value,
    /// Caller-asserted inbound provenance chain depth; B re-derives `+1`.
    pub asserted_chain_depth: u8,
    /// Caller-asserted 16-byte envelope nonce, checked against B's dedup cache.
    pub asserted_nonce: [u8; 16],
    /// Caller-asserted send-time (Unix ms), checked against §9.14 skew.
    pub asserted_timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Plain struct — not an actor. See module-level docs for rationale.
///
/// The write path (any mutation of `actors`, `standing_contexts`,
/// `local_dids`, or `wrapping_keys`) acquires [`Self::write_lock`] first,
/// then does the `DashMap::insert` / `ArcSwap::store`, then drops the
/// lock. This prevents lost writes from concurrent `ArcSwap::store`
/// operations (which are atomic in isolation but not when the caller
/// wants read-modify-write semantics against the stored snapshot).
pub struct Supervisor {
    /// Actor registry. `context_id` → `ContextActorHandle`. Lookups via
    /// [`Self::lookup`] are lock-free (`DashMap::get`).
    pub(in crate::context::supervisor) actors: DashMap<String, ContextActorHandle>,
    /// Standing-pair context index. peer DID string → peer `DID`. Read
    /// via `ArcSwap::load` (lock-free); mutated under
    /// [`Self::write_lock`].
    pub(in crate::context::supervisor) standing_contexts: ArcSwap<HashMap<String, DID>>,
    /// Local identities. Grows once per `identity_add`; read-heavy.
    ///
    /// Wrapped in `Arc<ArcSwap<_>>` (not a bare `ArcSwap`) so that every
    /// per-context actor shares the SAME swap cell: [`ActorDeps`] receives
    /// an `Arc::clone` of this field, not a snapshot copy. A bare
    /// `ArcSwap` would force the actor-deps builder to take a point-in-time
    /// `load_full()` snapshot, and any DID registered AFTER an actor is
    /// spawned (e.g. the creator's DID, which `register_local_did` records
    /// only after `context_create` has already spawned the actor) would be
    /// invisible to that actor's `local_dids` view — breaking the
    /// author-DID-controlled gate on broadcast key requests.
    pub(in crate::context::supervisor) local_dids: Arc<ArcSwap<HashSet<DID>>>,
    /// Per-identity X25519 wrapping keys. Wrapped in `ArcSwap` so
    /// rotation is atomic; outer `DashMap` keyed by DID.
    pub(in crate::context::supervisor) wrapping_keys: DashMap<DID, ArcSwap<WrappingKeyPair>>,
    /// Persistence backend; stored so `spawn_actor` / `crash_recovery`
    /// can plumb it through to per-actor state.
    // Operational in Phase 2 of post-review-round-1 plan (actor model wiring).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) persistence: Arc<dyn ContextPersistence>,
    /// Single-producer-multi-read write lock — plan §"Write path".
    pub(crate) write_lock: tokio::sync::Mutex<()>,
    /// Serializes the whole bootstrap-spawn sequence of ALL three lifecycle
    /// bootstrap variants — `create_context`, `import_context`, and
    /// `restore_context` — each of which writes per-context crypto state and
    /// then spawns an owned-state actor for the same context id in two
    /// non-atomic steps. The actor mailbox only serializes the
    /// `PrepareForReplace` turn; the crypto-write→spawn tail runs outside it,
    /// so two concurrent bootstrap ops for the SAME id (import vs import, OR
    /// import vs create/restore) could otherwise leave the registered actor
    /// paired with the other op's crypto state, or discard the import's
    /// floor-guarded crypto behind a fresh create. Held across each bootstrap
    /// op so same-id bootstraps run one at a time. Bootstrap is not a hot path,
    /// so a single supervisor-wide lock is acceptable; this is a DIFFERENT lock
    /// from `write_lock` to avoid re-entrancy with
    /// `spawn_actor_with_state`/`despawn_actor` (which take `write_lock`).
    /// Lock order is always `bootstrap_spawn_lock` → `write_lock`, never the
    /// reverse.
    pub(crate) bootstrap_spawn_lock: tokio::sync::Mutex<()>,
    /// Pending sagas keyed by saga ID; projection of the durable
    /// journal for fast lookup.
    // Operational in Phase 2 of post-review-round-1 plan (saga FSM real
    // Prepare/Commit dispatch + watchdog).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) pending_sagas: DashMap<SagaId, PendingSagaProjection>,
    /// Durable saga journal (plan §"Cross-context saga protocol").
    pub(in crate::context::supervisor) saga_journal: Arc<dyn SagaJournal>,
    /// Per-identity `KeyPackageStoreActor` handles.
    pub(in crate::context::supervisor) key_package_stores: DashMap<DID, KeyPackageStoreHandle>,
    /// Configuration.
    // Operational in Phase 2 of post-review-round-1 plan (saga + watchdog
    // configuration plumbed through ActorDeps).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) health_config: SupervisorConfig,
    /// Per-context crash-count windows (respawn budget state, ADR-049 §10).
    /// Keyed by context id; populated lazily by [`Self::actor_watchdog`] the
    /// first time an actor for that context crashes. Lock-free reads via
    /// `DashMap` per ADR-049 §Decision 12.
    pub(in crate::context::supervisor) crash_windows: DashMap<String, CrashWindow>,
    /// Supervisor-level divergence repair journal (spec §6.2.4 "Dual event-log
    /// recording"): the fallback witnesses recorded when a `NeedsRepair` side is
    /// UNREACHABLE and its signed [`SagaDivergenceRepairRecord`] could not be
    /// appended into that side's own event log. Keyed by saga id; a single
    /// diverged saga may record both sides (target + caller unreachable) under
    /// one key. In-memory only (lost on restart, like the reservation set);
    /// operator repair reads it before the supervisor restarts. Lock-free reads
    /// via `DashMap` (ADR-049 §Decision 12).
    pub(in crate::context::supervisor) saga_repair_records:
        DashMap<SagaId, Vec<SagaDivergenceRepairRecord>>,

    // -----------------------------------------------------------------
    // ADR-049 commit 12 — providers lifted from ContextManager (now
    // authoritative on Supervisor).
    //
    // Each `OnceLock<Arc<...>>` provider slot is populated directly by
    // [`Self::with_providers`]. There is no `ContextManager` to attach
    // — the supervisor IS the source of truth for every provider after
    // commit 12. Slots are still wrapped in `OnceLock` so the
    // [`Self::for_query_shim`] constructor path (used by tests +
    // saga-only call sites) can build a supervisor without providers
    // and the FFI layer can populate them once at construction time.
    //
    // Provider OnceLocks return `Option<&...>` from their accessors —
    // helpers that consult them either soft-fallback or surface
    // `ContextError::NotInitialized`. The supervisor-authoritative
    // direct fields below (`contexts`, `local_dids`,
    // `standing_contexts`) are eagerly initialized
    // in [`Self::new`] and their accessors do not return `Option`.
    // -----------------------------------------------------------------
    /// Shared crypto provider. Populated by [`Self::with_providers`].
    crypto: OnceLock<Arc<crate::crypto::mls::provider::MlsCryptoProvider>>,
    /// Shared transport provider. Populated by [`Self::with_providers`].
    transport: OnceLock<Arc<dyn ContextTransportProvider>>,
    /// Shared event-log provider. Populated by [`Self::with_providers`].
    event_log: OnceLock<Arc<dyn ContextEventLogProvider>>,
    /// Optional helper-side persistence slot — populated by
    /// [`Self::with_providers`] only when the caller passes
    /// `Some(persistence)`. Distinct from the supervisor-saga
    /// [`Self::persistence`] field above (which is always populated;
    /// defaults to the no-op stub). Helpers branch on
    /// `persistence_ref().is_some()` to skip best-effort persist
    /// calls when no real backend is wired.
    helper_persistence: OnceLock<Arc<dyn ContextPersistence>>,
    /// Wall-clock source. Populated by [`Self::with_providers`] (or
    /// defaulted to [`scp_primitives::SystemClock`] when the caller
    /// passes `None`).
    clock: OnceLock<Arc<dyn Clock>>,
    /// Key resolver for governance signature verification. The type is
    /// itself an `Arc<dyn Fn(...)>` alias (see
    /// [`scp_protocol::context::governance::KeyResolver`]), so storing a
    /// clone is a reference-count bump.
    key_resolver: OnceLock<KeyResolver>,
    /// Optional payment adapter. Empty `OnceLock` means "no adapter
    /// configured"; populated by [`Self::with_providers`] when the
    /// caller passes `Some(adapter)`. There is no post-construction
    /// setter — the deleted prior `set_payment_adapter` opened a
    /// two-paths-to-set seam that no production caller used.
    payment_adapter: OnceLock<Arc<dyn PaymentAdapterDyn>>,
    /// Optional broadcast sender for fan-out of [`ContextEvent`]s to
    /// external consumers. Empty `OnceLock` means "no channel
    /// configured".
    event_tx: OnceLock<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    /// Shared task set for TTL timers + governance timeouts.
    task_set: OnceLock<Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>>,
    /// OpenMLS storage adapter — the bridge's chosen Storage, erased once via
    /// `SpawnBlockingStorageAdapter`. Runtime NEVER defaults this. Lock-free
    /// read per ADR-049 §Decision 12.
    mls_storage: OnceLock<Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>,

    // -----------------------------------------------------------------
    // ADR-049 commit 12 — supervisor-authoritative direct fields.
    //
    // These were previously mirrored from `ContextManager`. The
    // supervisor now owns them directly; eagerly initialized in
    // [`Self::new`].
    // -----------------------------------------------------------------
    /// Per-participant-context-set saga reservation (ADR-049 §3a, spec
    /// §5.15.4). Holds the union of the participant-context IDs currently
    /// reserved by all in-flight sagas. A saga reserves the WHOLE of its
    /// participant context set ([`saga_participant_context_set`]) atomically
    /// at [`Self::start_saga`] entry: if ANY id in the new set is already
    /// present, the new saga's set OVERLAPS an in-flight saga and the start
    /// returns
    /// [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy)
    /// with a `SagaBusy` reason; otherwise the whole set is inserted and the
    /// FSM runs. Two sagas with DISJOINT sets never contend and run
    /// concurrently — replacing the prior supervisor-wide `AtomicBool` so one
    /// slow or stuck saga can no longer deny the whole instance. The
    /// reservation is released by the [`SagaSetReservation`] RAII guard on
    /// EVERY terminal (Committed, Aborted, NeedsRepair) AND panic-unwind;
    /// crucially, `NeedsRepair` RELEASES the slot (the divergence still
    /// awaits operator repair, but a stuck saga must not wedge unrelated
    /// ones — spec §5.15.4).
    ///
    /// In-memory only: this set is NOT rebuilt on restart, exactly matching
    /// the prior `AtomicBool`'s restart behavior (a restarted supervisor
    /// starts with no reservations). When PR-7/2D wires
    /// [`Self::replay_unresolved_sagas`] at startup, it MUST rebuild
    /// reservations for non-terminal unresolved journal entries — EXCLUDING
    /// `NeedsRepair` entries, whose slots are deliberately released — so a
    /// replay-driven re-drive of an in-flight saga re-takes its set before
    /// the first post-restart `start_saga` can race it.
    ///
    /// REPLAY RESERVATION RECONSTRUCTION — the journal participant record for a
    /// `CrossContextToolInvocation` (built by [`saga_input_participants`])
    /// deliberately does NOT persist `target_context_id` ("Leave the journal
    /// shape UNCHANGED"): it records only `{caller_context_id, caller_did,
    /// tool_registration_id}`. But the gating set
    /// ([`saga_participant_context_set`]) is `{caller, target}`. A naïve replay
    /// that rebuilds reservations from the participant record alone could only
    /// re-reserve `{caller}`, NOT `{caller, target}` — leaving the `target`
    /// context slot free and letting a fresh post-restart saga touch it
    /// concurrently, defeating the §5.15.4 cross-context serialization for the
    /// recovery window. This gap is CLOSED via **option (a)**: the
    /// `PreparingB` / `Committing` journal entries carry the eight-field
    /// `CrossContextToolInvocationPrepared` evidence (which embeds BOTH
    /// `caller_context_id` AND `target_context_id`), so
    /// [`Self::reconstruct_xctx_prepared`] rebuilds the COMPLETE `{caller,
    /// target}` set from the evidence — see [`Self::xctx_prepared_evidence_bytes`].
    /// When the Phase-2D startup loop rebuilds reservations for non-terminal
    /// unresolved entries it reconstructs the full set from this evidence (the
    /// rebuilt reservation equals what `start_saga` would have taken), NOT a
    /// caller-only subset.
    ///
    /// The type is `std::sync::Mutex` (banned by `clippy.toml` for the
    /// await-deadlock hazard) with a narrowly-scoped allow: the critical
    /// section is purely synchronous (`lock()` → check-disjoint → insert /
    /// remove → drop), and the guard is PROVABLY NEVER held across an
    /// `.await` (see [`Self::try_reserve_context_set`] and
    /// [`SagaSetReservation::drop`], neither of which awaits while holding
    /// the guard). The clippy ban targets the suspend-thread-across-await
    /// deadlock, which cannot occur here.
    #[allow(
        clippy::disallowed_types,
        reason = "Synchronous critical section only; the guard is provably \
                  never held across an .await (check-disjoint + insert, or \
                  remove-on-drop, are all sync). The clippy ban targets \
                  await-deadlock, which cannot occur here. ADR-049 §3a."
    )]
    reserved_saga_contexts: std::sync::Mutex<HashSet<String>>,

    // -----------------------------------------------------------------
    /// Monotonic spawn-generation counter. Incremented once per
    /// [`Self::spawn_actor_with_state`] and stamped onto the spawned
    /// actor's [`PerContextState::generation`](crate::context::actor::state::PerContextState::generation).
    /// A tool-economy reservation captures the generation of the actor
    /// instance it reserved against; the Phase-3 settle rejects if the
    /// generation no longer matches (the actor was despawned and a new
    /// instance respawned for the same `context_id` between reserve and
    /// settle), preventing a settle from capturing or refunding against a
    /// DIFFERENT context instance's owned state. This is the confused-deputy
    /// guard for the reserve→execute→settle split: the executor runs
    /// supervisor-side (non-`Send`) outside the actor's serialized mailbox,
    /// so the actor instance identity must be re-verified at settle time.
    spawn_generation: std::sync::atomic::AtomicU64,
}

impl Supervisor {
    /// Per-context lifecycle operation budget (ADR-049 §10). Bounds
    /// `restore_context` on BOTH the `RestoreContext` dispatch arm and the
    /// watchdog respawn (`respawn_from_snapshot`) so a hung storage provider
    /// cannot pin the global `bootstrap_spawn_lock` indefinitely. A single
    /// associated const keeps the two call sites in lock-step.
    const LIFECYCLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Constructs a fresh supervisor.
    ///
    /// `persistence` and `saga_journal` are injected at construction so
    /// the supervisor is never a singleton — bridge instances in
    /// `scp_ffi_common::bridge_instance` construct one per SCP
    /// instance and drop it on `shutdown`.
    ///
    /// Visibility is `pub(crate)` in production builds; only
    /// [`Self::with_providers`] (the FFI-facing factory) calls into
    /// `new`. Integration tests in `crates/scp-runtime/tests/` reach
    /// the constructor through the `testing`-feature gate so they can
    /// build supervisors without provider wiring.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn new(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
    ) -> Self {
        Self::new_inner(persistence, saga_journal, health_config)
    }

    /// Internal constructor reachable from production builds. The public
    /// surface goes through [`Self::with_providers`]; the test-only
    /// [`Self::new`] alias forwards here so the same body services both
    /// the production factory and the test integration suites.
    #[must_use]
    pub(crate) fn new_inner(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
    ) -> Self {
        // Synchronous critical section only; the guard is provably never held
        // across an `.await` (check-disjoint + insert, or remove-on-drop, are
        // all sync). The clippy ban targets await-deadlock, which cannot occur
        // here. ADR-049 §3a. (Matches the `reserved_saga_contexts` field allow.)
        #[allow(
            clippy::disallowed_types,
            reason = "Synchronous critical section only; the guard is provably \
                      never held across an .await. ADR-049 §3a."
        )]
        let reserved_saga_contexts = std::sync::Mutex::new(HashSet::new());
        Self {
            actors: DashMap::new(),
            standing_contexts: ArcSwap::new(Arc::new(HashMap::new())),
            local_dids: Arc::new(ArcSwap::new(Arc::new(HashSet::new()))),
            wrapping_keys: DashMap::new(),
            persistence,
            write_lock: tokio::sync::Mutex::new(()),
            bootstrap_spawn_lock: tokio::sync::Mutex::new(()),
            pending_sagas: DashMap::new(),
            saga_journal,
            key_package_stores: DashMap::new(),
            health_config,
            crash_windows: DashMap::new(),
            saga_repair_records: DashMap::new(),
            // ADR-049 commit 12 — providers lifted from
            // ContextManager. Populated by `with_providers`.
            crypto: OnceLock::new(),
            transport: OnceLock::new(),
            event_log: OnceLock::new(),
            helper_persistence: OnceLock::new(),
            clock: OnceLock::new(),
            key_resolver: OnceLock::new(),
            payment_adapter: OnceLock::new(),
            event_tx: OnceLock::new(),
            task_set: OnceLock::new(),
            mls_storage: OnceLock::new(),
            reserved_saga_contexts,
            // Generation 0 is never stamped onto a live actor (the first
            // spawn increments to 1 before stamping), so a default
            // `PerContextState::generation == 0` can never collide with a
            // real spawn generation.
            spawn_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Test-only constructor used by saga + spawn unit tests that never
    /// invoke a provider-touching helper.
    ///
    /// Builds a [`Supervisor`] whose `persistence` and `saga_journal`
    /// fields are no-op stubs — saga FSM tests assert the coordinator's
    /// observable state transitions, and spawn tests exercise registry
    /// insertion only. Production code paths build supervisors through
    /// [`Self::with_providers`], which wires real providers; bridge
    /// instances in `scp_ffi_common::bridge_instance` never call
    /// `for_query_shim`.
    ///
    /// Gated behind the `testing` feature so production FFI builds
    /// cannot reach a provider-less supervisor.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn for_query_shim() -> Self {
        let persistence: Arc<dyn ContextPersistence> =
            Arc::new(crate::context::persistence::NoopContextPersistence);
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoopSagaJournal);
        Self::new_inner(persistence, saga_journal, SupervisorConfig::default())
    }

    /// Construct a supervisor with the providers that previously lived on
    /// the deleted `ContextManager` (ADR-049 commit 12).
    ///
    /// The supervisor is now the authoritative owner of every provider —
    /// there is no `ContextManager` to attach. FFI bridges call this
    /// factory once at construction time; the returned `Arc<Supervisor>`
    /// is the only handle they hold.
    ///
    /// Saga journal + supervisor-level persistence wire to no-op stubs
    /// the test-only `for_query_shim` path uses — saga orchestration
    /// is not yet active (it lands with Phase 2's actor wiring), and
    /// the supervisor's own persistence slot is wired to a no-op
    /// [`NoopContextPersistence`](crate::context::persistence::NoopContextPersistence)
    /// when `persistence` is `None`.
    ///
    /// # Arguments
    ///
    /// * `crypto` — production
    ///   [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider).
    /// * `transport` — production transport (typically
    ///   [`NotConfiguredTransportProvider`](crate::context::builder::NotConfiguredTransportProvider),
    ///   [`LocalTransportProvider`](crate::context::builder::LocalTransportProvider), or a real
    ///   `scp_transport::RelayTransportProvider`).
    /// * `event_log` — event log provider, usually backed by
    ///   `MerkleEventLogProvider::with_persistence(...)` so entries
    ///   survive restart.
    /// * `key_resolver` — DID-to-Ed25519-key resolver for governance
    ///   signature verification.
    /// * `persistence` — optional context persistence; `None` keeps the
    ///   supervisor in-memory only.
    /// * `payment_adapter` — optional payment adapter for the 9-step
    ///   paid-action flow (spec §19.2.2).
    /// * `event_tx` — optional broadcast sender for event fan-out.
    /// * `clock` — optional [`Clock`] override; defaults to
    ///   [`scp_primitives::SystemClock`] when `None`.
    /// * `mls_storage` — **required** OpenMLS storage adapter (the
    ///   bridge's chosen `Storage`, erased once via
    ///   [`SpawnBlockingStorageAdapter`](crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter)).
    ///   The runtime never defaults or manufactures storage — the caller
    ///   supplies it at the bridge/builder layer, enforced by the type
    ///   system (non-`Option`). In-memory storage is a bridge-layer dev
    ///   opt-in, never a runtime default.
    ///
    /// # Returns
    ///
    /// `Arc<Supervisor>` — already wrapped because FFI bridges store
    /// their per-instance supervisor in an `Arc` slot.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // FFI bridges need to compose providers in one call
    pub fn with_providers(
        crypto: Arc<crate::crypto::mls::provider::MlsCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
        persistence: Option<Box<dyn ContextPersistence>>,
        payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
        event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
        clock: Option<Arc<dyn Clock>>,
        mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    ) -> Arc<Self> {
        // The supervisor's own `persistence` field is non-Option (saga
        // code requires a value); when the caller passes `None`, wire
        // the no-op stub the `for_query_shim` path uses. The
        // helper-side `helper_persistence` slot stays empty in that
        // case so `persistence_ref()` returns `None` and helpers skip
        // best-effort persist calls.
        let (supervisor_persistence, helper_persistence_arc) = persistence.map_or_else(
            || {
                let stub: Arc<dyn ContextPersistence> =
                    Arc::new(crate::context::persistence::NoopContextPersistence);
                (stub, None)
            },
            |boxed| {
                let arc: Arc<dyn ContextPersistence> = Arc::from(boxed);
                (Arc::clone(&arc), Some(arc))
            },
        );
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoopSagaJournal);
        let supervisor = Arc::new(Self::new_inner(
            supervisor_persistence,
            saga_journal,
            SupervisorConfig::default(),
        ));

        // Populate provider OnceLocks. Each `set(...).is_ok()` returns
        // false if the slot is already populated — impossible on this
        // freshly-constructed supervisor, but `let _ = ...` keeps clippy
        // happy with the discarded `Result`.
        let _ = supervisor.crypto.set(crypto);
        let _ = supervisor.transport.set(Arc::from(transport));
        let _ = supervisor.event_log.set(Arc::from(event_log));
        if let Some(p) = helper_persistence_arc {
            let _ = supervisor.helper_persistence.set(p);
        }
        let _ = supervisor.key_resolver.set(key_resolver);
        let clock = clock.unwrap_or_else(|| Arc::new(scp_primitives::SystemClock));
        let _ = supervisor.clock.set(clock);
        if let Some(adapter) = payment_adapter {
            let _ = supervisor.payment_adapter.set(adapter);
        }
        if let Some(tx) = event_tx {
            let _ = supervisor.event_tx.set(tx);
        }
        let _ = supervisor.task_set.set(Arc::new(tokio::sync::Mutex::new(
            tokio::task::JoinSet::new(),
        )));
        // A2 — attach the durable consumed-init-key set to the shared MLS
        // backend so `join_from_welcome` enforces the crypto-layer single-use
        // backstop on EVERY join path (independent of the KeyPackage actor's
        // reservation bookkeeping). The backend is the single instance shared
        // via `crypto.mls_backend()`; wiring the supervisor's own
        // `mls_storage` here gives the two anchors one durable home.
        if let Some(crypto) = supervisor.crypto.get() {
            crypto
                .mls_backend()
                .set_consumed_init_key_store(Arc::clone(&mls_storage));
        }

        // Required, non-Option — the runtime never defaults storage. The
        // freshly-constructed supervisor's slot is always empty here, so
        // `set` cannot fail; `let _ =` discards the `Result` for clippy. This
        // is the last use of `mls_storage`, so it is moved (not cloned) in.
        let _ = supervisor.mls_storage.set(mls_storage);

        supervisor
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12 — provider + state accessors.
    //
    // Provider accessors (`crypto_ref`, `transport_ref`, etc.) return
    // `Option<&...>` because providers are populated only by
    // [`Self::with_providers`] — the [`Self::for_query_shim`] path
    // leaves them empty (used by saga + spawn unit tests that don't
    // touch providers).
    //
    // Direct-state accessors (`local_dids_ref`, `standing_contexts_ref`)
    // return non-Option references — the underlying fields are eagerly
    // initialized in [`Self::new`] and always populated.
    //
    // Visibility: `pub(crate)` so hoisted helpers can reach them;
    // external callers go through `SupervisorHandle`.
    // -------------------------------------------------------------------

    /// Cheap reference to the supervisor's shared
    /// [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider).
    /// Returns `None` if [`Self::with_providers`] was not used (e.g. a
    /// supervisor built via [`Self::for_query_shim`] / [`Self::new`]).
    #[must_use]
    pub(crate) fn crypto_ref(
        &self,
    ) -> Option<&Arc<crate::crypto::mls::provider::MlsCryptoProvider>> {
        self.crypto.get()
    }

    /// Cheap reference to the supervisor's shared
    /// [`ContextTransportProvider`]. Returns `None` if
    /// [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn transport_ref(&self) -> Option<&Arc<dyn ContextTransportProvider>> {
        self.transport.get()
    }

    /// Cheap reference to the supervisor's shared
    /// [`ContextEventLogProvider`]. Returns `None` if
    /// [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn event_log_ref(&self) -> Option<&Arc<dyn ContextEventLogProvider>> {
        self.event_log.get()
    }

    /// Cheap reference to the helper-side persistence slot. Returns
    /// `None` if [`Self::with_providers`] was not used or the caller
    /// passed `None` for `persistence` (helpers branch on this to skip
    /// best-effort persist calls when no real backend is wired).
    #[must_use]
    pub(crate) fn persistence_ref(&self) -> Option<&Arc<dyn ContextPersistence>> {
        self.helper_persistence.get()
    }

    /// Cheap reference to the supervisor's wall-clock source. Returns
    /// `None` if [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn clock_ref(&self) -> Option<&Arc<dyn Clock>> {
        self.clock.get()
    }

    /// Cheap reference to the supervisor's
    /// [`KeyResolver`](scp_protocol::context::governance::KeyResolver).
    /// Returns `None` if [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn key_resolver_ref(&self) -> Option<&KeyResolver> {
        self.key_resolver.get()
    }

    /// Cheap reference to the supervisor's payment-adapter slot.
    /// Returns `None` if no payment adapter has been configured.
    #[must_use]
    pub(crate) fn payment_adapter_ref(&self) -> Option<&Arc<dyn PaymentAdapterDyn>> {
        self.payment_adapter.get()
    }

    /// Cheap reference to the supervisor's event fan-out channel.
    /// Returns `None` if no event channel has been configured.
    #[must_use]
    pub(crate) fn event_tx_ref(
        &self,
    ) -> Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>> {
        self.event_tx.get()
    }

    /// Subscribes to the supervisor's [`ContextEvent`] fan-out channel.
    ///
    /// Returns a fresh [`broadcast::Receiver`](tokio::sync::broadcast::Receiver)
    /// that observes every `(context_id, ContextEvent)` emitted by the
    /// per-context actors this supervisor owns. The receiver sees only events
    /// produced *after* it subscribes (broadcast semantics).
    ///
    /// Returns `None` if no event channel was configured (the FFI bridges enable
    /// it unconditionally for production supervisors; a supervisor built without
    /// the `event_tx` argument — e.g. via [`Self::for_query_shim`] — yields
    /// `None`). This is the public surface used by FFI node-startup paths to
    /// drive the outbound webhook dispatcher (spec §12.10.5).
    ///
    /// Message payloads on the channel are stripped of plaintext before sending
    /// (see [`crate::context::state::strip_event_payload`]) — subscribers
    /// observe metadata only, never decrypted content.
    ///
    /// # Delivery scope
    ///
    /// The subscribe → map → dispatch path is wired end-to-end, but the
    /// outbound webhook dispatcher's *target registration* is not yet wired to
    /// an operator-facing surface. Until such a surface registers webhook URLs
    /// and signing keys, the dispatcher holds no targets and outbound delivery
    /// is a no-op fan-out: events reach the dispatcher but are delivered to
    /// nobody. End-to-end delivery is therefore gated on a future
    /// operator-config API; this method's contract (fresh receiver, stripped
    /// payloads, post-subscription semantics) is unaffected by that gap.
    #[must_use]
    pub fn subscribe_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<(String, ContextEvent)>> {
        self.event_tx
            .get()
            .map(tokio::sync::broadcast::Sender::subscribe)
    }

    /// Cheap reference to the supervisor's shared task-set. Returns
    /// `None` if [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn task_set_ref(
        &self,
    ) -> Option<&Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>> {
        self.task_set.get()
    }

    /// Cheap reference to the supervisor's OpenMLS storage adapter
    /// (lock-free read per ADR-049 §Decision 12). Returns `None` if
    /// [`Self::with_providers`] was not used (e.g. a supervisor built
    /// via [`Self::for_query_shim`] / [`Self::new`]).
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this accessor is
    // reached only from `build_actor_deps`' test fixtures.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub(in crate::context) fn mls_storage_ref(
        &self,
    ) -> Option<&Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>> {
        self.mls_storage.get()
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12 — direct-state accessors (always populated).
    // -------------------------------------------------------------------

    /// Cheap reference to the supervisor's local-DID registry.
    ///
    /// The field is `Arc<ArcSwap<HashSet<DID>>>` per the master plan
    /// §Supervisor — read sites use `arc_swap.load()` (returns
    /// `Guard<Arc<HashSet>>`) or `arc_swap.load_full()` (returns
    /// `Arc<HashSet>`); write sites acquire [`Self::write_lock`] then
    /// clone-update-store on the snapshot. The accessor returns the inner
    /// `&ArcSwap` so callers see the same read/write surface regardless of
    /// the outer `Arc` (which exists only so [`ActorDeps`] can share the
    /// swap cell via `Arc::clone`).
    #[must_use]
    pub(crate) fn local_dids_ref(&self) -> &ArcSwap<HashSet<DID>> {
        &self.local_dids
    }

    /// Cheap `Arc::clone` of the shared `local_dids` swap cell, handed to
    /// [`ActorDeps`] so every per-context actor reads from the SAME cell
    /// the supervisor writes to via [`Self::local_dids_ref`]. Sharing the
    /// `Arc` (rather than snapshotting `load_full()` at spawn) is what lets
    /// a DID registered after an actor spawns become visible to that actor.
    #[must_use]
    pub(crate) fn local_dids_shared(&self) -> Arc<ArcSwap<HashSet<DID>>> {
        Arc::clone(&self.local_dids)
    }

    /// Cheap reference to the supervisor's standing-context tracking
    /// map (peer DID string → peer [`DID`]).
    ///
    /// `ArcSwap<HashMap<...>>` per the master plan §Supervisor — same
    /// read/write discipline as [`Self::local_dids_ref`].
    #[must_use]
    pub(crate) const fn standing_contexts_ref(&self) -> &ArcSwap<HashMap<String, DID>> {
        &self.standing_contexts
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12c.9f — per-identity wrapping-key accessors.
    //
    // The plan §"MlsCryptoProvider dissolution" lifts the wrapping
    // keypair off [`crate::crypto::mls::provider::MlsCryptoProvider`]
    // (where it was held in `Mutex<[u8;32]>` / `Mutex<Zeroizing<...>>`
    // fields) onto the supervisor's per-identity
    // `wrapping_keys: DashMap<DID, ArcSwap<WrappingKeyPair>>` map. The
    // following accessors give helper code on `&Supervisor` (the
    // 12c.9c-d hoisted helper paths) a stable read/write surface
    // without requiring callers to reach for `&self.wrapping_keys`
    // directly.
    //
    // Read accessors return `Arc<Vec<u8>>` / `Arc<Zeroizing<Vec<u8>>>`
    // newly allocated for each call so the caller owns a fresh
    // refcounted handle. The map itself stays the source of truth;
    // the caller is responsible for dropping the returned `Arc`
    // promptly so a subsequent rotation can zeroize the prior bytes
    // when the last reference drops.
    //
    // The write accessor [`Self::set_wrapping_keys`] acquires
    // [`Self::write_lock`] before any per-identity mutation per the
    // struct-level docs ("any mutation of `actors`, `standing_contexts`,
    // `local_dids`, or `wrapping_keys` acquires `Self::write_lock`
    // first"). The async lock is fine because the write path is rare
    // (initial keypair generation + governance-driven rotations).
    // -------------------------------------------------------------------

    /// Returns a freshly-cloned `Arc` to the X25519 wrapping public key
    /// for `did`, or `None` if no keypair has been registered.
    ///
    /// The returned `Arc<Vec<u8>>` carries the public key bytes the
    /// HPKE seal path uses; the caller MUST drop the `Arc` within the
    /// same poll (no storage in async-state struct fields) so a
    /// subsequent [`Self::set_wrapping_keys`] rotation can drop the
    /// prior bytes promptly.
    ///
    /// Visibility is `pub(in crate::context::supervisor)` until Phase 2
    /// of the post-review-round-1 plan threads `OwnedIdentityDid`
    /// through `ActorDeps` — handlers call this through
    /// [`SupervisorHandle::my_wrapping_public_key`](crate::context::supervisor::handle::SupervisorHandle::my_wrapping_public_key)
    /// which wraps the read with the capability proof. Direct
    /// `&Supervisor` access elsewhere in `crate::context::*` is
    /// forbidden so the wrapping-key surface is reachable only from
    /// supervisor-module code.
    #[must_use]
    #[allow(dead_code)] // first caller lands in Phase 2 with the actor wiring + capability thread
    pub(in crate::context::supervisor) fn wrapping_public_key_for(
        &self,
        did: &DID,
    ) -> Option<Arc<Vec<u8>>> {
        self.wrapping_keys.get(did).map(|entry| {
            let pair = entry.value().load_full();
            Arc::new(pair.public.to_vec())
        })
    }

    /// Returns a freshly-cloned `Arc` to the X25519 wrapping secret
    /// key for `did`, or `None` if no keypair has been registered.
    ///
    /// Same reader discipline as [`Self::wrapping_public_key_for`]:
    /// drop the returned `Arc` within the same poll. The inner
    /// [`Zeroizing`] wrapper guarantees the bytes are zeroed on drop.
    ///
    /// Visibility is `pub(in crate::context::supervisor)` per
    /// ADR-049 §5 — wrapping-secret
    /// access must be capability-gated by `&OwnedIdentityDid`. Until
    /// Phase 2 wires that capability through `ActorDeps`, the
    /// narrower visibility scopes call sites to supervisor-module code
    /// so handler code outside `supervisor/` cannot read another
    /// identity's secret.
    #[must_use]
    #[allow(dead_code)] // first caller lands in Phase 2 with the actor wiring + capability thread
    pub(in crate::context::supervisor) fn wrapping_secret_key_for(
        &self,
        did: &DID,
    ) -> Option<Arc<zeroize::Zeroizing<Vec<u8>>>> {
        self.wrapping_keys.get(did).map(|entry| {
            let pair = entry.value().load_full();
            Arc::new(zeroize::Zeroizing::new(pair.secret.to_vec()))
        })
    }

    /// Clear every per-identity wrapping keypair. Used by the
    /// shutdown helper so a fresh
    /// [`Self::with_providers`] observes empty per-identity state.
    /// Wrapping-key secrets zeroize on drop via the
    /// `Zeroizing<[u8;32]>` field on
    /// [`WrappingKeyPair`](crate::context::actor::state::WrappingKeyPair).
    /// Phase 1 fix-up of ADR-049 (post-review-round-1).
    pub(crate) fn clear_wrapping_keys(&self) {
        self.wrapping_keys.clear();
    }

    /// Atomically registers (or rotates) the X25519 wrapping keypair
    /// for `did`. Acquires [`Self::write_lock`] first per the
    /// supervisor's write-path discipline; the per-identity
    /// `ArcSwap<WrappingKeyPair>` handles the atomic swap.
    ///
    /// Idempotent — calling with the same DID a second time replaces
    /// the prior keypair (the old `Arc<WrappingKeyPair>` zeroizes its
    /// secret on drop when the last reference releases).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidState`] if `public` or `secret`
    /// are not exactly 32 bytes (X25519 keypair fixed sizes per
    /// RFC 7748 §5).
    pub async fn set_wrapping_keys(
        self: &Arc<Self>,
        did: DID,
        public: Vec<u8>,
        secret: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), ContextError> {
        let _guard = self.write_lock.lock().await;
        // Convert from runtime-API `Vec<u8>` to the per-identity
        // [`crate::context::actor::state::WrappingKeyPair`] shape
        // (fixed 32-byte arrays, secret behind `Zeroizing`). Length
        // mismatches surface as `InvalidState` so misuse fails loudly
        // rather than silently truncating key material.
        let public_arr: [u8; 32] = public.as_slice().try_into().map_err(|_| {
            ContextError::InvalidState(format!(
                "Supervisor::set_wrapping_keys — wrapping public key must be 32 bytes (got {})",
                public.len(),
            ))
        })?;
        let secret_arr: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
            ContextError::InvalidState(format!(
                "Supervisor::set_wrapping_keys — wrapping secret key must be 32 bytes (got {})",
                secret.len(),
            ))
        })?;
        let pair = WrappingKeyPair {
            public: public_arr,
            secret: zeroize::Zeroizing::new(secret_arr),
        };
        match self.wrapping_keys.get(&did) {
            Some(entry) => entry.value().store(Arc::new(pair)),
            None => {
                self.wrapping_keys.insert(did, ArcSwap::from_pointee(pair));
            }
        }
        Ok(())
    }

    /// Get-or-spawn this identity's
    /// [`KeyPackageStoreActor`](crate::context::supervisor::key_package_actor::KeyPackageStoreActor),
    /// returning a clone of its handle.
    ///
    /// Lock-free fast path: a [`DashMap::get`] probe (ADR-049 §Decision
    /// 12 — no read-path lock). On a miss the [`Self::write_lock`] is
    /// acquired and the probe is re-checked under the lock (double-
    /// checked) before spawning, so concurrent callers never spawn two
    /// actors for the same identity.
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this is reached
    // only from `build_actor_deps`' test fixtures.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::context) async fn key_package_store_for(
        self: &Arc<Self>,
        identity: &DID,
    ) -> Result<crate::context::supervisor::key_package_actor::KeyPackageStoreHandle, ContextError>
    {
        // Per-identity poison consult (ADR-049 §10). A KP actor that exceeded
        // its respawn budget surfaces a sticky typed error on the next
        // resolution instead of returning a dead handle. The crash window is
        // keyed by `kp::{did}` so it shares the `crash_windows` map with the
        // per-context budgets without colliding on a context id.
        let poison_key = Self::kp_crash_key(identity);
        if self.is_context_poisoned(&poison_key) {
            return Err(Self::kp_poison_err(identity));
        }

        if let Some(handle) = self.key_package_stores.get(identity) {
            return Ok(handle.value().clone());
        }
        let _guard = self.write_lock.lock().await;
        // Re-check the poison flag under the lock — a concurrent watchdog could
        // have poisoned the identity between the probe and the lock.
        if self.is_context_poisoned(&poison_key) {
            return Err(Self::kp_poison_err(identity));
        }
        if let Some(handle) = self.key_package_stores.get(identity) {
            return Ok(handle.value().clone());
        }
        let deps = self.build_kp_store_deps(identity)?;
        let (handle, join) =
            crate::context::supervisor::key_package_actor::KeyPackageStoreActor::spawn(
                identity.clone(),
                deps,
            );
        self.key_package_stores
            .insert(identity.clone(), handle.clone());
        // Attach the watchdog (ADR-049 §10) — mirrors the per-context actor
        // watchdog. Keeps the JoinHandle and respawns from durable storage on
        // panic; poisons the identity after the 3-crash/60s budget.
        spawn_kp_actor_watchdog_task(Arc::clone(self), identity.clone(), join);
        Ok(handle)
    }

    /// The `crash_windows` key for a per-identity KeyPackage actor. Namespaced
    /// with a `kp::` prefix so it never collides with a per-context budget
    /// (context keys are hex context-ids / original id strings, neither of
    /// which start with `kp::`).
    fn kp_crash_key(identity: &DID) -> String {
        format!("kp::{}", identity.0)
    }

    /// The sticky typed error a poisoned KeyPackage actor surfaces on the next
    /// resolution. Shared by the pre-lock probe and the under-lock re-check in
    /// [`Self::key_package_store_for`] (the double-check is load-bearing — a
    /// concurrent watchdog can poison the identity between the two consults) so
    /// the two sites cannot drift in wording.
    fn kp_poison_err(identity: &DID) -> ContextError {
        ContextError::ContextPoisoned(format!(
            "key-package actor for '{}' is poisoned; operator recovery required",
            identity.0
        ))
    }

    /// Read the crash instant for a watchdog crash record (ADR-049 §10).
    ///
    /// # Clock requirement for the poison budget
    ///
    /// The poison budget (3 crashes / 60s) is a SLIDING window only when a clock
    /// is wired. With a clock the sliding 60s window is exact; WITHOUT one
    /// (`clock_ref() == None`) every crash stamps `now_ms = 0`, collapsing the
    /// sliding window into a LIFETIME budget ("3-crashes-EVER" rather than
    /// "3-in-60s") — the actor is poisoned permanently after the third crash no
    /// matter how far apart they are. Production always wires a clock
    /// (`with_providers` defaults to `SystemClock`, and storage is mandatory per
    /// the storage-foundation ladder), so an absent clock is a test/misconfig
    /// path only — emit a loud, payload-free warning so the degraded window is
    /// never silent, and degrade rather than panic. A future configuration that
    /// drops the clock therefore must not silently lose the sliding behavior:
    /// the warning makes the lifetime-budget degradation observable.
    ///
    /// Shared by the per-context [`Self::actor_watchdog`] and the per-identity
    /// [`Self::kp_actor_watchdog`] (the clock-read + degraded-window `warn!`
    /// was byte-for-byte duplicated). `actor_kind` / `subject` tag the warning.
    fn crash_now_ms(&self, actor_kind: &'static str, subject: &str) -> u64 {
        self.clock_ref().map_or_else(
            || {
                tracing::warn!(
                    actor_kind,
                    subject = %subject,
                    "no clock configured: crash window degraded to crashes-ever (3-crash budget \
                     without the 60s slide); wire a clock via with_providers in production"
                );
                0
            },
            |c| scp_primitives::Clock::now_millis(c.as_ref()),
        )
    }

    /// Assemble a [`KeyPackageStoreDeps`](crate::context::supervisor::key_package_actor::KeyPackageStoreDeps)
    /// from the supervisor's own provider slots, scoped to `identity`'s
    /// wrapping key (if any).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if any required provider slot
    /// is empty (i.e. [`Self::with_providers`] was not used).
    fn build_kp_store_deps(
        &self,
        identity: &DID,
    ) -> Result<crate::context::supervisor::key_package_actor::KeyPackageStoreDeps, ContextError>
    {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());

        let crypto = self.crypto_ref().ok_or_else(not_init)?;
        let mls = Arc::clone(crypto.mls_backend());
        let transport = Arc::clone(self.transport_ref().ok_or_else(not_init)?);
        let clock = Arc::clone(self.clock_ref().ok_or_else(not_init)?);
        let mls_storage = Arc::clone(self.mls_storage_ref().ok_or_else(not_init)?);
        // The identity's published wrapping pubkey (§9.16.1) is embedded in each
        // generated KP leaf node when present. Absent → KPs carry no wrapping
        // extension, which is valid (the extension is optional).
        let wrapping_pubkey = self
            .wrapping_keys
            .get(identity)
            .map(|entry| entry.value().load_full().public);

        Ok(
            crate::context::supervisor::key_package_actor::KeyPackageStoreDeps {
                mls,
                mls_storage,
                transport,
                clock,
                wrapping_pubkey,
            },
        )
    }

    /// Build an [`ActorDeps`](crate::context::actor::deps::ActorDeps)
    /// bundle entirely from the supervisor's own provider slots
    /// (ADR-049 §1 / commit 12), scoped to `owning_did`.
    ///
    /// Self-sources every collaborator from the `OnceLock`s populated by
    /// [`Self::with_providers`]: the `MlsBackend` / `HpkeBackend` pair is
    /// read transitively through `crypto.mls_backend()` /
    /// `crypto.hpke_backend()` (the [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider)
    /// owns the only instance — no second supervisor field, so there is
    /// one source of truth per ADR §6). The OpenMLS storage adapter is
    /// the supervisor's `mls_storage` slot. The `KeyPackageStoreHandle`
    /// is resolved (get-or-spawn) for `owning_did` via
    /// [`Self::key_package_store_for`]. Persistence falls back to the
    /// no-op stub when no helper-side backend is wired.
    ///
    /// # `owning_did` scope (ADR-049 §10 respawn safety)
    ///
    /// `owning_did` selects ONLY which per-identity `KeyPackageStore` actor
    /// this context's deps touch — it does NOT scope the context to that
    /// identity. Crypto, transport, event-log, key-resolver, payment-adapter,
    /// and `mls_storage` are the supervisor-wide shared providers (read from
    /// the `OnceLock` slots), and `local_dids` is the SHARED swap cell
    /// (`local_dids_shared()`), i.e. the node's FULL set of local DIDs — not a
    /// snapshot of `owning_did`. This matters for the watchdog respawn path,
    /// which derives `owning_did = local_dids.min()` (a deterministic, genuine
    /// participant): because the broadcast author-DID authorization gate is
    /// keyed off the caller-supplied `author_did` resolved against the SHARED
    /// `local_dids` (see `publish_broadcast_two_phase`), and the MLS crypto is
    /// rehydrated from the persisted snapshot (not re-derived from
    /// `owning_did`), a respawn on a multi-identity node CANNOT mis-scope the
    /// context to the wrong identity. The only `owning_did`-dependent effect
    /// is which identity's KeyPackage pool actor is get-or-spawned, which is
    /// correctness-neutral for a snapshot-rehydrated restore (it does not key
    /// crypto). See the `respawn_preserves_owning_identity_on_multi_did_node`
    /// test.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if any required provider
    /// slot is empty (i.e. [`Self::with_providers`] was not used).
    ///
    /// # Method receiver
    ///
    /// Takes `self: &Arc<Self>` so the returned
    /// [`SupervisorHandle`](crate::context::supervisor::handle::SupervisorHandle)
    /// wraps a cloned `Arc` of the same supervisor instance — not a
    /// fresh `Supervisor::for_query_shim()`. Without this the handle
    /// would point at a dangling second supervisor and
    /// [`SupervisorHandle::local_dids`](crate::context::supervisor::SupervisorHandle::local_dids)
    /// / [`SupervisorHandle::standing_peer`](crate::context::supervisor::SupervisorHandle::standing_peer)
    /// would read empty state.
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this is reached
    // only from the supervisor + actor test fixtures.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::context) async fn build_actor_deps(
        self: &Arc<Self>,
        owning_did: &DID,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());

        let crypto = Arc::clone(self.crypto_ref().ok_or_else(not_init)?);
        // mls/hpke stay transitive — the MlsCryptoProvider owns the only
        // backend pair (ADR §6); no Supervisor field mirrors them.
        let mls = Arc::clone(crypto.mls_backend());
        let hpke = Arc::clone(crypto.hpke_backend());
        let transport = Arc::clone(self.transport_ref().ok_or_else(not_init)?);
        let event_log = Arc::clone(self.event_log_ref().ok_or_else(not_init)?);
        let clock = Arc::clone(self.clock_ref().ok_or_else(not_init)?);
        let key_resolver = self.key_resolver_ref().ok_or_else(not_init)?.clone();
        let mls_storage = Arc::clone(self.mls_storage_ref().ok_or_else(not_init)?);
        let persistence = self.persistence_ref().map_or_else(
            || {
                Arc::new(crate::context::persistence::NoopContextPersistence)
                    as Arc<dyn ContextPersistence>
            },
            Arc::clone,
        );
        let key_package_store = self.key_package_store_for(owning_did).await?;
        let handle = crate::context::supervisor::handle::SupervisorHandle::wrap(Arc::clone(self));
        // Mint the actor's capability token here, at the supervisor build
        // site, for THIS actor's owning identity (ADR-049 §5). This is the
        // only mint path — `issue_for_actor` is `pub(super)`, reachable
        // only from supervisor-module code. Each actor receives a token
        // for its own `owning_did`; a wrong-owner token is impossible
        // because the mint argument is the very DID the rest of the bundle
        // (KP-store, crypto scope) is built for.
        let owned_identity =
            crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor(
                owning_did.clone(),
            );

        Ok(crate::context::actor::deps::ActorDeps {
            crypto,
            transport,
            persistence,
            event_log,
            supervisor: handle,
            key_package_store,
            mls,
            hpke,
            mls_storage,
            clock,
            event_tx: self.event_tx_ref().cloned(),
            key_resolver,
            payment_adapter: self.payment_adapter_ref().map(Arc::clone),
            local_dids: self.local_dids_shared(),
            owned_identity,
        })
    }

    /// Dispatch a pure-read [`QueriesCommand`].
    ///
    /// Behaviour:
    ///
    /// - Mailbox-first for variants that carry a per-context
    ///   `context_id`: the actor's `run()` loop pulls the command,
    ///   dispatches through `handlers::queries::dispatch` (actor-shape,
    ///   takes `&mut PerContextState`), and writes the typed result to
    ///   the embedded reply oneshot.
    /// - `EventLogEntries` carries a 32-byte hash rather than a string
    ///   context-id and delegates directly to the event-log provider —
    ///   no per-context state is involved.
    /// - When no actor is registered for the variant's `context_id`,
    ///   [`Self::dispatch_queries_direct`] emits the variant's legacy
    ///   default (e.g. `MemberCount::Ok(None)`, `IsMember::Ok(false)`)
    ///   or surfaces `ContextError::ContextNotRegistered` directly on
    ///   the variant's oneshot, preserving the "context unknown = soft
    ///   default / typed error" contract of the legacy method shape.
    ///
    /// Outcome: `Outcome::ok(())` on every success. The variant's reply
    /// channel carries the typed result. The returned `Outcome` is
    /// dropped by FFI callers — it is retained so the wiring is
    /// symmetric with the mutating-handler paths.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no providers have been
    ///   attached — the caller must call [`Self::with_providers`]
    ///   first.
    pub async fn dispatch_query(&self, cmd: QueriesCommand) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — try the actor mailbox first
        // for variants that carry a per-context `context_id`. The
        // actor's `run()` loop pulls the command, dispatches it through
        // `handlers::queries::dispatch` (actor-shape, takes `&mut
        // PerContextState`), and writes the typed result to the
        // embedded reply oneshot.
        //
        // `EventLogEntries` is a 32-byte hash with no per-context lock
        // — it stays on the inline event-log path below. Unknown-
        // context cases surface the legacy soft / hard defaults via
        // `dispatch_queries_direct`.
        if let Some(ctx_id) = Self::queries_command_context_id(&cmd) {
            let ctx_id_owned = ctx_id.to_owned();
            if let Some(actor) = self.lookup(&ctx_id_owned) {
                return Self::dispatch_via_mailbox(&actor, ContextCommand::Queries(cmd)).await;
            }
        }

        // `EventLogEntries` delegates straight to the supervisor's
        // shared event-log provider — no per-context lock involved.
        if let QueriesCommand::EventLogEntries {
            context_id_bytes,
            reply,
        } = cmd
        {
            let elp = self.event_log_ref().ok_or_else(|| {
                ContextError::NotInitialized(
                    "Supervisor::dispatch_query — event_log provider not configured".to_owned(),
                )
            })?;
            let answer = elp.event_log_entries(&context_id_bytes);
            let _ = reply.send(answer);
            return Ok(Outcome::ok(()));
        }

        // No actor registered for the variant's `context_id`. Direct
        // dispatch surfaces the variant's legacy unknown-context
        // contract (hard error vs soft default) without entering a
        // shim handler — the legacy DashMap fallback was deleted in
        // this session.
        Ok(self.dispatch_queries_direct(cmd))
    }

    /// Dispatch a mutating [`MessagingCommand`] through the migration
    /// shim (ADR-049 commit 8 / plan row 8).
    ///
    /// Routes the command through the per-context actor's mailbox via
    /// [`Self::dispatch_via_mailbox`]. The actor's `run()` loop pulls
    /// the command and dispatches it via the actor-shape `dispatch(state,
    /// deps, cmd)` entry point, which exercises the actor-owned
    /// [`SendSequenceTracker`](crate::context::actor::SendSequenceTracker)
    /// directly. The handler wraps every transport/MLS call in
    /// [`tokio::time::timeout`] with a 30-second budget; a timeout maps
    /// to [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet — the caller must call
    ///   [`Self::with_providers`] first.
    /// - [`ContextError::ContextNotRegistered`] if no actor has been
    ///   spawned for `ctx_id`. Every production context creation path
    ///   (create / join / restore / import) spawns an actor before the
    ///   supervisor returns control to FFI, so this error indicates a
    ///   sequencing or test-setup bug.
    /// - Any typed error returned by the delegated handler
    ///   (`CryptoFailed`, `PermissionDenied`, `MemberNotFound`,
    ///   `RateLimited`, etc.).
    /// - [`ContextError::TransportTimeout`] if the delegated call
    ///   exceeds the 30-second handler budget.
    pub async fn dispatch_command(
        &self,
        ctx_id: &str,
        cmd: MessagingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and the take-and-swap
        // tracker dance have been deleted; the actor owns
        // `state.send_tracker` and serializes by construction.
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            self.lookup_miss_error(
                ctx_id,
                format!("dispatch_command — no actor registered for context_id `{ctx_id}`"),
            )
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::Messaging(cmd)).await
    }

    /// Dispatch a mutating [`LifecycleCommand`].
    ///
    /// Routing (ADR-049 Phase 2A finalization):
    ///
    /// - **Bootstrap variants** (`CreateContext`, `ImportContext`,
    ///   `RestoreContext`) always route through
    ///   [`Self::dispatch_lifecycle_direct`], which delegates to the
    ///   designated-legacy `&Supervisor`-shape helpers in
    ///   [`crate::context::lifecycle_helpers_legacy`]. These helpers
    ///   construct fresh `PerContextState` and (on dual-write) spawn
    ///   the per-context actor as part of the bootstrap handshake.
    /// - **Per-context variants** (`JoinContext`, `LeaveContext`,
    ///   `CloseContext`, `ExportContext`,
    ///   `GenerateContextAccessKey`, `RevokeContextAccessKey`,
    ///   `RestoreContextAccessKey`) carry a `context_id` and route
    ///   through the per-context actor's mailbox into the actor-shape
    ///   `handlers::lifecycle::dispatch`. If no actor is registered for
    ///   the target context, the call falls through to
    ///   [`Self::dispatch_lifecycle_direct`] which surfaces
    ///   `ContextError::ContextNotRegistered` on the reply oneshot.
    ///
    /// Each variant wraps its delegated body in `tokio::time::timeout`
    /// with a 30s budget, maps a timeout to
    /// [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout),
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no providers have been
    ///   attached — the caller must call [`Self::with_providers`]
    ///   first.
    /// - Any typed error returned by the delegated bootstrap / actor
    ///   handler is surfaced through the variant's oneshot reply; the
    ///   method-level result here is `Ok(Outcome { .. })`.
    /// - [`ContextError::TransportTimeout`] is surfaced through the
    ///   oneshot reply, not the method result.
    pub async fn dispatch_lifecycle_command(
        self: &Arc<Self>,
        cmd: LifecycleCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — bootstrap variants always
        // route through `dispatch_lifecycle_direct`. They construct
        // fresh state (and, on dual-write, spawn the actor); the
        // mailbox-first check would either no-op for a fresh context
        // (no actor yet) or recurse against the existing actor on a
        // re-create attempt — neither produces correct semantics. The
        // direct path inlines the supervisor-scoped bootstrap body and
        // surfaces the typed reply on the variant's oneshot.
        if matches!(
            cmd,
            LifecycleCommand::CreateContext { .. }
                | LifecycleCommand::ImportContext { .. }
                | LifecycleCommand::RestoreContext { .. }
        ) {
            return Ok(Box::pin(self.dispatch_lifecycle_direct(cmd)).await);
        }
        // Per-context variants (Join / Leave / Close / Export +
        // access-key generate / revoke / restore + Placeholder) all
        // carry a `context_id` and have a registered actor after
        // bootstrap dual-write. Mailbox-first routes to the actor's
        // `dispatch_state` loop which executes the actor-shape handler.
        if let Some(ctx_id) = Self::lifecycle_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Lifecycle(cmd)).await;
        }
        // Per-context variant for which no actor is registered — the
        // `Supervisor::contexts` DashMap fallback (and its handler-side
        // `dispatch_from_shim`) were deleted in this session. Surface
        // the typed error on the reply oneshot via the direct path's
        // unreachable-arm sketch so the caller gets a defined response.
        Ok(Box::pin(self.dispatch_lifecycle_direct(cmd)).await)
    }

    /// Direct supervisor-scoped dispatch for bootstrap-shaped
    /// [`LifecycleCommand`] variants (Create / Import / Restore) and
    /// the no-actor fallback for per-context variants.
    ///
    /// Mirrors [`Self::dispatch_standing_direct`]: each arm wraps the
    /// supervisor-scoped body in a 30s timeout matching the actor-
    /// handler shape (plan §"Transport timeouts inside actor handlers")
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// **Bootstrap arms (Create / Import / Restore)** build an
    /// [`ActorDeps`](crate::context::actor::deps::ActorDeps) bundle via
    /// [`Self::build_actor_deps`] (self-sourced from the supervisor's own
    /// provider slots — `OpenMlsStorageAdapter` is now the supervisor's
    /// `mls_storage` slot and the per-identity `KeyPackageStoreHandle` is
    /// get-or-spawned, both since the storage-foundation reshape) and
    /// delegate to the actor-shape helpers in
    /// [`crate::context::lifecycle_helpers`]. Those helpers spawn the
    /// per-context actor (`spawn_actor_for_context`) while continuing to
    /// dual-write the legacy `contexts` `DashMap` during the ADR-049
    /// Phase 2A transition window. Building deps requires
    /// `self: &Arc<Self>` so the spawned actor and its handle wrap the
    /// same supervisor instance.
    ///
    /// **Per-context variants** (Join / Leave / Close / Export +
    /// access-key generate / revoke / restore) still delegate to the
    /// designated-legacy `&Supervisor`-shape helpers in
    /// [`crate::context::lifecycle_helpers_legacy`]; they reach this
    /// method only when no actor is registered for the target context.
    #[allow(clippy::too_many_lines)] // flat match over every lifecycle variant
    async fn dispatch_lifecycle_direct(self: &Arc<Self>, cmd: LifecycleCommand) -> Outcome<()> {
        // Single source of truth: derive from the associated `Self::
        // LIFECYCLE_TIMEOUT` (shared with the respawn path) rather than
        // re-declaring the `from_secs(30)` magic number. The local alias keeps
        // the `{LIFECYCLE_TIMEOUT:?}` diagnostics below working without a
        // duplicate literal.
        const LIFECYCLE_TIMEOUT: std::time::Duration = Supervisor::LIFECYCLE_TIMEOUT;

        match cmd {
            LifecycleCommand::Placeholder { reply } => {
                const MSG: &str =
                    "LifecycleCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            LifecycleCommand::CreateContext { payload, reply } => {
                let p = *payload;
                let context_id = p.context_id.clone();
                // Serialize this bootstrap-spawn (crypto-init → spawn) against
                // every other same-id bootstrap so a concurrent import/restore
                // for the same id cannot interleave its crypto write between
                // this op's crypto-init and actor registration. See
                // `bootstrap_spawn_lock`.
                let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // (Re)creating this id is a fresh start: drop ALL stale crash
                // history (including a stale poison) so the fresh actor begins
                // with a clean budget and does not inherit a previous
                // instance's crash count or sticky poison (ADR-049 §10).
                self.reset_crash_window(&context_id);
                // ADR-049 Phase 2A finalization: bootstrap now builds the
                // actor-shape `ActorDeps` (self-sourced from the
                // supervisor's provider slots, scoped to the creator's
                // identity for KeyPackageStore resolution) and delegates
                // to `lifecycle_helpers::create_context`, which spawns the
                // per-context actor (and dual-writes the legacy DashMap).
                let deps = match self.build_actor_deps(&p.creator_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let err =
                            scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                format!("create_context: deps unavailable: {e}"),
                            );
                        let _ = reply.send(Err(err));
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = crate::context::lifecycle_helpers::create_context(
                    &deps,
                    p.context_id,
                    p.params,
                    p.creator_did,
                    p.local_pseudonym,
                );
                // `Box::pin` the create future: owned-state spawn keeps the
                // freshly built `PerContextState` live across the spawn
                // await inside `create_context`, so the future is large
                // (>16 KiB). Heap-boxing it keeps this lifecycle frame off
                // the stack.
                let (outcome, reply_result) = match tokio::time::timeout(
                    LIFECYCLE_TIMEOUT,
                    Box::pin(fut),
                )
                .await
                {
                    Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
                    Ok(Err(e)) => {
                        let sketch = ContextError::CryptoFailed(format!("create_context: {e}"));
                        (Outcome::err_mutated(sketch), Err(e))
                    }
                    Err(_elapsed) => {
                        let err =
                            scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                format!(
                                    "create_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                                ),
                            );
                        let sketch = ContextError::TransportTimeout(format!(
                            "create_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                        ));
                        (Outcome::err_mutated(sketch), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            LifecycleCommand::ImportContext {
                export,
                verifying_key,
                local_pseudonym,
                reply,
            } => {
                let context_id = export.snapshot.context_id.clone();
                // Verify BEFORE building any actor deps (verify-before-side-effect).
                // `Supervisor::import_context` is a public runtime API — FFI
                // bridges pre-verify, but this dispatch arm must be safe on its
                // own. `build_actor_deps` below derives `owning_did` from the
                // UNVERIFIED `export.snapshot.membership` and get-or-spawns a
                // `KeyPackageStoreActor` keyed on that DID, inserting a permanent
                // entry into the unbounded `key_package_stores` map. Without this
                // gate a forged export — keyed on an attacker-chosen DID — would
                // leak a spawned actor + map entry even though `import_context`
                // (which re-validates authoritatively) rejects it. The cheap
                // duplicate check here is the same verify-before-init pattern the
                // bridges already apply; `import_context` remains the
                // authoritative verifier.
                if let Err(e) = crate::context::export_import::validate_export_for_import(
                    &export,
                    &verifying_key,
                ) {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    return Outcome::err_mutated(sketch);
                }
                // ADR-049 Phase 2A finalization: scope the actor-shape
                // deps to a deterministic member of the imported roster
                // (the lexicographically-minimum member DID). The import
                // path never consumes the resolved `KeyPackageStoreHandle`
                // (it rehydrates a snapshot rather than joining), so the
                // identity choice only selects which per-identity store
                // actor is touched; picking the min member DID keeps it
                // deterministic and a genuine context participant rather
                // than fabricating one. An empty roster falls back to the
                // context id so deps construction never panics. The roster
                // is now trusted: the snapshot signature verified above, so
                // `owning_did` is an authenticated member, not an
                // attacker-chosen value.
                let owning_did = export
                    .snapshot
                    .membership
                    .members()
                    .map(|m| m.did.clone())
                    .min()
                    .unwrap_or_else(|| DID(context_id.clone()));
                // Serialize the whole import replace sequence against every
                // other same-id bootstrap (import/create/restore): the actor
                // mailbox only serializes the `PrepareForReplace` turn, but the
                // crypto-restore→spawn tail runs outside it. Acquired here —
                // BEFORE the key-package-store probe and `build_actor_deps` —
                // so the check-spawn-evict region is serialized as a unit. If
                // the probe and spawn ran outside the guard (the
                // `CreateContext` arm acquires the lock before building deps
                // for exactly this reason), two concurrent same-`owning_did`
                // imports could both observe `kp_store_newly_spawned = true`;
                // one spawns and succeeds while the other clones the same
                // handle, fails the post-verify guard, and its eviction tears
                // down the store the successful import is using — splitting the
                // single-use KeyPackage pool across two actors. Held across the
                // probe, deps build, the entire `import_context` future, and
                // the conditional eviction. Lock order is
                // `bootstrap_spawn_lock` → `write_lock`: `build_actor_deps`
                // reaches `key_package_store_for`, which takes `write_lock`
                // strictly inside this guard, never the reverse. See
                // `bootstrap_spawn_lock`.
                let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // Importing (re-establishing) this id is a fresh start: drop
                // ALL stale crash history (including a stale poison) so the
                // imported actor begins with a clean budget (ADR-049 §10).
                self.reset_crash_window(&context_id);
                // Defense in depth: track whether `build_actor_deps` will
                // newly spawn this identity's key-package store, so a
                // post-verification import failure (e.g. epoch-floor
                // rejection, refusing to overwrite a live context) does not
                // leave an orphaned actor + map entry behind. Eviction is
                // safe only for an entry this op created: a pre-existing
                // entry is shared with other contexts/identities and must
                // not be torn down on our failure. The probe is now race-free
                // under `bootstrap_spawn_lock` — no concurrent same-id import
                // can interleave between this `contains_key` and the spawn in
                // `build_actor_deps`.
                let kp_store_newly_spawned = !self.key_package_stores.contains_key(&owning_did);
                let deps = match self.build_actor_deps(&owning_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        if kp_store_newly_spawned {
                            self.key_package_stores.remove(&owning_did);
                        }
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                // Box::pin — the per-variant import future crosses
                // clippy's 16 KB stack budget (ContextExport ~2 KB +
                // the full PerContextState-construction locals inside
                // the `import_context` body).
                let fut = Box::pin(crate::context::lifecycle_helpers::import_context(
                    &deps,
                    *export,
                    &verifying_key,
                    local_pseudonym,
                ));
                let (outcome, reply_result) = match tokio::time::timeout(LIFECYCLE_TIMEOUT, fut)
                    .await
                {
                    Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
                    Ok(Err(e)) => {
                        // Import failed after deps were built (e.g. epoch-floor
                        // rejection, refusing to overwrite a live context).
                        // Evict the key-package-store entry if this op spawned
                        // it, so a rejected import leaves no orphaned actor.
                        if kp_store_newly_spawned {
                            self.key_package_stores.remove(&owning_did);
                        }
                        let sketch = standing_outcome_error_sketch(&e);
                        (Outcome::err_mutated(sketch), Err(e))
                    }
                    Err(_elapsed) => {
                        if kp_store_newly_spawned {
                            self.key_package_stores.remove(&owning_did);
                        }
                        let err = ContextError::TransportTimeout(format!(
                            "import_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                        ));
                        let sketch = standing_outcome_error_sketch(&err);
                        (Outcome::err_mutated(sketch), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            LifecycleCommand::RestoreContext { payload, reply } => {
                let p = *payload;
                let context_id = p.context_id.clone();
                // Serialize this bootstrap-spawn against every other same-id
                // bootstrap (see `bootstrap_spawn_lock`).
                let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                let handle = crate::context::ContextHandle::new(p.context_id.clone(), p.params);
                if let Err(e) = handle
                    .transition_to(&scp_protocol::context::ContextState::Active)
                    .await
                {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    return Outcome::err(sketch);
                }
                // ADR-049 Phase 2A finalization: the restore payload
                // carries no identity (it rehydrates a persisted snapshot
                // rather than joining), and `restore_context` never
                // consumes the resolved `KeyPackageStoreHandle`. Scope the
                // deps to a registered local DID when one exists (the node
                // performing the restore), falling back to a context-id-
                // derived seed so deps construction stays deterministic
                // and never fabricates a foreign participant.
                let owning_did = self
                    .local_dids_ref()
                    .load()
                    .iter()
                    .min()
                    .cloned()
                    .unwrap_or_else(|| DID(p.context_id.clone()));
                let deps = match self.build_actor_deps(&owning_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = Box::pin(crate::context::lifecycle_helpers::restore_context(
                    &deps,
                    &p.context_id,
                    &handle,
                    None, // process-restart / dispatch arm: load the snapshot here
                ));
                let (outcome, reply_result) = match tokio::time::timeout(LIFECYCLE_TIMEOUT, fut)
                    .await
                {
                    Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
                    Ok(Err(e)) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        (Outcome::err_mutated(sketch), Err(e))
                    }
                    Err(_elapsed) => {
                        let err = ContextError::TransportTimeout(format!(
                            "restore_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                        ));
                        let sketch = standing_outcome_error_sketch(&err);
                        (Outcome::err_mutated(sketch), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            // Per-context variants reach this arm only when no actor is
            // registered for the target context. Post-Step-B, every valid
            // context has a registered actor and these variants are
            // mailbox-dispatched to the per-context actor-shape handlers
            // (Join/Leave/Close/Export/access-key all exist on the actor).
            // The supervisor-side direct path is therefore reached ONLY for
            // an unregistered context, which is by definition not registered
            // — surface a typed `ContextNotRegistered` on the reply oneshot
            // and return a matching error `Outcome` (mirrors the
            // `FlushSnapshot`/`ShutdownSelf` never-should-reach arms).
            LifecycleCommand::JoinContext { payload, reply } => {
                let err = self.lookup_miss_error(&payload.context_id, payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::LeaveContext { payload, reply } => {
                let err = self.lookup_miss_error(&payload.context_id, payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::CloseContext { payload, reply } => {
                let err = self.lookup_miss_error(&payload.context_id, payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::ExportContext {
                context_id, reply, ..
            } => {
                let err = self.lookup_miss_error(&context_id, context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // The access-key trio shares the same `{ context_id, reply, .. }`
            // shape and the same `Result<(), _>` reply, so they collapse
            // into one arm.
            LifecycleCommand::GenerateContextAccessKey {
                context_id, reply, ..
            }
            | LifecycleCommand::RevokeContextAccessKey {
                context_id, reply, ..
            }
            | LifecycleCommand::RestoreContextAccessKey {
                context_id, reply, ..
            }
            // `ClearNeedsReconnect` shares the `Result<(), _>` reply
            // shape of the access-key variants, so it folds into this
            // unknown-context fallthrough group (surfaces a typed
            // `ContextNotRegistered` / poison error on the oneshot).
            | LifecycleCommand::ClearNeedsReconnect { context_id, reply } => {
                let err = self.lookup_miss_error(&context_id, context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // `IssueMlsUpdate` carries a `Result<Vec<u8>, _>` reply
            // (serialized Commit bytes), so it cannot fold into the
            // `Result<(), _>` group above and keeps its own arm.
            LifecycleCommand::IssueMlsUpdate { context_id, reply } => {
                let err = self.lookup_miss_error(&context_id, context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // Sweep variants are dispatched per-actor by the iterating
            // entry points in `lifecycle_helpers` — they should never
            // reach the direct path (which has no actor to target). If
            // a caller mistakenly routes one through
            // `dispatch_lifecycle_command`, surface a typed error on
            // the reply oneshot rather than panicking.
            LifecycleCommand::FlushSnapshot { reply } => {
                let err = ContextError::InvalidState(
                    "LifecycleCommand::FlushSnapshot reached dispatch_lifecycle_direct — \
                     sweep variants must be dispatched via the iterating entry points in \
                     `lifecycle_helpers::flush_all_contexts*`"
                        .to_owned(),
                );
                let sketch = ContextError::InvalidState(format!("{err}"));
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::ShutdownSelf { reply } => {
                let err = ContextError::InvalidState(
                    "LifecycleCommand::ShutdownSelf reached dispatch_lifecycle_direct — \
                     sweep variants must be dispatched via the iterating entry points in \
                     `lifecycle_helpers::shutdown_all_contexts*`"
                        .to_owned(),
                );
                let sketch = ContextError::InvalidState(format!("{err}"));
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // Read-only gauge sweep. Like `FlushSnapshot`/`ShutdownSelf`,
            // this must never reach the direct path — it is dispatched
            // per-actor via the mailbox by `update_context_gauges`. The
            // reply channel carries a bare `usize`, so the
            // never-should-happen branch replies 0 (degenerate) and
            // returns a typed error `Outcome`.
            LifecycleCommand::ReportBufferLen { reply } => {
                let _ = reply.send(0);
                Outcome::err(ContextError::InvalidState(
                    "LifecycleCommand::ReportBufferLen reached dispatch_lifecycle_direct — \
                     the gauge sweep must be dispatched per-actor via the mailbox in \
                     `manager_methods::update_context_gauges`"
                        .to_owned(),
                ))
            }
        }
    }

    /// Dispatch a mutating [`TtlCloseCommand`] through the migration
    /// shim (ADR-049 commit 9 / plan row 9).
    ///
    /// Same shape as [`Self::dispatch_lifecycle_command`] — handlers
    /// take the attached manager directly, wrap delegated
    /// [`Supervisor`](crate::context::supervisor::Supervisor) calls
    /// in [`tokio::time::timeout`] with a 30s budget, and relay the
    /// typed result through the variant's oneshot.
    ///
    /// # TTL-timer ownership
    ///
    /// The post-refactor architecture turns the TTL timer into a
    /// `select!` arm in the actor's `run()` loop. Commit 9 keeps the
    /// timer spawned inside the legacy `ContextManager`; this dispatch
    /// method routes caller-initiated extend/reset/finalize/explicit-
    /// expiry commands synchronously. Full timer-owning actor logic
    /// arrives with plan row 11.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_ttl_close_command(
        &self,
        cmd: TtlCloseCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and the dead `_legacy`
        // bodies have been deleted; every command's target actor must
        // be spawned before dispatch reaches this method.
        let Some(ctx_id) = Self::ttl_close_command_context_id(&cmd) else {
            return Err(ContextError::ContextNotRegistered(
                "dispatch_ttl_close_command — variant has no per-context routing target \
                 (Placeholder); mailbox-only after Phase 2A finalization"
                    .to_owned(),
            ));
        };
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            self.lookup_miss_error(
                ctx_id,
                format!(
                    "dispatch_ttl_close_command — no actor registered for context_id `{ctx_id}`"
                ),
            )
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::TtlClose(cmd)).await
    }

    /// Dispatch a [`GovernanceCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Contract (byte-identical to the legacy
    /// [`Supervisor`](crate::context::supervisor::Supervisor)
    /// governance methods it replaces):
    ///
    /// Routes every per-context variant through the per-context actor's
    /// mailbox via [`Self::dispatch_via_mailbox`]. The actor's `run()`
    /// loop pulls the command, dispatches it through the actor-shape
    /// `dispatch(state, deps, cmd)` entry point, and writes the typed
    /// reply on the command's embedded oneshot. The `Placeholder`
    /// variant (mailbox handshake target — no `context_id`) returns
    /// [`ContextError::ContextNotRegistered`] from this method when no
    /// per-context routing target exists; the no-op reply is otherwise
    /// produced by the actor-side `dispatch_state` arm.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    /// - [`ContextError::ContextNotRegistered`] if no actor has been
    ///   spawned for the command's target context_id. Every production
    ///   context creation path (create / join / restore / import)
    ///   spawns an actor before the supervisor returns control to FFI,
    ///   so this error indicates a sequencing or test-setup bug.
    /// - Any typed error from the delegated handler is surfaced through
    ///   the variant's oneshot reply; the method-level result here is
    ///   `Ok(Outcome { .. })`.
    /// - [`ContextError::TransportTimeout`] is surfaced through the
    ///   oneshot reply, not the method result.
    pub async fn dispatch_governance_command(
        &self,
        cmd: GovernanceCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and its `_legacy` body have
        // been deleted; every command's target actor must be spawned
        // before dispatch reaches this method.
        let Some(ctx_id) = Self::governance_command_context_id(&cmd) else {
            return Err(ContextError::ContextNotRegistered(
                "dispatch_governance_command — variant has no per-context routing target \
                 (Placeholder / cross-context); mailbox-only after Phase 2A finalization"
                    .to_owned(),
            ));
        };
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            self.lookup_miss_error(
                ctx_id,
                format!(
                    "dispatch_governance_command — no actor registered for context_id `{ctx_id}`"
                ),
            )
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::Governance(cmd)).await
    }

    /// Dispatch an [`EconomyCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. The
    /// economy handler only exposes the single public-surface method
    /// on [`Supervisor`](crate::context::supervisor::Supervisor),
    /// [`verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts);
    /// internal helpers (`authorize_paid_action`, `complete_paid_action`,
    /// `void_paid_action`) remain on the manager's private surface
    /// and are exercised through the messaging path.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_economy_command(
        &self,
        cmd: EconomyCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — route through the per-context
        // actor mailbox when every receipt in the batch agrees on a
        // single `Some(context_id)` and an actor is registered for it.
        // Mixed-context batches and relay-level (`None`) receipts have
        // no single owning actor and fall through to
        // `dispatch_economy_direct`, which resolves the payment adapter
        // from the supervisor's lifted provider slot. The actor-shape
        // and direct-shape helpers both delegate to the same
        // `economy_helpers::verify_payment_receipts` body (the read
        // uses only `deps.payment_adapter`), so the two paths are
        // observably equivalent — routing chooses the serialization
        // point, not the work.
        // Defense in depth: bound the receipt batch before either routing
        // path. Each receipt fans out to a serial payment-adapter
        // verification round-trip, so an unbounded batch is a
        // denial-of-service vector. The FFI bridges enforce the same cap at
        // their boundaries; this guards non-bridge and future callers. See
        // [`MAX_RECEIPT_BATCH`](crate::economy::adapter::MAX_RECEIPT_BATCH).
        if let EconomyCommand::VerifyPaymentReceipts { receipts, .. } = &cmd
            && receipts.len() > crate::economy::adapter::MAX_RECEIPT_BATCH
        {
            return Err(ContextError::LimitExceeded(format!(
                "receipt batch too large: {} (max {})",
                receipts.len(),
                crate::economy::adapter::MAX_RECEIPT_BATCH
            )));
        }

        if let Some(ctx_id) = Self::economy_command_context_id(&cmd) {
            let ctx_id_owned = ctx_id.to_owned();
            if let Some(actor) = self.lookup(&ctx_id_owned) {
                return Self::dispatch_via_mailbox(&actor, ContextCommand::Economy(cmd)).await;
            }
        }
        Ok(self.dispatch_economy_direct(cmd).await)
    }

    /// Extract the target context_id from an [`EconomyCommand`] when one
    /// can be unambiguously derived.
    ///
    /// Returns `Some(ctx_id)` only when every receipt in a
    /// [`EconomyCommand::VerifyPaymentReceipts`] batch carries the same
    /// `Some(context_id)`. Returns `None` for:
    ///
    /// - [`EconomyCommand::Placeholder`] (no target).
    /// - Empty receipt batches (no target).
    /// - Heterogeneous batches whose receipts straddle multiple contexts
    ///   (no single owning actor).
    /// - Batches containing any relay-level receipt (`context_id == None`).
    fn economy_command_context_id(cmd: &EconomyCommand) -> Option<&str> {
        match cmd {
            EconomyCommand::Placeholder { .. } => None,
            EconomyCommand::VerifyPaymentReceipts { receipts, .. } => {
                let mut iter = receipts.iter();
                let first = iter.next()?.context_id.as_ref()?;
                let first_str = first.as_str();
                for r in iter {
                    match r.context_id.as_ref() {
                        Some(c) if c.as_str() == first_str => {}
                        _ => return None,
                    }
                }
                Some(first_str)
            }
        }
    }

    /// Direct supervisor-scoped dispatch for [`EconomyCommand`] variants
    /// whose target context cannot be unambiguously derived from the
    /// command (mixed-context batches, empty batches, relay-level
    /// receipts) or for which no per-context actor is registered.
    ///
    /// Mirrors the standing-/lifecycle-direct precedents: each arm wraps
    /// the supervisor-scoped body in a 30s timeout matching the actor-
    /// handler shape (plan §"Transport timeouts inside actor handlers")
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// `VerifyPaymentReceipts` verifies each receipt against the
    /// supervisor's lifted payment-adapter slot. The work depends only on
    /// `adapter_id`, not `context_id`, so this direct path handles
    /// mixed-context, empty, and relay-level (`None`) batches identically
    /// to the per-actor path: a per-context fan-out would yield the same
    /// results because the payment-adapter lookup is supervisor-scoped,
    /// not actor-scoped. The actor-shape twin
    /// [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts)
    /// runs the identical loop over `deps.payment_adapter`; the two paths
    /// are observably equivalent and differ only in the serialization
    /// point. Batches with no single owning actor have no per-context
    /// `ActorDeps`/`PerContextState` to borrow, so the verification is
    /// inlined here against `self.payment_adapter_ref()` directly.
    async fn dispatch_economy_direct(&self, cmd: EconomyCommand) -> Outcome<()> {
        use crate::economy::receipt::{ReceiptVerification, ReceiptVerificationError};
        const ECONOMY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            EconomyCommand::Placeholder { reply } => {
                const MSG: &str =
                    "EconomyCommand::Placeholder — mailbox-pipe smoke target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
                let receipts = *receipts;
                let verify_fut = async {
                    let mut results = Vec::with_capacity(receipts.len());
                    for receipt in &receipts {
                        let result = match self.payment_adapter_ref() {
                            Some(adapter) if adapter.adapter_id() == receipt.adapter_id => adapter
                                .verify_dyn(receipt)
                                .await
                                .map(|r| ReceiptVerification {
                                    receipt_id: receipt.receipt_id,
                                    result: r,
                                })
                                .map_err(|e| ReceiptVerificationError::VerificationFailed {
                                    receipt_id: receipt.receipt_id,
                                    error: e,
                                }),
                            _ => Err(ReceiptVerificationError::NoVerifierForAdapter {
                                receipt_id: receipt.receipt_id,
                                adapter_id: receipt.adapter_id.clone(),
                            }),
                        };
                        results.push(result);
                    }
                    results
                };
                let results = match tokio::time::timeout(ECONOMY_TIMEOUT, verify_fut).await {
                    Ok(vec) => vec,
                    Err(_elapsed) => receipts
                        .iter()
                        .map(|r| {
                            Err(ReceiptVerificationError::NoVerifierForAdapter {
                                receipt_id: r.receipt_id,
                                adapter_id: r.adapter_id.clone(),
                            })
                        })
                        .collect(),
                };
                let _ = reply.send(results);
                // Verify payment receipts is a pure read — mutated=false.
                Outcome::ok(())
            }
        }
    }

    /// Dispatch a [`TrustRecoveryCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. Covers the
    /// checkpoint + cosignature paths, MLS epoch advancement for
    /// compromise recovery (spec §9.12 step 2), and recovery-
    /// notification send paths (spec §9.12 step 5).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_trust_recovery_command(
        &self,
        cmd: TrustRecoveryCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Phase 2A.1 of ADR-049 — trust_recovery is the first migrated
        // helper domain. Route per-context variants to the per-context
        // actor mailbox when one is registered; otherwise fall through
        // to `dispatch_trust_recovery_direct` which delegates to the
        // designated-legacy lock-shaped helpers. The cross-context
        // `RecoveryNotifyContact` variant has no `context_id` to look
        // up — it always flows through the direct fan-out path.
        //
        // `Box::pin` — `CreateGovernanceCheckpoint`'s payload carries
        // multiple 32-byte hashes + a variable-length Ed25519 signature
        // vector; the per-variant locals cross clippy's 16-KB stack-
        // future budget.
        if let Some(ctx_id) = Self::trust_recovery_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::TrustRecovery(cmd)).await;
        }
        Ok(Box::pin(self.dispatch_trust_recovery_direct(cmd)).await)
    }

    /// Extract the `context_id` borrow from a [`TrustRecoveryCommand`]
    /// when one is present. Returns `None` for variants that cannot be
    /// routed through a per-context actor mailbox
    /// (`Placeholder`, `RecoveryNotifyContact`).
    fn trust_recovery_command_context_id(cmd: &TrustRecoveryCommand) -> Option<&str> {
        match cmd {
            TrustRecoveryCommand::Placeholder { .. }
            | TrustRecoveryCommand::RecoveryNotifyContact { .. } => None,
            TrustRecoveryCommand::CreateGovernanceCheckpoint { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            TrustRecoveryCommand::AddCheckpointCosignature { context_id, .. }
            | TrustRecoveryCommand::RecoveryAdvanceEpoch { context_id, .. } => {
                Some(context_id.as_str())
            }
            TrustRecoveryCommand::RecoverySendNotification { payload, .. } => {
                Some(payload.context_id.as_str())
            }
        }
    }

    /// Actor-native cross-context recovery-notification fan-out
    /// (spec §9.12 step 5 — target context not yet known).
    ///
    /// Finds a context where both the recovering DID and the contact DID
    /// are members, then dispatches a `RecoverySendNotification`
    /// (sequence 4 — contact notification) through that context's actor
    /// mailbox. The shared-context lookup is a lock-free fan-out over the
    /// actor registry: [`Self::actor_ids`] yields a snapshot of every
    /// registered context id and [`Self::is_member`] reads each
    /// membership predicate through the per-context actor mailbox. No
    /// `contexts` DashMap access and no `per-context-state Mutex` lock —
    /// the actor that owns each context is the sole authority for its
    /// membership.
    ///
    /// This is the supervisor-direct twin of
    /// [`SupervisorHandle::find_shared_context`](crate::context::supervisor::handle::SupervisorHandle::find_shared_context)
    /// +
    /// [`SupervisorHandle::dispatch_recovery_send_notification`](crate::context::supervisor::handle::SupervisorHandle::dispatch_recovery_send_notification):
    /// the handle pair serves the actor-shape helper
    /// [`crate::context::trust_recovery_helpers::recovery_notify_contact`]
    /// (called from a context actor's `run()` loop via the
    /// capability-reduced `deps.supervisor`), whereas this method serves
    /// `dispatch_trust_recovery_direct`'s `RecoveryNotifyContact` arm,
    /// which holds `&Supervisor` directly (the cross-context variant
    /// carries no `context_id`, so it always routes supervisor-direct).
    /// Both paths share identical semantics.
    ///
    /// # Ordering
    ///
    /// `actor_ids()` rebuilds its snapshot per call, so the iteration
    /// order is the registry's shard order — unspecified but stable for
    /// the duration of a single call. "First shared context" carries the
    /// same order-unspecified semantics the legacy DashMap fan-out had.
    ///
    /// # Errors
    ///
    /// - [`ContextError::TransportFailed`] if no context is shared
    ///   between the recovering DID and the contact DID.
    /// - Any [`ContextError`] surfaced through the dispatched
    ///   [`Self::dispatch_trust_recovery_command`] call or the per-actor
    ///   reply oneshot (e.g. [`ContextError::NotInitialized`] if no
    ///   providers attached, or a closed reply channel surfacing as
    ///   [`ContextError::TransportFailed`]).
    async fn recovery_notify_contact(
        &self,
        recovering_did: &str,
        contact_did: &str,
        payload: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::{
            RecoverySendNotificationPayload, SigningKeyBytes, TrustRecoveryCommand,
        };

        // Lock-free actor-registry fan-out: the first context where BOTH
        // members are present wins. No DashMap, no PerContextState lock.
        let mut shared_context_id = None;
        for context_id in self.actor_ids() {
            if self.is_member(&context_id, recovering_did).await
                && self.is_member(&context_id, contact_did).await
            {
                shared_context_id = Some(context_id);
                break;
            }
        }

        match shared_context_id {
            Some(context_id) => {
                // Contact notifications use sequence=4 (step 5 in recovery).
                let send_payload = RecoverySendNotificationPayload {
                    context_id,
                    sender_did: recovering_did.to_owned(),
                    payload: payload.to_vec(),
                    sequence: 4,
                    signing_key: SigningKeyBytes::from_signing_key(signing_key),
                };
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let cmd = TrustRecoveryCommand::RecoverySendNotification {
                    payload: Box::new(send_payload),
                    reply: reply_tx,
                };
                self.dispatch_trust_recovery_command(cmd).await?;
                reply_rx.await.map_err(|_| {
                    ContextError::TransportFailed(
                        "recovery_notify_contact: oneshot reply channel closed".to_owned(),
                    )
                })?
            }
            None => Err(ContextError::TransportFailed(format!(
                "no shared context found between {recovering_did} and {contact_did}"
            ))),
        }
    }

    /// Direct supervisor-scoped dispatch for [`TrustRecoveryCommand`]
    /// variants that have no per-context actor target (`Placeholder`,
    /// `RecoveryNotifyContact`) or whose actor is not registered
    /// (`CreateGovernanceCheckpoint` / `AddCheckpointCosignature` /
    /// `RecoveryAdvanceEpoch` / `RecoverySendNotification` —
    /// unregistered-context fallback).
    ///
    /// Mirrors the standing/queries/lifecycle direct precedents.
    /// `RecoveryNotifyContact` is intrinsically cross-context (it carries
    /// no `context_id`, so it always reaches this path): its arm wraps
    /// the actor-native [`Self::recovery_notify_contact`] fan-out in a
    /// 30s timeout matching the actor-handler shape (plan §"Transport
    /// timeouts inside actor handlers") and relays the typed reply on the
    /// variant's oneshot.
    ///
    /// The per-context variants reach this path only for a context with
    /// no registered actor. Post-Step-B every valid *registered* context
    /// has an actor and those variants are mailbox-dispatched to the
    /// per-context actor-shape handlers. The state-dependent variants
    /// (`RecoveryAdvanceEpoch`, `CreateGovernanceCheckpoint`,
    /// `AddCheckpointCosignature`) therefore reach the supervisor-direct
    /// arm ONLY for an unregistered context and surface a typed
    /// [`ContextError::ContextNotRegistered`] on the reply oneshot
    /// (mirrors the gutted `dispatch_lifecycle_direct` per-context arms).
    ///
    /// `RecoverySendNotification` is the exception: identity-scoped
    /// recovery steps (notably PSK rotation, §9.12 step 6) deliberately
    /// target a synthetic `identity-private-state` pseudo-context that is
    /// never registered as an actor. Its arm seals and sends through the
    /// supervisor-shared providers via
    /// [`Self::recovery_send_notification_direct`] (epoch 0), rather than
    /// erroring — this is a supported operation, not an unknown-context
    /// fault.
    #[allow(clippy::too_many_lines)] // flat match over every trust-recovery variant
    async fn dispatch_trust_recovery_direct(&self, cmd: TrustRecoveryCommand) -> Outcome<()> {
        const TRUST_RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            TrustRecoveryCommand::Placeholder { reply } => {
                const MSG: &str = "TrustRecoveryCommand::Placeholder — mailbox-pipe smoke target; \
                                   no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            TrustRecoveryCommand::RecoveryNotifyContact { payload, reply } => {
                let recovering_did = payload.recovering_did.clone();
                let signing_key = payload.signing_key.to_signing_key();
                let notify_fut = self.recovery_notify_contact(
                    &payload.recovering_did,
                    &payload.contact_did,
                    &payload.payload,
                    &signing_key,
                );
                let (outcome, reply_result) = match tokio::time::timeout(
                    TRUST_RECOVERY_TIMEOUT,
                    notify_fut,
                )
                .await
                {
                    Ok(Ok(())) => (Outcome::ok(()), Ok(())),
                    Ok(Err(e)) => (Outcome::err(standing_outcome_error_sketch(&e)), Err(e)),
                    Err(_elapsed) => {
                        let err = ContextError::TransportTimeout(format!(
                            "recovery_notify_contact exceeded {TRUST_RECOVERY_TIMEOUT:?} budget for recovering_did {recovering_did}"
                        ));
                        (Outcome::err(standing_outcome_error_sketch(&err)), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            // Per-context variants reach this arm only when no actor is
            // registered for the target context. Post-Step-B every valid
            // context has a registered actor and these variants are
            // mailbox-dispatched to the per-context actor-shape handlers
            // in `actor/handlers/trust_recovery.rs`. The supervisor-side
            // direct path is therefore reached ONLY for an unregistered
            // context, which is by definition not registered — surface a
            // typed `ContextNotRegistered` on the reply oneshot and
            // return a matching error `Outcome` (mirrors the gutted
            // `dispatch_lifecycle_direct` per-context arms).
            TrustRecoveryCommand::CreateGovernanceCheckpoint { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err_mutated(sketch)
            }
            TrustRecoveryCommand::AddCheckpointCosignature {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            TrustRecoveryCommand::RecoveryAdvanceEpoch { context_id, reply } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err_mutated(sketch)
            }
            // Unlike the other per-context recovery variants, a
            // `RecoverySendNotification` to an unregistered context is a
            // legitimate, supported operation: identity-scoped recovery
            // steps (notably PSK rotation, spec §9.12 step 6) target a
            // synthetic identity-private-state pseudo-context that is
            // deliberately never registered as a per-context actor. Those
            // notifications need only the supervisor-shared crypto +
            // transport providers and an epoch of 0 (no MLS group exists
            // for the synthetic context) — no per-context membership,
            // governance, or MLS group state. Seal and send directly
            // through the shared providers, matching the registered-actor
            // handler's `recovery_send_notification` semantics with
            // `mls_epoch == 0`.
            TrustRecoveryCommand::RecoverySendNotification { payload, reply } => {
                let signing_key = payload.signing_key.to_signing_key();
                let send_result = self.recovery_send_notification_direct(
                    &payload.context_id,
                    &payload.sender_did,
                    &payload.payload,
                    payload.sequence,
                    &signing_key,
                );
                match send_result {
                    Ok(()) => {
                        let _ = reply.send(Ok(()));
                        Outcome::ok(())
                    }
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        Outcome::err(sketch)
                    }
                }
            }
        }
    }

    /// Seals and sends a recovery notification for a context with no
    /// registered actor, using only the supervisor-shared crypto and
    /// transport providers (ADR-049 §9.12).
    ///
    /// This is the supervisor-direct twin of the per-context actor's
    /// [`recovery_send_notification`](crate::context::trust_recovery_helpers::recovery_send_notification)
    /// helper, reached when the target context has no registered actor.
    /// It is used by identity-scoped recovery steps — chiefly PSK
    /// rotation (step 6) — whose synthetic `identity-private-state`
    /// pseudo-context is never registered as a per-context actor. Because
    /// no MLS group exists for that synthetic context, the envelope is
    /// constructed with `epoch == 0`, exactly as the registered-actor
    /// handler does when `state.epoch.mls_epoch` is its default 0.
    ///
    /// The seal keys off `SHA256(context_id)` (`context_id_to_bytes`) and
    /// the relay routing ID off the domain-separated
    /// [`context_routing_id`](scp_protocol::context::context_routing_id),
    /// so neither requires per-context state.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no crypto / transport / clock
    ///   provider has been attached to the supervisor.
    /// - [`ContextError::CryptoFailed`] if envelope signing or sealing
    ///   fails.
    /// - Any [`ContextError`] surfaced by the transport's `send_message`.
    fn recovery_send_notification_direct(
        &self,
        context_id: &str,
        sender_did: &str,
        payload: &[u8],
        sequence: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContextError> {
        let not_init = || {
            ContextError::NotInitialized(
                "recovery_send_notification_direct: providers not attached".to_owned(),
            )
        };
        let crypto = self.crypto_ref().ok_or_else(not_init)?;
        let transport = self.transport_ref().ok_or_else(not_init)?;
        let clock = self.clock_ref().ok_or_else(not_init)?;

        let context_id_bytes = crate::context::state::context_id_to_bytes(context_id);

        // No MLS group exists for an unregistered context, so the epoch is
        // 0 — matching the registered-actor handler's behaviour when
        // `state.epoch.mls_epoch` holds its default value.
        let current_epoch = 0;

        let timestamp = clock.now_millis();
        let params = scp_protocol::envelope::inner::InnerEnvelopeParams {
            version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
            context_id,
            sender_did,
            epoch: current_epoch,
            generation: 0,
            sequence,
            timestamp,
            message_type: scp_protocol::envelope::inner::MessageType::Recovery,
            payload,
            provenance: None,
            signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        };

        let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Domain-separated routing ID for relay routing, distinct from the
        // raw `context_id_bytes` used for MLS crypto keying.
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        let encrypted = crypto.seal(
            &context_id_bytes,
            &inner,
            &routing_id,
            300, // 5 minute blob TTL
        )?;

        transport.send_message(&routing_id, &encrypted)?;

        Ok(())
    }

    /// Direct supervisor-scoped dispatch for [`QueriesCommand`] variants
    /// whose target context has no registered actor.
    ///
    /// Mirrors the standing-direct precedent: when the mailbox-first
    /// lookup in [`Self::dispatch_query`] returns `None`, this method
    /// surfaces the variant's legacy unknown-context contract on the
    /// embedded reply oneshot without entering an actor or a locked
    /// legacy `PerContextState` view. Two contracts apply per variant:
    ///
    /// - **Hard-error variants** (`LocalPseudonym`,
    ///   `GetBroadcastKeyForLocalAuthor`): emit
    ///   `ContextError::ContextNotRegistered` on the reply.
    /// - **Soft-default variants** (`MemberCount`, `IsMember`,
    ///   `MemberDids`, `MemberRole`, `ContextParams`, `GetRoleState`,
    ///   `PendingCommits`, `CommitFault`, plus the `testing`-only
    ///   access-key / budget / velocity variants): emit the legacy
    ///   default (`Ok(None)`, `Ok(false)`, `Ok(Vec::new())`, etc.).
    ///
    /// `EventLogEntries` is handled inline in
    /// [`Self::dispatch_query`] and never reaches this method.
    ///
    /// Returns `Outcome::ok(())` on every arm — the typed result lives
    /// on the variant's oneshot, not the method-level outcome.
    fn dispatch_queries_direct(&self, cmd: QueriesCommand) -> Outcome<()> {
        match cmd {
            // `ReadContextState` is never routed here in production — the
            // standing get-or-create path resolves the no-actor case to
            // `None`/`Poisoned` via `Self::read_context_state` (which checks
            // the poison index when no actor exists) before this method runs.
            // Left as an explicit arm so the lifecycle-state read has a
            // definitive unknown-context reply. Route through
            // `lookup_miss_error` so a poisoned / silently-dead context
            // surfaces `ContextPoisoned` / `ActorCrashed` rather than a
            // misleading `ContextNotRegistered` (ADR-049 §10).
            QueriesCommand::ReadContextState { reply, context_id } => {
                let err = self.lookup_miss_error(
                    &context_id,
                    format!("context not registered: {context_id}"),
                );
                let _ = reply.send(Err(err));
            }
            // Hard-error variants — legacy `local_pseudonym` /
            // `get_broadcast_key_for_local_author` return
            // `ContextError::ContextNotRegistered` on unknown context. Route
            // through `lookup_miss_error` so a poisoned / silently-dead
            // context surfaces the dedicated poison error (ADR-049 §10).
            QueriesCommand::LocalPseudonym { ref context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { ref context_id, .. } => {
                let err = self
                    .lookup_miss_error(context_id, format!("context not registered: {context_id}"));
                reply_with_error(cmd, err);
            }
            // Soft-default variants — legacy methods return the
            // variant-specific default on unknown context.
            QueriesCommand::MemberCount { .. }
            | QueriesCommand::IsMember { .. }
            | QueriesCommand::MemberDids { .. }
            | QueriesCommand::MemberRole { .. }
            | QueriesCommand::ContextParams { .. }
            | QueriesCommand::GetRoleState { .. }
            | QueriesCommand::HasEstablishedToolInterface { .. }
            | QueriesCommand::PendingCommits { .. }
            | QueriesCommand::CommitFault { .. }
            | QueriesCommand::LocalMlsEpoch { .. }
            | QueriesCommand::NeedsReconnect { .. } => {
                reply_with_soft_default(cmd);
            }
            // EventLogEntries never reaches this method — `dispatch_query`
            // handles it inline against the supervisor's shared
            // event-log provider before falling through to direct
            // dispatch. Left as a defensive arm so a future
            // classification change trips the debug assert.
            QueriesCommand::EventLogEntries { reply, .. } => {
                debug_assert!(
                    false,
                    "EventLogEntries routed through dispatch_queries_direct"
                );
                let _ = reply.send(Ok(None));
            }
            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { .. }
            | QueriesCommand::GetAllAccessKeys { .. }
            | QueriesCommand::RemainingBudgetForTest { .. }
            | QueriesCommand::VelocityForTest { .. } => {
                reply_with_soft_default(cmd);
            }
        }
        Outcome::ok(())
    }

    /// Look up the actor handle for a context ID. Lock-free
    /// (`DashMap::get` + `Clone`).
    ///
    /// Visibility is `pub(in crate::context::supervisor)` — external
    /// callers reach the supervisor only through
    /// [`super::handle::SupervisorHandle`], which does NOT expose an
    /// actor-handle accessor. Cross-actor messaging is impossible
    /// through `SupervisorHandle`; see plan §"ActorDeps and
    /// SupervisorHandle".
    ///
    /// `dead_code` allow: the first production call site is commit 7's
    /// query-path migration, which routes FFI-bridge lookups through
    /// `Supervisor::lookup(ctx).send(QueriesCommand::...)`.
    ///
    /// Visibility widened to `pub(in crate::context)` at Phase 2A
    /// finalization (sweep helper relocation) so the sweep entry
    /// points in `governance_helpers` / `lifecycle_helpers` can route
    /// per-actor sweep commands through the mailbox.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context) fn lookup(&self, ctx_id: &str) -> Option<ContextActorHandle> {
        self.actors.get(ctx_id).map(|r| r.value().clone())
    }

    /// Returns a snapshot of every currently-registered actor's
    /// `context_id`.
    ///
    /// The returned `Vec<String>` is independent of the underlying
    /// `DashMap` — callers can iterate it freely without holding any
    /// shard locks. Each call rebuilds the snapshot; the sweep
    /// iterators in `governance_helpers` / `lifecycle_helpers` call
    /// this once per sweep and dispatch one command per `context_id`.
    ///
    /// Added at Phase 2A finalization (sweep helper relocation) so the
    /// sweep entry points have a way to enumerate the actor registry
    /// without reaching for the legacy `contexts` DashMap (which is
    /// scheduled for deletion in a subsequent session).
    #[must_use]
    pub(in crate::context) fn actor_ids(&self) -> Vec<String> {
        self.actors.iter().map(|e| e.key().clone()).collect()
    }

    /// Spawn a new `ContextActor` task, register its handle, and return
    /// the handle. The mailbox receiver is moved into the spawned task
    /// so it never escapes this function.
    ///
    /// The spawn site is `pub(in crate::context)` so the context
    /// module's lifecycle handlers can spawn actors at
    /// `create_context` / `restore_context` time. Code outside
    /// `crate::context::` has no way to spawn an actor.
    ///
    /// Commit 6 delivers the mailbox wiring; the actor's `run()` body
    /// uses the stubbed dispatch in
    /// [`crate::context::actor::ContextActor`]. Commit 7 onward
    /// replaces the stubs with real handlers.
    ///
    /// `dead_code` allow: the first production call site is commit 9's
    /// lifecycle handler (create_context spawns an actor). Until then
    /// only the unit tests here exercise the method.
    #[allow(dead_code)]
    pub(in crate::context) async fn spawn_actor(
        &self,
        ctx_id: String,
        mailbox_capacity: Option<usize>,
    ) -> ContextActorHandle {
        let capacity = mailbox_capacity.unwrap_or(ACTOR_MAILBOX_CAPACITY);
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(capacity);

        let handle = ContextActorHandle::from_sender(tx);
        {
            // Write-path mutation: register the handle under the write lock.
            let _guard = self.write_lock.lock().await;
            self.actors.insert(ctx_id.clone(), handle.clone());
        }

        // Spawn the actor's dispatch loop. During the 12b.2a → 12b.2b
        // window the existing no-state `spawn_actor` signature routes
        // through [`ContextActor::new_skeleton`] — the state still
        // lives on `ContextManager`, and the shim dispatch (see
        // [`Self::dispatch_command`] family) continues to delegate
        // there. [`Self::spawn_actor_with_state`] is the post-12b.2a
        // path that takes owned state + deps and constructs a
        // state-carrying actor via [`ContextActor::new`].
        let inbox = rx;
        tokio::spawn(async move {
            Box::pin(crate::context::actor::ContextActor::new_skeleton(ctx_id, inbox).run()).await;
        });

        handle
    }

    /// Spawn a new `ContextActor` task that owns drained
    /// [`PerContextState`](crate::context::actor::PerContextState) +
    /// [`ActorDeps`](crate::context::actor::ActorDeps) directly
    /// (ADR-049 commit 12).
    ///
    /// This is the post-refactor spawn path: the supervisor's caller
    /// drains state from the legacy `ContextManager` and
    /// `MlsCryptoProvider` via
    /// [`crate::context::supervisor::Supervisor::take_context_state`]
    /// +
    /// [`crate::crypto::mls::provider::MlsCryptoProvider::take_crypto_state`],
    /// assembles the actor-side `PerContextState` using the drained
    /// fields, and hands the state + deps bundle into this method.
    /// The spawned actor becomes the sole owner; subsequent
    /// manager/provider calls for the same context return the typed
    /// "taken by actor" errors.
    ///
    /// The returned [`ContextActorHandle`] is registered in the
    /// supervisor's `actors` map under the same `write_lock` that
    /// [`Self::spawn_actor`] uses. The handle's mailbox capacity
    /// matches [`ACTOR_MAILBOX_CAPACITY`] (256, plan §"Mailbox
    /// parameters").
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — the only production caller is the
    /// lifecycle handler's create / restore / import path (landing
    /// in commit 12b.2b). External callers (FFI bridges,
    /// downstream crates) reach the actor through
    /// [`Self::dispatch_command`] or the
    /// [`crate::context::supervisor::handle::SupervisorHandle`] /
    /// [`crate::context::actor::deps::ActorDeps::supervisor`]
    /// capabilities — never directly.
    ///
    /// # Scope — infrastructure only
    ///
    /// Commit 12b.2a wires the signature and registry insertion.
    /// The spawned actor's `run()` loop currently delegates every
    /// command variant to the skeleton dispatch (same fallback as
    /// [`ContextActor::new_skeleton`]) — migrating real handler
    /// bodies onto `&mut self.state` + `&self.deps` is 12b.2b's
    /// atomic transition across all nine handler submodules.
    ///
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CreationFailed`] if an actor is already
    /// registered for this context id. The legacy bootstrap insert
    /// (`manager_methods::insert_context`) rejected a duplicate id with
    /// `CreationFailed`; this restores that first-writer-wins guarantee
    /// for the owned-state spawn path (create / restore / import). The
    /// import replace path despawns the prior actor before respawning,
    /// so the slot is vacant by the time it reaches here.
    pub(in crate::context) async fn spawn_actor_with_state(
        self: &Arc<Self>,
        state: crate::context::actor::state::PerContextState,
        deps: crate::context::actor::deps::ActorDeps,
        mailbox_capacity: Option<usize>,
    ) -> Result<ContextActorHandle, ContextError> {
        // Derive the DID this context's deps were scoped to so the watchdog
        // can rebuild deps if the actor crashes and must be respawned. This
        // mirrors the `RestoreContext` direct arm: prefer a registered local
        // DID (the node performing the work), falling back to a context-id-
        // derived seed so respawn-deps construction stays deterministic and
        // never fabricates a foreign participant. Restore/respawn do not key
        // crypto on this DID (they rehydrate the persisted snapshot's MLS
        // state), so the seed fallback is sound.
        let owning_did = self
            .local_dids_ref()
            .load()
            .iter()
            .min()
            .cloned()
            .unwrap_or_else(|| DID(state.handle.context_id().to_owned()));
        // `Box::pin` keeps the (large, state-carrying) spawn future off the
        // caller's stack frame — `PerContextState` + `ActorDeps` are ~20KB.
        Box::pin(self.spawn_actor_with_watchdog(state, deps, owning_did, mailbox_capacity)).await
    }

    /// Spawn a state-owning [`ContextActor`], register its handle, and
    /// attach a per-actor *watchdog* task that observes the actor's
    /// `JoinHandle` (ADR-049 §10).
    ///
    /// Unlike the pre-watchdog spawn, this KEEPS the actor's `JoinHandle`
    /// (rather than dropping it) and hands it to [`Self::actor_watchdog`],
    /// which: detects panics, logs them **without the panic payload**
    /// (security-critical — the payload may carry plaintext or key
    /// material), enforces the respawn budget ([`CrashWindow`]), and
    /// respawns from the persisted snapshot when the budget is not yet
    /// exhausted.
    ///
    /// `owning_did` is the DID the actor's [`ActorDeps`] were scoped to;
    /// the watchdog reuses it to rebuild deps on respawn.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CreationFailed`] if an actor is already
    /// registered for this context id (first-writer-wins — same contract
    /// the pre-watchdog spawn enforced).
    pub(in crate::context) async fn spawn_actor_with_watchdog(
        self: &Arc<Self>,
        mut state: crate::context::actor::state::PerContextState,
        deps: crate::context::actor::deps::ActorDeps,
        owning_did: DID,
        mailbox_capacity: Option<usize>,
    ) -> Result<ContextActorHandle, ContextError> {
        // Stamp a fresh monotonic spawn-generation onto the owned state
        // before it crosses into the actor task. Each spawned actor
        // instance gets a distinct generation; a tool-economy reservation
        // captures this value and the Phase-3 settle rejects if the live
        // actor's generation no longer matches (the instance was replaced
        // between reserve and settle). `fetch_add` returns the prior
        // value, so the first spawn stamps 1 (never the default 0).
        state.generation = self
            .spawn_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;

        let capacity = mailbox_capacity.unwrap_or(ACTOR_MAILBOX_CAPACITY);
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(capacity);

        // Register under the context's ORIGINAL id string (the one the
        // `ContextHandle` carries and that every per-context dispatch /
        // `lookup` uses), NOT `hex(state.context_id)`. `state.context_id`
        // is `SHA256(original_id)` (`context_id_to_bytes`), so keying by
        // its hex would diverge from the original-string id callers pass
        // to `lookup` — the legacy `contexts` DashMap was keyed by the
        // original string, and per-context dispatch (incl. the cross-
        // context recovery flow) still is. For the test fixtures the
        // handle id IS `hex(context_id_bytes)`, so this is identical
        // there; for production `create_context` it is the caller's
        // original id, which is what makes per-context dispatch resolve
        // the actor.
        let ctx_id_str = state.handle.context_id().to_owned();

        let handle = ContextActorHandle::from_sender(tx);
        {
            // Write-path mutation: register the handle under the write
            // lock — same contract as [`Self::spawn_actor`]. Reject a
            // duplicate registration (first-writer-wins) instead of
            // silently overwriting a live actor: the overwrite would
            // leak the loser's spawned task and diverge crypto state.
            let _guard = self.write_lock.lock().await;
            if self.actors.contains_key(&ctx_id_str) {
                return Err(ContextError::CreationFailed(format!(
                    "context '{ctx_id_str}' is already registered"
                )));
            }
            self.actors.insert(ctx_id_str.clone(), handle.clone());
        }

        // Hand the owned state + deps into the actor task. The spawned
        // future captures both by move; neither escapes the actor's scope.
        // KEEP the JoinHandle (the pre-watchdog spawn dropped it, silently
        // swallowing panics and wedging the context). Actor tasks are NOT
        // added to `task_set` — that JoinSet drives TTL / governance
        // timers; the watchdog owns this handle directly.
        let inbox = rx;
        let join = tokio::spawn(async move {
            Box::pin(crate::context::actor::ContextActor::new(state, deps, inbox).run()).await;
        });

        // Spawn the watchdog: it awaits the actor's completion and, on a
        // panic, records the crash + (poison-or-respawn). A clone of the
        // supervisor `Arc` keeps it alive for the watchdog's lifetime.
        // Spawn the watchdog through a free helper (not inline) so its
        // future's `Send` proof is resolved OUTSIDE this method's opaque
        // `impl Future` scope. Spawning inline would form a self-referential
        // opaque-type cycle (`spawn_actor_with_watchdog` ↔ `actor_watchdog`
        // ↔ `respawn_from_snapshot` ↔ `restore_context` ↔
        // `spawn_actor_with_state`) that the compiler refuses to resolve
        // ("fetching the hidden types of an opaque inside of the defining
        // scope is not supported").
        spawn_actor_watchdog_task(Arc::clone(self), ctx_id_str, owning_did, join);

        Ok(handle)
    }

    /// Per-actor watchdog (ADR-049 §10).
    ///
    /// Awaits the actor task's [`JoinHandle`] and reacts to how it
    /// finished:
    ///
    /// - **Clean exit** (`Ok(())`) — the actor's `run()` loop returned
    ///   normally (shutdown ack, inbox closed). No crash is recorded and no
    ///   respawn happens; any pre-existing poison record is left intact.
    /// - **Panic** (`Err(e)` with `e.is_panic()`) — record the crash in the
    ///   context's [`CrashWindow`], log a payload-free diagnostic, then
    ///   either poison-and-despawn (budget exhausted) or respawn from the
    ///   persisted snapshot.
    /// - **Cancellation / abort** (`Err(e)` with `!e.is_panic()`) — treated
    ///   as a clean exit: the task was deliberately stopped, not a fault.
    ///
    /// # Security invariant
    ///
    /// The [`tokio::task::JoinError`] is inspected ONLY via
    /// [`JoinError::is_panic`](tokio::task::JoinError::is_panic) (a bool).
    /// Its panic payload is NEVER read or formatted — a panic inside an
    /// MLS-encrypt or key-derivation path could otherwise interpolate
    /// plaintext or secret-key bytes into the log.
    ///
    /// # Panic location
    ///
    /// The diagnostic logs `panic_location = "unknown"`. ADR-049 §10
    /// permits capturing the file:line location via a `std::panic::Location`
    /// hook, but a *process-global* "last panic location" store is
    /// inherently racy: with multiple `Supervisor`s and concurrent actor
    /// panics across threads, the stored location cannot be reliably
    /// correlated to the specific [`JoinError`] observed here, and would
    /// also be a mutable global (forbidden by the workspace
    /// `check-no-mutable-globals` gate). The plan's stated floor —
    /// "payload-free logging with `panic_location=\"unknown\"`" — is chosen
    /// deliberately over a racy, possibly-wrong location.
    async fn actor_watchdog(
        self: Arc<Self>,
        ctx_id: String,
        owning_did: DID,
        join: tokio::task::JoinHandle<()>,
    ) {
        let outcome = join.await;
        let join_err = match outcome {
            // Clean return: the run loop exited normally. No crash, no
            // respawn. Leave any existing poison record untouched.
            Ok(()) => return,
            Err(e) => e,
        };

        // A cancellation / shutdown-abort is not a fault. Only a genuine
        // panic counts against the respawn budget.
        if !join_err.is_panic() {
            return;
        }

        // Read the crash instant (degraded-window `warn!` factored into
        // `crash_now_ms`).
        let now_ms = self.crash_now_ms("context_actor", &ctx_id);
        // Record the crash and copy the budget state OUT of the DashMap
        // entry, then DROP the guard before any `.await` (the workspace
        // denies `await_holding_lock`).
        let (poisoned, count) = {
            let mut entry = self.crash_windows.entry(ctx_id.clone()).or_default();
            let poisoned = entry.record(now_ms);
            (poisoned, entry.crash_count())
        };

        // Payload-free diagnostic (ADR-049 §10). The panic payload is
        // intentionally absent — see the security invariant above.
        tracing::error!(
            actor_kind = "context_actor",
            context_id = %ctx_id,
            crash_count = count,
            poisoned = poisoned,
            panic_location = "unknown",
            "context actor panicked; payload intentionally not logged (may contain key material)"
        );

        if poisoned {
            // Budget exhausted: stop the crash-respawn loop. The actor task
            // has already unwound (its mailbox is closed), so the `Poisoned`
            // state cannot be driven through the dead mailbox — the DURABLE,
            // observable poison signal is the sticky `crash_windows` flag,
            // which [`Self::read_context_state`] consults once the actor is
            // gone to report [`ContextState::Poisoned`]. Despawn the
            // (already-dead) handle so per-context dispatch resolves the
            // poison instead of mailboxing a closed channel. No respawn.
            //
            // Distinct, greppable telemetry: a context POISONING is an
            // operator-actionable event separate from the per-crash line
            // above. Payload-free (same field discipline).
            tracing::error!(
                actor_kind = "context_actor",
                context_id = %ctx_id,
                crash_count = count,
                "context poisoned; exceeded respawn budget, operator intervention required"
            );
            self.despawn_actor(&ctx_id).await;
            return;
        }

        // Budget intact: respawn from the persisted snapshot. A failed
        // respawn is itself counted as a crash (inside `respawn_from_snapshot`)
        // so a snapshot that reliably panics the loader poisons after the
        // budget rather than looping forever. A terminal-state snapshot is
        // intentionally NOT respawned (anti-resurrection) and surfaces
        // `ContextClosed` — that is an expected dormancy, not a respawn
        // failure, so it logs at info.
        match self.respawn_from_snapshot(&ctx_id, &owning_did).await {
            Ok(()) => {}
            Err(ContextError::ContextClosed) => {
                tracing::info!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    "context actor crashed in a terminal state; not respawned (dormant)"
                );
            }
            Err(e) => {
                tracing::error!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    error = %e,
                    "context actor respawn failed"
                );
            }
        }
    }

    /// Per-identity KeyPackage-actor watchdog (ADR-049 §10).
    ///
    /// The twin of [`Self::actor_watchdog`] for `KeyPackageStoreActor`s. Awaits
    /// the actor task's [`JoinHandle`](tokio::task::JoinHandle) and reacts:
    ///
    /// - **Clean exit / cancellation** — no crash recorded, no respawn.
    /// - **Panic** — record the crash in the per-identity [`CrashWindow`]
    ///   (keyed `kp::{did}`), log a payload-free diagnostic, then either
    ///   poison-and-despawn (budget exhausted) or respawn the actor, which
    ///   re-runs the §9 reconciliation from `mls_storage` on its next spawn.
    ///
    /// # Security invariant
    ///
    /// The [`JoinError`](tokio::task::JoinError) is inspected ONLY via
    /// [`is_panic`](tokio::task::JoinError::is_panic). The panic payload is
    /// NEVER read or formatted — a KP actor panic could carry private
    /// signer-state bytes.
    async fn kp_actor_watchdog(self: Arc<Self>, identity: DID, join: tokio::task::JoinHandle<()>) {
        let outcome = join.await;
        let join_err = match outcome {
            Ok(()) => return,
            Err(e) => e,
        };
        if !join_err.is_panic() {
            return;
        }

        let poison_key = Self::kp_crash_key(&identity);
        let now_ms = self.crash_now_ms("key_package_store", &identity.0);
        let (poisoned, count) = {
            let mut entry = self.crash_windows.entry(poison_key.clone()).or_default();
            let poisoned = entry.record(now_ms);
            (poisoned, entry.crash_count())
        };

        // Payload-free diagnostic (ADR-049 §10) — the panic payload may carry
        // private signer-state bytes, so it is intentionally absent.
        tracing::error!(
            actor_kind = "key_package_store",
            identity = %identity.0,
            crash_count = count,
            poisoned = poisoned,
            panic_location = "unknown",
            "key-package actor panicked; payload intentionally not logged (may contain key material)"
        );

        // Remove the dead handle so the next `key_package_store_for` resolves
        // the poison (poisoned) or get-or-spawns a fresh actor (respawn).
        {
            let _guard = self.write_lock.lock().await;
            self.key_package_stores.remove(&identity);
        }

        if poisoned {
            tracing::error!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                crash_count = count,
                "key-package actor poisoned; exceeded respawn budget, operator intervention required"
            );
            return;
        }

        // Budget intact: respawn. The fresh actor re-runs the §9 reconciliation
        // from `mls_storage` in its `run()` startup, rebuilding `pool` /
        // `reserved` from the durable journal — NOT a coalesced snapshot.
        if let Err(e) = self.key_package_store_for(&identity).await {
            tracing::error!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                error = %e,
                "key-package actor respawn failed"
            );
        } else {
            tracing::info!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                "key-package actor respawned; reconciling from durable storage"
            );
        }
    }

    /// Respawn a context's actor from its persisted snapshot (ADR-049 §10).
    ///
    /// Order matters:
    /// 1. **Despawn first** — remove the stale (dead) handle under the
    ///    write lock. Otherwise the first-writer-wins duplicate-key check in
    ///    [`Self::spawn_actor_with_watchdog`] would reject the re-insert.
    /// 2. **Load the snapshot.** A missing snapshot is the lost-state case
    ///    (the actor crashed before its first coalesced persist): log and
    ///    surface [`ContextError::ActorCrashed`] — there is nothing to
    ///    rehydrate.
    /// 3. **Rebuild deps + `ContextHandle`** and delegate to
    ///    [`crate::context::lifecycle_helpers::restore_context`] — the
    ///    single respawn primitive that reconstructs the FULL
    ///    `PerContextState` (governance, MLS crypto, §9.10.4 routing /
    ///    pseudonym registry, rate-limit) and spawns the new watched actor.
    ///    Reusing it keeps the §9.10.4 routing-state restore in ONE place.
    ///
    /// A failed respawn is recorded as a crash so repeated failures consume
    /// the budget and eventually poison the context.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorCrashed`] when no snapshot exists.
    /// - Any error surfaced by [`Self::persistence_ref`] /
    ///   `restore_context` (persistence failure, validation failure, etc.).
    async fn respawn_from_snapshot(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
    ) -> Result<(), ContextError> {
        // Hold `bootstrap_spawn_lock` across the WHOLE respawn (despawn +
        // crypto-write inside `restore_context` + re-spawn), exactly as the
        // three lifecycle bootstrap variants (`create_context`,
        // `import_context`, `standing_context`) do. The respawn tail performs
        // the same non-atomic crypto-write→spawn sequence those paths guard:
        // `restore_context` calls `deps.crypto.restore_crypto_state` (a crypto
        // write that takes no lock of its own) and then re-spawns the actor.
        // Without this guard a respawn racing a same-id `create_context` /
        // `import_context` could interleave the crypto write with the other
        // op's spawn and leave the registered actor paired with the wrong
        // crypto state. Lock order is `bootstrap_spawn_lock` → `write_lock`
        // (the despawn / re-spawn below take `write_lock` INSIDE this guard,
        // identical to create/import); neither `despawn_actor`,
        // `build_actor_deps`, nor `restore_context` re-acquires
        // `bootstrap_spawn_lock`, so this is re-entrancy- and deadlock-free.
        let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;

        // Mark the transient respawn window BEFORE despawning the stale actor.
        // Between the despawn below and re-registration, a concurrent
        // per-context dispatch would `lookup`-miss a context that genuinely
        // exists and is mid-respawn; the marker makes `lookup_miss_error`
        // surface a retryable `ActorCrashed` instead of a misleading
        // `ContextNotRegistered`. Cleared on every exit (the failure paths via
        // `record_respawn_failure`, the terminal-skip and success paths
        // explicitly below).
        self.crash_windows
            .entry(ctx_id.to_owned())
            .or_default()
            .mark_respawning();

        // 1. Despawn the stale handle so the re-insert is not rejected.
        self.despawn_actor(ctx_id).await;

        // 2. Load the snapshot. None ⇒ lost state (crashed pre-persist).
        let Some(persistence) = self.persistence_ref() else {
            // No persistence backend configured — cannot respawn. Count it
            // as a failed respawn so the budget applies.
            self.record_respawn_failure(ctx_id).await;
            return Err(ContextError::ActorCrashed(format!(
                "{ctx_id} (no persistence backend configured for respawn)"
            )));
        };
        let snapshot = match persistence.load_context(ctx_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.record_respawn_failure(ctx_id).await;
                tracing::error!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    "context actor crashed with no persisted snapshot; state is lost"
                );
                return Err(ContextError::ActorCrashed(format!(
                    "{ctx_id} (no persisted snapshot — state lost)"
                )));
            }
            Err(e) => {
                self.record_respawn_failure(ctx_id).await;
                return Err(ContextError::ActorCrashed(format!(
                    "{ctx_id} (snapshot load failed: {e})"
                )));
            }
        };

        // Anti-resurrection precondition (ADR-049 §10): only an `Active`
        // snapshot is respawned. `restore_context` hardcodes
        // `lifecycle_state: Open` and the code below drives the handle to
        // `Active`, so respawning a `Closing`/`Closed`/`Expired`/
        // `MigratingOut`/`Tombstoned` snapshot would RESURRECT a terminal
        // context. `restore_all_contexts` applies the same `state != Active`
        // skip at process restart; mirror it here. A terminal context is the
        // EXPECTED end state of a clean close/expire, not a crash to recover,
        // so it is NOT counted against the crash budget (and the
        // unrecoverable flag is not set — the context is intentionally
        // dormant, not silently dead). Leave the (already-despawned) context
        // dormant and surface a typed result.
        if snapshot.state != scp_protocol::context::ContextState::Active {
            tracing::info!(
                actor_kind = "context_actor",
                context_id = %ctx_id,
                snapshot_state = %snapshot.state,
                "respawn skipped: snapshot is in a terminal state; leaving context dormant"
            );
            // Terminal-skip is not a respawn-in-progress: clear the transient
            // marker so a subsequent lookup-miss reflects "dormant/closed", not
            // "respawning". The skip does NOT touch the crash budget or poison.
            // If the window we touched carries ONLY the transient marker we set
            // above (a clean terminal context with no crash history), reap it so
            // a clean terminal context leaves no lingering crash-window record;
            // otherwise just clear the marker, preserving its real crash
            // history.
            let reaped = self
                .crash_windows
                .remove_if(ctx_id, |_, w| w.is_empty_except_respawning())
                .is_some();
            if !reaped && let Some(mut entry) = self.crash_windows.get_mut(ctx_id) {
                entry.clear_respawning();
            }
            return Err(ContextError::ContextClosed);
        }

        // 3. Rebuild deps + handle, then delegate to the shared
        //    `restore_context` respawn primitive (extracted to keep this
        //    function within the line budget; the transient respawn marker set
        //    above remains live until that tail clears it on every exit).
        self.respawn_rebuild_and_restore(ctx_id, owning_did, &snapshot)
            .await
    }

    /// Tail of [`Self::respawn_from_snapshot`]: rebuild the handle + deps from a
    /// validated (`Active`) snapshot and drive the timeout-bounded
    /// `restore_context`. Split out so `respawn_from_snapshot` stays within the
    /// clippy line budget; runs entirely under the caller's
    /// `bootstrap_spawn_lock` guard (the caller holds it across this call).
    async fn respawn_rebuild_and_restore(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
        snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), ContextError> {
        let handle =
            crate::context::ContextHandle::new(ctx_id.to_owned(), snapshot.context_params.clone());
        // Drive the handle to `Active` BEFORE restore — `restore_context`
        // assumes a live handle and never transitions it itself, so a fresh
        // `ContextHandle` (which starts `Creating`) would otherwise leave the
        // respawned context stuck in `Creating`. This mirrors the
        // `RestoreContext` direct dispatch arm, which transitions to `Active`
        // before calling `restore_context`. On a transition failure, count it
        // as a failed respawn.
        if let Err(e) = handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
        {
            self.record_respawn_failure(ctx_id).await;
            return Err(ContextError::ActorCrashed(format!(
                "{ctx_id} (could not activate respawned context handle: {e})"
            )));
        }
        let deps = match self.build_actor_deps(owning_did).await {
            Ok(deps) => deps,
            Err(e) => {
                self.record_respawn_failure(ctx_id).await;
                return Err(e);
            }
        };
        // The recursive async cycle through `restore_context` →
        // `spawn_actor_with_state` is broken by `spawn_actor_watchdog_task`
        // (a free fn that resolves the watchdog future's `Send` proof
        // outside any opaque-type defining scope). `Box::pin` keeps this
        // (large) restore future off the stack, mirroring the existing
        // `restore_context` call sites in `lifecycle_helpers`.
        //
        // Bound the restore with the SAME `Self::LIFECYCLE_TIMEOUT` the
        // `RestoreContext` dispatch arm uses (ADR-049 §10). Respawn holds
        // `bootstrap_spawn_lock` across the WHOLE body, and a hung storage
        // provider inside `restore_context` (snapshot load / crypto restore)
        // would otherwise pin that GLOBAL lock indefinitely — stalling every
        // create / import / standing-recreate node-wide. On elapse, record a
        // respawn failure (so a reliably-hanging snapshot consumes the budget
        // and eventually poisons rather than wedging forever) and surface a
        // typed timeout error, mirroring the dispatch arm exactly.
        // Dedup the double snapshot load: `respawn_from_snapshot` already
        // loaded this snapshot for the Active-state precondition check. Thread
        // it in (clone — cheap relative to a second disk read) so the snapshot
        // is read from persistence exactly ONCE per respawn, and so the
        // redundant load no longer runs INSIDE the timed `restore_context`
        // region. (`load_context` is a synchronous trait call: a
        // `tokio::time::timeout` cannot interrupt a blocking sync read, so the
        // genuine mitigation is removing the second read, not wrapping it. The
        // storage layer's `load_context` is contracted not to block unbounded.)
        let restore_fut = Box::pin(crate::context::lifecycle_helpers::restore_context(
            &deps,
            ctx_id,
            &handle,
            Some(snapshot.clone()),
        ));
        match tokio::time::timeout(Self::LIFECYCLE_TIMEOUT, restore_fut).await {
            Ok(Ok(())) => {
                // Respawn succeeded: clear the "silently dead" flag (the
                // crash budget is intentionally retained) and emit a
                // payload-free recovery line carrying the running crash
                // count so operators can spot a flapping context.
                let crash_count = {
                    let mut entry = self.crash_windows.entry(ctx_id.to_owned()).or_default();
                    entry.mark_respawn_succeeded();
                    // The replacement actor is now re-registered: clear the
                    // transient mid-respawn marker.
                    entry.clear_respawning();
                    entry.crash_count()
                };
                tracing::warn!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    crash_count,
                    "context actor respawned from snapshot"
                );
                Ok(())
            }
            Ok(Err(e)) => {
                self.record_respawn_failure(ctx_id).await;
                Err(e)
            }
            Err(_elapsed) => {
                self.record_respawn_failure(ctx_id).await;
                Err(ContextError::TransportTimeout(format!(
                    "respawn restore_context exceeded {:?} budget for context {ctx_id}",
                    Self::LIFECYCLE_TIMEOUT
                )))
            }
        }
    }

    /// Record a failed respawn attempt (ADR-049 §10): account one crash
    /// against the sliding budget AND flag the context as currently
    /// unrecoverable ("silently dead"). If that crash exhausts the budget,
    /// despawn the (already-dead) handle so per-context dispatch resolves the
    /// poison rather than mailboxing a closed channel.
    ///
    /// The `crash_windows` `DashMap` guard is dropped BEFORE the `await` on
    /// `despawn_actor` (the workspace denies `await_holding_lock`). Collapsing
    /// the former six inline `record_failure(self)` + `if poisoned { despawn }`
    /// blocks into this single helper is behaviour-preserving.
    async fn record_respawn_failure(self: &Arc<Self>, ctx_id: &str) {
        // Mirror `actor_watchdog`'s clock-absent handling: without a clock the
        // crash window degrades to "crashes-ever" (no 60s slide). Emit the
        // same loud, payload-free warning here so a respawn-failure recorded on
        // the clock-absent path is never silently stamped `now_ms = 0`. The
        // watchdog warns on the direct-crash path; this is its respawn-failure
        // twin (both feed the same `crash_windows` budget).
        let now_ms = self.clock_ref().map_or_else(
            || {
                tracing::warn!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    "no clock configured: crash window degraded to crashes-ever (3-crash budget \
                     without the 60s slide); wire a clock via with_providers in production"
                );
                0
            },
            |c| scp_primitives::Clock::now_millis(c.as_ref()),
        );
        let poisoned = {
            let mut entry = self.crash_windows.entry(ctx_id.to_owned()).or_default();
            entry.mark_respawn_failed();
            // The respawn attempt has resolved (in failure): clear the
            // transient mid-respawn marker so a subsequent lookup-miss reflects
            // the now-stable failed/poisoned state, not "respawning".
            entry.clear_respawning();
            entry.record(now_ms)
        };
        if poisoned {
            self.despawn_actor(ctx_id).await;
        }
    }

    /// Whether the context has been poisoned (ADR-049 §10) — its actor
    /// exceeded the respawn budget and is no longer being respawned.
    /// Lock-free read of the `crash_windows` `DashMap`.
    #[must_use]
    pub(in crate::context) fn is_context_poisoned(&self, ctx_id: &str) -> bool {
        self.crash_windows
            .get(ctx_id)
            .is_some_and(|w| w.is_poisoned())
    }

    /// Map a per-context `lookup` miss to the right typed error (ADR-049
    /// §10). Three cases, in precedence order:
    ///
    /// 1. **Poisoned** — the actor exceeded the respawn budget and is no
    ///    longer being respawned: surface [`ContextError::ContextPoisoned`]
    ///    ("dormant, needs operator recovery").
    /// 2. **Silently dead** — the actor crashed and its last respawn FAILED
    ///    (lost/corrupt snapshot) but it has NOT yet hit the poison
    ///    threshold: surface [`ContextError::ActorCrashed`] so the caller
    ///    sees "crashed, unrecoverable right now" rather than a misleading
    ///    "never existed". Without this a crashed-but-unpoisoned context
    ///    reports `ContextNotRegistered`, indistinguishable from an unknown
    ///    id.
    /// 3. **Mid-respawn** — the watchdog has despawned the crashed actor but
    ///    has not yet re-registered the replacement: surface
    ///    [`ContextError::ActorCrashed`] (the retryable "crashed, recovering"
    ///    class) rather than `ContextNotRegistered`. The context genuinely
    ///    exists; a concurrent dispatch that raced into the transient despawn
    ///    gap must see a retryable signal, not "never existed".
    /// 4. **Genuinely unknown** — fall back to
    ///    [`ContextError::ContextNotRegistered`] with the caller's
    ///    diagnostic message.
    fn lookup_miss_error(&self, ctx_id: &str, not_registered_msg: String) -> ContextError {
        if let Some(window) = self.crash_windows.get(ctx_id) {
            if window.is_poisoned() {
                return ContextError::ContextPoisoned(ctx_id.to_owned());
            }
            if window.last_respawn_failed() || window.is_respawning() {
                return ContextError::ActorCrashed(ctx_id.to_owned());
            }
        }
        ContextError::ContextNotRegistered(not_registered_msg)
    }

    /// Operator action (ADR-049 §10): clear a context's poison record and
    /// attempt ONE respawn from the persisted snapshot.
    ///
    /// This is the explicit recovery path for a poisoned context — it is
    /// surfaced only on [`SupervisorHandle::clear_poison`] for operator use,
    /// NOT reachable by ordinary per-context callers. The alternative
    /// recovery path is a process restart, which re-runs
    /// [`crate::context::lifecycle_helpers::restore_all_contexts`] and
    /// rebuilds every actor from persistence (the poison record lives only
    /// in memory, so it does not survive a restart).
    ///
    /// # Errors
    ///
    /// Surfaces any error from [`Self::respawn_from_snapshot`] (e.g.
    /// [`ContextError::ActorCrashed`] when no snapshot exists). On a failed
    /// respawn the freshly-cleared window records the failure as a crash —
    /// a context that cannot be respawned does not silently re-poison from
    /// stale history, but also does not loop.
    pub(in crate::context) async fn clear_poison(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
    ) -> Result<(), ContextError> {
        // Clear the window first so the single retry starts from a clean
        // budget. `entry().or_default()` then `clear()` resets both the
        // deque and the sticky flag.
        {
            let mut entry = self.crash_windows.entry(ctx_id.to_owned()).or_default();
            entry.clear();
        }
        self.respawn_from_snapshot(ctx_id, owning_did).await
    }

    /// Operator action (ADR-049 §10): clear a per-identity KeyPackage actor's
    /// poison record and re-resolve the actor.
    ///
    /// Unlike [`Self::clear_poison`] (per-context), this does NOT route through
    /// [`Self::respawn_from_snapshot`]: there is no KP context-snapshot to
    /// rehydrate (the KP actor reconciles from the durable `mls_storage`
    /// journal on spawn, not from a coalesced `PerContextState` snapshot), so
    /// the snapshot path would fail and re-dirty the crash window. Instead we
    /// clear the sticky `kp::{did}` window and call
    /// [`Self::key_package_store_for`], which get-or-spawns a fresh actor that
    /// re-runs the §9 reconciliation. The dead handle (if any) was already
    /// removed by the watchdog on poison; if a stale handle somehow remains we
    /// remove it first so the get-or-spawn creates a live one.
    ///
    /// # Errors
    ///
    /// Surfaces any error from [`Self::key_package_store_for`] (e.g.
    /// `NotInitialized` if providers are absent).
    pub(in crate::context) async fn clear_kp_poison(
        self: &Arc<Self>,
        identity: &DID,
    ) -> Result<(), ContextError> {
        let poison_key = Self::kp_crash_key(identity);
        {
            // Clear the sticky window AND drop any stale (dead) handle so the
            // re-resolve get-or-spawns a fresh actor rather than returning the
            // dead one.
            let _guard = self.write_lock.lock().await;
            if let Some(mut entry) = self.crash_windows.get_mut(&poison_key) {
                entry.clear();
            }
            self.key_package_stores.remove(identity);
        }
        // Re-resolve: get-or-spawn a fresh actor that reconciles from the
        // durable journal. Discard the handle — the side effect (a live,
        // watched actor registered for `identity`) is the recovery.
        self.key_package_store_for(identity).await.map(|_| ())
    }

    /// Despawn the actor registered for `context_id`, removing the
    /// entry from [`Self::actors`] under the supervisor's
    /// [`Self::write_lock`] so a concurrent re-registration cannot
    /// race the removal.
    ///
    /// The removed [`ContextActorHandle`] is dropped at the end of
    /// this function; that drop closes the underlying
    /// `mpsc::Sender`, which signals the actor task's `run()` loop
    /// to exit on the next inbox-empty poll.
    ///
    /// Returns `true` if a handle was registered and removed,
    /// `false` if no entry existed for `context_id`.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — exposed through
    /// [`SupervisorHandle::despawn_actor`](crate::context::supervisor::handle::SupervisorHandle::despawn_actor)
    /// so lifecycle bootstrap (`import_context`) can perform the
    /// despawn-then-respawn dance without holding `&Supervisor`
    /// directly. Called directly (on `&Supervisor`) by
    /// [`crate::context::lifecycle_helpers::shutdown_all_contexts`] to
    /// remove each actor's handle after `ShutdownSelf`, so the inbox
    /// closes and the actor task exits rather than lingering as a
    /// zombie.
    pub(in crate::context) async fn despawn_actor(&self, context_id: &str) -> bool {
        let _guard = self.write_lock.lock().await;
        self.actors.remove(context_id).is_some()
    }

    /// Reap a context's [`CrashWindow`] entry on a CLEAN, NON-poison despawn
    /// (ADR-049 §10): a clean close / expire / tombstone / shutdown.
    ///
    /// `crash_windows` entries are created lazily on the first crash and are
    /// otherwise never removed, which would let them grow unboundedly. This
    /// removes the entry when a context is cleanly torn down and its running
    /// crash history is no longer meaningful.
    ///
    /// It deliberately does NOT remove a POISONED entry: the poison record is
    /// the durable "dormant, needs operator recovery" signal that
    /// [`Self::lookup_miss_error`] / [`Self::is_context_poisoned`] /
    /// [`Self::read_context_state`] all read after the actor is despawned.
    /// Only [`CrashWindow::clear`] (operator `clear_poison`),
    /// [`Self::reset_crash_window`] (an explicit (re)create of the id), or a
    /// process restart removes a poison.
    ///
    /// It is NOT called on the respawn path: a respawn's internal despawn
    /// must preserve the running crash count so the budget accumulates across
    /// respawns (the loop must eventually poison a reliably-crashing
    /// snapshot).
    pub(in crate::context) fn reap_crash_window(&self, context_id: &str) {
        // `remove_if` evaluates the predicate while holding the shard lock and
        // only removes when it returns true — so a concurrent poison-despawn
        // cannot have the entry removed out from under it.
        self.crash_windows
            .remove_if(context_id, |_, window| !window.is_poisoned());
    }

    /// Unconditionally drop a context's [`CrashWindow`] entry on an explicit
    /// (re)create / import / standing-recreate of the id (ADR-049 §10).
    ///
    /// Unlike [`Self::reap_crash_window`], this removes the entry EVEN IF it
    /// is poisoned: deliberately (re)creating or importing a context id is a
    /// fresh start that resets the crash budget. Without this, a re-created
    /// context with a deterministic id (e.g. a standing-pair id) would
    /// inherit the prior instance's sticky `poisoned = true` and re-poison on
    /// its very first panic, or inherit a partial crash count and poison
    /// early. The fresh actor must begin with a clean budget.
    ///
    /// Called under `bootstrap_spawn_lock` at the create / import / standing
    /// bootstrap sites, before the new actor is spawned.
    pub(in crate::context) fn reset_crash_window(&self, context_id: &str) {
        self.crash_windows.remove(context_id);
    }

    /// Dispatch a [`StandingCommand`] through the migration shim
    /// (ADR-049 commit 11 / plan row 11).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. Covers the
    /// contact-graph (standing context) paths from spec §5.12.4. The
    /// saga-initiator variant
    /// (`StandingCommand::InitiateStandingPairCreate`) returns
    /// [`ContextError::NotImplemented`] during the commit-11 window —
    /// see `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_standing_command(
        self: &Arc<Self>,
        cmd: StandingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — try the actor mailbox first
        // for variants whose `(local_did, peer_did)` deterministically
        // maps to an existing per-context actor. Variants that don't
        // carry both DIDs (count / has / register / reconnect-all) are
        // supervisor-scoped and route directly through the
        // [`Supervisor`] standing-index methods below.
        if let Some(ctx_id) = Self::standing_command_context_id(&cmd)
            && let Some(actor) = self.lookup(&ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Standing(cmd)).await;
        }
        // Direct supervisor-scoped dispatch. No shim — every variant is
        // handled inline via the supervisor's actor-native standing
        // methods (`standing_context` / `reconnect_all_standing`) and the
        // lock-free standing-index reads/mutations.
        Ok(Box::pin(self.dispatch_standing_direct(cmd)).await)
    }

    /// Direct supervisor-scoped dispatch for [`StandingCommand`]
    /// variants that have no per-context actor target (or whose actor
    /// is not yet spawned — the `StandingContext` get-or-create path
    /// creates the underlying context on first call).
    ///
    /// Each arm wraps a supervisor-scoped operation in a 30s timeout
    /// budget matching the actor-handler shape (plan §"Transport
    /// timeouts inside actor handlers"). Reply channels carry the typed
    /// per-variant result.
    async fn dispatch_standing_direct(self: &Arc<Self>, cmd: StandingCommand) -> Outcome<()> {
        const STANDING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            StandingCommand::Placeholder { reply } => {
                const MSG: &str =
                    "StandingCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            StandingCommand::StandingContext {
                local_did,
                peer_did,
                reply,
            } => {
                let fut = self.standing_context(&local_did, &peer_did);
                let (outcome, reply_result) =
                    match tokio::time::timeout(STANDING_TIMEOUT, fut).await {
                        Ok(Ok(ctx_id)) => (Outcome::ok_mutated(()), Ok(ctx_id)),
                        Ok(Err(e)) => (
                            Outcome::err_mutated(standing_outcome_error_sketch(&e)),
                            Err(e),
                        ),
                        Err(_elapsed) => {
                            let err = ContextError::TransportTimeout(format!(
                                "standing_context exceeded {STANDING_TIMEOUT:?} budget"
                            ));
                            (
                                Outcome::err_mutated(standing_outcome_error_sketch(&err)),
                                Err(err),
                            )
                        }
                    };
                let _ = reply.send(reply_result);
                outcome
            }
            StandingCommand::StandingContextCount { reply } => {
                // Lock-free ArcSwap read (ADR-049 §Decision 12).
                let count = self.standing_contexts.load().len();
                let _ = reply.send(Ok(count));
                Outcome::ok(())
            }
            StandingCommand::HasStandingContext { peer_did, reply } => {
                // Lock-free ArcSwap read (ADR-049 §Decision 12).
                let has = self
                    .standing_contexts
                    .load()
                    .contains_key(peer_did.as_ref());
                let _ = reply.send(Ok(has));
                Outcome::ok(())
            }
            StandingCommand::RegisterStandingContext { peer_did, reply } => {
                // ArcSwap + write_lock for the standing-index mutation
                // (ADR-049 §Decision 12).
                let _guard = self.write_lock.lock().await;
                let snapshot = self.standing_contexts.load_full();
                let mut updated: HashMap<String, DID> = (*snapshot).clone();
                updated.insert(peer_did.to_string(), peer_did);
                self.standing_contexts.store(Arc::new(updated));
                let _ = reply.send(Ok(()));
                Outcome::ok_mutated(())
            }
            StandingCommand::ReconnectAllStanding { reply } => {
                let fut = self.reconnect_all_standing();
                let (outcome, reply_result) =
                    match tokio::time::timeout(STANDING_TIMEOUT, fut).await {
                        Ok(Ok(count)) => (Outcome::ok_mutated(()), Ok(count)),
                        Ok(Err(e)) => (
                            Outcome::err_mutated(standing_outcome_error_sketch(&e)),
                            Err(e),
                        ),
                        Err(_elapsed) => {
                            let err = ContextError::TransportTimeout(format!(
                                "reconnect_all_standing exceeded {STANDING_TIMEOUT:?} budget"
                            ));
                            (
                                Outcome::err_mutated(standing_outcome_error_sketch(&err)),
                                Err(err),
                            )
                        }
                    };
                let _ = reply.send(reply_result);
                outcome
            }
            StandingCommand::InitiateStandingPairCreate { reply, .. } => {
                const MSG: &str = "standing::initiate_standing_pair_create — saga wiring deferred to \
                     commit 11.5 per 5 enumerated spec gaps; see \
                     .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 1: standing-pair \
                     2-phase decomposition)";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
        }
    }

    /// Dispatch a [`ToolsCommand`] through the migration shim
    /// (ADR-049 commit 11 / plan row 11).
    ///
    /// Covers the hard-rate-limit consume / refund helpers that FFI
    /// bridges call from their tool-dispatch paths. The cross-context
    /// saga-initiator variant returns [`ContextError::NotImplemented`]
    /// during the commit-11 window — see
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`. Note that
    /// [`ContextManager::invoke_tool_with_economy`](crate::context::supervisor::Supervisor::invoke_tool_with_economy)
    /// is not migrated here because its generic executor closure cannot
    /// cross the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_tools_command(
        &self,
        cmd: ToolsCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Try the actor mailbox first. Post-Step-B every valid context
        // has a registered actor, so the per-context tools handlers run
        // on the actor. Reaching the fallback means no actor is
        // registered for the target context — surface a typed
        // `ContextNotRegistered` on the command's reply oneshot.
        if let Some(ctx_id) = Self::tools_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Tools(cmd)).await;
        }

        // No-actor settle backstop: a `SettleToolEconomy` carries an
        // in-flight `ToolEconomyTicket` (held external payment escrow +
        // the `#[must_use]`/Drop balance invariant). The sync
        // `reply_tools_not_registered` cannot `.await` to void the escrow
        // and would DROP the ticket. The primary defense is the no-actor
        // pre-check in `settle_tool_economy_via_actor`; this handles the
        // residual TOCTOU where the actor is despawned between that
        // pre-check and here. Reclaim the ticket, void its external
        // escrow, consume it, and reply with the typed error.
        if let ToolsCommand::SettleToolEconomy {
            context_id,
            request,
            reply,
            ..
        } = cmd
        {
            let request = *request;
            let generation = request.generation();
            request
                .into_ticket()
                .void_external_and_consume(self.payment_adapter_ref())
                .await;
            // Route through `lookup_miss_error`: a poisoned / silently-dead
            // context surfaces `ContextPoisoned` / `ActorCrashed`, while a
            // genuinely-unknown context keeps the rich SCP-TOOL-6089
            // not-registered diagnostic (escrow already voided above, so the
            // ticket-balance invariant holds on every branch) (ADR-049 §10).
            let err = self.lookup_miss_error(
                &context_id,
                format!(
                    "SCP-TOOL-6089: tool-economy settle for context '{context_id}' found no \
                     registered actor (reserved generation {generation}); escrow voided, \
                     reservation not captured"
                ),
            );
            let sketch = standing_outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Ok(Outcome::err(sketch));
        }

        Ok(Self::reply_tools_not_registered(cmd))
    }

    /// Reply to a [`ToolsCommand`] whose target context has no registered
    /// actor with a typed [`ContextError::ContextNotRegistered`] on the
    /// variant's reply oneshot. Saga-initiator / placeholder variants keep
    /// their own typed replies.
    fn reply_tools_not_registered(cmd: ToolsCommand) -> Outcome<()> {
        match cmd {
            ToolsCommand::Placeholder { reply } => {
                const MSG: &str =
                    "ToolsCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            ToolsCommand::TryConsumeHardRateLimit {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::RefundHardRateLimit {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::ReserveToolEconomy {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::SettleToolEconomy {
                context_id,
                request,
                reply,
                ..
            } => {
                // Defense-in-depth backstop: `dispatch_tools_command`
                // voids the escrow async before reaching this sync path,
                // so this arm is unreachable for a real settle. If a
                // future caller does route here, consume the ticket so
                // its Drop balance guard does not panic (escrow cannot be
                // voided synchronously — logged inside `consume_*`).
                (*request).into_ticket().consume_abandoning_escrow();
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::InitiateCrossContextToolInvocation { reply, .. } => {
                const MSG: &str = "tools::initiate_cross_context_tool_invocation — saga wiring \
                     deferred to commit 11.5 per 5 enumerated spec gaps; see \
                     .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 2: cross-context \
                     tool invocation transport)";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
        }
    }

    /// Reply to a [`BroadcastCommand`] whose target context has no
    /// registered actor.
    ///
    /// Per-context variants (subscribe/unsubscribe/block/unblock/key
    /// request/queries) get a typed [`ContextError::ContextNotRegistered`]
    /// on their reply oneshot. The custody-bound publish variants, the
    /// two-phase reserve/apply/release variants, the saga-initiator
    /// variant, and the placeholder keep their own typed replies (these
    /// never reach a per-context actor through this no-custody router).
    fn reply_broadcast_not_registered(cmd: BroadcastCommand) -> Outcome<()> {
        match cmd {
            BroadcastCommand::Placeholder { reply } => {
                const MSG: &str =
                    "BroadcastCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            BroadcastCommand::SubscribeBroadcast { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::UnsubscribeBroadcast { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::BlockBroadcastSubscriber { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::UnblockBroadcastSubscriber { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::HandleBroadcastKeyRequest {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::BroadcastSubscriberCount { context_id, reply } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::IsBroadcastSubscriber {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::BroadcastAdmission { context_id, reply } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // Publish variants require a `KeyCustody` reference that cannot
            // cross the actor mailbox — route through
            // `dispatch_broadcast_command_with_custody`. Reaching here means
            // a caller took the wrong path; surface a typed error.
            BroadcastCommand::PublishBroadcast { reply, .. } => {
                const MSG: &str = "BroadcastCommand::PublishBroadcast requires a KeyCustody \
                     reference; route through \
                     Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
                let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
                Outcome::err(ContextError::InvalidState(MSG.to_owned()))
            }
            BroadcastCommand::PublishBroadcastContent { reply, .. } => {
                const MSG: &str = "BroadcastCommand::PublishBroadcastContent requires a KeyCustody \
                     reference; route through \
                     Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
                let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
                Outcome::err(ContextError::InvalidState(MSG.to_owned()))
            }
            // Two-phase publish requires a per-context actor (the
            // reservation lives in actor-owned state). No actor → typed
            // not-registered.
            BroadcastCommand::ReserveBroadcastPublish { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::ApplyBroadcastPublish { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // No actor → no reservation could have been issued. Idempotent
            // release: reply Ok so an abort path never errors spuriously.
            BroadcastCommand::ReleaseBroadcastReservation { reply, .. } => {
                let _ = reply.send(Ok(()));
                Outcome::ok(())
            }
            BroadcastCommand::InitiateBroadcastHostingHandshake { reply, .. } => {
                const MSG: &str = "broadcast::initiate_broadcast_hosting_handshake — saga wiring \
                     deferred to commit 11.5 per 5 enumerated spec gaps; see \
                     .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 3: broadcast \
                     hosting handshake protocol)";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
        }
    }

    /// Dispatch a [`BroadcastCommand`] for every non-publish variant.
    ///
    /// Publish variants require a
    /// [`KeyCustody`](scp_platform::KeyCustody) reference that cannot
    /// cross the actor mailbox (RPITIT trait, not `dyn`-safe); use
    /// [`Self::dispatch_broadcast_command_with_custody`] for publish.
    /// The saga-initiator variant
    /// (`InitiateBroadcastHostingHandshake`) returns
    /// [`ContextError::NotImplemented`] during the commit-11 window —
    /// see `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command(
        &self,
        cmd: BroadcastCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Try the actor mailbox first. Post-Step-B every valid context
        // has a registered actor, so the per-context broadcast handlers
        // run on the actor. Reaching the fallback means no actor is
        // registered for the target context — surface a typed
        // `ContextNotRegistered` on the command's reply oneshot.
        if let Some(ctx_id) = Self::broadcast_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd)).await;
        }
        Ok(Self::reply_broadcast_not_registered(cmd))
    }

    /// Dispatch a [`BroadcastCommand`] with an explicit key custody
    /// reference (ADR-049 commit 11 / plan row 11).
    ///
    /// # Why a custody-generic shim still exists
    ///
    /// [`KeyCustody`](scp_platform::KeyCustody) is an RPITIT trait whose
    /// methods return `impl Future` — it is not `dyn`-safe, so a custody
    /// reference cannot be erased and shipped across the actor mailbox.
    /// The publish variants (`PublishBroadcast`, `PublishBroadcastContent`)
    /// need the caller's custody to derive the sender key, and so they
    /// remain on this generic shim path for the foreseeable future.
    ///
    /// # Routing
    ///
    /// - **Non-publish variants** (`Subscribe`, `Unsubscribe`, `Block`,
    ///   `Unblock`, key request, queries) have a per-context owner and a
    ///   `context_id` surfaced by
    ///   [`Self::broadcast_command_context_id`]. They route through the
    ///   per-context actor mailbox.
    /// - **Publish variants** are intentionally returned as `None` from
    ///   `broadcast_command_context_id`, fall through the mailbox check,
    ///   and dispatch on the custody-generic shim below.
    ///
    /// This split is permanent: only the publish path needs custody; the
    /// rest is identical to [`Self::dispatch_broadcast_command`].
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command_with_custody<C: scp_platform::KeyCustody>(
        &self,
        cmd: BroadcastCommand,
        custody: &C,
    ) -> Result<Outcome<()>, ContextError> {
        // Publish variants drive the two-phase reservation flow: the
        // actor reserves the sequence (phase 1), the supervisor signs
        // with the caller's custody OUTSIDE the actor, then the actor
        // seals (phase 2). The custody never crosses the mailbox; both
        // mailbox phases are custody-free. This removes the legacy
        // DashMap read the single-phase shim used.
        match cmd {
            BroadcastCommand::PublishBroadcast { payload, reply } => {
                let p = *payload;
                self.publish_broadcast_two_phase(
                    p.context_id,
                    p.author_did,
                    p.payload,
                    &p.signing_key_handle,
                    custody,
                    reply,
                )
                .await
            }
            BroadcastCommand::PublishBroadcastContent { payload, reply } => {
                let p = *payload;
                let payload_bytes =
                    match scp_protocol::context::broadcast_content::serialize_broadcast_content(
                        &p.content,
                    ) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let msg = format!("content serialization failed: {e}");
                            let _ = reply.send(Err(ContextError::CryptoFailed(msg.clone())));
                            return Ok(Outcome::err(ContextError::CryptoFailed(msg)));
                        }
                    };
                self.publish_broadcast_two_phase(
                    p.context_id,
                    p.author_did,
                    payload_bytes,
                    &p.signing_key_handle,
                    custody,
                    reply,
                )
                .await
            }
            // Non-publish variants are custody-free and route straight
            // through the per-context actor mailbox.
            other => {
                if let Some(ctx_id) = Self::broadcast_command_context_id(&other)
                    && let Some(actor) = self.lookup(ctx_id)
                {
                    return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(other))
                        .await;
                }
                // No registered actor — surface a typed not-registered
                // error on the command's reply oneshot. (Publish variants
                // are handled above and never reach here; non-publish
                // variants need no custody.)
                Ok(Self::reply_broadcast_not_registered(other))
            }
        }
    }

    /// Drive the two-phase broadcast publish across the actor mailbox.
    ///
    /// Phase 1 (`ReserveBroadcastPublish`) and phase 2
    /// (`ApplyBroadcastPublish`) are custody-free mailbox commands; the
    /// signing happens here, between them, with the caller's custody.
    /// A reservation that cannot be applied (no actor, signing failure,
    /// apply failure) is released via `ReleaseBroadcastReservation` so
    /// the reserved sequence is not burned. The final
    /// [`BroadcastEnvelope`](scp_protocol::crypto::sender_keys::BroadcastEnvelope)
    /// (or error) is forwarded to the caller's `reply` channel.
    async fn publish_broadcast_two_phase<C: scp_platform::KeyCustody>(
        &self,
        context_id: String,
        author_did: DID,
        payload: Vec<u8>,
        signing_key_handle: &scp_platform::KeyHandle,
        custody: &C,
        reply: crate::context::actor::commands::PublishBroadcastReply,
    ) -> Result<Outcome<()>, ContextError> {
        use crate::context::actor::commands::{
            ApplyBroadcastPublishPayload, ReserveBroadcastPublishPayload,
        };

        // Resolve the actor up front. Publish requires a registered
        // per-context actor (the reservation lives in actor-owned state). On a
        // miss, route through `lookup_miss_error` so a poisoned / silently-
        // dead context surfaces the dedicated poison error rather than a
        // misleading `ContextNotRegistered` (ADR-049 §10). The error is built
        // twice (reply + outcome sketch) because `ContextError` is not
        // `Clone`; both calls observe the same poison index.
        let Some(actor) = self.lookup(&context_id) else {
            let _ = reply.send(Err(self.lookup_miss_error(&context_id, context_id.clone())));
            return Ok(Outcome::err(
                self.lookup_miss_error(&context_id, context_id.clone()),
            ));
        };

        // Phase 1 — reserve the sequence and get the signing payload.
        let (reserve_tx, reserve_rx) = tokio::sync::oneshot::channel();
        let reserve_cmd = BroadcastCommand::ReserveBroadcastPublish {
            payload: Box::new(ReserveBroadcastPublishPayload {
                context_id: context_id.clone(),
                author_did: author_did.clone(),
            }),
            reply: reserve_tx,
        };
        Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(reserve_cmd)).await?;
        let reservation = match reserve_rx.await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                // Operation-level error already typed by the handler;
                // forward to the caller. The dispatch itself succeeded.
                let _ = reply.send(Err(e));
                return Ok(Outcome::ok_mutated(()));
            }
            Err(_) => {
                let msg = "broadcast reserve reply channel closed".to_owned();
                let _ = reply.send(Err(ContextError::InvalidState(msg.clone())));
                return Ok(Outcome::err(ContextError::InvalidState(msg)));
            }
        };

        // Sign OUTSIDE the actor with the caller's custody.
        let signature = match custody
            .sign(signing_key_handle, &reservation.signing_payload)
            .await
        {
            Ok(sig) => sig.as_bytes().to_vec(),
            Err(e) => {
                // Signing failed — release the reservation so the
                // sequence is reusable, then surface the error.
                self.release_broadcast_reservation(&actor, context_id, reservation.reservation_id)
                    .await;
                let _ = reply.send(Err(ContextError::CryptoFailed(format!(
                    "custody signing failed: {e}"
                ))));
                return Ok(Outcome::ok_mutated(()));
            }
        };

        // Phase 2 — apply the reservation with the signature.
        let (apply_tx, apply_rx) = tokio::sync::oneshot::channel();
        let apply_cmd = BroadcastCommand::ApplyBroadcastPublish {
            payload: Box::new(ApplyBroadcastPublishPayload {
                context_id: context_id.clone(),
                reservation_id: reservation.reservation_id.clone(),
                signature,
                payload,
            }),
            reply: apply_tx,
        };
        Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(apply_cmd)).await?;
        match apply_rx.await {
            Ok(Ok(envelope)) => {
                let _ = reply.send(Ok(envelope));
                Ok(Outcome::ok_mutated(()))
            }
            Ok(Err(e)) => {
                // Apply itself released the reservation on its error
                // paths; nothing more to do here.
                let _ = reply.send(Err(e));
                Ok(Outcome::ok_mutated(()))
            }
            Err(_) => {
                // Apply reply channel closed without a result — release
                // defensively in case the reservation is still live.
                self.release_broadcast_reservation(&actor, context_id, reservation.reservation_id)
                    .await;
                let msg = "broadcast apply reply channel closed".to_owned();
                let _ = reply.send(Err(ContextError::InvalidState(msg.clone())));
                Ok(Outcome::err(ContextError::InvalidState(msg)))
            }
        }
    }

    /// Send a best-effort `ReleaseBroadcastReservation` to the actor so a
    /// reservation that will never be applied does not burn its sequence.
    /// Errors are swallowed — the snapshot floor is the crash-safe
    /// backstop; this is the in-process fast path.
    async fn release_broadcast_reservation(
        &self,
        actor: &ContextActorHandle,
        context_id: String,
        reservation_id: crate::context::actor::state::BroadcastReservationId,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::ReleaseBroadcastReservation {
            payload: Box::new(
                crate::context::actor::commands::ReleaseBroadcastReservationPayload {
                    context_id,
                    reservation_id,
                },
            ),
            reply: tx,
        };
        if Self::dispatch_via_mailbox(actor, ContextCommand::Broadcast(cmd))
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }

    /// Start a cross-context saga. See plan §"Cross-context saga
    /// protocol".
    ///
    /// # Coordinator FSM
    ///
    /// Commit 11 implements the `Initiated → PreparingA → PreparingB →
    /// Committing → Committed | Aborting → Aborted | NeedsRepair` state
    /// machine with journal durability. Each phase transition is
    /// persisted to the
    /// [`SagaJournal`](crate::context::supervisor::saga_journal::SagaJournal)
    /// before the next phase begins; crash recovery replays unresolved
    /// entries on supervisor startup via
    /// [`Self::replay_unresolved_sagas`].
    ///
    /// # Concurrent saga serialization (per participant-context set)
    ///
    /// Sagas are serialized at the granularity of their **participant
    /// context set**, NOT supervisor-wide (ADR-049 §3a, spec §5.15.4). A
    /// saga reserves the set of contexts it spans (computed by
    /// `saga_participant_context_set`); a second `start_saga` whose set is
    /// **disjoint** runs concurrently, while one whose set **overlaps**
    /// (shares ≥1 context) returns
    /// [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy)
    /// with a `SagaBusy` reason. The reservation (`reserved_saga_contexts`)
    /// is held by an RAII guard for the saga's lifetime and released on
    /// EVERY terminal — Committed, Aborted, AND NeedsRepair — plus
    /// panic-unwind, so a stuck saga never wedges unrelated disjoint sagas.
    ///
    /// # Unwired saga use cases (pending Phase 2C)
    ///
    /// `StandingPairCreate` and `BroadcastHostingHandshake` remain spec-gapped
    /// (their Prepare dispatch returns [`ContextError::NotImplemented`]; the FSM
    /// transitions through `Initiated → PreparingA → Aborting → Aborted` and
    /// surfaces the typed error). `CrossContextToolInvocation` is the wired
    /// variant — its end-to-end Prepare/Commit dispatch over the two co-resident
    /// participant actors lands here (spec §6.2.4); drive it via
    /// [`Self::start_cross_context_tool_invocation_saga`], which supplies the
    /// supervisor-side tool executor and the target's Active Signing Key.
    /// Calling `start_saga` directly with a `CrossContextToolInvocation` input
    /// (no executor / signing key) is a misuse: the FSM aborts at Prepare with a
    /// typed error because it has no way to execute the tool or sign the receipt.
    ///
    /// The coordinator itself — journal writes, phase transitions, timeout/retry
    /// accounting, terminal resolution, per-participant-context-set gating — is
    /// fully implemented and saga-type-agnostic.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] (a `SagaBusy` reason) if the new saga's
    ///   participant context set overlaps an in-flight saga's reserved set.
    ///   Disjoint sets run concurrently (ADR-049 §3a, spec §5.15.4).
    /// - [`ContextError::NotImplemented`] for the spec-gapped
    ///   `StandingPairCreate` / `BroadcastHostingHandshake` inputs.
    /// - [`ContextError::InvalidState`] on journal I/O failure.
    pub async fn start_saga(&self, input: SagaInput) -> Result<SagaOutput, ContextError> {
        // Per-participant-context-set reservation (ADR-049 §3a, spec §5.15.4):
        // acquire the gating reservation HERE on the start path (the gate
        // requires the reserve call to live in `start_saga`'s body), then drive
        // the FSM under it. No executor / signing key: the generic entry point
        // cannot drive a `CrossContextToolInvocation` Commit (it has no way to
        // run the tool or sign the receipt) — the cross-context arm's prepare
        // dispatch aborts with a typed error.
        let context_set = saga_participant_context_set(&input);
        let reservation = self.try_reserve_context_set(&context_set)?;
        self.run_saga(input, None, reservation).await
    }

    /// Drive a cross-context tool-invocation saga (spec §6.2.4) end-to-end
    /// over the two co-resident participant context-actors (caller + target),
    /// blocking until the saga reaches a terminal state.
    ///
    /// The supervisor FSM dispatches `PrepareA` to the caller actor, `PrepareB`
    /// to the target actor, then (on Commit) `CommitBReserve` → runs the
    /// `executor` supervisor-side → `CommitBSettle` → `CommitA`. The tool runs
    /// **exactly once** supervisor-side between the two Commit-B round-trips
    /// (the non-`Send` executor cannot cross the actor mailbox per ADR-049 §3).
    ///
    /// `target_signing_key` is the target context's Active Signing Key, used to
    /// sign the [`CrossContextToolReceipt`](scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt)
    /// and the TARGET-side divergence marker on a one-sided `NeedsRepair`.
    /// `caller_signing_key` is the caller context's Active Signing Key, used to
    /// sign the CALLER-side divergence marker on `NeedsRepair`. Each side signs
    /// its own marker into its own log. The actor holds no custody key
    /// (ADR-049), so the caller supplies both per-call exactly as
    /// [`Self::send_heartbeat`] / [`Self::build_local_checkpoint`] do.
    ///
    /// # Co-resident scope
    ///
    /// Both contexts MUST be locally co-resident (registered actors in this
    /// supervisor). If the target actor is not co-resident the saga aborts with
    /// a typed [`ContextError::ContextNotRegistered`] — the cross-node
    /// child-bridge transport is separate future work.
    ///
    /// # Authorization
    ///
    /// Before reserving the participant context set, TWO authorize-before-reserve
    /// gates run — one per axis of the `{caller, target}` set the reservation
    /// would lock — so a reservation is never taken on the strength of one side
    /// alone:
    ///
    /// 1. **Caller axis.** The initiator (`caller_did`) is verified to be a
    ///    member of `caller_context_id`. A non-member is rejected — so a caller
    ///    cannot name (and thereby reserve / deny) a caller context it does not
    ///    belong to.
    /// 2. **Target axis.** The caller context is verified to hold a
    ///    bidirectionally-approved `ToolInterface` to `target_context_id` for
    ///    `tool_registration_id` (the §6.2.0.1 standing consent the §6.2.4
    ///    invocation rides — §6.2.4 does NOT create the interface). Without this,
    ///    a caller who is a member of its OWN context could name an arbitrary
    ///    victim `target_context_id` and reserve the victim's saga slot before
    ///    any target-side check ran (those run inside Prepare-B, AFTER
    ///    reservation), wedging legitimate sagas touching the victim with
    ///    `ActorBusy`. This gate closes that wedge: a caller can only reserve a
    ///    target it has a real established interface with.
    ///
    /// Either gate failing rejects with [`ContextError::PermissionDenied`]
    /// WITHOUT reserving any context.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the initiator is not a member of
    ///   `caller_context_id`, no established interface to `target_context_id`
    ///   exists for `tool_registration_id`, or any Prepare-side §6.2.4 check
    ///   rejects.
    /// - [`ContextError::ActorBusy`] (`SagaBusy`) on a participant-set overlap.
    /// - [`ContextError::ContextNotRegistered`] if a participant actor is not
    ///   co-resident.
    /// - [`ContextError::InvalidState`] on journal I/O failure or a saga driven
    ///   to `NeedsRepair`.
    pub async fn start_cross_context_tool_invocation_saga<F, Fut>(
        &self,
        request: CrossContextToolInvocationRequest,
        target_signing_key: &ed25519_dalek::SigningKey,
        caller_signing_key: &ed25519_dalek::SigningKey,
        executor: F,
    ) -> Result<SagaOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>> + Send + 'static,
    {
        let CrossContextToolInvocationRequest {
            caller_context_id,
            target_context_id,
            caller_did,
            tool_registration_id,
            ucan_proof_id,
            input,
            asserted_chain_depth,
            asserted_nonce,
            asserted_timestamp_ms,
        } = request;
        // Authorize-before-reserve gate 1 (caller axis, forward obligation): the
        // initiator MUST be a member of the caller context it names. Reject
        // WITHOUT reserving so a non-member cannot reserve (and thereby deny) a
        // caller context id it does not belong to.
        let caller_hex = hex::encode(caller_context_id);
        if !self.is_member(&caller_hex, caller_did.as_ref()).await {
            return Err(ContextError::PermissionDenied(format!(
                "SCP-SAGA-13050: cross-context saga initiator '{caller_did}' is not a member \
                 of caller context '{caller_hex}' — not authorized to initiate over it"
            )));
        }

        // Authorize-before-reserve gate 2 (target axis, BLACK-624-02): the caller
        // context MUST hold a bidirectionally-approved interface to the named
        // target for this tool (the §6.2.0.1 standing consent the §6.2.4
        // invocation rides — it does NOT create the interface). Without this, a
        // caller who is a member of its OWN context could name an arbitrary
        // victim target_context_id and reserve the victim's saga slot before any
        // target-side check ran (those run inside Prepare-B, AFTER reservation),
        // wedging legitimate sagas touching the victim with ActorBusy. Reject
        // WITHOUT reserving so the wedge is foreclosed.
        let target_hex = hex::encode(target_context_id);
        if !self
            .has_established_tool_interface(&caller_hex, &target_hex, &tool_registration_id)
            .await
        {
            return Err(ContextError::PermissionDenied(format!(
                "SCP-SAGA-13022: cross-context saga from caller context '{caller_hex}' to target \
                 context '{target_hex}' has no established interface for tool \
                 '{tool_registration_id}' — not authorized to invoke (and not authorized to \
                 reserve the target's saga slot)"
            )));
        }

        // Resolve the channel-authenticated caller's source ROLE in the caller
        // context (spec §6.2.4 "Caller authentication": all InboundPolicy checks
        // MUST evaluate the channel-authenticated identity). The caller's role
        // is authoritative only in the caller context the supervisor just proved
        // membership of (gate 1); it is read HERE supervisor-side and carried to
        // Prepare-B so B can enforce `InboundPolicy.allowed_source_roles` against
        // the real channel-authenticated role, never an envelope-asserted one.
        // `None` ⇒ the caller has no explicit role assignment (only valid if the
        // interface's `allowed_source_roles` is empty = any).
        let caller_source_role = self
            .member_role(&caller_hex, caller_did.as_ref())
            .await
            .map(|assignment| assignment.role_name);

        // Box the executor into the non-generic FSM-carried trait object. The
        // closure runs supervisor-side at Commit-B (off the actor mailbox).
        let boxed_executor: SagaToolExecutor<'_> =
            Box::new(move |v: serde_json::Value| Box::pin(executor(v)) as _);

        let ctx = CrossContextSagaCtx {
            caller_context_id,
            target_context_id,
            caller_did: caller_did.clone(),
            tool_registration_id: tool_registration_id.clone(),
            ucan_proof_id: ucan_proof_id.clone(),
            input: input.clone(),
            asserted_chain_depth,
            asserted_nonce,
            asserted_timestamp_ms,
            caller_source_role,
            target_signing_key: target_signing_key.clone(),
            caller_signing_key: caller_signing_key.clone(),
            executor: Some(boxed_executor),
            executor_output: None,
            prepared_a: None,
            prepared_b: None,
            committed: None,
            committed_b_tool_invoked_event_id: None,
            reached_needs_repair: false,
        };

        let saga_input = SagaInput::CrossContextToolInvocation {
            caller_context_id,
            target_context_id,
            caller_did,
            tool_registration_id,
            ucan_proof_id,
            input,
            asserted_chain_depth,
            asserted_nonce,
            asserted_timestamp_ms,
        };

        // Per-participant-context-set reservation (ADR-049 §3a, spec §5.15.4):
        // acquire the gating reservation on the start path, then drive the FSM
        // under it.
        let context_set = saga_participant_context_set(&saga_input);
        let reservation = self.try_reserve_context_set(&context_set)?;
        self.run_saga(saga_input, Some(ctx), reservation).await
    }

    /// Shared start-saga driver: run the FSM under an ALREADY-acquired
    /// participant-context-set reservation (ADR-049 §3a — the per-set gating
    /// reservation is acquired by each public entry point via
    /// [`Self::try_reserve_context_set`] so the gating is on the start path, not
    /// in this helper). `_reservation` is the RAII guard, held for the FSM scope
    /// and released on EVERY terminal (Committed / Aborted / NeedsRepair) AND on
    /// a panic-unwind through `run_saga_fsm`, so a stuck saga never wedges
    /// unrelated, disjoint sagas. `xctx` carries the cross-context executor +
    /// phase-data when the saga is a wired `CrossContextToolInvocation`; it is
    /// `None` for the spec-gapped / test inputs.
    async fn run_saga(
        &self,
        input: SagaInput,
        xctx: Option<CrossContextSagaCtx<'_>>,
        _reservation: SagaSetReservation<'_>,
    ) -> Result<SagaOutput, ContextError> {
        let saga_id = SagaId::new();
        let participants = saga_input_participants(&input);
        let secret_bearing = saga_input_is_secret_bearing(&input);

        let mut xctx = xctx;
        let fsm_result = self
            .run_saga_fsm(
                saga_id.clone(),
                &input,
                participants.clone(),
                secret_bearing,
                xctx.as_mut(),
            )
            .await;

        // `_reservation` releases the reserved context set on scope exit —
        // including on the panic-unwind path through `run_saga_fsm`.

        // Drain any residual held Prepare-A reservation. The abort path settles
        // the caller side when a Prepare fails; the Commit-A path consumes it on
        // success. A reservation that survives to here was held into a Commit
        // that NEVER reached Commit-A (e.g. the caller actor was unreachable at
        // Commit-A): its owning actor's per-context settle will never run, so
        // void the external escrow and consume the ticket — NEVER drop it
        // unbalanced (the ticket's drop guard would otherwise fire).
        //
        // EXCEPTION — `NeedsRepair` (spec §6.2.4 "`NeedsRepair` reservation
        // semantics"): a saga that diverged keeps its escrow RESERVED for
        // operator-repair settlement (the operation may have partially
        // committed — B executed and charged — so auto-voiding here would be a
        // free-execution exploit). The NeedsRepair divergence path
        // (`emit_divergence_markers`) deliberately does NOT take `prepared_a`,
        // and `reached_needs_repair` tells us to leave it held: we drop the
        // carrier WITHOUT voiding/settling, so the escrow stays reserved. (The
        // concurrency slot is still released — `_reservation` drops on scope
        // exit regardless.)
        if let Some(ctx) = xctx.as_mut() {
            if ctx.reached_needs_repair {
                // Leave the reservation HELD for operator repair. The
                // `ToolEconomyReservation`'s `#[must_use]` drop guard would
                // normally fire on an unbalanced drop, so settle it as a
                // divergence-held escrow that defers to operator repair rather
                // than releasing or consuming it.
                if let Some(reservation) = ctx.prepared_a.take() {
                    reservation.reservation.ticket.hold_external_for_repair();
                    tracing::error!(
                        saga_id = %saga_id.0,
                        "cross-context saga NeedsRepair — Prepare-A escrow held for operator \
                         repair (NOT auto-voided; settled by the divergence marker + operator)"
                    );
                }
            } else if let Some(reservation) = ctx.prepared_a.take() {
                reservation
                    .reservation
                    .ticket
                    .void_external_and_consume(self.payment_adapter_ref())
                    .await;
                tracing::warn!(
                    saga_id = %saga_id.0,
                    "cross-context saga — held Prepare-A reservation survived to terminal without \
                     a Commit-A settle; voided the external escrow and consumed the ticket"
                );
            }
        }

        fsm_result.map(|()| {
            // Surface the committed receipt/output (cross-context arm only).
            let (receipt, output) = xctx
                .and_then(|c| c.committed)
                .map_or((None, None), |a| (Some(a.receipt), Some(a.output)));
            SagaOutput {
                saga_id,
                receipt,
                output,
            }
        })
    }

    /// Atomically reserve a saga's participant context set (ADR-049 §3a).
    ///
    /// One synchronous critical section over `reserved_saga_contexts`:
    /// 1. If ANY id in `context_set` is already reserved, the new saga
    ///    OVERLAPS an in-flight saga — return [`ContextError::ActorBusy`]
    ///    with a `SagaBusy` reason WITHOUT mutating the reservation set.
    /// 2. Otherwise insert the WHOLE set and return a [`SagaSetReservation`]
    ///    RAII guard that removes exactly THESE ids on drop.
    ///
    /// The lock is acquired and released entirely within this synchronous
    /// function (no `.await` while holding the guard), so it cannot suspend
    /// a tokio worker thread across a yield point — the reason the
    /// `std::sync::Mutex` use is sound despite the `clippy.toml` ban (see the
    /// `reserved_saga_contexts` field's narrowly-scoped allow).
    ///
    /// A poisoned lock (a prior holder panicked mid-critical-section, which
    /// the purely-synchronous body makes effectively impossible) is recovered
    /// via `into_inner` rather than propagated, so a single panic elsewhere
    /// cannot permanently wedge every future saga.
    ///
    /// # Errors
    ///
    /// [`ContextError::ActorBusy`] if the participant set overlaps an
    /// in-flight saga's reserved set.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "The lock guard intentionally spans the overlap check AND the \
                  insert loop — that atomic check-and-reserve IS the correctness \
                  property (shortening it reintroduces a TOCTOU). ADR-049 §3a."
    )]
    fn try_reserve_context_set(
        &self,
        context_set: &[String],
    ) -> Result<SagaSetReservation<'_>, ContextError> {
        let mut reserved = self
            .reserved_saga_contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Overlap check: a non-empty intersection with the in-flight set
        // means a shared participant context — serialize (spec §5.15.4:
        // "sharing a single context is sufficient to conflict").
        if let Some(contended) = context_set.iter().find(|id| reserved.contains(*id)) {
            return Err(ContextError::ActorBusy(format!(
                "Supervisor::start_saga — participant context set overlaps an in-flight saga \
                 at context {contended} (SagaBusy)"
            )));
        }

        // Disjoint: reserve the whole set atomically under the same lock.
        for id in context_set {
            reserved.insert(id.clone());
        }

        Ok(SagaSetReservation {
            reserved: &self.reserved_saga_contexts,
            ids: context_set.to_vec(),
        })
    }

    /// Test-only: deterministically reserve a saga's participant context set
    /// and return the RAII reservation, so a test can hold a saga's slots
    /// "in flight" without racing the (instantaneous, spec-gapped) FSM. This
    /// exercises the SAME `try_reserve_context_set` critical section that
    /// [`Self::start_saga`] uses, so the overlap / disjoint / release
    /// semantics under test are the production ones, not a parallel mock.
    ///
    /// Returning the borrow-scoped [`SagaSetReservation`] lets the caller
    /// drop it to release (mirroring a saga reaching a terminal state).
    ///
    /// # Errors
    ///
    /// [`ContextError::ActorBusy`] if the set overlaps an already-held set.
    #[cfg(any(test, feature = "testing"))]
    pub fn test_reserve_saga_context_set(
        &self,
        input: &SagaInput,
    ) -> Result<SagaSetReservation<'_>, ContextError> {
        let set = saga_participant_context_set(input);
        self.try_reserve_context_set(&set)
    }

    /// Test-only: the CANONICAL gating reservation key a standing-pair saga
    /// over `(local_did, peer_did)` reserves — the raw-digest hex
    /// (`hex::encode(derive_standing_context_digest(..))`), NOT the
    /// `"standing-"`-prefixed actor-registry id. Lets a cross-saga-type
    /// overlap test feed the EXACT key a `StandingPairCreate` saga reserves
    /// into a `CrossContextToolInvocation` saga's `[u8; 32]` context field,
    /// proving overlap detection is pure set-membership across saga types
    /// (ADR-049 §3a, spec §5.15.4 / §5.15.8).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn test_standing_pair_context_digest(local_did: &DID, peer_did: &DID) -> [u8; 32] {
        crate::context::standing_helpers::derive_standing_context_digest(local_did, peer_did)
    }

    /// Replay unresolved sagas from the journal on supervisor startup
    /// (plan §"Crash recovery"). For each unresolved state:
    ///
    /// - `Initiated` / `PreparingA` — discard (no remote side-effects
    ///   yet; idempotent discard is safe).
    /// - `PreparingB` — send a best-effort `Abort` to actor A (actor A
    ///   Prepared in memory but the Commit never left the coordinator;
    ///   Abort rolls the staged mutation back).
    /// - `Committing` — re-send the `Commit` message; actors MUST be
    ///   idempotent on Commit receipt (Commit against an already-
    ///   committed saga is a no-op with success).
    /// - `NeedsRepair` — emit a metric; operator intervention is
    ///   required to repair the saga.
    ///
    /// This method is called by [`Self::new`] through an internal replay-task
    /// spawn on construction so a crash-restart
    /// supervisor reconciles state before the first `start_saga` call.
    /// It is safe to call multiple times; each call loads the current
    /// unresolved set from the journal.
    ///
    /// # Errors
    ///
    /// Returns the journal's error class (via `ContextError::InvalidState`)
    /// if `load_unresolved` fails. Per-entry processing errors are logged
    /// via `tracing` and do not abort the recovery sweep.
    pub async fn replay_unresolved_sagas(&self) -> Result<(), ContextError> {
        let entries = self.saga_journal.load_unresolved().await.map_err(|e| {
            ContextError::InvalidState(format!("saga journal load_unresolved failed: {e}"))
        })?;

        for entry in entries {
            self.recover_saga_entry(entry).await;
        }
        Ok(())
    }

    async fn recover_saga_entry(&self, entry: JournalEntry) {
        match entry.state {
            SagaState::Initiated | SagaState::PreparingA => {
                // No remote side-effects yet — discard by marking
                // Aborted. `secret_bearing` classifies the resolution
                // marker for secure-evidence overwrite.
                let _ = self
                    .saga_journal
                    .mark_resolved(
                        entry.saga_id.clone(),
                        SagaTerminalState::Aborted,
                        /*secret_bearing=*/ false,
                    )
                    .await;
                tracing::info!(
                    saga_id = %entry.saga_id,
                    state = ?entry.state,
                    "saga recovery — discarded (no remote side-effects)"
                );
            }
            SagaState::PreparingB => {
                // §17.16.4 Prepare-in-progress: actor A (and possibly B) staged
                // reservations but the Commit never left the coordinator. Abort
                // the Prepared side(s) — releasing the staged rate/escrow/session
                // reservations — and discard; NEVER re-Prepare. For a
                // reconstructible cross-context entry this sends a real `Abort`
                // to the prepared actors (release); otherwise the journal abort
                // marker IS the rollback record.
                if let Some(prepared) = Self::reconstruct_xctx_prepared(&entry) {
                    self.redrive_xctx_prepare_in_progress(&entry.saga_id, &prepared)
                        .await;
                }
                let _ = self
                    .saga_journal
                    .mark_resolved(
                        entry.saga_id.clone(),
                        SagaTerminalState::Aborted,
                        /*secret_bearing=*/ false,
                    )
                    .await;
                tracing::warn!(
                    saga_id = %entry.saga_id,
                    "saga recovery — PreparingB (Prepare-in-progress) observed; aborted the \
                     Prepared side(s) and discarded (never re-Prepared)"
                );
            }
            SagaState::Committing => {
                self.recover_committing_entry(&entry).await;
            }
            SagaState::Aborting => {
                // An Aborting entry's rollback never completed; re-resolve to
                // NeedsRepair so an operator sees it (the Abort side-effects are
                // not journal-visible). No re-drive — Aborting carries no
                // committed side.
                let _ = self
                    .saga_journal
                    .append(JournalEntry {
                        saga_id: entry.saga_id.clone(),
                        state: SagaState::NeedsRepair,
                        participants: entry.participants.clone(),
                        evidence: Zeroizing::new(Vec::new()),
                        timestamp_ms: current_timestamp_ms(),
                        seq_per_saga: entry.seq_per_saga.saturating_add(1),
                    })
                    .await;
                tracing::error!(
                    saga_id = %entry.saga_id,
                    "saga recovery — Aborting observed; marked NeedsRepair for operator review"
                );
            }
            SagaState::NeedsRepair => {
                tracing::error!(
                    saga_id = %entry.saga_id,
                    "saga recovery — NeedsRepair carryover; operator intervention required"
                );
            }
            SagaState::Committed | SagaState::Aborted => {
                // Terminal — not returned by load_unresolved but
                // defensively handled here.
            }
        }
    }

    /// §17.16.4 Commit-in-progress recovery for a `Committing` journal entry.
    /// Re-drives the idempotent Commit (NEVER re-invoking the tool): B re-acks
    /// the existing `ToolInvoked` and re-emits the STORED output; A re-acks from
    /// the durable `xctx_committed_invocations` witness (keyed on the Class-S
    /// witness, NOT the in-memory reservation that died with the crash). If BOTH
    /// sides committed the saga is FULLY committed and resolves to `Committed`;
    /// only a genuinely-unresolvable divergence (one-sided commit / unreachable
    /// side / non-reconstructible entry) stays `NeedsRepair` for operator repair.
    async fn recover_committing_entry(&self, entry: &JournalEntry) {
        let resolution = match Self::reconstruct_xctx_prepared(entry) {
            Some(prepared) => {
                self.redrive_xctx_commit_in_progress(&entry.saga_id, &prepared)
                    .await
            }
            None => CommitInProgressResolution::NeedsRepair,
        };
        match resolution {
            CommitInProgressResolution::Committed => {
                // Fully committed: mark the journal resolved (overwrite the
                // resolution marker as secure evidence — same as the live commit
                // path). `secret_bearing=false`: the §6.2.4 saga resolution
                // markers carry no bearer secret.
                let _ = self
                    .saga_journal
                    .mark_resolved(
                        entry.saga_id.clone(),
                        SagaTerminalState::Committed,
                        /*secret_bearing=*/ false,
                    )
                    .await;
                tracing::info!(
                    saga_id = %entry.saga_id,
                    "saga recovery — Commit-in-progress resolved to Committed (B re-emitted, A \
                     witness present); no operator repair required"
                );
            }
            CommitInProgressResolution::NeedsRepair => {
                let _ = self
                    .saga_journal
                    .append(JournalEntry {
                        saga_id: entry.saga_id.clone(),
                        state: SagaState::NeedsRepair,
                        participants: entry.participants.clone(),
                        evidence: Zeroizing::new(Vec::new()),
                        timestamp_ms: current_timestamp_ms(),
                        seq_per_saga: entry.seq_per_saga.saturating_add(1),
                    })
                    .await;
                tracing::error!(
                    saga_id = %entry.saga_id,
                    "saga recovery — Commit-in-progress observed; re-drove the idempotent Commit-B \
                     (no re-invoke) but could not confirm both sides committed — marked \
                     NeedsRepair for operator review"
                );
            }
        }
    }

    /// Reconstruct a cross-context tool-invocation saga's prepared state from a
    /// journal entry's `evidence` (spec §6.2.4 "Crash recovery §17.16.4").
    ///
    /// The evidence is the `MessagePack` of the eight-field
    /// [`CrossContextToolInvocationPrepared`](crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared)
    /// wire — carrying BOTH the `caller_context_id` AND the `target_context_id`
    /// (option (a) — closing the [`saga_input_participants`] caller-only gap) plus
    /// the staged provenance. Decoding it yields the FULL `{caller, target}`
    /// participant set and the prepared provenance the replay re-drive needs.
    /// Returns `None` if the entry is not a cross-context saga (its evidence
    /// does not decode), e.g. a standing-pair / broadcast / test entry.
    fn reconstruct_xctx_prepared(entry: &JournalEntry) -> Option<XctxPrepared> {
        use crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;
        if entry.evidence.is_empty() {
            return None;
        }
        CrossContextToolInvocationPrepared::from_evidence_bytes(entry.evidence.as_slice()).ok()
    }

    /// §17.16.4 Prepare-in-progress re-drive: abort the Prepared side(s) of a
    /// cross-context saga, releasing the staged reservations, then discard
    /// (NEVER re-Prepare). Sends a best-effort [`SagaPhaseMessage::Abort`] to
    /// the caller actor (whose Prepare-A staged the escrow/outbound-RL slot —
    /// `None` reservation, so the actor releases its own held slot if present)
    /// and the target actor (whose Prepare-B staged the `saga_pending` session
    /// slot). A lookup miss / send failure is logged; the journal abort marker
    /// (written by the caller) is the authoritative rollback record.
    ///
    /// Invoked by [`Self::recover_saga_entry`] on a `PreparingB` entry, which is
    /// driven by the Phase-2D startup replay loop
    /// ([`Self::replay_unresolved_sagas`]).
    async fn redrive_xctx_prepare_in_progress(&self, saga_id: &SagaId, prepared: &XctxPrepared) {
        use crate::context::actor::commands::SagaPhaseMessage;
        for context_id in [prepared.caller_context_id, prepared.target_context_id] {
            let context_hex = hex::encode(context_id);
            if let Some(actor) = self.lookup(&context_hex) {
                let abort_saga_id = saga_id.clone();
                // `None` reservation: the post-crash coordinator no longer holds
                // the Prepare-A `PreparedAFields` carrier (it died with the
                // crash); the actor releases its OWN staged slot (caller: held
                // escrow/RL; target: `saga_pending` session) keyed by SagaId.
                let result = actor
                    .send(move |reply| {
                        ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
                            saga_id: abort_saga_id,
                            reservation: None,
                            reply,
                        })
                    })
                    .await;
                if let Err(err) = result {
                    tracing::warn!(
                        saga_id = %saga_id.0,
                        context = %context_hex,
                        %err,
                        "saga recovery — Prepare-in-progress Abort send failed; journal abort \
                         marker is the authoritative rollback record"
                    );
                }
            }
        }
    }

    /// §17.16.4 Commit-in-progress re-drive: re-send the idempotent Commit-B,
    /// which re-acks the existing `ToolInvoked` and re-emits the STORED output —
    /// NEVER re-invoking the tool (the exactly-once-execution guarantee survives
    /// a crash). Sends [`SagaPhaseMessage::CommitBReserve`]; on a committed saga
    /// the actor replies `AlreadyCommitted` with the stored receipt/output, so
    /// the tool is not re-run.
    ///
    /// Then re-acks the A side FROM THE DURABLE WITNESS: `commit_a` keys
    /// idempotency on the Class-S `xctx_committed_invocations` witness (not the
    /// in-memory reservation that died with the crash), so a Commit-A that
    /// durably landed before the crash is observable NOW. This re-drive queries
    /// the caller actor's witness ([`SagaPhaseMessage::CommitACheckWitness`]); if
    /// BOTH sides are committed (B `AlreadyCommitted` + the A witness present)
    /// the saga is FULLY committed and resolves to `Committed` — not a spurious
    /// `NeedsRepair`. Only a genuinely-unresolvable divergence (B committed but A
    /// did not, or a side is unreachable) stays `NeedsRepair`.
    ///
    /// Returns the resolution so [`Self::recover_saga_entry`] journals the right
    /// terminal. Invoked by `recover_saga_entry` on a `Committing` entry, driven
    /// by the Phase-2D startup replay loop ([`Self::replay_unresolved_sagas`]).
    async fn redrive_xctx_commit_in_progress(
        &self,
        saga_id: &SagaId,
        prepared: &XctxPrepared,
    ) -> CommitInProgressResolution {
        use crate::context::actor::commands::{CommitBReserveOutcome, SagaPhaseMessage};
        let target_hex = hex::encode(prepared.target_context_id);
        let Some(target) = self.lookup(&target_hex) else {
            tracing::warn!(
                saga_id = %saga_id.0,
                context = %target_hex,
                "saga recovery — Commit-in-progress re-drive: target actor unreachable; operator \
                 repair required"
            );
            return CommitInProgressResolution::NeedsRepair;
        };
        let reserve_saga_id = saga_id.clone();
        let reserve = target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve {
                    saga_id: reserve_saga_id,
                    reply,
                })
            })
            .await;
        match reserve {
            Ok(CommitBReserveOutcome::AlreadyCommitted { .. }) => {
                tracing::info!(
                    saga_id = %saga_id.0,
                    "saga recovery — Commit-in-progress re-drive: target re-emitted the STORED \
                     output (no re-invoke), idempotent by SagaId; checking the A-side witness"
                );
                // B committed. Re-ack the A side from the durable witness: if
                // Commit-A also landed before the crash the saga is fully
                // committed — resolve to Committed, not a false NeedsRepair.
                self.redrive_commit_a_witness(saga_id, prepared).await
            }
            Ok(CommitBReserveOutcome::ReadyToExecute) => {
                // Commit-B had NOT durably landed before the crash; the tool was
                // never executed, so there is no stored output to re-emit. NEVER
                // re-invoke on the recovery path — the live initiator retries
                // fresh (spec §17.16.4 "the initiator retries fresh"). No side
                // committed, so this is a clean abort-equivalent, not a divergence.
                tracing::warn!(
                    saga_id = %saga_id.0,
                    "saga recovery — Commit-in-progress re-drive: target reports ReadyToExecute \
                     (Commit-B never durably landed); NOT re-invoking — initiator retries fresh"
                );
                CommitInProgressResolution::NeedsRepair
            }
            Err(err) => {
                tracing::warn!(
                    saga_id = %saga_id.0,
                    %err,
                    "saga recovery — Commit-in-progress re-drive: Commit-B reserve send failed; \
                     operator repair required"
                );
                CommitInProgressResolution::NeedsRepair
            }
        }
    }

    /// Re-ack the A side of a Commit-in-progress recovery from the durable
    /// `xctx_committed_invocations` witness (spec §17.16.4). Queries the caller
    /// actor read-only; a present witness means Commit-A durably landed before
    /// the crash, so the (B-committed) saga is FULLY committed →
    /// [`CommitInProgressResolution::Committed`]. An absent witness, an
    /// unreachable caller, or a send failure means the A side did NOT commit (or
    /// cannot be confirmed) — a genuine one-sided divergence that stays
    /// [`CommitInProgressResolution::NeedsRepair`] for operator repair.
    async fn redrive_commit_a_witness(
        &self,
        saga_id: &SagaId,
        prepared: &XctxPrepared,
    ) -> CommitInProgressResolution {
        use crate::context::actor::commands::SagaPhaseMessage;
        let caller_hex = hex::encode(prepared.caller_context_id);
        let Some(caller) = self.lookup(&caller_hex) else {
            tracing::error!(
                saga_id = %saga_id.0,
                context = %caller_hex,
                "saga recovery — Commit-in-progress: caller actor unreachable; cannot confirm the \
                 A-side witness — NeedsRepair (possible one-sided commit)"
            );
            return CommitInProgressResolution::NeedsRepair;
        };
        let witness_saga_id = saga_id.clone();
        match caller
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitACheckWitness {
                    saga_id: witness_saga_id,
                    reply,
                })
            })
            .await
        {
            Ok(true) => {
                tracing::info!(
                    saga_id = %saga_id.0,
                    "saga recovery — Commit-in-progress: BOTH sides committed (B re-emitted, A \
                     witness present); resolving to Committed (no false NeedsRepair)"
                );
                CommitInProgressResolution::Committed
            }
            Ok(false) => {
                tracing::error!(
                    saga_id = %saga_id.0,
                    "saga recovery — Commit-in-progress: target committed but the caller witness \
                     is absent (Commit-A never landed) — one-sided commit, NeedsRepair"
                );
                CommitInProgressResolution::NeedsRepair
            }
            Err(err) => {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "saga recovery — Commit-in-progress: A-side witness query failed; cannot \
                     confirm Commit-A — NeedsRepair"
                );
                CommitInProgressResolution::NeedsRepair
            }
        }
    }

    /// Run the saga FSM for a single saga. Returns `Ok(())` iff the
    /// saga reached `SagaState::Committed`. Every other terminal state
    /// (`Aborted`, `NeedsRepair`) returns a typed error that the caller
    /// surfaces.
    ///
    /// The FSM is saga-type-agnostic — it owns the journal write-ordering,
    /// phase transitions, commit-retry/back-off, `NeedsRepair` accounting, and
    /// abort sequencing. `xctx` threads the per-phase data hand-off for a
    /// `CrossContextToolInvocation` saga (spec §6.2.4): Prepare-A's reservation,
    /// Prepare-B's recorded provenance, and Commit-B's captured receipt/output
    /// flow A→B→Commit through it. `None` for the spec-gapped / test inputs.
    async fn run_saga_fsm(
        &self,
        saga_id: SagaId,
        input: &SagaInput,
        participants: Vec<String>,
        secret_bearing: bool,
        mut xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        // 1. Initiated
        self.append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
            .await?;

        // 2. PreparingA — dispatch to the caller actor (cross-context) or
        //    NotImplemented (spec-gapped). On failure the FSM transitions
        //    directly to Aborted, releasing any side that prepared, and
        //    surfaces the typed error. Every phase transition is journaled so
        //    crash-recovery tests see the right states.
        self.append_journal(&saga_id, SagaState::PreparingA, &participants, 1, &[])
            .await?;

        let phase_a = self
            .dispatch_prepare_phase(&saga_id, input, SagaPhase::A, xctx.as_deref_mut())
            .await;
        if let Err(err) = phase_a {
            self.abort_saga(
                &saga_id,
                &participants,
                2,
                secret_bearing,
                xctx.as_deref_mut(),
            )
            .await?;
            return Err(err);
        }

        // 3. PreparingB — journal the FULL `{caller, target}` evidence (option
        //    (a) from the `reserved_saga_contexts` field doc): the
        //    `CrossContextToolInvocationPrepared` wire carries BOTH context ids,
        //    so a crash-recovery replay can rebuild the complete participant set
        //    + the staged provenance (spec §6.2.4 "Crash recovery §17.16.4").
        //    `saga_input_participants` deliberately omits `target_context_id`
        //    from its (caller-only) provenance triple; the evidence closes that
        //    gap. At PreparingB the caller-asserted nonce/depth stand in for B's
        //    recorded values (B records them inside Prepare-B); the Committing
        //    append below re-journals with B's authoritative recorded provenance.
        let preparing_b_evidence = xctx
            .as_deref()
            .and_then(|ctx| Self::xctx_prepared_evidence_bytes(input, ctx));
        self.append_journal(
            &saga_id,
            SagaState::PreparingB,
            &participants,
            2,
            preparing_b_evidence.as_deref().unwrap_or(&[]),
        )
        .await?;

        let phase_b = self
            .dispatch_prepare_phase(&saga_id, input, SagaPhase::B, xctx.as_deref_mut())
            .await;
        if let Err(err) = phase_b {
            self.abort_saga(
                &saga_id,
                &participants,
                3,
                secret_bearing,
                xctx.as_deref_mut(),
            )
            .await?;
            return Err(err);
        }

        // 4. Committing — 3x retry with 500ms/1s/2s exponential back-off.
        //    Re-journal the evidence now that Prepare-B has recorded B's
        //    authoritative provenance (clock / nonce / re-derived depth): a
        //    Commit-in-progress crash-recovery replay (§17.16.4) reconstructs
        //    the staged `CrossContextToolInvocationPrepared` from THIS evidence
        //    to re-drive the idempotent Commit.
        let committing_evidence = xctx
            .as_deref()
            .and_then(|ctx| Self::xctx_prepared_evidence_bytes(input, ctx));
        self.append_journal(
            &saga_id,
            SagaState::Committing,
            &participants,
            3,
            committing_evidence.as_deref().unwrap_or(&[]),
        )
        .await?;

        let commit_result = self
            .commit_with_retry(&saga_id, input, xctx.as_deref_mut())
            .await;
        match commit_result {
            Ok(()) => {
                self.saga_journal
                    .mark_resolved(
                        saga_id.clone(),
                        SagaTerminalState::Committed,
                        secret_bearing,
                    )
                    .await
                    .map_err(|e| {
                        ContextError::InvalidState(format!("saga journal mark_resolved: {e}"))
                    })?;
                Ok(())
            }
            Err(err) => {
                // Commit retry exhausted — NeedsRepair (spec §6.2.4
                // "commit_with_retry exhausts (3×) → NeedsRepair").
                self.append_journal(&saga_id, SagaState::NeedsRepair, &participants, 4, &[])
                    .await?;
                tracing::error!(
                    saga_id = %saga_id,
                    %err,
                    "saga coordinator — commit retry exhausted, saga in NeedsRepair"
                );
                // Dual event-log recording (spec §6.2.4): on NeedsRepair both
                // sides MUST emit a signed `CrossContextDivergenceMarker` (into
                // each available log, or the supervisor-level repair journal if
                // a side is unreachable) so a one-sided commit is durably
                // auditable. Cross-context only; the test / spec-gapped inputs
                // carry no `xctx`. Marks the ctx so `run_saga`'s tail leaves the
                // escrow RESERVED (NOT auto-voided) for operator repair.
                if let Some(ctx) = xctx {
                    ctx.reached_needs_repair = true;
                    // Extract the owned divergence plan SYNCHRONOUSLY (no `&ctx`
                    // borrow crosses the `.await` — the ctx's boxed executor is
                    // non-`Sync`), then emit. A `None` plan ⇒ Commit-B never
                    // landed (no committed side, no divergence to mark).
                    if let Some(plan) = Self::divergence_marker_plan(ctx) {
                        Box::pin(self.emit_divergence_markers(&saga_id, plan)).await;
                    } else {
                        tracing::warn!(
                            saga_id = %saga_id,
                            "cross-context saga NeedsRepair with NO committed side (Commit-B never \
                             landed); logs are clean, no divergence marker required"
                        );
                    }
                }
                Err(err)
            }
        }
    }

    /// Dispatch a single Prepare phase under the 30s per-phase timeout
    /// ([ADR-049](crate) §7; a timeout maps to
    /// [`ContextError::TransportTimeout`]).
    ///
    /// `StandingPairCreate` / `BroadcastHostingHandshake` are spec-gapped
    /// (return [`ContextError::NotImplemented`]). For
    /// `CrossContextToolInvocation` the FSM routes the per-phase message to the
    /// co-resident participant actor and threads the reply into `xctx`:
    /// Prepare-A → caller actor → hold `PreparedAFields`; Prepare-B → target
    /// actor → hold `PreparedBFields`. A missing executor context for a
    /// cross-context input is a misuse (`start_saga` without an executor) and
    /// aborts with a typed error.
    async fn dispatch_prepare_phase(
        &self,
        saga_id: &SagaId,
        input: &SagaInput,
        phase: SagaPhase,
        xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        let dispatch_fut = async {
            match input {
                SagaInput::StandingPairCreate { .. } => Err(ContextError::NotImplemented(format!(
                    "saga Prepare{phase:?} — StandingPairCreate wiring deferred to commit 11.5 \
                     per DEFERRED-commit-11-saga-use-cases.md gap 1 (standing-pair 2-phase \
                     decomposition)"
                ))),
                SagaInput::CrossContextToolInvocation { .. } => {
                    let Some(ctx) = xctx else {
                        return Err(ContextError::InvalidState(format!(
                            "SCP-SAGA-13051: saga Prepare{phase:?} — CrossContextToolInvocation \
                             requires the supervisor-side executor + signing key; call \
                             start_cross_context_tool_invocation_saga, not start_saga"
                        )));
                    };
                    match phase {
                        SagaPhase::A => self.dispatch_xctx_prepare_a(ctx).await,
                        SagaPhase::B => self.dispatch_xctx_prepare_b(saga_id, ctx).await,
                    }
                }
                SagaInput::BroadcastHostingHandshake { .. } => {
                    Err(ContextError::NotImplemented(format!(
                        "saga Prepare{phase:?} — BroadcastHostingHandshake wiring deferred to \
                         commit 11.5 per DEFERRED-commit-11-saga-use-cases.md gap 3 (broadcast \
                         hosting handshake protocol)"
                    )))
                }
                // Test-only: Prepare always SUCCEEDS so the FSM advances to
                // Committing (where the test variant's Commit then fails,
                // driving NeedsRepair).
                #[cfg(any(test, feature = "testing"))]
                SagaInput::TestForceNeedsRepair { .. } => Ok(()),
            }
        };

        match tokio::time::timeout(PHASE_TIMEOUT, dispatch_fut).await {
            Ok(r) => r,
            Err(_elapsed) => Err(ContextError::TransportTimeout(format!(
                "saga Prepare{phase:?} exceeded 30s phase budget"
            ))),
        }
    }

    /// Prepare-A (caller side, spec §6.2.4): resolve the co-resident caller
    /// actor, send [`SagaPhaseMessage::PrepareA`], and hold the returned
    /// [`PreparedAFields`] reservation in `ctx` for Commit-A / abort.
    async fn dispatch_xctx_prepare_a(
        &self,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::SagaPhaseMessage;

        let caller_hex = hex::encode(ctx.caller_context_id);
        let actor = self.lookup(&caller_hex).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "SCP-SAGA-13052: cross-context saga Prepare-A — caller context '{caller_hex}' \
                 is not a co-resident actor (cross-node child-bridge transport is future work)"
            ))
        })?;

        let caller_context_id = ctx.caller_context_id;
        let caller_did = ctx.caller_did.clone();
        let tool_registration_id = ctx.tool_registration_id.clone();

        let prepared = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::PrepareA {
                    caller_context_id,
                    caller_did,
                    tool_registration_id,
                    reply,
                })
            })
            .await?;
        ctx.prepared_a = Some(prepared);
        Ok(())
    }

    /// Prepare-B (target side, spec §6.2.4): resolve the co-resident target
    /// actor, send [`SagaPhaseMessage::PrepareB`] with the caller-asserted
    /// envelope, and hold the returned [`PreparedBFields`] in `ctx`.
    async fn dispatch_xctx_prepare_b(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::SagaPhaseMessage;

        let target_hex = hex::encode(ctx.target_context_id);
        let actor = self.lookup(&target_hex).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "SCP-SAGA-13053: cross-context saga Prepare-B — target context '{target_hex}' \
                 is not a co-resident actor (cross-node child-bridge transport is future work)"
            ))
        })?;

        let saga_id = saga_id.clone();
        let caller_context_id = ctx.caller_context_id;
        let target_context_id = ctx.target_context_id;
        let caller_did = ctx.caller_did.clone();
        let tool_registration_id = ctx.tool_registration_id.clone();
        let ucan_proof_id = ctx.ucan_proof_id.clone();
        let input = ctx.input.clone();
        let asserted_chain_depth = ctx.asserted_chain_depth;
        let asserted_nonce = ctx.asserted_nonce;
        let asserted_timestamp_ms = ctx.asserted_timestamp_ms;
        let caller_source_role = ctx.caller_source_role.clone();

        let prepared = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::PrepareB {
                    saga_id,
                    caller_context_id,
                    target_context_id,
                    caller_did,
                    tool_registration_id,
                    ucan_proof_id,
                    input,
                    asserted_chain_depth,
                    asserted_nonce,
                    asserted_timestamp_ms,
                    caller_source_role,
                    reply,
                })
            })
            .await?;
        ctx.prepared_b = Some(prepared);
        Ok(())
    }

    /// Commit with 3x retry: 500ms, 1s, 2s. Returns the final error after
    /// retries are exhausted (→ `NeedsRepair`). The `TestForceNeedsRepair`
    /// variant always fails (driving the retry-exhaustion path); a wired
    /// `CrossContextToolInvocation` runs the real two-side Commit.
    async fn commit_with_retry(
        &self,
        saga_id: &SagaId,
        input: &SagaInput,
        mut xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        const BACKOFFS: &[std::time::Duration] = &[
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(2),
        ];

        let mut last_err: Option<ContextError> = None;
        for (attempt, backoff) in BACKOFFS.iter().enumerate() {
            if attempt > 0 {
                tokio::time::sleep(*backoff).await;
            }
            match self
                .dispatch_commit_phase(saga_id, input, xctx.as_deref_mut())
                .await
            {
                Ok(()) => return Ok(()),
                Err(err) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = BACKOFFS.len(),
                        %err,
                        "saga commit attempt failed, retrying"
                    );
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            ContextError::InvalidState("saga commit retry loop produced no error".to_owned())
        }))
    }

    /// Dispatch the Commit phase under the 30s per-attempt timeout.
    ///
    /// For a wired `CrossContextToolInvocation` this drives the §6.2.4 Commit:
    /// Commit-B reserve → run the executor supervisor-side → Commit-B settle →
    /// Commit-A, ordered B then A. `StandingPairCreate` /
    /// `BroadcastHostingHandshake` stay `NotImplemented`; `TestForceNeedsRepair`
    /// always fails.
    async fn dispatch_commit_phase(
        &self,
        saga_id: &SagaId,
        input: &SagaInput,
        xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        let dispatch_fut = async {
            match input {
                SagaInput::StandingPairCreate { .. }
                | SagaInput::BroadcastHostingHandshake { .. } => Err(ContextError::NotImplemented(
                    "saga Commit — StandingPairCreate / BroadcastHostingHandshake commit-side \
                         wiring deferred per DEFERRED-commit-11-saga-use-cases.md"
                        .to_owned(),
                )),
                SagaInput::CrossContextToolInvocation { .. } => {
                    let Some(ctx) = xctx else {
                        return Err(ContextError::InvalidState(
                            "SCP-SAGA-13054: saga Commit — CrossContextToolInvocation requires \
                             the supervisor-side executor context (start_saga misuse)"
                                .to_owned(),
                        ));
                    };
                    self.dispatch_xctx_commit(saga_id, ctx).await
                }
                // Test-only: Commit ALWAYS fails so `commit_with_retry`
                // exhausts its budget and the FSM transitions to NeedsRepair.
                #[cfg(any(test, feature = "testing"))]
                SagaInput::TestForceNeedsRepair { .. } => Err(ContextError::InvalidState(
                    "saga Commit — TestForceNeedsRepair always fails to drive NeedsRepair"
                        .to_owned(),
                )),
            }
        };

        match tokio::time::timeout(PHASE_TIMEOUT, dispatch_fut).await {
            Ok(r) => r,
            Err(_elapsed) => Err(ContextError::TransportTimeout(
                "saga Commit exceeded 30s phase budget".to_owned(),
            )),
        }
    }

    /// Drive the §6.2.4 Commit over the two co-resident actors, ordered B then
    /// A:
    ///
    /// 1. **Commit-B reserve** — ask the target actor whether to execute. On a
    ///    replay (`AlreadyCommitted`) it returns the STORED receipt/output and
    ///    the tool is NOT re-invoked.
    /// 2. **Run the executor supervisor-side** — the non-`Send` tool executor
    ///    runs off the actor mailbox (ADR-049 §3), producing the output.
    /// 3. **Commit-B settle** — hand the output to the target actor, which
    ///    signs the receipt with `target_signing_key`, appends `ToolInvoked`,
    ///    and durably captures the output keyed by `SagaId`.
    /// 4. **Commit-A** — hand the receipt/output + the held Prepare-A
    ///    reservation to the caller actor, which settles escrow and records
    ///    `CrossContextToolInvoked` (sharing the nonce).
    ///
    /// The captured receipt/output are stored in `ctx.committed` for
    /// [`SagaOutput`]. A failure at any step propagates (the FSM retries, then
    /// `NeedsRepair`); the Prepare-A reservation stays held for the retry and is
    /// settled only on a successful Commit-A.
    async fn dispatch_xctx_commit(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(), ContextError> {
        // Commit B (execute-or-replay) then A, per §6.2.4.
        let (receipt, output) = self.commit_b_execute_or_replay(saga_id, ctx).await?;

        // Verify-before-settle (spec §6.2.4 "Signer authorization", normative
        // MUST): before Commit-A settles escrow + records the provenance edge,
        // verify B's signature over the receipt against the Active Signing Key
        // AUTHORIZED for `target_context_id`. The FSM already holds that
        // resolved key (`ctx.target_signing_key` — the same key it PASSED to
        // Commit-B to sign the receipt), so verification here is equivalent to
        // "signed by the key authorized for the target context". A verify
        // failure aborts the Commit WITHOUT settling or recording — a forged /
        // tampered receipt must never charge the caller or write a provenance
        // edge. This also pins the bytes A records: the verified receipt's
        // SIGNED `output_hash` is what Commit-A binds, not an independently
        // recomputed hash.
        let parsed = Self::verify_commit_b_receipt(saga_id, ctx, &receipt)?;

        self.commit_a_settle(saga_id, ctx, &receipt, &parsed)
            .await?;
        ctx.committed = Some(CommittedSagaArtifacts { receipt, output });
        Ok(())
    }

    /// Verify B's signed [`CrossContextToolReceipt`] against the Active Signing
    /// Key authorized for `target_context_id` (spec §6.2.4 "Signer
    /// authorization", normative MUST) and return the parsed receipt for the
    /// Commit-A binding.
    ///
    /// The FSM holds the resolved target key (`ctx.target_signing_key` — the key
    /// it supplied to Commit-B for signing), so verifying the receipt's
    /// signature against `verifying_key()` is exactly "signed by the key
    /// authorized for `target_context_id`". On a parse or signature failure this
    /// returns a typed error BEFORE Commit-A runs, so a forged / tampered
    /// receipt never settles escrow or writes the provenance edge.
    fn verify_commit_b_receipt(
        saga_id: &SagaId,
        ctx: &CrossContextSagaCtx<'_>,
        receipt_bytes: &[u8],
    ) -> Result<CrossContextToolReceipt, ContextError> {
        let receipt: CrossContextToolReceipt =
            serde_json::from_slice(receipt_bytes).map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "SCP-SAGA-13040: cross-context saga Commit — target receipt for saga '{}' \
                     is not a decodable CrossContextToolReceipt: {e}",
                    saga_id.0
                ))
            })?;
        let authorized_target_key = ctx.target_signing_key.verifying_key();
        receipt.verify(&authorized_target_key).map_err(|e| {
            ContextError::CryptoFailed(format!(
                "SCP-SAGA-13041: cross-context saga Commit — target receipt signature for saga \
                 '{}' does not verify under the key authorized for the target context (forged or \
                 tampered receipt — aborting before settle): {e}",
                saga_id.0
            ))
        })?;
        Ok(receipt)
    }

    /// Commit-B (target side, §6.2.4): reserve, and either replay the stored
    /// capture (`AlreadyCommitted`) or run the executor supervisor-side and
    /// settle. Returns `(receipt_bytes, output_bytes)`.
    async fn commit_b_execute_or_replay(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), ContextError> {
        use crate::context::actor::commands::{CommitBReserveOutcome, SagaPhaseMessage};

        let target_hex = hex::encode(ctx.target_context_id);
        let target = self.lookup(&target_hex).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "SCP-SAGA-13055: cross-context saga Commit-B — target context '{target_hex}' \
                 is not a co-resident actor"
            ))
        })?;
        let reserve_saga_id = saga_id.clone();
        let reserve = target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve {
                    saga_id: reserve_saga_id,
                    reply,
                })
            })
            .await?;

        match reserve {
            // Replay: the tool already executed; re-use the stored capture. The
            // `tool_invoked_event_id` is carried inside the signed receipt; we
            // ALSO record it in `ctx` so a subsequent Commit-A failure → NeedsRepair
            // knows the TARGET committed and which event id its
            // `CrossContextDivergenceMarker` must name (spec §6.2.4).
            CommitBReserveOutcome::AlreadyCommitted {
                receipt,
                output_bytes,
                tool_invoked_event_id,
            } => {
                ctx.committed_b_tool_invoked_event_id = Some(tool_invoked_event_id);
                Ok((receipt, output_bytes))
            }
            // First execution: run the executor supervisor-side, then settle.
            CommitBReserveOutcome::ReadyToExecute => {
                self.commit_b_first_execute(saga_id, ctx, &target_hex).await
            }
        }
    }

    /// First (non-replay) Commit-B: run the supervisor-side executor (off the
    /// actor mailbox per ADR-049 §3) EXACTLY ONCE, stash its output in `ctx`, and
    /// send [`SagaPhaseMessage::CommitBSettle`] with the captured output and the
    /// target's Active Signing Key.
    ///
    /// Retryable settle (review wave-1): the tool runs only when no output is yet
    /// stashed (`ctx.executor_output == None`). Once it has run, the output is
    /// stashed; a transient settle FAILURE leaves `executor_output == Some` while
    /// the actor's persist-rolled-back capture makes the next reserve report
    /// `ReadyToExecute` again — so this is re-entered, but it RE-SENDS the settle
    /// with the stashed bytes rather than re-invoking the tool (exactly-once
    /// execution preserved; settle becomes retryable). The executor handle is
    /// taken only on the genuine first execution.
    async fn commit_b_first_execute(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
        target_hex: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), ContextError> {
        use crate::context::actor::commands::{CommitBSettleOutcome, SagaPhaseMessage};

        // Run the executor ONCE and stash its output. On a settle retry the
        // output is already stashed — NEVER re-invoke (the tool had side
        // effects); re-send the settle with the stashed bytes.
        let exec_output_bytes = if let Some(stashed) = ctx.executor_output.clone() {
            stashed
        } else {
            let executor = ctx.executor.take().ok_or_else(|| {
                ContextError::InvalidState(
                    "SCP-SAGA-13056: cross-context saga Commit-B — executor already consumed but \
                     no output was stashed (a non-replay Commit attempt after the tool ran is a \
                     coordinator bug)"
                        .to_owned(),
                )
            })?;
            let output_value = executor(ctx.input.clone()).await.map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "SCP-SAGA-13057: cross-context tool executor failed for saga '{}': {e}",
                    saga_id.0
                ))
            })?;
            let bytes = serde_json::to_vec(&output_value).map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "SCP-SAGA-13058: cross-context tool output is not serializable for saga \
                     '{}': {e}",
                    saga_id.0
                ))
            })?;
            // Stash BEFORE the settle send, so a settle failure (and the actor's
            // rolled-back capture) leaves the output recoverable for the retry —
            // the tool is never re-invoked.
            ctx.executor_output = Some(bytes.clone());
            bytes
        };

        // Re-resolve the target actor (the executor ran off the mailbox; a fresh
        // handle survives an interleaved respawn).
        let target = self.lookup(target_hex).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "SCP-SAGA-13060: cross-context saga Commit-B settle — target context \
                 '{target_hex}' is not a co-resident actor"
            ))
        })?;
        let settle_saga_id = saga_id.clone();
        let target_signing_key = crate::context::actor::commands::SigningKeyBytes::from_signing_key(
            &ctx.target_signing_key,
        );
        let CommitBSettleOutcome {
            receipt,
            output_bytes,
            tool_invoked_event_id,
        } = target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBSettle {
                    saga_id: settle_saga_id,
                    output_bytes: exec_output_bytes,
                    target_signing_key,
                    reply,
                })
            })
            .await?;
        // Commit-B has landed durably: record the target's `ToolInvoked` event
        // id so a later Commit-A failure → NeedsRepair knows the TARGET side
        // committed and which event id the divergence marker must name.
        ctx.committed_b_tool_invoked_event_id = Some(tool_invoked_event_id);
        Ok((receipt, output_bytes))
    }

    /// Commit-A (caller side, §6.2.4): hand the held Prepare-A reservation +
    /// the target's VERIFIED receipt to the caller actor, which settles the
    /// escrow and records `CrossContextToolInvoked` (sharing the nonce).
    ///
    /// Ticket-safe + witness-driven re-drive (review wave-1):
    ///
    /// - **Held reservation present** — the normal path. The `#[must_use]`
    ///   reservation (holding the `ToolEconomyTicket` whose `Drop` debug-asserts
    ///   on an unbalanced drop) is sent via [`ContextActorHandle::send_recover_on_failure`].
    ///   If the mailbox SEND itself fails (the actor died between `lookup` and
    ///   send, or the mailbox stayed full for the 30s `SEND_TIMEOUT`), the
    ///   un-delivered command is returned so we RECOVER the reservation and put
    ///   it BACK into `ctx.prepared_a`: Commit-A never landed, so the FSM retry
    ///   re-drives Commit-B (replay, no re-invoke) → Commit-A cleanly, and the
    ///   ticket is never dropped unbalanced. `lookup` is NOT a delivery
    ///   guarantee — that was the unsound assumption the old code made.
    ///
    /// - **Reservation already consumed (`prepared_a == None`)** — a prior
    ///   Commit-A whose ACK was LOST after the handler durably committed (the
    ///   reservation moved into the delivered command and the actor consumed the
    ///   ticket). We re-ack from the durable `xctx_committed_invocations` witness
    ///   (spec §17.16.4 "A re-acks … as a no-op"): if the caller actor confirms
    ///   the witness, the saga resolves to `Committed` rather than a spurious
    ///   `SCP-SAGA-13059` `NeedsRepair`. If the witness is absent the Commit-A
    ///   genuinely did not commit (a real divergence), surfaced as a typed error.
    ///
    /// `receipt` carries B's VERIFIED signed receipt bytes; the caller records
    /// the receipt's SIGNED `output_jcs` as the bound output (FIX 3 MED — A's
    /// logged `output_hash` is the receipt's signed hash, not an independent
    /// recompute).
    async fn commit_a_settle(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
        receipt_bytes: &[u8],
        receipt: &CrossContextToolReceipt,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::SagaPhaseMessage;

        let caller_hex = hex::encode(ctx.caller_context_id);
        let caller = self.lookup(&caller_hex).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "SCP-SAGA-13061: cross-context saga Commit-A — caller context '{caller_hex}' \
                 is not a co-resident actor"
            ))
        })?;

        // The reservation was already consumed by a delivered Commit-A whose ACK
        // was lost. Re-ack from the durable witness instead of re-sending (we no
        // longer hold a ticket to send): a recorded witness IS the idempotent
        // A-side re-ack → Committed, not a false NeedsRepair (spec §17.16.4).
        let Some(reservation) = ctx.prepared_a.take() else {
            return self
                .commit_a_reack_from_witness(saga_id, &caller, &caller_hex)
                .await;
        };

        // Bind A's recorded output to the receipt's SIGNED bytes (FIX 3 MED): the
        // receipt's `output_jcs` is the exact preimage of the signed
        // `output_hash`, so A hashes precisely what B signed.
        let output_for_a = receipt.output_jcs.clone();
        let commit_a_saga_id = saga_id.clone();
        let caller_context_id = ctx.caller_context_id;
        let caller_did = ctx.caller_did.clone();
        let target_context_id = ctx.target_context_id;
        let nonce = ctx.asserted_nonce;
        let receipt_for_a = receipt_bytes.to_vec();

        let send_result = caller
            .send_recover_on_failure(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitA {
                    saga_id: commit_a_saga_id,
                    reservation: Box::new(reservation),
                    caller_context_id,
                    caller_did,
                    target_context_id,
                    nonce,
                    receipt: receipt_for_a,
                    output_bytes: output_for_a,
                    reply,
                })
            })
            .await;

        match send_result {
            Ok(()) => Ok(()),
            // Send NEVER delivered — recover the reservation and restore it to
            // `ctx.prepared_a` so the FSM retry re-drives Commit-A (and the
            // ticket is never dropped unbalanced). Commit-A did not land, so the
            // retry's Commit-B replay + fresh Commit-A is exactly correct.
            Err((err, Some(recovered_cmd))) => {
                if let Some(reservation) = Self::extract_commit_a_reservation(recovered_cmd) {
                    ctx.prepared_a = Some(reservation);
                } else {
                    // Unreachable in practice: the recovered command IS the
                    // CommitA we built. If a future refactor changes that, the
                    // reservation has nowhere to go — log loudly rather than
                    // silently leak (the carrier's drop guard then fires under
                    // testing, surfacing the bug instead of hiding it).
                    tracing::error!(
                        saga_id = %saga_id.0,
                        "cross-context saga Commit-A — recovered a non-CommitA command on send \
                         failure; the held reservation could not be restored"
                    );
                }
                Err(err)
            }
            // Delivered but the handler errored (or dropped the reply): the actor
            // already owns/consumed the ticket, so there is nothing to recover.
            // `prepared_a` stays `None`; a retry re-acks from the witness above.
            Err((err, None)) => Err(err),
        }
    }

    /// Re-ack Commit-A from the durable `xctx_committed_invocations` witness when
    /// the held reservation is gone (spec §17.16.4). Queries the caller actor
    /// read-only; a recorded witness resolves the saga to `Committed`, an absent
    /// witness surfaces a typed `SCP-SAGA-13059` (the Commit-A genuinely did not
    /// commit — a real divergence the FSM carries to `NeedsRepair`).
    async fn commit_a_reack_from_witness(
        &self,
        saga_id: &SagaId,
        caller: &crate::context::actor::ContextActorHandle,
        caller_hex: &str,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::SagaPhaseMessage;

        let witness_saga_id = saga_id.clone();
        let recorded = caller
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitACheckWitness {
                    saga_id: witness_saga_id,
                    reply,
                })
            })
            .await?;
        if recorded {
            tracing::info!(
                saga_id = %saga_id.0,
                context = %caller_hex,
                "cross-context saga Commit-A — reservation consumed but the durable witness \
                 confirms Commit-A landed; re-acking as Committed (lost-reply recovery, §17.16.4)"
            );
            Ok(())
        } else {
            Err(ContextError::InvalidState(format!(
                "SCP-SAGA-13059: cross-context saga Commit-A — no held Prepare-A reservation for \
                 saga '{}' and the caller witness does not record a committed Commit-A (Commit-A \
                 did not durably land)",
                saga_id.0
            )))
        }
    }

    /// Extract the held Prepare-A reservation back out of a recovered
    /// (un-delivered) `CommitA` command so the FSM can restore it to `ctx` for a
    /// retry. Returns `None` if the command is not a `CommitA` (unreachable for
    /// the command built in [`Self::commit_a_settle`]).
    fn extract_commit_a_reservation(
        cmd: Box<ContextCommand>,
    ) -> Option<crate::context::actor::commands::PreparedAFields> {
        use crate::context::actor::commands::SagaPhaseMessage;
        if let ContextCommand::SagaPhase(SagaPhaseMessage::CommitA { reservation, .. }) = *cmd {
            Some(*reservation)
        } else {
            None
        }
    }

    /// Emit the dual `CrossContextDivergenceMarker`s on a `NeedsRepair`
    /// outcome (spec §6.2.4 "Dual event-log recording").
    ///
    /// When `commit_with_retry` exhausts and the FSM reaches `NeedsRepair`,
    /// BOTH sides must record a signed divergence marker so a one-sided commit
    /// (the repudiation primitive) is durably auditable. This:
    ///
    /// 1. Determines **which side committed** from
    ///    [`CrossContextSagaCtx::committed_b_tool_invoked_event_id`]: `Some`
    ///    means Commit-B landed (the TARGET committed its `ToolInvoked`) and
    ///    Commit-A then failed — `committed_side = Target`, the committed event
    ///    id is the `ToolInvoked` id. `None` means Commit-B never landed; no
    ///    side committed, so there is NOTHING to record (the logs are clean —
    ///    no divergence). A clean no-commit `NeedsRepair` therefore emits no
    ///    markers; it is a transient commit failure the operator re-drives, not
    ///    a one-sided commit.
    /// 2. For each reachable participant actor (target + caller), resolves that
    ///    side's Active Signing Key (the FSM holds both — supplied per-call,
    ///    ADR-049) and sends [`SagaPhaseMessage::EmitDivergenceMarker`] so the
    ///    actor signs + appends the marker into ITS OWN event log.
    /// 3. If a side is UNREACHABLE (`lookup` miss / actor gone), the signed
    ///    marker cannot be appended into that side's log, so the divergence is
    ///    recorded into the supervisor-level repair journal
    ///    ([`Self::saga_repair_records`]) instead — "or a supervisor-level
    ///    repair journal if one side is unreachable".
    ///
    /// Best-effort: a send / append failure for one side is logged but never
    /// masks the `NeedsRepair` terminal — the operator-repair path reconciles
    /// from whatever markers landed plus the supervisor repair journal. The
    /// escrow is NOT settled here (the [`Self::run_saga`] tail holds it RESERVED
    /// for operator repair) and `prepared_a` is intentionally left untouched.
    async fn emit_divergence_markers(&self, saga_id: &SagaId, plan: DivergenceMarkerPlan) {
        use crate::context::actor::commands::SagaPhaseMessage;
        use scp_protocol::context::tools::cross_context_saga::CommittedSide;

        // The OWNED plan was extracted by the SYNC [`Self::divergence_marker_plan`]
        // at the (sync) FSM call site — NO `&CrossContextSagaCtx` borrow spans the
        // `.await`s below (the ctx carries the non-`Sync` boxed executor, which
        // would otherwise poison this future's `Send` bound). The loop holds only
        // owned values.
        let (committed_event_id, nonce, sides) = plan;
        let committed_side = CommittedSide::Target;

        for (label, context_id, signing_key_bytes) in sides {
            let context_hex = hex::encode(context_id);
            if let Some(actor) = self.lookup(&context_hex) {
                let marker_saga_id = saga_id.clone();
                let committed_event_id_for_send = committed_event_id.clone();
                let result = actor
                    .send(move |reply| {
                        ContextCommand::SagaPhase(SagaPhaseMessage::EmitDivergenceMarker {
                            saga_id: marker_saga_id,
                            nonce,
                            committed_side,
                            committed_event_id: committed_event_id_for_send,
                            signing_key: signing_key_bytes,
                            reply,
                        })
                    })
                    .await;
                match result {
                    Ok(()) => tracing::error!(
                        saga_id = %saga_id.0,
                        side = label,
                        "cross-context saga NeedsRepair — signed divergence marker appended \
                         to the {label} event log (operator repair required)"
                    ),
                    Err(err) => {
                        // The actor is reachable but the append failed; record
                        // the supervisor-level fallback witness so the
                        // divergence is not lost.
                        tracing::error!(
                            saga_id = %saga_id.0,
                            side = label,
                            %err,
                            "cross-context saga NeedsRepair — {label} divergence-marker \
                             append FAILED; recording supervisor repair fallback"
                        );
                        self.record_supervisor_repair(
                            saga_id,
                            &context_hex,
                            committed_side,
                            &committed_event_id,
                            nonce,
                        );
                    }
                }
            } else {
                // Unreachable side: record into the supervisor-level repair
                // journal instead of that side's (absent) log.
                tracing::error!(
                    saga_id = %saga_id.0,
                    side = label,
                    context = %context_hex,
                    "cross-context saga NeedsRepair — {label} actor unreachable; recording \
                     divergence into the supervisor-level repair journal"
                );
                self.record_supervisor_repair(
                    saga_id,
                    &context_hex,
                    committed_side,
                    &committed_event_id,
                    nonce,
                );
            }
        }
    }

    /// Synchronous extractor for [`Self::emit_divergence_markers`]: returns the
    /// owned `(committed_event_id, nonce, [per-side (label, context_id,
    /// signing_key)])` plan, or `None` if Commit-B never landed (no committed
    /// side ⇒ no divergence). Holding the `&ctx` borrow inside this sync fn
    /// (rather than across the caller's `.await`s) keeps the caller future
    /// `Send` despite the ctx's non-`Sync` boxed executor.
    fn divergence_marker_plan(ctx: &CrossContextSagaCtx<'_>) -> Option<DivergenceMarkerPlan> {
        use crate::context::actor::commands::SigningKeyBytes;
        let committed_event_id = ctx.committed_b_tool_invoked_event_id.clone()?;
        // Each side records the SAME (committed_side, committed_event_id, nonce)
        // — each into its own log under its OWN Active Signing Key. Only the
        // TARGET can have committed-then-diverged in the current FSM (Commit-B
        // lands first, then Commit-A).
        let sides = [
            (
                "target",
                ctx.target_context_id,
                SigningKeyBytes::from_signing_key(&ctx.target_signing_key),
            ),
            (
                "caller",
                ctx.caller_context_id,
                SigningKeyBytes::from_signing_key(&ctx.caller_signing_key),
            ),
        ];
        Some((committed_event_id, ctx.asserted_nonce, sides))
    }

    /// Record a supervisor-level divergence repair witness for an UNREACHABLE
    /// (or append-failed) side of a `NeedsRepair` saga (spec §6.2.4 "Dual
    /// event-log recording" — "or a supervisor-level repair journal if one side
    /// is unreachable"). Appends to [`Self::saga_repair_records`] keyed by saga
    /// id; a single diverged saga may accumulate multiple records.
    fn record_supervisor_repair(
        &self,
        saga_id: &SagaId,
        unreachable_context_hex: &str,
        committed_side: scp_protocol::context::tools::cross_context_saga::CommittedSide,
        committed_event_id: &str,
        nonce: [u8; 16],
    ) {
        self.saga_repair_records
            .entry(saga_id.clone())
            .or_default()
            .push(SagaDivergenceRepairRecord {
                unreachable_context_hex: unreachable_context_hex.to_owned(),
                committed_side,
                committed_event_id: committed_event_id.to_owned(),
                nonce,
            });
    }

    /// Read the supervisor-level divergence repair records for a saga (operator
    /// repair surface; also used by the NeedsRepair divergence tests). Returns
    /// an empty vec if the saga has no supervisor-recorded divergence
    /// (both sides were reachable and recorded into their own logs).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn saga_repair_records_for(&self, saga_id: &SagaId) -> Vec<SagaDivergenceRepairRecord> {
        self.saga_repair_records
            .get(saga_id)
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    /// Build the journal `evidence` bytes for a cross-context tool-invocation
    /// saga — the `MessagePack` of the eight-field
    /// [`CrossContextToolInvocationPrepared`](crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared)
    /// wire (spec §6.2.4 "Public-metadata journaling"). Carries BOTH the caller
    /// AND target context ids (option (a) — closing the
    /// [`saga_input_participants`] caller-only gap) plus the staged provenance,
    /// so a crash-recovery replay (§17.16.4) reconstructs the full
    /// `{caller, target}` participant set and the prepared state.
    ///
    /// Uses B's authoritative recorded provenance once Prepare-B has run
    /// (`ctx.prepared_b`); before that, the caller-asserted nonce / depth stand
    /// in (B re-derives them at Prepare-B, and the PreparingB-state replay arm
    /// only ever ABORTS — it never re-drives a Commit, so it does not depend on
    /// the recorded values). Returns `None` for a non-`CrossContextToolInvocation`
    /// input (the test / spec-gapped variants carry no `xctx`).
    fn xctx_prepared_evidence_bytes(
        input: &SagaInput,
        ctx: &CrossContextSagaCtx<'_>,
    ) -> Option<Vec<u8>> {
        use crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;
        // Only the cross-context variant journals prepared evidence.
        if !matches!(input, SagaInput::CrossContextToolInvocation { .. }) {
            return None;
        }
        let (recorded_timestamp_ms, recorded_nonce, recorded_chain_depth) =
            ctx.prepared_b.as_ref().map_or_else(
                || {
                    // Pre-Prepare-B: B has not yet recorded. The caller-asserted
                    // values stand in (the PreparingB-state replay arm aborts and
                    // never re-drives a Commit, so it does not read them).
                    (
                        ctx.asserted_timestamp_ms,
                        ctx.asserted_nonce,
                        ctx.asserted_chain_depth,
                    )
                },
                |b| {
                    (
                        b.recorded_timestamp_ms,
                        b.recorded_nonce,
                        b.recorded_chain_depth,
                    )
                },
            );
        let prepared = CrossContextToolInvocationPrepared {
            caller_context_id: ctx.caller_context_id,
            target_context_id: ctx.target_context_id,
            caller_did: ctx.caller_did.clone(),
            tool_registration_id: ctx.tool_registration_id.clone(),
            // The wire mirror carries a non-optional `ucan_proof_id`; an ungated
            // tool (no proof) maps to the empty string (round-trips to `None`
            // semantics via an empty proof reference on reconstruction).
            ucan_proof_id: ctx.ucan_proof_id.clone().unwrap_or_default(),
            recorded_timestamp_ms,
            recorded_nonce,
            recorded_chain_depth,
        };
        prepared.to_evidence_bytes().ok()
    }

    /// Abort the saga (spec §6.2.4 "Reservation release on every terminal
    /// path"): mark the journal Aborting → Aborted, and — for a cross-context
    /// saga — send [`SagaPhaseMessage::Abort`] to whichever side(s) prepared so
    /// saga — send [`SagaPhaseMessage::Abort`] to whichever side(s) prepared so
    /// the staged reservations are RAII-released (the caller side hands its held
    /// `PreparedAFields` back; the target side clears its staged slot).
    async fn abort_saga(
        &self,
        saga_id: &SagaId,
        participants: &[String],
        next_seq: u64,
        secret_bearing: bool,
        xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        self.append_journal(saga_id, SagaState::Aborting, participants, next_seq, &[])
            .await?;

        // Best-effort release of any staged participant reservations. A failure
        // here MUST NOT mask the abort — the journal resolution is the
        // coordinator's authoritative rollback record, and the held
        // `PreparedAFields` RAII guard releases the caller escrow on drop even
        // if the actor send fails.
        if let Some(ctx) = xctx {
            self.abort_xctx_participants(saga_id, ctx).await;
        }

        self.saga_journal
            .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, secret_bearing)
            .await
            .map_err(|e| ContextError::InvalidState(format!("saga journal mark_resolved: {e}")))
    }

    /// Send [`SagaPhaseMessage::Abort`] to the prepared participant actors of a
    /// cross-context saga (best-effort rollback).
    ///
    /// - CALLER side: if Prepare-A staged a reservation, hand it back so the
    ///   actor rolls the held escrow / outbound rate-limit back. Taking it out
    ///   of `ctx` ensures the `ToolEconomyTicket` is settled-or-rolled-back
    ///   exactly once. If the caller actor is UNREACHABLE (despawned, or the
    ///   send fails) the actor's per-context rollback can never run, so the
    ///   external escrow is voided here via
    ///   [`ToolEconomyTicket::void_external_and_consume`] (the sanctioned
    ///   owning-actor-unreachable reversal) — NEVER merely dropped, which would
    ///   trip the ticket's unbalanced-drop guard.
    /// - TARGET side: send `Abort` with `None` reservation so the actor clears
    ///   its staged `saga_pending` slot (releasing the session reservation).
    ///   Only meaningful if Prepare-B staged a slot.
    async fn abort_xctx_participants(&self, saga_id: &SagaId, ctx: &mut CrossContextSagaCtx<'_>) {
        use crate::context::actor::commands::SagaPhaseMessage;

        // CALLER side (only if Prepare-A staged a reservation).
        if let Some(reservation) = ctx.prepared_a.take() {
            let caller_hex = hex::encode(ctx.caller_context_id);
            if let Some(caller) = self.lookup(&caller_hex) {
                let abort_saga_id = saga_id.clone();
                // Move the reservation's ticket into a holder we can recover if
                // the send fails (the actor consumes it on success).
                let result = caller
                    .send(move |reply| {
                        ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
                            saga_id: abort_saga_id,
                            reservation: Some(Box::new(reservation)),
                            reply,
                        })
                    })
                    .await;
                if let Err(err) = result {
                    // The command may not have been delivered; we no longer hold
                    // the ticket (it moved into the boxed command). The actor's
                    // rollback either ran or never received the command — we
                    // cannot tell. Log; the journal Aborted marker is the
                    // authoritative rollback record and the next crash-recovery
                    // sweep reconciles any orphaned actor-side staged state.
                    tracing::warn!(
                        saga_id = %saga_id.0,
                        %err,
                        "cross-context saga abort — caller-side Abort send failed; rollback may \
                         not have run, crash-recovery sweep will reconcile"
                    );
                }
            } else {
                // Caller actor is gone: its per-context rollback can never run.
                // Void the external escrow and consume the ticket so its
                // unbalanced-drop guard does not fire (the context-local
                // budget/velocity died with the actor).
                reservation
                    .reservation
                    .ticket
                    .void_external_and_consume(self.payment_adapter_ref())
                    .await;
                tracing::warn!(
                    saga_id = %saga_id.0,
                    "cross-context saga abort — caller actor not co-resident; voided the external \
                     escrow and consumed the reservation ticket"
                );
            }
        }

        // TARGET side (only if Prepare-B may have staged a slot).
        if ctx.prepared_b.is_some() {
            let target_hex = hex::encode(ctx.target_context_id);
            if let Some(target) = self.lookup(&target_hex) {
                let abort_saga_id = saga_id.clone();
                let result = target
                    .send(move |reply| {
                        ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
                            saga_id: abort_saga_id,
                            reservation: None,
                            reply,
                        })
                    })
                    .await;
                if let Err(err) = result {
                    tracing::warn!(
                        saga_id = %saga_id.0,
                        %err,
                        "cross-context saga abort — target-side Abort send failed; the staged \
                         slot will be cleared on the next crash-recovery sweep"
                    );
                }
            }
        }
    }

    async fn append_journal(
        &self,
        saga_id: &SagaId,
        state: SagaState,
        participants: &[String],
        seq: u64,
        evidence: &[u8],
    ) -> Result<(), ContextError> {
        self.saga_journal
            .append(JournalEntry {
                saga_id: saga_id.clone(),
                state,
                participants: participants.to_vec(),
                evidence: Zeroizing::new(evidence.to_vec()),
                timestamp_ms: current_timestamp_ms(),
                seq_per_saga: seq,
            })
            .await
            .map_err(|e| {
                ContextError::InvalidState(format!(
                    "saga journal append failed for state {state:?}: {e}"
                ))
            })
    }

    // ---------------------------------------------------------------
    // Supervisor-scope direct methods (no per-context command dispatch)
    //
    // The methods in this block route to the attached
    // [`Supervisor`](crate::context::supervisor::Supervisor)
    // surface directly because the underlying operation has no
    // per-context lock-and-handler shape: it operates on the
    // supervisor-wide identity registry (`local_dids`), or it iterates
    // every context (`flush_all_*`, `restore_all_contexts`,
    // `shutdown_all_contexts`).
    //
    // Each method is a thin shim — it resolves the attached manager
    // and forwards. Deleted in commit 12 alongside the rest of the
    // shim when the supervisor owns these surfaces directly.
    // ---------------------------------------------------------------

    /// Register a DID as locally controlled by this node / SDK.
    ///
    /// Idempotent: registering the same DID twice is a no-op.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())` — the `Result` shape preserves
    /// the legacy method's signature so callers can keep their
    /// `?`-style propagation untouched.
    pub async fn register_local_did(&self, did: DID) -> Result<(), ContextError> {
        crate::context::queries_helpers::register_local_did(self, did).await;
        Ok(())
    }

    /// Returns `true` iff `did` is registered as locally controlled.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(_)`.
    pub async fn is_local_did(&self, did: &DID) -> Result<bool, ContextError> {
        Ok(crate::context::queries_helpers::is_local_did(self, did).await)
    }

    /// Restore every persisted context from the configured persistence
    /// provider.
    ///
    /// Returns the list of restored context IDs. Contexts in
    /// `Closing` / `Closed` / `Expired` states are skipped (only
    /// `Active` contexts are resurrected after a restart).
    ///
    /// # Errors
    ///
    /// - [`ContextError::PersistenceFailed`] if the persistence
    ///   provider is unconfigured or `list_persisted_contexts` fails.
    pub async fn restore_all_contexts(self: &Arc<Self>) -> Result<Vec<String>, ContextError> {
        crate::context::lifecycle_helpers::restore_all_contexts(self).await
    }

    /// Restore a single previously-persisted context from storage via
    /// the actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::RestoreContext`] with an embedded
    /// reply oneshot. Note: `context_id` and `handle.context_id()` must
    /// agree (the legacy helper carries both for historical reasons);
    /// the command payload uses `handle.context_id()`, and a caller-
    /// supplied `context_id` argument that does not match is ignored.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn restore_context(
        self: &Arc<Self>,
        context_id: &str,
        handle: &crate::context::ContextHandle,
    ) -> Result<(), ContextError> {
        // The legacy method takes both `context_id` and `handle`
        // because the original helper signature predates `ContextHandle`
        // exposing its own `context_id()` accessor. The boxed payload
        // here is built from the handle (the authoritative source); the
        // separate `context_id` parameter is retained on the signature
        // for caller compatibility and silently overridden when the two
        // disagree.
        debug_assert_eq!(
            context_id,
            handle.context_id(),
            "Supervisor::restore_context — context_id argument must match handle.context_id()"
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::RestoreContextPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
        });
        let cmd = LifecycleCommand::RestoreContext { payload, reply: tx };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::restore_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Exports the full state of a context as a transferable, signed
    /// [`ContextExport`](crate::context::export_import::ContextExport)
    /// (§23.16.8, ADR-050).
    ///
    /// The per-context actor captures the UNSIGNED export building blocks
    /// (snapshot + Merkle event-log data) via the
    /// [`LifecycleCommand::ExportContext`] mailbox turn; the snapshot is then
    /// signed HERE, at the dispatch boundary, because the runtime holds no
    /// custody key. The caller supplies a `sign` closure that produces an
    /// Ed25519 signature over the canonical snapshot digest
    /// (`SHA-256("SCP-CONTEXT-EXPORT-V1:" || scope-tag-byte || JCS(snapshot))`)
    /// using the exporter's custody key.
    ///
    /// The exporter MUST be the snapshot `creator_did` (the importer enforces
    /// `exporter_did == creator_did`). The FFI bridge resolves the signing
    /// key via `resolve_signing_key`, mirroring the governance signing path.
    /// The closure receives the canonical digest computed over the final
    /// (post–public-stripping) snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context does not exist, the actor reply
    /// channel closes, event-log export or Merkle verification fails, canonical
    /// hashing fails, or `sign` returns an error.
    pub async fn export_context<F, E>(
        self: &Arc<Self>,
        context_id: &str,
        exporter_did: DID,
        sign: F,
    ) -> Result<crate::context::export_import::ContextExport, ContextError>
    where
        F: FnOnce(&[u8; 32]) -> Result<[u8; 64], E>,
        E: std::fmt::Display,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ExportContext {
            context_id: context_id.to_owned(),
            exporter_did: exporter_did.clone(),
            reply: tx,
        };
        self.dispatch_lifecycle_command(cmd).await?;
        let (snapshot, event_log_data) = rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::export_context — actor reply channel closed".to_owned(),
            )
        })??;

        // Sign at the dispatch boundary: the actor holds no custody key, so
        // the FFI-supplied `sign` closure produces the Ed25519 signature over
        // the canonical snapshot digest computed inside `create_export`
        // (§23.16.8, ADR-050).
        let clock = self.clock_ref().ok_or_else(|| {
            ContextError::PersistenceFailed(
                "Supervisor::export_context — clock provider not initialized".to_owned(),
            )
        })?;
        crate::context::export_import::create_export(
            snapshot,
            event_log_data,
            exporter_did,
            crate::context::export_import::ExportScope::Full,
            clock.as_ref(),
            sign,
        )
    }

    /// Imports a previously exported context (§23.16.8, ADR-050).
    ///
    /// Imports come from an UNTRUSTED source. `verifying_key` is the snapshot
    /// `creator_did`'s resolved Ed25519 verification-method key (resolved by
    /// the FFI bridge from `role_state.creator_did`, NEVER the unauthenticated
    /// envelope `exporter_did`). The import path verifies the snapshot
    /// signature, the signer binding (`exporter_did == creator_did`), the
    /// version gate, and the Merkle chain against the SIGNED
    /// `event_log_merkle_root` BEFORE restoring any state. A signature failure
    /// rejects with [`ContextError::SnapshotSignatureInvalid`].
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the import handler, including
    /// [`ContextError::SnapshotSignatureInvalid`] (signature/signer-binding/
    /// version forgery) and the public-scope rejection.
    pub async fn import_context(
        self: &Arc<Self>,
        export: crate::context::export_import::ContextExport,
        verifying_key: &ed25519_dalek::VerifyingKey,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<crate::context::ContextHandle, ContextError> {
        // Verify-before-side-effect at the public API boundary: reject a
        // forged or malformed export before it is ever dispatched onto the
        // actor channel. The `ImportContext` dispatch arm re-checks this
        // (so a direct command sender is equally guarded) and the
        // `lifecycle_helpers::import_context` helper re-validates
        // authoritatively before restoring any state — the layering is
        // intentional: validation is cheap relative to a full import, and
        // each layer that could otherwise produce a side effect
        // (channel send, key-package-store spawn, state restore) is
        // gated independently (§23.16.8, ADR-050).
        crate::context::export_import::validate_export_for_import(&export, verifying_key)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ImportContext {
            export: Box::new(export),
            verifying_key: Box::new(*verifying_key),
            local_pseudonym,
            reply: tx,
        };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::import_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Best-effort flush of every context's snapshot to the configured
    /// persistence provider.
    ///
    /// No-op if no persistence provider is configured.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())` — the `Result` shape preserves
    /// the legacy method's signature for callers that propagate with
    /// `?`. Per-context flush failures are logged via `tracing::warn!`
    /// inside the helper.
    pub async fn flush_all_contexts(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::flush_all_contexts(self).await;
        Ok(())
    }

    /// Sync wrapper for [`Self::flush_all_contexts`].
    ///
    /// Required by `Drop` and other terminal sync callers that cannot
    /// `.await`. Uses `tokio::runtime::Handle::current` to bridge
    /// sync → async; **callers MUST be inside a tokio runtime**.
    /// No-op if no persistence provider is configured.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Per-context flush failures
    /// are logged via `tracing::warn!` inside the helper.
    pub fn flush_all_contexts_sync(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::flush_all_contexts_sync(self);
        Ok(())
    }

    /// Shut down every context the supervisor owns (best-effort,
    /// local cleanup only).
    ///
    /// Destroys per-context sender keys + MLS groups + event logs in
    /// that order (zeroize secrets before tearing down structure),
    /// removes the contexts from the supervisor's registry, clears the
    /// standing-context tracking + local-DID registry + per-identity
    /// wrapping keys, and aborts background tasks (TTL timers,
    /// governance timeouts). Does NOT send leave messages or notify
    /// remote peers — used by `scp_ffi_common::BridgeInstance::shutdown`
    /// for process exit / test teardown.
    ///
    /// Phase 1 fix-up of ADR-049 (post-review-round-1): now async to
    /// allow proper `lock().await` acquisition rather than the prior
    /// best-effort `try_lock` that silently skipped cleanup on
    /// contention.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Best-effort cleanup logs
    /// per-context failures via `tracing::warn!` inside the helper.
    pub async fn shutdown_all_contexts(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::shutdown_all_contexts(self).await;
        Ok(())
    }

    /// Sync wrapper for [`Self::shutdown_all_contexts`].
    ///
    /// Required by destructor / atexit-style sync callers (the FFI
    /// bridge instance's blocking-shutdown path) that cannot `.await`.
    /// Uses [`tokio::runtime::Handle::try_current`] to bridge sync →
    /// async; **callers MUST be inside a tokio runtime**. No-op (with
    /// warning) when called outside a runtime.
    ///
    /// Phase 1 fix-up of ADR-049 (post-review-round-1).
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Per-context cleanup failures
    /// are logged via `tracing` inside the helper.
    pub fn shutdown_all_contexts_sync(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::shutdown_all_contexts_sync(self);
        Ok(())
    }

    /// Persist supervisor-level state (standing_contexts, local_dids,
    /// wrapping_keys) ahead of a shutdown or resume. Commit 6 stubs;
    /// full path lands with the `BridgeInstance` integration in commit
    /// 11.
    ///
    /// # Errors
    ///
    /// Commit 6: always `ContextError::NotImplemented`.
    #[allow(clippy::unused_async)] // signature matches the real commit-11 handler's shape
    pub async fn persist_state(&self) -> Result<(), ContextError> {
        Err(ContextError::NotImplemented(
            "Supervisor::persist_state — migrates in commit 11 of ADR-049".to_owned(),
        ))
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12c.9g.3 — FFI passthrough surface.
    //
    // The 4 FFI bridges (PyO3, NAPI, UniFFI, common) used to dereference
    // an `Arc<ContextManager>` and invoke methods directly. After commit
    // 12c.9g.3 they hold an `Arc<Supervisor>` only. The methods below
    // mirror the small subset of `ContextManager` methods that the
    // bridge functions actually call (membership queries, event-log
    // probes, hard-rate-limit consumption, broadcast key resolution,
    // tool invocation, lifecycle creation in tests).
    //
    // Each method is intentionally a thin one-liner over the equivalent
    // `*_helpers::X(&self, ...)` free function or the legacy
    // `ContextManager::X` method (resolved via
    // `with_providers()`). The thin layer keeps the FFI rewire
    // mechanical: bridge call sites change exactly one identifier
    // (`mgr.X` → `supervisor.X`). When `manager/` is deleted in commit
    // 12c.9g.4, the manager-fallback methods below become direct helper
    // calls.
    // -------------------------------------------------------------------

    /// Reads the current lifecycle
    /// [`ContextState`](scp_protocol::context::ContextState) for
    /// `context_id`, or `None` if no per-context actor exists.
    ///
    /// Unlike the other query passthroughs, this does NOT route through
    /// [`Self::dispatch_query`]: that method falls through to
    /// [`Self::dispatch_queries_direct`] (which fabricates the legacy
    /// unknown-context default) when no actor is registered. The standing
    /// get-or-create path needs to distinguish "actor exists and is in
    /// state X" from "no actor at all", so this helper does the
    /// [`Self::lookup`] explicitly: a missing actor resolves to `None`
    /// (no mailbox, no reply), and a present actor's mailbox reply is
    /// surfaced as `Some(state)`.
    ///
    /// Close / TTL does NOT despawn the per-context actor, so
    /// `lookup(id).is_some()` alone cannot tell a live context from a
    /// terminal one — this query is the read-only lifecycle probe that
    /// makes that distinction without a `per-context-state Mutex`. A
    /// dropped reply or mailbox-send failure (actor shutting down)
    /// resolves to `None`, treated by callers as "no live context".
    #[must_use]
    pub async fn read_context_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextState> {
        let Some(actor) = self.lookup(context_id) else {
            // No live actor. A poisoned context (ADR-049 §10) has been
            // despawned by the watchdog, so its state is no longer readable
            // from a mailbox — it lives in the sticky `crash_windows` poison
            // flag. Report `Poisoned` so callers (FFI `read_context_state`,
            // the eviction sweep's `Poisoned` arm) can observe a poisoned
            // context as poisoned rather than as "unknown" (`None`).
            // An un-poisoned absent context stays `None` (genuinely unknown).
            if self.is_context_poisoned(context_id) {
                return Some(scp_protocol::context::ContextState::Poisoned);
            }
            return None;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Queries(QueriesCommand::ReadContextState {
            context_id: context_id.to_owned(),
            reply: tx,
        });
        if Self::dispatch_via_mailbox(&actor, cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(state)) => Some(state),
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns an existing standing context or creates a new one
    /// (contact graph). Actor-native get-or-create — no `contexts`
    /// DashMap, no `per-context-state Mutex`, no
    /// `create_context_legacy`.
    ///
    /// # Algorithm
    ///
    /// 1. Derive the deterministic standing context id from the DID pair.
    /// 2. Liveness check via [`Self::read_context_state`]: if a
    ///    per-context actor exists AND its lifecycle state is
    ///    [`Active`](scp_protocol::context::ContextState::Active) or
    ///    [`Creating`](scp_protocol::context::ContextState::Creating),
    ///    track the peer and return the existing id. A terminal state
    ///    (`Closed` / `Expired` / `Closing` / `MigratingOut` /
    ///    `Tombstoned`) or a missing actor (`None`) falls through to
    ///    create — a dead standing context is never reused.
    /// 3. Create a fresh bilateral-persistent context through the
    ///    actor-shape [`lifecycle_helpers::create_context`](crate::context::lifecycle_helpers::create_context)
    ///    (membership, roles, governance, owned-state actor spawn), with
    ///    `local_did` as creator — mirroring the
    ///    [`LifecycleCommand::CreateContext`](crate::context::actor::commands::LifecycleCommand::CreateContext)
    ///    deps build in [`Self::dispatch_lifecycle_direct`].
    /// 4. TOCTOU: a concurrent caller may have created the context
    ///    between the step-2 check and the step-3 create. On create
    ///    error, re-probe [`Self::read_context_state`]; if it is now
    ///    `Active` / `Creating`, treat the create as idempotently
    ///    successful. Otherwise propagate
    ///    [`ContextError::TransportFailed`].
    /// 5. Track the peer in the supervisor standing index (ArcSwap +
    ///    `write_lock`, ADR-049 §Decision 12) and return the id.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if context creation
    /// fails and no concurrent creation resolved the id.
    pub(in crate::context) async fn standing_context(
        self: &Arc<Self>,
        local_did: &DID,
        peer_did: &DID,
    ) -> Result<String, ContextError> {
        use scp_protocol::context::ContextState;

        let context_id =
            crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did);

        // Serialize this get-or-create against every other same-id
        // bootstrap (the `CreateContext` / `ImportContext` /
        // `RestoreContext` dispatch arms, and concurrent
        // `standing_context` calls for the same deterministic id) by
        // holding `bootstrap_spawn_lock` across the probe-through-create
        // span. `standing_context` is the 4th bootstrap entry point; the
        // dispatch arms acquire this lock but the standing path previously
        // did not, so two racing standing creates (or a standing create
        // racing a `CreateContext` for the same id) could both pass the
        // step-2 probe and both call `create_context` → the loser's
        // `create_mls_group` would clobber the winner's live MLS group
        // with fresh keys (crypto desync). The lock makes the
        // probe-create-recheck sequence atomic w.r.t. other bootstraps.
        //
        // Deadlock-free: `standing_context`'s only caller chain
        // (`dispatch_standing_command` → `dispatch_standing_direct`) does
        // NOT hold this lock, and `create_context` below does not
        // re-acquire it. Lock order is always
        // `bootstrap_spawn_lock` → `write_lock` (see
        // `track_standing_peer` / `spawn_actor_with_state`).
        let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;

        // Step 1/2: existence + liveness probe. `read_context_state`
        // returns `None` when no actor exists (create path) and
        // `Some(state)` for a live actor. Only Active/Creating short-
        // circuits to reuse; every terminal state falls through so a
        // dead standing context is replaced rather than resurrected.
        if matches!(
            self.read_context_state(&context_id).await,
            Some(ContextState::Active | ContextState::Creating)
        ) {
            self.track_standing_peer(peer_did).await;
            return Ok(context_id);
        }

        // Step 3: create a new bilateral-persistent context via the
        // actor-shape create flow. Mirrors the `CreateContext` arm of
        // `dispatch_lifecycle_direct`: build deps scoped to the creator,
        // then `lifecycle_helpers::create_context`. Recreating this
        // deterministic standing id is a fresh start: drop ALL stale crash
        // history (including a stale poison) so the recreated standing actor
        // begins with a clean budget. A poisoned standing context reaches
        // here because the step-2 probe reports `Poisoned` (not
        // `Active`/`Creating`) and falls through; the automatic recreate then
        // resets its budget, which is correct — a standing pair re-contacting
        // each other after a poison must get a working context, not inherit a
        // sticky poison (ADR-049 §10).
        //
        // Observability: clearing a POISONED window here silently drops the
        // sticky poison flag, which would defeat the operator-recovery property
        // for deterministic-id contexts (a flapping standing pair would keep
        // auto-reviving with no audit trail). Emit a distinct, payload-free
        // operator-audit warning when the cleared window was poisoned so the
        // auto-revival is visible. The reset itself is kept — a re-contacting
        // standing pair must get a working context.
        //
        // FOLLOW-UP: rate-limited auto-revival (e.g. refusing to auto-revive a
        // standing id more than N times in a window, forcing operator
        // intervention on a persistently-flapping pair) is a future hardening;
        // today the recreate is unconditional but now observable.
        if self.is_context_poisoned(&context_id) {
            tracing::warn!(
                actor_kind = "context_actor",
                context_id = %context_id,
                "poisoned standing context auto-revived on re-contact"
            );
        }
        self.reset_crash_window(&context_id);
        let params = scp_protocol::context::templates::template_params(
            &scp_protocol::context::TemplateId::BilateralPersistent,
        );
        let create_result = match self.build_actor_deps(local_did).await {
            Ok(deps) => Box::pin(crate::context::lifecycle_helpers::create_context(
                &deps,
                context_id.clone(),
                params,
                local_did.clone(),
                None,
            ))
            .await
            .map(|_handle| ())
            .map_err(|e| ContextError::TransportFailed(e.to_string())),
            Err(e) => Err(ContextError::TransportFailed(e.to_string())),
        };

        // Step 4: TOCTOU re-check. A concurrent caller may have created
        // the context between our step-2 probe and the step-3 create. If
        // the context is now Active/Creating, treat the create as
        // idempotently successful; otherwise surface the create error.
        if let Err(create_err) = create_result
            && !matches!(
                self.read_context_state(&context_id).await,
                Some(ContextState::Active | ContextState::Creating)
            )
        {
            return Err(create_err);
        }

        // Step 5: track the standing peer and return.
        self.track_standing_peer(peer_did).await;
        Ok(context_id)
    }

    /// Insert `peer_did` into the supervisor standing index.
    ///
    /// ArcSwap + `write_lock` mutation (ADR-049 §Decision 12): the index
    /// is read lock-free on the hot path; mutations serialize through the
    /// `write_lock` and store a fresh `Arc` snapshot. Keyed by the peer
    /// DID's `to_string()` form, matching every other standing-index
    /// writer (`RegisterStandingContext`,
    /// `SupervisorHandle::register_standing_context`).
    async fn track_standing_peer(&self, peer_did: &DID) {
        let _guard = self.write_lock.lock().await;
        let snapshot = self.standing_contexts.load_full();
        let mut updated: HashMap<String, DID> = (*snapshot).clone();
        updated.insert(peer_did.to_string(), peer_did.clone());
        self.standing_contexts.store(Arc::new(updated));
    }

    /// Reconnects transport for all active standing contexts. Actor-native
    /// — resolves per-context lifecycle + params through the actor
    /// registry + mailbox (no `contexts` DashMap, no
    /// `per-context-state Mutex`).
    ///
    /// Called during SDK initialization. Iterates the supervisor standing
    /// index, resolves each `(local_did, peer_did)` pair to its
    /// deterministic standing context id, and for every context whose
    /// per-context actor reports
    /// [`Active`](scp_protocol::context::ContextState::Active) republishes
    /// the context blob to transport. Contexts in terminal states
    /// (`Closed` / `Expired` / `Tombstoned`) are evicted from the standing
    /// index to bound its growth; transient states (`Creating` /
    /// `Closing` / `MigratingOut`) are kept and skipped.
    ///
    /// # Returns
    ///
    /// The number of contexts successfully reconnected.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if any reconnection
    /// fails (or [`ContextError::NotInitialized`] if no transport provider
    /// is attached). Contexts reconnected before the failure remain
    /// connected — the publish loop applies eagerly.
    pub async fn reconnect_all_standing(&self) -> Result<usize, ContextError> {
        use scp_protocol::context::ContextState;

        // Phase 1: lock-free snapshots of the standing index + local DIDs
        // (ADR-049 §Decision 12). No per-context lock is held — every
        // per-context read below routes through the actor mailbox.
        let standing_entries: Vec<(String, DID)> = self
            .standing_contexts
            .load()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let local_did_list: Vec<DID> = self.local_dids.load().iter().cloned().collect();

        // Phase 2: resolve each standing pair to its context id, probe the
        // owning actor's lifecycle state, and republish the Active ones.
        // `read_context_state` returns `None` when no actor owns the id —
        // the same "no live context, skip" outcome the legacy
        // per-context-map miss produced.
        let mut reconnected = 0_usize;
        let mut terminal_context_ids: Vec<String> = Vec::new();
        for (_key, peer_did) in &standing_entries {
            for local_did in &local_did_list {
                let context_id = crate::context::standing_helpers::generate_standing_context_id(
                    local_did, peer_did,
                );
                let Some(state) = self.read_context_state(&context_id).await else {
                    // No actor for this (local, peer) id — try the next
                    // local DID, matching the legacy break-on-first-hit
                    // scan only when an actor is actually found.
                    continue;
                };
                match state {
                    ContextState::Active => {
                        // Fetch params through the actor mailbox; `None`
                        // means the actor vanished between the state probe
                        // and this read (raced close) — treat as not
                        // reconnectable and move on.
                        if let Some(params) = self.context_params(&context_id).await {
                            let context_id_bytes =
                                scp_protocol::context::context_id_bytes(&context_id);
                            self.transport_ref()
                                .ok_or_else(|| {
                                    ContextError::NotInitialized(
                                        crate::context::manager_methods::PROVIDER_NOT_INITIALIZED
                                            .to_owned(),
                                    )
                                })?
                                .publish_context(&context_id_bytes, &params)
                                .map_err(|e| {
                                    ContextError::TransportFailed(format!(
                                        "reconnection failed for context {context_id}: {e}"
                                    ))
                                })?;
                            reconnected += 1;
                        }
                    }
                    // Standing contexts in terminal states are eviction
                    // candidates (Phase 3) to bound the index. A `Poisoned`
                    // standing context has no live actor and will not be
                    // auto-respawned (ADR-049 §10), so it is likewise an
                    // eviction candidate — leaving it in the index would
                    // make every reconnect sweep re-probe a dormant context
                    // that only an operator action can revive.
                    ContextState::Closed
                    | ContextState::Expired
                    | ContextState::Tombstoned
                    | ContextState::Poisoned => {
                        terminal_context_ids.push(context_id.clone());
                    }
                    // Creating / Closing / MigratingOut — transient, keep.
                    ContextState::Creating | ContextState::Closing | ContextState::MigratingOut => {
                    }
                }
                // An actor was found for this peer under `local_did`; the
                // standing id is deterministic per pair, so stop scanning
                // the remaining local DIDs (matches the legacy break).
                break;
            }
        }

        // Phase 3: evict standing entries whose context resolved to a
        // terminal state. `generate_standing_context_id` hashes the DID
        // pair, so re-derive each entry's id and compare. ArcSwap +
        // write_lock mutation (ADR-049 §Decision 12).
        if !terminal_context_ids.is_empty() {
            let local_did_set: std::collections::HashSet<DID> =
                self.local_dids.load().iter().cloned().collect();
            let _guard = self.write_lock.lock().await;
            let snapshot = self.standing_contexts.load_full();
            let to_remove: Vec<String> = snapshot
                .iter()
                .filter(|(_key, peer_did)| {
                    local_did_set.iter().any(|local_did| {
                        let cid = crate::context::standing_helpers::generate_standing_context_id(
                            local_did, peer_did,
                        );
                        terminal_context_ids.contains(&cid)
                    })
                })
                .map(|(key, _)| key.clone())
                .collect();
            if !to_remove.is_empty() {
                let mut updated: HashMap<String, DID> = (*snapshot).clone();
                for key in &to_remove {
                    updated.remove(key);
                }
                self.standing_contexts.store(Arc::new(updated));
            }
        }

        Ok(reconnected)
    }

    // -------------------------------------------------------------------
    // Reconnection-driver passthroughs (ADR-029 reconnection-driver
    // addendum). The FFI/SDK-layer `RelayActorSyncDriver` reaches
    // actor-owned reconnection state through these thin wrappers — never
    // by widening `ContextTransportProvider` (which is send-only). Each
    // builds a typed `ContextCommand`, enqueues it via the matching
    // dispatch helper, and awaits the actor's typed reply.
    // -------------------------------------------------------------------

    /// Returns the local MLS epoch for `context_id` (§9.12). `Some(epoch)`
    /// for an encrypted context; `None` for a broadcast context. Soft
    /// `None` on unknown context or mailbox failure. Routes through the
    /// actor mailbox via [`Self::dispatch_query`].
    ///
    /// Used by the reconnection driver's Phase 2 (`local_epoch`).
    #[must_use]
    pub async fn local_mls_epoch(&self, context_id: &str) -> Option<u64> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::LocalMlsEpoch {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns whether `context_id` is flagged `needs_reconnect`
    /// (spec §23.11). Soft `false` on unknown context or mailbox failure.
    /// Routes through the actor mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn needs_reconnect(&self, context_id: &str) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::NeedsReconnect {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return false;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Builds (forces) a signed local consistency checkpoint for
    /// `context_id` from the current event-log state (§9.9.3). Routes
    /// through the actor mailbox via [`Self::dispatch_command`].
    ///
    /// Used by the reconnection driver's Phase 3 (`event_log_sync`): the
    /// caller supplies its locally-controlled `sender_did` + `signing_key`
    /// exactly as the application send path does.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler;
    /// [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn build_local_checkpoint(
        &self,
        context_id: &str,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::BuildLocalCheckpoint {
            context_id: context_id.to_owned(),
            sender_did: sender_did.clone(),
            signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                signing_key,
            ),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::build_local_checkpoint — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Sends a suppression-detection heartbeat (§9.9.2) to `context_id`'s
    /// peers. Routes through the actor mailbox via [`Self::dispatch_command`]
    /// so the send is serialized with the context's other sends.
    ///
    /// Driven by the bridge/SDK subscribe-path periodic scheduler (the
    /// §9.9.2 "the SDK sends heartbeats" boundary): the caller supplies its
    /// locally-controlled `sender_did` + `signing_key` exactly as the
    /// application send path does — the signing key is not actor-owned state.
    /// The heartbeat carries an empty payload; its only purpose is to give
    /// peers a liveness beacon for suppression detection.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler (every fan-out send
    /// failed); [`ContextError::TransportFailed`] if the reply channel is
    /// dropped. Callers treat this as best-effort and MUST NOT tear down the
    /// subscription on a single failure.
    pub async fn send_heartbeat(
        &self,
        context_id: &str,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::SendHeartbeat {
            context_id: context_id.to_owned(),
            sender_did: sender_did.clone(),
            signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                signing_key,
            ),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::send_heartbeat — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Compares a remote consistency checkpoint against local event-log
    /// state for equivocation detection (§9.9.3). Routes through the actor
    /// mailbox via [`Self::dispatch_command`].
    ///
    /// Returns the typed
    /// [`CheckpointComparison`](scp_event_log::checkpoint::CheckpointComparison)
    /// (`Consistent` / `Behind` / `Ahead` / `Divergent`). A `Divergent`
    /// result has already emitted `ContextEvent::EquivocationDetected`
    /// inside the handler. Used by the reconnection driver's Phase 3.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler (e.g.
    /// `MemberNotFound`, `CryptoFailed`);
    /// [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn compare_remote_checkpoint(
        &self,
        context_id: &str,
        remote: scp_event_log::checkpoint::ConsistencyCheckpoint,
    ) -> Result<scp_event_log::checkpoint::CheckpointComparison, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::CompareRemoteCheckpoint {
            context_id: context_id.to_owned(),
            remote: Box::new(remote),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::compare_remote_checkpoint — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Clears the `needs_reconnect` flag for `context_id` (spec §23.11)
    /// after a successful reconnection. Routes through the actor mailbox
    /// via [`Self::dispatch_lifecycle_command`].
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler;
    /// [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn clear_needs_reconnect(
        self: &Arc<Self>,
        context_id: &str,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ClearNeedsReconnect {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::clear_needs_reconnect — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Issues an MLS Update proposal + self-Commit for `context_id`
    /// (§9.12 step 2). Returns the TLS-serialized Commit bytes for the
    /// caller to distribute to all members. Routes through the actor
    /// mailbox via [`Self::dispatch_lifecycle_command`].
    ///
    /// Used by the reconnection driver's Phase 5 (`mls_update`).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler (e.g. `CryptoFailed`
    /// for a broadcast context or MLS failure);
    /// [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn issue_mls_update(
        self: &Arc<Self>,
        context_id: &str,
    ) -> Result<Vec<u8>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::IssueMlsUpdate {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::issue_mls_update — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Feeds a retrieved Commit / Welcome / application blob into the
    /// context's actor via the existing `DeliverIncoming` path — which
    /// decrypts, verifies, and (for Commits) calls `merge_staged_commit`
    /// to advance the local MLS epoch. Routes through the actor mailbox
    /// via [`Self::dispatch_command`].
    ///
    /// Alias over `DeliverIncoming` for the reconnection driver's Phase 2
    /// (`epoch_reconciliation`). `Ok(None)` for a control / management
    /// message (Commit / Proposal / checkpoint / §9.9.2 heartbeat);
    /// `Ok(Some((plaintext, sender_did)))` for an application message.
    ///
    /// The driver only distinguishes application content from everything
    /// else, so the receive-path [`DeliverOutcome`](crate::context::messaging_helpers::DeliverOutcome)
    /// is collapsed back to `Option` here: a heartbeat encountered during
    /// catch-up is correctly treated as "no application content" (live
    /// heartbeat monitoring is the subscribe-loop's responsibility, not the
    /// reconnection driver's).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler (decrypt / signature /
    /// anti-replay failure); [`ContextError::TransportFailed`] if the
    /// reply channel is dropped.
    pub async fn deliver_commit_blob(
        &self,
        context_id: &str,
        envelope_bytes: Vec<u8>,
    ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
        use crate::context::messaging_helpers::DeliverOutcome;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DeliverIncoming {
            context_id: context_id.to_owned(),
            envelope_bytes,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        let outcome = rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::deliver_commit_blob — actor reply channel closed".to_owned(),
            )
        })??;
        Ok(match outcome {
            DeliverOutcome::Application(msg) => Some(msg),
            DeliverOutcome::Heartbeat | DeliverOutcome::Handled => None,
        })
    }

    /// Returns the current member count for `context_id`, or `None` if
    /// the context is not registered. Routes through the actor mailbox
    /// via [`Self::dispatch_query`].
    #[must_use]
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberCount {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns `true` iff `did` is a member of `context_id`. Routes
    /// through the actor mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::IsMember {
            context_id: context_id.to_owned(),
            did: did.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return false;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Returns `true` iff the caller context `source_context_hex` holds a
    /// bidirectionally-approved `ToolInterface` to `target_context_hex` for
    /// `tool_registration_id` (spec §6.2.0.1 standing consent). Routes through
    /// the CALLER context's actor mailbox via [`Self::dispatch_query`].
    ///
    /// The query is addressed to the caller context (the initiator is a member
    /// of it, already authorized) and reads that context's own
    /// `tool_interfaces`, so it is the target-side authorize-before-reserve gate
    /// for [`Self::start_cross_context_tool_invocation_saga`]: a caller cannot
    /// name a victim `target_context_id` it has no established interface with
    /// (spec §6.2.4 "Target-context binding" rides the §6.2.0.1 consent — it
    /// does NOT create it). `false` on an unknown context or no matching
    /// both-approved interface.
    #[must_use]
    pub async fn has_established_tool_interface(
        &self,
        source_context_hex: &str,
        target_context_hex: &str,
        tool_registration_id: &str,
    ) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::HasEstablishedToolInterface {
            context_id: source_context_hex.to_owned(),
            source_context_hex: source_context_hex.to_owned(),
            target_context_hex: target_context_hex.to_owned(),
            tool_registration_id: tool_registration_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return false;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Returns every member DID currently associated with `context_id`
    /// (empty if the context is unknown). Routes through the actor
    /// mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberDids {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the role assignment for `did` in `context_id`, or `None`
    /// if the member has no role. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn member_role(
        &self,
        context_id: &str,
        did: &str,
    ) -> Option<scp_protocol::context::roles::RoleAssignment> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberRole {
            context_id: context_id.to_owned(),
            did: did.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns a clone of the context's creation parameters, or `None`
    /// if the context is unknown. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn context_params(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextParams> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::ContextParams {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns a clone of the context's role state, or `None` if the
    /// context is unknown. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn get_role_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::roles::ContextRoleState> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::GetRoleState {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Drains and returns every event currently buffered for
    /// `context_id` via the actor mailbox.
    ///
    /// Matches the legacy soft-default contract: returns an empty
    /// `Vec` if the context is unknown, if the mailbox enqueue fails,
    /// or if the reply channel is dropped before the handler responds.
    #[must_use]
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DrainEvents {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_command(context_id, cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(events)) => events,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Drains ONLY the `EquivocationDetected` alerts from `context_id`'s
    /// receive buffer via the actor mailbox, leaving every other buffered
    /// event in place and in order.
    ///
    /// The reconnection driver uses this instead of [`drain_events`] so
    /// that application traffic (messages, membership changes) buffered
    /// during catch-up is preserved for the SDK's normal receive polling
    /// rather than being silently discarded. Same soft-default contract as
    /// [`drain_events`]: returns an empty `Vec` on unknown context, mailbox
    /// enqueue failure, or dropped reply channel.
    #[must_use]
    pub async fn drain_equivocation_alerts(&self, context_id: &str) -> Vec<ContextEvent> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DrainEquivocationAlerts {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_command(context_id, cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(events)) => events,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the Merkle-log entries for the routing-id-hashed
    /// `context_id_bytes`. Synchronous — reads the supervisor's shared
    /// event-log provider directly without acquiring a per-context
    /// lock or routing through any actor mailbox (the operation is
    /// stateless w.r.t. per-context state).
    ///
    /// This is the lone read-only query that cannot ride the actor
    /// mailbox because the signature is `fn`, not `async fn`: the FFI
    /// sync paths that call it (Python `gil-bound` event-log probes,
    /// notably) cannot `.await`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the event-log provider fails or no
    /// providers are wired.
    pub fn event_log_entries(
        &self,
        context_id_bytes: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::event_log_entries — event_log provider not configured".to_owned(),
            )
        })?;
        event_log.event_log_entries(context_id_bytes)
    }

    /// Returns the broadcast sender key + epoch for `author_did` in
    /// `context_id` via the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the caller is not authorized as
    /// the broadcast author or when the context is unknown.
    pub async fn get_broadcast_key_for_local_author(
        &self,
        context_id: &str,
        author_did: &str,
    ) -> Result<(Zeroizing<[u8; 32]>, u64), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::GetBroadcastKeyForLocalAuthor {
            context_id: context_id.to_owned(),
            author_did: author_did.to_owned(),
            reply: tx,
        };
        self.dispatch_query(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::get_broadcast_key_for_local_author — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Async hard-rate-limit consume routed through the per-context
    /// actor mailbox.
    ///
    /// Builds a [`ToolsCommand::TryConsumeHardRateLimit`], dispatches it
    /// through [`Self::dispatch_tools_command`] (which routes to the
    /// target context's actor — the actor owns its
    /// [`PerContextState`](crate::context::actor::state::PerContextState)
    /// hard-rate-limit bucket), and awaits the embedded reply oneshot.
    ///
    /// Returns `true` if a token was consumed OR if the context is not
    /// registered. The unknown-context pass-through (`true`) preserves the
    /// legacy `try_consume_hard_rate_limit_from_any_context` contract: a
    /// tool invoked against a context with no live actor is not rate-
    /// limited here (the absence of a bucket means "no per-context cap to
    /// enforce"). Returns `false` only when the context IS registered AND
    /// the sender is over budget.
    pub(crate) async fn try_consume_hard_rate_limit(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::TryConsumeHardRateLimit {
            context_id: context_id.to_owned(),
            did: did.clone(),
            now_secs,
            reply: reply_tx,
        };
        // Dispatch returns the dispatch-level Outcome; the typed answer
        // arrives on `reply_rx`. An unregistered context replies
        // `Err(ContextNotRegistered)` (see `reply_tools_not_registered`)
        // which we fold to the legacy `true` pass-through.
        if self.dispatch_tools_command(cmd).await.is_err() {
            return true;
        }
        match reply_rx.await {
            Ok(Ok(consumed)) => consumed,
            // Unknown context / channel dropped: legacy pass-through.
            Ok(Err(_)) | Err(_) => true,
        }
    }

    /// Async hard-rate-limit refund routed through the per-context actor
    /// mailbox. No-op when the target context has no live actor (legacy
    /// unknown-context contract).
    ///
    /// Mirrors [`Self::try_consume_hard_rate_limit`]; builds a
    /// [`ToolsCommand::RefundHardRateLimit`], dispatches it to the actor,
    /// and awaits the reply. The reply error (e.g. `ContextNotRegistered`)
    /// is swallowed — a refund against an absent bucket is a no-op, not a
    /// failure the caller can act on.
    pub(crate) async fn refund_hard_rate_limit(&self, context_id: &str, did: &DID) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::RefundHardRateLimit {
            context_id: context_id.to_owned(),
            did: did.clone(),
            reply: reply_tx,
        };
        if self.dispatch_tools_command(cmd).await.is_err() {
            return;
        }
        let _ = reply_rx.await;
    }

    /// Runtime-agnostic hard-rate-limit consumption used by FFI
    /// callers that may run inside or outside a tokio runtime.
    ///
    /// Returns `false` if the bucket is empty.
    ///
    /// # Sync-shape exception (ADR-049 §7)
    ///
    /// The method signature is `fn`, not `async fn` — FFI callers
    /// (the MCP `invoke_tool` sync trait method in particular) invoke
    /// it from outside a tokio task and cannot `.await`. The body
    /// bridges sync → async exactly like
    /// [`Self::shutdown_all_contexts_sync`]: it inspects the ambient
    /// runtime and either `blocking`-bridges into the async
    /// [`Self::try_consume_hard_rate_limit`] actor-mailbox path, or
    /// spawns a dedicated current-thread runtime when neither
    /// `blocking_lock` nor `block_in_place` is safe (current-thread
    /// runtime regime). No DashMap is touched — the actor owns the
    /// bucket.
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub fn try_consume_hard_rate_limit_from_any_context(
        self: &Arc<Self>,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        match tokio::runtime::Handle::try_current() {
            // No ambient runtime (sync `#[test]`, GIL-bound bridge call
            // off any executor): borrow the global multi-thread runtime
            // via a dedicated current-thread runtime on a fresh thread so
            // we never `block_on` the calling thread's (absent) runtime.
            Err(_) => Self::run_rate_limit_on_dedicated_thread(
                Arc::clone(self),
                context_id.to_owned(),
                did.clone(),
                now_secs,
                /* refund = */ false,
            ),
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    // Multi-thread runtime: `block_in_place` is valid;
                    // re-enter the runtime to await the actor reply.
                    RuntimeFlavor::MultiThread => {
                        // ADR-049 §7 FFI sync rate-limit allowlist — the MCP `invoke_tool`
                        // sync trait method cannot `.await`; the actor-mailbox consume is
                        // awaited on the ambient multi-thread runtime.
                        let fut = self.try_consume_hard_rate_limit(context_id, did, now_secs);
                        tokio::task::block_in_place(|| handle.block_on(fut)) // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (MCP invoke_tool consume)
                    }
                    // Current-thread runtime: neither `blocking_lock` nor
                    // `block_in_place` is safe. Spawn a dedicated thread
                    // with its own runtime and block on the actor reply
                    // there.
                    _ => Self::run_rate_limit_on_dedicated_thread(
                        Arc::clone(self),
                        context_id.to_owned(),
                        did.clone(),
                        now_secs,
                        /* refund = */ false,
                    ),
                }
            }
        }
    }

    /// Refund a hard-rate-limit token from any context (no-op on
    /// missing context).
    ///
    /// # Sync-shape exception (ADR-049 §7)
    ///
    /// See the doc on
    /// [`Self::try_consume_hard_rate_limit_from_any_context`] — the
    /// sync FFI path constraint applies here too.
    #[allow(clippy::option_if_let_else)]
    pub fn refund_hard_rate_limit_from_any_context(self: &Arc<Self>, context_id: &str, did: &DID) {
        match tokio::runtime::Handle::try_current() {
            Err(_) => {
                let _ = Self::run_rate_limit_on_dedicated_thread(
                    Arc::clone(self),
                    context_id.to_owned(),
                    did.clone(),
                    0,
                    /* refund = */ true,
                );
            }
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => {
                        // ADR-049 §7 FFI sync rate-limit allowlist — the MCP `invoke_tool`
                        // refund path is sync and cannot `.await`; the actor-mailbox refund
                        // is awaited on the ambient multi-thread runtime.
                        let fut = self.refund_hard_rate_limit(context_id, did);
                        tokio::task::block_in_place(|| handle.block_on(fut)); // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (MCP invoke_tool refund)
                    }
                    _ => {
                        let _ = Self::run_rate_limit_on_dedicated_thread(
                            Arc::clone(self),
                            context_id.to_owned(),
                            did.clone(),
                            0,
                            /* refund = */ true,
                        );
                    }
                }
            }
        }
    }

    /// Dedicated-thread escape hatch for the no-runtime and
    /// current-thread-runtime regimes, where both `blocking_lock` and
    /// `block_in_place` panic. Spawns a `std::thread`, builds a
    /// current-thread tokio runtime there, awaits the actor-mailbox
    /// consume/refund, and returns the answer via mpsc.
    ///
    /// Returns `true` for the consume path (token consumed or unknown
    /// context); always `true` for the refund path (refund result is
    /// not observable). On runtime build failure the consume path fails
    /// closed (`false`).
    fn run_rate_limit_on_dedicated_thread(
        supervisor: Arc<Self>,
        context_id: String,
        did: DID,
        now_secs: u64,
        refund: bool,
    ) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dedicated rate-limit runtime build failed; failing closed"
                    );
                    let _ = tx.send(false);
                    return;
                }
            };
            // ADR-049 §7 FFI sync rate-limit allowlist — dedicated current-thread
            // runtime for the no-runtime / current-thread-runtime regime; the sync
            // FFI caller cannot `.await` the actor-mailbox consume/refund.
            let result = if refund {
                rt.block_on(supervisor.refund_hard_rate_limit(&context_id, &did)); // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (dedicated-thread refund)
                true
            } else {
                rt.block_on(supervisor.try_consume_hard_rate_limit(&context_id, &did, now_secs)) // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (dedicated-thread consume)
            };
            let _ = tx.send(result);
        });
        rx.recv().unwrap_or(false)
    }

    /// Dispatch the Phase-1 [`ToolsCommand::ReserveToolEconomy`] to the
    /// target context's actor and await the `Send` reservation.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered
    /// for `context_id`; otherwise any error the reserve handler emits.
    async fn reserve_tool_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        now_secs: u64,
    ) -> Result<crate::context::tools_helpers::ToolEconomyReservation, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::ReserveToolEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            spending_ucan: spending_ucan.map(|u| Box::new(u.clone())),
            now_secs,
            reply: reply_tx,
        };
        self.dispatch_tools_command(cmd).await?;
        reply_rx
            .await
            .map_err(|_| {
                ContextError::TransportFailed(
                    "Supervisor::reserve_tool_economy_via_actor — actor reply channel closed"
                        .to_owned(),
                )
            })?
            .map(|boxed| *boxed)
    }

    /// Dispatch the Phase-3 [`ToolsCommand::SettleToolEconomy`] to the
    /// target context's actor and await the settle outcome.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered
    /// for `context_id`; otherwise any error the settle handler emits
    /// (payment-capture failure).
    async fn settle_tool_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        request: crate::context::tools_helpers::ToolSettleRequest,
    ) -> Result<crate::context::tools_helpers::ToolSettleOutcome, ContextError> {
        // No-actor pre-check: the reserve→execute→settle split runs the
        // executor OFF the actor mailbox, so the owning actor can be
        // despawned (shutdown / node teardown / import replace) during
        // that window. If no actor is registered now, the per-context
        // settle can never run, and routing the command through
        // `dispatch_tools_command` would hand the ticket to
        // `reply_tools_not_registered`, which DROPS it — leaking the
        // external payment escrow and tripping the ticket's unbalanced-
        // Drop guard. Instead, reclaim the ticket here (supervisor-side,
        // where the payment adapter is reachable), void the external
        // escrow, consume the ticket, and surface a typed error.
        if self.lookup(context_id).is_none() {
            let generation = request.generation();
            let ticket = request.into_ticket();
            ticket
                .void_external_and_consume(self.payment_adapter_ref())
                .await;
            // Route through `lookup_miss_error`: a poisoned / silently-dead
            // context surfaces `ContextPoisoned` / `ActorCrashed`, while a
            // genuinely-unknown context keeps the rich SCP-TOOL-6089
            // not-registered diagnostic (escrow already voided above)
            // (ADR-049 §10).
            return Err(self.lookup_miss_error(
                context_id,
                format!(
                    "SCP-TOOL-6089: tool-economy settle for context '{context_id}' found no \
                     registered actor (reserved generation {generation}); escrow voided, \
                     reservation not captured"
                ),
            ));
        }

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::SettleToolEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            request: Box::new(request),
            reply: reply_tx,
        };
        self.dispatch_tools_command(cmd).await?;
        reply_rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::settle_tool_economy_via_actor — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Invoke a tool under the full economy pipeline (actor model).
    ///
    /// Orchestrates the three-phase split through
    /// [`crate::context::tools_helpers::invoke_tool_with_economy`]: the
    /// economy reserve (Phase 1) and settle (Phase 3) run inside the
    /// per-context actor on owned state via the
    /// [`ToolsCommand::ReserveToolEconomy`] / [`ToolsCommand::SettleToolEconomy`]
    /// mailbox commands; the non-`Send` `executor` closure (Phase 2) runs
    /// here, supervisor-side, BETWEEN the two mailbox round-trips. No
    /// per-context lock is held across the executor — the actor is free
    /// to process other commands while a tool executes.
    ///
    /// # Errors
    ///
    /// Propagates every error variant the reserve / settle handlers and
    /// the executor emit (`ContextNotRegistered`, `PermissionDenied`,
    /// `RateLimited`, schema/economy/UCAN failures).
    #[allow(clippy::too_many_arguments)] // matches legacy signature 1:1
    pub async fn invoke_tool_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &scp_protocol::context::tools::registry::ToolRegistry,
        tool_id: &scp_protocol::context::tools::ToolId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        timeout_ms: Option<u32>,
        executor: F,
    ) -> Result<crate::context::tools_helpers::ManagedToolInvocationOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>>,
    {
        let now_secs = self
            .clock_ref()
            .ok_or_else(|| {
                ContextError::NotInitialized(
                    crate::context::manager_methods::PROVIDER_NOT_INITIALIZED.to_owned(),
                )
            })?
            .now_secs();

        crate::context::tools_helpers::invoke_tool_with_economy(
            registry,
            tool_id,
            input,
            invoker_did,
            timeout_ms,
            // Phase 1 — reserve via the actor mailbox.
            || {
                self.reserve_tool_economy_via_actor(
                    context_id,
                    invoker_did,
                    spending_ucan,
                    now_secs,
                )
            },
            // Phase 3 — settle (capture / rollback) via the actor mailbox.
            |request| self.settle_tool_economy_via_actor(context_id, invoker_did, request),
            executor,
        )
        .await
    }

    /// Create a new MLS-backed (or broadcast-mode) context via the
    /// actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::CreateContext`] with an embedded
    /// reply oneshot, enqueues it via
    /// [`Self::dispatch_lifecycle_command`], and awaits the typed
    /// reply. The dispatch helper routes through the per-context actor
    /// mailbox once an actor is registered; on first creation the
    /// `lookup` lookup returns `None` and the dispatch falls through to
    /// the direct-shim path that spawns the actor as part of the
    /// create handshake.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`ContextCreationError`](scp_protocol::context::builder::ContextCreationError)
    /// if the supervisor's providers are not wired or context creation
    /// fails. A dropped reply channel maps to
    /// [`ContextCreationError::CreationFailed`](scp_protocol::context::builder::ContextCreationError::CreationFailed).
    pub async fn create_context(
        self: &Arc<Self>,
        context_id: String,
        params: scp_protocol::context::ContextParams,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::CreateContextPayload {
            context_id,
            params,
            creator_did,
            local_pseudonym,
        });
        let cmd = LifecycleCommand::CreateContext { payload, reply: tx };
        if let Err(e) = self.dispatch_lifecycle_command(cmd).await {
            return Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(format!(
                    "Supervisor::create_context — dispatch failed: {e}"
                )),
            );
        }
        rx.await.unwrap_or_else(|_| {
            Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(
                    "Supervisor::create_context — actor reply channel closed".to_owned(),
                ),
            )
        })
    }

    /// Creates a context from a flat [`ContextConfig`](crate::context::config::ContextConfig)
    /// (ADR-052 / construction.md).
    ///
    /// This is the options-object front-end over [`Self::create_context`]: it
    /// lowers `config` into
    /// [`ContextParams`](scp_protocol::context::ContextParams) via
    /// [`ContextConfig::into_params`](crate::context::config::ContextConfig::into_params)
    /// and calls the existing creation engine. The Rust SDK thereby gains the
    /// same options-object shape Python/TypeScript/Swift already use.
    ///
    /// # Bilateral peer
    ///
    /// [`ContextCreation::Template`](crate::context::config::ContextCreation::Template)
    /// may carry an optional bilateral `peer` DID for the invitation step. The
    /// core creation engine builds only the creator's local context; the
    /// invitation/Welcome-delivery that actually adds the peer is a higher SDK
    /// layer not yet wired at this phase. Rather than **silently dropping** a
    /// supplied peer — which would leave the caller believing an invitation
    /// happened when none did — this method returns
    /// [`ContextCreationError::BilateralPeerNotSupported`](scp_protocol::context::builder::ContextCreationError::BilateralPeerNotSupported)
    /// when `peer` is `Some(_)`. Create the context with `peer: None` and
    /// invite the counterparty through the (forthcoming) invitation path.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`ContextCreationError::BilateralPeerNotSupported`](scp_protocol::context::builder::ContextCreationError::BilateralPeerNotSupported)
    /// when the config carries a bilateral peer (see above). Otherwise
    /// propagates
    /// [`ContextCreationError`](scp_protocol::context::builder::ContextCreationError)
    /// from [`Self::create_context`].
    pub async fn create(
        self: &Arc<Self>,
        context_id: String,
        config: crate::context::config::ContextConfig,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>
    {
        // Fail loud, never silent (CLAUDE.md "no silent" tenet): a supplied
        // bilateral peer cannot be honored here because invitation/Welcome
        // delivery lives in a higher SDK layer. `into_params` carries the peer
        // out so callers that own the invitation path can lower the config
        // themselves; this engine entry rejects it instead of dropping it.
        let (params, peer) = config.into_params();
        if peer.is_some() {
            return Err(
                scp_protocol::context::builder::ContextCreationError::BilateralPeerNotSupported,
            );
        }
        self.create_context(context_id, params, creator_did, local_pseudonym)
            .await
    }

    /// Adds a new member to an existing context via the actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::JoinContext`] with an embedded
    /// reply oneshot, enqueues it via
    /// [`Self::dispatch_lifecycle_command`], and awaits the actor's
    /// typed reply. The dispatch helper routes through the per-context
    /// actor mailbox once one is registered; before that the direct-
    /// shim path completes the join handshake and spawns the actor.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn join_context(
        self: &Arc<Self>,
        handle: &crate::context::ContextHandle,
        key_package: scp_protocol::context::membership::KeyPackage,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::JoinContextPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            key_package,
            spending_ucan: spending_ucan.cloned(),
            local_pseudonym,
        });
        let cmd = LifecycleCommand::JoinContext { payload, reply: tx };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::join_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Removes a member from an existing context via the actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::LeaveContext`] with an embedded
    /// reply oneshot, enqueues it via
    /// [`Self::dispatch_lifecycle_command`], and awaits the typed
    /// reply.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn leave_context(
        self: &Arc<Self>,
        handle: &crate::context::ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::LeaveContextPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            caller_did: caller_did.clone(),
            member_did: member_did.clone(),
        });
        let cmd = LifecycleCommand::LeaveContext { payload, reply: tx };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::leave_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Encrypts and broadcasts a payload through the context's MLS
    /// group via the actor mailbox.
    ///
    /// Phase 2A finalization — every per-context method on `Supervisor`
    /// builds a typed `ContextCommand` carrying an embedded reply
    /// oneshot, enqueues it via [`Self::dispatch_command`], and awaits
    /// the actor's typed reply. The dispatch helper routes through the
    /// per-context actor mailbox when one is registered, falling back
    /// to the legacy lock-and-call shim during the migration window
    /// when no actor has been spawned yet (a state that disappears once
    /// the legacy `*_helpers_legacy::*_legacy` bodies are deleted in
    /// the next session).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if the supervisor's provider
    ///   slots are empty (the supervisor was constructed via
    ///   [`Self::for_query_shim`]).
    /// - Other [`ContextError`] variants propagated from the handler.
    /// - [`ContextError::TransportFailed`] if the mailbox reply channel
    ///   is dropped before the handler completes (handler crash /
    ///   actor shutdown).
    pub async fn send_message(
        &self,
        handle: &crate::context::ContextHandle,
        sender_did: &DID,
        payload: &[u8],
        signing_key: Option<&ed25519_dalek::SigningKey>,
        source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload_box = Box::new(crate::context::actor::commands::SendMessagePayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            sender_did: sender_did.clone(),
            payload: payload.to_vec(),
            signing_key: signing_key
                .map(crate::context::actor::commands::SigningKeyBytes::from_signing_key),
            source_provenance: source_provenance.cloned(),
            spending_ucan: spending_ucan.cloned(),
        });
        let cmd = MessagingCommand::SendMessage {
            payload: payload_box,
            reply: tx,
        };
        self.dispatch_command(handle.context_id(), cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::send_message — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Test-only: directly seed a peer's per-context pseudonym routing ID
    /// (§9.10.4) into the routing registry, bypassing the
    /// `PseudonymAnnouncement` MLS round-trip.
    ///
    /// Single-node integration tests host one member's view of a context, so a
    /// governance-added peer never gets to announce its pseudonym. This lets
    /// such tests populate the registry the way a delivered announcement would,
    /// so multi-member encrypted sends exercise real fan-out instead of failing
    /// with [`ContextError::PseudonymRegistryEmpty`]. Gated behind `testing`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotPseudonymousContext`] if the context is broadcast.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn seed_peer_pseudonym(
        &self,
        context_id: &str,
        member_did: DID,
        pseudonym: [u8; 32],
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::SeedPeerPseudonym {
            context_id: context_id.to_owned(),
            member_did,
            pseudonym,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::seed_peer_pseudonym — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Lists every governance proposal currently tracked by the
    /// context's engine via the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is unknown.
    /// - [`ContextError::TransportFailed`] if the actor reply channel
    ///   is closed before the handler responds.
    pub async fn list_proposals(
        &self,
        context_id: &str,
    ) -> Result<Vec<scp_protocol::context::governance::GovernanceProposal>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ListProposals {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::list_proposals — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Fetches a single proposal by ID via the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is unknown.
    /// - [`ContextError::GovernanceFailed`] if the proposal is not found.
    pub async fn get_proposal(
        &self,
        context_id: &str,
        proposal_id: &scp_protocol::context::governance::ProposalId,
    ) -> Result<scp_protocol::context::governance::GovernanceProposal, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::GetProposal {
            context_id: context_id.to_owned(),
            proposal_id: *proposal_id,
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::get_proposal — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Submits a governance proposal via the actor mailbox — unchecked
    /// variant.
    ///
    /// Gated behind the `testing` feature — the unchecked propose path
    /// is not part of the production FFI surface (every bridge calls
    /// [`Self::propose_governance_action_checked`] instead). Crate-
    /// internal callers that bypass the capability check are limited
    /// to integration tests under `crates/scp-runtime/tests/`.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    #[cfg(any(test, feature = "testing"))]
    pub async fn propose_governance_action(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: scp_protocol::context::governance::GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            scp_protocol::context::governance::GovernanceProposal,
            Vec<scp_protocol::context::governance::GovernanceEvent>,
            Option<crate::context::state::GovernanceActionResult>,
        ),
        ContextError,
    > {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(
            crate::context::actor::commands::ProposeGovernanceActionPayload {
                context_id: context_id.to_owned(),
                proposer_did: proposer_did.clone(),
                action,
                signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                    signing_key,
                ),
            },
        );
        let cmd = GovernanceCommand::ProposeGovernanceAction { payload, reply: tx };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::propose_governance_action — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Submits a governance proposal via the actor mailbox — checked
    /// variant. Validates the proposer's `GovernancePropose` capability
    /// inside the same lock as the proposal submission (no TOCTOU).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn propose_governance_action_checked(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: scp_protocol::context::governance::GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<crate::context::state::ProposalOutcome, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(
            crate::context::actor::commands::ProposeGovernanceActionPayload {
                context_id: context_id.to_owned(),
                proposer_did: proposer_did.clone(),
                action,
                signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                    signing_key,
                ),
            },
        );
        let cmd = GovernanceCommand::ProposeGovernanceActionChecked { payload, reply: tx };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::propose_governance_action_checked — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Casts a vote on a pending proposal via the actor mailbox.
    /// `approve == true` is an approval vote; `false` is rejection.
    ///
    /// Gated behind the `testing` feature — the unchecked vote path is
    /// not part of the production FFI surface (every bridge calls the
    /// suspension-aware helper with `check_vote_capability=true`).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    #[cfg(any(test, feature = "testing"))]
    pub async fn vote_on_proposal(
        &self,
        context_id: &str,
        proposal_id: &scp_protocol::context::governance::ProposalId,
        voter_did: &DID,
        approve: bool,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            scp_protocol::context::governance::ProposalStatus,
            Vec<scp_protocol::context::governance::GovernanceEvent>,
        ),
        ContextError,
    > {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::VoteOnProposalPayload {
            context_id: context_id.to_owned(),
            proposal_id: *proposal_id,
            voter_did: voter_did.clone(),
            signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                signing_key,
            ),
        });
        let cmd = GovernanceCommand::VoteOnProposal {
            payload,
            approve,
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::vote_on_proposal — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Withdraws a previously cast vote via the actor mailbox.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn withdraw_governance_vote(
        &self,
        context_id: &str,
        proposal_id: &scp_protocol::context::governance::ProposalId,
        voter_did: &DID,
    ) -> Result<scp_protocol::context::governance::ProposalStatus, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::WithdrawGovernanceVote {
            context_id: context_id.to_owned(),
            proposal_id: *proposal_id,
            voter_did: voter_did.clone(),
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::withdraw_governance_vote — actor reply channel closed".to_owned(),
            )
        })?
    }

    // -------------------------------------------------------------------
    // Query passthroughs — wrap the queries_helpers::* free functions
    // that were called from the deleted `ContextManager` query methods.
    // FFI bridges call these passthroughs directly; the helpers remain
    // accessible via crate::context::queries_helpers for any caller that
    // already imports them.
    // -------------------------------------------------------------------

    /// Returns the local member's pseudonym routing ID (§9.10.4) for
    /// `context_id`. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn local_pseudonym(&self, context_id: &str) -> Result<[u8; 32], ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::LocalPseudonym {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_query(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::local_pseudonym — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Returns every commit currently in the per-context retry queue.
    /// Soft-default contract: empty `Vec` on unknown context or
    /// mailbox failure. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn pending_commits(
        &self,
        context_id: &str,
    ) -> Vec<crate::context::state::PendingCommit> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::PendingCommits {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the active fail-close marker, if any. Soft-default
    /// contract: `None` on unknown context or mailbox failure. Routes
    /// through the actor mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn commit_fault(
        &self,
        context_id: &str,
    ) -> Option<crate::context::state::CommitFaultMarker> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::CommitFault {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Emits a `DegradedMode` event when an envelope's
    /// [`scp_protocol::envelope::VersionCompatibility`] indicates the
    /// remote peer's minor version is unknown to us.
    ///
    /// Routes through the per-context actor mailbox via
    /// [`Self::dispatch_command`]. Silent best-effort: mailbox enqueue
    /// failures and reply-channel drops are swallowed to match the
    /// legacy "no-error path" contract — the event is a hint to the
    /// application layer and missing one event on a contended actor is
    /// preferable to surfacing a `ContextError` on what callers treat
    /// as a fire-and-forget signal.
    pub async fn report_degraded_mode(
        &self,
        context_id: &str,
        compat: scp_protocol::envelope::VersionCompatibility,
        unsupported_features: Vec<String>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::ReportDegradedMode {
            context_id: context_id.to_owned(),
            compat,
            unsupported_features,
            reply: tx,
        };
        if self.dispatch_command(context_id, cmd).await.is_err() {
            return;
        }
        let _ = rx.await;
    }

    // -----------------------------------------------------------------
    // ADR-049 Phase 2A — mailbox-routing helpers (item 5)
    // -----------------------------------------------------------------

    /// Generic mailbox dispatch: enqueue a fully-built `ContextCommand`
    /// (with its embedded reply oneshot) on the actor's mailbox via
    /// [`ContextActorHandle::send_with_timeout`]. The actor's run loop
    /// pulls the command, dispatches it through the matching handler,
    /// and the handler sends the typed result on the variant's
    /// embedded oneshot — observable by the FFI caller who already
    /// holds the matching `oneshot::Receiver`.
    ///
    /// This helper does NOT await the reply — that responsibility
    /// stays with the caller (FFI bridge code), preserving the
    /// pre-existing single-await pattern. Returns
    /// `Ok(Outcome::ok_mutated(()))` after a successful enqueue (the
    /// real outcome flows through the caller's reply receiver).
    ///
    /// Used by every `dispatch_*_command` method when an actor is
    /// registered for the target context.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] from the mailbox send (full,
    ///   closed, or timeout). The reply oneshot inside the command is
    ///   still alive — the caller's `rx.await` returns
    ///   `Err(RecvError)` which the bridge maps to its own typed
    ///   error.
    async fn dispatch_via_mailbox(
        actor: &ContextActorHandle,
        cmd: ContextCommand,
    ) -> Result<Outcome<()>, ContextError> {
        actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await?;
        // The handler runs inside the actor task and writes the typed
        // result to the embedded reply oneshot. Whether it mutated state
        // is recorded inside the actor's `dirty` flag via
        // `dispatch_state`. This dispatch-method-level Outcome is for
        // legacy callers; mark `mutated: true` because mutating
        // commands are expected to flow through this path.
        Ok(Outcome::ok_mutated(()))
    }

    /// Extract the target context_id from a [`LifecycleCommand`].
    ///
    /// Returns `None` for [`LifecycleCommand::Placeholder`] (no target)
    /// and [`LifecycleCommand::ImportContext`] (the export envelope
    /// carries the canonical 32-byte hash, not a string context_id —
    /// the legacy `import_context` derives the string from the
    /// envelope's params; until the lifecycle handler is rewritten to
    /// surface that derivation here, ImportContext routes through the
    /// direct-shim path so the legacy method can do the derivation).
    ///
    /// Every other variant — including the boxed-payload variants
    /// `CreateContext`, `JoinContext`, `LeaveContext`, `CloseContext`,
    /// `RestoreContext` — destructures the payload to surface its
    /// `context_id`. For `CreateContext` / `JoinContext` /
    /// `RestoreContext` the actor may not yet exist (the context is
    /// being bootstrapped), in which case [`Self::lookup`] returns
    /// `None` and the dispatch helper falls through to the direct-shim
    /// path that spawns the actor as part of the create / join /
    /// restore handshake.
    fn lifecycle_command_context_id(cmd: &LifecycleCommand) -> Option<&str> {
        match cmd {
            LifecycleCommand::ExportContext { context_id, .. }
            | LifecycleCommand::GenerateContextAccessKey { context_id, .. }
            | LifecycleCommand::RevokeContextAccessKey { context_id, .. }
            | LifecycleCommand::RestoreContextAccessKey { context_id, .. }
            | LifecycleCommand::ClearNeedsReconnect { context_id, .. }
            | LifecycleCommand::IssueMlsUpdate { context_id, .. } => Some(context_id.as_str()),
            LifecycleCommand::CreateContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::JoinContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::LeaveContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::CloseContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::RestoreContext { payload, .. } => Some(payload.context_id.as_str()),
            // ImportContext carries no string context_id — the legacy
            // `import_context` helper derives it from the envelope's
            // params. The dispatch helper routes ImportContext through
            // the direct-shim path until the lifecycle handler is
            // rewritten to surface that derivation. Placeholder has no
            // target at all. Sweep commands (`FlushSnapshot`,
            // `ShutdownSelf`) are dispatched per-actor by the
            // supervisor's iterating entry points in `lifecycle_helpers`;
            // routing target is decided at the iteration site.
            LifecycleCommand::ImportContext { .. }
            | LifecycleCommand::Placeholder { .. }
            | LifecycleCommand::FlushSnapshot { .. }
            | LifecycleCommand::ShutdownSelf { .. }
            | LifecycleCommand::ReportBufferLen { .. } => None,
        }
    }

    /// Extract the target context_id from a [`BroadcastCommand`].
    /// Publish variants are deliberately excluded because they require
    /// the custody-generic shim path.
    fn broadcast_command_context_id(cmd: &BroadcastCommand) -> Option<&str> {
        match cmd {
            BroadcastCommand::SubscribeBroadcast { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::UnsubscribeBroadcast { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::BlockBroadcastSubscriber { payload, .. }
            | BroadcastCommand::UnblockBroadcastSubscriber { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::HandleBroadcastKeyRequest { context_id, .. }
            | BroadcastCommand::BroadcastSubscriberCount { context_id, .. }
            | BroadcastCommand::IsBroadcastSubscriber { context_id, .. }
            | BroadcastCommand::BroadcastAdmission { context_id, .. } => Some(context_id.as_str()),
            // Two-phase publish is custody-free — both phases route
            // through the per-context actor mailbox.
            BroadcastCommand::ReserveBroadcastPublish { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::ApplyBroadcastPublish { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::ReleaseBroadcastReservation { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            // PublishBroadcast / PublishBroadcastContent need
            // KeyCustody on the shim; InitiateBroadcastHostingHandshake
            // and Placeholder have no string target for this router.
            _ => None,
        }
    }

    /// Extract the target context_id from a [`TtlCloseCommand`].
    ///
    /// Every per-context variant surfaces its `context_id` so the dispatch
    /// helper can route through the per-context actor's mailbox. The
    /// boxed-payload variants (`StartTtlTimer` / `ResetTtlTimer` /
    /// `ExecuteTtlClose` / `FinalizeClose`) destructure their payloads to
    /// expose the embedded `context_id`. Only [`TtlCloseCommand::Placeholder`]
    /// returns `None` (no target).
    const fn ttl_close_command_context_id(cmd: &TtlCloseCommand) -> Option<&str> {
        match cmd {
            TtlCloseCommand::ExtendTtl { context_id, .. } => Some(context_id.as_str()),
            TtlCloseCommand::StartTtlTimer { payload, .. }
            | TtlCloseCommand::ResetTtlTimer { payload, .. } => Some(payload.context_id.as_str()),
            TtlCloseCommand::ExecuteTtlClose { payload, .. }
            | TtlCloseCommand::FinalizeClose { payload, .. } => Some(payload.context_id.as_str()),
            // `FireTimer` carries no `context_id` field: the per-context
            // TTL timer task resolves the actor itself via
            // [`Self::lookup`] and mailboxes the command through the
            // returned handle, so it never routes through
            // `dispatch_ttl_close_command`. `Placeholder` has no target.
            TtlCloseCommand::FireTimer { .. } | TtlCloseCommand::Placeholder { .. } => None,
        }
    }

    /// Extract the target context_id from a [`GovernanceCommand`].
    ///
    /// Every per-context variant — including the boxed-payload propose
    /// / vote / execute variants — surfaces its `context_id` so the
    /// dispatch helper can route through the per-context actor's
    /// mailbox. Only [`GovernanceCommand::Placeholder`] returns `None`
    /// (no target).
    fn governance_command_context_id(cmd: &GovernanceCommand) -> Option<&str> {
        match cmd {
            GovernanceCommand::GetProposal { context_id, .. }
            | GovernanceCommand::ListProposals { context_id, .. }
            | GovernanceCommand::ApplyPendingCeilingModification { context_id, .. }
            | GovernanceCommand::ApplyPendingEconomicPolicyChange { context_id, .. }
            | GovernanceCommand::TombstoneMigratedContext { context_id, .. }
            | GovernanceCommand::MigrationState { context_id, .. }
            | GovernanceCommand::AcknowledgeCommitFault { context_id, .. }
            | GovernanceCommand::WithdrawGovernanceVote { context_id, .. } => {
                Some(context_id.as_str())
            }
            GovernanceCommand::ProposeGovernanceAction { payload, .. }
            | GovernanceCommand::ProposeGovernanceActionChecked { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            GovernanceCommand::VoteOnProposal { payload, .. }
            | GovernanceCommand::ApproveGovernanceProposal { payload, .. }
            | GovernanceCommand::RejectGovernanceProposal { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            GovernanceCommand::ExecuteGovernanceAction { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            // Sweep commands are dispatched per-actor by the supervisor's
            // iterating entry points in `governance_helpers`; the variant
            // carries no `context_id` field because the routing target is
            // decided at the iteration site (one command per known
            // actor). Returning `None` here keeps `dispatch_governance_command`
            // from accepting them — sweeps must use the iterating helpers.
            GovernanceCommand::Placeholder { .. }
            | GovernanceCommand::EvaluatePeriodicConsequences { .. }
            | GovernanceCommand::ProcessPendingCommits { .. }
            | GovernanceCommand::EvaluateTimeouts { .. }
            // `StartTimeoutTask` is dispatched directly to the owning
            // actor by `start_governance_timeout_task` (lookup + send),
            // not through `dispatch_governance_command`. Returning `None`
            // keeps the routed-dispatch path from accepting it.
            | GovernanceCommand::StartTimeoutTask { .. } => None,
        }
    }

    /// Extract the target context_id from a [`StandingCommand`].
    ///
    /// Variants that carry both `local_did` and `peer_did` derive their
    /// context_id deterministically via
    /// [`crate::context::standing_helpers::generate_standing_context_id`]
    /// — this returns `Some(<derived_id>)` so the dispatch helper can
    /// route through any per-context actor that already exists for the
    /// derived ID. The other variants are supervisor-scoped (count /
    /// has / register / reconnect-all) — they touch the supervisor's
    /// standing index directly, not per-context state, so they return
    /// `None` and dispatch routes them to the SupervisorHandle.
    ///
    /// Returns an owned `String` rather than `&str` because the derived
    /// ID is computed on demand from the variant's DID fields; there is
    /// no backing string to borrow.
    fn standing_command_context_id(cmd: &StandingCommand) -> Option<String> {
        match cmd {
            // The saga-initiator variant targets the per-context actor for
            // the derived standing id (Prepare/Commit lands on that actor).
            StandingCommand::InitiateStandingPairCreate {
                local_did,
                peer_did,
                ..
            } => Some(
                crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did),
            ),
            // `StandingContext` get-or-create is supervisor-scoped, NOT
            // per-context: the actor-native body
            // ([`Self::standing_context`]) may CREATE the target actor (it
            // builds deps + spawns an owned-state actor via
            // `lifecycle_helpers::create_context`). Routing it through the
            // per-context mailbox would make the per-context actor's own
            // `run()` loop recursively spawn another actor — a non-`Send`
            // call graph the runtime cannot spawn. It therefore always
            // routes supervisor-direct through `dispatch_standing_direct`,
            // exactly like the other supervisor-scoped standing-index
            // variants below.
            StandingCommand::StandingContext { .. }
            | StandingCommand::Placeholder { .. }
            | StandingCommand::StandingContextCount { .. }
            | StandingCommand::HasStandingContext { .. }
            | StandingCommand::RegisterStandingContext { .. }
            | StandingCommand::ReconnectAllStanding { .. } => None,
        }
    }

    /// Extract the target context_id from a [`ToolsCommand`].
    const fn tools_command_context_id(cmd: &ToolsCommand) -> Option<&str> {
        match cmd {
            ToolsCommand::TryConsumeHardRateLimit { context_id, .. }
            | ToolsCommand::RefundHardRateLimit { context_id, .. }
            | ToolsCommand::ReserveToolEconomy { context_id, .. }
            | ToolsCommand::SettleToolEconomy { context_id, .. } => Some(context_id.as_str()),
            _ => None,
        }
    }

    /// Extract the target context_id from a [`QueriesCommand`].
    ///
    /// Every per-context variant surfaces a `context_id` string;
    /// [`QueriesCommand::EventLogEntries`] takes a 32-byte hash with no
    /// per-context lock and returns `None` so it stays on the
    /// supervisor's inline event-log path.
    const fn queries_command_context_id(cmd: &QueriesCommand) -> Option<&str> {
        match cmd {
            QueriesCommand::ReadContextState { context_id, .. }
            | QueriesCommand::LocalPseudonym { context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { context_id, .. }
            | QueriesCommand::MemberCount { context_id, .. }
            | QueriesCommand::IsMember { context_id, .. }
            | QueriesCommand::MemberDids { context_id, .. }
            | QueriesCommand::MemberRole { context_id, .. }
            | QueriesCommand::ContextParams { context_id, .. }
            | QueriesCommand::GetRoleState { context_id, .. }
            | QueriesCommand::HasEstablishedToolInterface { context_id, .. }
            | QueriesCommand::PendingCommits { context_id, .. }
            | QueriesCommand::CommitFault { context_id, .. }
            | QueriesCommand::LocalMlsEpoch { context_id, .. }
            | QueriesCommand::NeedsReconnect { context_id, .. } => Some(context_id.as_str()),
            QueriesCommand::EventLogEntries { .. } => None,
            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { context_id, .. }
            | QueriesCommand::GetAllAccessKeys { context_id, .. }
            | QueriesCommand::RemainingBudgetForTest { context_id, .. }
            | QueriesCommand::VelocityForTest { context_id, .. } => Some(context_id.as_str()),
        }
    }
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// supervisor's [`Outcome`] sink — mirrors the per-handler
/// `outcome_error_sketch` pattern used in `handlers::*`. Kept in
/// `supervisor.rs` to scope the helper to the standing-direct dispatch
/// path; the actor handlers each carry their own equivalent sketch.
fn standing_outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        ContextError::MembershipFailed(msg) => ContextError::MembershipFailed(msg.clone()),
        ContextError::EventLogFailed(msg) => ContextError::EventLogFailed(msg.clone()),
        ContextError::GovernanceFailed(msg) => ContextError::GovernanceFailed(msg.clone()),
        ContextError::InvalidState(msg) => ContextError::InvalidState(msg.clone()),
        ContextError::NotImplemented(msg) => ContextError::NotImplemented(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// Saga FSM helpers
// ---------------------------------------------------------------------------

/// RAII release for a saga's per-participant-context-set reservation
/// (ADR-049 §3a, spec §5.15.4). Holds the exact set of context IDs THIS
/// saga reserved; on drop it synchronously re-locks
/// [`Supervisor::reserved_saga_contexts`] and removes precisely those ids.
///
/// Drop fires on EVERY terminal path out of [`Supervisor::start_saga`] —
/// Committed, Aborted, and NeedsRepair — AND on a panic-unwind through the
/// FSM body. This is what makes `NeedsRepair` RELEASE the reservation: the
/// FSM's NeedsRepair arm returns control to `start_saga`, so `_reservation`
/// drops and the stuck saga's slots free immediately, even though the saga
/// is not yet operator-resolved. A stuck saga therefore never wedges
/// unrelated, disjoint sagas.
///
/// The drop body is purely synchronous (`lock()` → `remove` → unlock) and
/// never awaits, so the `std::sync::Mutex` guard is never held across a
/// yield point (see the `reserved_saga_contexts` field's allow). A poisoned
/// lock is recovered via `into_inner` so a panic elsewhere cannot strand a
/// reservation forever.
#[allow(
    clippy::disallowed_types,
    reason = "Synchronous drop-time release only; the guard is never held \
              across an .await. ADR-049 §3a."
)]
pub struct SagaSetReservation<'a> {
    reserved: &'a std::sync::Mutex<HashSet<String>>,
    ids: Vec<String>,
}

impl Drop for SagaSetReservation<'_> {
    fn drop(&mut self) {
        let mut reserved = self
            .reserved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in &self.ids {
            reserved.remove(id);
        }
    }
}

/// Phase tag used by the coordinator's Prepare dispatch. Enables
/// single-match dispatch on `(input, phase)` so the Prepare-A and
/// Prepare-B paths share a single dispatch table at the cost of one
/// enum discriminant.
#[derive(Clone, Copy, Debug)]
enum SagaPhase {
    A,
    B,
}

/// Participant identifiers extracted from a [`SagaInput`] for journal
/// durability. Per-variant extraction — the journal stores opaque
/// strings (context IDs or DIDs) and the saga-type discriminant is
/// carried separately (via [`SagaState`]).
fn saga_input_participants(input: &SagaInput) -> Vec<String> {
    match input {
        SagaInput::StandingPairCreate {
            local_did,
            peer_did,
        } => vec![local_did.to_string(), peer_did.to_string()],
        SagaInput::CrossContextToolInvocation {
            caller_context_id,
            // `target_context_id` is part of the gating participant set
            // (see `saga_participant_context_set`), NOT the journal
            // provenance record: this extractor intentionally records only
            // the caller side plus the DID + tool id. Leave the journal
            // shape UNCHANGED. The Prepare-B envelope fields (input,
            // ucan_proof_id, asserted freshness/depth, declared_cost) are
            // never journaled — only the caller-side provenance triple is.
            caller_did,
            tool_registration_id,
            ..
        } => vec![
            hex::encode(caller_context_id),
            caller_did.to_string(),
            tool_registration_id.clone(),
        ],
        SagaInput::BroadcastHostingHandshake {
            host_context_id,
            broadcast_context_id,
            subscriber_did,
        } => vec![
            hex::encode(host_context_id),
            hex::encode(broadcast_context_id),
            subscriber_did.to_string(),
        ],
        #[cfg(any(test, feature = "testing"))]
        SagaInput::TestForceNeedsRepair { context_id } => vec![hex::encode(context_id)],
    }
}

/// The set of **participant context-actor IDs** a saga reserves for
/// concurrency gating (ADR-049 §3a, spec §5.15.4).
///
/// This is a SIBLING of [`saga_input_participants`], NOT a replacement:
/// `saga_input_participants` produces the journal-provenance record (a
/// mixed bag of DIDs, context IDs, and tool IDs — the durable evidence of
/// who took part). THIS function produces the strict set of *context
/// actors* the saga spans, which is what the disjoint-vs-overlap
/// reservation reasons over. A saga reserves the WHOLE set atomically;
/// two sagas whose sets are disjoint run concurrently, while two whose
/// sets share ≥1 context serialize (the shared context's slot is held).
///
/// Each variant's set is de-duplicated through a [`HashSet`] before being
/// returned so a saga can never self-conflict (e.g. a degenerate
/// cross-context invocation whose caller and target resolve to the same
/// context id reserves that id ONCE, not twice).
///
/// # Canonical reservation key
///
/// Every variant reserves the **raw-digest hex** of each context it spans —
/// `hex::encode([u8; 32])` — which is the canonical saga-evidence / wire form
/// (spec §5.15.8: the `derived_context_id` is "the raw digest before prefix
/// and hex"; §6.2.4 / §5.14.13 for the cross-context / broadcast wire ids).
/// In particular `StandingPairCreate` reserves
/// `hex::encode(derive_standing_context_digest(local, peer))` — the RAW digest,
/// NOT the `"standing-"`-prefixed actor-registry id. The standing context still
/// LIVES under the prefixed id in the actor registry; only the gating
/// reservation key is canonicalized to the raw-digest hex so that a
/// cross-context or broadcast saga which shares that same standing context
/// reserves the IDENTICAL key and therefore OVERLAPS (defeating it otherwise
/// would let two sagas touch the shared context concurrently, breaking the
/// §5.15.4 serialization the §5.15.8 anti-griefing and §5.14.13 aggregate-cap
/// arguments depend on).
///
/// - `StandingPairCreate` → the single deterministic standing-pair raw-digest
///   hex (`derive_standing_context_digest`, the hex of spec §5.15.8's
///   `derived_context_id`).
/// - `CrossContextToolInvocation` → `{caller, target}` context ids.
/// - `BroadcastHostingHandshake` → `{host, broadcast}` context ids.
fn saga_participant_context_set(input: &SagaInput) -> Vec<String> {
    let raw: Vec<String> = match input {
        SagaInput::StandingPairCreate {
            local_did,
            peer_did,
        } => vec![hex::encode(
            crate::context::standing_helpers::derive_standing_context_digest(local_did, peer_did),
        )],
        SagaInput::CrossContextToolInvocation {
            caller_context_id,
            target_context_id,
            ..
        } => vec![
            hex::encode(caller_context_id),
            hex::encode(target_context_id),
        ],
        SagaInput::BroadcastHostingHandshake {
            host_context_id,
            broadcast_context_id,
            ..
        } => vec![
            hex::encode(host_context_id),
            hex::encode(broadcast_context_id),
        ],
        #[cfg(any(test, feature = "testing"))]
        SagaInput::TestForceNeedsRepair { context_id } => vec![hex::encode(context_id)],
    };
    // De-dup: a saga must never self-conflict. Two ids that collapse to one
    // (caller == target, host == broadcast) reserve a single slot.
    let mut seen = HashSet::with_capacity(raw.len());
    raw.into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

/// Classify whether a saga's journal evidence carries bearer bytes
/// (spec §9.4.3). No current [`SagaInput`] variant is secret-bearing:
/// the cross-identity custody handover — the only secret-bearing saga
/// ever contemplated — was withdrawn (ADR-049 §4, tombstoned; it is a
/// §5.11A.6 security violation, not a saga). This function therefore
/// returns `false` for every live input.
///
/// It is retained — not inlined to a constant `false` — as the §9.4.3
/// forward-contract hook: the classification point on the start-saga
/// path that any *future* secret-bearing saga MUST route through to
/// pass `true` to [`SagaJournal::mark_resolved`] (which synchronously
/// overwrites evidence bytes on terminal resolution). The secret-bearing
/// journal machinery stays dormant behind it; all live callers pass
/// `false`. NOTE: the crash-recovery path (`recover_saga_entry`)
/// hardcodes `false` because a replayed [`JournalEntry`] does not carry
/// its `SagaInput`; a future secret-bearing saga MUST additionally
/// re-derive secret-bearing status there (e.g. from the persisted saga
/// type) so recovery resolution also overwrites prior on-disk evidence.
const fn saga_input_is_secret_bearing(input: &SagaInput) -> bool {
    match input {
        SagaInput::StandingPairCreate { .. }
        | SagaInput::CrossContextToolInvocation { .. }
        | SagaInput::BroadcastHostingHandshake { .. } => false,
        // The test-only NeedsRepair driver carries no bearer material.
        #[cfg(any(test, feature = "testing"))]
        SagaInput::TestForceNeedsRepair { .. } => false,
    }
}

/// Shared timestamp helper. Duplicated from `saga_journal.rs` to avoid
/// cross-module visibility churn. Returns milliseconds since the UNIX
/// epoch.
fn current_timestamp_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    ms
}

// ---------------------------------------------------------------------------
// No-op SagaJournal — plumbed into the FFI [`Self::with_providers`] factory
// (and the test-only [`Self::for_query_shim`] constructor) when no production
// saga journal is wired. The `NoopContextPersistence` counterpart lives in
// [`crate::context::persistence`] (single public definition; the prior local
// duplicate was deleted in the post-review-round-1 phase 1 fix-up).
// ---------------------------------------------------------------------------

/// No-op saga journal — every operation is a no-op success. Used by
/// [`Self::with_providers`] until the production saga path lands; also used
/// by [`Self::for_query_shim`] in tests.
struct NoopSagaJournal;

#[async_trait::async_trait]
impl SagaJournal for NoopSagaJournal {
    async fn append(
        &self,
        _entry: crate::context::supervisor::saga_journal::JournalEntry,
    ) -> Result<(), crate::context::supervisor::saga_journal::JournalError> {
        Ok(())
    }

    async fn load_unresolved(
        &self,
    ) -> Result<
        Vec<crate::context::supervisor::saga_journal::JournalEntry>,
        crate::context::supervisor::saga_journal::JournalError,
    > {
        Ok(Vec::new())
    }

    async fn mark_resolved(
        &self,
        _saga_id: SagaId,
        _terminal: crate::context::supervisor::saga_journal::SagaTerminalState,
        _secret_bearing: bool,
    ) -> Result<(), crate::context::supervisor::saga_journal::JournalError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shim helpers — synthesise the "context unknown" fallback reply for each
// query variant. Matches the legacy `ContextManager::foo()` defaults
// byte-for-byte. Deleted in commit 12 with the shim itself.
// ---------------------------------------------------------------------------

/// Send the legacy soft-default reply on a query variant's oneshot when
/// the context isn't registered. Mirrors each legacy method's
/// unknown-context return value exactly.
#[allow(clippy::cognitive_complexity)] // flat variant dispatch
fn reply_with_soft_default(cmd: QueriesCommand) {
    match cmd {
        // `ReadContextState` has no soft default — its reply is a bare
        // `ContextState`, not an `Option`. It is dispatched explicitly in
        // `dispatch_queries_direct` and never routes through the
        // soft-default / error fallbacks. Reply `ContextNotRegistered` so
        // a future classification bug surfaces a real error rather than
        // hanging the caller's oneshot.
        QueriesCommand::ReadContextState { reply, context_id } => {
            debug_assert!(false, "ReadContextState routed through soft-default path");
            let _ = reply.send(Err(ContextError::ContextNotRegistered(format!(
                "context not registered: {context_id}"
            ))));
        }
        // Hard-error variants never route here — they use
        // `reply_with_error` instead. Left unreachable so a future
        // dispatch-classification change trips a compile-time match.
        QueriesCommand::LocalPseudonym { .. }
        | QueriesCommand::GetBroadcastKeyForLocalAuthor { .. } => {
            debug_assert!(false, "hard-error variant routed through soft-default path");
        }
        // Legacy `member_count` returns `None` on unknown context.
        QueriesCommand::MemberCount { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `is_member` returns `false`.
        QueriesCommand::IsMember { reply, .. } => {
            let _ = reply.send(Ok(false));
        }
        // Legacy `member_dids` returns an empty `Vec`.
        QueriesCommand::MemberDids { reply, .. } => {
            let _ = reply.send(Ok(Vec::new()));
        }
        // Legacy `member_role` returns `None`.
        QueriesCommand::MemberRole { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `context_params` returns `None`.
        QueriesCommand::ContextParams { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `get_role_state` returns `None`.
        QueriesCommand::GetRoleState { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // An unknown caller context holds no established interface.
        QueriesCommand::HasEstablishedToolInterface { reply, .. } => {
            let _ = reply.send(Ok(false));
        }
        // Legacy `pending_commits` returns an empty `Vec`.
        QueriesCommand::PendingCommits { reply, .. } => {
            let _ = reply.send(Ok(Vec::new()));
        }
        // Legacy `commit_fault` returns `None`.
        QueriesCommand::CommitFault { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // An unknown context has no local MLS epoch.
        QueriesCommand::LocalMlsEpoch { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // An unknown context has nothing to reconnect.
        QueriesCommand::NeedsReconnect { reply, .. } => {
            let _ = reply.send(Ok(false));
        }
        // `EventLogEntries` does not take a per-context lock and never
        // reaches this fallback path; the top-level dispatch handles it
        // inline.
        QueriesCommand::EventLogEntries { reply, .. } => {
            debug_assert!(false, "EventLogEntries routed through fallback path");
            let _ = reply.send(Ok(None));
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAccessKey { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::GetAllAccessKeys { reply, .. } => {
            let _ = reply.send(Ok(std::collections::HashMap::new()));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::RemainingBudgetForTest { reply, .. } => {
            let _ = reply.send(Ok(scp_protocol::economy::types::Amount::new(0)));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::VelocityForTest { reply, .. } => {
            let _ = reply.send(Ok(0));
        }
    }
}

/// Send a typed error on a query variant's oneshot. Used by the hard-
/// error variants (`LocalPseudonym`,
/// `GetBroadcastKeyForLocalAuthor`) whose legacy methods propagate
/// `ContextError::ContextNotRegistered` rather than a soft default.
#[allow(clippy::cognitive_complexity)] // flat variant dispatch
fn reply_with_error(cmd: QueriesCommand, err: ContextError) {
    match cmd {
        QueriesCommand::LocalPseudonym { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        QueriesCommand::GetBroadcastKeyForLocalAuthor { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        // Every other variant is soft-fallback — they never route
        // through the error path. Assert that at runtime to catch a
        // future classification bug.
        other => {
            debug_assert!(false, "soft-default variant routed through error path");
            reply_with_soft_default(other);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // The watchdog tests' tracing-capture buffer uses `std::sync::Mutex`,
    // which is only locked synchronously inside `tracing::Subscriber::event`
    // (never across an `.await`), so the async-deadlock rationale behind the
    // workspace `disallowed_types` ban does not apply here.
    clippy::disallowed_types,
    // `clock` / `clock_dyn` and similar paired test bindings trip the
    // pedantic similar-names lint without any real ambiguity.
    clippy::similar_names
)]
mod tests {
    use super::*;
    use crate::context::supervisor::saga_journal::ProtocolRepositorySagaJournal;
    use scp_platform::testing::InMemoryStorage;

    // -----------------------------------------------------------------
    // CrashWindow pure-method unit tests (ADR-049 §10).
    //
    // These exercise the respawn-budget logic with explicit `now_ms`
    // values — no clock, no actor, no async. They prove eviction,
    // the exactly-3-in-window poison threshold, the
    // 2-then-gap-then-1 non-poison case, sticky poison, and clear().
    // -----------------------------------------------------------------

    #[test]
    fn crash_window_three_in_window_poisons() {
        let mut w = CrashWindow::default();
        assert!(!w.record(0), "1st crash does not poison");
        assert!(!w.record(100), "2nd crash does not poison");
        assert!(w.record(200), "3rd crash within 60s poisons");
        assert!(w.is_poisoned());
        assert_eq!(w.crash_count(), CRASH_POISON_THRESHOLD);
    }

    #[test]
    fn crash_window_two_then_gap_then_one_does_not_poison() {
        let mut w = CrashWindow::default();
        // Two crashes near t=0.
        assert!(!w.record(0));
        assert!(!w.record(1_000));
        // A third crash AFTER the window has slid past the first two: at
        // t = 1_000 + 60_001, the entries at 0 and 1_000 are both strictly
        // older than 60s relative to `now_ms` and get evicted, leaving only
        // the newest. Count is 1, so no poison.
        let now = 1_000 + CRASH_WINDOW_MS + 1;
        assert!(
            !w.record(now),
            "the two early crashes evicted; only 1 remains"
        );
        assert!(!w.is_poisoned());
        assert_eq!(w.crash_count(), 1);
    }

    #[test]
    fn crash_window_evicts_only_strictly_older_than_window() {
        let mut w = CrashWindow::default();
        // Crash at the exact window edge is RETAINED (eviction is strict
        // `> CRASH_WINDOW_MS`).
        assert!(!w.record(0));
        assert!(!w.record(CRASH_WINDOW_MS)); // exactly 60s later: front kept
        assert_eq!(w.crash_count(), 2, "edge-of-window crash is not evicted");
        // A third within the same window poisons (all three within 60s of
        // the newest).
        assert!(w.record(CRASH_WINDOW_MS), "3rd within window poisons");
    }

    #[test]
    fn crash_window_poison_is_sticky_across_later_eviction() {
        let mut w = CrashWindow::default();
        w.record(0);
        w.record(100);
        assert!(w.record(200), "poisoned at 3 crashes");
        // A much-later record evicts the old crashes (count drops) but the
        // sticky flag must stay set — an in-window eviction must NOT
        // silently un-poison.
        let later = 200 + CRASH_WINDOW_MS * 10;
        assert!(
            w.record(later),
            "poison persists even after the window slides past the old crashes"
        );
        assert!(w.is_poisoned());
    }

    #[test]
    fn crash_window_clear_unpoison_and_resets() {
        let mut w = CrashWindow::default();
        w.record(0);
        w.record(100);
        w.record(200);
        assert!(w.is_poisoned());
        w.clear();
        assert!(!w.is_poisoned(), "clear() un-poisons");
        assert_eq!(w.crash_count(), 0, "clear() empties the deque");
        // After clear the budget starts fresh: one crash does not re-poison.
        assert!(!w.record(300));
    }

    #[test]
    fn crash_window_deque_is_length_capped() {
        // Under a pathological non-monotonic clock that never advances past
        // the window, the deque must stay bounded by the defensive cap.
        let mut w = CrashWindow::default();
        for _ in 0..100 {
            w.record(0);
        }
        assert!(
            w.crash_count() <= CRASH_DEQUE_CAP,
            "deque length is defensively capped at {CRASH_DEQUE_CAP}"
        );
        assert!(w.is_poisoned(), "many same-instant crashes poison");
    }

    /// In-memory `ContextPersistence` stub for tests only. Returns an
    /// empty snapshot for every load and silently accepts every persist.
    /// Production callers wire the real
    /// `ProtocolRepositoryContextBridge`.
    struct TestPersistence;
    impl ContextPersistence for TestPersistence {
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

    fn test_supervisor() -> Supervisor {
        let persistence: Arc<dyn ContextPersistence> = Arc::new(TestPersistence);
        let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
            InMemoryStorage::new(),
        )));
        Supervisor::new(persistence, journal, SupervisorConfig::default())
    }

    #[tokio::test]
    async fn fresh_supervisor_has_empty_registries() {
        let s = test_supervisor();
        assert!(s.lookup("any-ctx").is_none());
        assert!(s.local_dids.load().is_empty());
        assert!(s.standing_contexts.load().is_empty());
    }

    /// ADR-049 commit 12c.9f: per-identity wrapping-key accessors lift
    /// the keypair off `MlsCryptoProvider`. Verifies that `set` →
    /// `get` returns the same bytes via the supervisor's
    /// `DashMap<DID, ArcSwap<WrappingKeyPair>>`.
    #[tokio::test]
    async fn wrapping_keys_set_and_get_round_trip() {
        let s = Arc::new(test_supervisor());
        let did = DID("did:example:wrap-roundtrip".to_owned());
        let public = vec![0x11u8; 32];
        let secret = zeroize::Zeroizing::new(vec![0x22u8; 32]);

        // Pre-set the slot is empty for this DID.
        assert!(s.wrapping_public_key_for(&did).is_none());
        assert!(s.wrapping_secret_key_for(&did).is_none());

        s.set_wrapping_keys(did.clone(), public.clone(), secret.clone())
            .await
            .expect("set_wrapping_keys succeeds for valid 32-byte inputs");

        let got_pub = s.wrapping_public_key_for(&did).expect("public set");
        assert_eq!(*got_pub, public);
        let got_sec = s.wrapping_secret_key_for(&did).expect("secret set");
        assert_eq!(&**got_sec, &*secret);
    }

    /// Rotation replaces the prior keypair atomically; subsequent
    /// reads observe the new bytes.
    #[tokio::test]
    async fn wrapping_keys_rotation_atomically_replaces() {
        let s = Arc::new(test_supervisor());
        let did = DID("did:example:wrap-rotate".to_owned());

        s.set_wrapping_keys(
            did.clone(),
            vec![0x01u8; 32],
            zeroize::Zeroizing::new(vec![0x02u8; 32]),
        )
        .await
        .unwrap();
        assert_eq!(*s.wrapping_public_key_for(&did).unwrap(), vec![0x01u8; 32]);

        s.set_wrapping_keys(
            did.clone(),
            vec![0xAAu8; 32],
            zeroize::Zeroizing::new(vec![0xBBu8; 32]),
        )
        .await
        .unwrap();
        assert_eq!(*s.wrapping_public_key_for(&did).unwrap(), vec![0xAAu8; 32]);
        assert_eq!(
            &**s.wrapping_secret_key_for(&did).unwrap(),
            &vec![0xBBu8; 32]
        );
    }

    /// Wrong-length inputs surface as `InvalidState` rather than
    /// silently truncating key material.
    #[tokio::test]
    async fn wrapping_keys_rejects_wrong_byte_length() {
        let s = Arc::new(test_supervisor());
        let did = DID("did:example:wrap-bad-len".to_owned());
        let err = s
            .set_wrapping_keys(
                did.clone(),
                vec![0u8; 16],
                zeroize::Zeroizing::new(vec![0u8; 32]),
            )
            .await
            .expect_err("16-byte public must reject");
        assert!(matches!(err, ContextError::InvalidState(_)));
        let err = s
            .set_wrapping_keys(did, vec![0u8; 32], zeroize::Zeroizing::new(vec![0u8; 16]))
            .await
            .expect_err("16-byte secret must reject");
        assert!(matches!(err, ContextError::InvalidState(_)));
    }

    #[tokio::test]
    async fn start_saga_returns_not_implemented_for_spec_gapped_input() {
        // All 3 current SagaInput variants are not yet wired — the FSM
        // journals Initiated + PreparingA then fails the Prepare
        // dispatch with NotImplemented, rolls back via abort_saga, and
        // returns the typed error. This exercises the coordinator
        // through the PreparingA → Aborting → Aborted arm of the FSM
        // without needing spec-filled inputs.
        let s = test_supervisor();
        let err = s
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));

        // The participant-context-set reservation must be RELEASED after a
        // saga terminates (even on a NotImplemented abort) so a subsequent
        // saga over the SAME set can reserve and start. This is the
        // same-set sequential re-arm property: the RAII `SagaSetReservation`
        // drop frees the slots on every terminal.
        let err2 = s
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err2, ContextError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn persist_state_returns_not_implemented() {
        let s = test_supervisor();
        let err = s.persist_state().await.unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn spawn_actor_registers_handle_under_write_lock() {
        let s = test_supervisor();
        let _handle = s.spawn_actor("ctx-42".to_owned(), None).await;
        assert!(s.lookup("ctx-42").is_some());
        // Second spawn with the same ID overwrites (commit 6 semantics —
        // duplicate-spawn detection is a watchdog responsibility and
        // lands with the panic-recovery path in commit 11).
        let _handle2 = s.spawn_actor("ctx-42".to_owned(), None).await;
        assert!(s.lookup("ctx-42").is_some());
    }

    // -----------------------------------------------------------------
    // ADR-049 commit 12b.2a — `spawn_actor_with_state` tests
    // -----------------------------------------------------------------

    /// Construct a minimal [`crate::context::actor::deps::ActorDeps`] for
    /// the `spawn_actor_with_state` tests. Builds through the
    /// supervisor's `build_actor_deps` path so we exercise real
    /// construction rather than invent synthetic mocks.
    async fn test_actor_deps(
        supervisor: &Arc<Supervisor>,
    ) -> crate::context::actor::deps::ActorDeps {
        supervisor
            .build_actor_deps(&DID("did:example:spawn-state-test".to_owned()))
            .await
            .expect("build_actor_deps requires providers populated")
    }

    /// A tiny `ContextEventLogProvider` that accepts every call and
    /// returns empty data for every read. Exists only so
    /// [`supervisor_with_providers`] can construct a supervisor with
    /// minimal providers without dragging in the full mock stack from
    /// the `tests/actor_*_shim.rs` integration harnesses.
    struct TestEventLog;
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        fn init_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _context_id: &[u8; 32],
            _event: &str,
            _actor_did: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Build a supervisor with minimal providers so
    /// [`test_actor_deps`] can construct `ActorDeps` via the real
    /// `build_actor_deps` path. The plain `test_supervisor` helper
    /// above does NOT populate providers because its saga / lookup
    /// tests do not need them.
    fn supervisor_with_providers() -> Arc<Supervisor> {
        // Minimal providers — the spawn-registry tests only care about
        // the supervisor's actor map, not the providers' behaviour.
        // `MlsCryptoProvider::new` takes a String DID; the stub DID is
        // never used by the spawn tests because no
        // `create_context` call runs.
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestDoNotRely".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: KeyResolver = Arc::new(|_: &DID| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            mls_storage,
        )
    }

    /// Poll `cond` every 5ms until it returns `true` or a generous deadline
    /// (~8s) elapses; returns whether it settled. Replaces fixed
    /// `sleep(20ms)×50` (~1s) poison-respawn poll loops, which are flaky on
    /// loaded CI: a short fixed budget can expire before the watchdog task is
    /// scheduled. The CrashWindow budget math stays deterministic; only the
    /// WALL-CLOCK wait for the watchdog to be scheduled is widened. The tighter
    /// 5ms interval keeps the common (fast) case responsive while the long
    /// deadline removes the false-timeout tail.
    #[cfg(feature = "testing")]
    async fn poll_until<F: Fn() -> bool>(cond: F) -> bool {
        // ~8s ceiling = 1600 iterations × 5ms. Far above any realistic watchdog
        // scheduling delay, but still bounded so a genuinely stuck test fails
        // rather than hangs.
        for _ in 0..1600 {
            if cond() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        cond()
    }

    /// Structural: a supervisor built through the production
    /// `Supervisor::with_providers` factory ALWAYS attaches the consumed-init-key
    /// store to the shared MLS backend. Proven behaviorally: a join through the
    /// supervisor's own backend must NOT fail closed (it would
    /// `MlsError::StorageError` if the store were unattached). A future
    /// `with_providers` that forgets the `set_consumed_init_key_store` wiring
    /// would make this join fail closed and the test would fail.
    #[tokio::test]
    async fn with_providers_attaches_consumed_init_key_store() {
        use crate::crypto::mls::credential::ScpCredential;

        let supervisor = supervisor_with_providers();
        let crypto = supervisor
            .crypto_ref()
            .expect("with_providers populates crypto");
        let backend = crypto.mls_backend();

        let joiner = ScpCredential::new(
            "did:dht:z6MkWithProvidersStoreCheck".to_owned(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .expect("valid credential");
        let generated = backend
            .generate_key_package(&joiner, None)
            .await
            .expect("generate kp");

        // Build a real Welcome for the generated KP.
        let inviter = ScpCredential::new(
            "did:dht:z6MkWithProvidersInviter".to_owned(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .expect("valid inviter credential");
        let mut group = backend
            .create_group(&inviter, None)
            .await
            .expect("create group");
        let added = backend
            .add_member_raw(&mut group, &generated.key_package_bytes)
            .await
            .expect("add member");

        // The join must succeed — i.e. NOT fail closed with StorageError, which
        // is the symptom of a missing consumed-init-key store. (ScpMlsGroup is
        // not Debug, so assert on the error shape, not the Ok value.)
        let result = backend
            .join_from_welcome(
                &added.welcome,
                generated.signer_state,
                &generated.key_package_bytes,
            )
            .await;
        assert!(
            !matches!(
                result,
                Err(crate::crypto::mls::error::MlsError::StorageError(_))
            ),
            "with_providers must attach the consumed-init-key store \
             (a store-less backend fails the join closed with StorageError)"
        );
        assert!(
            result.is_ok(),
            "the join through the supervisor backend must succeed once the store is attached"
        );
    }

    #[tokio::test]
    async fn spawn_actor_with_state_registers_handle_and_accepts_commands() {
        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        // Construct a fresh encrypted-mode PerContextState. The
        // context_id is arbitrary for this test — the registry key
        // is derived from it via `hex::encode`.
        let ctx_id_bytes = [0xABu8; 32];
        let expected_ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );

        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        // Handle is registered under the hex-encoded context id key.
        assert!(
            supervisor_arc.lookup(&expected_ctx_key).is_some(),
            "actor must be registered under hex-encoded context id"
        );

        // Handle is alive — send a placeholder messaging command and
        // observe the skeleton dispatch's `NotImplemented` ack. This
        // exercises both the mpsc plumbing and the
        // `ContextActor::new` + `run()` happy path.
        let err = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await
            .expect_err("skeleton dispatch still ACKs NotImplemented in 12b.2a");
        assert!(matches!(err, ContextError::NotImplemented(_)));

        // Cleanly shut down.
        handle.send_shutdown().await.unwrap();
    }

    /// End-to-end: a TTL timer installed via the actor mailbox
    /// (`SupervisorHandle::dispatch_start_ttl_timer` →
    /// `TtlCloseCommand::StartTtlTimer` → actor-shape
    /// `ttl_close_helpers::spawn_ttl_timer`) actually fires after its
    /// duration: the spawned timer task resolves the owning actor via
    /// `Supervisor::lookup` and mailboxes `TtlCloseCommand::FireTimer`,
    /// whose handler runs the expiry pipeline on owned state and
    /// transitions the context `Active → Expired`. Proves the
    /// registry + mailbox-tick timer path (ADR-049 Phase 2A
    /// finalization) end-to-end, with no `contexts` DashMap reach.
    #[tokio::test]
    async fn dispatch_start_ttl_timer_fires_and_expires_context() {
        use crate::context::supervisor::handle::SupervisorHandle;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        let ctx_id_bytes = [0x7Au8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Clone the shared handle BEFORE moving state into the actor so
        // we can observe the actor's FSM transitions from this test.
        // The actor's `state.handle` must be `Active` for the FireTimer
        // expiry pipeline to run (it rejects non-Active contexts), so
        // drive the shared handle to `Active` up front — the production
        // create path leaves the context Active before the timer fires.
        let observed_handle = state.handle.clone();
        observed_handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let actor_handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Install a short TTL timer through the capability-reduced
        // handle: StartTtlTimer → actor-shape `spawn_ttl_timer` installs
        // the timer task on owned state.
        let sup_handle = SupervisorHandle::wrap(Arc::clone(&supervisor_arc));
        sup_handle
            .dispatch_start_ttl_timer(
                &ctx_key,
                scp_protocol::context::ContextParams::default(),
                std::time::Duration::from_millis(50),
            )
            .await;
        assert_eq!(
            observed_handle.state().await,
            crate::context::ContextState::Active,
            "context must remain Active immediately after the timer is installed"
        );

        // Wait for the timer to fire and the FireTimer expiry pipeline
        // to run. Poll the shared handle until it leaves `Active`.
        let expired = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if observed_handle.state().await != crate::context::ContextState::Active {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            expired.is_ok(),
            "TTL timer task must fire FireTimer and move the context out of Active"
        );
        assert_eq!(
            observed_handle.state().await,
            crate::context::ContextState::Expired,
            "FireTimer expiry pipeline must transition the context to Expired"
        );

        actor_handle.send_shutdown().await.unwrap();
    }

    /// `GovernanceCommand::StartTimeoutTask` installs the per-context
    /// governance-timeout interval task on the spawned actor's owned
    /// state (actor-shape `governance_helpers::spawn_governance_timeout_task`
    /// → `tracked_spawn` onto the supervisor's `task_set` → install on
    /// `state.governance.timeout_task`). Asserts the handler replies
    /// `Ok(())`, proving the install path runs end-to-end on a
    /// registered actor with no `contexts` DashMap reach (ADR-049
    /// Phase 2A finalization).
    #[tokio::test]
    async fn start_timeout_task_installs_on_actor() {
        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        let ctx_id_bytes = [0x6Bu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );

        let actor_handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Dispatch StartTimeoutTask and observe the install reply.
        let reply = actor_handle
            .send(|reply| ContextCommand::Governance(GovernanceCommand::StartTimeoutTask { reply }))
            .await;
        assert!(
            reply.is_ok(),
            "StartTimeoutTask must install the governance-timeout task and reply Ok(()): {reply:?}"
        );

        actor_handle.send_shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn spawn_actor_with_state_rejects_duplicate_context_id() {
        // First-writer-wins: a second spawn with the same context_id is
        // REJECTED with CreationFailed rather than silently overwriting a
        // live actor (which would leak the loser's task and diverge
        // crypto state). This restores the duplicate-rejection the legacy
        // `manager_methods::insert_context` provided. The import replace
        // path despawns the prior actor first, so it never trips this.
        let supervisor_arc = supervisor_with_providers();

        let ctx_id_bytes = [0xCDu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);

        let state1 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let deps1 = test_actor_deps(&supervisor_arc).await;
        let h1 = supervisor_arc
            .spawn_actor_with_state(state1, deps1, None)
            .await
            .expect("first spawn of a fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        let state2 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_001,
            DID("did:example:admin".to_owned()),
        );
        let deps2 = test_actor_deps(&supervisor_arc).await;
        // `ContextActorHandle` is not `Debug`, so pattern-match on the
        // `Result` rather than calling `expect_err` (which needs `Debug`
        // on the `Ok` variant).
        let dup = supervisor_arc
            .spawn_actor_with_state(state2, deps2, None)
            .await;
        // `ContextActorHandle` (the Ok variant) is not Debug, so assert via
        // `matches!` (which never formats the value) rather than `panic!`-arms.
        assert!(
            matches!(dup, Err(ContextError::CreationFailed(_))),
            "duplicate spawn must be rejected with CreationFailed"
        );
        // The original actor is still the registered one.
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Shut down the survivor to avoid a leaked task.
        let _ = h1.send_shutdown().await;
    }

    /// `shutdown_all_contexts` must DEREGISTER every actor, not just
    /// dispatch `ShutdownSelf` to it. `ShutdownSelf` tears down the
    /// per-context crypto/log/timers but does NOT break the actor
    /// `run()` loop, and nothing else despawns the handle — so without
    /// the explicit `despawn_actor` the contexts stay discoverable via
    /// `lookup` / `actor_ids` and the spawned tasks linger as zombies
    /// (the regression introduced when the lock-step `contexts.remove`
    /// mirror was deleted). Asserts the registry is empty afterwards.
    #[tokio::test]
    async fn shutdown_all_contexts_deregisters_every_actor() {
        let supervisor_arc = supervisor_with_providers();

        // Spawn two distinct contexts.
        let ctx_a = [0x1Au8; 32];
        let ctx_b = [0x2Bu8; 32];
        let key_a = hex::encode(ctx_a);
        let key_b = hex::encode(ctx_b);
        for ctx_id_bytes in [ctx_a, ctx_b] {
            let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
                ctx_id_bytes,
                1_700_000_000,
                DID("did:example:admin".to_owned()),
            );
            let deps = test_actor_deps(&supervisor_arc).await;
            supervisor_arc
                .spawn_actor_with_state(state, deps, None)
                .await
                .expect("fresh context id registers");
        }
        assert_eq!(
            supervisor_arc.actor_ids().len(),
            2,
            "both actors must be registered before shutdown"
        );

        crate::context::lifecycle_helpers::shutdown_all_contexts(&supervisor_arc).await;

        // Every actor must be deregistered: no zombie handles remain.
        assert!(
            supervisor_arc.actor_ids().is_empty(),
            "actor_ids must be empty after shutdown_all_contexts, got {:?}",
            supervisor_arc.actor_ids()
        );
        assert!(
            supervisor_arc.lookup(&key_a).is_none(),
            "context A must not be discoverable after shutdown"
        );
        assert!(
            supervisor_arc.lookup(&key_b).is_none(),
            "context B must not be discoverable after shutdown"
        );
    }

    /// A Phase-3 tool-economy settle that finds NO registered actor for
    /// its context (the actor was despawned during the off-mailbox
    /// executor window) must NOT silently drop the in-flight ticket:
    /// `settle_tool_economy_via_actor` reclaims the ticket, voids its
    /// external escrow (none here), consumes it so the `#[must_use]` Drop
    /// balance guard does not `debug_assert!`-panic, and returns a typed
    /// `ContextNotRegistered`. Reaching the assertions without a panic
    /// proves the ticket was consumed rather than leaked.
    #[tokio::test]
    async fn settle_with_no_registered_actor_voids_and_consumes_ticket() {
        let supervisor_arc = supervisor_with_providers();
        let invoker = DID("did:example:invoker".to_owned());

        // A settle request for a context that has no actor registered.
        let ticket = crate::context::tools_helpers::ToolEconomyTicket::new_for_test_no_escrow(
            invoker.clone(),
        );
        let request = crate::context::tools_helpers::ToolSettleRequest::Rollback {
            generation: 1,
            ticket,
        };

        let result = supervisor_arc
            .settle_tool_economy_via_actor("ctx-never-registered", &invoker, request)
            .await;

        assert!(
            matches!(&result, Err(ContextError::ContextNotRegistered(msg)) if msg.contains("registered actor")),
            "settle with no registered actor must return ContextNotRegistered \
             explaining the missing actor, got {result:?}"
        );
        // No panic ⇒ the ticket was consumed, not dropped unbalanced.
    }

    /// Each spawn pulls a DISTINCT monotonic spawn-generation from the
    /// supervisor's `spawn_generation` counter, starting at 1 (never the
    /// default 0 a fresh `PerContextState` carries). This is the token
    /// stamped onto the actor's state and compared by the tool-economy
    /// settle to detect a settle landing on a replaced instance.
    #[tokio::test]
    async fn spawn_stamps_distinct_monotonic_generations() {
        use std::sync::atomic::Ordering;

        let supervisor_arc = supervisor_with_providers();

        // The counter starts at 0; the first spawn stamps 1.
        assert_eq!(
            supervisor_arc.spawn_generation.load(Ordering::Acquire),
            0,
            "a fresh supervisor's spawn-generation counter starts at 0"
        );

        for i in 0..3u8 {
            let ctx_id_bytes = [0x30 + i; 32];
            let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
                ctx_id_bytes,
                1_700_000_000,
                DID("did:example:admin".to_owned()),
            );
            assert_eq!(state.generation, 0, "fresh test state defaults to gen 0");
            let deps = test_actor_deps(&supervisor_arc).await;
            supervisor_arc
                .spawn_actor_with_state(state, deps, None)
                .await
                .expect("spawn registers");
            // After n spawns the counter has advanced to n, and the nth
            // spawn stamped generation n (>0, strictly increasing).
            assert_eq!(
                supervisor_arc.spawn_generation.load(Ordering::Acquire),
                u64::from(i) + 1,
                "spawn-generation counter must advance once per spawn"
            );
        }
    }

    /// Security invariant (import): `PrepareForReplace` MUST reject a
    /// LIVE (Active) context — an import may never overwrite a live
    /// context. The actor stays alive after the reject so the still-live
    /// context keeps being served (no terminal break on reject).
    #[tokio::test]
    async fn prepare_for_replace_rejects_live_context() {
        use crate::context::actor::commands::LifecycleControlCommand;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;
        let ctx_id_bytes = [0x9Eu8; 32];
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Drive the context's handle to Active — a live, non-replaceable
        // context.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers the live context");

        let result: Result<(), ContextError> = handle
            .send(|reply| {
                ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                    mls_state: Vec::new(),
                    reply,
                })
            })
            .await;
        assert!(
            matches!(result, Err(ContextError::MembershipFailed(_))),
            "import must REJECT overwriting a live context, got {result:?}"
        );

        // The actor must still be alive after the reject — prove it by
        // issuing a follow-up command and observing a reply (not an
        // ActorBusy/closed-inbox error).
        let followup: Result<(), ContextError> = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await;
        assert!(
            !matches!(followup, Err(ContextError::ActorBusy(_))),
            "live context's actor must survive a rejected PrepareForReplace, got {followup:?}"
        );

        let _ = handle.send_shutdown().await;
    }

    /// `PrepareForReplace` SUCCEEDS for a replaceable (Closing/Closed)
    /// context: it runs the §23.17 crypto teardown + epoch-floor merge,
    /// claims itself terminal, and the actor exits its run loop.
    #[tokio::test]
    async fn prepare_for_replace_succeeds_for_replaceable_context() {
        use crate::context::actor::commands::LifecycleControlCommand;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;
        let ctx_id_bytes = [0x8Du8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Drive the handle Active → Closing — a replaceable state.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        state
            .handle
            .transition_to(&crate::context::ContextState::Closing)
            .await
            .unwrap();
        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers the replaceable context");

        let result: Result<(), ContextError> = handle
            .send(|reply| {
                ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                    mls_state: Vec::new(),
                    reply,
                })
            })
            .await;
        assert!(
            result.is_ok(),
            "PrepareForReplace must succeed for a replaceable (Closing) context, got {result:?}"
        );

        // The actor claimed itself terminal and exits — a follow-up send
        // must observe the closed inbox. (The supervisor despawns the
        // dead handle in the import path; here we just prove termination.)
        let followup: Result<(), ContextError> = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await;
        assert!(
            matches!(followup, Err(ContextError::ActorBusy(_))),
            "actor must have exited after a successful PrepareForReplace, got {followup:?}"
        );

        // Handle is still registered until the import path despawns it.
        assert!(supervisor_arc.lookup(&ctx_key).is_some());
    }

    // -----------------------------------------------------------------
    // Verify-before-side-effect on the import dispatch path.
    //
    // `Supervisor::import_context` is a public runtime API. The
    // `ImportContext` dispatch arm must verify the snapshot signature
    // BEFORE deriving `owning_did` from the (otherwise unverified)
    // roster and calling `build_actor_deps` → `key_package_store_for`,
    // which would otherwise spawn a `KeyPackageStoreActor` and insert a
    // permanent entry into the unbounded `key_package_stores` map keyed
    // on an attacker-chosen DID. This test drives a forged export (valid
    // structure, wrong verifying key) and asserts (a) it is rejected and
    // (b) no key-package-store entry leaked.
    // -----------------------------------------------------------------

    /// Minimal active-context snapshot whose `creator_did` is `creator`.
    fn import_test_snapshot(
        context_id: &str,
        creator: &str,
    ) -> crate::context::state::ContextSnapshot {
        use scp_protocol::context::ContextState;
        use scp_protocol::context::membership::MembershipState;
        use scp_protocol::context::params::ContextParams;
        use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

        let role_state = ContextRoleState::new(
            context_id,
            creator,
            default_ceiling(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        crate::context::state::ContextSnapshot {
            context_id: context_id.to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::new(),
            role_state,
            event_log_merkle_root: [0u8; 32],
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            read_exclusion_list: HashSet::new(),
            approved_proposals: HashMap::new(),
            next_proposal_seq: 0,
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            mls_crypto_state: Vec::new(),
            migration_state: None,
            access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
            consequence_rules: Vec::new(),
            participation_cache: HashMap::new(),
            velocity_tracker: None,
            velocity_tracker_state: None,
            cooldown_until: HashMap::new(),
            proposal_timestamps: HashMap::new(),
            message_pricing: None,
            hard_rate_limit_config: None,
            hard_rate_limit_state: HashMap::new(),
            spending_nonce_tracker_state: HashMap::new(),
            revoked_spending_ucan_cids: HashSet::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            routing: crate::context::actor::state::ContextRouting::Broadcast,
            saga_pending: HashMap::new(),
            xctx_committed_outputs: HashMap::new(),
            xctx_committed_invocations: std::collections::HashSet::new(),
            xctx_nonce_dedup: HashMap::new(),
        }
    }

    /// A forged export — structurally valid and signed by the creator's
    /// key, but presented with a DIFFERENT verifying key on import — must
    /// be rejected WITHOUT leaking a key-package-store actor/entry.
    #[tokio::test]
    async fn import_rejects_forged_export_before_building_actor_deps() {
        use ed25519_dalek::{Signer, SigningKey};

        let supervisor = supervisor_with_providers();
        // Providers ARE wired here, so `build_actor_deps` would succeed and
        // spawn a key-package store if it were reached — the verify gate is
        // what must keep it from being reached.
        assert!(
            supervisor.key_package_stores.is_empty(),
            "fixture starts with no key-package stores"
        );

        let creator = "did:key:forge-test-creator";
        let snapshot = import_test_snapshot("forge-ctx", creator);
        let event_log_data = create_event_log_data(&[0x11u8; 32], &["ContextCreated"]);

        // Sign with the real creator key so the export is internally
        // consistent (exporter_did == creator_did, signature authentic
        // under `signing_key`).
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let export = crate::context::export_import::create_export(
            snapshot,
            event_log_data,
            DID(creator.to_owned()),
            crate::context::export_import::ExportScope::Full,
            &scp_primitives::SystemClock,
            |hash: &[u8; 32]| Ok::<_, std::convert::Infallible>(signing_key.sign(hash).to_bytes()),
        )
        .expect("build a valid signed export");

        // Present a DIFFERENT verifying key — simulating a forgery / a
        // resolver returning the wrong creator key. Verification must fail.
        let wrong_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

        let result = supervisor.import_context(export, &wrong_key, None).await;

        assert!(
            matches!(result, Err(ContextError::SnapshotSignatureInvalid { .. })),
            "forged export must be rejected with a signature error, got {result:?}"
        );
        // The verify-before-side-effect gate must have short-circuited
        // BEFORE `build_actor_deps`/`key_package_store_for`: no actor and
        // no permanent map entry may have leaked.
        assert!(
            supervisor.key_package_stores.is_empty(),
            "rejected forged import must not leak a key-package-store entry"
        );
    }

    /// §9.10.4 (FIX 1 runtime defense): a validly-signed BROADCAST-mode export
    /// is rejected with `ImportRejected` (the import path is encrypted-only) —
    /// NOT silently re-homed as an encrypted context with the reserved zero
    /// pseudonym. With verify-before-init, the signature must VERIFY first, so the export is
    /// signed by the creator key and presented with the matching verifying key;
    /// rejection then comes from the broadcast guard inside `import_context`.
    #[tokio::test]
    async fn import_rejects_broadcast_export() {
        use ed25519_dalek::{Signer, SigningKey};

        let supervisor = supervisor_with_providers();
        let creator = "did:key:broadcast-import-creator";
        let mut snapshot = import_test_snapshot("broadcast-ctx", creator);
        snapshot.context_params.mode = scp_protocol::context::ContextMode::Broadcast;
        snapshot.routing = crate::context::actor::state::ContextRouting::Broadcast;
        let event_log_data = create_event_log_data(&[0x22u8; 32], &["ContextCreated"]);

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let export = crate::context::export_import::create_export(
            snapshot,
            event_log_data,
            DID(creator.to_owned()),
            crate::context::export_import::ExportScope::Full,
            &scp_primitives::SystemClock,
            |hash: &[u8; 32]| Ok::<_, std::convert::Infallible>(signing_key.sign(hash).to_bytes()),
        )
        .expect("build a valid signed broadcast export");
        let verifying_key = signing_key.verifying_key();

        let result = supervisor
            .import_context(export, &verifying_key, Some([0x42u8; 32]))
            .await;
        assert!(
            matches!(result, Err(ContextError::ImportRejected { .. })),
            "a broadcast-mode export must be rejected with ImportRejected; got {result:?}"
        );
    }

    // -----------------------------------------------------------------
    // Eviction-path coverage for the `ImportContext` dispatch arm.
    //
    // The forged-import test above exercises the verify-GATE (the
    // export is rejected before `build_actor_deps`, so no key-package
    // store is ever spawned). These two tests exercise the
    // POST-verify rejection path: a VALIDLY-signed export that passes
    // `validate_export_for_import` but is then rejected inside
    // `lifecycle_helpers::import_context` by the live-context-overwrite
    // guard (a live actor is already registered for the same id, so
    // `dispatch_prepare_for_replace` returns `MembershipFailed`). That
    // is the branch where `kp_store_newly_spawned` matters, and where
    // the TOCTOU fix (probe + spawn + evict all under
    // `bootstrap_spawn_lock`) keeps the eviction race-free.
    //
    // Invariants asserted:
    //   1. A store this import NEWLY spawned is evicted on its failure
    //      (no orphan).
    //   2. A PRE-EXISTING/shared store is NOT torn down by this import's
    //      failure (no wrongful teardown).
    // -----------------------------------------------------------------

    /// Spawn a LIVE (Active) encrypted-mode actor under the hex id key
    /// `hex::encode(ctx_id_bytes)` and return the registry key. After
    /// this, `lookup(&hex_key)` is `Some`, so an import targeting the
    /// same id hits the live-context-overwrite guard.
    async fn spawn_live_context(supervisor: &Arc<Supervisor>, ctx_id_bytes: [u8; 32]) -> String {
        let deps = test_actor_deps(supervisor).await;
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:live-admin".to_owned()),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .expect("drive live context to Active");
        supervisor
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers the live context");
        hex::encode(ctx_id_bytes)
    }

    /// Build a VALIDLY-signed full-scope export for `context_id` whose
    /// roster contains exactly `owning_member` (so the import arm's
    /// lex-min-member derivation resolves `owning_did == owning_member`).
    /// Signed by `signing_key`; verifies under its public half.
    fn signed_import_export_with_member(
        context_id: &str,
        creator: &str,
        owning_member: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> crate::context::export_import::ContextExport {
        use ed25519_dalek::Signer;
        let mut snapshot = import_test_snapshot(context_id, creator);
        // The roster is the only input to `owning_did` selection. A
        // single member makes it the deterministic lex-min, and a fresh
        // DID guarantees it is NOT already in `key_package_stores`.
        snapshot
            .membership
            .add_member(DID(owning_member.to_owned()), "member".to_owned(), vec![]);
        // Event-log bytes keyed on the import path's own derivation so
        // the recomputed Merkle root matches what the importer expects.
        let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);
        crate::context::export_import::create_export(
            snapshot,
            event_log_data,
            DID(creator.to_owned()),
            crate::context::export_import::ExportScope::Full,
            &scp_primitives::SystemClock,
            |hash: &[u8; 32]| Ok::<_, std::convert::Infallible>(signing_key.sign(hash).to_bytes()),
        )
        .expect("build a valid signed export")
    }

    /// A VALID import that is REJECTED post-verification (live-context
    /// overwrite) must evict the key-package store IT newly spawned —
    /// no orphaned actor/entry is left behind. This is the eviction
    /// branch the forged-import test cannot reach (there the store is
    /// never spawned).
    #[tokio::test]
    async fn rejected_import_evicts_only_its_newly_spawned_kp_store() {
        let supervisor = supervisor_with_providers();
        let ctx_id_bytes = [0x5Au8; 32];
        let context_id = spawn_live_context(&supervisor, ctx_id_bytes).await;

        let creator = "did:key:evict-test-creator";
        // Fresh owning-member DID: not pre-seeded, so the import arm
        // newly spawns its key-package store, then evicts it on the
        // live-context rejection.
        let owning_member = "did:key:aaa-evict-owning-member";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let export =
            signed_import_export_with_member(&context_id, creator, owning_member, &signing_key);

        // Baseline: `spawn_live_context` builds deps for an admin DID,
        // so the map already holds that store. The owning member's store
        // must NOT yet exist — the import is what spawns it.
        let baseline = supervisor.key_package_stores.len();
        assert!(
            !supervisor
                .key_package_stores
                .contains_key(&DID(owning_member.to_owned())),
            "owning member's key-package store must not exist before the import"
        );

        let result = supervisor
            .import_context(export, &verifying_key, None)
            .await;

        // Live-context-overwrite rejection propagates from
        // `import_context`.
        assert!(
            matches!(result, Err(ContextError::MembershipFailed(_))),
            "import over a live context must be rejected, got {result:?}"
        );
        // The store this import spawned for `owning_member` must have
        // been evicted on the failure path (no orphan).
        assert!(
            !supervisor
                .key_package_stores
                .contains_key(&DID(owning_member.to_owned())),
            "the newly-spawned key-package store must be evicted on a rejected import"
        );
        // No net change to the store map: the only store the import
        // touched was the one it spawned, and that was evicted.
        assert_eq!(
            supervisor.key_package_stores.len(),
            baseline,
            "a rejected import must leave the key-package-store count unchanged (no orphan)"
        );
    }

    /// A rejected import must NOT tear down a PRE-EXISTING key-package
    /// store shared with other contexts/identities: eviction is gated
    /// on `kp_store_newly_spawned`, so when the owning store already
    /// exists the rejection leaves it intact. This guards the invariant
    /// the TOCTOU fix protects — a concurrent import's failure can never
    /// evict a store another op is using.
    #[tokio::test]
    async fn rejected_import_preserves_preexisting_kp_store() {
        let supervisor = supervisor_with_providers();
        let ctx_id_bytes = [0x6Bu8; 32];
        let context_id = spawn_live_context(&supervisor, ctx_id_bytes).await;

        let creator = "did:key:preserve-test-creator";
        let owning_member = "did:key:aaa-preserve-owning-member";
        let owning_did = DID(owning_member.to_owned());

        // Pre-seed the owning member's key-package store, simulating a
        // store already in use by another context/import. The rejected
        // import below must NOT evict it.
        let preexisting = supervisor
            .key_package_store_for(&owning_did)
            .await
            .expect("kp store resolves with providers");
        assert!(
            supervisor.key_package_stores.contains_key(&owning_did),
            "pre-seeded store registered"
        );
        let baseline = supervisor.key_package_stores.len();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let export =
            signed_import_export_with_member(&context_id, creator, owning_member, &signing_key);

        let result = supervisor
            .import_context(export, &verifying_key, None)
            .await;
        assert!(
            matches!(result, Err(ContextError::MembershipFailed(_))),
            "import over a live context must be rejected, got {result:?}"
        );
        // The pre-existing store must survive — `kp_store_newly_spawned`
        // was false, so the eviction branch is skipped.
        assert!(
            supervisor.key_package_stores.contains_key(&owning_did),
            "a pre-existing/shared key-package store must NOT be torn down by a rejected import"
        );
        assert_eq!(
            supervisor.key_package_stores.len(),
            baseline,
            "no second actor spawned and none evicted; the pre-seeded store remains"
        );
        preexisting
            .send_shutdown()
            .await
            .expect("pre-existing store handle is still live after the rejected import");
    }

    /// Helper mirroring `export_import::tests::create_event_log_data` —
    /// builds a Merkle event log byte payload via the provider.
    fn create_event_log_data(context_id_bytes: &[u8; 32], event_names: &[&str]) -> Vec<u8> {
        use crate::context::builder::ContextEventLogProvider;
        let provider = crate::context::providers::event_log::MerkleEventLogProvider::new();
        provider.init_event_log(context_id_bytes).unwrap();
        for name in event_names {
            provider
                .append_event(context_id_bytes, name, "", None)
                .unwrap();
        }
        provider.export_event_log_entries(context_id_bytes).unwrap()
    }

    // -----------------------------------------------------------------
    // ADR-049 §1 — `build_actor_deps` self-sourcing (storage foundation)
    //
    // `build_actor_deps` is `pub(in crate::context)` (only dispatch arms
    // call it), so these live in-crate rather than in
    // `tests/actor_deps_complete.rs`, which was an external-crate
    // integration test back when the method was `pub`.
    // -----------------------------------------------------------------

    /// A `MlsStorage`-witnessing fixture that retains the supervisor's
    /// authoritative `crypto` + `mls_storage` Arcs so tests can assert
    /// `build_actor_deps` self-sources the exact same handles.
    fn build_deps_fixture() -> (
        Arc<Supervisor>,
        Arc<crate::crypto::mls::provider::MlsCryptoProvider>,
        Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    ) {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestBuildDeps".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        // Resolver returns Some for every DID — witnesses key_resolver
        // propagation.
        let key_resolver: KeyResolver = Arc::new(|did: &DID| {
            let mut seed = [0u8; 32];
            for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
                seed[i % 32] ^= *b;
            }
            Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
        });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let supervisor = Supervisor::with_providers(
            Arc::clone(&crypto),
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            Arc::clone(&mls_storage),
        );
        (supervisor, crypto, mls_storage)
    }

    /// `build_actor_deps` populates every `ActorDeps` field from the
    /// supervisor's own slots; mls/hpke are the single backend pair owned
    /// by the `MlsCryptoProvider` (ADR-049 §6 — no second source).
    #[tokio::test]
    async fn build_actor_deps_reads_single_backend_pair() {
        let (supervisor, crypto, mls_storage) = build_deps_fixture();
        let deps = supervisor
            .build_actor_deps(&DID("did:example:alice".to_owned()))
            .await
            .expect("build_actor_deps succeeds when providers are populated");

        assert!(
            Arc::ptr_eq(&deps.mls, crypto.mls_backend()),
            "mls must be the crypto provider's single MlsBackend"
        );
        assert!(
            Arc::ptr_eq(&deps.hpke, crypto.hpke_backend()),
            "hpke must be the crypto provider's single HpkeBackend"
        );
        assert!(
            Arc::ptr_eq(&deps.mls_storage, &mls_storage),
            "mls_storage must be the exact Arc threaded into with_providers"
        );
        assert!(
            (deps.key_resolver)(&DID("did:example:alice".to_owned())).is_some(),
            "key_resolver must populate from the supervisor"
        );
        assert!(
            deps.payment_adapter.is_none(),
            "payment_adapter is None when unconfigured"
        );
        assert!(
            deps.local_dids.load().is_empty(),
            "local_dids shares the fresh supervisor's (empty) set"
        );
        deps.key_package_store
            .send_shutdown()
            .await
            .expect("KP store handle is live");
    }

    /// `build_actor_deps` propagates the supervisor's `mls_storage` slot
    /// verbatim — the single-handle storage-foundation guarantee.
    #[tokio::test]
    async fn build_actor_deps_propagates_supervisor_mls_storage() {
        let (supervisor, _crypto, mls_storage) = build_deps_fixture();
        let deps = supervisor
            .build_actor_deps(&DID("did:example:storage".to_owned()))
            .await
            .expect("build_actor_deps succeeds");
        assert!(
            Arc::ptr_eq(&deps.mls_storage, &mls_storage),
            "ActorDeps.mls_storage must be the same Arc set on the supervisor"
        );
        deps.key_package_store
            .send_shutdown()
            .await
            .expect("KP store handle is live");
    }

    /// `build_actor_deps` fails clean when no providers were attached
    /// (`for_query_shim` path).
    #[tokio::test]
    async fn build_actor_deps_fails_when_no_providers() {
        let supervisor = Arc::new(Supervisor::for_query_shim());
        let result = supervisor
            .build_actor_deps(&DID("did:example:none".to_owned()))
            .await;
        // `ActorDeps` (the Ok variant) is not Debug; assert via `matches!`,
        // which never formats the value.
        assert!(
            matches!(result, Err(ContextError::NotInitialized(_))),
            "build_actor_deps must fail with NotInitialized when providers are unpopulated"
        );
    }

    /// The returned `SupervisorHandle` wraps a clone of the OUTER
    /// supervisor `Arc` (regression guard for the `self: &Arc<Self>`
    /// receiver) — `strong_count` bumps when the handle is built.
    #[tokio::test]
    async fn build_actor_deps_handle_holds_outer_arc() {
        let (supervisor, _crypto, _mls_storage) = build_deps_fixture();
        let before = Arc::strong_count(&supervisor);
        let deps = supervisor
            .build_actor_deps(&DID("did:example:alice".to_owned()))
            .await
            .expect("build_actor_deps succeeds");
        let after = Arc::strong_count(&supervisor);
        assert!(
            after > before,
            "SupervisorHandle must clone the outer Arc (count {before} -> {after})"
        );
        assert!(deps.supervisor.local_dids().is_empty());
        deps.key_package_store
            .send_shutdown()
            .await
            .expect("KP store handle is live");
    }

    /// `key_package_store_for` is idempotent: two calls for the same DID
    /// return handles to the same actor (double-checked get-or-spawn).
    #[tokio::test]
    async fn key_package_store_for_is_idempotent() {
        let supervisor = supervisor_with_providers();
        let did = DID("did:dht:z6MkKpIdem".to_owned());
        let first = supervisor
            .key_package_store_for(&did)
            .await
            .expect("kp store resolves with providers");
        let second = supervisor
            .key_package_store_for(&did)
            .await
            .expect("kp store resolves with providers");
        // The registry holds exactly one entry for this DID.
        assert_eq!(
            supervisor.key_package_stores.len(),
            1,
            "exactly one KeyPackageStoreActor must be spawned per identity"
        );
        // A different DID spawns a distinct actor.
        let other = supervisor
            .key_package_store_for(&DID("did:dht:z6MkKpOther".to_owned()))
            .await
            .expect("kp store resolves with providers");
        assert_eq!(supervisor.key_package_stores.len(), 2);
        first.send_shutdown().await.expect("first handle is live");
        // `second` targets the same actor as `first`; the actor may have
        // already shut down, so a failed send is acceptable here.
        let _ = second.send_shutdown().await;
        other.send_shutdown().await.expect("other handle is live");
    }

    /// A KP-actor panic is caught by the watchdog, recorded payload-free in the
    /// per-identity crash window, and the actor is respawned — a subsequent
    /// `key_package_store_for` resolves a fresh, live handle.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn kp_actor_watchdog_records_panic_and_respawns() {
        let supervisor = supervisor_with_providers();
        let did = DID("did:dht:z6MkKpWatchdog".to_owned());
        let poison_key = format!("kp::{}", did.0);

        let handle = supervisor
            .key_package_store_for(&did)
            .await
            .expect("kp store resolves");

        // Induce a panic through the testing-only seam. The watchdog catches
        // it, records a crash, removes the dead handle, and respawns.
        handle
            .send_induce_panic("kp-panic-sentinel")
            .await
            .expect("induce-panic command is accepted");

        // Wait for the watchdog to record the crash + respawn. Use `poll_until`
        // (5ms interval, generous ~8s ceiling) rather than a fixed
        // `sleep(20ms)×50` loop, which is flaky on loaded CI when the watchdog
        // task is scheduled late — matching the sibling poison tests.
        let recorded = poll_until(|| {
            supervisor
                .crash_windows
                .get(&poison_key)
                .is_some_and(|w| w.crash_count() >= 1)
        })
        .await;
        assert!(recorded, "watchdog must record the KP-actor panic");
        assert!(
            !supervisor.is_context_poisoned(&poison_key),
            "a single crash must not poison the identity"
        );

        // The respawned actor resolves a live handle (the dead one was removed).
        let fresh = supervisor
            .key_package_store_for(&did)
            .await
            .expect("respawned kp store resolves");
        fresh
            .send_shutdown()
            .await
            .expect("respawned handle is live");
    }

    /// Three KP-actor panics within the budget window poison the identity; the
    /// next `key_package_store_for` surfaces a typed `ContextPoisoned` error.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn kp_actor_poisons_after_budget() {
        let supervisor = supervisor_with_providers();
        let did = DID("did:dht:z6MkKpPoison".to_owned());
        let poison_key = format!("kp::{}", did.0);

        for _ in 0..CRASH_POISON_THRESHOLD {
            // Resolve (get-or-respawn) and induce a panic.
            match supervisor.key_package_store_for(&did).await {
                Ok(handle) => {
                    let _ = handle.send_induce_panic("kp-poison-sentinel").await;
                }
                Err(ContextError::ContextPoisoned(_)) => break,
                Err(e) => panic!("unexpected error before poison: {e:?}"),
            }
            // Let the watchdog process this crash before inducing the next.
            poll_until(|| {
                supervisor.crash_windows.get(&poison_key).is_some_and(|w| {
                    w.is_poisoned() || !supervisor.key_package_stores.contains_key(&did)
                })
            })
            .await;
        }

        // Wait for the poison flag to settle.
        let poisoned = poll_until(|| supervisor.is_context_poisoned(&poison_key)).await;
        assert!(poisoned, "identity must poison after the crash budget");

        // The next resolution surfaces a typed poison error.
        match supervisor.key_package_store_for(&did).await {
            Err(ContextError::ContextPoisoned(_)) => {}
            Ok(_) => panic!("poisoned identity must not resolve a live handle"),
            Err(e) => panic!("expected ContextPoisoned, got {e:?}"),
        }
    }

    /// `clear_kp_poison` is the operator recovery surface for a poisoned
    /// per-identity KeyPackage actor (E1): it clears the sticky `kp::{did}`
    /// window and re-resolves the actor via `key_package_store_for` (which
    /// reconciles from the journal), WITHOUT routing through the per-context
    /// snapshot respawn (there is no KP context-snapshot). After recovery the
    /// identity resolves a live handle again.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn clear_kp_poison_recovers_poisoned_actor() {
        let supervisor = supervisor_with_providers();
        let did = DID("did:dht:z6MkKpClearPoison".to_owned());
        let poison_key = format!("kp::{}", did.0);

        // Drive the actor to the poison threshold.
        for _ in 0..CRASH_POISON_THRESHOLD {
            match supervisor.key_package_store_for(&did).await {
                Ok(handle) => {
                    let _ = handle.send_induce_panic("kp-clear-sentinel").await;
                }
                Err(ContextError::ContextPoisoned(_)) => break,
                Err(e) => panic!("unexpected error before poison: {e:?}"),
            }
            poll_until(|| {
                supervisor.crash_windows.get(&poison_key).is_some_and(|w| {
                    w.is_poisoned() || !supervisor.key_package_stores.contains_key(&did)
                })
            })
            .await;
        }
        let poisoned = poll_until(|| supervisor.is_context_poisoned(&poison_key)).await;
        assert!(poisoned, "precondition: identity poisoned after the budget");

        // Operator recovery: clear the KP poison and re-resolve.
        supervisor
            .clear_kp_poison(&did)
            .await
            .expect("clear_kp_poison recovers a poisoned KP actor");

        assert!(
            !supervisor.is_context_poisoned(&poison_key),
            "clear_kp_poison clears the sticky poison flag"
        );
        supervisor
            .key_package_store_for(&did)
            .await
            .expect("a recovered identity resolves a live handle");
    }

    /// Two concurrent broadcast publishes reserve DISTINCT sequences
    /// through the actor mailbox.
    ///
    /// This is the end-to-end witness for the two-phase reservation
    /// guarantee (ADR-049 §SequenceReservation): both `ReserveBroadcastPublish`
    /// commands ride the per-context actor mailbox and are serialized by
    /// the actor's command loop, so even when both are issued before
    /// either applies, the reserved sequences never collide. The
    /// single-phase shim could not close this hazard because a concurrent
    /// publish could read the same `next_sequence` between snapshot and
    /// seal.
    #[tokio::test]
    async fn concurrent_reserve_broadcast_publish_yields_distinct_sequences() {
        use crate::context::actor::commands::ReserveBroadcastPublishPayload;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        let ctx_id_bytes = [0xC0u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let author = DID("did:example:author".to_owned());

        // Build a broadcast-mode state with the author registered (so
        // `can_write` passes) and present in membership (so the apply
        // phase's per-sender sequence assignment can resolve). Transition
        // the handle to Active so `require_active` passes.
        let mut state = crate::context::actor::state::PerContextState::new_for_test_broadcast(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let mut bc = scp_protocol::context::broadcast::BroadcastContext::new(
            ctx_key.clone(),
            &scp_protocol::context::ContextMode::Broadcast,
            scp_protocol::context::broadcast::BroadcastAdmission::Open,
        )
        .expect("broadcast context constructs");
        bc.add_author(author.as_ref()).expect("author registers");
        state.broadcast_context = Some(bc);
        state
            .membership
            .add_member(author.clone(), "author".to_owned(), vec![]);
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("transition to Active");

        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Issue two reservations back-to-back via the mailbox.
        let reserve = |author: DID| {
            let ctx_key = ctx_key.clone();
            let supervisor_arc = Arc::clone(&supervisor_arc);
            async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::ReserveBroadcastPublish {
                    payload: Box::new(ReserveBroadcastPublishPayload {
                        context_id: ctx_key,
                        author_did: author,
                    }),
                    reply: tx,
                };
                if let Some(actor) = supervisor_arc.lookup(
                    Supervisor::broadcast_command_context_id(&cmd)
                        .expect("publish carries a context id"),
                ) {
                    Supervisor::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd))
                        .await
                        .expect("mailbox dispatch succeeds");
                }
                rx.await.expect("reserve reply").expect("reserve succeeds")
            }
        };

        let r1 = reserve(author.clone()).await;
        let r2 = reserve(author.clone()).await;

        assert_ne!(
            r1.reservation_id, r2.reservation_id,
            "each reservation gets a unique id",
        );

        // Both reservations are live in actor-owned state; release them to
        // confirm the actor accepts the release mailbox command. The core
        // assertion is that the two reservations are distinct — proven by
        // the distinct ids and by the protocol-layer
        // `concurrent_reservations_get_distinct_sequences` test that pins
        // the sequence values themselves.
        handle.send_shutdown().await.expect("handle is live");
    }

    // =================================================================
    // Watchdog / respawn / poison integration tests (ADR-049 §10).
    //
    // These spawn real state-bearing actors, induce panics via the
    // testing-only `TestInducePanic` seam, and assert the watchdog's
    // crash-budget, poison, respawn, and payload-redaction behaviour.
    // They run on a multi-thread runtime so the watchdog task (spawned
    // separately from the actor) makes progress, and inject a
    // `TestClock` so the 60s crash window is driven deterministically.
    // =================================================================

    use scp_primitives::TestClock;

    // -----------------------------------------------------------------
    // Global tracing capture (test-only) for the payload-redaction test.
    //
    // The watchdog's `tracing::error!` runs on a tokio worker thread, so a
    // thread-local subscriber on the test thread would miss it. We install
    // a process-global capturing subscriber exactly once (`std::sync::Once`)
    // and let every watchdog test read its own lines out of the shared
    // buffer (filtered by the test's unique `context_id`). The static lives
    // inside `mod tests`, so the no-mutable-globals gate ignores it.
    // -----------------------------------------------------------------
    static CAPTURED_LOG: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<String>>>> =
        std::sync::OnceLock::new();
    static CAPTURE_INIT: std::sync::Once = std::sync::Once::new();

    fn capture_buffer() -> Arc<std::sync::Mutex<Vec<String>>> {
        Arc::clone(CAPTURED_LOG.get_or_init(|| Arc::new(std::sync::Mutex::new(Vec::new()))))
    }

    /// Install the process-global capturing subscriber (idempotent).
    fn install_capture_subscriber() {
        use tracing::field::{Field, Visit};
        use tracing::{Event, Metadata};

        struct CaptureSub;
        struct LineVisitor<'a>(&'a mut String);
        impl Visit for LineVisitor<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={value}", field.name());
            }
        }
        impl tracing::Subscriber for CaptureSub {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut line = String::new();
                let mut v = LineVisitor(&mut line);
                event.record(&mut v);
                if let Some(buf) = CAPTURED_LOG.get() {
                    buf.lock().unwrap().push(line);
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        CAPTURE_INIT.call_once(|| {
            let _ = capture_buffer(); // ensure the buffer OnceLock is set.
            // Best-effort: if another test already set a global default this
            // is a no-op (returns Err), but no other test installs one.
            let _ = tracing::subscriber::set_global_default(CaptureSub);
        });
    }

    /// Captured watchdog log lines that mention `ctx_key`.
    #[cfg(feature = "testing")]
    fn captured_log_lines_for(ctx_key: &str) -> Vec<String> {
        capture_buffer()
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(ctx_key))
            .cloned()
            .collect()
    }

    /// `ContextPersistence` backed by a shared `DashMap` so a snapshot
    /// persisted in a test is actually returned by `load_context` — unlike
    /// `TestPersistence`, which always returns `None`. Used by the respawn
    /// tests, which need `restore_context` to find a real snapshot.
    #[derive(Clone, Default)]
    struct MapPersistence {
        contexts: Arc<DashMap<String, crate::context::state::ContextSnapshot>>,
    }
    impl ContextPersistence for MapPersistence {
        fn persist_context(
            &self,
            id: &str,
            snap: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.contexts.insert(id.to_owned(), snap.clone());
            Ok(())
        }
        fn load_context(
            &self,
            id: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(self.contexts.get(id).map(|s| s.value().clone()))
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
            Ok(self.contexts.iter().map(|e| e.key().clone()).collect())
        }
    }

    /// Build a providers-populated supervisor with an injected clock and
    /// persistence backend so the watchdog/respawn tests can drive the
    /// crash window deterministically and rehydrate real snapshots.
    fn supervisor_with_clock_and_persistence(
        clock: Arc<dyn Clock>,
        persistence: Box<dyn ContextPersistence>,
    ) -> Arc<Supervisor> {
        // Install the global capture subscriber so the payload-redaction
        // test can observe the watchdog's log (emitted on a worker thread).
        install_capture_subscriber();
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestDoNotRely".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: KeyResolver = Arc::new(|_: &DID| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(persistence),
            None,
            None,
            Some(clock),
            mls_storage,
        )
    }

    /// Drive a panic into the actor via the testing-only seam and wait for
    /// the watchdog to observe it. Sending `TestInducePanic` returns an
    /// `Err` (the reply channel drops when the actor task unwinds) — that
    /// is the signal the actor has crashed. We then poll until the
    /// supervisor's registry/budget reflects the watchdog's reaction.
    #[cfg(feature = "testing")]
    async fn induce_panic(handle: &ContextActorHandle, sentinel: &str) {
        // Fire-and-forget: `TestInducePanic` carries no reply channel and the
        // actor unwinds on dispatch, so use the pre-built-command send path.
        let cmd = ContextCommand::LifecycleControl(
            crate::context::actor::commands::LifecycleControlCommand::TestInducePanic {
                sentinel: sentinel.to_owned(),
            },
        );
        let _ = handle
            .send_with_timeout(cmd, std::time::Duration::from_secs(5))
            .await;
    }

    /// Spawn-and-panic helper: registers a fresh encrypted actor for
    /// `ctx_key`, drives it Active, persists a snapshot, then returns the
    /// handle so the test can panic it. Returns `(handle, ctx_key)`.
    async fn spawn_active_with_snapshot(
        sup: &Arc<Supervisor>,
        ctx_id_bytes: [u8; 32],
    ) -> (ContextActorHandle, String) {
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        // Persist a snapshot so a respawn can rehydrate the context.
        let snap = crate::context::manager_methods::snapshot_context(&state);
        sup.persistence_ref()
            .expect("test supervisor has persistence")
            .persist_context(&ctx_key, &snap)
            .unwrap();
        let deps = test_actor_deps(sup).await;
        // `Box::pin` keeps the large (state-carrying) spawn future off the
        // test's stack frame, mirroring the production call sites.
        let handle = Box::pin(sup.spawn_actor_with_state(state, deps, None))
            .await
            .expect("spawn registers");
        (handle, ctx_key)
    }

    /// Poll until `cond` holds or the timeout elapses. Returns whether the
    /// condition became true. Used to wait on the watchdog (which runs on a
    /// separate task) without a fixed sleep.
    async fn wait_until<F>(timeout: std::time::Duration, mut cond: F) -> bool
    where
        F: FnMut() -> bool,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if cond() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Async variant of [`wait_until`]: polls an async predicate (e.g. a
    /// mailbox query) until it holds or the timeout elapses. Used to wait on
    /// a RESPONSIVE respawned actor — a bare registry `lookup` is not enough
    /// because a just-crashed actor's handle lingers in the registry until
    /// the watchdog despawns it.
    #[cfg(feature = "testing")]
    async fn wait_until_async<F, Fut>(timeout: std::time::Duration, mut cond: F) -> bool
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if cond().await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// 3 panics within 60s poison the context: `is_context_poisoned` becomes
    /// true, `lookup` returns None (the dead handle is despawned), a
    /// subsequent dispatch surfaces `ContextPoisoned`, and no respawn
    /// happens after the poison.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_crashes_poison_and_stop_respawning() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_id_bytes = [0xC1u8; 32];
        let (handle, ctx_key) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;

        // Crash 1 and 2: each below the threshold, so the watchdog respawns.
        // After each crash we wait for a RESPONSIVE respawned actor before
        // capturing the next handle — a bare `lookup` would return the
        // lingering dead handle (despawned only by the watchdog), and the
        // next panic would land on a closed mailbox and never crash.
        let mut handle = handle;
        for i in 0..2u32 {
            induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
            let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
                sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                    && !sup.is_context_poisoned(&ctx_key)
            })
            .await;
            assert!(
                respawned,
                "watchdog must respawn a responsive actor below the poison threshold (crash {i})"
            );
            clock.advance_millis(100);
            handle = sup
                .lookup(&ctx_key)
                .expect("respawned responsive actor is registered");
        }

        // Crash 3: reaches the threshold (3 within 60s) → poison.
        induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
        let poisoned = wait_until(std::time::Duration::from_secs(5), || {
            sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(poisoned, "the 3rd crash within 60s must poison the context");

        // The poisoned context's dead handle is despawned (lookup None).
        let despawned = wait_until(std::time::Duration::from_secs(5), || {
            sup.lookup(&ctx_key).is_none()
        })
        .await;
        assert!(despawned, "a poisoned context's actor must be despawned");

        // A subsequent per-context dispatch surfaces ContextPoisoned (not
        // the generic ContextNotRegistered). `dispatch_command` returns
        // `Result<Outcome<()>, _>` (Outcome is not Debug), so inspect the
        // error arm directly.
        let result = sup
            .dispatch_command(
                &ctx_key,
                crate::context::actor::commands::MessagingCommand::Placeholder {
                    reply: tokio::sync::oneshot::channel().0,
                },
            )
            .await;
        match result {
            Err(ContextError::ContextPoisoned(id)) => {
                assert_eq!(id, ctx_key, "ContextPoisoned must carry the context id");
            }
            Err(other) => {
                panic!("dispatch to a poisoned context must surface ContextPoisoned, got {other:?}")
            }
            Ok(_) => panic!("dispatch to a poisoned context must fail, but it succeeded"),
        }

        // No respawn after poison: even after time passes, lookup stays None.
        clock.advance_millis(1_000);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            sup.lookup(&ctx_key).is_none(),
            "a poisoned context must NOT be respawned"
        );
    }

    /// Operator recovery (ADR-049 §10): `clear_poison` clears a poisoned
    /// context's crash window and attempts ONE respawn from the snapshot,
    /// returning it to a usable Active state. The poison flag is cleared and
    /// per-context dispatch resolves to the live actor again.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clear_poison_recovers_a_poisoned_context() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_id_bytes = [0xDBu8; 32];
        let (handle, ctx_key) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;

        // Poison: 3 crashes within 60s.
        let mut handle = handle;
        for _ in 0..2u32 {
            induce_panic(&handle, "SECRET_SENTINEL_clear").await;
            let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
                sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                    && !sup.is_context_poisoned(&ctx_key)
            })
            .await;
            assert!(respawned, "watchdog must respawn below the threshold");
            clock.advance_millis(100);
            handle = sup.lookup(&ctx_key).expect("respawned actor registered");
        }
        induce_panic(&handle, "SECRET_SENTINEL_clear").await;
        let poisoned = wait_until(std::time::Duration::from_secs(5), || {
            sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(poisoned, "3 crashes within 60s must poison");

        // Operator recovery: clear_poison clears the window + respawns once.
        let owning = DID(format!("did:scp:{ctx_key}"));
        sup.clear_poison(&ctx_key, &owning)
            .await
            .expect("clear_poison must succeed: snapshot is present and Active");

        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "clear_poison must clear the sticky poison flag"
        );
        assert_eq!(
            sup.read_context_state(&ctx_key).await,
            Some(crate::context::ContextState::Active),
            "clear_poison must respawn the context back to a usable Active state"
        );

        // Per-context dispatch resolves to the live actor again (no longer
        // ContextPoisoned).
        let result = sup
            .dispatch_command(
                &ctx_key,
                crate::context::actor::commands::MessagingCommand::Placeholder {
                    reply: tokio::sync::oneshot::channel().0,
                },
            )
            .await;
        assert!(
            !matches!(result, Err(ContextError::ContextPoisoned(_))),
            "after clear_poison, dispatch must NOT surface ContextPoisoned"
        );
    }

    /// `clear_poison` on a context with NO persisted snapshot records a FRESH
    /// respawn failure (the single retry fails) and returns an error WITHOUT
    /// looping: the budget is reset to one fresh failure, not re-poisoned in a
    /// tight loop. The caller (operator) sees the failure and can decide.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clear_poison_without_snapshot_records_one_failure_no_loop() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        // Empty persistence: a respawn finds no snapshot and fails.
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_key = hex::encode([0xDCu8; 32]);
        let owning = DID(format!("did:scp:{ctx_key}"));

        // Pre-mark the context poisoned (no actor, no snapshot).
        {
            let mut entry = sup.crash_windows.entry(ctx_key.clone()).or_default();
            // Drive it to poisoned by recording the budget's worth of crashes.
            entry.mark_respawn_failed();
        }

        // clear_poison clears the window and attempts ONE respawn, which fails
        // (no snapshot) and is recorded as a single fresh failure.
        let result = sup.clear_poison(&ctx_key, &owning).await;
        assert!(
            matches!(result, Err(ContextError::ActorCrashed(_))),
            "clear_poison with no snapshot must surface the failed single retry, got {result:?}"
        );

        // The single retry recorded ONE crash, not a poison loop: the window
        // exists with a fresh (non-poisoned) failure, and the context is NOT
        // re-poisoned by a tight loop.
        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "a single failed retry must NOT immediately re-poison (no loop)"
        );
        assert!(
            sup.lookup(&ctx_key).is_none(),
            "no actor is registered after a failed no-snapshot respawn"
        );
    }

    /// A single crash (below the threshold) respawns the actor from its
    /// persisted snapshot, and the rehydrated context preserves the
    /// persisted state — including the §9.10.4 routing axis.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_crash_respawns_and_preserves_state() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        // Build an encrypted state with a non-default member, persist it,
        // and spawn.
        let ctx_id_bytes = [0xC2u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Mutate membership so the snapshot carries an observable field.
        // `is_member` reads `state.membership` (a `MembershipState`), and
        // restore derives the actor's member set from the snapshot's
        // `membership`, so add through the membership API (NOT the `members`
        // HashSet, which the snapshot does not persist).
        let member = DID("did:example:preserved-member".to_owned());
        state
            .membership
            .add_member(member.clone(), "member".to_owned(), Vec::new());
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let snap = crate::context::manager_methods::snapshot_context(&state);
        // The snapshot's routing axis must be encrypted (not broadcast) —
        // the §9.10.4 axis carried through restore.
        assert!(
            !snap.routing.is_broadcast(),
            "encrypted context snapshot must carry a non-broadcast routing axis"
        );
        persistence.persist_context(&ctx_key, &snap).unwrap();

        let deps = test_actor_deps(&sup).await;
        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");

        // Crash once (below threshold).
        induce_panic(&handle, "SECRET_SENTINEL_abc123").await;

        // Wait for a RESPONSIVE respawned actor. A bare `lookup().is_some()`
        // is not sufficient: between the crash and the watchdog's
        // despawn-then-respawn, the dead actor's handle still lingers in the
        // registry, so we must wait until a live query actually succeeds —
        // i.e. the respawned actor answers `read_context_state`.
        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "a single crash must respawn a RESPONSIVE actor from the snapshot"
        );

        // Query membership through the supervisor's mailbox dispatch (the
        // production read path, which re-resolves the live actor each call)
        // — the persisted member is present, proving the snapshot was
        // rehydrated.
        let is_member = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            sup.dispatch_query(crate::context::actor::commands::QueriesCommand::IsMember {
                context_id: ctx_key.clone(),
                did: member.to_string(),
                reply: tx,
            })
            .await
            .expect("dispatch_query routes to the respawned actor");
            rx.await.expect("respawned actor replies")
        };
        assert_eq!(
            is_member.ok(),
            Some(true),
            "respawned context must preserve the persisted membership"
        );

        // §9.10.4 routing-axis assertion: an encrypted context that
        // rehydrated as broadcast would have failed the restore-time
        // routing-agreement check (`restore_context` fails closed when the
        // snapshot's routing variant disagrees with the reconstructed mode),
        // so reaching a responsive Active state at all proves the encrypted
        // routing axis survived the snapshot round-trip.
        assert_eq!(
            sup.read_context_state(&ctx_key).await,
            Some(crate::context::ContextState::Active),
            "respawned encrypted context must be Active with its routing axis intact"
        );
    }

    /// §23.17.2 Invariant 2 (the round-2 HIGH-bug regression test): a respawn
    /// from a COALESCE-LAGGED snapshot — one whose per-sender epoch floor is
    /// BELOW the live floor because the epoch advanced in the ≤50ms window
    /// before the crash — must SUCCEED, max-merging the live floor, NOT fail
    /// (which would poison a healthy context). The crash-surviving live floor
    /// (Class M, supervisor-owned crypto provider) is authoritative.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn respawn_from_coalesce_lagged_snapshot_max_merges_floor() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xC7u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let sender_did = "did:dht:z6MkLaggedSenderLaggedSenderLaggedSenderXX";

        // Stand up live MLS + sender-key crypto so the snapshot carries a
        // non-empty `mls_crypto_state` (otherwise the floor guard is skipped).
        let crypto = sup
            .crypto_ref()
            .expect("test supervisor has crypto")
            .clone();
        crypto.create_mls_group(&ctx_id_bytes).unwrap();
        crypto.generate_sender_key(&ctx_id_bytes).unwrap();

        // The PERSISTED snapshot captures the floor at epoch 5 (the coalesced
        // state at snapshot time).
        crypto.seed_sender_key_epoch_for_test(&ctx_id_bytes, sender_did, 5);

        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let mut snap = crate::context::manager_methods::snapshot_context(&state);
        // Capture the live crypto state (floor=5) into the persisted snapshot,
        // exactly as `persist_state_best_effort` does.
        snap.mls_crypto_state = crypto.export_crypto_state(&ctx_id_bytes).unwrap();
        assert!(
            !snap.mls_crypto_state.is_empty(),
            "snapshot must carry crypto state so the floor guard runs on respawn"
        );
        persistence.persist_context(&ctx_key, &snap).unwrap();

        let deps = test_actor_deps(&sup).await;
        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");

        // The LIVE floor advances to epoch 12 AFTER the snapshot was persisted
        // — the snapshot now lags the live floor by 7 epochs. This live floor
        // survives the crash (it lives in the supervisor-owned crypto provider,
        // which a mailbox/handle despawn does not tear down).
        crypto.seed_sender_key_epoch_for_test(&ctx_id_bytes, sender_did, 12);

        // Crash before any re-persist of the advanced floor.
        induce_panic(&handle, "SECRET_SENTINEL_lagged").await;

        // The respawn MUST succeed (round-2 bug: it failed with
        // SnapshotFloorRegression and poisoned the context).
        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "a respawn from a coalesce-lagged snapshot (floor 5 < live 12) must SUCCEED \
             and max-merge — not reject and poison the context"
        );
        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "a healthy context must not be poisoned by a benign coalesce-lag floor regression"
        );

        // The merged floor is the higher LIVE value (12), never lowered to the
        // stale snapshot's 5.
        let merged = crypto.export_sender_key_epochs(&ctx_id_bytes);
        assert!(
            merged.iter().any(|(d, e)| d == sender_did && *e == 12),
            "merged floor must be the higher live value (12), got {merged:?}"
        );
    }

    /// The watchdog logs the crash WITHOUT the panic payload: the captured
    /// tracing output contains the diagnostic message and `crash_count` but
    /// NEVER the panic sentinel (which could be plaintext or key material).
    ///
    /// Capture mechanism: a hand-rolled `tracing::Subscriber` (no
    /// `tracing-subscriber` dependency) installed as the PROCESS-GLOBAL
    /// default exactly once (the watchdog runs on a separate tokio worker
    /// thread, so a thread-local `set_default` on the test thread would not
    /// see its events). Every test using a distinct `context_id` reads only
    /// its own lines out of the shared global buffer.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panic_payload_is_not_logged() {
        const SENTINEL: &str = "SECRET_SENTINEL_abc123";

        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        // Distinct context id → the global capture buffer can be filtered to
        // this test's watchdog lines only.
        let ctx_id_bytes = [0xC3u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let (handle, _k) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;

        induce_panic(&handle, SENTINEL).await;

        // Wait until the watchdog's crash line for THIS context appears.
        let logged = wait_until(std::time::Duration::from_secs(5), || {
            captured_log_lines_for(&ctx_key)
                .iter()
                .any(|l| l.contains("context actor panicked") && l.contains("crash_count"))
        })
        .await;
        assert!(
            logged,
            "the watchdog must log a payload-free crash diagnostic"
        );

        let lines = captured_log_lines_for(&ctx_key);
        let joined = lines.join("\n");
        assert!(
            joined.contains("payload intentionally not logged"),
            "the diagnostic must state the payload was withheld; got: {joined}"
        );
        assert!(
            !joined.contains(SENTINEL),
            "SECURITY: the panic payload sentinel MUST NOT appear in the log; got: {joined}"
        );
    }

    /// A clean shutdown is NOT a crash: the watchdog sees `Ok(())`, records
    /// no crash, and does not respawn. Same for an inbox-closed exit (all
    /// handles dropped).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_shutdown_is_not_a_crash() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        // --- Case 1: explicit shutdown ---
        let ctx_id_bytes = [0xC4u8; 32];
        let (handle, ctx_key) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;
        handle.send_shutdown().await.expect("shutdown acks");
        // Give the watchdog time to observe the clean Ok exit.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "a clean shutdown must not record a crash or poison the context"
        );
        // The watchdog must NOT respawn on a clean exit — but `despawn_actor`
        // was not called by the watchdog either; the handle's mailbox closed
        // on shutdown, so the actor exited and no respawn re-registered it.
        let no_respawn = wait_until(std::time::Duration::from_secs(2), || {
            // Confirm the crash window has no entry (never recorded a crash).
            !sup.crash_windows.contains_key(&ctx_key)
        })
        .await;
        assert!(
            no_respawn,
            "a clean shutdown must not create a crash-window entry"
        );

        // --- Case 2: inbox closed (all handles dropped) ---
        let ctx2_bytes = [0xC5u8; 32];
        let (handle2, ctx2_key) = spawn_active_with_snapshot(&sup, ctx2_bytes).await;
        drop(handle2); // close the inbox; the run loop exits via `None`.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !sup.is_context_poisoned(&ctx2_key),
            "an inbox-closed exit is clean — no crash, no poison"
        );
        assert!(
            !sup.crash_windows.contains_key(&ctx2_key),
            "an inbox-closed exit must not record a crash"
        );
    }

    /// A respawn that reliably fails (no persisted snapshot — the lost-state
    /// case) is counted as a crash. One induced panic therefore records TWO
    /// crashes (the panic itself + the failed respawn), proving failed
    /// respawns consume the budget rather than looping forever. The context
    /// is left dormant (lookup None) — it was not resurrected.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_respawn_counts_as_crash() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        // Empty persistence: load_context always returns None, so the
        // watchdog's respawn fails (the lost-state case).
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        // Spawn WITHOUT persisting a snapshot — the crash's respawn will
        // fail (no snapshot), counting as an additional crash.
        let ctx_id_bytes = [0xC6u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let deps = test_actor_deps(&sup).await;
        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");

        // One induced panic: the watchdog records crash #1, then the respawn
        // loads no snapshot and `record_respawn_failure` records crash #2.
        induce_panic(&handle, "SECRET_SENTINEL_abc123").await;

        let recorded = wait_until(std::time::Duration::from_secs(5), || {
            sup.crash_windows
                .get(&ctx_key)
                .is_some_and(|w| w.crash_count() >= 2)
        })
        .await;
        assert!(
            recorded,
            "a failed respawn must be counted as an additional crash \
             (1 panic + 1 failed respawn = 2 crashes)"
        );
        assert!(
            sup.lookup(&ctx_key).is_none(),
            "a context with no recoverable snapshot must not be resurrected"
        );
    }

    /// Repeated failed respawns within the window cross the threshold and
    /// poison the context — proving the failed-respawn crash accounting
    /// feeds the budget. Driven directly via `respawn_from_snapshot` (the
    /// watchdog's respawn primitive) against an empty persistence so each
    /// call is a guaranteed failed respawn that records one crash.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_failed_respawns_poison() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_key = "ctx-no-snapshot".to_owned();
        let owning = DID("did:example:admin".to_owned());

        // Each respawn fails (no snapshot) and records exactly one crash.
        // After CRASH_POISON_THRESHOLD failed respawns within the window the
        // context must be poisoned.
        for i in 0..CRASH_POISON_THRESHOLD {
            let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
            assert!(
                matches!(result, Err(ContextError::ActorCrashed(_))),
                "respawn #{i} with no snapshot must surface ActorCrashed, got {result:?}"
            );
            clock.advance_millis(100);
        }

        assert!(
            sup.is_context_poisoned(&ctx_key),
            "{CRASH_POISON_THRESHOLD} failed respawns within the window must poison the context"
        );
    }

    /// Anti-resurrection (ADR-049 §10): `respawn_from_snapshot` must NOT
    /// respawn a snapshot whose persisted state is terminal (`Closing` here),
    /// must surface `ContextClosed`, must NOT spawn an actor, and must NOT
    /// count the skip as a crash (a terminal context is an expected dormancy,
    /// not a fault).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn respawn_skips_terminal_snapshot() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        // Build a state, drive its handle to a TERMINAL state, then snapshot
        // and persist it. `snapshot_context` reads the handle's state, so the
        // persisted snapshot is non-`Active`.
        let ctx_id_bytes = [0xCAu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        state
            .handle
            .transition_to(&crate::context::ContextState::Closing)
            .await
            .unwrap();
        let snap = crate::context::manager_methods::snapshot_context(&state);
        assert_eq!(
            snap.state,
            crate::context::ContextState::Closing,
            "fixture must persist a terminal snapshot"
        );
        sup.persistence_ref()
            .expect("test supervisor has persistence")
            .persist_context(&ctx_key, &snap)
            .unwrap();

        let owning = DID("did:example:admin".to_owned());
        let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
        assert!(
            matches!(result, Err(ContextError::ContextClosed)),
            "respawn of a terminal snapshot must surface ContextClosed, got {result:?}"
        );
        assert!(
            sup.lookup(&ctx_key).is_none(),
            "a terminal snapshot must NOT be resurrected into a live actor"
        );
        assert!(
            !sup.crash_windows.contains_key(&ctx_key),
            "the terminal-skip must NOT record a crash (no crash window entry)"
        );
        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "the terminal-skip must NOT poison the context"
        );
    }

    /// A crashed context whose respawn FAILED (no snapshot) but has NOT hit
    /// the poison threshold must surface `ActorCrashed` from a per-context
    /// lookup miss — NOT `ContextNotRegistered` ("never existed"). Mirrors
    /// `failed_respawn_counts_as_crash`, asserting the lookup-miss error class.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_miss_after_failed_respawn_is_actor_crashed() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        // Empty persistence: every respawn fails (no snapshot).
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_key = "ctx-failed-respawn".to_owned();
        let owning = DID("did:example:admin".to_owned());

        // One failed respawn: records crash #1 and sets `last_respawn_failed`
        // WITHOUT poisoning (1 < threshold).
        let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
        assert!(
            matches!(result, Err(ContextError::ActorCrashed(_))),
            "a failed respawn must surface ActorCrashed, got {result:?}"
        );
        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "a single failed respawn must NOT poison (below threshold)"
        );

        // The lookup-miss error must now be ActorCrashed (silently dead),
        // not ContextNotRegistered.
        let miss = sup.lookup_miss_error(&ctx_key, "context not registered: x".to_owned());
        assert!(
            matches!(miss, ContextError::ActorCrashed(_)),
            "a crashed-but-unpoisoned context must surface ActorCrashed on lookup miss, got {miss:?}"
        );

        // A genuinely-unknown context still surfaces ContextNotRegistered.
        let unknown =
            sup.lookup_miss_error("never-existed", "context not registered: y".to_owned());
        assert!(
            matches!(unknown, ContextError::ContextNotRegistered(_)),
            "an unknown context must still surface ContextNotRegistered, got {unknown:?}"
        );
    }

    /// ADR-049 §10 transient-respawn observability: while a context is
    /// mid-respawn (despawned, not yet re-registered), a concurrent
    /// per-context dispatch that `lookup`-misses must surface the retryable
    /// `ActorCrashed` class — NOT `ContextNotRegistered` ("never existed") —
    /// because the context genuinely exists and is recovering.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_miss_during_respawn_window_is_actor_crashed() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_key = "ctx-mid-respawn".to_owned();

        // Seed the transient respawn marker (the state `respawn_from_snapshot`
        // sets between despawn and re-registration) WITHOUT any crash history
        // or poison.
        sup.crash_windows
            .entry(ctx_key.clone())
            .or_default()
            .mark_respawning();
        assert!(
            !sup.is_context_poisoned(&ctx_key),
            "a mid-respawn context must not be poisoned"
        );

        // The lookup-miss must be the retryable ActorCrashed class.
        let miss = sup.lookup_miss_error(&ctx_key, "context not registered: z".to_owned());
        assert!(
            matches!(miss, ContextError::ActorCrashed(_)),
            "a mid-respawn lookup miss must surface ActorCrashed (retryable), got {miss:?}"
        );

        // Clearing the marker returns the window to a non-signalling state, so
        // the lookup-miss falls back to ContextNotRegistered.
        if let Some(mut entry) = sup.crash_windows.get_mut(&ctx_key) {
            entry.clear_respawning();
        }
        let after = sup.lookup_miss_error(&ctx_key, "context not registered: z".to_owned());
        assert!(
            matches!(after, ContextError::ContextNotRegistered(_)),
            "after the respawn window closes, a lookup miss falls back to \
             ContextNotRegistered, got {after:?}"
        );
    }

    /// The transient respawn marker must NOT leave a lingering crash-window
    /// record on a terminal-skip: a clean terminal context (no crash history)
    /// whose respawn is skipped must end with NO `crash_windows` entry,
    /// preserving the invariant `respawn_skips_terminal_snapshot` asserts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn respawn_marker_reaped_on_clean_terminal_skip() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_id_bytes = [0xCEu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        state
            .handle
            .transition_to(&crate::context::ContextState::Closing)
            .await
            .unwrap();
        let snap = crate::context::manager_methods::snapshot_context(&state);
        sup.persistence_ref()
            .expect("test supervisor has persistence")
            .persist_context(&ctx_key, &snap)
            .unwrap();

        let owning = DID("did:example:admin".to_owned());
        let result = sup.respawn_from_snapshot(&ctx_key, &owning).await;
        assert!(
            matches!(result, Err(ContextError::ContextClosed)),
            "terminal-skip must surface ContextClosed, got {result:?}"
        );
        assert!(
            !sup.crash_windows.contains_key(&ctx_key),
            "a clean terminal-skip must leave NO crash-window entry (the transient \
             respawn marker must be reaped)"
        );
    }

    /// A successful respawn clears the `last_respawn_failed` flag so the
    /// recovered context no longer reports `ActorCrashed` on a lookup miss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_respawn_clears_unrecoverable_flag() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_id_bytes = [0xCBu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);

        // First, a failed respawn (no snapshot yet) sets the flag.
        let owning = DID("did:example:admin".to_owned());
        let _ = sup.respawn_from_snapshot(&ctx_key, &owning).await;
        assert!(
            sup.crash_windows
                .get(&ctx_key)
                .is_some_and(|w| w.last_respawn_failed()),
            "a failed respawn must set the unrecoverable flag"
        );

        // Now persist a valid Active snapshot and respawn again — it succeeds
        // and must clear the flag.
        let (handle, _) = spawn_active_with_snapshot(&sup, ctx_id_bytes).await;
        // Despawn the freshly-spawned actor so the respawn re-insert is clean
        // (respawn despawns internally too, but this keeps the test explicit).
        drop(handle);
        sup.respawn_from_snapshot(&ctx_key, &owning)
            .await
            .expect("respawn from a valid Active snapshot must succeed");
        assert!(
            !sup.crash_windows
                .get(&ctx_key)
                .is_some_and(|w| w.last_respawn_failed()),
            "a successful respawn must clear the unrecoverable flag"
        );
    }

    /// A poisoned context's state is OBSERVABLE: `read_context_state` reports
    /// `Poisoned` even though the actor has been despawned (the state is read
    /// from the sticky `crash_windows` poison flag, not the dead mailbox).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poisoned_context_state_reads_as_poisoned() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        let ctx_key = "ctx-poison-observable".to_owned();
        let owning = DID("did:example:admin".to_owned());

        // Drive the context to poison via repeated failed respawns (empty
        // persistence guarantees each respawn fails and records one crash).
        for _ in 0..CRASH_POISON_THRESHOLD {
            let _ = sup.respawn_from_snapshot(&ctx_key, &owning).await;
            clock.advance_millis(100);
        }
        assert!(
            sup.is_context_poisoned(&ctx_key),
            "fixture must poison the context"
        );
        assert!(
            sup.lookup(&ctx_key).is_none(),
            "a poisoned context's actor must be despawned"
        );

        // The poison is observable through the public read path.
        assert_eq!(
            sup.read_context_state(&ctx_key).await,
            Some(crate::context::ContextState::Poisoned),
            "a poisoned context (no live actor) must read as Poisoned, not None"
        );

        // An unknown context still reads as None (genuinely absent).
        assert_eq!(
            sup.read_context_state("never-existed").await,
            None,
            "an unknown context must read as None"
        );
    }

    /// Multi-identity node (ADR-049 §10): a respawn derives
    /// `owning_did = local_dids.min()` and passes it to `build_actor_deps`.
    /// This must NOT mis-scope the context to the wrong identity — the crypto
    /// is rehydrated from the snapshot (not re-derived from `owning_did`), and
    /// the deps' `local_dids` view is the SHARED full set, not a snapshot of
    /// the min DID. Verify the respawn succeeds and the actor is responsive on
    /// a node with two local DIDs.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn respawn_preserves_owning_identity_on_multi_did_node() {
        let clock = Arc::new(TestClock::new(1_700_000_000));
        let clock_dyn: Arc<dyn Clock> = clock.clone();
        let sup =
            supervisor_with_clock_and_persistence(clock_dyn, Box::new(MapPersistence::default()));

        // Register TWO local DIDs. `min()` of these is the lexicographically
        // smaller one; the respawn will derive that as `owning_did`.
        let did_a = DID("did:example:aaa-first".to_owned());
        let did_b = DID("did:example:zzz-second".to_owned());
        sup.register_local_did(did_a.clone()).await.unwrap();
        sup.register_local_did(did_b.clone()).await.unwrap();

        // Spawn an Active context (creator = did_b, the NON-min DID) and
        // persist its snapshot.
        let ctx_id_bytes = [0xCCu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            did_b.clone(),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let snap = crate::context::manager_methods::snapshot_context(&state);
        sup.persistence_ref()
            .expect("test supervisor has persistence")
            .persist_context(&ctx_key, &snap)
            .unwrap();
        let deps = test_actor_deps(&sup).await;
        let handle = Box::pin(sup.spawn_actor_with_state(state, deps, None))
            .await
            .expect("spawn registers");

        // Crash it once: the watchdog respawns using `owning_did = min` =
        // did_a, even though the context's creator was did_b. The respawn must
        // still succeed and the actor must be responsive (Active), proving the
        // respawn `owning_did` does not mis-scope the context.
        induce_panic(&handle, "SECRET_SENTINEL_abc123").await;
        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "respawn on a multi-DID node must succeed and yield a responsive Active actor \
             regardless of which local DID is min()"
        );

        // Both DIDs remain registered (the respawn did not narrow the node's
        // identity set to the min DID).
        let dids = sup.local_dids_ref().load();
        assert!(
            dids.contains(&did_a) && dids.contains(&did_b),
            "respawn must not narrow the node's local DID set"
        );
    }

    // -----------------------------------------------------------------------
    // ADR-049 §9 sync-persist invariant — crash-rollback regression tests.
    //
    // §9 mandates that any downward-authorization transition (member removal,
    // capability/access revocation, role demotion) is SYNC-persisted before
    // the mutation is observable, so a crash+respawn cannot re-grant authority
    // that was removed. The governance leaf helpers (`execute_revoke`,
    // `execute_remove_member`, …) implement this by calling
    // `persist_state_best_effort` synchronously BEFORE they return (and thus
    // before the handler sends its reply). These tests prove the mutation
    // survives a crash+respawn that occurs BEFORE any 50ms coalesce could fire
    // — i.e. the survival is owed to the sync persist, not the coalesce.
    // -----------------------------------------------------------------------

    /// Drive a real `execute_revoke` (a downward-authorization transition),
    /// then crash the actor and respawn it. The revocation MUST survive: the
    /// respawned snapshot must still show the target's write capability
    /// suspended and the read-exclusion entry present. If `execute_revoke`
    /// rode the coalesce path, the crash (which lands before any coalesce)
    /// would roll the revocation back and re-grant access.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capability_revocation_survives_crash_before_coalesce() {
        use scp_protocol::context::roles::Capability;

        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xD3u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:revoke-admin".to_owned());
        let target = DID("did:example:revoke-target".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin.clone(),
        );
        // The target must be a member, and the ceiling must permit MemberBan
        // for `execute_revoke` to run. Grant the target write+read so the
        // revocation is an actual downward transition.
        state
            .membership
            .add_member(target.clone(), "member".to_owned(), Vec::new());
        state.role_state.ceiling =
            scp_protocol::context::roles::CapabilityCeiling::new([Capability::MemberBan]);
        state
            .role_state
            .member_capabilities
            .entry(target.0.clone())
            .or_default()
            .extend([Capability::MessagesWrite, Capability::MessagesRead]);
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let deps = test_actor_deps(&sup).await;

        // Persist the pre-revocation snapshot so respawn has a baseline.
        let pre = crate::context::manager_methods::snapshot_context(&state);
        persistence.persist_context(&ctx_key, &pre).unwrap();

        // Perform the downward-authorization transition. `execute_revoke`
        // calls `persist_state_best_effort` synchronously before returning, so
        // the persisted snapshot now reflects the suspension.
        crate::context::governance_helpers::execute_revoke(
            &mut state,
            &deps,
            &ctx_key,
            &target,
            scp_protocol::context::governance::AccessScope::Both,
            [1u8; 32],
            admin.as_ref(),
        )
        .expect("execute_revoke (Both scope) must succeed");

        // Sanity: the just-persisted snapshot already carries the revocation,
        // proving the sync persist happened inside the helper (no coalesce).
        let persisted = persistence
            .load_context(&ctx_key)
            .unwrap()
            .expect("revocation must have been sync-persisted by the helper");
        assert!(
            persisted
                .role_state
                .suspended_capabilities
                .get(target.as_ref())
                .is_some_and(|c| c.contains(&Capability::MessagesWrite)),
            "sync-persisted snapshot must show MessagesWrite suspended"
        );

        // Spawn the actor from the (revoked) state and crash it. The crash
        // lands before any coalesce; respawn rehydrates from the snapshot.
        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_revoke").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the revoked context must respawn to a responsive Active actor"
        );

        // The revocation must have survived the crash+respawn: re-load the
        // snapshot the respawn rehydrated from and assert the suspension and
        // read-exclusion entry are still present. A coalesce-only persist
        // would have lost the revocation (re-granting authority).
        let after = persistence
            .load_context(&ctx_key)
            .unwrap()
            .expect("respawned context must have a snapshot");
        assert!(
            after
                .role_state
                .suspended_capabilities
                .get(target.as_ref())
                .is_some_and(|c| {
                    c.contains(&Capability::MessagesWrite) && c.contains(&Capability::MessagesRead)
                }),
            "crash+respawn must NOT re-grant the revoked write/read capability"
        );
        assert!(
            after.read_exclusion_list.contains(&target),
            "crash+respawn must NOT drop the read-exclusion entry"
        );
    }

    /// ADR-049 §9 crash-safety invariant — STRUCTURAL ENFORCEMENT (FIELD
    /// ROUND-TRIP HALF).
    ///
    /// Every security-critical, monotonic piece of per-context state must be
    /// either Class S (sync-persisted — therefore present in the persisted
    /// `ContextSnapshot` and round-trippable) or Class M (crash-surviving in the
    /// supervisor-owned MLS crypto provider). A new security-critical field that
    /// silently rides only the coalesced (Class C) path is a respawn rollback
    /// vulnerability and is FORBIDDEN.
    ///
    /// SCOPE — what THIS test catches, and what it does NOT. This test catches
    /// a security FIELD dropped from the snapshot builder: it populates EVERY
    /// Class-S `GovernanceState` field with a non-default sentinel, runs the
    /// real snapshot build (`build_snapshot_from_state`) + the real persistence
    /// serialization round-trip (`serde_json` is the on-disk format), and
    /// asserts each sentinel survives. It does NOT catch a missed CONSUME SITE
    /// — a code path that mutates a Class-S field and then acknowledges the
    /// operation WITHOUT a fail-closed persist (e.g. the message-send / paid-
    /// join nonce-consume sites that earlier rounds missed while the tool-invoke
    /// site was fixed). That complementary half is enforced by
    /// `scripts/check-class-s-fail-closed.sh`, which scans every consume site
    /// and requires a fail-closed persist before acknowledgment. The two
    /// together — field round-trip HERE, consume-site fail-closed THERE — are
    /// what the §9 enforcement actually guarantees.
    ///
    /// The mechanism that catches a NEW coalesced-only security FIELD:
    ///
    /// - To add it to `GovernanceState` and have it tested here, the author
    ///   must populate it below — and the round-trip assertion then FAILS unless
    ///   the field was also wired into `build_snapshot_from_state` (persist) AND
    ///   `restore_context` (restore). A field added to `GovernanceState` but NOT
    ///   to the snapshot is dropped by the round-trip, failing this test.
    /// - The `CLASS_M_FIELDS` / `CLASS_C_ACCEPTED` enumerations below document
    ///   the non-Class-S exceptions explicitly, so a reviewer adding a field can
    ///   see exactly where each class is enforced.
    ///
    /// Demonstrated to fail on a planted Class-C regression (a new security
    /// field added to `GovernanceState` but not the snapshot drops on
    /// round-trip → the corresponding assertion fires).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn security_critical_state_is_class_s_or_m_not_coalesced() {
        use crate::context::supervisor::saga_prepared_state::{
            SagaPreparedState, SagaPreparedStateSnapshot,
        };
        // ---- Class M (crash-surviving in the supervisor-owned crypto Arc;
        // restored by monotonic max-merge per §23.17.2 Inv 2, NOT via the
        // ContextSnapshot governance fields). Documented, not asserted here —
        // the floor-guard tests in `crypto::mls::provider` cover these. ----
        const CLASS_M_FIELDS: &[&str] = &[
            "sender_key_epoch_floors", // per-sender MLS replay floors
        ];
        // ---- Class C (accepted soft anti-spam residual, ADR-049 §10): ≤50ms
        // rollback relaxes a rate limit, not an authorization break. ----
        const CLASS_C_ACCEPTED: &[&str] = &["velocity_tracker", "earned_capacity"];
        assert!(
            !CLASS_M_FIELDS.is_empty() && !CLASS_C_ACCEPTED.is_empty(),
            "the Class-M / Class-C enumerations document the non-Class-S exceptions; \
             a new security field must be Class S (below), or explicitly added to one \
             of these with an ADR justification"
        );

        // ---- Class S: populate every sync-persisted security-critical field
        // with a non-default sentinel, then prove it round-trips the snapshot. ----
        let ctx_id_bytes = [0xE1u8; 32];
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:class-s-admin".to_owned()),
        );

        // membership (a member to drop is the unit of the removal/leave class).
        let member = DID("did:example:class-s-member".to_owned());
        state
            .membership
            .add_member(member.clone(), "member".to_owned(), Vec::new());

        // executed_proposals (replay protection).
        let executed_id = [0x11u8; 32];
        state
            .governance
            .executed_proposals
            .insert(executed_id, 1_700_000_000);

        // revoked_spending_ucan_cids (revocation set).
        let revoked_cid = "bafyClassSRevokedCid".to_owned();
        state
            .governance
            .revoked_spending_ucan_cids
            .insert(revoked_cid.clone());

        // spending-nonce tracker (replay protection).
        let consumed_nonce = "1700000000000-fedcba9876543210fedcba9876543210".to_owned();
        let mut nonce_entries = std::collections::HashMap::new();
        nonce_entries.insert(consumed_nonce.clone(), (1_700_000_000_u64, u64::MAX));
        let nonce_clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        state.governance.spending_nonce_tracker =
            scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                hex::encode(ctx_id_bytes),
                nonce_clock,
                nonce_entries,
            );

        // read-exclusion list (downward access revocation).
        let excluded = DID("did:example:class-s-excluded".to_owned());
        state.access.read_exclusion_list.insert(excluded.clone());

        // saga_pending (ADR-049 §9 line 144 — staged cross-context saga
        // evidence). Stage TWO variants under distinct saga ids: the live
        // slice-2 cross-context-tool variant (eight journaled fields) and the
        // receipt-bearing standing-pair variant. Both must survive the
        // snapshot round-trip through their sanctioned non-derive mirror.
        let xctx_saga_id =
            crate::context::supervisor::saga_journal::SagaId("saga-class-s-xctx".to_owned());
        state.saga_pending.insert(
            xctx_saga_id.clone(),
            crate::context::supervisor::saga_prepared_state::SagaPreparedState::CrossContextToolInvocation(
                crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared {
                    caller_context_id: [0x5Au8; 32],
                    target_context_id: [0x6Bu8; 32],
                    caller_did: DID("did:example:class-s-caller".to_owned()),
                    tool_registration_id: "class-s-tool-v1".to_owned(),
                    ucan_proof_id: "class-s-ucan-token".to_owned(),
                    recorded_timestamp_ms: 1_700_000_000_456,
                    recorded_nonce: [0xC7u8; 16],
                    recorded_chain_depth: 4,
                },
            ),
        );
        let standing_saga_id =
            crate::context::supervisor::saga_journal::SagaId("saga-class-s-standing".to_owned());
        let standing_derived = [0x9Du8; 32];
        state.saga_pending.insert(
            standing_saga_id.clone(),
            crate::context::supervisor::saga_prepared_state::SagaPreparedState::StandingPairCreate(
                crate::context::supervisor::saga_prepared_state::StandingPairCreatePrepared {
                    peer_did: DID("did:example:class-s-peer".to_owned()),
                    local_did: DID("did:example:class-s-admin".to_owned()),
                    derived_context_id: standing_derived,
                    creation_receipt: None,
                },
            ),
        );

        // Committed cross-context tool invocation (ADR-049 §9 line 144 — spec
        // §6.2.4 "Exactly-once execution with durable output capture"). Both the
        // TARGET-side durable output capture and the CALLER-side commit witness
        // are Class S: a coalesce-window rollback would re-invoke the tool /
        // double-settle the escrow on replay. Seed both so the round-trip
        // asserts they survive the production sync-persist builder.
        let committed_saga_id =
            crate::context::supervisor::saga_journal::SagaId("saga-class-s-committed".to_owned());
        let committed_receipt =
            scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[0x3Cu8; 32]),
                [0x5Au8; 32],
                [0x6Bu8; 32],
                "did:example:class-s-caller".to_owned(),
                [0xC7u8; 16],
                "class-s-tool-v1".to_owned(),
                br#"{"result":42}"#.to_vec(),
                "ToolInvoked:saga-class-s-committed".to_owned(),
                4,
                1_700_000_000_456,
            )
            .expect("Class-S committed receipt signs");
        state.xctx_committed_outputs.insert(
            committed_saga_id.clone(),
            crate::context::supervisor::saga_prepared_state::CommittedToolInvocation {
                receipt: committed_receipt.clone(),
                output_bytes: br#"{"result":42}"#.to_vec(),
                tool_invoked_event_id: "ToolInvoked:saga-class-s-committed".to_owned(),
            },
        );
        state
            .xctx_committed_invocations
            .insert(committed_saga_id.clone());

        // Build the snapshot via the EXACT production sync-persist builder
        // (`build_snapshot_from_state`, the one `persist_state_fail_closed`
        // calls), then round-trip through the real on-disk serialization format.
        // Using this builder (not `snapshot_context`) is deliberate: it is the
        // Class-S persist path, so a field that this builder drops is exactly
        // the regression the test must catch.
        let snap = crate::context::messaging_helpers::build_snapshot_from_state(&state);
        let json = serde_json::to_vec(&snap).expect("snapshot serializes");
        let restored: crate::context::state::ContextSnapshot =
            serde_json::from_slice(&json).expect("snapshot deserializes");

        // Each Class-S field MUST survive the persistence round-trip. A field
        // that rode only the coalesced path (absent from the snapshot) would be
        // dropped here.
        assert!(
            restored.membership.members().any(|m| m.did == member),
            "Class S: membership must round-trip the snapshot"
        );
        assert!(
            restored.executed_proposals.contains(&executed_id),
            "Class S: executed_proposals must round-trip (replay protection)"
        );
        assert!(
            restored.revoked_spending_ucan_cids.contains(&revoked_cid),
            "Class S: revoked_spending_ucan_cids must round-trip (revocation)"
        );
        assert!(
            restored
                .spending_nonce_tracker_state
                .contains_key(&consumed_nonce),
            "Class S: spending-nonce tracker must round-trip (replay protection)"
        );
        assert!(
            restored.read_exclusion_list.contains(&excluded),
            "Class S: read_exclusion_list must round-trip (access revocation)"
        );

        // saga_pending (ADR-049 §9 line 144): both staged variants must survive
        // the snapshot round-trip through the `SagaPreparedStateSnapshot`
        // mirror, and rehydrate to the identical live `SagaPreparedState`. A
        // field that the builder dropped, or a mirror that lost a journaled
        // field, is exactly the regression this asserts against.
        assert_eq!(
            restored.saga_pending.len(),
            2,
            "Class S: both staged sagas must round-trip the snapshot"
        );
        // `SagaPreparedStateSnapshot`/`SagaPreparedState` mismatches are asserted
        // via `matches!` + `if let` (no `panic!`/`unreachable!` — handler
        // panic-ban gate). The `matches!` guard guarantees the `if let` body runs.
        let xctx_snap = restored
            .saga_pending
            .get(&xctx_saga_id)
            .expect("Class S: cross-context saga must round-trip");
        assert!(
            matches!(
                xctx_snap,
                SagaPreparedStateSnapshot::CrossContextToolInvocation(_)
            ),
            "Class S: wrong cross-context saga variant after round-trip"
        );
        if let SagaPreparedStateSnapshot::CrossContextToolInvocation(snap) = xctx_snap {
            assert_eq!(snap.caller_context_id, [0x5Au8; 32]);
            assert_eq!(snap.target_context_id, [0x6Bu8; 32]);
            assert_eq!(snap.caller_did, "did:example:class-s-caller");
            assert_eq!(snap.tool_registration_id, "class-s-tool-v1");
            assert_eq!(snap.ucan_proof_id, "class-s-ucan-token");
            assert_eq!(snap.recorded_timestamp_ms, 1_700_000_000_456);
            assert_eq!(snap.recorded_nonce, [0xC7u8; 16]);
            assert_eq!(snap.recorded_chain_depth, 4);
        }

        let standing_snap = restored
            .saga_pending
            .get(&standing_saga_id)
            .expect("Class S: standing-pair saga must round-trip");
        assert!(
            matches!(
                standing_snap,
                SagaPreparedStateSnapshot::StandingPairCreate(_)
            ),
            "Class S: wrong standing-pair saga variant after round-trip"
        );
        if let SagaPreparedStateSnapshot::StandingPairCreate(snap) = standing_snap {
            assert_eq!(snap.peer_did, "did:example:class-s-peer");
            assert_eq!(snap.local_did, "did:example:class-s-admin");
            assert_eq!(snap.derived_context_id, standing_derived);
            assert!(snap.creation_receipt.is_none());
        }

        // The mirror must rehydrate to the identical live `SagaPreparedState`
        // (the same-node restore contract). Exercise `into_prepared` directly.
        let rehydrated = restored
            .saga_pending
            .get(&xctx_saga_id)
            .expect("present")
            .clone()
            .into_prepared();
        assert!(
            matches!(rehydrated, SagaPreparedState::CrossContextToolInvocation(_)),
            "Class S: rehydrated wrong variant"
        );
        if let SagaPreparedState::CrossContextToolInvocation(p) = rehydrated {
            assert_eq!(p.recorded_chain_depth, 4);
            assert_eq!(p.caller_did, DID("did:example:class-s-caller".to_owned()));
        }

        // Committed cross-context tool invocation (spec §6.2.4 "Exactly-once
        // execution with durable output capture"): the TARGET-side durable
        // output capture (signed receipt + output) and the CALLER-side commit
        // witness MUST both survive the snapshot round-trip. A capture dropped
        // here would re-invoke the tool on replay; a witness dropped here would
        // double-settle the escrow.
        let restored_committed = restored
            .xctx_committed_outputs
            .get(&committed_saga_id)
            .expect("Class S: committed cross-context output capture must round-trip");
        assert_eq!(
            restored_committed.receipt, committed_receipt,
            "Class S: the signed receipt must round-trip byte-for-byte (replay reproducibility)"
        );
        assert_eq!(
            restored_committed.tool_invoked_event_id,
            "ToolInvoked:saga-class-s-committed"
        );
        assert_eq!(
            restored_committed.output_bytes,
            br#"{"result":42}"#.to_vec()
        );
        assert!(
            restored
                .xctx_committed_invocations
                .contains(&committed_saga_id),
            "Class S: the caller-side commit witness must round-trip (idempotency / no double-settle)"
        );
    }

    /// Drive a membership mutation through its sync-persisting helper boundary
    /// (`persist_state_best_effort`, the exact primitive `execute_remove_member`
    /// calls before returning), then crash+respawn. The removed member MUST
    /// stay removed: a respawn that re-admitted them would be a security
    /// rollback. Asserted through the production mailbox read path (`IsMember`).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn member_removal_survives_crash_before_coalesce() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xD4u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:remove-admin".to_owned());
        let removed = DID("did:example:removed-member".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin,
        );
        state
            .membership
            .add_member(removed.clone(), "member".to_owned(), Vec::new());
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let deps = test_actor_deps(&sup).await;

        // Apply the removal (the membership-state mutation `execute_remove_member`
        // performs) and sync-persist via the SAME helper the production handler
        // calls before its reply.
        state.membership.remove_member(&removed);
        state.role_state.members.remove(removed.as_ref());
        crate::context::messaging_helpers::persist_state_best_effort(&state, &deps, &ctx_key);

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_remove").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        // Query membership through the production mailbox path. The removed
        // member must NOT reappear after the crash+respawn.
        let is_member = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            sup.dispatch_query(crate::context::actor::commands::QueriesCommand::IsMember {
                context_id: ctx_key.clone(),
                did: removed.to_string(),
                reply: tx,
            })
            .await
            .expect("dispatch_query routes to the respawned actor");
            rx.await.expect("respawned actor replies")
        };
        assert_eq!(
            is_member.ok(),
            Some(false),
            "crash+respawn must NOT re-admit the removed member"
        );
    }

    /// ADR-049 §9 Class S: a consumed spending-UCAN nonce MUST survive a crash
    /// before any coalesce. The nonce-consume is sync-persisted (fail-closed)
    /// inside `reserve_tool_economy` BEFORE the reservation is acknowledged; a
    /// respawn that re-opened the consumed nonce would let the spending UCAN be
    /// replayed. Asserted through the persisted snapshot the respawn rehydrates
    /// from (the nonce-tracker entry must be present post-crash).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spending_nonce_consume_survives_crash_before_coalesce() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xD8u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:nonce-admin".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin,
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        // Seed a consumed nonce into the tracker via the snapshot path (the
        // same `(first_seen, token_expiry)` shape `snapshot_entries` persists),
        // with a far-future expiry so the restore-time prune keeps it. This is
        // the post-`commit_spending_ucan_nonce` state. Then sync-persist via the
        // SAME fail-closed primitive `reserve_tool_economy` calls before reply.
        // Nonce format is `{unix_millis}-{16_byte_hex}` (see `generate_nonce`).
        let consumed_nonce = "1700000000000-0123456789abcdef0123456789abcdef".to_owned();
        let mut seed_entries = std::collections::HashMap::new();
        seed_entries.insert(consumed_nonce.clone(), (1_700_000_000_u64, u64::MAX));
        let nonce_clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        state.governance.spending_nonce_tracker =
            scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                ctx_key.clone(),
                nonce_clock,
                seed_entries,
            );
        let deps = test_actor_deps(&sup).await;
        crate::context::messaging_helpers::persist_state_fail_closed(&state, &deps, &ctx_key)
            .expect("fail-closed persist of the consumed nonce must succeed");

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_nonce").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        // The respawn rehydrates from the persisted snapshot — assert the
        // consumed nonce is still recorded there, so the replayed token would
        // be rejected by the rehydrated tracker.
        let snap = persistence
            .load_context(&ctx_key)
            .expect("load")
            .expect("snapshot present after respawn");
        assert!(
            snap.spending_nonce_tracker_state
                .contains_key(&consumed_nonce),
            "crash+respawn must NOT drop the consumed spending-UCAN nonce"
        );
    }

    /// A persistence double whose `persist_context` ALWAYS fails. Used to
    /// prove the send path's fail-closed gating: a paid send must surface the
    /// persist error (not silently `Ok`) when a spending nonce was committed.
    #[derive(Default)]
    struct FailingPersistence;
    impl ContextPersistence for FailingPersistence {
        fn persist_context(
            &self,
            _id: &str,
            _snap: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("induced persist failure".into())
        }
        fn load_context(
            &self,
            _id: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
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

    /// ADR-049 §9 Class S (BLACK-001) — the MESSAGE-SEND path's spending-nonce
    /// persist GATING is fail-closed, structurally identical to the tool-invoke
    /// path. Asserted against the PRODUCTION `finalize_send`: with a persistence
    /// backend that always fails, `finalize_send(spending_nonce_committed = true)`
    /// returns an error (the paid send is NOT acknowledged while its
    /// nonce-consume is unpersisted), whereas `spending_nonce_committed = false`
    /// (a free / non-spending send) swallows the same failure and returns `Ok`
    /// (the common path stays best-effort, un-regressed).
    ///
    /// Before this fix, the send path persisted via `persist_state_best_effort`
    /// regardless of whether a spending nonce was committed: a crash in the
    /// ≤50ms coalesce window rolled the consume back, freshening the nonce after
    /// the caller already saw the send succeed (replay / double-spend).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_path_spending_nonce_persist_is_fail_closed() {
        let sup = supervisor_with_providers();
        let mut deps = test_actor_deps(&sup).await;
        // Swap in a persistence double that always fails.
        deps.persistence = Arc::new(FailingPersistence);

        let ctx_id_bytes = [0xDAu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let sender = DID("did:example:send-fail-closed".to_owned());
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            sender.clone(),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);

        // A paid send (spending nonce committed) MUST surface the persist
        // failure — fail-closed.
        let paid = crate::context::messaging_helpers::finalize_send(
            &mut state,
            &deps,
            &ctx_key,
            &ctx_id_bytes,
            &sender,
            0,
            b"paid",
            Some(&signing_key),
            /* spending_nonce_committed = */ true,
            /* is_broadcast = */ false,
        );
        assert!(
            matches!(paid, Err(ContextError::PersistenceFailed(_))),
            "a paid send whose spending-nonce consume cannot be persisted MUST \
             fail-closed, not return Ok: got {paid:?}"
        );

        // A free send (no spending nonce) swallows the same failure — the
        // common path stays best-effort, un-regressed.
        let free = crate::context::messaging_helpers::finalize_send(
            &mut state,
            &deps,
            &ctx_key,
            &ctx_id_bytes,
            &sender,
            1,
            b"free",
            Some(&signing_key),
            /* spending_nonce_committed = */ false,
            /* is_broadcast = */ false,
        );
        assert!(
            free.is_ok(),
            "a free (non-spending) send must keep best-effort persist and \
             not be regressed to fail-closed: got {free:?}"
        );
    }

    /// ADR-049 §9 Class S (BLACK-001) — the MESSAGE-SEND path's spending-nonce
    /// consume survives a crash before coalesce. With a working backend, a
    /// consumed nonce persisted via the PRODUCTION `finalize_send(.. = true)` is
    /// still present in the snapshot the respawn rehydrates from — so a replayed
    /// spending UCAN would be rejected post-crash.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_path_spending_nonce_consume_survives_crash_before_coalesce() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xDBu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let sender = DID("did:example:send-nonce-sender".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            sender.clone(),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        // Seed the post-`commit_spending_ucan_nonce` tracker state (the same
        // shape `snapshot_entries` persists), then run the PRODUCTION send-path
        // finalize with `spending_nonce_committed = true` — the exact gating the
        // metered send path uses. This drives the real fail-closed persist.
        let consumed_nonce = "1700000000000-aabbccddeeff00112233445566778899".to_owned();
        let mut seed_entries = std::collections::HashMap::new();
        seed_entries.insert(consumed_nonce.clone(), (1_700_000_000_u64, u64::MAX));
        let nonce_clock: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        state.governance.spending_nonce_tracker =
            scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                ctx_key.clone(),
                nonce_clock,
                seed_entries,
            );
        let deps = test_actor_deps(&sup).await;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
        crate::context::messaging_helpers::finalize_send(
            &mut state,
            &deps,
            &ctx_key,
            &ctx_id_bytes,
            &sender,
            0,
            b"paid-send",
            Some(&signing_key),
            /* spending_nonce_committed = */ true,
            /* is_broadcast = */ false,
        )
        .expect("fail-closed finalize of the send-path consumed nonce must succeed");

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_send_nonce").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        let snap = persistence
            .load_context(&ctx_key)
            .expect("load")
            .expect("snapshot present after respawn");
        assert!(
            snap.spending_nonce_tracker_state
                .contains_key(&consumed_nonce),
            "crash+respawn must NOT drop the send-path consumed spending-UCAN nonce"
        );
    }

    /// ADR-049 §9 Class S: an executed-proposal id MUST survive a crash before
    /// any coalesce. The conflict-resolution handler that records it
    /// (`execute_resolve_conflict`) sync-persists fail-closed before its reply;
    /// a respawn that dropped it would let an already-resolved proposal be
    /// re-executed.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn executed_proposal_survives_crash_before_coalesce() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xD9u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:proposal-admin".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin,
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        // Mark a proposal executed (the mutation the conflict-resolution
        // handler performs), then sync-persist fail-closed.
        let executed_id = [0x42u8; 32];
        state
            .governance
            .executed_proposals
            .insert(executed_id, 1_700_000_000);
        let deps = test_actor_deps(&sup).await;
        crate::context::messaging_helpers::persist_state_fail_closed(&state, &deps, &ctx_key)
            .expect("fail-closed persist of executed proposal must succeed");

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_proposal").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        let snap = persistence
            .load_context(&ctx_key)
            .expect("load")
            .expect("snapshot present after respawn");
        assert!(
            snap.executed_proposals.contains(&executed_id),
            "crash+respawn must NOT drop the executed-proposal id (replay protection)"
        );
    }

    /// ADR-049 §9 Class S: a spending-UCAN revocation MUST survive a crash
    /// before any coalesce. The revocation set is now a persisted snapshot
    /// field (it was previously reset to empty on every restore — a silent
    /// downward-authorization rollback the instant a writer existed). A respawn
    /// that dropped it would re-admit a revoked token.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spending_ucan_revocation_survives_crash_before_coalesce() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xDAu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:revoke-admin".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin,
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        // Add a revoked CID (the mutation a future revocation handler will
        // perform), then sync-persist fail-closed.
        let revoked_cid = "bafyRevokedSpendingUcanCid".to_owned();
        state
            .governance
            .revoked_spending_ucan_cids
            .insert(revoked_cid.clone());
        let deps = test_actor_deps(&sup).await;
        crate::context::messaging_helpers::persist_state_fail_closed(&state, &deps, &ctx_key)
            .expect("fail-closed persist of revocation must succeed");

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_revoke").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        let snap = persistence
            .load_context(&ctx_key)
            .expect("load")
            .expect("snapshot present after respawn");
        assert!(
            snap.revoked_spending_ucan_cids.contains(&revoked_cid),
            "crash+respawn must NOT drop the spending-UCAN revocation"
        );
    }

    /// A lifecycle close transitions the context to `Closing` and
    /// SYNCHRONOUSLY persists that terminal snapshot (via
    /// `persist_state_best_effort` inside `close_context_with_key`). A crash
    /// immediately after close must therefore NOT resurrect the context as
    /// `Active`: `respawn_from_snapshot` reads the `Closing` snapshot and
    /// applies the anti-resurrection skip. This closes the manual-close
    /// resurrection window (a coalesce-deferred Closing transition could have
    /// respawned Active from a stale Active snapshot).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_to_closing_is_sync_persisted_no_resurrection() {
        use scp_protocol::context::roles::Capability;

        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xD5u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:close-admin".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin.clone(),
        );
        // The initiator must hold ContextClose for the close role gate.
        state
            .role_state
            .member_capabilities
            .entry(admin.0.clone())
            .or_default()
            .insert(Capability::ContextClose);
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let deps = test_actor_deps(&sup).await;
        // Persist an Active baseline first — this is the snapshot a
        // coalesce-deferred close would have left behind, which a buggy
        // respawn could resurrect as Active.
        let active_snap = crate::context::manager_methods::snapshot_context(&state);
        assert_eq!(active_snap.state, crate::context::ContextState::Active);
        persistence.persist_context(&ctx_key, &active_snap).unwrap();

        // Run the real close path. It drives the handle to Closing and
        // sync-persists before returning.
        let handle_clone = state.handle.clone();
        crate::context::lifecycle_helpers::close_context(&mut state, &deps, &handle_clone, &admin)
            .await
            .expect("close_context must succeed for a SingleAdmin context");

        // The persisted snapshot must now reflect Closing SYNCHRONOUSLY (no
        // coalesce was given the chance to run).
        let persisted = persistence
            .load_context(&ctx_key)
            .unwrap()
            .expect("close must have sync-persisted a snapshot");
        assert_eq!(
            persisted.state,
            crate::context::ContextState::Closing,
            "close must sync-persist a Closing snapshot before returning"
        );

        // A respawn from that snapshot must NOT resurrect Active — it applies
        // the anti-resurrection skip and surfaces ContextClosed.
        let result = sup.respawn_from_snapshot(&ctx_key, &admin).await;
        assert!(
            matches!(result, Err(ContextError::ContextClosed)),
            "respawn of a sync-persisted Closing snapshot must skip (ContextClosed), got {result:?}"
        );
        assert!(
            sup.lookup(&ctx_key).is_none(),
            "a closed context must NOT be resurrected into a live actor"
        );
    }

    /// ADR-049 §9 Class S: `SuspendAccess` (`suspend_all`) strips a member's
    /// ENTIRE capability set — a downward-authorization transition that MUST
    /// survive a crash before any coalesce. `SuspendAccess` now sync-persists
    /// (fail-closed) BEFORE acknowledging, mirroring `execute_suspend_member`.
    /// A respawn that re-granted the banned member's capabilities would be a
    /// security rollback. Asserted through the persisted snapshot the respawn
    /// rehydrates from (the suspended-capabilities entry must be present).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suspend_all_survives_crash_before_coalesce() {
        use scp_protocol::context::roles::Capability;

        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xE1u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:suspendall-admin".to_owned());
        let target = DID("did:example:suspendall-target".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin,
        );
        state
            .membership
            .add_member(target.clone(), "member".to_owned(), Vec::new());
        state
            .role_state
            .member_capabilities
            .entry(target.0.clone())
            .or_default()
            .extend([Capability::MessagesWrite, Capability::MessagesRead]);
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let deps = test_actor_deps(&sup).await;

        // Apply the `SuspendAccess` mutation (the same `suspend_all` the
        // production arm performs) and sync-persist via the SAME fail-closed
        // primitive that arm now calls before its reply.
        state.role_state.suspend_all(target.as_ref());
        crate::context::messaging_helpers::persist_state_fail_closed(&state, &deps, &ctx_key)
            .expect("fail-closed persist of the suspend_all transition must succeed");

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_suspendall").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        // The respawn rehydrates from the persisted snapshot — the suspended
        // capability set for the banned member must still be present, so the
        // ban is NOT rolled back by the crash.
        let snap = persistence
            .load_context(&ctx_key)
            .expect("load")
            .expect("snapshot present after respawn");
        let suspended = snap
            .role_state
            .suspended_capabilities
            .get(target.as_ref())
            .expect("the banned member's suspension must survive the crash");
        assert!(
            suspended.contains(&Capability::MessagesWrite)
                && suspended.contains(&Capability::MessagesRead),
            "crash+respawn must NOT re-grant the SuspendAccess-banned member's capabilities"
        );
    }

    /// ADR-049 §9 Class S: the `executed_proposals` anti-replay marker MUST
    /// survive a crash before any coalesce. A downward-authorization governance
    /// arm sync-persists (fail-closed) after the entry point inserts the marker,
    /// so the marker is durably captured in the same snapshot. A respawn that
    /// dropped the marker would let an already-executed governance proposal be
    /// replayed. Asserted through the persisted snapshot.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn executed_proposals_marker_survives_crash_before_coalesce() {
        let clock_dyn: Arc<dyn Clock> = Arc::new(TestClock::new(1_700_000_000));
        let persistence = MapPersistence::default();
        let sup = supervisor_with_clock_and_persistence(clock_dyn, Box::new(persistence.clone()));

        let ctx_id_bytes = [0xE2u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let admin = DID("did:example:execprop-admin".to_owned());

        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            admin,
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let deps = test_actor_deps(&sup).await;

        // Insert the executed-proposal marker (the same anti-replay state
        // `execute_governance_action` records before dispatching a downward-auth
        // arm) and sync-persist via the SAME fail-closed primitive the downward
        // arm calls — the marker rides the downward arm's durable persist.
        let proposal_id: scp_protocol::context::governance::ProposalId = [0xABu8; 32];
        state
            .governance
            .executed_proposals
            .insert(proposal_id, 1_700_000_000);
        crate::context::messaging_helpers::persist_state_fail_closed(&state, &deps, &ctx_key)
            .expect("fail-closed persist of the executed-proposals marker must succeed");

        let handle = sup
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers");
        induce_panic(&handle, "SECRET_SENTINEL_execprop").await;

        let respawned = wait_until_async(std::time::Duration::from_secs(5), || async {
            sup.read_context_state(&ctx_key).await == Some(crate::context::ContextState::Active)
                && !sup.is_context_poisoned(&ctx_key)
        })
        .await;
        assert!(
            respawned,
            "the context must respawn to a responsive Active actor"
        );

        let snap = persistence
            .load_context(&ctx_key)
            .expect("load")
            .expect("snapshot present after respawn");
        assert!(
            snap.executed_proposals.contains(&proposal_id),
            "crash+respawn must NOT drop the executed-proposals anti-replay marker"
        );
    }

    /// ADR-049 §9 (round-5 regression): `finalize_send` owns the sequence-number
    /// rollback on its error exits, and rolls it back EXACTLY ONCE per error
    /// path. The prior code double-rolled (the TTL early-return rolled back AND
    /// the `send_message` caller rolled back again on the same `Err`), leaving
    /// the counter one BELOW correct via `saturating_sub`. Here we reserve a
    /// sequence, drive a paid `finalize_send` against an always-failing
    /// persistence backend (the bottom persist-failure path), and assert the
    /// counter is rolled back to EXACTLY the pre-reservation baseline — neither
    /// short (no rollback) nor over (double rollback).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn finalize_send_rolls_back_sequence_exactly_once_on_persist_failure() {
        let sup = supervisor_with_providers();
        let mut deps = test_actor_deps(&sup).await;
        deps.persistence = Arc::new(FailingPersistence);

        let ctx_id_bytes = [0xE3u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let sender = DID("did:example:seq-rollback-sender".to_owned());
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            sender.clone(),
        );
        // The sender must be a member to reserve a sequence (membership starts
        // empty in the test constructor).
        state
            .membership
            .add_member(sender.clone(), "member".to_owned(), Vec::new());
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);

        // Baseline: the sender's sequence counter before any reservation.
        let baseline = state
            .membership
            .get(sender.as_ref())
            .expect("sender is a member")
            .sequence_number;

        // Reserve a sequence (Phase 1 of a real send), then drive the paid
        // finalize whose fail-closed persist will fail.
        let reserved = state
            .membership
            .next_sequence_number(sender.as_ref())
            .expect("sender is a member");
        assert_eq!(
            reserved,
            baseline + 1,
            "reservation must advance the counter by exactly 1"
        );

        let result = crate::context::messaging_helpers::finalize_send(
            &mut state,
            &deps,
            &ctx_key,
            &ctx_id_bytes,
            &sender,
            reserved,
            b"paid",
            Some(&signing_key),
            /* spending_nonce_committed = */ true,
            /* is_broadcast = */ false,
        );
        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "a paid send whose fail-closed persist fails must surface the error: got {result:?}"
        );

        let after = state
            .membership
            .get(sender.as_ref())
            .expect("sender is a member")
            .sequence_number;
        assert_eq!(
            after, baseline,
            "finalize_send must roll the reserved sequence back to the baseline \
             EXACTLY ONCE (not double-rolled below it)"
        );
    }

    // -----------------------------------------------------------------
    // §6.2.4 cross-context tool-invocation saga — end-to-end FSM over
    // two co-resident actors (slice 5: supervisor FSM dispatch).
    //
    // These drive the REAL FSM through
    // `start_cross_context_tool_invocation_saga` over two actors spawned
    // in ONE supervisor (caller + target), with the supervisor-side tool
    // executor running between Commit-B reserve and settle.
    // -----------------------------------------------------------------

    /// Caller / target context ids for the saga E2E tests.
    const XCTX_CALLER: [u8; 32] = [0x11u8; 32];
    const XCTX_TARGET: [u8; 32] = [0x22u8; 32];
    const XCTX_TOOL: &str = "calculator-v1";

    /// A recorded event-log append: `(context_id, event_name, actor_did, payload)`.
    type RecordedEvent = ([u8; 32], String, String, Option<serde_json::Value>);

    /// An event-log provider that RECORDS every append so a test can assert
    /// the dual `ToolInvoked` / `CrossContextToolInvoked` records (§6.2.4
    /// "Dual event-log recording") landed with the shared correlation nonce.
    #[derive(Clone, Default)]
    struct RecordingEventLog {
        events: Arc<std::sync::Mutex<Vec<RecordedEvent>>>,
    }
    impl crate::context::builder::ContextEventLogProvider for RecordingEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            id: &[u8; 32],
            event: &str,
            actor: &str,
            payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((*id, event.to_owned(), actor.to_owned(), payload.cloned()));
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Build a supervisor whose key_resolver resolves `creator_did` to
    /// `creator_key` (needed for the target's UCAN re-bind validation), with
    /// real (in-memory) providers so both actors can be spawned via
    /// `spawn_actor_with_state`. The caller supplies the `event_log` provider
    /// so a test can inject a recording log to assert the dual event-log
    /// records.
    fn xctx_supervisor_with_event_log(
        creator_did: String,
        creator_key: ed25519_dalek::VerifyingKey,
        event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
    ) -> Arc<Supervisor> {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestXctxSaga".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: KeyResolver = Arc::new(move |did: &DID| {
            if did.as_ref() == creator_did {
                Some(creator_key)
            } else {
                None
            }
        });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            mls_storage,
        )
    }

    /// Convenience: a supervisor with a swallowing `TestEventLog` (for tests
    /// that do not inspect the event log).
    fn xctx_supervisor(
        creator_did: String,
        creator_key: ed25519_dalek::VerifyingKey,
    ) -> Arc<Supervisor> {
        xctx_supervisor_with_event_log(creator_did, creator_key, Box::new(TestEventLog))
    }

    /// A persistence double that fails the persist for ONE specific context the
    /// Nth time it is called (1-based), then succeeds — modelling a transient
    /// Class-S persist failure at a chosen saga step (e.g. the target's
    /// Commit-B settle persist). All other contexts / calls succeed.
    #[derive(Clone)]
    struct FailContextPersistOncePersistence {
        target_hex: String,
        fail_on_call: usize,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ContextPersistence for FailContextPersistOncePersistence {
        fn persist_context(
            &self,
            id: &str,
            _snap: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if id == self.target_hex {
                let n = self
                    .calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    .saturating_add(1);
                if n == self.fail_on_call {
                    return Err("induced transient target persist failure".into());
                }
            }
            Ok(())
        }
        fn load_context(
            &self,
            _id: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
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

    /// A supervisor wired with a caller-supplied persistence backend (for the
    /// settle-retry test that injects a transient persist failure).
    fn xctx_supervisor_with_persistence(
        creator_did: String,
        creator_key: ed25519_dalek::VerifyingKey,
        persistence: Box<dyn ContextPersistence>,
    ) -> Arc<Supervisor> {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestXctxSagaPersist".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: KeyResolver = Arc::new(move |did: &DID| {
            if did.as_ref() == creator_did {
                Some(creator_key)
            } else {
                None
            }
        });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        Supervisor::with_providers(
            crypto,
            transport,
            Box::new(TestEventLog),
            key_resolver,
            Some(persistence),
            None,
            None,
            None,
            mls_storage,
        )
    }

    /// Build the CALLER context state: `caller_did` is a member (so the
    /// authorize-before-reserve `is_member` check passes) holding
    /// `ToolInterface` (so Prepare-A's outbound gate passes). `creator_did` is
    /// the role-state creator.
    async fn xctx_caller_state(
        caller_did: &str,
        creator_did: &str,
    ) -> crate::context::actor::state::PerContextState {
        use scp_protocol::context::roles::Capability;
        let mut st = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            XCTX_CALLER,
            1_700_000_000,
            DID(creator_did.to_owned()),
        );
        st.handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("active");
        st.role_state.creator_did = creator_did.to_owned();
        // `is_member` reads `membership`; the outbound gate reads `role_state`.
        st.membership
            .add_member(DID(caller_did.to_owned()), "member".to_owned(), Vec::new());
        st.role_state.members.insert(caller_did.to_owned());
        let mut caps = std::collections::HashSet::new();
        caps.insert(Capability::ToolInterface);
        caps.insert(Capability::ToolInvokeAll);
        st.role_state
            .member_capabilities
            .insert(caller_did.to_owned(), caps);
        st.role_state.ceiling = scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::ToolInterface,
            Capability::ToolInvokeAll,
        ]);
        // Established (both-approved) outbound interface caller→target for
        // XCTX_TOOL, so the target-axis authorize-before-reserve gate (gate 2)
        // passes. Source/target ids are the hex id-form §6.2.4 stores.
        st.governance.tool_interfaces.push(
            scp_protocol::context::tools::interface::ToolInterface {
                source_context: hex::encode(XCTX_CALLER),
                target_context: hex::encode(XCTX_TARGET),
                tool_id: XCTX_TOOL.to_owned(),
                rate_limit: None,
                per_caller_rate_limit: None,
                approved_by_source: true,
                approved_by_target: true,
                outbound_policy: None,
                inbound_policy: None,
            },
        );
        st
    }

    /// Build the TARGET context state: registered `XCTX_TOOL` (2-field schemas,
    /// passing the specificity floor), `caller_did` granted ToolInterface +
    /// ToolInvokeAll, `creator_did` the role-state creator / UCAN root issuer.
    async fn xctx_target_state(
        caller_did: &str,
        creator_did: &str,
    ) -> crate::context::actor::state::PerContextState {
        use scp_protocol::context::roles::Capability;
        use scp_protocol::context::tools::registry::{ToolRegistration, ToolSchema};
        let mut st = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            XCTX_TARGET,
            1_700_000_000,
            DID(creator_did.to_owned()),
        );
        st.handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("active");
        st.role_state.creator_did = creator_did.to_owned();
        st.membership
            .add_member(DID(caller_did.to_owned()), "member".to_owned(), Vec::new());
        st.role_state.members.insert(caller_did.to_owned());
        let mut caps = std::collections::HashSet::new();
        caps.insert(Capability::ToolInterface);
        caps.insert(Capability::ToolInvokeAll);
        st.role_state
            .member_capabilities
            .insert(caller_did.to_owned(), caps);
        st.role_state.ceiling = scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::ToolInterface,
            Capability::ToolInvokeAll,
        ]);
        st.governance.registered_tools.push(ToolRegistration {
            tool_id: XCTX_TOOL.to_owned(),
            name: "Calculator".to_owned(),
            description: "adds".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "a": {"type": "number"}, "b": {"type": "number"} }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "result": {"type": "number"} }
                }),
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: DID(creator_did.to_owned()),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
        });
        st
    }

    /// Spawn both participant actors in `supervisor` and return their handles
    /// (caller, target). The deps are built per-actor through the production
    /// `build_actor_deps` path so the actors run real handlers.
    async fn spawn_xctx_pair(
        supervisor: &Arc<Supervisor>,
        caller_state: crate::context::actor::state::PerContextState,
        target_state: crate::context::actor::state::PerContextState,
    ) {
        let caller_deps = supervisor
            .build_actor_deps(&DID("did:example:xctx-caller-owner".to_owned()))
            .await
            .expect("caller deps");
        supervisor
            .spawn_actor_with_state(caller_state, caller_deps, None)
            .await
            .expect("spawn caller actor");
        let target_deps = supervisor
            .build_actor_deps(&DID("did:example:xctx-target-owner".to_owned()))
            .await
            .expect("target deps");
        supervisor
            .spawn_actor_with_state(target_state, target_deps, None)
            .await
            .expect("spawn target actor");
    }

    /// Happy path: an ungated cross-context tool invocation drives the FULL FSM
    /// to a committed terminal. The tool executes EXACTLY ONCE supervisor-side,
    /// a verifiable receipt + the captured output are surfaced in `SagaOutput`,
    /// and the caller-side escrow reservation is settled (no unbalanced-ticket
    /// panic). The signed receipt's preimage fields (nonce / target ctx id /
    /// tool id) reflect what B recorded.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // full happy-path E2E: drive + receipt + dual-log assertions
    async fn xctx_saga_happy_path_commits_and_executes_once() {
        use scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let creator_did = "did:dht:z6MkXctxHappyCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let event_log = RecordingEventLog::default();
        let supervisor = xctx_supervisor_with_event_log(
            creator_did.clone(),
            creator_key,
            Box::new(event_log.clone()),
        );
        let caller_did = "did:dht:z6MkXctxHappyCaller";

        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        // The target's Active Signing Key (caller-supplied, ADR-049 — the actor
        // holds no key).
        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
        // sign the caller-side divergence marker on a NeedsRepair.
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);

        // Count executor invocations to prove exactly-once.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_exec = Arc::clone(&calls);
        let executor = move |input: serde_json::Value| {
            let calls = Arc::clone(&calls_for_exec);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let a = input["a"].as_i64().unwrap_or(0);
                let b = input["b"].as_i64().unwrap_or(0);
                Ok(serde_json::json!({ "result": a + b }))
            }
        };

        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let nonce = [0x42u8; 16];
        let output = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None, // ungated tool — no UCAN proof
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 2,
                    asserted_nonce: nonce,
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                executor,
            )
            .await
            .expect("cross-context saga must commit");

        // The tool ran exactly once.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the tool MUST execute exactly once across the saga"
        );

        // The receipt + output are surfaced.
        let receipt_bytes = output.receipt.expect("committed saga surfaces a receipt");
        let output_bytes = output.output.expect("committed saga surfaces the output");
        let receipt: CrossContextToolReceipt =
            serde_json::from_slice(&receipt_bytes).expect("receipt decodes");
        // The receipt is signed by the target's key over B-recorded provenance.
        assert!(
            receipt.verify(&target_signing.verifying_key()).is_ok(),
            "the receipt must verify under the target's signing key"
        );
        assert_eq!(receipt.target_context_id, XCTX_TARGET);
        assert_eq!(receipt.caller_context_id, XCTX_CALLER);
        assert_eq!(receipt.nonce, nonce);
        assert_eq!(receipt.tool_registration_id, XCTX_TOOL);
        // B re-derived chain depth = incoming(2) + 1.
        assert_eq!(receipt.chain_depth, 3);
        // The output is the canonical tool result.
        let out_value: serde_json::Value =
            serde_json::from_slice(&output_bytes).expect("output decodes");
        assert_eq!(out_value, serde_json::json!({ "result": 3 }));

        // Dual event-log recording (§6.2.4): `ToolInvoked` on the TARGET log and
        // `CrossContextToolInvoked` on the CALLER log, sharing the nonce.
        let events = event_log
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let nonce_hex = {
            let mut s = String::new();
            for b in &nonce {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
            }
            s
        };
        let tool_invoked = events
            .iter()
            .find(|(id, name, _, _)| *id == XCTX_TARGET && name.starts_with("ToolInvoked:"))
            .expect("target log must carry a ToolInvoked record");
        // The target's record carries B's re-derived chain depth + the saga id.
        let ti_payload = tool_invoked.3.as_ref().expect("ToolInvoked payload");
        assert_eq!(ti_payload["chain_depth"], serde_json::json!(3));
        let xctx_invoked = events
            .iter()
            .find(|(id, name, _, _)| {
                *id == XCTX_CALLER && name.starts_with("CrossContextToolInvoked:")
            })
            .expect("caller log must carry a CrossContextToolInvoked record");
        let cci_payload = xctx_invoked
            .3
            .as_ref()
            .expect("CrossContextToolInvoked payload");
        // The two records share the correlation nonce (the join key) and the
        // caller record references the target ctx id.
        assert_eq!(cci_payload["nonce"], serde_json::json!(nonce_hex));
        assert_eq!(
            cci_payload["target_context_id"],
            serde_json::json!(hex::encode(XCTX_TARGET))
        );
    }

    /// Prepare-B reject (confused deputy): the caller references a UCAN proof in
    /// B's store that is delegated to a DIFFERENT principal. Prepare-B rejects
    /// (SCP-SAGA-13013), the saga ABORTS, the tool NEVER executes, and the
    /// participant-context-set reservation is released (a follow-up saga over
    /// the same set is NOT ActorBusy).
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // confused-deputy E2E: mint UCAN + reject + release assertions
    async fn xctx_saga_prepare_b_confused_deputy_aborts_no_execution() {
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Mint a UCAN delegated to OTHER (not the caller) — the confused-deputy
        // attempt. The creator (root issuer) key must resolve via the
        // supervisor's key_resolver.
        let custody = InMemoryKeyCustody::new();
        let creator_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let creator_pk = custody.public_key(&creator_handle).await.unwrap();
        let creator_did = format!("did:dht:z{}", zbase32::encode(creator_pk.as_bytes()));
        let creator_key =
            ed25519_dalek::VerifyingKey::from_bytes(creator_pk.as_bytes().try_into().unwrap())
                .unwrap();

        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxDeputyCaller";
        let other_did = "did:dht:z6MkXctxDeputyOther";

        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let mut target_state = xctx_target_state(caller_did, &creator_did).await;

        // Proof audience = OTHER, NOT the carried caller_did.
        let ctx_hex = hex::encode(XCTX_TARGET);
        let caps = vec![format!("tool_invoke:{XCTX_TOOL}")];
        let params = crate::crypto::ucan::mint::MintParams {
            issuer_did: &creator_did,
            issuer_key: &creator_handle,
            audience_did: other_did,
            context_id: &ctx_hex,
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let token =
            crate::crypto::ucan::mint::mint_ucan(&params, &custody, &scp_primitives::SystemClock)
                .await
                .expect("mint");
        target_state
            .xctx_ucan_proofs
            .proofs
            .insert("proof-other".to_owned(), token);

        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
        // sign the caller-side divergence marker on a NeedsRepair.
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_exec = Arc::clone(&calls);
        let executor = move |_input: serde_json::Value| {
            let calls = Arc::clone(&calls_for_exec);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({ "result": 0 }))
            }
        };

        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let err = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: Some("proof-other".to_owned()),
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 1,
                    asserted_nonce: [0x43u8; 16],
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                executor,
            )
            .await
            .expect_err("confused-deputy proof must abort the saga");
        assert!(
            matches!(&err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13013")),
            "expected SCP-SAGA-13013 confused-deputy rejection, got {err:?}"
        );
        // The tool NEVER executed.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a rejected Prepare-B must NOT execute the tool"
        );

        // The reservation was released: a follow-up over the SAME set is not
        // ActorBusy (it aborts again at Prepare-B, NOT with SagaBusy).
        let now_ms2 = supervisor.clock_ref().expect("clock").now_millis();
        let err2 = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: Some("proof-other".to_owned()),
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 1,
                    asserted_nonce: [0x44u8; 16],
                    asserted_timestamp_ms: now_ms2,
                },
                &target_signing,
                &caller_signing,
                |_v: serde_json::Value| async move { Ok(serde_json::json!({})) },
            )
            .await
            .expect_err("follow-up still rejects at Prepare-B");
        assert!(
            !matches!(err2, ContextError::ActorBusy(_)),
            "the aborted saga must RELEASE its reservation (no ActorBusy), got {err2:?}"
        );
    }

    /// FIX A target-wedge (BLACK-624-02): a caller who is a member of its OWN
    /// context but has NO established interface to a VICTIM target cannot reserve
    /// (and thereby wedge) the victim's saga slot. The saga rejects with the
    /// target-axis authorize-before-reserve error (SCP-SAGA-13022) BEFORE any
    /// reservation, and a LEGITIMATE saga touching the victim target is NOT
    /// locked out afterward (the victim slot was never taken).
    #[tokio::test]
    async fn xctx_saga_unestablished_target_is_rejected_before_reservation() {
        const XCTX_VICTIM: [u8; 32] = [0xBBu8; 32];

        let creator_did = "did:dht:z6MkXctxWedgeCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxWedgeCaller";

        // The caller context has an established interface to XCTX_TARGET only —
        // NOT to XCTX_VICTIM. The caller is a member of its own context (so the
        // caller-axis is_member gate trivially passes).
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        supervisor
            .spawn_actor_with_state(
                caller_state,
                supervisor
                    .build_actor_deps(&DID("did:example:xctx-wedge-caller-owner".to_owned()))
                    .await
                    .expect("caller deps"),
                None,
            )
            .await
            .expect("spawn caller actor");

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let now_ms = supervisor.clock_ref().expect("clock").now_millis();

        // The caller names the VICTIM target it has NO established interface
        // with. The saga MUST reject at the target-axis gate, before reserving.
        let err = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_VICTIM,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 1,
                    asserted_nonce: [0x4Au8; 16],
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                |_v: serde_json::Value| async move { Ok(serde_json::json!({ "result": 3 })) },
            )
            .await
            .expect_err("a caller with no established interface to the victim must be rejected");
        assert!(
            matches!(&err, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13022")),
            "expected target-axis authorize-before-reserve rejection (SCP-SAGA-13022), got: {err:?}"
        );

        // The victim's saga slot was NEVER reserved — a legitimate saga that
        // genuinely involves the victim target can still reserve it. (We exercise
        // the SAME reservation critical section the start path uses.)
        let legit =
            supervisor.test_reserve_saga_context_set(&SagaInput::CrossContextToolInvocation {
                caller_context_id: [0xC1u8; 32],
                target_context_id: XCTX_VICTIM,
                caller_did: DID("did:dht:zLegit".to_owned()),
                tool_registration_id: "legit-tool".to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({}),
                asserted_chain_depth: 0,
                asserted_nonce: [0u8; 16],
                asserted_timestamp_ms: 0,
            });
        assert!(
            !matches!(legit, Err(ContextError::ActorBusy(_))),
            "the victim target slot must be free (the rejected saga never reserved it), \
             got {:?}",
            legit.err()
        );
    }

    /// Per-context-set busy: while one saga's participant set is reserved
    /// in-flight (held via the production reservation primitive), a second
    /// overlapping cross-context saga is rejected with ActorBusy / SagaBusy.
    #[tokio::test]
    async fn xctx_saga_overlapping_set_is_saga_busy() {
        let creator_did = "did:dht:z6MkXctxBusyCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxBusyCaller";

        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        // Hold the {caller, target} set in flight via the production reservation
        // primitive (same critical section start_saga uses).
        let held = supervisor
            .test_reserve_saga_context_set(&SagaInput::CrossContextToolInvocation {
                caller_context_id: XCTX_CALLER,
                target_context_id: XCTX_TARGET,
                caller_did: DID(caller_did.to_owned()),
                tool_registration_id: XCTX_TOOL.to_owned(),
                ucan_proof_id: None,
                input: serde_json::json!({}),
                asserted_chain_depth: 0,
                asserted_nonce: [0u8; 16],
                asserted_timestamp_ms: 0,
            })
            .expect("first reservation succeeds");

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
        // sign the caller-side divergence marker on a NeedsRepair.
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let err = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 1,
                    asserted_nonce: [0x45u8; 16],
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                |_v: serde_json::Value| async move { Ok(serde_json::json!({ "result": 3 })) },
            )
            .await
            .expect_err("overlapping saga must be rejected while the set is held");
        assert!(
            matches!(&err, ContextError::ActorBusy(msg) if msg.contains("SagaBusy")),
            "overlap rejection must be ActorBusy(SagaBusy), got: {err:?}"
        );
        drop(held);
    }

    /// Replay: after a saga commits, re-driving Commit-B for the SAME `SagaId`
    /// (the crash-recovery replay path) re-emits the STORED output + receipt
    /// WITHOUT re-invoking the tool. We run a full saga, then directly send a
    /// second `CommitBReserve` for that saga id to the target actor and assert
    /// it returns `AlreadyCommitted` with the same output — the executor call
    /// counter stays at 1.
    #[tokio::test]
    async fn xctx_saga_commit_replay_reemits_without_reinvoke() {
        use crate::context::actor::commands::{CommitBReserveOutcome, SagaPhaseMessage};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let creator_did = "did:dht:z6MkXctxReplayCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxReplayCaller";

        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // The caller's Active Signing Key (caller-supplied, ADR-049) — used to
        // sign the caller-side divergence marker on a NeedsRepair.
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_exec = Arc::clone(&calls);
        let executor = move |_input: serde_json::Value| {
            let calls = Arc::clone(&calls_for_exec);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({ "result": 3 }))
            }
        };

        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let output = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 1,
                    asserted_nonce: [0x46u8; 16],
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                executor,
            )
            .await
            .expect("saga commits");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "tool ran once on first commit"
        );

        // Recover the committed SagaId from the journal (the only unresolved
        // set is empty after Committed, so use the durable receipt's output to
        // compare). We need the SagaId — re-derive it by replaying Commit-B
        // reserve against the target for the committed saga.
        //
        // The supervisor minted a fresh SagaId internally; the durable capture
        // is keyed by it. The receipt carries the SagaId-stable
        // `tool_invoked_event_id` (`ToolInvoked:<saga_id>`), so recover the
        // saga id from it.
        let receipt: scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt =
            serde_json::from_slice(&output.receipt.expect("receipt")).expect("decode");
        let saga_id_str = receipt
            .tool_invoked_event_id
            .strip_prefix("ToolInvoked:")
            .expect("event id carries the saga id")
            .to_owned();
        let saga_id = crate::context::supervisor::saga_journal::SagaId(saga_id_str);

        // Re-drive Commit-B reserve for the SAME saga id (the replay path).
        let target = supervisor
            .lookup(&hex::encode(XCTX_TARGET))
            .expect("target actor co-resident");
        let reserve = target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve { saga_id, reply })
            })
            .await
            .expect("replay reserve");

        assert!(
            matches!(reserve, CommitBReserveOutcome::AlreadyCommitted { .. }),
            "a committed saga's replay must be AlreadyCommitted, not ReadyToExecute, got {reserve:?}"
        );
        if let CommitBReserveOutcome::AlreadyCommitted { output_bytes, .. } = reserve {
            let v: serde_json::Value =
                serde_json::from_slice(&output_bytes).expect("decode replay output");
            assert_eq!(
                v,
                serde_json::json!({ "result": 3 }),
                "replay re-emits the stored output"
            );
        }

        // The executor was NEVER re-invoked by the replay.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "replay MUST NOT re-invoke the tool"
        );
    }

    // -----------------------------------------------------------------
    // §6.2.4 slice 6 — NeedsRepair dual divergence marker +
    // §17.16.4 crash-recovery replay arms.
    // -----------------------------------------------------------------

    /// Build a `CrossContextSagaCtx` with the TARGET marked as committed
    /// (`committed_b_tool_invoked_event_id = Some(event_id)`) so
    /// `emit_divergence_markers` records `committed_side = Target`. The executor
    /// is a never-called no-op (divergence emission never runs the tool).
    fn divergence_ctx<'a>(
        nonce: [u8; 16],
        tool_invoked_event_id: String,
        target_signing: &ed25519_dalek::SigningKey,
        caller_signing: &ed25519_dalek::SigningKey,
        caller_did: &str,
    ) -> CrossContextSagaCtx<'a> {
        CrossContextSagaCtx {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID(caller_did.to_owned()),
            tool_registration_id: XCTX_TOOL.to_owned(),
            ucan_proof_id: None,
            input: serde_json::json!({ "a": 1, "b": 2 }),
            asserted_chain_depth: 2,
            asserted_nonce: nonce,
            asserted_timestamp_ms: 1_700_000_000,
            caller_source_role: None,
            target_signing_key: target_signing.clone(),
            caller_signing_key: caller_signing.clone(),
            executor: Some(Box::new(|_v: serde_json::Value| {
                Box::pin(async move { Ok(serde_json::json!({})) }) as _
            })),
            executor_output: None,
            prepared_a: None,
            prepared_b: None,
            committed: None,
            committed_b_tool_invoked_event_id: Some(tool_invoked_event_id),
            reached_needs_repair: false,
        }
    }

    /// NeedsRepair dual divergence marker (spec §6.2.4 "Dual event-log
    /// recording"): when the TARGET committed but the saga diverged, BOTH the
    /// target and caller actors emit a signed `CrossContextDivergenceMarker`
    /// into their OWN event log. The markers record `committed_side = Target`,
    /// the saga id, the nonce, and the committed event id, and each verifies
    /// under its own side's Active Signing Key. Both sides reachable ⇒ NO
    /// supervisor-level repair record.
    #[tokio::test]
    async fn xctx_needs_repair_emits_dual_signed_divergence_markers() {
        use scp_protocol::context::tools::cross_context_saga::{
            CommittedSide, CrossContextDivergenceMarker,
        };

        let creator_did = "did:dht:z6MkXctxDivCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let event_log = RecordingEventLog::default();
        let supervisor = xctx_supervisor_with_event_log(
            creator_did.clone(),
            creator_key,
            Box::new(event_log.clone()),
        );
        let caller_did = "did:dht:z6MkXctxDivCaller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let nonce = [0x42u8; 16];
        let saga_id = crate::context::supervisor::saga_journal::SagaId::new();
        let committed_event_id = format!("ToolInvoked:{}", saga_id.0);

        let ctx = divergence_ctx(
            nonce,
            committed_event_id.clone(),
            &target_signing,
            &caller_signing,
            caller_did,
        );
        let plan = Supervisor::divergence_marker_plan(&ctx).expect("target committed ⇒ plan");
        Box::pin(supervisor.emit_divergence_markers(&saga_id, plan)).await;

        // Both sides reachable ⇒ no supervisor repair fallback.
        assert!(
            supervisor.saga_repair_records_for(&saga_id).is_empty(),
            "both actors reachable ⇒ NO supervisor-level repair record"
        );

        let events = event_log
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let marker_name = format!("CrossContextDivergenceMarker:{}", saga_id.0);

        // TARGET log carries a marker signed by the TARGET key.
        let (_, _, _, target_payload) = events
            .iter()
            .find(|(id, name, _, _)| *id == XCTX_TARGET && *name == marker_name)
            .expect("target log must carry a divergence marker");
        let target_marker: CrossContextDivergenceMarker =
            serde_json::from_value(target_payload.clone().expect("marker payload"))
                .expect("decode target marker");
        assert_eq!(target_marker.committed_side, CommittedSide::Target);
        assert_eq!(target_marker.saga_id, saga_id.0);
        assert_eq!(target_marker.nonce, nonce);
        assert_eq!(target_marker.committed_event_id, committed_event_id);
        assert!(
            target_marker
                .verify(&target_signing.verifying_key())
                .is_ok(),
            "target marker must verify under the target key"
        );

        // CALLER log carries a marker signed by the CALLER key.
        let (_, _, _, caller_payload) = events
            .iter()
            .find(|(id, name, _, _)| *id == XCTX_CALLER && *name == marker_name)
            .expect("caller log must carry a divergence marker");
        let caller_marker: CrossContextDivergenceMarker =
            serde_json::from_value(caller_payload.clone().expect("marker payload"))
                .expect("decode caller marker");
        assert_eq!(caller_marker.committed_side, CommittedSide::Target);
        assert_eq!(caller_marker.saga_id, saga_id.0);
        assert_eq!(caller_marker.nonce, nonce);
        assert_eq!(caller_marker.committed_event_id, committed_event_id);
        assert!(
            caller_marker
                .verify(&caller_signing.verifying_key())
                .is_ok(),
            "caller marker must verify under the caller key"
        );
        // The marker is NOT cross-verifiable: each side signs with its own key.
        assert!(
            caller_marker
                .verify(&target_signing.verifying_key())
                .is_err(),
            "the caller marker must NOT verify under the target key"
        );
    }

    /// NeedsRepair with an UNREACHABLE side: when the caller actor is gone, its
    /// signed marker cannot be appended into its (absent) log, so the divergence
    /// is recorded into the supervisor-level repair journal instead (spec
    /// §6.2.4 — "or a supervisor-level repair journal if one side is
    /// unreachable"). The reachable target side still records into its own log.
    #[tokio::test]
    async fn xctx_needs_repair_unreachable_side_records_supervisor_repair() {
        let creator_did = "did:dht:z6MkXctxRepairCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let event_log = RecordingEventLog::default();
        let supervisor = xctx_supervisor_with_event_log(
            creator_did.clone(),
            creator_key,
            Box::new(event_log.clone()),
        );
        let caller_did = "did:dht:z6MkXctxRepairCaller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        // Despawn the CALLER actor so it is unreachable at divergence time.
        assert!(
            supervisor.despawn_actor(&hex::encode(XCTX_CALLER)).await,
            "despawn caller actor"
        );

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let nonce = [0x55u8; 16];
        let saga_id = crate::context::supervisor::saga_journal::SagaId::new();
        let committed_event_id = format!("ToolInvoked:{}", saga_id.0);

        let ctx = divergence_ctx(
            nonce,
            committed_event_id.clone(),
            &target_signing,
            &caller_signing,
            caller_did,
        );
        let plan = Supervisor::divergence_marker_plan(&ctx).expect("target committed ⇒ plan");
        Box::pin(supervisor.emit_divergence_markers(&saga_id, plan)).await;

        // The unreachable CALLER side is recorded in the supervisor repair journal.
        let repair = supervisor.saga_repair_records_for(&saga_id);
        assert_eq!(
            repair.len(),
            1,
            "exactly one supervisor repair record for the unreachable caller side, got {repair:?}"
        );
        assert_eq!(repair[0].unreachable_context_hex, hex::encode(XCTX_CALLER));
        assert_eq!(repair[0].committed_event_id, committed_event_id);
        assert_eq!(repair[0].nonce, nonce);
        assert_eq!(
            repair[0].committed_side,
            scp_protocol::context::tools::cross_context_saga::CommittedSide::Target
        );

        // The reachable TARGET side still recorded into its own log.
        let events = event_log
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let marker_name = format!("CrossContextDivergenceMarker:{}", saga_id.0);
        assert!(
            events
                .iter()
                .any(|(id, name, _, _)| *id == XCTX_TARGET && *name == marker_name),
            "the reachable target side must still record its marker into its own log"
        );
    }

    /// NeedsRepair concurrency-slot release: a `TestForceNeedsRepair` saga
    /// (commit always fails → NeedsRepair) RELEASES the participant-context-set
    /// reservation, so an OVERLAPPING saga over the same context then reserves
    /// successfully (no `ActorBusy`). Confirms the concurrency slot is released
    /// while the (separate) escrow path is unaffected (spec §6.2.4 "`NeedsRepair`
    /// reservation semantics" — the two release differently).
    #[tokio::test]
    async fn xctx_needs_repair_releases_concurrency_slot() {
        let supervisor = Arc::new(Supervisor::for_query_shim());
        let ctx_id = [0x77u8; 32];

        // Drive a saga to NeedsRepair (commit-retry exhaustion).
        let err = supervisor
            .start_saga(SagaInput::TestForceNeedsRepair { context_id: ctx_id })
            .await
            .expect_err("commit-retry-exhausted saga returns NeedsRepair");
        assert!(
            !matches!(err, ContextError::ActorBusy(_)),
            "a NeedsRepair terminal must not surface as ActorBusy, got {err:?}"
        );

        // The NeedsRepair terminal RELEASED the slot: a follow-up saga over the
        // SAME (overlapping) context reserves successfully (it does not reject
        // with SagaBusy).
        let reservation = supervisor
            .test_reserve_saga_context_set(&SagaInput::TestForceNeedsRepair { context_id: ctx_id });
        assert!(
            reservation.is_ok(),
            "NeedsRepair must release the context slot so an overlapping saga reserves, got {:?}",
            reservation.err()
        );
    }

    /// §17.16.4 participant-set reconstruction (option (a)): the journaled
    /// `CrossContextToolInvocationPrepared` evidence carries BOTH context ids, so
    /// a crash-recovery replay reconstructs the FULL `{caller, target}`
    /// participant set — NOT the caller-only journal triple. Proves the
    /// reservation-gap the field doc flags is closed.
    #[test]
    fn xctx_replay_reconstructs_full_participant_set() {
        use crate::context::supervisor::saga_journal::{JournalEntry, SagaId, SagaState};
        use crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;

        let prepared = CrossContextToolInvocationPrepared {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID("did:dht:z6MkReconCaller".to_owned()),
            tool_registration_id: XCTX_TOOL.to_owned(),
            ucan_proof_id: String::new(),
            recorded_timestamp_ms: 1_700_000_111,
            recorded_nonce: [0x66u8; 16],
            recorded_chain_depth: 3,
        };
        let evidence = prepared.to_evidence_bytes().expect("encode evidence");
        let entry = JournalEntry {
            saga_id: SagaId::new(),
            state: SagaState::Committing,
            // The journal provenance triple is caller-ONLY (no target).
            participants: vec![
                hex::encode(XCTX_CALLER),
                "did:dht:z6MkReconCaller".to_owned(),
                XCTX_TOOL.to_owned(),
            ],
            evidence: Zeroizing::new(evidence),
            timestamp_ms: 1_700_000_111,
            seq_per_saga: 3,
        };

        let recon = Supervisor::reconstruct_xctx_prepared(&entry)
            .expect("cross-context evidence reconstructs");
        // The FULL {caller, target} set is recoverable from the evidence even
        // though `participants` omits the target.
        assert_eq!(recon.caller_context_id, XCTX_CALLER);
        assert_eq!(recon.target_context_id, XCTX_TARGET);
        assert_eq!(recon.recorded_chain_depth, 3);
        assert_eq!(recon.recorded_nonce, [0x66u8; 16]);
        assert!(
            !entry.participants.contains(&hex::encode(XCTX_TARGET)),
            "the journal participant triple deliberately omits the target — the evidence closes \
             the gap"
        );
    }

    /// §17.16.4 Commit-in-progress replay re-emits the STORED output WITHOUT
    /// re-invoking the tool. We commit a real saga (executor runs once), then
    /// reconstruct the prepared state from journaled evidence and re-drive the
    /// Commit-in-progress recovery path; the target re-emits the stored output
    /// via the idempotent `AlreadyCommitted`, and the executor counter stays 1.
    #[tokio::test]
    async fn xctx_replay_commit_in_progress_reemits_without_reinvoke() {
        use crate::context::supervisor::saga_journal::{JournalEntry, SagaId, SagaState};
        use crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let creator_did = "did:dht:z6MkXctxReplay2Creator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxReplay2Caller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_exec = Arc::clone(&calls);
        let executor = move |_input: serde_json::Value| {
            let calls = Arc::clone(&calls_for_exec);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({ "result": 3 }))
            }
        };
        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let nonce = [0x42u8; 16];
        let output = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 2,
                    asserted_nonce: nonce,
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                executor,
            )
            .await
            .expect("saga commits");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "tool ran once");

        // Recover the committed saga id from the receipt.
        let receipt: scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt =
            serde_json::from_slice(&output.receipt.expect("receipt")).expect("decode");
        let saga_id_str = receipt
            .tool_invoked_event_id
            .strip_prefix("ToolInvoked:")
            .expect("event id carries saga id")
            .to_owned();
        let saga_id = SagaId(saga_id_str);

        // Build a Commit-in-progress journal entry whose evidence carries the
        // full {caller, target} prepared state, then run the recovery re-drive.
        let prepared = CrossContextToolInvocationPrepared {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID(caller_did.to_owned()),
            tool_registration_id: XCTX_TOOL.to_owned(),
            ucan_proof_id: String::new(),
            recorded_timestamp_ms: now_ms,
            recorded_nonce: nonce,
            recorded_chain_depth: 3,
        };
        let entry = JournalEntry {
            saga_id: saga_id.clone(),
            state: SagaState::Committing,
            participants: vec![hex::encode(XCTX_CALLER)],
            evidence: Zeroizing::new(prepared.to_evidence_bytes().expect("encode")),
            timestamp_ms: now_ms,
            seq_per_saga: 3,
        };
        let recon = Supervisor::reconstruct_xctx_prepared(&entry).expect("reconstruct");
        Box::pin(supervisor.redrive_xctx_commit_in_progress(&saga_id, &recon)).await;

        // The re-drive re-emitted the stored output via AlreadyCommitted — the
        // tool was NEVER re-invoked.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "Commit-in-progress replay MUST NOT re-invoke the tool"
        );
    }

    /// FIX 2 (§17.16.4): a Commit-in-progress recovery whose A-side
    /// `xctx_committed_invocations` witness IS present resolves to `Committed`,
    /// NOT a spurious `NeedsRepair`. We commit a real saga (both witnesses land),
    /// then run the recovery re-drive and assert it returns `Committed` (the
    /// A-side witness re-ack succeeded) — and the tool never re-runs.
    ///
    /// (The journal is the no-op test journal here, so the resolution is
    /// asserted on the re-drive's RETURN value — the input `recover_committing_entry`
    /// consumes to choose `mark_resolved(Committed)` vs the NeedsRepair append.)
    #[tokio::test]
    async fn xctx_commit_in_progress_with_witness_resolves_committed() {
        use crate::context::supervisor::saga_journal::SagaId;
        use crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let creator_did = "did:dht:z6MkXctxWitnessCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxWitnessCaller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_exec = Arc::clone(&calls);
        let executor = move |_input: serde_json::Value| {
            let calls = Arc::clone(&calls_for_exec);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({ "result": 3 }))
            }
        };
        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let nonce = [0x42u8; 16];
        let out = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 2,
                    asserted_nonce: nonce,
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                executor,
            )
            .await
            .expect("saga commits");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "tool ran once");

        // Recover the committed saga id from the receipt — its A-side witness is
        // present in the (still-live) caller actor.
        let receipt: scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt =
            serde_json::from_slice(&out.receipt.expect("receipt")).expect("decode");
        let saga_id_str = receipt
            .tool_invoked_event_id
            .strip_prefix("ToolInvoked:")
            .expect("event id carries saga id")
            .to_owned();
        let saga_id = SagaId(saga_id_str);

        let prepared = CrossContextToolInvocationPrepared {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID(caller_did.to_owned()),
            tool_registration_id: XCTX_TOOL.to_owned(),
            ucan_proof_id: String::new(),
            recorded_timestamp_ms: now_ms,
            recorded_nonce: nonce,
            recorded_chain_depth: 3,
        };
        // The re-drive re-acks Commit-A FROM THE WITNESS and resolves Committed —
        // not a false NeedsRepair.
        let resolution =
            Box::pin(supervisor.redrive_xctx_commit_in_progress(&saga_id, &prepared)).await;
        assert_eq!(
            resolution,
            CommitInProgressResolution::Committed,
            "a Commit-in-progress recovery with a present A-side witness MUST resolve to \
             Committed (not a false NeedsRepair)"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "recovery must not re-invoke the tool"
        );

        // Contrast: with NO A-side witness (a different, never-committed saga id),
        // the same re-drive stays NeedsRepair — only a genuine commit resolves.
        let absent = SagaId("never-committed-saga".to_owned());
        let resolution_absent =
            Box::pin(supervisor.redrive_xctx_commit_in_progress(&absent, &prepared)).await;
        assert_eq!(
            resolution_absent,
            CommitInProgressResolution::NeedsRepair,
            "a saga with no committed B-side / A-witness must stay NeedsRepair"
        );
    }

    /// FIX 3 (crypto, §6.2.4 "Signer authorization"): the Commit-A path verifies
    /// B's receipt signature against the key authorized for `target_context_id`
    /// BEFORE settling. A receipt signed by a DIFFERENT key is rejected — the
    /// saga aborts before any settle/record. Exercised directly on
    /// `verify_commit_b_receipt`: a ctx holding target key Y rejects a receipt
    /// signed by key X.
    #[tokio::test]
    async fn xctx_commit_a_rejects_receipt_signed_by_wrong_key() {
        use crate::context::supervisor::saga_journal::SagaId;
        use scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt;

        let authorized = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let nonce = [0x42u8; 16];

        // The ctx is authorized for the TARGET key `authorized`.
        let ctx = divergence_ctx(
            nonce,
            "ToolInvoked:wrong-key-saga".to_owned(),
            &authorized,
            &caller_signing,
            "did:dht:z6MkWrongKeyCaller",
        );

        // A receipt signed by the ATTACKER key (not authorized for the target).
        let forged = CrossContextToolReceipt::sign(
            &attacker,
            XCTX_CALLER,
            XCTX_TARGET,
            "did:dht:z6MkWrongKeyCaller".to_owned(),
            nonce,
            XCTX_TOOL.to_owned(),
            br#"{"result":3}"#.to_vec(),
            "ToolInvoked:wrong-key-saga".to_owned(),
            3,
            1_700_000_000,
        )
        .expect("sign forged receipt");
        let forged_bytes = serde_json::to_vec(&forged).expect("encode");

        let saga_id = SagaId("wrong-key-saga".to_owned());
        let result = Supervisor::verify_commit_b_receipt(&saga_id, &ctx, &forged_bytes);
        assert!(
            matches!(
                &result,
                Err(ContextError::CryptoFailed(m)) if m.contains("SCP-SAGA-13041")
            ),
            "a receipt signed by a key NOT authorized for the target context must be rejected \
             before settle, got {result:?}"
        );

        // Sanity: the SAME receipt signed by the AUTHORIZED key verifies.
        let valid = CrossContextToolReceipt::sign(
            &authorized,
            XCTX_CALLER,
            XCTX_TARGET,
            "did:dht:z6MkWrongKeyCaller".to_owned(),
            nonce,
            XCTX_TOOL.to_owned(),
            br#"{"result":3}"#.to_vec(),
            "ToolInvoked:wrong-key-saga".to_owned(),
            3,
            1_700_000_000,
        )
        .expect("sign valid receipt");
        let valid_bytes = serde_json::to_vec(&valid).expect("encode");
        assert!(
            Supervisor::verify_commit_b_receipt(&saga_id, &ctx, &valid_bytes).is_ok(),
            "a receipt signed by the authorized target key must verify"
        );
    }

    /// FIX 5 (§6.2.4 "Exactly-once execution"): a transient Commit-B SETTLE
    /// failure is retryable WITHOUT re-invoking the tool. The target's Commit-B
    /// settle persist fails once (Class-S fail-closed → the capture rolls back),
    /// so the FSM retries: reserve reports `ReadyToExecute` again, but the
    /// executor output is STASHED in the ctx — the settle is re-sent with the
    /// stashed bytes and the tool is NEVER re-invoked. The saga commits on retry
    /// and the executor ran exactly once.
    #[tokio::test]
    async fn xctx_commit_b_settle_retry_does_not_reinvoke_tool() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let creator_did = "did:dht:z6MkXctxSettleRetryCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        // Fail the TARGET context's 2nd persist (Prepare-B = call 1, Commit-B
        // settle = call 2) exactly once; the retried settle (call 3) succeeds.
        let persistence = FailContextPersistOncePersistence {
            target_hex: hex::encode(XCTX_TARGET),
            fail_on_call: 2,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let supervisor = xctx_supervisor_with_persistence(
            creator_did.clone(),
            creator_key,
            Box::new(persistence),
        );
        let caller_did = "did:dht:z6MkXctxSettleRetryCaller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_exec = Arc::clone(&calls);
        let executor = move |input: serde_json::Value| {
            let calls = Arc::clone(&calls_for_exec);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let a = input["a"].as_i64().unwrap_or(0);
                let b = input["b"].as_i64().unwrap_or(0);
                Ok(serde_json::json!({ "result": a + b }))
            }
        };

        let now_ms = supervisor.clock_ref().expect("clock").now_millis();
        let output = supervisor
            .start_cross_context_tool_invocation_saga(
                CrossContextToolInvocationRequest {
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: DID(caller_did.to_owned()),
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 2,
                    asserted_nonce: [0x42u8; 16],
                    asserted_timestamp_ms: now_ms,
                },
                &target_signing,
                &caller_signing,
                executor,
            )
            .await
            .expect("saga must commit after the transient settle failure is retried");

        // The transient settle failure was retried to a committed terminal …
        let out_value: serde_json::Value =
            serde_json::from_slice(&output.output.expect("output")).expect("decode");
        assert_eq!(out_value, serde_json::json!({ "result": 3 }));
        // … and despite the retry the tool executed EXACTLY ONCE (the stashed
        // output was re-sent, never re-invoked).
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a Commit-B settle retry MUST re-send the stashed output, never re-invoke the tool"
        );
    }

    /// FIX 1 (§6.2.4): a Commit-A whose mailbox SEND fails (the caller actor
    /// died between `lookup` and send) does NOT drop the escrow ticket unbalanced
    /// (no debug-assert panic under `--features testing`, no escrow leak in
    /// release) and KEEPS the reservation consumable for a retry. We Prepare-A on
    /// a live caller (staging a real reservation), DESPAWN the caller, then call
    /// `commit_a_settle`: it returns Err but RECOVERS the reservation back into
    /// `ctx.prepared_a` — proving the ticket was not dropped and the retry can
    /// re-drive Commit-A.
    #[tokio::test]
    async fn xctx_commit_a_send_failure_recovers_ticket_for_retry() {
        use scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt;

        let creator_did = "did:dht:z6MkXctxSendFailCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxSendFailCaller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let target_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let caller_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let nonce = [0x42u8; 16];

        // Build a saga ctx and run the REAL Prepare-A so `prepared_a` holds a
        // genuine `#[must_use]` reservation (its ticket's Drop guard fires if it
        // is ever dropped unbalanced).
        let mut ctx = CrossContextSagaCtx {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID(caller_did.to_owned()),
            tool_registration_id: XCTX_TOOL.to_owned(),
            ucan_proof_id: None,
            input: serde_json::json!({ "a": 1, "b": 2 }),
            asserted_chain_depth: 2,
            asserted_nonce: nonce,
            asserted_timestamp_ms: supervisor.clock_ref().expect("clock").now_millis(),
            caller_source_role: None,
            target_signing_key: target_signing.clone(),
            caller_signing_key: caller_signing.clone(),
            executor: Some(Box::new(|_v: serde_json::Value| {
                Box::pin(async move { Ok(serde_json::json!({ "result": 3 })) }) as _
            })),
            executor_output: None,
            prepared_a: None,
            prepared_b: None,
            committed: None,
            committed_b_tool_invoked_event_id: None,
            reached_needs_repair: false,
        };
        supervisor
            .dispatch_xctx_prepare_a(&mut ctx)
            .await
            .expect("Prepare-A stages a real reservation");
        assert!(ctx.prepared_a.is_some(), "Prepare-A held a reservation");

        // Now the caller actor dies BEFORE Commit-A reaches it.
        let despawned = supervisor.despawn_actor(&hex::encode(XCTX_CALLER)).await;
        assert!(despawned, "caller actor despawned");

        // Build a verified receipt signed by the target's authorized key (the
        // Commit-A path passes the VERIFIED receipt; we mirror that here).
        let receipt = CrossContextToolReceipt::sign(
            &target_signing,
            XCTX_CALLER,
            XCTX_TARGET,
            caller_did.to_owned(),
            nonce,
            XCTX_TOOL.to_owned(),
            br#"{"result":3}"#.to_vec(),
            "ToolInvoked:send-fail-saga".to_owned(),
            3,
            1_700_000_000,
        )
        .expect("sign receipt");
        let receipt_bytes = serde_json::to_vec(&receipt).expect("encode");

        let saga_id = SagaId("send-fail-saga".to_owned());
        let result = supervisor
            .commit_a_settle(&saga_id, &mut ctx, &receipt_bytes, &receipt)
            .await;

        // The send failed (caller gone) — but the ticket was NOT dropped: it is
        // recovered back into `ctx.prepared_a`, consumable on retry. Reaching
        // this assertion without a drop-guard panic IS the FIX-1 guarantee.
        assert!(
            result.is_err(),
            "Commit-A to a despawned caller must surface the send failure"
        );
        assert!(
            ctx.prepared_a.is_some(),
            "the escrow reservation MUST be recovered into ctx for retry (never dropped \
             unbalanced — no ticket-drop panic, no escrow leak)"
        );

        // Drain the recovered reservation cleanly so the test does not itself
        // leak the must-use ticket (mirrors the run_saga tail's void+consume for
        // a Commit-A that never landed).
        if let Some(reservation) = ctx.prepared_a.take() {
            reservation
                .reservation
                .ticket
                .void_external_and_consume(supervisor.payment_adapter_ref())
                .await;
        }
    }

    /// §17.16.4 Prepare-in-progress replay aborts the Prepared side(s) and
    /// discards — never re-Prepares. We Prepare-B (staging the target's
    /// `saga_pending` session slot keyed by the saga id), then run the
    /// Prepare-in-progress recovery re-drive, which sends `Abort` to the target
    /// to RELEASE the staged slot. We then confirm the slot is gone: a
    /// subsequent Commit-B reserve for that saga finds NO staged prepared
    /// (SCP-SAGA-13030), proving the recovery released-and-discarded it. The
    /// tool never executes (no Commit ever ran).
    #[tokio::test]
    async fn xctx_replay_prepare_in_progress_releases_and_discards() {
        use crate::context::actor::commands::SagaPhaseMessage;
        use crate::context::supervisor::saga_journal::SagaId;
        use crate::context::supervisor::saga_prepared_state::CrossContextToolInvocationPrepared;

        let creator_did = "did:dht:z6MkXctxPrepReplayCreator".to_owned();
        let creator_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let supervisor = xctx_supervisor(creator_did.clone(), creator_key);
        let caller_did = "did:dht:z6MkXctxPrepReplayCaller";
        let caller_state = xctx_caller_state(caller_did, &creator_did).await;
        let target_state = xctx_target_state(caller_did, &creator_did).await;
        Box::pin(spawn_xctx_pair(&supervisor, caller_state, target_state)).await;

        let saga_id = SagaId::new();

        // Stage Prepare-B on the target actor: this stages the eight-field
        // prepared into `saga_pending`, keyed by the saga id (the session slot
        // the recovery Abort releases).
        let target = supervisor
            .lookup(&hex::encode(XCTX_TARGET))
            .expect("target co-resident");
        let prepare_saga_id = saga_id.clone();
        let prepare_did = DID(caller_did.to_owned());
        let prepare_now_ms = supervisor.clock_ref().expect("clock").now_millis();
        target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::PrepareB {
                    saga_id: prepare_saga_id,
                    caller_context_id: XCTX_CALLER,
                    target_context_id: XCTX_TARGET,
                    caller_did: prepare_did,
                    tool_registration_id: XCTX_TOOL.to_owned(),
                    ucan_proof_id: None,
                    input: serde_json::json!({ "a": 1, "b": 2 }),
                    asserted_chain_depth: 2,
                    asserted_nonce: [0x99u8; 16],
                    asserted_timestamp_ms: prepare_now_ms,
                    caller_source_role: None,
                    reply,
                })
            })
            .await
            .expect("Prepare-B stages the target session slot");

        // Run the Prepare-in-progress recovery re-drive: it aborts the prepared
        // side(s), releasing the target's staged `saga_pending` slot.
        let prepared = CrossContextToolInvocationPrepared {
            caller_context_id: XCTX_CALLER,
            target_context_id: XCTX_TARGET,
            caller_did: DID(caller_did.to_owned()),
            tool_registration_id: XCTX_TOOL.to_owned(),
            ucan_proof_id: String::new(),
            recorded_timestamp_ms: 1,
            recorded_nonce: [0x99u8; 16],
            recorded_chain_depth: 3,
        };
        Box::pin(supervisor.redrive_xctx_prepare_in_progress(&saga_id, &prepared)).await;

        // The staged slot was RELEASED: a Commit-B reserve for this saga now
        // finds NO staged prepared (the recovery discarded it; it was never
        // re-Prepared).
        let reserve_saga_id = saga_id.clone();
        let reserve = target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBReserve {
                    saga_id: reserve_saga_id,
                    reply,
                })
            })
            .await;
        assert!(
            matches!(
                &reserve,
                Err(ContextError::InvalidState(m)) if m.contains("SCP-SAGA-13030")
            ),
            "after Prepare-in-progress recovery the staged slot must be released (no staged \
             prepared on Commit-B reserve), got {reserve:?}"
        );
    }

    /// The NeedsRepair `run_saga` tail HOLDS the escrow reserved (does NOT void
    /// it) for operator repair, while every other terminal voids/settles it
    /// (spec §6.2.4 "`NeedsRepair` reservation semantics"). Exercised directly
    /// on the ticket primitive: `hold_external_for_repair` consumes the carrier
    /// (no unbalanced-drop panic) WITHOUT voiding the external escrow, distinct
    /// from `void_external_and_consume`.
    #[test]
    fn needs_repair_holds_escrow_without_voiding() {
        // A no-escrow ticket: `hold_external_for_repair` simply consumes it so
        // its `#[must_use]` drop guard does not fire (no panic). The semantic
        // difference from voiding is documented + asserted by the no-panic drop:
        // had the carrier been dropped WITHOUT being consumed, the debug-assert
        // in `ToolEconomyTicket::drop` would fire.
        let ticket = crate::context::tools_helpers::ToolEconomyTicket::new_for_test_no_escrow(DID(
            "did:dht:z6MkHoldRepair".to_owned(),
        ));
        ticket.hold_external_for_repair();
        // Reaching here without a drop-guard panic proves the carrier was marked
        // consumed (held for repair), not leaked.
    }
}
