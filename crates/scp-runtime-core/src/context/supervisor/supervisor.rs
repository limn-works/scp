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
//! - `DashMap<DID, Arc<IdentityWrappingKey>>` for per-identity wrapping
//!   keys (custody handles), loaded under a per-identity
//!   `tokio::sync::Mutex<()>` in `wrapping_key_loads`.
//! - `tokio::sync::Mutex<()>` write-lock serializing ALL mutations of
//!   the above. Reads are lock-free; the mutex prevents lost writes
//!   when two callers race a `store` on the same `ArcSwap`.
//!
//! # Scope
//!
//! The supervisor implements the actor registry (`new`, `lookup`,
//! `spawn_actor`) and the saga coordinator (`start_saga` → `run_saga` →
//! `run_saga_fsm`) per ADR-049. Per-context operations dispatch through
//! the per-context actor mailbox; cross-context outlet invocation runs as a
//! durable-journalled saga FSM. No migration stubs remain.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;

use crate::context::actor::commands::{
    BroadcastCommand, ContextCommand, EconomyCommand, GovernanceCommand, LifecycleCommand,
    MessagingCommand, OutletsCommand, PrepareAOutcome, PrepareBOutcome, PushCommand,
    QueriesCommand, SagaReject, StandingCommand, TrustRecoveryCommand, TtlCloseCommand,
    saga_reject,
};
use crate::context::actor::handle::ContextActorHandle;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::{BoundedReplyError, bounded_reply_await};
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::crypto::wrapping::{IdentityWrappingKey, WrappingCustodySource};
use scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt;
use scp_runtime_types::context::outlets::stream::{OriginAdmissionTracker, StreamAdmissionTracker};
use scp_runtime_types::context::supervisor::saga_journal::{
    JournalEntry, SagaId, SagaJournal, SagaState, SagaTerminalState,
};
use scp_runtime_types::economy::adapter::PaymentAdapterDyn;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "testing")]
#[path = "testing_access.rs"]
mod testing_access;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Actor mailbox capacity. Plan §"Mailbox parameters": bounded at 256 so
/// the mailbox applies backpressure to callers.
pub const ACTOR_MAILBOX_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// SagaInput / SagaOutput — plan §"Cross-context saga protocol"
// ---------------------------------------------------------------------------

/// Construction seal for [`SagaInput::CrossContextOutletInvocation`]. A field of
/// this type makes the variant un-constructible outside this module: the seal's
/// single field is PRIVATE, so no `CrossContextSagaSeal { .. }` literal is
/// possible outside `supervisor.rs`, and the only constructor
/// (`Self::new`) is module-private. A cross-context outlet invocation can
/// therefore only be started via
/// [`Supervisor::start_cross_context_outlet_invocation_saga`] — the sole entry
/// point that supplies the supervisor-side executor + signing keys. The variant
/// remains freely pattern-matchable (`{ .. }`) everywhere; only its
/// construction is sealed.
///
/// The TYPE is named at the enclosing `pub enum`'s visibility (so the
/// `private_interfaces` lint is satisfied — the field is `pub` by enum
/// inheritance), but CONSTRUCTABILITY is gated by the private field, exactly the
/// "nameable ≠ constructible" discipline ADR-049 §5 uses for `OwnedIdentityDid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossContextSagaSeal(());

impl CrossContextSagaSeal {
    /// Mint the seal. Module-private: only `supervisor.rs` can construct it, so
    /// only `supervisor.rs` can construct a `CrossContextOutletInvocation` input.
    #[must_use]
    const fn new() -> Self {
        Self(())
    }

    /// Mints the seal for a test that builds a `CrossContextOutletInvocation`
    /// input directly. Behind `saga-witness-test-mint`, like
    /// [`RestoredContexts::for_test`]: no crate's non-dev dependencies enable
    /// it, so no production or bridge `testing` build can forge the seal.
    #[cfg(feature = "saga-witness-test-mint")]
    #[must_use]
    pub const fn for_test() -> Self {
        Self(())
    }
}

/// Witness that `Supervisor::restore_all_contexts` ran — the §17.16.4
/// "restore, THEN reconcile" startup ordering, encoded in the TYPE SYSTEM.
///
/// [`Supervisor::replay_unresolved_sagas`] takes `&RestoredContexts`, and the
/// ONLY way to obtain one is to first call `Supervisor::restore_all_contexts`
/// (which returns it). So a `restore_on_startup` that tried to replay BEFORE
/// restore would have no token to pass — it would not COMPILE. This makes the
/// crash-recovery ordering unbreakable by construction rather than enforced only
/// by a source-text structural gate (which a `/* decoy */` block comment could
/// evade); see the `compile_fail` doctest on [`Supervisor::replay_unresolved_sagas`].
///
/// The construction discipline mirrors [`CrossContextSagaSeal`] and ADR-049 §5's
/// `OwnedIdentityDid`. Construction is SEALED: the `ids` field is PRIVATE (no
/// `RestoredContexts { ids: .. }` literal outside this module) and the only
/// production constructor (`Self::new`) is module-private. There is NO
/// `Default` impl (a derived `Default::default()` would be a public, zero-arg
/// constructor reachable from any crate — a forge that mints an empty witness
/// and voids the ordering guarantee), and no `Clone`. So no external crate can
/// forge a token to call replay without a real restore. A dedicated-feature-
/// gated `Self::for_test` (behind the `saga-witness-test-mint` cargo feature,
/// which NO crate's non-dev `[dependencies]` enables — not even `testing`, so it
/// cannot reach any production or bridge-`testing` build) exists ONLY for
/// the saga-FSM integration suites in `crates/scp-runtime/tests/`, which drive
/// replay in isolation over a harness with no persistence provider to restore
/// from. The `ids` payload doubles as the public restored-id result returned by
/// [`Supervisor::restore_on_startup`]; it is not part of the ordering enforcement (the
/// mere EXISTENCE of the witness is). The type stays `pub` so the `compile_fail`
/// doctests (external-crate compiles) can reference it.
#[derive(Debug)]
pub struct RestoredContexts {
    /// The context IDs rehydrated by `restore_all_contexts` (hex id-form).
    /// PRIVATE — only `restore_all_contexts` (or the `saga-witness-test-mint`-
    /// gated `for_test`) can populate it, so the token cannot be forged outside
    /// this module.
    ids: Vec<String>,
}

impl RestoredContexts {
    /// Mint the witness. Module-private: only [`Supervisor::restore_all_contexts`]
    /// can construct it, so a `RestoredContexts` proves a real restore ran.
    #[must_use]
    const fn new(ids: Vec<String>) -> Self {
        Self { ids }
    }

    /// Construct a witness directly for the saga-FSM / crash-recovery
    /// integration suites in `crates/scp-runtime/tests/`, which drive
    /// [`Supervisor::replay_unresolved_sagas`] in isolation over a harness that
    /// has NO persistence provider to restore from (so they cannot obtain a
    /// token via the real `restore_all_contexts` — a `Supervisor::new` harness
    /// leaves `helper_persistence` empty, so that restore returns
    /// `PersistenceFailed`, not an empty token).
    ///
    /// Gated behind the dedicated `saga-witness-test-mint` cargo feature, which
    /// NO crate's non-dev `[dependencies]` enables — in particular it is NOT
    /// implied by `testing`, so it cannot leak into a bridge `testing`
    /// build via the `scp-ffi/testing → dep:scp-testing → scp-core/testing →
    /// scp-runtime/testing` chain. It is enabled only by the `required-features`
    /// of the two `actor_saga_*` integration test targets. A production caller
    /// therefore physically cannot forge the restore-ran witness, preserving the
    /// compile-time ordering guarantee.
    #[cfg(feature = "saga-witness-test-mint")]
    #[must_use]
    pub const fn for_test(ids: Vec<String>) -> Self {
        Self { ids }
    }

    /// The restored context IDs (hex id-form), borrowed.
    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Consume the witness, returning the restored context IDs.
    #[must_use]
    pub fn into_ids(self) -> Vec<String> {
        self.ids
    }
}

/// Input to `Supervisor::start_saga`. The sole production saga is
/// cross-context outlet invocation (spec §6.2.4); the other contemplated
/// arms (custody handover, standing-pair create, broadcast hosting
/// handshake) were all withdrawn as category errors (ADR-049 §3/§3b).
///
/// The type is a discriminated union so that adding a new saga type
/// later is a compile error at every call site — the default branch is
/// not permitted.
///
/// # Construction of `CrossContextOutletInvocation` is sealed
///
/// The `CrossContextOutletInvocation` variant carries a private
/// [`CrossContextSagaSeal`] guard field, so it CANNOT be constructed outside
/// this module: an external caller cannot name the seal type to build the
/// variant. This makes a "construct it, then hand it to the generic
/// [`Supervisor::start_saga`]" misuse a COMPILE error rather than a runtime
/// abort — a cross-context outlet invocation can only be started through the
/// dedicated [`Supervisor::start_cross_context_outlet_invocation_saga`], which is
/// the only entry point that can supply the supervisor-side outlet executor and
/// the target/caller Active Signing Keys the FSM needs (Agent-first API tenet:
/// a required choice the type system can enforce must not be skippable). The
/// generic `start_saga` therefore only ever receives a publicly-constructible
/// input — the executor-less misuse path that aborts in Prepare-A. External
/// pattern-matching on `CrossContextOutletInvocation { .. }` is still allowed;
/// only construction is sealed.
pub enum SagaInput {
    /// Cross-context outlet invocation.
    CrossContextOutletInvocation {
        /// Calling context.
        caller_context_id: [u8; 32],
        /// Target context that hosts the outlet registration being invoked.
        /// The saga spans BOTH the caller and the target context-actors, so
        /// the gating reservation (ADR-049 §3a) needs the real 2-context set;
        /// spec §6.2.4's cross-context outlet-invoke transport needs it too.
        target_context_id: [u8; 32],
        /// Calling identity. The channel-authenticated initiator the
        /// supervisor binds (spec §6.2.4 "Caller authentication"), NOT an
        /// envelope-asserted value.
        caller_did: DID,
        /// Outlet registration to invoke — a context-LOCAL identifier indexing
        /// B's own outlet registry.
        outlet_registration_id: String,
        /// UCAN proof reference — an INDEX into B's own UCAN store, never the
        /// proof bytes (spec §6.2.4 normative (1)). `None` for an ungated outlet.
        ucan_proof_id: Option<String>,
        /// The invocation input — validated at Prepare-B against the target
        /// outlet's registered schema specificity floor (spec §9.2.1) and passed
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
        /// Private construction seal (see the `SagaInput` doc-comment): the
        /// variant cannot be built outside this module because the field's
        /// type is module-private, so the only way to start a cross-context
        /// outlet-invocation saga is the dedicated
        /// [`Supervisor::start_cross_context_outlet_invocation_saga`], which
        /// supplies the executor + signing keys the generic `start_saga`
        /// cannot.
        _seal: CrossContextSagaSeal,
    },
    /// Cross-context **streaming** outlet invocation — the streaming saga
    /// (ADR-061 seal phase; spec §6.2.5). Structurally mirrors
    /// [`Self::CrossContextOutletInvocation`] (same sealed construction
    /// discipline, same `{caller, target}` participant set), but its FSM entry
    /// ([`Supervisor::start_cross_context_streaming_outlet_invocation_saga`])
    /// does NOT run the generic synchronous `run_saga` FSM: the Commit-transition
    /// returns the `mpsc::Receiver` PROMPTLY, releases the per-participant-set
    /// concurrency slot (ADR-049 §3a(b)), and reaches `Committed` ASYNC at
    /// seal-close off the mailbox. This variant exists so the dedicated entry
    /// can compute the participant-context-set reservation via
    /// `saga_participant_context_set` with the SAME discipline as the unary
    /// saga; it is never dispatched through `Supervisor::run_saga`.
    CrossContextStreamingOutletInvocation {
        /// Calling context.
        caller_context_id: [u8; 32],
        /// Target context that hosts the streaming outlet registration.
        target_context_id: [u8; 32],
        /// Channel-authenticated calling identity (spec §6.2.4).
        caller_did: DID,
        /// Streaming outlet registration to invoke — a context-LOCAL identifier
        /// indexing B's own outlet registry.
        outlet_registration_id: String,
        /// UCAN proof reference — an INDEX into B's own UCAN store, never the
        /// proof bytes. `None` for an ungated outlet.
        ucan_proof_id: Option<String>,
        /// The invocation input — validated at Prepare-B against the target
        /// outlet's registered schema specificity floor (spec §9.2.1).
        input: serde_json::Value,
        /// Caller-asserted chain depth — advisory; the `+1` base for B's
        /// re-derived `recorded_chain_depth` (spec §6.2.4).
        asserted_chain_depth: u8,
        /// Caller-asserted 16-byte envelope nonce — checked against B's TTL
        /// dedup cache, then staged on accept (spec §6.2.4).
        asserted_nonce: [u8; 16],
        /// Caller-asserted send-time (ms) — used ONLY for the §9.14 skew check.
        asserted_timestamp_ms: u64,
        /// Private construction seal — same discipline as the unary variant: the
        /// streaming saga can only be started via
        /// [`Supervisor::start_cross_context_streaming_outlet_invocation_saga`].
        _seal: CrossContextSagaSeal,
    },
    /// Test-only saga whose Prepare phases succeed and whose Commit phase
    /// ALWAYS fails, so the FSM runs all the way to Committing, exhausts the
    /// commit-retry budget, and lands in `NeedsRepair`. The sole production
    /// saga (`CrossContextOutletInvocation`) reaches its real Prepare/Commit
    /// dispatch only via
    /// [`Supervisor::start_cross_context_outlet_invocation_saga`]; driven through
    /// the generic `start_saga`, an executor-less input aborts at Prepare-A
    /// with `InvalidState` (no executor) and never reaches Committing. So this
    /// variant remains the ONLY way to drive `start_saga` to a real
    /// `NeedsRepair` terminal — it lets the gating tests assert that
    /// `NeedsRepair` RELEASES the participant-context-set reservation
    /// (ADR-049 §3a, spec §5.15.4). Gated behind `test`/`testing` so a production FFI build can
    /// never construct or dispatch it.
    #[cfg(any(test, feature = "testing"))]
    TestForceNeedsRepair {
        /// The single participant context this test saga reserves.
        context_id: [u8; 32],
    },
}

#[cfg(any(test, feature = "testing"))]
impl SagaInput {
    /// Test-only constructor for a `CrossContextOutletInvocation` input whose only
    /// load-bearing fields are the `{caller, target}` participant context set
    /// (every other field is a fixed placeholder). It exists so the
    /// per-participant-context-set GATING tests — which drive a cross-context
    /// input through the generic `start_saga` precisely to prove the reservation
    /// is released on the executor-less misuse path — can still build the
    /// variant the production seal otherwise forbids. It is gated behind
    /// `test`/`testing` so no production FFI build can reach it: a production
    /// cross-context saga is started ONLY via
    /// [`Supervisor::start_cross_context_outlet_invocation_saga`], which supplies
    /// the executor + signing keys.
    #[must_use]
    pub fn test_cross_context_for_gating(
        caller_context_id: [u8; 32],
        target_context_id: [u8; 32],
    ) -> Self {
        Self::CrossContextOutletInvocation {
            caller_context_id,
            target_context_id,
            caller_did: DID("did:example:caller".to_owned()),
            outlet_registration_id: "outlet-1".to_owned(),
            ucan_proof_id: None,
            input: serde_json::json!({}),
            asserted_chain_depth: 0,
            asserted_nonce: [0u8; 16],
            asserted_timestamp_ms: 0,
            _seal: CrossContextSagaSeal::new(),
        }
    }
}

/// Output from `Supervisor::start_saga` on success. Carries the durable
/// saga identifier plus — for a committed cross-context outlet-invocation
/// saga — the target's signed receipt and captured outlet output (spec
/// §6.2.4 "Receipt / response return path").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaOutput {
    /// Durable saga identifier; usable as a handle into the journal.
    pub saga_id: SagaId,
    /// The target's signed `CrossContextOutletReceipt` bytes (JCS), present
    /// for a committed `CrossContextOutletInvocation` saga. `None` for saga
    /// inputs that produce no receipt (e.g. the test-only NeedsRepair driver).
    pub receipt: Option<Vec<u8>>,
    /// The captured outlet output bytes (the receipt's canonical `output_jcs`),
    /// present for a committed `CrossContextOutletInvocation` saga. The exact
    /// bytes the caller (A) side recorded a hash of. `None` otherwise.
    pub output: Option<Vec<u8>>,
}

/// Typed terminal-state error of the §6.2.4 cross-context outlet-invocation saga
/// — the legible terminal space the FFI saga surface (ADR-049 §3a) maps onto
/// the `SCP-SAGA-*` taxonomy WITHOUT parsing message strings.
///
/// Returned only by
/// [`Supervisor::start_cross_context_outlet_invocation_saga`]. A `Committed`
/// terminal is the `Ok(SagaOutput)` arm; every NON-committed terminal is one of
/// these variants, so a bridge's exhaustive `match` is forced to handle every
/// terminal:
///
/// - [`SagaError::Aborted`] — the saga aborted at a Prepare phase (a §6.2.4
///   authorization / freshness / rate-limit rejection, or a participant actor
///   unavailable to complete the Prepare exchange). The structured
///   [`SagaAbortReason`] distinguishes the three reasons — `RateLimited`
///   (retryable; carries the `retry_after_ms` back-off hint, read structurally
///   — never re-parsed from the message), `ParticipantUnavailable` (transient /
///   retryable, code `SCP-SAGA-13068`), and `Rejected` (a permanent policy
///   reject); `code` carries the numeric `SCP-SAGA-13xxx` discriminant so the
///   bridge maps to the canonical code directly. `Committed ⇒ Ok` /
///   `Aborted ⇒ neither side committed` (spec §6.2.4 "Dual event-log
///   recording").
/// - [`SagaError::NeedsRepair`] — Commit-retry exhausted; the saga may have
///   PARTIALLY committed (a possible divergence). Carries the durable
///   [`SagaId`] so an operator drives `repair_saga(saga_id)` (ADR-049 §3a). A
///   signed `CrossContextDivergenceMarker` was emitted (spec §6.2.4).
/// - [`SagaError::Busy`] — the saga's participant context set overlapped an
///   in-flight saga's set (spec §5.15.4 per-participant-context-set gating);
///   retry with back-off. `contended_context` names the shared context id.
/// - [`SagaError::SupervisorShutDown`] — the streaming saga was refused because
///   Supervisor shutdown had begun (`SCP-CTX-2138`); nothing was staged.
///
/// The variants carry the canonical `SCP-SAGA-13xxx` code (`SCP-CTX-2138` for
/// `SupervisorShutDown`) in their `Display`
/// so a flattened log line still `grep`-disambiguates: `Aborted` carries the
/// inner reject's already-registered code (minted via `saga_reject!`) where one
/// exists — EXCEPT the `ParticipantUnavailable` reason, whose code
/// `SCP-SAGA-13068` is SYNTHESIZED by `lift_run_saga_error`'s structural
/// `ActorBusy` match: a transient `ContextError::ActorBusy` is codeless, so
/// there is no inner reject code to mirror. `NeedsRepair` is the registered
/// terminal code `SCP-SAGA-13065`; `Busy` is `SCP-SAGA-13066`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SagaError {
    /// A Prepare-phase abort (spec §6.2.4). `Aborted ⇒ neither side
    /// committed`. `reason` distinguishes the three abort reasons — a rate-limit
    /// abort (`RateLimited`, retryable, with a structured `retry_after_ms`), a
    /// transiently-unavailable participant (`ParticipantUnavailable`, retryable,
    /// code `SCP-SAGA-13068`), and a permanent rejection (`Rejected`); `code` is
    /// the numeric `SCP-SAGA-13xxx` discriminant of the underlying reject.
    #[error("SCP-SAGA-{code}: saga aborted: {message}")]
    Aborted {
        /// Structured abort reason — `RateLimited { retry_after_ms }`,
        /// `ParticipantUnavailable`, or `Rejected` — so the bridge reads the
        /// back-off hint without parsing.
        reason: SagaAbortReason,
        /// The numeric `SCP-SAGA-13xxx` discriminant of the underlying reject.
        code: u16,
        /// Human-readable detail (the underlying reject's message).
        message: String,
    },
    /// Commit-retry exhausted — the saga diverged and requires operator repair
    /// (ADR-049 §3a). Carries the durable [`SagaId`] for `repair_saga`.
    #[error("SCP-SAGA-13065: saga needs repair: {saga_id}")]
    NeedsRepair {
        /// The durable saga identifier — the operator-repair handle.
        saga_id: SagaId,
        /// Human-readable detail (the Commit failure that exhausted retries).
        message: String,
    },
    /// The participant context set overlapped an in-flight saga's set
    /// (spec §5.15.4). Retry with back-off.
    #[error("SCP-SAGA-13066: saga busy: {message}")]
    Busy {
        /// The shared context id that forced serialization.
        contended_context: String,
        /// Human-readable detail naming the contended context.
        message: String,
    },
    /// The Supervisor refused the saga because `shutdown_all_contexts` has
    /// begun ([`ContextError::SupervisorShutDown`], `SCP-CTX-2138`, ADR-049
    /// Decision 16 item 2). Nothing was staged or debited.
    #[error("SCP-CTX-2138: saga refused: {message}")]
    SupervisorShutDown {
        /// Human-readable detail naming the refused operation.
        message: String,
    },
}

/// The step of a cross-context streaming saga's B-side open that returned an
/// [`OutletStreamOpenError`](crate::context::outlets::invoke::OutletStreamOpenError).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingSagaOpenStep {
    /// Phase 1: the B-side escrow reserve.
    EscrowReserve,
    /// Phase 2: the B-side `open_stream_session` call.
    StreamOpen,
}

impl StreamingSagaOpenStep {
    /// Returns the name this step carries in the saga error message.
    const fn label(self) -> &'static str {
        match self {
            Self::EscrowReserve => "B-side escrow reserve",
            Self::StreamOpen => "B-side stream open",
        }
    }
}

/// Maps a rejection that `step` of a streaming saga's B-side open returned onto
/// the saga error surface. A rejection by Supervisor shutdown keeps
/// `SCP-CTX-2138` as [`SagaError::SupervisorShutDown`] (ADR-049 Decision 16
/// item 2), the error the saga's own tracker refusal returns; every other
/// rejection aborts the saga with `SCP-SAGA-13067`.
#[must_use]
pub fn stream_open_rejection_to_saga_error(
    rejection: &crate::context::outlets::invoke::OutletStreamOpenError,
    step: StreamingSagaOpenStep,
) -> SagaError {
    match rejection {
        crate::context::outlets::invoke::OutletStreamOpenError::SupervisorShutDown { .. } => {
            SagaError::SupervisorShutDown {
                message: format!("{} of a cross-context streaming saga", step.label()),
            }
        }
        crate::context::outlets::invoke::OutletStreamOpenError::Rejected(other) => {
            SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13067,
                message: format!(
                    "streaming saga {} rejected: {}",
                    step.label(),
                    other.to_open_error()
                ),
            }
        }
    }
}

/// The structured reason a §6.2.4 saga reached the `Aborted` terminal — carried
/// by [`SagaError::Aborted`] so the FFI surface reads the reason structurally
/// (ADR-049 §3a), never by re-parsing the message. The reason is one of
/// `RateLimited` (carrying `retry_after_ms`), `ParticipantUnavailable`, or
/// `Rejected`; each variant's own rustdoc below is the authoritative home of its
/// rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SagaAbortReason {
    /// The abort was a rate-limit rejection. `retry_after_ms` carries the
    /// limiter's back-off hint: `Some(ms)` is the §6.2.0.2 sliding-window's
    /// computed cooldown (milliseconds until it admits the next call); `None`
    /// means the limiter has no precise back-off instant (the token-bucket
    /// hard limit, which has no exact refill instant to surface) and the
    /// caller should apply its own conservative back-off. Propagated from
    /// `ContextError::RateLimited.retry_after_ms` — never coerced to `0`, since
    /// `0` would read as "retry immediately" and re-trip the same hard limit.
    RateLimited {
        /// Milliseconds until the limit admits the next call, when the tripped
        /// limiter can compute it; `None` for the token-bucket hard limit.
        retry_after_ms: Option<u64>,
    },
    /// A TRANSIENT, retryable Prepare-phase abort: the target/caller participant
    /// actor was unavailable to COMPLETE the Prepare exchange, yielding a
    /// `ContextError::ActorBusy` on the Prepare-phase send. That error has three
    /// producers (see `ContextActorHandle::send`): (1) the actor's mailbox was
    /// full for the whole `SEND_TIMEOUT`, so the command was never accepted;
    /// (2) the actor's inbox is closed / the actor terminated, so the command
    /// was never accepted; or (3) the reply channel was dropped AFTER the
    /// command was received and processed (a handler panic, or actor shutdown
    /// after accepting), so the send landed but no reply came back. NEITHER side
    /// committed — the Prepare phase is staging-only (commit is a later phase
    /// this abort never reaches), and the Prepare-phase reservation is released
    /// or reconciled on every terminal path, including the reply-dropped case —
    /// so the saga aborted cleanly and the caller should retry after its own
    /// conservative back-off; there is no precise drain instant to surface, so
    /// the variant carries no `retry_after_ms` hint. Retry is meaningful because
    /// the actor may respawn (ADR-049 §10). This variant's rustdoc is the SINGLE
    /// authoritative home of the rationale for this terminal; the lift and its
    /// tests point here rather than re-deriving it. Reliably reached for the
    /// closed/terminated-inbox and reply-dropped subcases; a
    /// transiently-full-but-OPEN mailbox may currently race the phase timeout
    /// (`SEND_TIMEOUT == PHASE_TIMEOUT`) and surface as a generic Prepare timeout
    /// abort instead. Distinct from [`Self::Rejected`] (a permanent policy reject
    /// the caller must NOT blindly retry), from a commit-phase `ActorBusy` (which
    /// exhausts the commit-retry budget and lifts to `NeedsRepair`, not an
    /// abort), and from `SagaBusy` (the participant-context-set overlap gate,
    /// whose `contended_context` does not apply here).
    ParticipantUnavailable,
    /// Any other Prepare-phase rejection (authorization, freshness, schema,
    /// co-residency) — no back-off hint applies.
    Rejected,
}

/// Private error of the shared [`Supervisor::run_saga`] FSM driver. Carries the
/// FSM's internal [`ContextError`] (the type the saga FSM and the saga
/// integration tests depend on) PLUS whether the saga reached `NeedsRepair`, so
/// the boundary methods can lift it: `start_saga` discards the flag and
/// propagates the `ContextError`; `start_cross_context_outlet_invocation_saga`
/// lifts both into the typed [`SagaError`]. Not exposed — the FSM contract stays
/// `ContextError` internally.
pub struct RunSagaError {
    /// The FSM's terminal error (abort reject, NeedsRepair commit failure, …).
    pub error: ContextError,
    /// `true` iff the FSM journaled `NeedsRepair` (commit-retry exhaustion).
    pub needs_repair: bool,
    /// The canonical `SCP-SAGA-13xxx` discriminant of a §6.2.4 Prepare-axis
    /// POLICY reject, carried STRUCTURALLY off the reject path (via
    /// [`SagaReject`]) so the boundary lift reads it without parsing the message
    /// string. `None` for a codeless terminal — a mailbox / transport / journal
    /// failure or a `NeedsRepair` — which lifts to the generic saga-abort code
    /// `13067` (`NeedsRepair` ignores it: it lifts to `13065`).
    pub saga_code: Option<u16>,
}

/// The non-`Send` outlet executor the supervisor FSM runs supervisor-side
/// BETWEEN Commit-B reserve and Commit-B settle (spec §6.2.4 "Commit": the
/// generic executor cannot cross the actor mailbox per ADR-049 §3, so the
/// FSM triggers execution off the mailbox and forwards the captured output
/// to the settle round-trip).
///
/// Boxed as a trait object so [`Supervisor::run_saga_fsm`] stays
/// non-generic across saga inputs that have no executor (e.g. the
/// test-only NeedsRepair driver); only the `CrossContextOutletInvocation`
/// arm consumes it. The future is boxed for the same reason. The closure is
/// `FnOnce` — it executes the outlet exactly once (§6.2.4 "Exactly-once
/// execution"); a replayed Commit short-circuits before reaching it via
/// the actor-side `AlreadyCommitted` capture, so the FSM never invokes the
/// executor twice.
///
/// **`Send`.** "The generic executor cannot cross the mailbox" (ADR-049 §3)
/// means it is never embedded in a [`ContextCommand`] and never run on the
/// actor task — it runs supervisor-side. The closure itself IS `Send` (it
/// captures `Send` outlet-handler state, exactly like the closures
/// [`Supervisor::invoke_outlet_with_economy`] takes), so the saga future stays
/// `Send` and the block-until-terminal saga can be driven from a spawned task.
type SagaOutletExecutor<'a> = Box<
    dyn FnOnce(
            serde_json::Value,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + 'a>,
        > + Send
        + 'a,
>;

/// Shorthand for the cross-context outlet-invocation prepared state reconstructed
/// from a journal entry's evidence (spec §6.2.4 "Crash recovery §17.16.4").
type XctxPrepared =
    crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;

/// Outcome of a §17.16.4 Commit-in-progress recovery re-drive. The crash
/// recovery re-drives the idempotent Commit-B and re-acks Commit-A from the
/// durable witness, then journals the resolved terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitInProgressResolution {
    /// BOTH sides committed (B re-emitted the stored output AND the A-side
    /// `xctx_committed_invocations` witness is present): the saga is fully
    /// committed — resolve to `Committed`, NOT a false `NeedsRepair`.
    Committed,
    /// Genuinely unresolvable divergence (B committed but A did not, B never
    /// landed, or a side is unreachable): stays `NeedsRepair` for operator repair.
    NeedsRepair,
}

/// Whether a cross-context saga's CALLER-side LOCAL economy reversal (budget /
/// velocity / hard-rate-limit, deducted + Class-S-persisted at Prepare-A and
/// owned by the caller actor) was settled during an abort. This is the sole
/// input to the coordinator's terminal-marker decision (spec §6.2.4
/// "Reservation release on every terminal path"): a terminal-`Aborted` journal
/// asserts "fully compensated" and MUST NOT be written while a caller refund is
/// still outstanding. Produced by [`Supervisor::abort_xctx_participants`] (the
/// live abort path) and by [`Supervisor::redrive_xctx_prepare_in_progress`] (the
/// §17.16.4 crash-recovery `PreparingB` re-drive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerAbortReversal {
    /// The caller-side LOCAL economy was reversed (the `Abort` was delivered and
    /// the actor rolled it back), OR there was no caller reservation to reverse.
    /// The coordinator may write the terminal-`Aborted` marker.
    SettledOrAbsent,
    /// The caller-side LOCAL economy reversal could NOT be confirmed: the carrier
    /// `Abort { Some }` send failed AND the `Abort { None }` re-drive also failed
    /// (persistent backpressure / closed inbox), the caller actor was
    /// unreachable (despawned), or the delivered handler errored before durably
    /// persisting the reversal. The coordinator MUST leave the journal
    /// non-terminal (`PreparingB`) so the §17.16.4 crash-recovery sweep
    /// re-drives `Abort { None }` and reverses the LOCAL economy from the durable
    /// `CallerReservationRecord`.
    ReversalOutstanding,
}

/// The owned per-side plan [`Supervisor::divergence_marker_plan`] produces for
/// a `NeedsRepair` divergence: `(committed_event_id, nonce, [(side-label,
/// context_id, that side's Active Signing Key signer); 2])`. Each side signs +
/// appends its OWN marker (spec §6.2.4 "Dual event-log recording").
type DivergenceMarkerPlan = (
    String,
    [u8; 16],
    [(
        &'static str,
        [u8; 32],
        crate::context::actor::signer::CommandSigner,
    ); 2],
    // CONVERGENT committer-assigned leaf-timestamp (seconds) for the
    // divergence-marker leaf: B's staged `recorded_timestamp_ms / 1000`, the
    // same convergent instant the committed-side `OutletInvoked` leaf carries
    // (spec §6.2.4 *Recorded timestamp*).
    u64,
);

/// Per-saga phase-data context threaded through [`Supervisor::run_saga_fsm`]
/// for a `CrossContextOutletInvocation` saga (spec §6.2.4).
///
/// The generic FSM (journal, retry, NeedsRepair, abort, gating) stays
/// data-agnostic; this carrier holds the cross-context-specific inputs the
/// per-phase dispatch needs and accumulates the Prepare→Commit hand-off
/// data so each phase sees the prior phase's output:
///
/// - the supervisor-side outlet `executor` + the target/caller Active Signing
///   Keys (the actor holds NO key — ADR-049; the keys are supplied by the
///   FFI/SDK caller per-call, exactly like `send_heartbeat` /
///   `build_local_checkpoint`),
/// - `prepared_a` — the caller-side escrow/rate-limit reservation staged at
///   Prepare-A and held across the saga (RAII-released on any abort, settled
///   at Commit-A),
/// - `prepared_b` — B's recorded provenance from Prepare-B (B's clock / nonce /
///   re-derived chain depth). Read by [`Supervisor::xctx_prepared_evidence_bytes`] at
///   Committing-evidence time: once recorded, B's values OVERRIDE the
///   caller-asserted nonce / depth / timestamp in the journaled prepared
///   evidence (the §17.16.4 replay/crash-recovery surface), so a recovered saga
///   re-derives from B's authoritative provenance, not the caller's assertion,
/// - `committed` — the receipt + output captured at Commit-B, forwarded to
///   Commit-A and surfaced in [`SagaOutput`].
///
/// `executor` is an `Option` so it can be `take`n exactly once at Commit-B.
pub struct CrossContextSagaCtx<'a> {
    /// Raw 32-byte caller context id (A's own context).
    pub caller_context_id: [u8; 32],
    /// Raw 32-byte target context id (B's own context; where the outlet runs).
    pub target_context_id: [u8; 32],
    /// Channel-authenticated caller DID (spec §6.2.4 "Caller authentication").
    pub caller_did: DID,
    /// Context-local outlet registration id (indexes B's registry).
    pub outlet_registration_id: String,
    /// UCAN proof index into B's store (`None` ⇒ ungated outlet).
    pub ucan_proof_id: Option<String>,
    /// Outlet input — validated at Prepare-B, executed at Commit-B.
    pub input: serde_json::Value,
    /// Caller-asserted advisory chain depth (freshness/`+1` base only).
    pub asserted_chain_depth: u8,
    /// Caller-asserted 16-byte wire nonce (freshness + dual-log join key).
    pub asserted_nonce: [u8; 16],
    /// Caller-asserted send-time (ms) — §9.14 skew check only.
    pub asserted_timestamp_ms: u64,
    /// The channel-authenticated caller's role in the caller context, resolved
    /// supervisor-side at initiation (NOT envelope-asserted). Carried to
    /// Prepare-B so B enforces `InboundPolicy.allowed_source_roles` against the
    /// real role (spec §6.2.4 "Caller authentication"). `None` ⇒ no explicit
    /// role assignment.
    pub caller_source_role: Option<String>,
    /// The signer for the target context's Active Signing Key — receipt +
    /// divergence-marker signing (Commit-B / NeedsRepair). The actor holds no
    /// custody key (ADR-049); the FSM passes a clone of this caller-supplied
    /// signer with each command, and the actor signs through it in the turn
    /// (Decision 7a).
    pub target_signer: crate::context::actor::signer::CommandSigner,
    /// The signer for the caller context's Active Signing Key — used ONLY to
    /// sign the caller-side `CrossContextDivergenceMarker` on a `NeedsRepair`
    /// outcome (spec §6.2.4 "Dual event-log recording"). Distinct from
    /// `target_signer`: each side signs its OWN marker into its OWN log under
    /// its OWN Active Signing Key.
    pub caller_signer: crate::context::actor::signer::CommandSigner,
    /// The supervisor-side outlet executor, taken once at Commit-B.
    pub executor: Option<SagaOutletExecutor<'a>>,
    /// The captured outlet output bytes, stashed the moment the executor runs
    /// ONCE (Commit-B first execute), so a transient Commit-B SETTLE failure is
    /// retryable WITHOUT re-invoking the outlet (spec §6.2.4 "Exactly-once
    /// execution"). On a retry the reserve returns `ReadyToExecute` (the capture
    /// was rolled back by the failed settle's persist), but the outlet already ran
    /// and had side effects — so the FSM re-sends `CommitBSettle` with THESE
    /// stashed bytes rather than calling the (already-taken) executor again.
    /// `Some` ⇒ the outlet has executed; never call the executor when this is set.
    pub executor_output: Option<Vec<u8>>,
    /// Prepare-A's held reservation (settled at Commit-A, released on abort).
    pub prepared_a: Option<crate::context::actor::commands::PreparedAFields>,
    /// Prepare-B's recorded provenance (B's clock / nonce / re-derived depth).
    /// Read by [`Supervisor::xctx_prepared_evidence_bytes`]: once `Some`, these values
    /// override the caller-asserted nonce / depth / timestamp in the journaled
    /// prepared evidence (the §17.16.4 replay surface).
    pub prepared_b: Option<crate::context::actor::commands::PreparedBFields>,
    /// Commit-B's captured receipt + output (forwarded to Commit-A + output).
    pub committed: Option<CommittedSagaArtifacts>,
    /// The target side's `OutletInvoked` event id, captured the moment Commit-B
    /// lands (reserve `AlreadyCommitted` OR a first execution settle). `Some`
    /// proves the TARGET committed its `OutletInvoked` record even when the saga
    /// later diverges (Commit-A fails → `NeedsRepair`): the
    /// [`CrossContextDivergenceMarker`](scp_protocol::context::outlets::cross_context_saga::CrossContextDivergenceMarker) then records
    /// `committed_side = Target` and this event id (spec §6.2.4
    /// "Dual event-log recording"). `None` means Commit-B never landed, so no
    /// side committed and a `NeedsRepair` cannot have diverged the logs.
    pub committed_b_outlet_invoked_event_id: Option<String>,
    /// Set by the FSM when the saga reaches `NeedsRepair` (commit-retry
    /// exhaustion). It tells the [`Supervisor::run_saga`] tail to LEAVE any held
    /// Prepare-A escrow reservation RESERVED rather than voiding it (spec
    /// §6.2.4 "`NeedsRepair` reservation semantics": the escrow is NOT
    /// auto-voided — only the concurrency slot is released — because the
    /// operation may have partially committed; the signed
    /// [`CrossContextDivergenceMarker`](scp_protocol::context::outlets::cross_context_saga::CrossContextDivergenceMarker) + operator repair settles the escrow).
    /// Every other terminal leaves this `false`, so the tail's void-or-settle
    /// behaviour is unchanged on Aborted / unreachable-Commit-A paths.
    pub reached_needs_repair: bool,
}

/// The receipt + output captured at Commit-B, forwarded to Commit-A and
/// surfaced in [`SagaOutput`]. The `SagaId`-stable `OutletInvoked` event id is
/// carried INSIDE the signed receipt (`receipt`), so it is not duplicated
/// here — an auditor reads it from the verified receipt.
pub struct CommittedSagaArtifacts {
    /// JCS bytes of the target's signed `CrossContextOutletReceipt`.
    receipt: Vec<u8>,
    /// The captured outlet output bytes (the receipt's canonical `output_jcs`).
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
/// In-memory it is a fast read cache, but it is ALSO durably journaled (see
/// `Supervisor::record_supervisor_repair`): each record is appended to the
/// supervisor's saga journal as the `evidence` of a `NeedsRepair`
/// [`JournalEntry`], so a supervisor restart REHYDRATES it from the journal
/// rather than losing the unreachable-leg divergence account — preserving the
/// spec's "durably auditable" guarantee for that leg. The reachable side's
/// marker (when one side IS reachable) lives durably in that side's event log;
/// the unreachable half is durably recorded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaDivergenceRepairRecord {
    /// The context id (raw 32-byte digest, hex) of the UNREACHABLE side whose
    /// marker could not be appended into its own log.
    pub unreachable_context_hex: String,
    /// Which side committed (caller or target).
    pub committed_side: scp_protocol::context::outlets::cross_context_saga::CommittedSide,
    /// The committed-side `OutletInvoked` / `CrossContextOutletInvoked` event id.
    pub committed_event_id: String,
    /// The 16-byte correlation nonce joining the two event-log records.
    #[serde(with = "scp_protocol::serde_util::serde_nonce_16")]
    pub nonce: [u8; 16],
}

/// `MessagePack` (`rmp_serde::to_vec_named`) of the full accumulated repair-record
/// set for one saga, carried as the `evidence` of a durable `NeedsRepair`
/// [`JournalEntry`]. A NON-EMPTY `NeedsRepair` evidence is, by this convention,
/// the supervisor-level divergence repair journal (the plain `NeedsRepair`
/// transition appended on commit-retry exhaustion carries EMPTY evidence); the
/// recovery path decodes it to rehydrate [`Supervisor::saga_repair_records`].
fn encode_repair_records_evidence(
    records: &[SagaDivergenceRepairRecord],
) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec_named(records).map_err(|e| format!("encode repair records: {e}"))
}

/// Decode the `MessagePack` repair-record set from a durable `NeedsRepair`
/// journal entry's `evidence` (the inverse of [`encode_repair_records_evidence`]).
///
/// # Errors
///
/// A description of the decode failure when `bytes` is not a `MessagePack` repair-record
/// set.
pub fn decode_repair_records_evidence(
    bytes: &[u8],
) -> Result<Vec<SagaDivergenceRepairRecord>, String> {
    rmp_serde::from_slice(bytes).map_err(|e| format!("decode repair records: {e}"))
}

// ---------------------------------------------------------------------------
// Supervisor configuration + crash tracking
// ---------------------------------------------------------------------------

/// Default node-level concurrent outlet-stream-pump ceiling
/// (`max_concurrent_outlet_stream_pumps`), spec §5.4.5 round-8. Mirrors the
/// reference `ContextManager` default (feat/outlet-redesign). Bounds the
/// runtime's aggregate streaming task/memory footprint independent of any
/// per-context admission cap.
pub const DEFAULT_MAX_CONCURRENT_OUTLET_STREAM_PUMPS: u32 = 4096;

/// Minimum configurable node-level concurrent-pump ceiling. A value of 0
/// would deadlock all streaming, so the floor is 1.
pub const MIN_MAX_CONCURRENT_OUTLET_STREAM_PUMPS: u32 = 1;

/// Maximum configurable node-level concurrent-pump ceiling.
///
/// `tokio::sync::Semaphore` caps permits at `Semaphore::MAX_PERMITS`
/// (`usize::MAX >> 3`); 65536 is a generous practical upper bound well
/// under that limit.
pub const MAX_MAX_CONCURRENT_OUTLET_STREAM_PUMPS: u32 = 65_536;

/// Clamps a requested `max_concurrent_outlet_stream_pumps` into the
/// `[MIN, MAX]` range and constructs the backing node-wide pump semaphore.
fn build_outlet_stream_pump_semaphore(requested: u32) -> Arc<tokio::sync::Semaphore> {
    let clamped = requested.clamp(
        MIN_MAX_CONCURRENT_OUTLET_STREAM_PUMPS,
        MAX_MAX_CONCURRENT_OUTLET_STREAM_PUMPS,
    );
    Arc::new(tokio::sync::Semaphore::new(clamped as usize))
}

/// Supervisor configuration (per-node tunables). Saga phase timeouts and
/// respawn-budget windows are still derived from code constants
/// (`Supervisor::LIFECYCLE_TIMEOUT`, the Prepare phase's function-local
/// `PHASE_TIMEOUT`, and the module-level `COMMIT_PHASE_TIMEOUT` and
/// `CRASH_WINDOW_MS`) rather than this struct.
#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    /// Node-level ceiling on the number of outlet stream pumps that may run
    /// concurrently across ALL contexts on this supervisor (spec §5.4.5
    /// round-8). Sizes the shared
    /// [`Supervisor::outlet_stream_pump_semaphore`] at construction, clamped
    /// into [`MIN_MAX_CONCURRENT_OUTLET_STREAM_PUMPS`] ..=
    /// [`MAX_MAX_CONCURRENT_OUTLET_STREAM_PUMPS`]. Bounds the runtime's
    /// aggregate streaming task/memory footprint regardless of per-context
    /// admission caps. Defaults to
    /// [`DEFAULT_MAX_CONCURRENT_OUTLET_STREAM_PUMPS`].
    pub max_concurrent_outlet_stream_pumps: u32,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_outlet_stream_pumps: DEFAULT_MAX_CONCURRENT_OUTLET_STREAM_PUMPS,
        }
    }
}

/// Sliding-window length for the actor respawn budget (ADR-049 §10).
/// Crashes older than this (relative to the newest crash) are evicted
/// before the budget is evaluated.
pub const CRASH_WINDOW_MS: u64 = 60_000;

/// The budget of the supervisor-side outlet executor within one saga Commit
/// attempt (§6.2.4). The executor runs off the actor mailbox (ADR-049 §3), so
/// no actor turn bounds it.
const COMMIT_EXECUTOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The budget of one saga Commit attempt, built from its parts: the executor
/// ([`COMMIT_EXECUTOR_TIMEOUT`]), the Commit-B settle turn, which signs the
/// receipt through `CommandSigner::sign_bounded_ed25519` and so takes
/// [`SIGNING_HANDLER_TIMEOUT`](crate::context::actor::signer::SIGNING_HANDLER_TIMEOUT),
/// and 30 seconds for the Commit-B reserve and Commit-A turns.
///
/// A phase budget equal to the sign budget would expire with it, so a stalled
/// custody would surface as the phase's `TransportTimeout`. With this budget
/// the stalled sign fails first, as `SCP-CRYPTO-4062` (ADR-049 Decision 7a).
const COMMIT_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(
    COMMIT_EXECUTOR_TIMEOUT.as_secs()
        + crate::context::actor::signer::SIGNING_HANDLER_TIMEOUT.as_secs()
        + 30,
);

const _: () = assert!(
    COMMIT_PHASE_TIMEOUT.as_secs()
        > COMMIT_EXECUTOR_TIMEOUT.as_secs() + crate::context::actor::signer::SIGN_TIMEOUT.as_secs()
);
const _: () = assert!(
    COMMIT_PHASE_TIMEOUT.as_secs()
        > COMMIT_EXECUTOR_TIMEOUT.as_secs()
            + crate::context::actor::signer::SIGNING_HANDLER_TIMEOUT.as_secs()
);

/// Number of crashes within [`CRASH_WINDOW_MS`] that poisons a context
/// (ADR-049 §10): "3 crashes in 60s poisons the context."
pub const CRASH_POISON_THRESHOLD: usize = 3;

/// Defensive upper bound on the retained crash-timestamp deque. The
/// sliding-window eviction already bounds the deque to crashes within
/// [`CRASH_WINDOW_MS`], but a pathological clock (non-monotonic, or stuck)
/// could otherwise let it grow without bound. Capping at the poison
/// threshold is sufficient: once the threshold is reached the context is
/// poisoned and never respawned, so no further timestamps accrue. The cap
/// keeps the structure O(1) in space regardless of clock behaviour.
pub const CRASH_DEQUE_CAP: usize = CRASH_POISON_THRESHOLD;

/// The `crash_windows` key prefix of a per-identity KeyPackage actor's window
/// ([`Supervisor::kp_crash_key`]); no context ID starts with it.
pub const KP_CRASH_KEY_PREFIX: &str = "kp::";

/// Per-context crash-count window (ADR-049 §10 — actor respawn budget).
///
/// Tracks the wall-clock-millisecond timestamps of recent actor crashes
/// in a sliding `CRASH_WINDOW_MS` window. When `CRASH_POISON_THRESHOLD`
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
    pub poisoned: bool,
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
    /// respawn exit (success, failure, or terminal-skip). The import path
    /// sets the same marker for its replace gap
    /// ([`Supervisor::despawn_for_replace`]) and clears it when the
    /// `ImportContext` arm exits.
    respawning: bool,
}

/// The bootstrap scope [`Supervisor::begin_bootstrap_window`] returns. When
/// it drops, an id an actor now serves keeps a fresh budget, and an id no
/// actor serves gets its prior [`CrashWindow`] back.
pub struct BootstrapCrashWindow<'a> {
    supervisor: &'a Supervisor,
    context_id: String,
    prior: Option<CrashWindow>,
}

impl Drop for BootstrapCrashWindow<'_> {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(prior) if self.supervisor.lookup(&self.context_id).is_none() => {
                self.supervisor
                    .crash_windows
                    .insert(self.context_id.clone(), prior);
            }
            _ => self.supervisor.end_bootstrap_window(&self.context_id),
        }
    }
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
    pub fn record(&mut self, now_ms: u64) -> bool {
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
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whether the most recent respawn failed without poisoning the context
    /// — the "silently dead" case (ADR-049 §10). Used by
    /// [`Supervisor::lookup_miss_error`] to surface
    /// [`ContextError::ActorCrashed`] rather than `ContextNotRegistered`.
    #[must_use]
    pub const fn last_respawn_failed(&self) -> bool {
        self.last_respawn_failed
    }

    /// Record that the most recent respawn attempt failed (lost/corrupt
    /// snapshot, deps build failure). Distinct from [`Self::record`] —
    /// `record` accounts a *crash* against the sliding budget; this flag is
    /// the orthogonal "currently unrecoverable" signal that drives the
    /// lookup-miss error class. Always paired with a `record` call at the
    /// failure site.
    pub const fn mark_respawn_failed(&mut self) {
        self.last_respawn_failed = true;
    }

    /// Clear the unrecoverable flag after a respawn succeeds. The crash
    /// history (budget) is intentionally left intact — a context that
    /// flapped and then recovered must still be one crash away from its
    /// budget — but it is no longer "silently dead".
    const fn mark_respawn_succeeded(&mut self) {
        self.last_respawn_failed = false;
    }

    /// Whether the window records a context whose actor is down: poisoned,
    /// its last respawn failed, or mid-respawn. [`Supervisor::lookup_miss_error`]
    /// returns `ContextPoisoned` or `ActorCrashed` for exactly these windows,
    /// and [`Supervisor::known_context_ids`] lists their context IDs.
    const fn actor_down(&self) -> bool {
        self.poisoned || self.last_respawn_failed || self.respawning
    }

    /// Whether the context is mid-respawn (despawned, not yet re-registered).
    /// Used by [`Supervisor::lookup_miss_error`] to surface a retryable
    /// `ActorCrashed` rather than a misleading `ContextNotRegistered` during
    /// the transient respawn gap (ADR-049 §10).
    #[must_use]
    pub const fn is_respawning(&self) -> bool {
        self.respawning
    }

    /// Mark the start of a respawn (set just before the despawn). Paired with
    /// [`Self::clear_respawning`] on every respawn exit.
    pub const fn mark_respawning(&mut self) {
        self.respawning = true;
    }

    /// Clear the transient respawn marker once the respawn has completed
    /// (success, failure, or terminal-skip) and the registry once again
    /// reflects the true state.
    pub const fn clear_respawning(&mut self) {
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
    #[must_use]
    pub fn crash_count(&self) -> usize {
        self.crashes.len()
    }

    /// Operator un-poison: clear the recorded crashes and the sticky
    /// poison flag so the context can be respawned again. Distinct from
    /// the automatic window eviction in [`Self::record`], which never
    /// touches `poisoned`.
    pub fn clear(&mut self) {
        self.crashes.clear();
        self.poisoned = false;
        self.last_respawn_failed = false;
        self.respawning = false;
    }
}

/// Spawn a context actor's watchdog task (ADR-049 §10).
///
/// This is a free function — deliberately NOT an inline spawn
/// inside [`Supervisor::spawn_actor_with_watchdog`] — so the watchdog
/// future's `Send` proof is resolved here, OUTSIDE the opaque `impl
/// Future` scope of the spawn method. The watchdog reaches
/// `Supervisor::respawn_from_snapshot` → `restore_context` →
/// `Supervisor::spawn_actor_with_state` → `spawn_actor_with_watchdog`,
/// forming a self-referential async cycle. Spawning inline makes the
/// compiler try to fetch an opaque type's hidden type within its own
/// defining scope (unsupported); moving the spawn into this free fn
/// breaks that self-reference. The watchdog owns its `JoinHandle`
/// directly (TTL / governance timers are actor-owned arms — ADR-049
/// finding A3 — so no supervisor timer JoinSet exists).
///
/// The watchdog spawns through the caller's [`SpawnPermit`] onto the
/// supervisor's task tracker and holds only a `Weak<Supervisor>` while it
/// waits (ADR-049 Decision 16). It upgrades once the actor exits, for the one
/// crash-handling operation; a failed upgrade means every owner dropped the
/// Supervisor, so no respawn is possible and the watchdog ends.
fn spawn_actor_watchdog_task(
    permit: &SpawnPermit<'_>,
    supervisor: std::sync::Weak<Supervisor>,
    ctx_id: String,
    owning_did: DID,
    join: tokio::task::JoinHandle<()>,
) {
    permit.spawn(async move {
        let outcome = join.await;
        let Some(supervisor) = supervisor.upgrade() else {
            log_watchdog_without_supervisor("context_actor", &ctx_id, &outcome);
            return;
        };
        supervisor.actor_watchdog(ctx_id, owning_did, outcome).await;
    });
}

/// Logs an actor exit that a watchdog observed after every owner dropped the
/// Supervisor. A clean exit is the expected end of a drained actor; a panic
/// can no longer be respawned and is reported without its payload (the
/// ADR-049 §10 payload-free rule).
fn log_watchdog_without_supervisor(
    actor_kind: &'static str,
    subject: &str,
    outcome: &Result<(), tokio::task::JoinError>,
) {
    match outcome {
        Err(e) if JoinFailure::from_join_error(e) == JoinFailure::Panicked => tracing::error!(
            actor_kind,
            subject,
            panic_location = "unknown",
            "actor panicked after its supervisor dropped; not respawned, payload intentionally not logged"
        ),
        Ok(()) | Err(_) => tracing::debug!(
            actor_kind,
            subject,
            "actor exited after its supervisor dropped"
        ),
    }
}

/// Log line for a streaming-open escrow reversal task that ended without
/// returning. A panic is named without its payload (the ADR-049 §10
/// payload-free rule; a `JoinError`'s `Display` carries the payload), and a
/// cancellation, such as its runtime shutting down, is named as one.
#[must_use]
pub fn escrow_reversal_join_failure_message(err: &tokio::task::JoinError) -> &'static str {
    match JoinFailure::from_join_error(err) {
        JoinFailure::Panicked => {
            "streaming open escrow reversal task panicked — the hold may stay debited; \
             payload intentionally not logged"
        }
        JoinFailure::Cancelled => {
            "streaming open escrow reversal task was cancelled — the hold may stay debited"
        }
    }
}

/// How a spawned task ended without returning. It holds no panic payload (the
/// ADR-049 §10 payload-free rule; a `JoinError`'s `Display` carries the
/// payload), so its `Display` is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinFailure {
    /// The task panicked.
    Panicked,
    /// The task was cancelled, for example because its runtime shut down.
    Cancelled,
}

impl JoinFailure {
    /// Classifies `err` without reading its payload.
    #[must_use]
    pub fn from_join_error(err: &tokio::task::JoinError) -> Self {
        if err.is_panic() {
            Self::Panicked
        } else {
            Self::Cancelled
        }
    }
}

impl std::fmt::Display for JoinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Panicked => "task panicked; payload intentionally not logged",
            Self::Cancelled => "task was cancelled",
        })
    }
}

/// Clears a [`Supervisor::discard_joined_context`] pending mark on drop, so a
/// discarding call that ends or is dropped before it hands the exit wait to a
/// task never leaves the id refused forever.
struct PendingDiscardMark<'a> {
    supervisor: &'a Supervisor,
    context_id: &'a str,
}

impl Drop for PendingDiscardMark<'_> {
    fn drop(&mut self) {
        self.supervisor.pending_discards.remove(self.context_id);
    }
}

/// Finishes a [`Supervisor::discard_joined_context`] whose exit wait timed out,
/// from the tracked task, after the discarded actor has exited.
///
/// Holds a `Weak<Supervisor>` (ADR-049 Decision 16) and the persistence
/// strongly: once the Supervisor has dropped, its floor and tracker registries
/// dropped with it, but the snapshot is durable and still has to go. Nobody
/// awaits this task, so a failure is logged at error level.
async fn finish_discard_after_exit(
    supervisor: &std::sync::Weak<Supervisor>,
    persistence: Option<&Arc<dyn ContextPersistence>>,
    context_id: &str,
) {
    let result = match supervisor.upgrade() {
        Some(supervisor) => {
            let finished = supervisor.finish_discard(context_id).await;
            supervisor.pending_discards.remove(context_id);
            finished
        }
        None => match persistence {
            Some(persistence) => persistence.delete_context(context_id).await.map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "discard of joined context '{context_id}': snapshot delete failed: {e}"
                ))
            }),
            None => Ok(()),
        },
    };
    if let Err(error) = result {
        tracing::error!(
            context_id,
            %error,
            "discard of a joined context did not finish after its actor exited"
        );
    }
}

/// Spawn a `KeyPackageStoreActor`'s watchdog task (ADR-049 §10).
///
/// The per-identity twin of [`spawn_actor_watchdog_task`]. A free function for
/// the same reason: the watchdog reaches `Supervisor::kp_actor_watchdog` →
/// `Supervisor::respawn_kp_actor` → `Supervisor::key_package_store_for` →
/// (spawn), which forms a self-referential async cycle the compiler refuses to
/// resolve when spawned inline. The watchdog owns its `JoinHandle` directly
/// (no supervisor timer JoinSet exists — timers are actor-owned arms, ADR-049
/// finding A3).
///
/// Spawns through the caller's [`SpawnPermit`] and holds a `Weak<Supervisor>`,
/// exactly as [`spawn_actor_watchdog_task`] does (ADR-049 Decision 16).
fn spawn_kp_actor_watchdog_task(
    permit: &SpawnPermit<'_>,
    supervisor: std::sync::Weak<Supervisor>,
    identity: DID,
    join: tokio::task::JoinHandle<()>,
) {
    permit.spawn(async move {
        let outcome = join.await;
        let Some(supervisor) = supervisor.upgrade() else {
            log_watchdog_without_supervisor("key_package_store", &identity.0, &outcome);
            return;
        };
        supervisor.kp_actor_watchdog(identity, outcome).await;
    });
}

/// Permission to spawn onto the Supervisor's task tracker (ADR-049 Decision
/// 16), issued by [`Supervisor::spawn_permit`] only while the closed flag is
/// clear.
///
/// The permit holds the read guard of the closed flag, so
/// `shutdown_all_contexts` cannot set the flag, and therefore cannot take its
/// actor snapshot, while a permit is alive. Take a permit, register what the
/// spawned task serves, spawn, and drop the permit, all without an `.await`
/// in between: the guard is `!Send`, so holding it across an `.await` fails to
/// compile in any spawned future.
pub(in crate::context) struct SpawnPermit<'a> {
    tracker: &'a tokio_util::task::TaskTracker,
    _closed: std::sync::RwLockReadGuard<'a, bool>,
}

impl SpawnPermit<'_> {
    /// Spawns `future` onto the Supervisor's task tracker, marked as a
    /// tracked task (see [`tracked_task_marker`]).
    pub(in crate::context) fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn_marked(self.tracker, future)
    }

    /// A [`SubtaskSpawner`] for the actor this permit spawns, onto the same
    /// tracker.
    pub(in crate::context) fn subtask_spawner(&self) -> SubtaskSpawner {
        SubtaskSpawner {
            tracker: self.tracker.clone(),
        }
    }
}

/// Spawns a tracked actor's own subtasks, such as a `KeyPackage` store's mint,
/// onto the Supervisor's task tracker (ADR-049 Decision 16). Issued by
/// [`SpawnPermit::subtask_spawner`] to the actor the permit spawns. It holds
/// no tracker token: the actor that spawns through it is itself a tracked
/// task, so the tracker is not empty while a subtask can start, and the drain
/// waits for every subtask as it waits for the actor.
#[derive(Clone)]
pub(in crate::context) struct SubtaskSpawner {
    tracker: tokio_util::task::TaskTracker,
}

impl SubtaskSpawner {
    /// Spawns `future` onto the tracker, marked as a tracked task (see
    /// [`tracked_task_marker`]).
    pub(in crate::context) fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn_marked(&self.tracker, future)
    }

    /// A spawner over a tracker of its own, for tests that run an actor with
    /// no Supervisor.
    #[cfg(any(test, feature = "testing"))]
    pub fn standalone() -> Self {
        Self {
            tracker: tokio_util::task::TaskTracker::new(),
        }
    }
}

/// Spawns onto the Supervisor's task tracker for one operation that began
/// before shutdown, such as a streaming open that starts its pump and its
/// seal task (ADR-049 Decision 16, item 2). Issued by
/// [`Supervisor::tracked_spawner`]. It holds a tracker token, so the tracker
/// is not empty while the spawner lives: the drain waits for the operation
/// that holds it and for every task spawned through it.
#[derive(Clone)]
pub struct TrackedSpawner {
    tracker: tokio_util::task::TaskTracker,
    _token: tokio_util::task::task_tracker::TaskTrackerToken,
}

impl TrackedSpawner {
    /// Spawns `future` onto the Supervisor's task tracker, marked as a
    /// tracked task (see [`tracked_task_marker`]).
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn_marked(&self.tracker, future)
    }

    /// [`Self::spawn`] on `runtime`, for a caller that may run off a runtime
    /// thread, such as a `Drop`.
    fn spawn_on<F>(
        &self,
        future: F,
        runtime: &tokio::runtime::Handle,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tracker.spawn_on(
            tracked_task_marker().scope(self.tracker.clone(), future),
            runtime,
        )
    }
}

/// The escrow-refund sink of a streaming open's escrow ticket.
///
/// It hands the [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)'s
/// `Drop` refund to a task spawned through the open's
/// [`TrackedSpawner`], so a refund fired after `shutdown_all_contexts` has
/// begun still runs (ADR-049 Decision 16, item 2, second exception). That
/// task awaits the [`ActorEscrowRefundSink`](crate::context::outlets::stream_settlement_adapter::ActorEscrowRefundSink)
/// refund itself and spawns nothing further.
pub struct SpawnerEscrowRefundSink {
    /// The sink the spawned task runs.
    inner: Arc<crate::context::outlets::stream_settlement_adapter::ActorEscrowRefundSink>,
    /// A clone of the open's spawner.
    spawner: TrackedSpawner,
    /// Runtime handle captured at construction, so the `Drop`-fired refund
    /// can spawn even when it runs off a runtime thread.
    runtime: tokio::runtime::Handle,
}

impl SpawnerEscrowRefundSink {
    /// Builds the sink for an open on `supervisor` that holds `spawner`,
    /// capturing the current runtime handle.
    pub fn new(supervisor: &Arc<Supervisor>, spawner: &TrackedSpawner) -> Self {
        Self {
            inner: Arc::new(
                crate::context::outlets::stream_settlement_adapter::ActorEscrowRefundSink::new(
                    Arc::downgrade(supervisor),
                ),
            ),
            spawner: spawner.clone(),
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl crate::context::outlets::dispatch::StreamEscrowRefundSink for SpawnerEscrowRefundSink {
    fn refund(
        &self,
        context_id: &str,
        member_did: &DID,
        amount: scp_protocol::economy::types::Amount,
    ) {
        let inner = Arc::clone(&self.inner);
        let context_id = context_id.to_owned();
        let member_did = member_did.clone();
        drop(self.spawner.spawn_on(
            async move { inner.refund(&context_id, &member_did, amount).await },
            &self.runtime,
        ));
    }
}

/// The result of [`Supervisor::drain_with_deadline`].
#[derive(Debug)]
pub enum DrainWithDeadline<T> {
    /// The drain and the post-drain step finished within the deadline; holds
    /// the post-drain step's value.
    Finished(T),
    /// The drain task ended without returning: the drain or the post-drain
    /// step panicked, or the task was cancelled.
    Failed(JoinFailure),
    /// The deadline passed first. The drain keeps running, and its result
    /// goes to the `on_late` callback.
    TimedOut,
}

/// The kind of work a tracked task hands to a task of its own through
/// [`Supervisor::spawn_tracked_on`]. The variants are the two kinds ADR-049
/// Decision 16 item 2 admits after the closed flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkHandoff {
    /// A streaming settlement routed to the context actor.
    StreamSettlement,
    /// The append of a stream's close-time `OutletInvokedEvent`.
    OutletInvokedEventAppend,
}

impl SinkHandoff {
    /// Returns the name this hand-off carries in logs and errors.
    pub(in crate::context) const fn label(self) -> &'static str {
        match self {
            Self::StreamSettlement => "stream settlement",
            Self::OutletInvokedEventAppend => "streaming OutletInvokedEvent append",
        }
    }
}

/// The task-local every task spawned onto a Supervisor's tracker runs inside.
/// It holds a clone of that tracker, so [`Supervisor::spawn_tracked_on`] can
/// tell a task tracked by this Supervisor from any other caller (ADR-049
/// Decision 16, item 2).
fn tracked_task_marker() -> &'static tokio::task::LocalKey<tokio_util::task::TaskTracker> {
    tokio::task_local! {
        static TRACKED_TASK: tokio_util::task::TaskTracker;
    }
    &TRACKED_TASK
}

/// Spawns `future` onto `tracker` inside the [`tracked_task_marker`] scope.
fn spawn_marked<F>(
    tracker: &tokio_util::task::TaskTracker,
    future: F,
) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tracker.spawn(tracked_task_marker().scope(tracker.clone(), future))
}

/// Whether the calling code runs inside a task spawned onto `tracker`.
fn in_tracked_task(tracker: &tokio_util::task::TaskTracker) -> bool {
    tracked_task_marker()
        .try_with(|own| tokio_util::task::TaskTracker::ptr_eq(own, tracker))
        .unwrap_or(false)
}

/// Flat, named-field request for
/// [`Supervisor::start_cross_context_outlet_invocation_saga`] (spec §6.2.4).
///
/// Carries the §6.2.4 invocation envelope field set by **value**. Replaces a
/// long positional argument list whose adjacent `[u8; 32]` ids
/// (`caller_context_id` / `target_context_id`) and asserted-provenance scalars
/// were transposable at a call site — a swap compiled and would silently sign
/// and record the saga under the wrong context, the confused-deputy footgun the
/// named fields foreclose. Per the project's Agent-first API tenet: one flat
/// config object, every field named, no builder, no ordering to track.
///
/// The two Active Signing Key signers (carried in the named-field [`SagaSigners`])
/// and the supervisor-side outlet executor stay explicit parameters of the entry
/// point — they are not envelope data (the keys are custody material the actor
/// never holds; the executor is a non-`Send` closure), so folding them onto the
/// wire request would mix envelope fields with capabilities.
#[derive(Debug, Clone)]
pub struct CrossContextOutletInvocationRequest {
    /// Raw 32-byte id of the caller (initiating) context.
    pub caller_context_id: [u8; 32],
    /// Raw 32-byte id of the target (executing) context.
    pub target_context_id: [u8; 32],
    /// Channel-authenticated DID of the initiator.
    pub caller_did: DID,
    /// Registration id of the outlet being invoked across the interface.
    pub outlet_registration_id: String,
    /// Optional id of the spending UCAN proof, resolved target-side at
    /// Prepare-B. `None` for an ungated outlet.
    pub ucan_proof_id: Option<String>,
    /// Outlet input payload (JSON), schema-checked target-side.
    pub input: serde_json::Value,
    /// Caller-asserted inbound provenance chain depth; B re-derives `+1`.
    pub asserted_chain_depth: u8,
    /// Caller-asserted 16-byte envelope nonce, checked against B's dedup cache.
    pub asserted_nonce: [u8; 16],
    /// Caller-asserted send-time (Unix ms), checked against §9.14 skew.
    pub asserted_timestamp_ms: u64,
}

/// Relay TTL (seconds) for a delivered invitation bundle (spec §5.12.3.3 —
/// 7-day default).
const INVITATION_TTL_SECS: u32 = 7 * 24 * 60 * 60;

// Security-model spec §9.18.7: the adder's minimum remaining KeyPackage
// lifetime covers the InvitationBundle relay TTL plus the lifetime margin, so a
// joiner fetching its Welcome while the relay still holds the bundle finds its
// own KeyPackage current. `u64::from` is not const, so the widening is `as`.
const _: () = assert!(
    scp_mls::KEY_PACKAGE_MIN_REMAINING_LIFETIME_SECS
        >= INVITATION_TTL_SECS as u64 + scp_mls::KEY_PACKAGE_LIFETIME_MARGIN_SECS
);

/// Outcome of [`Supervisor::invite_member`].
///
/// An extensible enum with a SINGLE variant today. `invite_member` currently
/// supports only `SingleAdmin` contexts, where the caller-as-admin is
/// authorized to add the member unilaterally: the governance action
/// auto-executes, the real MLS add runs in-actor (updating `role_state`,
/// broadcasting the epoch-advancing Commit to existing members), and the
/// resulting Welcome is sealed into a signed §5.12.3 `InvitationBundle` for the
/// invitee — surfaced here as [`Self::Sealed`].
///
/// A voting-governed context (Threshold / Majority / Unanimity) instead returns
/// `Err`: a unilateral invite is NOT authorized and governed-context
/// invitations (create + track a proposal, seal the Welcome once approved and
/// executed) are not yet implemented — see `invite_member`. When they are, a
/// second variant carrying the tracked proposal id is added ADDITIVELY; the
/// enum shape is preserved for exactly that forward extension.
#[derive(Debug, Clone)]
pub enum InviteMemberOutcome {
    /// The invitation was sealed and (best-effort) delivered.
    Sealed {
        /// The creator-signed, HPKE-sealed invitation bundle (`context_id`,
        /// `creator_did`, `enc`, `ciphertext`) — the SAME wire type the joiner
        /// passes to [`Supervisor::spawn_actor_from_welcome`], so the invite
        /// output is directly usable as the join input with no re-boxing.
        bundle: scp_runtime_types::context::invitation_helpers::SealedInvitation,
        /// `true` if the runtime published the sealed invitation to the
        /// invitee's `scp-invitations` routing id; `false` if the transport
        /// does not support routing-id delivery (the caller must deliver
        /// `bundle` itself).
        delivered: bool,
    },
}

/// Flat, named-field request for [`Supervisor::spawn_actor_from_welcome`]
/// (ADR-049 Phase 2J, spawn-from-Welcome; FFI-02 Option A). A config object (not
/// positional args) per the agent-first API tenet: an LLM constructs it from the
/// field names + one example, with no argument-order footgun. The joiner's OWN
/// identity is passed separately (as a `DID` on the `Supervisor` method, or as
/// the unforgeable `&OwnedIdentityDid` capability on the `SupervisorHandle`
/// wrapper) so it cannot be transposed with `creator_did`.
///
/// The request carries the creator-signed, HPKE-sealed
/// [`InvitationBundle`](scp_protocol::context::InvitationBundle) — NOT loose
/// caller-supplied params. `spawn_actor_from_welcome` opens the bundle (split
/// custody), verifies the creator signature, and derives ALL authority
/// (`creator_did`, `context_params`, `welcome_message`) from the AUTHENTICATED
/// bundle. `context_id` / `creator_did` here are UNTRUSTED binding hints used
/// only to rebuild the HPKE `info`/`aad`; they are AEAD-authenticated by a
/// successful open and additionally cross-checked against the signed bundle.
pub struct WelcomeJoinRequest {
    /// UNTRUSTED binding hint: the context id used to build the HPKE `info`/`aad`
    /// (`hex(digest)` under ADR-056). Cross-checked against `bundle.context_id`
    /// after the open; authority derives from the signed bundle, never this.
    pub context_id: String,
    /// UNTRUSTED binding hint: the creator did used to build the HPKE
    /// `info`/`aad`. Cross-checked against `bundle.creator_did` after the open.
    pub creator_did: DID,
    /// RFC 9180 HPKE encapsulated key (`enc`) of the sealed invitation
    /// bundle: the 65-byte uncompressed DHKEM(P-256) point (§9.16.2). The
    /// join validates it before any custody call; any other form is
    /// [`ContextError::CryptoFailed`].
    pub sealed_bundle_enc: Vec<u8>,
    /// RFC 9180 HPKE ciphertext (`ct`) of the MessagePack-serialized
    /// [`InvitationBundle`](scp_protocol::context::InvitationBundle).
    pub sealed_bundle_ct: Vec<u8>,
    /// The reservation id of the KeyPackage this Welcome was addressed to,
    /// obtained from the joiner's `KeyPackageStoreActor` `Reserve`.
    pub reservation_id: crate::context::supervisor::key_package_actor::ReservationId,
    /// The joiner's §9.10.4 local pseudonym for this context, or `None`.
    pub local_pseudonym: Option<[u8; 32]>,
}

/// The signers for the two Active Signing Keys a §6.2.4 cross-context saga
/// signs under, named by role so the call site cannot transpose them.
///
/// `target` and `caller` are the SAME type; passed as two adjacent positional
/// parameters a swap would compile and stay self-consistent (verification uses
/// whichever key was supplied), silently signing each side's divergence marker
/// under the wrong key — the same confused-deputy footgun the named-field
/// [`CrossContextOutletInvocationRequest`] foreclosed one layer up for the
/// `[u8; 32]` ids. Naming the role at the call site (`SagaSigners { target: …,
/// caller: … }`) makes a swap a visible field-name error, not a silent
/// miscapture. Per the Agent-first API tenet: one flat named-field object, no
/// ordering to track.
///
/// Each signer reaches its key through custody (ADR-049 Decision 7a): the
/// runtime never holds the key bytes. The signers are capabilities, NOT
/// envelope data, so they stay off the wire
/// [`CrossContextOutletInvocationRequest`].
#[derive(Debug, Clone)]
pub struct SagaSigners {
    /// The target context's Active Signing Key signer. Signs the
    /// [`CrossContextOutletReceipt`]
    /// and the TARGET-side divergence marker on a one-sided `NeedsRepair`.
    pub target: crate::context::actor::signer::CommandSigner,
    /// The caller context's Active Signing Key signer. Signs the CALLER-side
    /// divergence marker on `NeedsRepair`.
    pub caller: crate::context::actor::signer::CommandSigner,
}

/// The Phase-1 (pre-pump) outputs of an outlet-stream open, shared by
/// [`Supervisor::open_outlet_stream`] (same-context best-effort) and the
/// SCP-OUT-046 cross-context streaming-saga producer. Extracting the reserve →
/// escrow-ticket → §7.3.8 caveat-hook → `ContextParams` caps/timing →
/// admission/semaphore prologue keeps that money path in ONE place
/// (orchestrator decision 1: a behavior-preserving EXTRACT, never duplicated).
///
/// Deliberately SINK-AGNOSTIC: the helper builds NEITHER the close-time
/// `settlement_sink` NOR the durable `OutletInvoked` sink. Each caller supplies
/// both, because the streaming saga needs BOTH OFF — `settlement_sink = None`
/// so the saga settles from its durable Class-S ledger at seal-close, AND no
/// durable `OutletInvoked` sink because the saga's seal records B's
/// `OutletInvoked` itself (installing the pump's sink too would DOUBLE-record
/// the B-side leaf, SCP-OUT-046 AC5). The same-context caller installs both.
///
/// The §7.3.8 post-input check is `'static` (built by
/// [`build_stream_post_input_hook`](crate::context::shared::outlets::build_stream_post_input_hook),
/// which clones the effective caveats + counter-store `Arc` into the closure
/// rather than borrowing the binding), so this struct carries no lifetime — the
/// caller need not keep `caveat_binding` alive past the helper call.
struct OutletStreamPhase1 {
    /// The in-actor economy reservation — context/role snapshots, spawn
    /// generation, the debited `reserved_escrow`, and the acceptance-time policy.
    reservation: crate::context::shared::outlets::StreamEconomyReservation,
    /// The armed open-failure escrow guard. On a successful open the caller
    /// `consume`s it (the pump's close-time settlement then owns the refund); on
    /// a rejection the caller drops it so its `Drop` reverses the debited hold.
    escrow_ticket: crate::context::outlets::dispatch::StreamEscrowTicket,
    /// `params` with the manager-debited escrow hold, the acceptance-time
    /// economic-policy snapshot, and the authoritative `ContextParams` admission
    /// caps + timing/window policy all filled in.
    params: crate::context::outlets::dispatch::OpenStreamParams,
    /// The §7.3.8 synchronous post-input check (a `'static` closure over the
    /// cloned effective caveats + counter store), or `None` for an unbound /
    /// ungated open.
    caveat_post_input_check: Option<crate::context::outlets::invoke::CaveatPostInputCheck<'static>>,
    /// The durable §7.3.8 counter reservation committed at the pump's final open
    /// gate, or `None` when the effective caveats carry no counter-bearing cap.
    counter_reservation: Option<crate::context::outlets::dispatch::StreamCounterReservation>,
    /// Per-context admission tracker (per-invoker + per-outlet).
    admission: Arc<std::sync::RwLock<StreamAdmissionTracker>>,
    /// Operator-scoped per-origin-invoker admission tracker.
    origin_admission: Arc<std::sync::RwLock<OriginAdmissionTracker>>,
    /// Node-level concurrent-pump semaphore.
    pump_semaphore: Arc<tokio::sync::Semaphore>,
}

/// The prompt return of
/// [`Supervisor::start_cross_context_streaming_outlet_invocation_saga`]
/// (SCP-OUT-046 #134, ADR-061 seal phase). Handed to the caller at the
/// Commit-transition — BEFORE the stream drains — so the caller consumes frames
/// as B produces them (AC1), while the off-mailbox seal task pumps the durable
/// frontier capture + the seal-close asynchronously (AC6: the journal is
/// `Committing` here; `Committed` is reached inside the seal task at close).
///
/// `receiver` yields A's plaintext unmodified operator-signed
/// [`OutletStreamChunk`](scp_protocol::context::outlets::stream::OutletStreamChunk)s,
/// forwarded verbatim (the bridge never re-signs and introduces no new
/// send-sequence at the plaintext hand-off, §5.4.5). Re-encryption for A's OTHER
/// members is the SDK delivery seam (seal each still-operator-signed chunk under
/// A's MLS group key, its per-sender MLS send-sequence reserved at the
/// §9.16/§5.15.7 encrypt seam over A's persistent counter — SCP-OUT-047), NOT
/// this return type — mirroring the best-effort
/// [`open_outlet_stream_cross_context`](Supervisor::open_outlet_stream_cross_context).
pub struct StreamingSagaHandle {
    /// The durable saga id — the operator-repair handle a crash-recovery
    /// resolution keys on, and the id the seal task seals under.
    pub saga_id: SagaId,
    /// A's plaintext operator-signed chunk receiver, returned promptly (AC1).
    pub receiver:
        tokio::sync::mpsc::Receiver<scp_protocol::context::outlets::stream::OutletStreamChunk>,
}

// ---------------------------------------------------------------------------
// MessageSigner (ADR-039)
// ---------------------------------------------------------------------------

/// Pairs the signer with its verification method so the persona stamped on
/// the wire cannot disagree with the key that signed. Every send path requires a
/// signer, so this is non-optional.
///
/// ADR-039 — the inner envelope's `signing_key_id` (`#active` / `#agent`)
/// selects which DID-document verification method the recipient resolves to
/// check the signature. Carrying the signer and its persona as two independent
/// arguments let a caller stamp `#agent` while signing with the `#active` key
/// (or vice versa), producing a message the recipient cannot verify. This enum
/// binds the two together: [`Self::signing_key_id`] is derived from the same
/// variant that carries the signer, so the stamp and the key are one source of
/// truth. The single stamp+sign site
/// (`build_encrypted_envelope_actor`)
/// takes the `MessageSigner` directly. The signer is a [`CommandSigner`]
/// (ADR-049 Decision 7a): the key stays in custody.
///
/// [`CommandSigner`]: crate::context::actor::signer::CommandSigner
#[derive(Clone, Copy)]
pub enum MessageSigner<'a> {
    /// Sign under the human `#active` verification method.
    Active(&'a crate::context::actor::signer::CommandSigner),
    /// Sign under the autonomous `#agent` verification method (ADR-039).
    Agent(&'a crate::context::actor::signer::CommandSigner),
}

impl<'a> MessageSigner<'a> {
    /// The signer, regardless of persona.
    #[must_use]
    pub const fn signer(&self) -> &'a crate::context::actor::signer::CommandSigner {
        match self {
            Self::Active(s) | Self::Agent(s) => s,
        }
    }

    /// The verification method (`#active` / `#agent`) this signer stamps —
    /// derived from the same variant that carries the key, so the stamped
    /// persona and the signing key can never disagree.
    #[must_use]
    pub const fn signing_key_id(&self) -> scp_did::SigningKeyId {
        match self {
            Self::Active(_) => scp_did::SigningKeyId::Active,
            Self::Agent(_) => scp_did::SigningKeyId::Agent,
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Plain struct — not an actor. See module-level docs for rationale.
///
/// The write path (any mutation of `actors`, `standing_contexts`,
/// `local_dids`, or `wrapping_keys`) acquires `Self::write_lock` first,
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
    /// per-context actor shares the SAME swap cell: [`ActorDeps`](crate::context::actor::deps::ActorDeps) receives
    /// an `Arc::clone` of this field, not a snapshot copy. A bare
    /// `ArcSwap` would force the actor-deps builder to take a point-in-time
    /// `load_full()` snapshot, and any DID registered AFTER an actor is
    /// spawned (e.g. the creator's DID, which `register_local_did` records
    /// only after `context_create` has already spawned the actor) would be
    /// invisible to that actor's `local_dids` view — breaking the
    /// author-DID-controlled gate on broadcast key requests.
    pub(in crate::context::supervisor) local_dids: Arc<ArcSwap<HashSet<DID>>>,
    /// The 13 domain handlers (ADR-070 §3). Core reaches domain code only
    /// through this value; every actor's `ActorDeps::domains` shares it.
    pub(crate) domains: Arc<crate::context::domains::DomainHandlers>,
    /// Per-identity DHKEM(P-256) wrapping keys (spec 09 §9.16.1), the only
    /// writer of each identity's key. [`Self::load_wrapping_key`] fills an
    /// entry from durable storage (or generates and stores one) at every entry
    /// point that builds an actor for the identity, before any lock is taken;
    /// [`Self::wrapping_key`] reads it. An entry never changes once inserted,
    /// so the identity's `KeyPackageStoreActor` holds the same `Arc`.
    pub(in crate::context::supervisor) wrapping_keys: DashMap<DID, Arc<IdentityWrappingKey>>,
    /// Per-identity load locks of [`Self::load_wrapping_key`]: two concurrent
    /// first loads of one identity load or generate once. Lock order:
    /// `wrapping_key_loads[owner]` → [`Self::write_lock`]. No shard lock of
    /// this map is held across an await.
    #[allow(
        clippy::disallowed_types,
        reason = "ADR-049 §Decision 12 allow-list: per-identity guard held across the custody awaits of a first wrapping-key load. Cold path (once per identity per process), so the Mutex acquire cost the ban targets does not apply."
    )]
    pub(in crate::context::supervisor) wrapping_key_loads:
        DashMap<DID, Arc<tokio::sync::Mutex<()>>>,
    /// Finds the custody that holds each identity's wrapping key. Every
    /// constructor takes it from its caller, except the test-only ones, which
    /// install one shared in-memory custody ([`Self::testing_wrapping_custody`]).
    pub(in crate::context::supervisor) wrapping_custody: WrappingCustodySource,
    /// The in-memory custody a test-only constructor installed behind
    /// [`Self::wrapping_custody`]; empty when the caller supplied the source.
    #[cfg(any(test, feature = "testing"))]
    testing_wrapping_custody: OnceLock<Arc<scp_platform::testing::InMemoryKeyCustody>>,
    /// Persistence backend. [`Self::build_actor_deps`] hands it to every actor
    /// as `ActorDeps::persistence`. Every shipped constructor fills it with the
    /// caller's required backend.
    pub(in crate::context::supervisor) persistence: Arc<dyn ContextPersistence>,
    /// Single-producer-multi-read write lock — plan §"Write path".
    #[allow(
        clippy::disallowed_types,
        reason = "ADR-049 §Decision 12 allow-list: the ArcSwap+write_lock write-serialization guard. Cold write path (not a per-command read), so the Mutex acquire cost the ban targets does not apply."
    )]
    pub write_lock: tokio::sync::Mutex<()>,
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
    ///
    /// No actor turn waits for this lock, because its holders wait on actor
    /// mailboxes: the migration create, which runs in the source context's
    /// actor turn, try-locks it through
    /// [`SupervisorHandle::try_lock_bootstrap_spawn`](crate::context::supervisor::handle::SupervisorHandle::try_lock_bootstrap_spawn)
    /// and fails with a retryable `ActorBusy` while another bootstrap holds
    /// it, and work that must wait for it runs on a tracked task through
    /// [`SupervisorHandle::spawn_under_bootstrap_spawn_lock`](crate::context::supervisor::handle::SupervisorHandle::spawn_under_bootstrap_spawn_lock).
    /// It is held behind an `Arc` so that task holds the lock without
    /// holding the Supervisor.
    #[allow(
        clippy::disallowed_types,
        reason = "ADR-049 §Decision 12 allow-list: serializes the same-id bootstrap-spawn sequence. Cold bootstrap path (not a per-command read), so the Mutex acquire cost the ban targets does not apply."
    )]
    pub(crate) bootstrap_spawn_lock: Arc<tokio::sync::Mutex<()>>,
    /// Durable saga journal (plan §"Cross-context saga protocol").
    pub(in crate::context::supervisor) saga_journal: Arc<dyn SagaJournal>,
    /// Per-identity `KeyPackageStoreActor` handles.
    pub(in crate::context::supervisor) key_package_stores: DashMap<DID, KeyPackageStoreHandle>,
    /// Per-challenger `ChallengerLedgerActor` handles, keyed by the
    /// challenger's canonical identifier (spec 07 §7.3.4).
    pub(in crate::context::supervisor) challenger_ledgers: DashMap<
        String,
        crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerHandle,
    >,
    /// The one task tracker every supervisor-held task spawns through
    /// (ADR-049 Decision 16, supervisor task drain); Decision 16 item 1 states
    /// which tasks are members. Spawn only through [`Self::spawn_permit`],
    /// [`Self::spawn_tracked`], [`Self::spawn_tracked_on`], or a
    /// [`TrackedSpawner`] from [`Self::tracked_spawner`].
    /// [`Self::shutdown_all_contexts`] closes the tracker and awaits it.
    task_tracker: tokio_util::task::TaskTracker,
    /// The closed flag of ADR-049 Decision 16: `true` once
    /// [`Self::shutdown_all_contexts`] has begun. A spawner holds the read
    /// guard (inside a [`SpawnPermit`], or inside [`Self::spawn_tracked_on`])
    /// across the synchronous spawn call, and shutdown takes the write guard
    /// to set the flag, so no spawn that passed the check can land after
    /// shutdown's snapshot. The guard is never held across an `.await`;
    /// `std::sync::RwLock` is the workspace-permitted lock for a synchronous
    /// critical section.
    spawn_gate: std::sync::RwLock<bool>,
    /// Cancelled when the closed flag is set. Every streaming pump selects on
    /// it, so a pump parked on a credit grant or on its executor closes with
    /// `ContextClosedMidStream` instead of holding the drain (ADR-049
    /// Decision 16).
    shutdown_token: tokio_util::sync::CancellationToken,
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
    /// ADR-049 (read-authority switch) — supervisor-owned Class-M **floor
    /// registry**. Keyed by the 32-byte context id. Each [`ContextFloors`](crate::context::supervisor::floors::ContextFloors)
    /// bundles the per-sender epoch high-water and the receive-side
    /// `(epoch, sequence)` anti-replay floor. This is the AUTHORITATIVE Class-M
    /// home: the live receive seams gate on it fail-closed, the durable-blob
    /// export sources from it, and the restore/import guard merges into it. The
    /// provider's former floor mirrors are deleted.
    /// Lives on `Arc<Supervisor>` so it survives an actor task unwind — the
    /// Class-M requirement the floors exist to satisfy. Lock-free entry-scoped
    /// reads/writes via `DashMap` (ADR-049 Decision 12); an entry mutation does
    /// NOT take [`Self::write_lock`] (that guards the multi-field ArcSwap write
    /// path per Decision 2). Precedent: `crash_windows` above.
    pub(in crate::context::supervisor) floors:
        DashMap<[u8; 32], crate::context::supervisor::floors::ContextFloors>,
    /// Test-only completion signal for the KeyPackage-actor watchdog.
    ///
    /// A monotonically-incrementing counter bumped by [`Self::kp_actor_watchdog`]
    /// exactly once per crash it fully processes — AFTER the crash is recorded in
    /// `crash_windows` AND after the respawn-or-poison decision has taken effect
    /// (dead handle removed + fresh actor respawned, or the identity poisoned).
    ///
    /// This lets the KP-poison/recovery tests wait for the *event* (the watchdog
    /// observing a crash and settling its state) rather than polling
    /// `is_context_poisoned` against a wall-clock budget. A bounded poll can
    /// starve under CPU load and false-timeout; awaiting this watch signal
    /// cannot — it settles precisely when the watchdog has done its work. Gated
    /// behind `testing` so production builds carry neither the field nor the
    /// `send_modify` call (zero overhead, no behavior change).
    #[cfg(feature = "testing")]
    pub(in crate::context::supervisor) kp_watchdog_processed_tx: tokio::sync::watch::Sender<u64>,
    /// One-shot test seam: when set, the NEXT spawn-from-Welcome step-3b crypto
    /// durability check (ADR-049 PR-7 / SCP-CRYPTOMOVE-001) treats the ACTOR
    /// [`PerContextState::export_crypto_state`](crate::context::actor::state::PerContextState::export_crypto_state)
    /// as NON-durable and clears the flag.
    ///
    /// The crypto move relocated `export_crypto_state` off the provider onto the
    /// seeded actor `state`, and the spawn durability check now reads
    /// `state.export_crypto_state(...)`; the former provider `arm_export_failure_once`
    /// seam no longer sits on that path. This supervisor-resident seam lets the
    /// spawn-from-Welcome durability fail-closed branch be driven end-to-end (the
    /// real actor export always yields a durable blob for a just-installed group,
    /// so the branch is otherwise structurally unreachable). Armed pre-spawn via
    /// [`Self::arm_welcome_export_failure_once`]; consulted (and cleared) inside
    /// `spawn_actor_from_welcome`. Gated so production builds carry neither the
    /// field nor the branch.
    #[cfg(any(test, feature = "testing"))]
    pub(in crate::context::supervisor) force_welcome_export_failure_once:
        std::sync::atomic::AtomicBool,
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
    // ADR-049 §15 — providers lifted from ContextManager (now
    // authoritative on Supervisor).
    //
    // Each `OnceLock<Arc<...>>` provider slot is populated directly by
    // [`Self::with_providers_and_journal`]. There is no `ContextManager` to attach
    // — the supervisor IS the source of truth for every provider after
    // ADR-049 §15. Slots are still wrapped in `OnceLock` so the
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
    /// Shared crypto provider. Populated by [`Self::with_providers_and_journal`].
    crypto: OnceLock<Arc<crate::crypto::mls::provider::NodeMlsFactory>>,
    /// Shared transport binding. Populated by [`Self::with_providers_and_journal`]
    /// with a [`TransportSlot`](super::TransportSlot) around the caller's
    /// provider. The `OnceLock` is set once; the provider inside the slot is
    /// rebound through an `ArcSwap` (lock-free read per ADR-049 Decision 12).
    transport: OnceLock<Arc<super::TransportSlot>>,
    /// Shared event-log provider. Populated by [`Self::with_providers_and_journal`].
    event_log: OnceLock<Arc<dyn ContextEventLogProvider>>,
    /// Helper-side persistence slot. [`Self::with_providers_and_journal`]
    /// fills it with the same backend as [`Self::persistence`]. It stays empty
    /// only on the test-only constructors (`Self::new`, `Self::for_query_shim`,
    /// and `Self::with_providers` with `persistence: None`); helpers branch on
    /// `persistence_ref().is_some()` for those harnesses.
    helper_persistence: OnceLock<Arc<dyn ContextPersistence>>,
    /// Ids whose [`Self::discard_joined_context`] removed the actor and has
    /// not yet finished its teardown. Marked under `bootstrap_spawn_lock` and
    /// `write_lock` together with the registry removal, cleared once the
    /// teardown has run (or when the discarding call is dropped before
    /// handing the wait to a task). A discard of a marked id is refused, so it
    /// cannot delete the snapshot while the first discard's actor can still
    /// write it, and a respawn of a marked id is refused
    /// (`refuse_pending_discard`), so it cannot restore the context from the
    /// snapshot the discard is about to delete.
    pending_discards: dashmap::DashSet<String>,
    /// Context ids whose first-state writes a create, import, Welcome join,
    /// standing-context create or migration create has started and not yet
    /// committed or rolled back
    /// ([`crate::context::shared::lifecycle::FirstStateRollback`]). A
    /// rollback drains those writes with `bootstrap_spawn_lock` released, so
    /// this set, not the lock, keeps another bootstrap of the id from
    /// writing or spawning between the failure and the rollback: a second
    /// first-state write of a claimed id is refused, and so is a restore or
    /// respawn (`refuse_pending_first_state`), which would otherwise start an
    /// actor from the failed operation's snapshot.
    pub(in crate::context::supervisor) pending_first_state: dashmap::DashSet<String>,
    /// Notified each time a `pending_first_state` claim is released, so the
    /// crash watchdog, whose respawn a standing claim refuses, respawns once
    /// the claim's operation commits or rolls back.
    pub(in crate::context::supervisor) first_state_settled: tokio::sync::Notify,
    /// Wall-clock source. Populated by [`Self::with_providers_and_journal`] (or
    /// defaulted to [`scp_clock::SystemClock`] when the caller
    /// passes `None`).
    clock: OnceLock<Arc<dyn Clock>>,
    /// Key resolver for governance signature verification. The type is
    /// itself an `Arc<dyn Fn(...)>` alias (see
    /// [`scp_protocol::context::governance::KeyResolver`]), so storing a
    /// clone is a reference-count bump.
    key_resolver: OnceLock<KeyResolver>,
    /// Optional payment adapter. Empty `OnceLock` means "no adapter
    /// configured"; populated by [`Self::with_providers_and_journal`] when the
    /// caller passes `Some(adapter)`. There is no post-construction
    /// setter — the deleted prior `set_payment_adapter` opened a
    /// two-paths-to-set seam that no production caller used.
    payment_adapter: OnceLock<Arc<dyn PaymentAdapterDyn>>,
    /// Optional broadcast sender for fan-out of [`ContextEvent`]s to
    /// external consumers. Empty `OnceLock` means "no channel
    /// configured".
    event_tx: OnceLock<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    /// Bumped each time a context actor is added to or removed from
    /// `actors`, the two changes that add or drop a context's push routes
    /// without a [`ContextEvent`]. [`Self::push_routes_changed`] hands out
    /// receivers; the push registrar re-reads the routes on each bump
    /// (`10-infrastructure-and-self-hosting.md` §10.7.1 **Re-registration**).
    push_routes_tx: tokio::sync::watch::Sender<u64>,
    /// OpenMLS storage adapter — the bridge's chosen Storage, erased once via
    /// `SpawnBlockingStorageAdapter`. Runtime NEVER defaults this. Lock-free
    /// read per ADR-049 §Decision 12.
    mls_storage:
        OnceLock<Arc<dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>,
    /// The store of each context's last successful relay contact (ADR-029
    /// key `sync/{context_id}/last_relay_contact`): the one instance every
    /// writer and reader uses. A production supervisor takes it from
    /// [`DurableProviders`], over the same storage handle as `mls_storage`.
    relay_contacts: Arc<dyn crate::store::sync::RelayContactStore>,

    // -----------------------------------------------------------------
    // ADR-049 §15 — supervisor-authoritative direct fields.
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
    /// [`ContextError::ActorBusy`]
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
    /// starts with no reservations). When a later phase of the ADR-049 saga work
    /// wires [`Self::replay_unresolved_sagas`] at startup, it MUST rebuild
    /// reservations for non-terminal unresolved journal entries — EXCLUDING
    /// `NeedsRepair` entries, whose slots are deliberately released — so a
    /// replay-driven re-drive of an in-flight saga re-takes its set before
    /// the first post-restart `start_saga` can race it.
    ///
    /// REPLAY RESERVATION RECONSTRUCTION — the journal participant record for a
    /// `CrossContextOutletInvocation` (built by [`saga_input_participants`])
    /// deliberately does NOT persist `target_context_id` ("Leave the journal
    /// shape UNCHANGED"): it records only `{caller_context_id, caller_did,
    /// outlet_registration_id}`. But the gating set
    /// ([`saga_participant_context_set`]) is `{caller, target}`. A naïve replay
    /// that rebuilds reservations from the participant record alone could only
    /// re-reserve `{caller}`, NOT `{caller, target}` — leaving the `target`
    /// context slot free and letting a fresh post-restart saga touch it
    /// concurrently, defeating the §5.15.4 cross-context serialization for the
    /// recovery window. This gap is CLOSED via **option (a)**: the
    /// `PreparingB` / `Committing` journal entries carry the eight-field
    /// `CrossContextOutletInvocationPrepared` evidence (which embeds BOTH
    /// `caller_context_id` AND `target_context_id`), so
    /// [`Self::reconstruct_xctx_prepared`] rebuilds the COMPLETE `{caller,
    /// target}` set from the evidence — see [`Self::xctx_prepared_evidence_bytes`].
    /// When the startup replay loop rebuilds reservations for non-terminal
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
    /// A outlet-economy reservation captures the generation of the actor
    /// instance it reserved against; the Phase-3 settle rejects if the
    /// generation no longer matches (the actor was despawned and a new
    /// instance respawned for the same `context_id` between reserve and
    /// settle), preventing a settle from capturing or refunding against a
    /// DIFFERENT context instance's owned state. This is the confused-deputy
    /// guard for the reserve→execute→settle split: the executor runs
    /// supervisor-side (non-`Send`) outside the actor's serialized mailbox,
    /// so the actor instance identity must be re-verified at settle time.
    spawn_generation: std::sync::atomic::AtomicU64,

    // -----------------------------------------------------------------
    // Outlet streaming (spec §5.4.5) — supervisor-owned pump resources.
    // -----------------------------------------------------------------
    /// Node-wide ceiling on concurrently-running outlet stream pumps
    /// (spec §5.4.5 round-8). A pump permit is acquired AFTER all
    /// per-context admission / escrow gates pass in `open_outlet_stream`
    /// and held for the exact lifetime of the pump task (released on
    /// normal close, terminal, cancel-ack, or panic); saturation
    /// hard-rejects the open. Per-INSTANCE (ADR-048): owned by this
    /// supervisor, never a process-global static (a global would be caught
    /// by `check-no-mutable-globals`). Sized at construction from
    /// [`SupervisorConfig::max_concurrent_outlet_stream_pumps`] via
    /// [`build_outlet_stream_pump_semaphore`]. Read via
    /// [`Self::outlet_stream_pump_semaphore`].
    outlet_stream_pump_semaphore: Arc<tokio::sync::Semaphore>,
    /// Per-context §5.4.5 round-5 stream admission trackers, keyed by
    /// `context_id`. Get-or-created on stream open via
    /// [`Self::outlet_stream_admission_for`] and dropped on permanent
    /// context teardown via [`Self::reap_stream_admission`] (the twin of
    /// the [`Self::floors`] / [`Self::crash_windows`] teardown reap; NOT
    /// reaped on a respawn's transient despawn, so the per-context caps
    /// survive crash-recovery). The inner
    /// `Arc<std::sync::RwLock<StreamAdmissionTracker>>` is the exact type
    /// the off-mailbox pump (`dispatch::open_stream_session`) consumes; the
    /// outer `RwLock` guards the registry map. `std::sync::RwLock` is the
    /// sanctioned off-mailbox primitive here (clippy.toml bans only the
    /// tokio RwLock / Mutex read-path variants), and its guard is only ever
    /// taken in synchronous critical sections — never held across an
    /// `.await`. Removing a map entry drops only the registry's `Arc`
    /// reference: an in-flight pump holding its own `Arc` clone keeps the
    /// tracker alive until the pump ends.
    outlet_stream_admission:
        Arc<std::sync::RwLock<HashMap<String, Arc<std::sync::RwLock<StreamAdmissionTracker>>>>>,
    /// Operator-scoped §5.4.5 per-origin-invoker admission
    /// tracker. A SINGLE instance for the whole supervisor (operator) —
    /// deliberately NOT keyed by `context_id` like
    /// [`Self::outlet_stream_admission`] — so the per-origin-invoker
    /// concurrent-stream cap is enforced across EVERY context the operator
    /// hosts. This is the spec-mandated defense against a caller fanning
    /// out across a cluster of the operator's interfaces (contexts) to open
    /// `N × max_concurrent_inbound_streams_per_origin_invoker` streams and
    /// saturate the node-wide pump semaphore (§5.4.5 round-8). Handed to
    /// `dispatch::open_stream_session` alongside the per-context tracker;
    /// the off-mailbox pump increments it on admit and decrements it on
    /// stream close. Entries self-remove at zero, so it needs no teardown
    /// reap. `std::sync::RwLock` is the sanctioned off-mailbox primitive
    /// (matching [`Self::outlet_stream_admission`]); its guard is only ever
    /// taken in synchronous critical sections, never across an `.await`.
    outlet_stream_origin_admission: Arc<std::sync::RwLock<OriginAdmissionTracker>>,
}

/// The two durable providers — the saga journal and the `OpenMLS` `mls_storage`
/// view — bound into one value GUARANTEED to share a single `Storage` backend
/// (spec §17.6 / §17.16 / ADR-049).
///
/// The only non-test constructor is [`Self::from_handle`], which derives BOTH
/// providers from a single `Arc<S>`. A production construction site therefore
/// physically cannot wire the saga journal to a different backend than
/// `mls_storage`: the same-backend invariant is enforced by the type system,
/// not by convention or a source-text gate. (A reviewer proved that deriving the
/// two providers via separate module-level calls let a single mutated
/// constructor pass a fresh `InMemoryStorage` to the journal while leaving every
/// gate/test green — silently disabling crash-recovery replay. Folding the pair
/// behind one handle, and making the pair the ONLY accepted argument to
/// [`Supervisor::with_providers_and_journal`], makes that divergence impossible
/// by construction.)
///
/// The inner fields are private and the only consumer is the `pub(crate)`
/// `Self::into_parts`, so no out-of-crate caller (FFI bridge, node) can
/// decompose the pair and re-pair the halves with divergent backends — they can
/// only pass the whole `DurableProviders` to the supervisor constructor.
///
/// `Clone` is cheap (two `Arc` clones). Bridges that hold the pair in a field
/// between instance construction and supervisor build clone it out at build
/// time; the clone shares the same backend, preserving the invariant.
#[derive(Clone)]
pub struct DurableProviders {
    saga_journal: Arc<dyn SagaJournal>,
    mls_storage: Arc<dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    /// The store of each context's last successful relay contact (ADR-029
    /// key `sync/{context_id}/last_relay_contact`), over the same handle.
    relay_contacts: Arc<dyn crate::store::sync::RelayContactStore>,
}

impl DurableProviders {
    /// Derives BOTH durable providers — the saga journal and the `OpenMLS`
    /// `mls_storage` view — from ONE `Storage` handle (spec §17.6 / §17.16 /
    /// ADR-049).
    ///
    /// This is the ONLY non-test constructor. The journal is a
    /// [`ProtocolRepositorySagaJournal`](scp_runtime_types::context::supervisor::saga_journal::ProtocolRepositorySagaJournal)
    /// over a clone of `handle`; `mls_storage` is the same `handle` erased once
    /// via
    /// [`SpawnBlockingStorageAdapter`](scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter).
    /// Because both derive from the one `Arc<S>`, the journal, the `OpenMLS`
    /// view, persistence, and the event log all read/write a single backend.
    #[must_use]
    pub fn from_handle<S>(handle: Arc<S>) -> Self
    where
        S: scp_platform::traits::Storage + 'static,
    {
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(
            scp_runtime_types::context::supervisor::saga_journal::ProtocolRepositorySagaJournal::new(Arc::clone(&handle)),
        );
        let relay_contacts: Arc<dyn crate::store::sync::RelayContactStore> = Arc::new(
            crate::store::sync::StorageRelayContactStore::new(Arc::clone(&handle)),
        );
        let mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        > = Arc::new(
            scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                handle,
            ),
        );
        Self {
            saga_journal,
            mls_storage,
            relay_contacts,
        }
    }

    /// Test/legacy constructor: pairs an arbitrary caller-supplied journal with
    /// an arbitrary caller-supplied `mls_storage`.
    ///
    /// Gated behind `test`/`testing` so production FFI/node construction sites
    /// cannot reach a divergence-permitting constructor — only the
    /// same-backend-by-construction [`Self::from_handle`] is available to them.
    /// The saga-FSM / crash-recovery / journal-swap integration suites use this
    /// to drive the REAL journal write-ordering over a shared in-memory store
    /// (they build the journal and `mls_storage` over one store deliberately).
    ///
    /// The relay-contact store is a fresh in-memory one;
    /// [`Self::for_test_with_relay_contacts`] takes a caller-supplied store.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn for_test(
        saga_journal: Arc<dyn SagaJournal>,
        mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        >,
    ) -> Self {
        Self::for_test_with_relay_contacts(saga_journal, mls_storage, in_memory_relay_contacts())
    }

    /// Test constructor: [`Self::for_test`] with a caller-supplied
    /// relay-contact store, for tests that observe or fail its writes.
    ///
    /// Compiled only under `test` or the `testing` feature.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn for_test_with_relay_contacts(
        saga_journal: Arc<dyn SagaJournal>,
        mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        >,
        relay_contacts: Arc<dyn crate::store::sync::RelayContactStore>,
    ) -> Self {
        Self {
            saga_journal,
            mls_storage,
            relay_contacts,
        }
    }

    /// Pairs an `mls_storage` view with the no-op saga journal.
    ///
    /// Compiled only under `test` or the `testing` feature, for the test-only
    /// [`Supervisor::with_providers`]. A shipped build has no constructor that
    /// pairs `mls_storage` with a journal that stores nothing (§17.17
    /// `SCP-CAPSEL-8000`).
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn with_noop_journal(
        mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        >,
    ) -> Self {
        Self {
            saga_journal: Arc::new(NoOpSagaJournal),
            mls_storage,
            relay_contacts: in_memory_relay_contacts(),
        }
    }

    /// Returns a read-only clone of the `mls_storage` (`OpenMLS`) view.
    ///
    /// Intended for callers that need to inspect the mls backend — e.g. the FFI
    /// bridges' passphrase round-trip / fail-closed proofs, which run through
    /// scp-runtime-as-a-dependency where `cfg(test)` does not apply. Reading a
    /// half for assertions is harmless: the same-backend invariant is preserved
    /// because the only way to BUILD a `DurableProviders` pair remains
    /// [`Self::from_handle`]. This accessor returns a clone of one half and so
    /// cannot be used to wire a divergent journal/mls pair.
    #[must_use]
    pub fn mls_storage(
        &self,
    ) -> Arc<dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter> {
        Arc::clone(&self.mls_storage)
    }

    /// Decomposes the pair into its journal + `mls_storage` halves.
    ///
    /// `pub(crate)` — the ONLY consumer is
    /// [`Supervisor::with_providers_and_journal`] inside this crate. Keeping it
    /// crate-private is what prevents an out-of-crate caller from splitting the
    /// pair and re-pairing the halves with divergent backends.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Arc<dyn SagaJournal>,
        Arc<dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
        Arc<dyn crate::store::sync::RelayContactStore>,
    ) {
        (self.saga_journal, self.mls_storage, self.relay_contacts)
    }
}

/// A relay-contact store over fresh in-memory storage, for the test-only
/// supervisor constructors.
#[cfg(any(test, feature = "testing"))]
fn in_memory_relay_contacts() -> Arc<dyn crate::store::sync::RelayContactStore> {
    Arc::new(crate::store::sync::StorageRelayContactStore::new(Arc::new(
        scp_platform::in_memory::InMemoryStorage::new(),
    )))
}

/// The providers [`Supervisor::bootstrap`] installs, as named fields.
///
/// `persistence` backs the supervisor's own persistence field and every actor's
/// `ActorDeps::persistence`; `helper_persistence` fills the helper-side slot
/// that `persistence_ref()` reads. [`Supervisor::with_providers_and_journal`]
/// sets both to the caller's required persistence. Only the test-only
/// `Supervisor::with_providers` leaves `helper_persistence` empty.
struct ProviderBootstrap {
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    key_resolver: KeyResolver,
    persistence: Arc<dyn ContextPersistence>,
    helper_persistence: Option<Arc<dyn ContextPersistence>>,
    payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
    event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    clock: Option<Arc<dyn Clock>>,
    durable: DurableProviders,
    wrapping_custody: WrappingCustodySource,
    /// The in-memory custody behind `wrapping_custody` when the test-only
    /// `Supervisor::with_providers` built it.
    #[cfg(any(test, feature = "testing"))]
    testing_wrapping_custody: Option<Arc<scp_platform::testing::InMemoryKeyCustody>>,
    /// The 13 domain handlers the supervisor and every actor call (ADR-070).
    domains: crate::context::domains::DomainHandlers,
}

impl Supervisor {
    /// Per-context lifecycle operation budget (ADR-049 §10). Bounds
    /// `restore_context` on BOTH the `RestoreContext` dispatch arm and the
    /// watchdog respawn (`respawn_from_snapshot`) so a hung storage provider
    /// cannot pin the global `bootstrap_spawn_lock` indefinitely. A single
    /// associated const keeps the two call sites in lock-step.
    pub const LIFECYCLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Constructs a fresh supervisor.
    ///
    /// `persistence` and `saga_journal` are injected at construction so
    /// the supervisor is never a singleton — bridge instances in
    /// `scp_ffi_common::bridge_instance` construct one per SCP
    /// instance and drop it on `shutdown`.
    ///
    /// Compiled only under `test` or the `testing` feature; production
    /// builds construct through [`Self::with_providers_and_journal`], which
    /// calls `new_inner`. Integration tests in `crates/scp-runtime/tests/` reach
    /// the constructor through the `testing`-feature gate so they can
    /// build supervisors without provider wiring.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn new(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
        domains: crate::context::domains::DomainHandlers,
    ) -> Self {
        Self::with_in_memory_wrapping_custody(persistence, saga_journal, health_config, domains)
    }

    /// `new_inner` over one shared in-memory wrapping custody, which
    /// [`Self::testing_wrapping_custody`] returns.
    #[cfg(any(test, feature = "testing"))]
    fn with_in_memory_wrapping_custody(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
        domains: crate::context::domains::DomainHandlers,
    ) -> Self {
        let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
        let supervisor = Self::new_inner(
            persistence,
            saga_journal,
            health_config,
            crate::crypto::wrapping::single_custody_source(Arc::clone(&custody)),
            in_memory_relay_contacts(),
            domains,
        );
        let _ = supervisor.testing_wrapping_custody.set(custody);
        supervisor
    }

    /// The in-memory custody behind this supervisor's wrapping keys when a
    /// test-only constructor chose it; `None` when the caller supplied the
    /// source. Tests generate keys in it so the supervisor and the test share
    /// one custody.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn testing_wrapping_custody(
        &self,
    ) -> Option<Arc<scp_platform::testing::InMemoryKeyCustody>> {
        self.testing_wrapping_custody.get().cloned()
    }

    /// The custody `KeyHandle` of `owner`'s wrapping key, loading the key
    /// first. Tests use it to act on that one key in custody (destroy it,
    /// read it) without scanning handles.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::load_wrapping_key`].
    #[cfg(any(test, feature = "testing"))]
    pub async fn testing_wrapping_key_handle(
        &self,
        owner: &DID,
    ) -> Result<scp_platform::KeyHandle, ContextError> {
        Ok(*self.load_wrapping_key(owner).await?.handle())
    }

    /// Internal constructor reachable from production builds. The public
    /// surface goes through [`Self::with_providers_and_journal`]; the test-only
    /// `Self::new` alias forwards here so the same body services both
    /// the production factory and the test integration suites.
    #[must_use]
    pub(crate) fn new_inner(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
        wrapping_custody: WrappingCustodySource,
        relay_contacts: Arc<dyn crate::store::sync::RelayContactStore>,
        domains: crate::context::domains::DomainHandlers,
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
        // ADR-049 §Decision 12 allow-list: the ArcSwap+write_lock and
        // same-id bootstrap-spawn serialization guards. Cold write/bootstrap
        // paths (not per-command reads), so the Mutex acquire cost the ban
        // targets does not apply. Hoisted into `let`s to carry the `#[allow]`
        // the same way `reserved_saga_contexts` above does.
        #[allow(
            clippy::disallowed_types,
            reason = "ADR-049 §Decision 12 allow-list: ArcSwap+write_lock write-serialization guard; cold write path, not a per-command read."
        )]
        let write_lock = tokio::sync::Mutex::new(());
        #[allow(
            clippy::disallowed_types,
            reason = "ADR-049 §Decision 12 allow-list: same-id bootstrap-spawn serialization guard; cold bootstrap path, not a per-command read."
        )]
        let bootstrap_spawn_lock = Arc::new(tokio::sync::Mutex::new(()));
        // Size the node-wide pump ceiling from the config knob (clamped into
        // range). Read `health_config` BEFORE it is moved into the struct
        // literal below. §5.4.5 round-8.
        let outlet_stream_pump_semaphore =
            build_outlet_stream_pump_semaphore(health_config.max_concurrent_outlet_stream_pumps);
        Self {
            actors: DashMap::new(),
            standing_contexts: ArcSwap::new(Arc::new(HashMap::new())),
            local_dids: Arc::new(ArcSwap::new(Arc::new(HashSet::new()))),
            wrapping_keys: DashMap::new(),
            wrapping_key_loads: DashMap::new(),
            wrapping_custody,
            #[cfg(any(test, feature = "testing"))]
            testing_wrapping_custody: OnceLock::new(),
            persistence,
            write_lock,
            bootstrap_spawn_lock,
            pending_discards: dashmap::DashSet::new(),
            pending_first_state: dashmap::DashSet::new(),
            first_state_settled: tokio::sync::Notify::new(),
            saga_journal,
            key_package_stores: DashMap::new(),
            challenger_ledgers: DashMap::new(),
            task_tracker: tokio_util::task::TaskTracker::new(),
            spawn_gate: std::sync::RwLock::new(false),
            shutdown_token: tokio_util::sync::CancellationToken::new(),
            health_config,
            crash_windows: DashMap::new(),
            // ADR-049 (read-authority switch): supervisor-owned authoritative Class-M floor registry.
            floors: DashMap::new(),
            // Test-only KP-watchdog completion signal (see field docs). The
            // paired receiver is created on demand via `kp_watchdog_processed_tx.subscribe()`;
            // dropping the initial one here is fine — `watch::Sender::send_modify`
            // notifies regardless of live receivers, and `subscribe()` reads the
            // current value.
            #[cfg(feature = "testing")]
            kp_watchdog_processed_tx: tokio::sync::watch::channel(0u64).0,
            #[cfg(any(test, feature = "testing"))]
            force_welcome_export_failure_once: std::sync::atomic::AtomicBool::new(false),
            saga_repair_records: DashMap::new(),
            // ADR-049 §15 — providers lifted from
            // ContextManager. Populated by `with_providers`.
            crypto: OnceLock::new(),
            transport: OnceLock::new(),
            event_log: OnceLock::new(),
            helper_persistence: OnceLock::new(),
            clock: OnceLock::new(),
            key_resolver: OnceLock::new(),
            payment_adapter: OnceLock::new(),
            event_tx: OnceLock::new(),
            push_routes_tx: tokio::sync::watch::channel(0u64).0,
            mls_storage: OnceLock::new(),
            relay_contacts,
            reserved_saga_contexts,
            // Generation 0 is never stamped onto a live actor (the first
            // spawn increments to 1 before stamping), so a default
            // `PerContextState::generation == 0` can never collide with a
            // real spawn generation.
            spawn_generation: std::sync::atomic::AtomicU64::new(0),
            // Outlet streaming (spec §5.4.5) — pump ceiling sized above; the
            // admission registry starts empty (populated lazily per context
            // on the first stream open).
            outlet_stream_pump_semaphore,
            outlet_stream_admission: Arc::new(std::sync::RwLock::new(HashMap::new())),
            // §5.4.5: a SINGLE operator-scoped origin
            // admission tracker, shared across every context this
            // supervisor (operator) hosts. NOT keyed by context — that is
            // the whole point: the per-origin-invoker cap must span all of
            // the operator's contexts so one origin cannot fan out across a
            // cluster of interfaces to bypass the per-context limit.
            outlet_stream_origin_admission: Arc::new(std::sync::RwLock::new(
                OriginAdmissionTracker::new(),
            )),
            domains: Arc::new(domains),
        }
    }

    /// Arms the one-shot `Self::force_welcome_export_failure_once` seam: the
    /// NEXT spawn-from-Welcome step-3b crypto durability check treats the actor
    /// export as NON-durable and clears the flag (ADR-049 PR-7 /
    /// SCP-CRYPTOMOVE-001).
    ///
    /// Test-only (see the field docs) — drives the spawn-from-Welcome
    /// crypto-durability fail-closed branch, which the real actor export cannot
    /// otherwise reach (an installed group always exports a durable blob).
    #[cfg(any(test, feature = "testing"))]
    pub fn arm_welcome_export_failure_once(&self) {
        self.force_welcome_export_failure_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test-only constructor used by saga + spawn unit tests that never
    /// invoke a provider-touching helper.
    ///
    /// Builds a [`Supervisor`] whose `persistence` and `saga_journal`
    /// fields are no-op stubs — saga FSM tests assert the coordinator's
    /// observable state transitions, and spawn tests exercise registry
    /// insertion only. Production code paths build supervisors through
    /// [`Self::with_providers_and_journal`], which wires real providers; bridge
    /// instances in `scp_ffi_common::bridge_instance` never call
    /// `for_query_shim`.
    ///
    /// Gated behind the `testing` feature so production FFI builds
    /// cannot reach a provider-less supervisor.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn for_query_shim(domains: crate::context::domains::DomainHandlers) -> Self {
        let persistence: Arc<dyn ContextPersistence> =
            Arc::new(crate::context::persistence::NoOpContextPersistence);
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoOpSagaJournal);
        Self::with_in_memory_wrapping_custody(
            persistence,
            saga_journal,
            SupervisorConfig::default(),
            domains,
        )
    }

    /// Test-only constructor: builds a supervisor over the given providers with
    /// the no-op saga journal (`NoOpSagaJournal`), so the saga coordinator
    /// runs but never durably journals.
    ///
    /// Compiled only under `test` or the `testing` feature. A shipped build
    /// constructs through [`Self::with_providers_and_journal`], which takes a
    /// durable journal and a required context persistence, so no shipped
    /// constructor installs a no-op persistence or journal (§17.17
    /// `SCP-CAPSEL-8000`; ADR-049).
    ///
    /// `persistence: None` gives the supervisor's own persistence field and
    /// every actor it builds a
    /// [`NoOpContextPersistence`](crate::context::persistence::NoOpContextPersistence)
    /// and leaves the helper-side slot empty, so `persistence_ref()` returns
    /// `None`: helpers skip best-effort persists and `restore_all_contexts`
    /// returns `PersistenceFailed`.
    ///
    /// The other arguments match [`Self::with_providers_and_journal`], except
    /// that `mls_storage` arrives alone and is paired with the no-op journal,
    /// and that the wrapping custody is one shared in-memory custody, which
    /// [`Self::testing_wrapping_custody`] returns.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    #[allow(clippy::too_many_arguments)] // mirrors the provider bootstrap of `with_providers_and_journal`
    pub fn with_providers(
        crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
        persistence: Option<Box<dyn ContextPersistence>>,
        payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
        event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
        clock: Option<Arc<dyn Clock>>,
        mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        >,
        domains: crate::context::domains::DomainHandlers,
    ) -> Arc<Self> {
        let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
        let wrapping_custody = crate::crypto::wrapping::single_custody_source(Arc::clone(&custody));
        Self::with_test_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            persistence,
            payment_adapter,
            event_tx,
            clock,
            mls_storage,
            wrapping_custody,
            Some(custody),
            domains,
        )
    }

    /// [`Self::with_providers`] over the caller's wrapping custody source,
    /// for a test whose supervisor custody must be a wrapper (a counting or
    /// key-losing custody) or must outlive one supervisor (a restart).
    /// [`Self::testing_wrapping_custody`] returns `None`.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    #[allow(clippy::too_many_arguments)] // mirrors the provider bootstrap of `with_providers_and_journal`
    pub fn with_providers_and_wrapping_custody(
        crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
        persistence: Option<Box<dyn ContextPersistence>>,
        payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
        event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
        clock: Option<Arc<dyn Clock>>,
        mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        >,
        wrapping_custody: WrappingCustodySource,
        domains: crate::context::domains::DomainHandlers,
    ) -> Arc<Self> {
        Self::with_test_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            persistence,
            payment_adapter,
            event_tx,
            clock,
            mls_storage,
            wrapping_custody,
            None,
            domains,
        )
    }

    /// The body of the two test-only provider constructors.
    #[cfg(any(test, feature = "testing"))]
    #[allow(clippy::too_many_arguments)] // mirrors the provider bootstrap of `with_providers_and_journal`
    fn with_test_providers(
        crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
        persistence: Option<Box<dyn ContextPersistence>>,
        payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
        event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
        clock: Option<Arc<dyn Clock>>,
        mls_storage: Arc<
            dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
        >,
        wrapping_custody: WrappingCustodySource,
        testing_wrapping_custody: Option<Arc<scp_platform::testing::InMemoryKeyCustody>>,
        domains: crate::context::domains::DomainHandlers,
    ) -> Arc<Self> {
        let helper_persistence: Option<Arc<dyn ContextPersistence>> = persistence.map(Arc::from);
        let persistence: Arc<dyn ContextPersistence> = helper_persistence.as_ref().map_or_else(
            || Arc::new(crate::context::persistence::NoOpContextPersistence) as _,
            Arc::clone,
        );
        Self::bootstrap(ProviderBootstrap {
            crypto,
            transport,
            event_log,
            key_resolver,
            persistence,
            helper_persistence,
            payment_adapter,
            event_tx,
            clock,
            durable: DurableProviders::with_noop_journal(mls_storage),
            wrapping_custody,
            testing_wrapping_custody,
            domains,
        })
    }

    /// Constructs a supervisor that owns every provider the deleted
    /// `ContextManager` held (ADR-049 §15). Every production seam (the `PyO3`
    /// reference bridge, NAPI, `UniFFI`, scp-node) constructs through this
    /// function; the returned `Arc<Supervisor>` is the only handle it holds.
    ///
    /// The saga journal and the `OpenMLS` `mls_storage` view arrive as one
    /// [`DurableProviders`] built by [`DurableProviders::from_handle`] over the
    /// caller's single chosen `Storage` backend, so a production caller cannot
    /// wire the journal to a divergent backend (spec §17.6 / §17.16).
    ///
    /// **Visibility (`pub`, intentional).** The bridge-path bootstrap test
    /// (`scp-testing`, a separate crate) constructs a supervisor with a durable
    /// saga journal and a populated persistence slot, the two ingredients a real
    /// [`Self::restore_on_startup`] needs to exercise restore-then-replay through
    /// the FFI bridge entry.
    ///
    /// # Arguments
    ///
    /// * `crypto` — production
    ///   [`NodeMlsFactory`](crate::crypto::mls::provider::NodeMlsFactory).
    /// * `transport` — production transport (typically
    ///   [`NotConfiguredTransportProvider`](crate::context::builder::NotConfiguredTransportProvider),
    ///   [`LocalTransportProvider`](crate::context::builder::LocalTransportProvider), or a real
    ///   `scp_transport::RelayTransportProvider`).
    /// * `event_log` — event log provider, usually backed by
    ///   `MerkleEventLogProvider::with_persistence(...)` so entries
    ///   survive restart.
    /// * `key_resolver` — DID-to-Ed25519-key resolver for governance
    ///   signature verification.
    /// * `persistence` — **required** context persistence. It backs the
    ///   supervisor's own persistence field, the helper-side slot, and every
    ///   actor's `ActorDeps::persistence`. The runtime never substitutes a
    ///   backend that stores nothing; a caller without persistence cannot
    ///   construct a supervisor (§17.17 `SCP-CAPSEL-8000`).
    /// * `payment_adapter` — optional payment adapter for the 9-step
    ///   paid-action flow (spec §19.2.2).
    /// * `event_tx` — optional broadcast sender for event fan-out.
    /// * `clock` — optional [`Clock`] override; defaults to
    ///   [`scp_clock::SystemClock`] when `None`.
    /// * `durable` — **required** saga journal + `mls_storage` pair over one
    ///   `Storage` backend. The runtime never defaults storage.
    /// * `wrapping_custody` — **required** source of the custody that holds
    ///   each identity's wrapping key (spec 09 §9.16.1). An actor whose owner
    ///   it answers `None` for is not built
    ///   ([`ContextError::WrappingKeyCustodyUnavailable`]).
    ///
    /// A `None` persistence does not compile:
    ///
    /// ```compile_fail,E0308
    /// # use std::sync::Arc;
    /// # use scp_runtime_core::context::supervisor::{DurableProviders, Supervisor};
    /// # fn build(
    /// #     crypto: Arc<scp_runtime_core::crypto::mls::provider::NodeMlsFactory>,
    /// #     transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider>,
    /// #     event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
    /// #     key_resolver: scp_protocol::context::governance::KeyResolver,
    /// #     durable: DurableProviders,
    /// #     wrapping_custody: scp_runtime_core::context::supervisor::WrappingCustodySource,
    /// #     domains: scp_runtime_core::context::domains::DomainHandlers,
    /// # ) {
    /// let _ = Supervisor::with_providers_and_journal(
    ///     crypto, transport, event_log, key_resolver,
    ///     None, // E0308: expected `Box<dyn ContextPersistence>`
    ///     None, None, None, durable, wrapping_custody, domains,
    /// );
    /// # }
    /// ```
    #[must_use]
    #[allow(clippy::too_many_arguments)] // FFI bridges compose every provider in one call
    pub fn with_providers_and_journal(
        crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
        persistence: Box<dyn ContextPersistence>,
        payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
        event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
        clock: Option<Arc<dyn Clock>>,
        durable: DurableProviders,
        wrapping_custody: WrappingCustodySource,
        domains: crate::context::domains::DomainHandlers,
    ) -> Arc<Self> {
        let persistence: Arc<dyn ContextPersistence> = Arc::from(persistence);
        Self::bootstrap(ProviderBootstrap {
            crypto,
            transport,
            event_log,
            key_resolver,
            helper_persistence: Some(Arc::clone(&persistence)),
            persistence,
            payment_adapter,
            event_tx,
            clock,
            durable,
            wrapping_custody,
            #[cfg(any(test, feature = "testing"))]
            testing_wrapping_custody: None,
            domains,
        })
    }

    /// Builds the supervisor and fills its provider slots. The single body
    /// behind [`Self::with_providers_and_journal`] and the test-only
    /// `Self::with_providers`.
    fn bootstrap(providers: ProviderBootstrap) -> Arc<Self> {
        #[cfg(any(test, feature = "testing"))]
        let testing_wrapping_custody = providers.testing_wrapping_custody.clone();
        let ProviderBootstrap {
            crypto,
            transport,
            event_log,
            key_resolver,
            persistence,
            helper_persistence,
            payment_adapter,
            event_tx,
            clock,
            durable,
            wrapping_custody,
            domains,
            ..
        } = providers;
        // `into_parts` is `pub(crate)`, so this is the single in-crate site that
        // decomposes the same-backend journal + `mls_storage` pair.
        let (saga_journal, mls_storage, relay_contacts) = durable.into_parts();
        let supervisor = Arc::new(Self::new_inner(
            persistence,
            saga_journal,
            SupervisorConfig::default(),
            wrapping_custody,
            relay_contacts,
            domains,
        ));
        #[cfg(any(test, feature = "testing"))]
        if let Some(custody) = testing_wrapping_custody {
            let _ = supervisor.testing_wrapping_custody.set(custody);
        }

        // Populate provider OnceLocks. Each `set(...)` fails only when the slot
        // is already populated, which is impossible on this freshly-constructed
        // supervisor; `let _ =` discards the `Result` for clippy.
        let _ = supervisor.crypto.set(crypto);
        let _ = supervisor
            .transport
            .set(Arc::new(super::TransportSlot::new(Arc::from(transport))));
        let _ = supervisor.event_log.set(Arc::from(event_log));
        if let Some(p) = helper_persistence {
            let _ = supervisor.helper_persistence.set(p);
        }
        let _ = supervisor.key_resolver.set(key_resolver);
        let clock = clock.unwrap_or_else(|| Arc::new(scp_clock::SystemClock));
        let _ = supervisor.clock.set(clock);
        if let Some(adapter) = payment_adapter {
            let _ = supervisor.payment_adapter.set(adapter);
        }
        if let Some(tx) = event_tx {
            let _ = supervisor.event_tx.set(tx);
        }
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

        // Required, non-Option — the runtime never defaults storage. This is
        // the last use of `mls_storage`, so it is moved (not cloned) in.
        let _ = supervisor.mls_storage.set(mls_storage);

        supervisor
    }

    // -------------------------------------------------------------------
    // Outlet streaming (spec §5.4.5) — pump-resource accessors.
    // -------------------------------------------------------------------

    /// Node-wide outlet-stream-pump semaphore (spec §5.4.5 round-8).
    ///
    /// Returns an `Arc` clone of the shared per-instance semaphore.
    /// `open_outlet_stream` acquires a permit from it as the LAST gate
    /// (after all per-context admission / escrow checks pass) and holds it
    /// for the exact lifetime of the pump task.
    #[must_use]
    pub fn outlet_stream_pump_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.outlet_stream_pump_semaphore)
    }

    /// Get-or-create the §5.4.5 round-5 [`StreamAdmissionTracker`] for
    /// `context_id`.
    ///
    /// Returns an `Arc` clone of the per-context tracker, inserting a fresh
    /// one on first use. Repeated calls for the SAME `context_id` return
    /// clones of the SAME `Arc` (so every open for a context shares one
    /// admission state); distinct `context_id`s get distinct trackers. The
    /// returned `Arc<std::sync::RwLock<StreamAdmissionTracker>>` is exactly
    /// what the off-mailbox pump (`dispatch::open_stream_session`) consumes.
    ///
    /// Synchronous: the registry write guard is taken and dropped within
    /// this call and is never held across an `.await`. Stream opens are
    /// infrequent, so the single write-lock get-or-insert is cheap enough
    /// that no read-fast-path is warranted.
    // Wired by the `open_outlet_stream` orchestrator (chunk 3e), which hands
    // the returned tracker to `dispatch::open_stream_session`. Tested here in
    // chunk 3d (`outlet_stream_admission_for_is_get_or_create`).
    #[must_use]
    pub(in crate::context) fn outlet_stream_admission_for(
        &self,
        context_id: &str,
    ) -> Arc<std::sync::RwLock<StreamAdmissionTracker>> {
        let mut guard = self
            .outlet_stream_admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            guard
                .entry(context_id.to_owned())
                .or_insert_with(|| Arc::new(std::sync::RwLock::new(StreamAdmissionTracker::new()))),
        )
    }

    /// Drop the stream admission-tracker registry entry for `context_id` on
    /// PERMANENT context teardown (close / TTL-expiry / discard-join /
    /// shutdown sweep) — the twin of the [`Self::reap_crash_window`] /
    /// [`Self::remove_context_floors`] teardown reap, keeping the admission
    /// registry's lifecycle aligned 1:1 with them.
    ///
    /// Deliberately NOT called on a respawn's transient despawn (unlike the
    /// unconditional [`Self::despawn_actor`]): a respawned actor is the same
    /// logical context, and preserving its tracker keeps the §5.4.5 caps
    /// exact across crash-recovery. Removing the map entry drops ONLY the
    /// registry's `Arc` reference; an in-flight pump holding its own `Arc`
    /// clone of the tracker keeps it alive until the pump ends — this does
    /// not force-drop or invalidate any live tracker.
    pub fn reap_stream_admission(&self, context_id: &str) {
        self.outlet_stream_admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(context_id);
    }

    /// Returns an `Arc` clone of the operator-scoped §5.4.5
    /// per-origin-invoker admission tracker.
    ///
    /// Unlike [`Self::outlet_stream_admission_for`], this is NOT keyed by
    /// `context_id`: there is exactly ONE tracker per supervisor (operator),
    /// so the per-origin-invoker concurrent-stream cap is enforced across
    /// every context the operator hosts. Handed to
    /// `dispatch::open_stream_session` alongside the per-context tracker.
    /// Never reaped — entries self-remove at zero on stream close.
    #[must_use]
    pub(in crate::context) fn outlet_stream_origin_admission(
        &self,
    ) -> Arc<std::sync::RwLock<OriginAdmissionTracker>> {
        Arc::clone(&self.outlet_stream_origin_admission)
    }

    // -------------------------------------------------------------------
    // ADR-049 §15 — provider + state accessors.
    //
    // Provider accessors (`crypto_ref`, `transport_ref`, etc.) return
    // `Option<&...>` because providers are populated only by
    // [`Self::with_providers_and_journal`] — the [`Self::for_query_shim`] path
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
    /// [`NodeMlsFactory`](crate::crypto::mls::provider::NodeMlsFactory).
    /// Returns `None` if [`Self::with_providers_and_journal`] was not used (e.g. a
    /// supervisor built via `Self::for_query_shim` / `Self::new`).
    #[must_use]
    pub(crate) fn crypto_ref(&self) -> Option<&Arc<crate::crypto::mls::provider::NodeMlsFactory>> {
        self.crypto.get()
    }

    /// The supervisor's shared [`ContextTransportProvider`]: its
    /// [`TransportSlot`](super::TransportSlot), whose calls reach the
    /// provider bound at call time. Returns `None` if
    /// [`Self::with_providers_and_journal`] was not used.
    #[must_use]
    pub(crate) fn transport_ref(&self) -> Option<Arc<dyn ContextTransportProvider>> {
        self.transport
            .get()
            .map(|slot| Arc::clone(slot) as Arc<dyn ContextTransportProvider>)
    }

    /// This supervisor's [`TransportSlot`](super::TransportSlot), through which
    /// a bridge binds the transport of the node it starts
    /// (`construction.md` §"Node start — `NodeStartConfig`"). Every actor
    /// this supervisor spawned holds the same slot, so a
    /// [`TransportSlot::replace`](super::TransportSlot::replace) reaches
    /// running contexts without a respawn. Returns `None` for a supervisor
    /// built without providers.
    #[must_use]
    pub fn transport_slot(&self) -> Option<Arc<super::TransportSlot>> {
        self.transport.get().map(Arc::clone)
    }

    /// Cheap reference to the supervisor's shared
    /// [`ContextEventLogProvider`]. Returns `None` if
    /// [`Self::with_providers_and_journal`] was not used.
    #[must_use]
    pub(crate) fn event_log_ref(&self) -> Option<&Arc<dyn ContextEventLogProvider>> {
        self.event_log.get()
    }

    /// Cheap reference to the helper-side persistence slot. Returns
    /// `None` only on a test-only constructor that leaves the slot empty
    /// (`Self::new`, `Self::for_query_shim`, or `Self::with_providers` with
    /// `persistence: None`); [`Self::with_providers_and_journal`] always fills
    /// it.
    #[must_use]
    pub fn persistence_ref(&self) -> Option<&Arc<dyn ContextPersistence>> {
        self.helper_persistence.get()
    }

    /// Durably appends the §5.4.5 streaming `OutletInvokedEvent` at stream close
    /// through the [`ContextEventLogProvider::append_event_after_side_effect`]
    /// boundary: the stream has already closed and settled, so a failed store
    /// keeps the entry in memory and marks the stored log diverged (spec
    /// section 17.3, "Event log write failures"). The boundary re-runs the
    /// durable event-local
    /// `chunks_billed <= stream_chunk_count` backstop
    /// ([`verify_outlet_invoked_event_local`](scp_runtime_types::context::outlets::stream::verify_outlet_invoked_event_local)).
    ///
    /// Same-context billing integrity is enforced INLINE in the dispatch pump
    /// before this call (`AuditAnomaly::ChunksBilledSelfMismatch`, escrow-ledger
    /// vs Merkle-fold) — the pump does not retain the emitted payload set, so the
    /// full §5.4.5:566 manifest re-derivation
    /// ([`append_outlet_invoked_verified`](crate::context::builder::ContextEventLogProvider::append_outlet_invoked_verified))
    /// applies only on the Sequence path (cross-context reassembly / import,
    /// slice 3), not here.
    ///
    /// Called (fire-and-forget) by
    /// [`ActorOutletInvokedEventSink`](crate::context::outlets::stream_settlement_adapter::ActorOutletInvokedEventSink),
    /// which the streaming open orchestrator wires internally so the close event
    /// is persisted in production regardless of the FFI bridge.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when no event-log provider is configured, or the
    /// append serializes/persists/backstop-rejects the event.
    pub(crate) async fn append_streaming_outlet_invoked_event(
        &self,
        context_id_bytes: [u8; 32],
        event: scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
        actor_did: String,
    ) -> Result<(), ContextError> {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::append_streaming_outlet_invoked_event — event_log provider not configured"
                    .to_owned(),
            )
        })?;
        // Local committer-assigned leaf timestamp: the same-context streaming
        // close event is authored once, by the operator's node (not a
        // cross-member convergent commit leaf), so a wall-clock reading is
        // correct here. A missing clock falls back to 0 rather than failing the
        // append.
        let timestamp_secs = self.clock_ref().map_or(0, |clock| {
            use scp_clock::Clock as _;
            clock.now_secs()
        });
        let data = serde_json::to_vec(&event).map_err(|e| {
            ContextError::EventLogFailed(format!("failed to serialize OutletInvokedEvent: {e}"))
        })?;
        event_log
            .append_event_after_side_effect(
                &context_id_bytes,
                scp_event_log::EventType::OutletInvoked,
                &actor_did,
                scp_event_log::EventPayload { data },
                timestamp_secs,
            )
            .await
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Cheap reference to the supervisor's wall-clock source. Returns
    /// `None` if [`Self::with_providers_and_journal`] was not used.
    #[must_use]
    pub(crate) fn clock_ref(&self) -> Option<&Arc<dyn Clock>> {
        self.clock.get()
    }

    /// The supervisor clock's current Unix seconds: the time a challenger
    /// signs as `created_at`, from the same clock its ledger checks windows
    /// against.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInitialized`] when the supervisor has no clock
    /// ([`Self::with_providers_and_journal`] was not used).
    pub fn now_secs(&self) -> Result<u64, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        self.clock_ref()
            .map(scp_clock::Clock::now_secs)
            .ok_or_else(|| ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned()))
    }

    /// The supervisor's [`KeyResolver`], shared.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInitialized`] when
    /// [`Self::with_providers_and_journal`] was not used.
    pub(crate) fn key_resolver(&self) -> Result<KeyResolver, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        self.key_resolver
            .get()
            .map(Arc::clone)
            .ok_or_else(|| ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned()))
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
    /// the `event_tx` argument — e.g. via `Self::for_query_shim` — yields
    /// `None`). This is the public surface used by FFI node-startup paths to
    /// drive the outbound webhook dispatcher (spec §12.10.5).
    ///
    /// Message payloads on the channel are stripped of plaintext before sending
    /// (see `crate::context::state::strip_event_payload`) — subscribers
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

    /// A receiver that changes each time the output of
    /// [`Self::push_routing_ids`] can have changed, so a holder re-reads it
    /// (`10-infrastructure-and-self-hosting.md` §10.7.1 **Re-registration**):
    /// when a context actor is added or removed, and when a running actor's
    /// push routes change (a join or leave, a local pseudonym rotation, a
    /// close, an expiry or a tombstone). The value is a wrapping count and
    /// carries no other meaning.
    #[must_use]
    pub fn push_routes_changed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.push_routes_tx.subscribe()
    }

    /// Wakes every [`Self::push_routes_changed`] receiver. Called after each
    /// insert into and removal from `actors`, and by an actor whose push
    /// routes changed.
    pub(in crate::context) fn note_push_routes_changed(&self) {
        self.push_routes_tx
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Cheap reference to the supervisor's OpenMLS storage adapter
    /// (lock-free read per ADR-049 §Decision 12). Returns `None` if
    /// [`Self::with_providers_and_journal`] was not used (e.g. a supervisor built
    /// via `Self::for_query_shim` / `Self::new`).
    #[must_use]
    pub(in crate::context) fn mls_storage_ref(
        &self,
    ) -> Option<&Arc<dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>
    {
        self.mls_storage.get()
    }

    /// The store of each context's last successful relay contact (ADR-029
    /// key `sync/{context_id}/last_relay_contact`). Create, Welcome join and
    /// import write the first value through it, and every bridge reads and
    /// advances the value through it, so no reader sees a different backend
    /// than the writers.
    #[must_use]
    pub fn relay_contact_store(&self) -> Arc<dyn crate::store::sync::RelayContactStore> {
        Arc::clone(&self.relay_contacts)
    }

    // -------------------------------------------------------------------
    // ADR-049 §15 — direct-state accessors (always populated).
    // -------------------------------------------------------------------

    /// Cheap reference to the supervisor's local-DID registry.
    ///
    /// The field is `Arc<ArcSwap<HashSet<DID>>>` per the master plan
    /// §Supervisor — read sites use `arc_swap.load()` (returns
    /// `Guard<Arc<HashSet>>`) or `arc_swap.load_full()` (returns
    /// `Arc<HashSet>`); write sites acquire [`Self::write_lock`] then
    /// clone-update-store on the snapshot. The accessor returns the inner
    /// `&ArcSwap` so callers see the same read/write surface regardless of
    /// the outer `Arc` (which exists only so [`ActorDeps`](crate::context::actor::deps::ActorDeps) can share the
    /// swap cell via `Arc::clone`).
    #[must_use]
    pub fn local_dids_ref(&self) -> &ArcSwap<HashSet<DID>> {
        &self.local_dids
    }

    /// Cheap `Arc::clone` of the shared `local_dids` swap cell, handed to
    /// [`ActorDeps`](crate::context::actor::deps::ActorDeps) so every per-context actor reads from the SAME cell
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
    pub const fn standing_contexts_ref(&self) -> &ArcSwap<HashMap<String, DID>> {
        &self.standing_contexts
    }

    // -------------------------------------------------------------------
    // Per-identity wrapping key (spec 09 §9.16.1; spec 10 §10.8.1(4)).
    //
    // One key per identity, shared by every context the identity joins. The
    // supervisor's `wrapping_keys` map is its only writer; actors read it
    // through `SupervisorHandle::my_wrapping_key`, and the identity's
    // `KeyPackageStoreActor` holds the same `Arc`. Context snapshots carry no
    // wrapping key, so restoring a context never changes it.
    //
    // Load and lookup are split. `load_wrapping_key` runs at every entry point
    // that builds an actor for an identity, before that entry point takes
    // `bootstrap_spawn_lock` or `write_lock`, so no custody call runs under
    // either. `wrapping_key` is the sync lookup the actor builders use.
    // -------------------------------------------------------------------

    /// Clear every per-identity wrapping key. Used by the shutdown helper,
    /// after it closes the spawn gate, so no wrapping key stays resident past
    /// shutdown.
    ///
    /// `_write` is the held [`Self::write_lock`] guard. The only insert,
    /// [`Self::insert_wrapping_key`], checks the gate under that same lock, so
    /// an insert either precedes this clear or sees the closed gate and is
    /// refused: no load in flight at shutdown re-inserts a key afterwards.
    pub fn clear_wrapping_keys(&self, _write: &tokio::sync::MutexGuard<'_, ()>) {
        self.wrapping_keys.clear();
    }

    /// The only insert into `wrapping_keys`. Refuses with
    /// [`ContextError::SupervisorShutDown`] once the spawn gate is closed, so
    /// together with [`Self::clear_wrapping_keys`] (which takes the same
    /// [`Self::write_lock`], held here as `_write`) no wrapping key enters the
    /// map after shutdown has begun.
    fn insert_wrapping_key(
        &self,
        _write: &tokio::sync::MutexGuard<'_, ()>,
        identity: &DID,
        key: &Arc<IdentityWrappingKey>,
    ) -> Result<(), ContextError> {
        self.refuse_if_shut_down("wrapping key load")?;
        self.wrapping_keys.insert(identity.clone(), Arc::clone(key));
        Ok(())
    }

    /// Returns `owner`'s wrapping key, loading it from durable storage on first
    /// use and, when none is stored, creating one and storing it once.
    ///
    /// Lock-free when the key is already loaded. Otherwise it takes `owner`'s
    /// load lock in `wrapping_key_loads` and re-checks, so concurrent first
    /// loads of one identity load or create exactly once; loads of different
    /// identities do not wait on each other. [`Self::write_lock`] is held only
    /// for the final insert. The key is stored before it enters the map: a key
    /// this node could lose on restart is never published.
    ///
    /// Call it before taking `bootstrap_spawn_lock` or `write_lock`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::WrappingKeyCustodyUnavailable`] if the custody source
    ///   has no custody for `owner`.
    /// - [`ContextError::NotInitialized`] if the supervisor has no storage.
    /// - [`ContextError::PersistenceFailed`] if the read or write fails; a key
    ///   generated for a record that could not be written is destroyed once
    ///   its record is removed, and kept when the removal fails too.
    /// - [`ContextError::CryptoFailed`] if the stored value is not a version-1
    ///   handle record; the stored value is left as it is and no key is created
    ///   over it.
    /// - [`ContextError::WrappingKeyHandleInvalid`] if custody does not hold
    ///   the recorded handle or its public key differs from the record; nothing
    ///   is regenerated over the record.
    /// - [`ContextError::Custody`] if custody fails otherwise or does not
    ///   answer within the custody budget (`SCP-CRYPTO-4062`).
    /// - [`ContextError::SupervisorShutDown`] once shutdown has begun, whether
    ///   the gate closes before the call or while it loads.
    pub(crate) async fn load_wrapping_key(
        &self,
        owner: &DID,
    ) -> Result<Arc<IdentityWrappingKey>, ContextError> {
        self.refuse_if_shut_down("wrapping key load")?;
        if let Some(key) = self.wrapping_keys.get(owner) {
            return Ok(Arc::clone(key.value()));
        }
        // Clone the lock out of the entry so the entry (and its shard write
        // lock) drops at the end of this statement, before any await.
        let load_lock = Arc::clone(&*self.wrapping_key_loads.entry(owner.clone()).or_default());
        // The guard comes back with the key and is held until the key is in
        // the map, so a load waiting on the lock finds it there.
        let (key, load_guard) = {
            let held = load_lock.lock_owned().await;
            if let Some(key) = self.wrapping_keys.get(owner) {
                return Ok(Arc::clone(key.value()));
            }
            self.read_or_create_wrapping_key(owner, held).await?
        };
        let key = Arc::new(key);
        let guard = self.write_lock.lock().await;
        self.insert_wrapping_key(&guard, owner, &key)?;
        drop(guard);
        drop(load_guard);
        Ok(key)
    }

    /// Reads `owner`'s stored wrapping key record and checks it against
    /// `owner`'s custody or, when none is stored, generates a key in that
    /// custody and stores its record. Runs under `owner`'s load lock only,
    /// whose guard `load_guard` is, and returns that guard with the key.
    ///
    /// Generate, store, and the cleanup of a failed store run in a spawned
    /// task that holds `load_guard`, so a caller dropped mid-sequence (a
    /// UniFFI async cancellation drops the Rust future) cannot cut it, and no
    /// other load of `owner` reads the record before the task finishes. When
    /// the store reports an error, the task removes the record before it
    /// destroys the key, because the write may have committed; a record it
    /// cannot remove keeps its key. A stored record therefore never names a
    /// key this task destroyed. The cases that can still orphan a key are
    /// listed at [`custody_bounded`](crate::crypto::wrapping::custody_bounded).
    ///
    /// # Errors
    ///
    /// As [`Self::load_wrapping_key`], and [`ContextError::InvalidState`] if
    /// the creating task panics or is cancelled.
    async fn read_or_create_wrapping_key(
        &self,
        owner: &DID,
        load_guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<(IdentityWrappingKey, tokio::sync::OwnedMutexGuard<()>), ContextError> {
        let custody =
            (self.wrapping_custody)(owner).ok_or(ContextError::WrappingKeyCustodyUnavailable)?;
        let storage = self.mls_storage_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                crate::context::manager_methods::PROVIDER_NOT_INITIALIZED.to_owned(),
            )
        })?;
        let record =
            crate::store::wrapping_key::load_wrapping_key_handle(storage.as_ref(), owner).await?;
        if let Some(record) = record {
            let key = IdentityWrappingKey::new(custody, record.handle, record.public);
            return match key.read_public().await {
                Ok(public) if public == record.public => Ok((key, load_guard)),
                // Custody answered, and the handle is not this key: lost,
                // destroyed, or replaced. A custody that did not answer says
                // nothing about the handle, so its failure passes through.
                Ok(_) | Err(ContextError::CryptoFailed(_)) => {
                    Err(ContextError::WrappingKeyHandleInvalid)
                }
                Err(ContextError::Custody(failure)) if failure.is_key_not_found() => {
                    Err(ContextError::WrappingKeyHandleInvalid)
                }
                Err(e) => Err(e),
            };
        }
        let storage = Arc::clone(storage);
        let owner = owner.clone();
        tokio::spawn(async move {
            let key = IdentityWrappingKey::generate(custody).await?;
            if let Err(e) = crate::store::wrapping_key::store_wrapping_key_handle(
                storage.as_ref(),
                &owner,
                key.handle(),
                key.public(),
            )
            .await
            {
                // A write that reports an error may still have committed, so
                // the key is destroyed only once its record is gone: a stored
                // record never names a destroyed key, which a later load
                // would refuse forever as `WrappingKeyHandleInvalid`. When the
                // record cannot be removed either, the key stays: a committed
                // record then names a live key and the next load uses it, and
                // an uncommitted one leaves an orphan the next load does not
                // see.
                match crate::store::wrapping_key::delete_wrapping_key_handle(
                    storage.as_ref(),
                    &owner,
                )
                .await
                {
                    Ok(()) => key.destroy().await,
                    Err(delete_error) => tracing::warn!(
                        error = %delete_error,
                        "wrapping key record write failed and its removal failed; \
                         keeping the key in custody"
                    ),
                }
                return Err(e);
            }
            Ok((key, load_guard))
        })
        .await
        .map_err(|e| {
            ContextError::InvalidState(format!(
                "wrapping key creation: {}",
                JoinFailure::from_join_error(&e)
            ))
        })?
    }

    /// `owner`'s loaded wrapping key: a map read with no custody or storage
    /// call. An entry point loads the key ([`Self::load_wrapping_key`]) before
    /// any actor of `owner` is built, and only shutdown removes it, so a miss
    /// here is a programming error and fails closed.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] if no key is loaded for `owner`
    /// and shutdown has begun (shutdown clears the map), and
    /// [`ContextError::InvalidState`] if no key is loaded otherwise. The map is
    /// read before the gate, so a shutdown that clears the map between a gate
    /// check and the read still reports `SupervisorShutDown`.
    pub(crate) fn wrapping_key(
        &self,
        owner: &DID,
    ) -> Result<Arc<IdentityWrappingKey>, ContextError> {
        if let Some(key) = self.wrapping_keys.get(owner) {
            return Ok(Arc::clone(key.value()));
        }
        self.refuse_if_shut_down("wrapping key lookup")?;
        Err(ContextError::InvalidState(
            "wrapping key not loaded for the actor owner".to_owned(),
        ))
    }

    /// Returns `identity`'s 65-byte wrapping public key, the value it
    /// publishes as the `0xFF01` leaf extension (spec 09 §9.16.1). Loads or
    /// creates the key exactly as [`Self::load_wrapping_key`] does.
    ///
    /// A bridge that mints a KeyPackage outside the KeyPackage store attaches
    /// this key, so the leaf it adds advertises the key this supervisor opens
    /// with. Call it outside every supervisor lock.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::load_wrapping_key`].
    pub async fn wrapping_public_key(&self, identity: &DID) -> Result<[u8; 65], ContextError> {
        Ok(*self.load_wrapping_key(identity).await?.public())
    }

    /// Mints one `KeyPackage` for `owner` outside the `KeyPackage` store and
    /// returns its TLS-serialized public bytes. The private leaf state is
    /// dropped.
    ///
    /// The leaf carries `owning_did`'s wrapping public key as `0xFF01` (spec
    /// 09 §9.16.1) and a `0xFF03` attestation over its keys signed through
    /// `active_signer` (§9.7.1). `active_signer` must hold the key
    /// `owning_did`'s DID document names at `#active`: the key is resolved and
    /// compared before the sign, and the signature is verified under it before
    /// the `KeyPackage` is built. A bridge calls this for a `KeyPackage` it
    /// hands to `join_context`. Call it outside every supervisor lock.
    ///
    /// # Errors
    ///
    /// - The errors of [`Self::load_wrapping_key`].
    /// - [`ContextError::NotInitialized`] when the supervisor has no key
    ///   resolver or no crypto provider.
    /// - [`ContextError::AttestationSignerActiveKeyUnresolved`] when
    ///   `owning_did`'s `#active` key does not resolve, and
    ///   [`ContextError::AttestationSignerNotActiveKey`] when `active_signer`
    ///   does not hold it or signs under another key.
    /// - [`ContextError::Custody`] when custody refuses or does not answer the
    ///   sign, and [`ContextError::CryptoFailed`] when the `KeyPackage` cannot
    ///   be planned or built.
    pub async fn mint_attested_key_package(
        &self,
        owning_did: &DID,
        active_signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<Vec<u8>, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        use crate::crypto::mls::attestation_signer::{
            KeyPackageAttestationSigner, mint_attested_key_package,
        };
        let wrapping = *self.load_wrapping_key(owning_did).await?.public();
        let mls = Arc::clone(
            self.crypto_ref()
                .ok_or_else(|| ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned()))?
                .mls_backend(),
        );
        let signer = KeyPackageAttestationSigner::resolve(
            owning_did.clone(),
            active_signer.clone(),
            self.key_resolver()?,
        )
        .await?;
        let generated = mint_attested_key_package(&*mls, &signer, &wrapping).await?;
        Ok(generated.key_package_bytes)
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
    // Reached in production from `Supervisor::reserve_key_package` (the
    // spawn-from-Welcome reserve entrypoint); additional non-test callers land
    // when `dispatch_lifecycle_direct` switches to actor-shape (storage-
    // foundation Step 5).
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

        // The entry point that reached here loaded the identity's wrapping key
        // before taking any lock (spec 09 §9.16.1); a respawn path's owner was
        // loaded when its first actor was built. This is a map read, with no
        // custody call.
        let wrapping_key = self.wrapping_key(identity)?;

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
        let deps = self.build_kp_store_deps(wrapping_key)?;
        // ADR-049 Decision 16: the actor and its watchdog spawn through one
        // permit, taken after the last `.await` and before the insert, so a
        // shutdown that has begun refuses this spawn with a typed error and
        // a shutdown that begins later sees the registered handle.
        let permit = self.spawn_permit("spawn key-package actor")?;
        let (handle, join) =
            crate::context::supervisor::key_package_actor::KeyPackageStoreActor::spawn_through(
                &permit,
                identity.clone(),
                deps,
            );
        self.key_package_stores
            .insert(identity.clone(), handle.clone());
        // Attach the watchdog (ADR-049 §10) — mirrors the per-context actor
        // watchdog. Keeps the JoinHandle and respawns from durable storage on
        // panic; poisons the identity after the 3-crash/60s budget.
        spawn_kp_actor_watchdog_task(&permit, Arc::downgrade(self), identity.clone(), join);
        drop(permit);
        Ok(handle)
    }

    /// The `crash_windows` key for a per-identity KeyPackage actor. Namespaced
    /// with a `kp::` prefix so it never collides with a per-context budget
    /// (context keys are hex context-ids / original id strings, neither of
    /// which start with `kp::`).
    fn kp_crash_key(identity: &DID) -> String {
        format!("{KP_CRASH_KEY_PREFIX}{}", identity.0)
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
            |c| scp_clock::Clock::now_millis(c.as_ref()),
        )
    }

    /// Assemble a [`KeyPackageStoreDeps`](crate::context::supervisor::key_package_actor::KeyPackageStoreDeps)
    /// from the supervisor's own provider slots and the identity's
    /// wrapping-key slot.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if any required provider slot
    /// is empty (i.e. [`Self::with_providers_and_journal`] was not used).
    fn build_kp_store_deps(
        &self,
        wrapping_key: Arc<IdentityWrappingKey>,
    ) -> Result<crate::context::supervisor::key_package_actor::KeyPackageStoreDeps, ContextError>
    {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());

        let crypto = self.crypto_ref().ok_or_else(not_init)?;
        let mls = Arc::clone(crypto.mls_backend());
        let transport = self.transport_ref().ok_or_else(not_init)?;
        let clock = Arc::clone(self.clock_ref().ok_or_else(not_init)?);
        let mls_storage = Arc::clone(self.mls_storage_ref().ok_or_else(not_init)?);
        Ok(
            crate::context::supervisor::key_package_actor::KeyPackageStoreDeps {
                mls,
                mls_storage,
                transport,
                clock,
                // The owner's attestation signer arrives with the first
                // reserve (`KeyPackageCommand::ReserveAny`); until then the
                // store mints nothing.
                wrapping_key,
            },
        )
    }

    /// The identity a context acts as when its bootstrap names none: a
    /// restore, an import, or a recovery respawn rehydrates a persisted
    /// snapshot instead of joining. That identity is the DID of this node's
    /// crypto provider, the credential identity its MLS groups carry. It
    /// selects the identity's KeyPackage store and its wrapping keypair
    /// (spec 09 §9.16.1), which the context publishes in its own leaf's
    /// `0xFF01` and opens sender keys with, so it is never a roster member
    /// chosen by position or a DID derived from the context id.
    ///
    /// The push-wake pull fails closed with this error rather than substitute
    /// a DID (ADR-029 §2 push-wake pull mode, step 7).
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInitialized`] if no crypto provider is wired.
    pub fn node_identity(&self) -> Result<DID, ContextError> {
        self.crypto_ref()
            .map(|crypto| DID(crypto.local_did().to_owned()))
            .ok_or_else(|| {
                ContextError::NotInitialized(
                    crate::context::manager_methods::PROVIDER_NOT_INITIALIZED.to_owned(),
                )
            })
    }

    /// [`Self::build_actor_deps`] after [`Self::load_wrapping_key`], for tests
    /// that build deps without going through an entry point.
    ///
    /// # Errors
    ///
    /// The errors of the two calls.
    #[cfg(any(test, feature = "testing"))]
    #[allow(clippy::redundant_pub_crate)]
    pub async fn build_actor_deps_loaded(
        self: &Arc<Self>,
        owning_did: &DID,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        self.load_wrapping_key(owning_did).await?;
        self.build_actor_deps(owning_did).await
    }

    /// [`Self::key_package_store_for`] after [`Self::load_wrapping_key`], for
    /// tests that resolve the store without going through an entry point.
    ///
    /// # Errors
    ///
    /// The errors of the two calls.
    #[cfg(any(test, feature = "testing"))]
    pub async fn key_package_store_for_loaded(
        self: &Arc<Self>,
        owner: &DID,
    ) -> Result<crate::context::supervisor::key_package_actor::KeyPackageStoreHandle, ContextError>
    {
        self.load_wrapping_key(owner).await?;
        self.key_package_store_for(owner).await
    }

    /// Build an [`ActorDeps`](crate::context::actor::deps::ActorDeps)
    /// bundle entirely from the supervisor's own provider slots
    /// (ADR-049 §1 / ADR-049 §15), scoped to `owning_did`.
    ///
    /// Self-sources every collaborator from the `OnceLock`s populated by
    /// [`Self::with_providers_and_journal`]: the `MlsBackend` is read transitively
    /// through `crypto.mls_backend()` (the [`NodeMlsFactory`](crate::crypto::mls::provider::NodeMlsFactory)
    /// owns the only instance — no second supervisor field, so there is
    /// one source of truth per ADR §6). The OpenMLS storage adapter is
    /// the supervisor's `mls_storage` slot. The `KeyPackageStoreHandle`
    /// is resolved (get-or-spawn) for `owning_did` via
    /// [`Self::key_package_store_for`]. Persistence falls back to the
    /// no-op stub when no helper-side backend is wired.
    ///
    /// # `owning_did` scope (ADR-049 §10 respawn safety)
    ///
    /// `owning_did` selects the per-identity `KeyPackageStore` actor and the
    /// identity's wrapping keypair (spec 09 §9.16.1) that this context's deps
    /// read, and the capability token the actor carries. Crypto, transport,
    /// event-log, key-resolver, payment-adapter, and `mls_storage` are the
    /// supervisor-wide shared providers (read from the `OnceLock` slots), and
    /// `local_dids` is the SHARED swap cell (`local_dids_shared()`), i.e. the
    /// node's FULL set of local DIDs — not a snapshot of `owning_did`. Because
    /// the wrapping keypair is keyed on `owning_did`, a caller passes the
    /// identity the context acts as: the joining or creating DID, or
    /// [`Self::node_identity`] for a snapshot-rehydrated bootstrap; a watchdog
    /// respawn reuses the DID the crashed actor's deps were built for. See the
    /// `respawn_preserves_owning_identity_on_multi_did_node` test.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if any required provider slot is
    ///   empty (i.e. [`Self::with_providers_and_journal`] was not used).
    /// - [`ContextError::InvalidState`] if no entry point has loaded
    ///   `owning_did`'s wrapping key ([`Self::load_wrapping_key`]).
    /// - [`ContextError::SupervisorShutDown`] once shutdown has begun.
    /// - The errors of [`Self::key_package_store_for`] otherwise.
    ///
    /// # Method receiver
    ///
    /// Takes `self: &Arc<Self>` so the returned
    /// [`SupervisorHandle`](crate::context::supervisor::handle::SupervisorHandle)
    /// wraps a cloned `Arc` of the same supervisor instance — not a
    /// fresh `Supervisor::for_query_shim`. Without this the handle
    /// would point at a dangling second supervisor and
    /// [`SupervisorHandle::local_dids`](crate::context::supervisor::SupervisorHandle::local_dids)
    /// / [`SupervisorHandle::standing_peer`](crate::context::supervisor::SupervisorHandle::standing_peer)
    /// would read empty state.
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this is reached
    // only from the supervisor + actor test fixtures.
    // `pub(crate)` (widened from `pub(in crate::context)`): the shared two-party
    // test fixture in `crate::crypto::mls::two_party_test_support` drives a
    // provider-resident join (`ConfirmConsume` → `install_joined_group`) through
    // Bob's `key_package_store` handle, reached via these deps.
    #[cfg_attr(not(test), allow(dead_code))]
    // `redundant_pub_crate` is a false positive here: this method is defined in a
    // private module but is genuinely reached crate-wide (the shared two-party
    // test fixture in `crate::crypto::mls`), which `pub(in crate::context)` would
    // wrongly forbid (E0624). `pub(crate)` is the minimal correct visibility.
    #[allow(clippy::redundant_pub_crate)]
    pub(crate) async fn build_actor_deps(
        self: &Arc<Self>,
        owning_did: &DID,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());

        let crypto = Arc::clone(self.crypto_ref().ok_or_else(not_init)?);
        // mls/hpke stay transitive — the NodeMlsFactory owns the only
        // backend pair (ADR §6); no Supervisor field mirrors them.
        let mls = Arc::clone(crypto.mls_backend());
        let transport = self.transport_ref().ok_or_else(not_init)?;
        let event_log = Arc::clone(self.event_log_ref().ok_or_else(not_init)?);
        let clock = Arc::clone(self.clock_ref().ok_or_else(not_init)?);
        let key_resolver = self.key_resolver()?;
        let mls_storage = Arc::clone(self.mls_storage_ref().ok_or_else(not_init)?);
        // The supervisor's own non-Option persistence field. Every shipped
        // constructor (`with_providers_and_journal`) fills it with the caller's
        // required backend, so no actor receives a backend the caller did not
        // pass (§17.17 `SCP-CAPSEL-8000`).
        let persistence = Arc::clone(&self.persistence);
        let key_package_store = self.key_package_store_for(owning_did).await?;
        let handle = crate::context::supervisor::handle::SupervisorHandle::wrap(self);
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
            mls_storage,
            clock,
            event_tx: self.event_tx_ref().cloned(),
            key_resolver,
            payment_adapter: self.payment_adapter_ref().map(Arc::clone),
            local_dids: self.local_dids_shared(),
            owned_identity,
            domains: Arc::clone(&self.domains),
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
    ///   `Self::dispatch_queries_direct` emits the variant's legacy
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
    ///   attached — the caller must call [`Self::with_providers_and_journal`]
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

    /// Dispatch a mutating [`MessagingCommand`] to its per-context
    /// actor's mailbox (ADR-049 commit 8 / plan row 8).
    ///
    /// Routes the command through the per-context actor's mailbox via
    /// `Self::dispatch_via_mailbox`. The actor's `run()` loop pulls
    /// the command and dispatches it via the actor-shape `dispatch(state,
    /// deps, cmd)` entry point, which exercises the actor-owned
    /// [`SendSequenceTracker`](scp_runtime_types::context::actor::sequence::SendSequenceTracker)
    /// directly. The handler wraps every transport/MLS call in
    /// [`tokio::time::timeout`] with a 30-second budget; a timeout maps
    /// to [`ContextError::TransportTimeout`].
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
    ///   been attached yet — the caller must call
    ///   [`Self::with_providers_and_journal`] first.
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
    ///   `Self::dispatch_lifecycle_direct`, which delegates to the
    ///   actor-shape helpers in
    ///   `crate::context::lifecycle_helpers`. These helpers
    ///   construct fresh `PerContextState` and spawn the per-context
    ///   actor as part of the bootstrap handshake (the actor owns the
    ///   state; there is no legacy `contexts` `DashMap` write).
    /// - **Per-context variants** (`JoinContext`, `LeaveContext`,
    ///   `CloseContext`, `ExportContext`,
    ///   `GenerateContextAccessKey`, `RevokeContextAccessKey`,
    ///   `RestoreContextAccessKey`) carry a `context_id` and route
    ///   through the per-context actor's mailbox into the actor-shape
    ///   `handlers::lifecycle::dispatch`. If no actor is registered for
    ///   the target context, the call falls through to
    ///   `Self::dispatch_lifecycle_direct` which surfaces
    ///   `ContextError::ContextNotRegistered` on the reply oneshot.
    ///
    /// Each variant wraps its delegated body in `tokio::time::timeout`
    /// with a 30s budget, maps a timeout to
    /// [`ContextError::TransportTimeout`],
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no providers have been
    ///   attached — the caller must call [`Self::with_providers_and_journal`]
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
        // fresh state and spawn the per-context actor; the
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
        // access-key generate / revoke / restore) all
        // carry a `context_id` and have a registered actor after
        // bootstrap spawn. Mailbox-first routes to the actor's
        // `dispatch_state` loop which executes the actor-shape handler.
        if let Some(ctx_id) = Self::lifecycle_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Lifecycle(cmd)).await;
        }
        // Per-context variant for which no actor is registered — the
        // `Supervisor::contexts` DashMap fallback (and its handler-side
        // `dispatch_from_shim`) were deleted in Phase 2A finalization. Surface
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
    /// `scp_runtime_lifecycle::helpers`. Those helpers spawn the
    /// per-context actor that OWNS the freshly built `PerContextState`
    /// and register its handle in the supervisor registry — there is no
    /// legacy `contexts` `DashMap` write. Building deps requires
    /// `self: &Arc<Self>` so the spawned actor and its handle wrap the
    /// same supervisor instance.
    ///
    /// **Per-context variants** (Join / Leave / Close / Export +
    /// access-key generate / revoke / restore) reach this method only
    /// when no actor is registered for the target context; their arms
    /// surface `ContextNotRegistered` on the variant's oneshot, since
    /// post-Step-B every valid context has a registered actor.
    #[allow(clippy::too_many_lines)] // flat match over every lifecycle variant
    async fn dispatch_lifecycle_direct(self: &Arc<Self>, cmd: LifecycleCommand) -> Outcome<()> {
        // Single source of truth: derive from the associated `Self::
        // LIFECYCLE_TIMEOUT` (shared with the respawn path) rather than
        // re-declaring the `from_secs(30)` magic number. The local alias keeps
        // the `{LIFECYCLE_TIMEOUT:?}` diagnostics below working without a
        // duplicate literal.
        const LIFECYCLE_TIMEOUT: std::time::Duration = Supervisor::LIFECYCLE_TIMEOUT;

        match cmd {
            LifecycleCommand::CreateContext { payload, reply } => {
                let p = *payload;
                let context_id = p.context_id.clone();
                // Load the creator's wrapping key before any lock: a custody
                // call never runs under `bootstrap_spawn_lock` (spec 09
                // §9.16.1). A failure returns here, before any lock, as the
                // `ContextError` it is: a `Custody` failure keeps its custody
                // code at the bridges, and the two wrapping-key variants keep
                // their names.
                if let Err(e) = self.load_wrapping_key(&p.creator_did).await {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(
                        scp_protocol::context::builder::ContextCreationError::StateTransition(e),
                    ));
                    return Outcome::err_mutated(sketch);
                }
                // Serialize this bootstrap-spawn (crypto-init → spawn) against
                // every other same-id bootstrap so a concurrent import/restore
                // for the same id cannot interleave its crypto write between
                // this op's crypto-init and actor registration. See
                // `bootstrap_spawn_lock`. The guard drops before the post-spawn
                // wiring, which waits on the new actor's mailbox.
                let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // A create over a running context's id fails before any write
                // (ADR-029 Implementation), so it cannot replace the running
                // context's snapshot or contact. The check runs under the lock
                // every bootstrap holds, so no actor registers between it and
                // the writes.
                if self.lookup(&context_id).is_some() {
                    let msg = format!(
                        "create_context refused: context '{context_id}' is running"
                    );
                    if let Err(_unsent) = reply.send(Err(
                        scp_protocol::context::builder::ContextCreationError::CreationFailed(
                            msg.clone(),
                        ),
                    )) {
                        tracing::debug!(context_id, "create_context caller dropped its reply");
                    }
                    return Outcome::err_mutated(ContextError::CreationFailed(msg));
                }
                // (Re)creating this id is a fresh start: the fresh actor begins
                // with a clean budget and does not inherit a previous
                // instance's crash count or sticky poison (ADR-049 §10). A
                // create that registers no actor restores that history when
                // `crash_window` drops. Every exit drops it before the reply,
                // as the `ImportContext` arm does, so a caller that reads
                // `read_context_state_checked` on receiving the reply sees the
                // settled window, never the bootstrap's marker-only one.
                let crash_window = self.begin_bootstrap_window(&context_id);
                // ADR-049 Phase 2A finalization: bootstrap now builds the
                // actor-shape `ActorDeps` (self-sourced from the
                // supervisor's provider slots, scoped to the creator's
                // identity for KeyPackageStore resolution) and delegates
                // to `lifecycle_helpers::create_context`, which spawns the
                // per-context actor that OWNS the fresh state (no legacy
                // `contexts` DashMap write).
                let deps = match self.build_actor_deps(&p.creator_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        // A shutdown refusal keeps its typed `SCP-CTX-2138`
                        // (ADR-049 Decision 16 item 2), as the import and
                        // restore arms pass `e` through unchanged.
                        let err = match e {
                            ContextError::SupervisorShutDown(_) => {
                                scp_protocol::context::builder::ContextCreationError::StateTransition(e)
                            }
                            other => {
                                scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                    format!("create_context: deps unavailable: {other}"),
                                )
                            }
                        };
                        drop(crash_window);
                        let _ = reply.send(Err(err));
                        return Outcome::err_mutated(sketch);
                    }
                };
                // B8 — Create-time terminal-snapshot precheck (squatting /
                // tombstone-finality). Under the already-held
                // `bootstrap_spawn_lock`, mirror Precheck-D
                // (spawn-from-Welcome): refuse `CreateContext` over a DURABLE
                // snapshot whose lifecycle `state` is TERMINAL (`Expired` /
                // `Closed` / `Tombstoned`). Such an id is finished for good —
                // re-creating it would resurrect an expired/closed/tombstoned
                // context under a fresh actor, defeating tombstone-finality
                // (the "expired/tombstoned id re-creatable" residual,
                // black-hat). A storage READ fault refuses fail-closed (we
                // cannot prove the id is free). TERMINAL states ONLY: an absent
                // snapshot (`None`) or a NON-terminal one still creates — a
                // standing context legitimately re-creates over a
                // non-terminal/absent id and resets its crash window.
                //
                // PROVENANCE — this precheck INTENTIONALLY does NOT fire on the
                // standing-context path. A standing (deterministic-id) pair
                // reaches `create_context` DIRECTLY via `standing_context` →
                // `create_context` and never through this `CreateContext`
                // dispatch arm, so it bypasses B8 by construction. That
                // asymmetry is CORRECT and settled: a reaped / never-joined
                // standing handle AUTO-REVIVES under its deterministic id on the
                // next `standing_context(peer)` contact — standing pairs carry
                // NO permanent tombstone, and blocking is enforced via the
                // block-list / §3.7.1 severance (sender-key rotation), not via
                // context finality (ADR-049 §10 "Standing-context auto-revive
                // residual (BLACK-002 ACCEPTED, settled)"; spec 05-contexts.md
                // §5.12). B8 tombstone-finality applies ONLY to the explicit
                // `CreateContext` create flow, which is exactly this arm.
                //
                // `ContextState::is_terminal()` is the closed-by-construction
                // permanent-terminal predicate (`Expired | Closed | Tombstoned`;
                // N5) — an exhaustive match, so a future variant forces a
                // terminality decision at its definition rather than silently
                // slipping past this ad-hoc set.
                match deps.persistence.load_context(&context_id).await {
                    Ok(Some(snapshot)) if snapshot.state.is_terminal() => {
                        let msg = format!(
                            "create_context refused: a durable {:?} snapshot already exists \
                             for '{context_id}' — a terminal (expired/closed/tombstoned) \
                             context id is final and MUST NOT be re-created (tombstone \
                             finality)",
                            snapshot.state
                        );
                        let err =
                            scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                msg.clone(),
                            );
                        drop(crash_window);
                        let _ = reply.send(Err(err));
                        return Outcome::err_mutated(ContextError::CreationFailed(msg));
                    }
                    // Absent snapshot or a NON-terminal one — proceed (standing
                    // re-create reuses a non-terminal/absent id).
                    Ok(_) => {}
                    Err(e) => {
                        let msg = format!(
                            "create_context: cannot verify durable terminal-state precheck \
                             for '{context_id}' (snapshot existence read failed: {e}) — \
                             refusing fail-closed"
                        );
                        let err =
                            scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                msg.clone(),
                            );
                        drop(crash_window);
                        let _ = reply.send(Err(err));
                        return Outcome::err_mutated(ContextError::PersistenceFailed(msg));
                    }
                }
                // The arm owns the first-state guard outside the timeout, so a
                // create that fails or times out puts back what it wrote.
                let first_state = match crate::context::shared::lifecycle::FirstStateRollback::new(
                    &deps,
                    &context_id,
                ) {
                    Ok(guard) => guard,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        drop(crash_window);
                        if let Err(_unsent) = reply.send(Err(
                            scp_protocol::context::builder::ContextCreationError::StateTransition(
                                e,
                            ),
                        )) {
                            tracing::debug!(context_id, "create_context caller dropped its reply");
                        }
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = deps.domains.lifecycle.create_context(
                    &deps,
                    crate::context::domains::CreateContextRequest {
                        context_id: p.context_id,
                        params: p.params,
                        creator_did: p.creator_did,
                        local_pseudonym: p.local_pseudonym,
                        relay_urls: p.relay_urls,
                        first_state: &first_state,
                    },
                );
                // The trait method returns the create future already boxed:
                // owned-state spawn keeps the freshly built `PerContextState`
                // live across the spawn await, so the future is large
                // (>16 KiB), and the heap box keeps it off this frame.
                let (outcome, reply_result) = match tokio::time::timeout(LIFECYCLE_TIMEOUT, fut)
                    .await
                {
                    Ok(Ok(spawned)) => (Outcome::ok_mutated(()), Ok(spawned)),
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
                drop(crash_window);
                // No mailbox wait runs under the lock: the TTL install waits on
                // the new actor. The rollback waits for abandoned writes with
                // the lock released and retakes it for the restores.
                drop(bootstrap_guard);
                let (outcome, reply_result) = match reply_result {
                    Err(e) => match first_state.rollback(self.bootstrap_spawn_lock.lock()).await {
                        Ok(()) => (outcome, Err(e)),
                        Err(rollback) => {
                            let folded =
                                crate::context::shared::lifecycle::fold_rollback_failure(
                                    &e, &rollback,
                                );
                            let sketch = standing_outcome_error_sketch(&folded);
                            (
                                Outcome::err_mutated(sketch),
                                Err(scp_protocol::context::builder::ContextCreationError::StateTransition(folded)),
                            )
                        }
                    },
                    ok => (outcome, ok),
                };
                let (outcome, reply_result) = match reply_result {
                    Ok(spawned) => match spawned.finalize(&deps).await {
                        Ok(handle) => (outcome, Ok(handle)),
                        Err(e) => {
                            let sketch = standing_outcome_error_sketch(&e);
                            (
                                Outcome::err_mutated(sketch),
                                Err(scp_protocol::context::builder::ContextCreationError::StateTransition(e)),
                            )
                        }
                    },
                    Err(e) => (outcome, Err(e)),
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
                // The import rehydrates a snapshot rather than joining, so the
                // context acts as this node's identity; the imported roster
                // never selects the wrapping keypair the actor reads.
                let owning_did = match self.node_identity() {
                    Ok(did) => did,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
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
                // `bootstrap_spawn_lock`. The wrapping key loads first, outside
                // both locks, so no custody call runs under either.
                if let Err(e) = self.load_wrapping_key(&owning_did).await {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    return Outcome::err_mutated(sketch);
                }
                let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // Importing (re-establishing) this id is a fresh start: the
                // imported actor begins with a clean budget, free of stale
                // crash history and a stale poison (ADR-049 §10); a failed
                // import restores that history.
                let crash_window = self.begin_bootstrap_window(&context_id);
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
                        drop(crash_window);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                // Box::pin — the per-variant import future crosses
                // clippy's 16 KB stack budget (ContextExport ~2 KB +
                // the full PerContextState-construction locals inside
                // the `import_context` body).
                // The arm owns the first-state guard outside the timeout, so an
                // import that fails or times out puts back what it replaced.
                let first_state = match crate::context::shared::lifecycle::FirstStateRollback::new(
                    &deps,
                    &context_id,
                ) {
                    Ok(guard) => guard,
                    Err(e) => {
                        if kp_store_newly_spawned {
                            self.key_package_stores.remove(&owning_did);
                        }
                        let sketch = standing_outcome_error_sketch(&e);
                        drop(crash_window);
                        if let Err(_unsent) = reply.send(Err(e)) {
                            tracing::debug!(context_id, "import_context caller dropped its reply");
                        }
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = deps.domains.lifecycle.import_context_from_export(
                    &deps,
                    *export,
                    &verifying_key,
                    local_pseudonym,
                    &first_state,
                );
                let import_result = tokio::time::timeout(LIFECYCLE_TIMEOUT, fut).await;
                // `import_context` marks the replace gap when it despawns a
                // prior actor (`despawn_for_replace`). `crash_window` ends
                // that gap when it drops, before the reply: the imported actor
                // registers before the marker clears, which
                // `read_context_state_checked` relies on, and a failed import
                // gets the id's prior crash window back.
                let (outcome, reply_result) = match import_result {
                    Ok(Ok(spawned)) => (Outcome::ok_mutated(()), Ok(spawned)),
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
                drop(crash_window);
                // No mailbox wait runs under the lock: the TTL install waits on
                // the imported actor. The rollback waits for abandoned writes
                // with the lock released and retakes it for the restores.
                drop(bootstrap_guard);
                let (outcome, reply_result) = match reply_result {
                    Err(e) => match first_state.rollback(self.bootstrap_spawn_lock.lock()).await {
                        Ok(()) => (outcome, Err(e)),
                        Err(rollback) => {
                            let folded =
                                crate::context::shared::lifecycle::fold_rollback_failure(
                                    &e, &rollback,
                                );
                            let sketch = standing_outcome_error_sketch(&folded);
                            (Outcome::err_mutated(sketch), Err(folded))
                        }
                    },
                    ok => (outcome, ok),
                };
                let (outcome, reply_result) = match reply_result {
                    Ok(spawned) => match spawned.finalize(&deps).await {
                        Ok(handle) => (outcome, Ok(handle)),
                        Err(e) => {
                            let sketch = standing_outcome_error_sketch(&e);
                            (Outcome::err_mutated(sketch), Err(e))
                        }
                    },
                    Err(e) => (outcome, Err(e)),
                };
                let _ = reply.send(reply_result);
                outcome
            }
            LifecycleCommand::RestoreContext { payload, reply } => {
                let p = *payload;
                let context_id = p.context_id.clone();
                // The restore payload carries no identity (it rehydrates a
                // persisted snapshot rather than joining), so the context
                // acts as this node's identity. Its wrapping key loads before
                // any lock, so no custody call runs under one; a failure
                // returns here.
                let owner = match self.node_identity() {
                    Ok(owner) => self.load_wrapping_key(&owner).await.map(|_| owner),
                    Err(e) => Err(e),
                };
                let owner = match owner {
                    Ok(owner) => owner,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                // Serialize this bootstrap-spawn against every other same-id
                // bootstrap (see `bootstrap_spawn_lock`).
                let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // A restore must not start an actor from a snapshot a failed
                // create, import or join wrote and has not yet put back.
                if let Err(e) = self.refuse_pending_first_state(&p.context_id, &bootstrap_guard) {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    return Outcome::err(sketch);
                }
                let handle = crate::context::ContextHandle::new(p.context_id.clone(), p.params);
                if let Err(e) = handle
                    .transition_to(&scp_protocol::context::ContextState::Active)
                {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    return Outcome::err(sketch);
                }
                let deps = match self.build_actor_deps(&owner).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = deps.domains.lifecycle.restore_context(
                    &deps,
                    &p.context_id,
                    &handle,
                    None, // process-restart / dispatch arm: load the snapshot here
                );
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
            | LifecycleCommand::ClearNeedsReconnect { context_id, reply }
            | LifecycleCommand::IssueMlsUpdate { context_id, reply } => {
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
                     `crate::context::shared::lifecycle::flush_all_contexts*`"
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

    /// Dispatch a mutating [`TtlCloseCommand`] to its per-context
    /// actor's mailbox (ADR-049 commit 9 / plan row 9).
    ///
    /// Routes the command through the per-context actor's mailbox via
    /// `Self::dispatch_via_mailbox`. The actor's `run()` loop pulls the
    /// command and dispatches it via the actor-shape `dispatch(state,
    /// deps, cmd)` entry point. The handler wraps delegated
    /// [`Supervisor`] calls in
    /// [`tokio::time::timeout`] with a 30s budget, and relays the typed
    /// result through the variant's oneshot.
    ///
    /// # TTL-timer ownership
    ///
    /// The TTL timer is a `select!` arm in the actor's `run()` loop.
    /// This dispatch method routes caller-initiated
    /// extend/reset/finalize/explicit-expiry commands through that
    /// actor's mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
    ///   been attached yet.
    pub async fn dispatch_ttl_close_command(
        &self,
        cmd: TtlCloseCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and the dead `_legacy`
        // bodies have been deleted; every command's target actor must
        // be spawned before dispatch reaches this method.
        // Total: every `TtlCloseCommand` variant carries a routable
        // `context_id` (the `FireTimer` variant was retired — ADR-049
        // finding A3), so there is no no-target error branch.
        let ctx_id = Self::ttl_close_command_context_id(&cmd);
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

    /// Dispatch a [`GovernanceCommand`] to its per-context actor's mailbox
    /// (ADR-049 §15 / plan row 10).
    ///
    /// Contract (byte-identical to the legacy
    /// [`Supervisor`]
    /// governance methods it replaces):
    ///
    /// Routes every per-context variant through the per-context actor's
    /// mailbox via `Self::dispatch_via_mailbox`. The actor's `run()`
    /// loop pulls the command, dispatches it through the actor-shape
    /// `dispatch(state, deps, cmd)` entry point, and writes the typed
    /// reply on the command's embedded oneshot. Sweep / timeout-task
    /// variants carry no `context_id` and are dispatched per-actor by
    /// the iterating helpers rather than this routed entry point; they
    /// return [`ContextError::ContextNotRegistered`] from this method.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
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
                 (sweep / timeout-task use the iterating helpers); mailbox-only after Phase 2A finalization"
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

    /// Dispatch an [`EconomyCommand`] to its per-context actor's mailbox
    /// (ADR-049 §15 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. The
    /// economy handler only exposes the single public-surface method
    /// on [`Supervisor`],
    /// `verify_payment_receipts`;
    /// internal helpers (`authorize_paid_action`, `complete_paid_action`,
    /// `void_paid_action`) remain on the manager's private surface
    /// and are exercised through the messaging path.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
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
        // [`MAX_RECEIPT_BATCH`](scp_runtime_types::economy::adapter::MAX_RECEIPT_BATCH).
        if let EconomyCommand::VerifyPaymentReceipts { receipts, .. } = &cmd
            && receipts.len() > scp_runtime_types::economy::adapter::MAX_RECEIPT_BATCH
        {
            return Err(ContextError::LimitExceeded(format!(
                "receipt batch too large: {} (max {})",
                receipts.len(),
                scp_runtime_types::economy::adapter::MAX_RECEIPT_BATCH
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
    /// - Empty receipt batches (no target).
    /// - Heterogeneous batches whose receipts straddle multiple contexts
    ///   (no single owning actor).
    /// - Batches containing any relay-level receipt (`context_id == None`).
    fn economy_command_context_id(cmd: &EconomyCommand) -> Option<&str> {
        match cmd {
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
    /// `scp_runtime_economy::helpers::verify_payment_receipts`
    /// runs the identical loop over `deps.payment_adapter`; the two paths
    /// are observably equivalent and differ only in the serialization
    /// point. Batches with no single owning actor have no per-context
    /// `ActorDeps`/`PerContextState` to borrow, so the verification is
    /// inlined here against `self.payment_adapter_ref()` directly.
    async fn dispatch_economy_direct(&self, cmd: EconomyCommand) -> Outcome<()> {
        use scp_runtime_types::economy::receipt::{ReceiptVerification, ReceiptVerificationError};
        const ECONOMY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
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

    /// Dispatch a [`TrustRecoveryCommand`] to its per-context actor's mailbox
    /// (ADR-049 §15 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. Covers the
    /// checkpoint + cosignature paths, MLS epoch advancement for
    /// compromise recovery (spec §9.12 step 2), and recovery-
    /// notification send paths (spec §9.12 step 5).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
    ///   been attached yet.
    pub async fn dispatch_trust_recovery_command(
        self: &Arc<Self>,
        cmd: TrustRecoveryCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Phase 2A.1 of ADR-049 — trust_recovery is the first migrated
        // helper domain. Route per-context variants to the per-context
        // actor mailbox when one is registered; otherwise fall through
        // to `dispatch_trust_recovery_direct`, whose per-context arms
        // surface `ContextNotRegistered` (post-Step-B every valid
        // context has a registered actor). The cross-context
        // `RecoveryNotifyContact` variant has no `context_id` to look
        // up — it always flows through the direct fan-out path
        // (`recovery_notify_contact`).
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
    /// (`RecoveryNotifyContact`).
    fn trust_recovery_command_context_id(cmd: &TrustRecoveryCommand) -> Option<&str> {
        match cmd {
            TrustRecoveryCommand::RecoveryNotifyContact { .. } => None,
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
    /// `scp_runtime_trust_recovery::helpers::recovery_notify_contact`
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
        self: &Arc<Self>,
        recovering_did: &str,
        contact_did: &str,
        payload: &[u8],
        signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::{
            RecoverySendNotificationPayload, TrustRecoveryCommand,
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
                    signer: signer.clone(),
                };
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let cmd = TrustRecoveryCommand::RecoverySendNotification {
                    payload: Box::new(send_payload),
                    reply: reply_tx,
                };
                self.dispatch_trust_recovery_command(cmd).await?;
                bounded_reply_await(reply_rx).await.map_err(|_| {
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
    /// variants that have no per-context actor target
    /// (`RecoveryNotifyContact`) or whose actor is not registered
    /// (`CreateGovernanceCheckpoint` / `AddCheckpointCosignature` /
    /// `RecoveryAdvanceEpoch` / `RecoverySendNotification` —
    /// unregistered-context fallback).
    ///
    /// Mirrors the standing/queries/lifecycle direct precedents.
    /// `RecoveryNotifyContact` is intrinsically cross-context (it carries
    /// no `context_id`, so it always reaches this path): its arm wraps
    /// the actor-native [`Self::recovery_notify_contact`] fan-out in the
    /// signing handler budget
    /// ([`SIGNING_HANDLER_TIMEOUT`](crate::context::actor::signer::SIGNING_HANDLER_TIMEOUT)),
    /// because the dispatched notification signs in the shared context's turn,
    /// and relays the typed reply on the variant's oneshot.
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
    async fn dispatch_trust_recovery_direct(
        self: &Arc<Self>,
        cmd: TrustRecoveryCommand,
    ) -> Outcome<()> {
        const TRUST_RECOVERY_TIMEOUT: std::time::Duration =
            crate::context::actor::signer::SIGNING_HANDLER_TIMEOUT;

        match cmd {
            TrustRecoveryCommand::RecoveryNotifyContact { payload, reply } => {
                let recovering_did = payload.recovering_did.clone();
                let notify_fut = self.recovery_notify_contact(
                    &payload.recovering_did,
                    &payload.contact_did,
                    &payload.payload,
                    &payload.signer,
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
            // legitimate, supported operation. Since PR-7 moved the MLS crypto
            // state onto the per-context actor (one-way take), the direct path
            // no longer seals through the retired supervisor-scoped provider: it
            // lazily respawns the target context's actor from its persisted
            // snapshot and dispatches the notification to that actor's mailbox,
            // where the actor-shape `recovery_send_notification` handler seals
            // through the authoritative owned `ContextCryptoState`. Real
            // (64-hex) member contexts (`revoke_ucans` seq 1 /
            // `rotate_key_packages` seq 2) respawn and seal via the mailbox; the
            // synthetic `identity-private-state` pseudo-context (PSK rotation
            // §9.12 step 6) is non-64-hex with no snapshot and no production MLS
            // group, so it returns the same "no MLS group" error the retired
            // provider seal produced (best-effort no-op). See
            // `recovery_send_notification_direct` for the full contract.
            TrustRecoveryCommand::RecoverySendNotification { payload, reply } => {
                let send_result = self
                    .recovery_send_notification_direct(
                        &payload.context_id,
                        &payload.sender_did,
                        &payload.payload,
                        payload.sequence,
                        &payload.signer,
                    )
                    .await;
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

    /// Delivers a recovery notification for a context with no live actor by
    /// lazily respawning that actor from its persisted snapshot and dispatching
    /// the notification to its mailbox (ADR-049 §9.12, PR-7 SCP-CRYPTOMOVE-001).
    ///
    /// This is the supervisor-direct fallback for the per-context actor's
    /// `scp_runtime_trust_recovery::helpers::recovery_send_notification`
    /// handler, reached when the target context has no registered actor. Since
    /// PR-7 moved the MLS crypto state onto the per-context actor (one-way
    /// take), this path can no longer seal through the retired supervisor-scoped
    /// provider; it instead respawns the actor so the notification is sealed by
    /// the authoritative owned `ContextCryptoState` (the actor drives the
    /// persist-before-ack send sequence, so the reserved AAD sequence is
    /// nonce-safe — no risk of the transient-materialize `(epoch, sequence)`
    /// reuse the seal fork rejected).
    ///
    /// Two shapes reach here at recovery time (ADR-049 lazy-spawn):
    ///
    /// - Real (64-hex) member contexts that simply have no spawned actor —
    ///   e.g. the [`revoke_ucans`](crate::identity::recovery) (seq 1) and
    ///   [`rotate_key_packages`](crate::identity::recovery) (seq 2)
    ///   compromise-recovery notifications, which dispatch to a real member
    ///   context id with no registration gate. These respawn from their
    ///   persisted Active snapshot and seal via the mailbox. In practice
    ///   `restore_on_startup` eagerly spawns an actor for every persisted
    ///   Active context, so live recovery flows normally reach the mailbox
    ///   directly; this fallback covers only the transient crash-respawn gap.
    /// - The synthetic `identity-private-state` pseudo-context (PSK rotation
    ///   §9.12 step 6), which is never a real (64-hex) context id, never a
    ///   registered actor, and has no persisted snapshot. In production it has
    ///   no MLS group (`seed_identity_private_state_group` is test-only), so the
    ///   retired provider seal ALSO failed "no MLS group" and was swallowed
    ///   (`rotate_psk` returns false — a best-effort no-op). This method
    ///   preserves that exact contract: it returns the same "no MLS group"
    ///   [`ContextError::CryptoFailed`] for any non-64-hex id WITHOUT attempting
    ///   a snapshot respawn that cannot exist (which would emit a spurious
    ///   "state is lost" error and consume the crash budget on every rotation).
    ///   Whether production PSK delivery SHOULD work is a pre-existing question,
    ///   tracked separately — not changed here.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] ("no MLS group for this context") for a
    ///   non-64-hex synthetic id — the preserved best-effort no-op contract.
    /// - [`ContextError::ActorCrashed`] if a real context cannot be respawned
    ///   (genuinely lost snapshot) or the respawned actor vanishes before
    ///   dispatch — fail-closed and retryable.
    /// - [`ContextError::TransportFailed`] if the mailbox reply channel closes.
    /// - Any [`ContextError`] surfaced by the actor-shape handler's seal /
    ///   transport send.
    // Manual `Box::pin(async move { … })` (NOT `async fn`) is REQUIRED: the
    // respawn constructs a fresh `ContextActor::run()` future, and an actor
    // turn reaches the in-turn twin of this method, so an opaque `async fn`
    // type would make `run()`'s type/`Send` inference cyclic (E0391). The
    // explicit `Pin<Box<dyn Future + Send>>` breaks the cycle. This method
    // waits for `bootstrap_spawn_lock`, so only Supervisor callers reach it;
    // an actor turn goes through `recovery_send_notification_in_turn`.
    fn recovery_send_notification_direct<'a>(
        self: &'a Arc<Self>,
        context_id: &str,
        sender_did: &str,
        payload: &[u8],
        sequence: u64,
        signer: &crate::context::actor::signer::CommandSigner,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ContextError>> + Send + 'a>>
    {
        let notification =
            RecoveryNotification::new(context_id, sender_did, payload, sequence, signer);
        Box::pin(async move {
            recovery_notification_target_is_real(&notification.context_id)?;
            // The recovery respawn rehydrates the persisted snapshot, so the
            // context acts as this node's identity.
            let owning_did = self.node_identity()?;
            // A Supervisor caller holds no actor turn, so the respawn waits
            // for `bootstrap_spawn_lock`. A failed respawn (genuinely lost
            // snapshot for a real context) fails closed.
            self.respawn_from_snapshot(&notification.context_id, &owning_did)
                .await?;
            self.send_recovery_notification_to_respawned(notification)
                .await
        })
    }

    /// [`Self::recovery_send_notification_direct`] for a caller in an actor
    /// turn, which reaches it through
    /// [`SupervisorHandle::dispatch_recovery_send_notification`](crate::context::supervisor::handle::SupervisorHandle::dispatch_recovery_send_notification).
    /// A holder of `bootstrap_spawn_lock` waits on actor mailboxes, so this
    /// path try-locks it instead of waiting.
    ///
    /// # Errors
    ///
    /// [`ContextError::ActorBusy`] while another bootstrap holds the lock; it
    /// is retryable and nothing was sent. Otherwise the errors of
    /// [`Self::recovery_send_notification_direct`].
    fn recovery_send_notification_in_turn(
        self: &Arc<Self>,
        notification: RecoveryNotification,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ContextError>> + Send + '_>>
    {
        Box::pin(async move {
            recovery_notification_target_is_real(&notification.context_id)?;
            let owning_did = self.node_identity()?;
            let bootstrap_guard = self.bootstrap_spawn_lock.try_lock().map_err(|_| {
                ContextError::ActorBusy(format!(
                    "the recovery notification to '{}' needs its actor respawned while another \
                     bootstrap holds the bootstrap lock; retry",
                    notification.context_id
                ))
            })?;
            self.respawn_from_snapshot_locked(
                &notification.context_id,
                &owning_did,
                &bootstrap_guard,
            )
            .await?;
            drop(bootstrap_guard);
            self.send_recovery_notification_to_respawned(notification)
                .await
        })
    }

    /// The actor-turn twin of [`Self::dispatch_trust_recovery_command`] for
    /// one `RecoverySendNotification`: it sends to the target context's
    /// mailbox when an actor is registered, and otherwise respawns the actor
    /// through [`Self::recovery_send_notification_in_turn`], which never
    /// waits for `bootstrap_spawn_lock`. The send's result goes to `reply`.
    ///
    /// # Errors
    ///
    /// The mailbox dispatch errors of [`Self::dispatch_trust_recovery_command`].
    pub(in crate::context) async fn dispatch_recovery_send_notification_in_turn(
        self: &Arc<Self>,
        payload: Box<crate::context::actor::commands::RecoverySendNotificationPayload>,
        reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
    ) -> Result<Outcome<()>, ContextError> {
        use crate::context::actor::commands::TrustRecoveryCommand;
        if let Some(actor) = self.lookup(&payload.context_id) {
            let cmd = TrustRecoveryCommand::RecoverySendNotification { payload, reply };
            return Self::dispatch_via_mailbox(&actor, ContextCommand::TrustRecovery(cmd)).await;
        }
        let notification = RecoveryNotification::new(
            &payload.context_id,
            &payload.sender_did,
            &payload.payload,
            payload.sequence,
            &payload.signer,
        );
        Ok(
            match self.recovery_send_notification_in_turn(notification).await {
                Ok(()) => {
                    let _ = reply.send(Ok(()));
                    Outcome::ok(())
                }
                Err(e) => {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    Outcome::err(sketch)
                }
            },
        )
    }

    /// Sends the notification to the mailbox of the actor a respawn just
    /// registered for its context. It goes straight to the mailbox, not back
    /// through `dispatch_trust_recovery_command`, so a transient lookup miss
    /// cannot re-enter the respawn and loop.
    async fn send_recovery_notification_to_respawned(
        self: &Arc<Self>,
        notification: RecoveryNotification,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::{
            RecoverySendNotificationPayload, TrustRecoveryCommand,
        };

        let RecoveryNotification {
            context_id,
            sender_did,
            payload,
            sequence,
            signer,
        } = notification;
        let Some(actor) = self.lookup(&context_id) else {
            return Err(ContextError::ActorCrashed(format!(
                "{context_id} (respawned actor vanished before recovery-notification dispatch)"
            )));
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let send_payload = RecoverySendNotificationPayload {
            context_id: context_id.clone(),
            sender_did,
            payload,
            sequence,
            signer,
        };
        let cmd = ContextCommand::TrustRecovery(TrustRecoveryCommand::RecoverySendNotification {
            payload: Box::new(send_payload),
            reply: reply_tx,
        });
        Self::dispatch_via_mailbox(&actor, cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "recovery_send_notification_direct: mailbox reply channel closed".to_owned(),
            )
        })?
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
            | QueriesCommand::LocalRoutingIds { ref context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { ref context_id, .. }
            | QueriesCommand::GetCapabilityRequirements { ref context_id, .. } => {
                let err = self
                    .lookup_miss_error(context_id, format!("context not registered: {context_id}"));
                reply_with_error(cmd, err);
            }
            // Test-only counter read: a counter for an unknown context has no
            // honest default, so the reply is the hard error.
            #[cfg(feature = "testing")]
            QueriesCommand::CheckpointEventsSince { ref context_id, .. } => {
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
            | QueriesCommand::RelayUrls { .. }
            | QueriesCommand::GetRoleState { .. }
            | QueriesCommand::HasEstablishedOutletInterface { .. }
            | QueriesCommand::PendingCommits { .. }
            | QueriesCommand::CommitFault { .. }
            | QueriesCommand::LocalMlsEpoch { .. }
            | QueriesCommand::NeedsReconnect { .. }
            | QueriesCommand::PaymentHistory { .. } => {
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
    /// Every per-context dispatch method routes through this accessor
    /// (`self.lookup(ctx).send(...)`), as do the per-actor sweep entry
    /// points in `governance_helpers` / `lifecycle_helpers`.
    ///
    /// Visibility widened to `pub(in crate::context)` at Phase 2A
    /// finalization (sweep helper relocation) so the sweep entry
    /// points in `governance_helpers` / `lifecycle_helpers` can route
    /// per-actor sweep commands through the mailbox.
    #[must_use]
    pub fn lookup(&self, ctx_id: &str) -> Option<ContextActorHandle> {
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
    /// sweep entry points enumerate the actor registry directly. The
    /// actor registry is the only context map — there is no legacy
    /// `contexts` DashMap.
    #[must_use]
    pub fn actor_ids(&self) -> Vec<String> {
        self.actors.iter().map(|e| e.key().clone()).collect()
    }

    /// Returns every context ID the supervisor knows: each registered actor's,
    /// plus each context whose actor is down ([`CrashWindow::actor_down`]),
    /// for which [`Self::lookup_miss_error`] returns `ContextPoisoned` or
    /// `ActorCrashed`. KeyPackage-actor windows (`kp::` keys) are not contexts
    /// and are left out. Sorted, without duplicates.
    #[must_use]
    pub(in crate::context) fn known_context_ids(&self) -> Vec<String> {
        let mut ids: std::collections::BTreeSet<String> =
            self.actors.iter().map(|e| e.key().clone()).collect();
        ids.extend(
            self.crash_windows
                .iter()
                .filter(|e| !e.key().starts_with(KP_CRASH_KEY_PREFIX) && e.value().actor_down())
                .map(|e| e.key().clone()),
        );
        ids.into_iter().collect()
    }

    /// Spawn a new `ContextActor` task that owns drained
    /// [`PerContextState`](crate::context::actor::PerContextState) +
    /// [`ActorDeps`](crate::context::actor::ActorDeps) directly
    /// (ADR-049 §15).
    ///
    /// This is the owned-state spawn path. The lifecycle bootstrap caller
    /// (create / restore / import in
    /// `scp_runtime_lifecycle::helpers`) builds a fresh actor-shape
    /// `PerContextState` and hands the state + deps bundle into this
    /// method. The spawned actor becomes the sole owner of that state.
    ///
    /// The returned [`ContextActorHandle`] is registered in the
    /// supervisor's `actors` map under the same `write_lock` that
    /// [`Self::spawn_actor_with_state`] uses. The handle's mailbox capacity
    /// matches [`ACTOR_MAILBOX_CAPACITY`] (256, plan §"Mailbox
    /// parameters").
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — the only production caller is the
    /// lifecycle handler's create / restore / import path. External
    /// callers (FFI bridges, downstream crates) reach the actor through
    /// [`Self::dispatch_command`] or the
    /// [`crate::context::supervisor::handle::SupervisorHandle`] /
    /// [`crate::context::actor::deps::ActorDeps::supervisor`]
    /// capabilities — never directly.
    ///
    /// # Dispatch
    ///
    /// The spawned actor OWNS its `PerContextState` + `ActorDeps`, so its
    /// `run()` loop dispatches every command variant to the real
    /// per-domain handlers via
    /// [`ContextActor::dispatch_state`](crate::context::actor::ContextActor)
    /// (`&mut self.state` + `&self.deps`).
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
        // The watchdog rebuilds a crashed actor's deps for the same identity
        // its deps were built for, so a respawn keeps the context's KeyPackage
        // store and wrapping keypair.
        let owning_did = deps.owned_identity.as_did().clone();
        // `Box::pin` keeps the (large, state-carrying) spawn future off the
        // caller's stack frame — `PerContextState` + `ActorDeps` are ~20KB.
        Box::pin(self.spawn_actor_with_watchdog(state, deps, owning_did, mailbox_capacity)).await
    }

    /// Spawn a state-owning [`ContextActor`](crate::context::actor::ContextActor), register its handle, and
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
    /// `owning_did` is the DID the actor's [`ActorDeps`](crate::context::actor::deps::ActorDeps) were scoped to;
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
        // instance gets a distinct generation; a outlet-economy reservation
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

        // Register under the context's id string (the one the `ContextHandle`
        // carries and that every per-context dispatch / `lookup` uses). The
        // registry is keyed by this STRING, not by `state.context_id` bytes —
        // value-agnostic, so it needs no change under ADR-056. Under ADR-056 a
        // real context's id string is `hex(state.context_id)`:
        // `state.context_id` is the canonical DIGEST and the id is its hex
        // encoding (`context_id_to_bytes` round-trips them), so the
        // string and `hex(state.context_id)` now coincide for real contexts —
        // the production divergence that the old comment warned about no longer
        // exists. (Synthetic / non-64-hex ids still hash, so for those the
        // string is NOT `hex(state.context_id)`; that is irrelevant here since
        // the registry keys by the string in every case.)
        let ctx_id_str = state.handle.context_id().to_owned();

        let handle = ContextActorHandle::from_sender(tx);
        // Write-path mutation: register the handle under the write
        // lock — same contract as [`Self::spawn_actor`]. Reject a
        // duplicate registration (first-writer-wins) instead of
        // silently overwriting a live actor: the overwrite would
        // leak the loser's spawned task and diverge crypto state.
        let _guard = self.write_lock.lock().await;
        // ADR-049 Decision 16: take the spawn permit under the write lock,
        // after the last `.await`. Once shutdown has begun the spawn is
        // refused with a typed error; otherwise shutdown cannot take its
        // actor snapshot until this registration and both spawns finish.
        let permit = match self.spawn_permit("spawn context actor") {
            Ok(permit) => permit,
            Err(refused) => {
                // The refused `state` never becomes a live actor: dispose its
                // seeded crypto exactly as the duplicate-birth branch below.
                let _ = state.dispose_secrets();
                return Err(refused);
            }
        };
        {
            if self.actors.contains_key(&ctx_id_str) {
                // Losing duplicate birth: this `state` never becomes a live
                // actor, so dispose its seeded crypto (#2148 F6) — `destroy_group`
                // releases the group (the OpenMLS signer zeroizes on drop).
                // `state` drops on the very next line, so the call is equivalent
                // to that drop, matching
                // the close-seam teardown. A no-op for a broadcast /
                // never-seeded state.
                // #2199: rollback path — no attestation is built here, so discard
                // the observed `DisposalOutcome` (the `#[must_use]` guards that the
                // honest signal is consumed on the seams that DO build one).
                let _ = state.dispose_secrets();
                return Err(ContextError::CreationFailed(format!(
                    "context '{ctx_id_str}' is already registered"
                )));
            }
            self.actors.insert(ctx_id_str.clone(), handle.clone());
        }
        self.note_push_routes_changed();

        // Hand the owned state + deps into the actor task. The spawned
        // future captures both by move; neither escapes the actor's scope.
        // KEEP the JoinHandle (the pre-watchdog spawn dropped it, silently
        // swallowing panics and wedging the context). The watchdog owns this
        // handle directly. TTL / governance timers are ACTOR-OWNED arms
        // (ADR-049 finding A3), reconciled inside the actor's own `run()`
        // loop — no separate supervisor timer JoinSet exists.
        let inbox = rx;
        let exit = handle.exit_record();
        let join = permit.spawn(async move {
            Box::pin(crate::context::actor::ContextActor::new(state, deps, inbox, exit).run())
                .await;
        });

        // Spawn the watchdog: it awaits the actor's completion and, on a
        // panic, records the crash + (poison-or-respawn). It holds a `Weak`
        // and upgrades it only after the actor exits (ADR-049 Decision 16).
        // Spawn the watchdog through a free helper (not inline) so its
        // future's `Send` proof is resolved OUTSIDE this method's opaque
        // `impl Future` scope. Spawning inline would form a self-referential
        // opaque-type cycle (`spawn_actor_with_watchdog` ↔ `actor_watchdog`
        // ↔ `respawn_from_snapshot` ↔ `restore_context` ↔
        // `spawn_actor_with_state`) that the compiler refuses to resolve
        // ("fetching the hidden types of an opaque inside of the defining
        // scope is not supported").
        spawn_actor_watchdog_task(&permit, Arc::downgrade(self), ctx_id_str, owning_did, join);
        drop(permit);

        Ok(handle)
    }

    /// Per-actor watchdog (ADR-049 §10).
    ///
    /// Awaits the actor task's [`JoinHandle`](tokio::task::JoinHandle) and reacts to how it
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
    /// correlated to the specific [`JoinError`](tokio::task::JoinError) observed here, and would
    /// also be a mutable global (forbidden by the workspace
    /// `check-no-mutable-globals` gate). The plan's stated floor —
    /// "payload-free logging with `panic_location=\"unknown\"`" — is chosen
    /// deliberately over a racy, possibly-wrong location.
    async fn actor_watchdog(
        self: Arc<Self>,
        ctx_id: String,
        owning_did: DID,
        outcome: Result<(), tokio::task::JoinError>,
    ) {
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
        // Record the crash, or, once shutdown has begun, record nothing and
        // start no respawn (ADR-049 Decision 16 item 2): `shutdown_sweep`
        // reaps the crash window, and a record made after it would outlive it.
        let Some((poisoned, count)) = self.record_crash_while_open(&ctx_id, now_ms, false) else {
            tracing::warn!(
                actor_kind = "context_actor",
                context_id = %ctx_id,
                "context actor panicked after shutdown began; not respawned, payload intentionally not logged"
            );
            self.despawn_actor(&ctx_id).await;
            return;
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
        match self
            .respawn_after_first_state_settles(&ctx_id, &owning_did)
            .await
        {
            Ok(()) => {}
            Err(e @ ContextError::ContextNotRegistered(_)) => {
                tracing::info!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    reason = %e,
                    "context actor crashed after its id was released or replaced; not respawned"
                );
            }
            Err(ContextError::ContextClosed) => {
                tracing::info!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    "context actor crashed in a terminal state; not respawned (dormant)"
                );
            }
            Err(ContextError::SupervisorShutDown(_)) => {
                tracing::info!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    "context actor respawn refused: shutdown began during the respawn"
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

    /// [`Self::respawn_crashed_actor`], repeated each time a first-state
    /// claim is released while a claim on `ctx_id` refuses it: an actor that
    /// crashed while a create, import or join of its id had not committed or
    /// rolled back its first state is respawned once that operation settles,
    /// from the snapshot it left. Returns early when shutdown begins.
    ///
    /// # Errors
    ///
    /// As for [`Self::respawn_crashed_actor`];
    /// [`ContextError::SupervisorShutDown`] when shutdown begins while the
    /// claim stands.
    async fn respawn_after_first_state_settles(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
    ) -> Result<(), ContextError> {
        loop {
            // Enabled before the respawn reads the claim, so a release after
            // that read wakes it.
            let settled = self.first_state_settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            let busy = match self.respawn_crashed_actor(ctx_id, owning_did).await {
                Err(e @ ContextError::ActorBusy(_)) => e,
                other => return other,
            };
            if !self.pending_first_state.contains(ctx_id) {
                // A claim released since the respawn read it notified
                // `settled`; otherwise the busy is not the claim's.
                if futures::FutureExt::now_or_never(settled.as_mut()).is_some() {
                    continue;
                }
                return Err(busy);
            }
            tracing::info!(
                actor_kind = "context_actor",
                context_id = %ctx_id,
                "context actor respawn waits for an unsettled first state of its id"
            );
            tokio::select! {
                () = settled => {}
                () = self.shutdown_token.cancelled() => {
                    return Err(ContextError::SupervisorShutDown(format!(
                        "{ctx_id}: shutdown began while the respawn waited for its first state"
                    )));
                }
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
    async fn kp_actor_watchdog(
        self: Arc<Self>,
        identity: DID,
        outcome: Result<(), tokio::task::JoinError>,
    ) {
        let join_err = match outcome {
            Ok(()) => return,
            Err(e) => e,
        };
        if !join_err.is_panic() {
            return;
        }

        let poison_key = Self::kp_crash_key(&identity);
        let now_ms = self.crash_now_ms("key_package_store", &identity.0);
        // Once shutdown has begun, a panic records no crash and starts no
        // respawn, as in `actor_watchdog`. Remove the dead handle.
        let Some((poisoned, count)) = self.record_crash_while_open(&poison_key, now_ms, false)
        else {
            tracing::warn!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                "key-package actor panicked after shutdown began; not respawned, payload intentionally not logged"
            );
            {
                let _guard = self.write_lock.lock().await;
                self.key_package_stores.remove(&identity);
            }
            #[cfg(feature = "testing")]
            self.kp_watchdog_processed_tx.send_modify(|n| *n += 1);
            return;
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
            // Test-only: the crash is recorded and the identity is poisoned —
            // signal completion so a waiting test observes the settled state
            // without polling a wall-clock budget. Compiles to nothing (and the
            // field does not exist) in production builds.
            #[cfg(feature = "testing")]
            self.kp_watchdog_processed_tx.send_modify(|n| *n += 1);
            return;
        }

        // Budget intact: respawn. The fresh actor re-runs the §9 reconciliation
        // from `mls_storage` in its `run()` startup, rebuilding `pool` /
        // `reserved` from the durable journal — NOT a coalesced snapshot.
        match self.key_package_store_for(&identity).await {
            Ok(_) => tracing::info!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                "key-package actor respawned; reconciling from durable storage"
            ),
            Err(ContextError::SupervisorShutDown(_)) => tracing::info!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                "key-package actor respawn refused: shutdown began during the respawn"
            ),
            Err(e) => tracing::error!(
                actor_kind = "key_package_store",
                identity = %identity.0,
                error = %e,
                "key-package actor respawn failed"
            ),
        }
        // Test-only: the crash is recorded and the respawn attempt has
        // completed (fresh handle inserted, or the failure logged + recorded) —
        // signal completion. Compiles to nothing (and the field does not exist)
        // in production builds.
        #[cfg(feature = "testing")]
        self.kp_watchdog_processed_tx.send_modify(|n| *n += 1);
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
    ///    `scp_runtime_lifecycle::helpers::restore_context` — the
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
    /// - [`ContextError::ContextNotRegistered`] when a
    ///   [`Self::discard_joined_context`] of the id is in progress; the
    ///   snapshot is not read.
    /// - Any error surfaced by [`Self::persistence_ref`] /
    ///   `restore_context` (persistence failure, validation failure, etc.).
    pub(in crate::context::supervisor) async fn respawn_from_snapshot(
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
        let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
        self.respawn_from_snapshot_locked(ctx_id, owning_did, &bootstrap_guard)
            .await
    }

    /// The crash watchdog's respawn: [`Self::respawn_from_snapshot`] for the
    /// actor that crashed, run only while that actor still holds the id's
    /// registry slot.
    ///
    /// Under `bootstrap_spawn_lock`, the slot must hold a handle whose inbox
    /// is closed. A panicking actor's unwind drops its inbox receiver before
    /// its `JoinHandle` resolves, so the crashed actor's handle reads closed
    /// by the time the watchdog runs. An empty slot means another path
    /// removed the crashed actor before the watchdog took the lock, such as
    /// a [`Self::discard_joined_context`] that has already deleted the
    /// snapshot; an open handle means a later bootstrap registered a new
    /// actor for the id. Respawning in either case would restore a context
    /// that path tore down, or replace the new actor. The discard's removal
    /// and every bootstrap spawn hold the same lock, so neither lands between
    /// this check and the respawn.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when the crashed actor no longer
    /// holds the slot or a discard of the id is in progress; otherwise any
    /// error of [`Self::respawn_from_snapshot`].
    async fn respawn_crashed_actor(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
    ) -> Result<(), ContextError> {
        let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
        // The `Ref` drops at the end of this statement, before any await.
        let crashed_actor_registered = self
            .actors
            .get(ctx_id)
            .is_some_and(|handle| handle.is_closed());
        if !crashed_actor_registered {
            return Err(ContextError::ContextNotRegistered(format!(
                "{ctx_id} (the crashed actor no longer holds the id; not respawned)"
            )));
        }
        self.respawn_from_snapshot_locked(ctx_id, owning_did, &bootstrap_guard)
            .await
    }

    /// Refuses a respawn of `context_id` while a
    /// [`Self::discard_joined_context`] of it is in progress.
    ///
    /// The discard inserts its mark under `bootstrap_spawn_lock`, and the
    /// guard parameter proves the caller holds that lock, so the answer
    /// cannot change until the caller releases it.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when a discard of the id is in
    /// progress.
    fn refuse_pending_discard(
        &self,
        context_id: &str,
        _bootstrap_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<(), ContextError> {
        if self.pending_discards.contains(context_id) {
            return Err(ContextError::ContextNotRegistered(format!(
                "{context_id} (a discard of the joined context is in progress; not respawned)"
            )));
        }
        Ok(())
    }

    /// Refuses a restore or respawn of `context_id` while a bootstrap's
    /// first-state writes of it are unsettled (`pending_first_state`): the
    /// stored snapshot may be the one a failed operation wrote and its
    /// rollback is about to put back.
    ///
    /// The guard parameter proves the caller holds `bootstrap_spawn_lock`,
    /// so no bootstrap of the id can claim it and write until the caller's
    /// spawn finishes.
    ///
    /// # Errors
    ///
    /// [`ContextError::ActorBusy`] while the claim stands; it is retryable.
    fn refuse_pending_first_state(
        &self,
        context_id: &str,
        _bootstrap_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<(), ContextError> {
        if self.pending_first_state.contains(context_id) {
            return Err(ContextError::ActorBusy(format!(
                "{context_id}: a create, import or join of this context has not committed or \
                 rolled back its first state; retry"
            )));
        }
        Ok(())
    }

    /// Body of [`Self::respawn_from_snapshot`], run by a caller that already
    /// holds `bootstrap_spawn_lock`; the guard parameter proves it.
    /// [`Self::clear_poison`] takes the lock itself so that it clears the
    /// poison flag and sets the respawn marker under the lock.
    async fn respawn_from_snapshot_locked(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
        bootstrap_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<(), ContextError> {
        // A context whose discard is in progress must not come back: its
        // snapshot is about to be deleted, and an actor restored from it would
        // keep running for a context the bridge released.
        self.refuse_pending_discard(ctx_id, bootstrap_guard)?;
        self.refuse_pending_first_state(ctx_id, bootstrap_guard)?;
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
            return self
                .record_respawn_failure(
                    ctx_id,
                    ContextError::ActorCrashed(format!(
                        "{ctx_id} (no persistence backend configured for respawn)"
                    )),
                )
                .await;
        };
        let snapshot = match persistence.load_context(ctx_id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                tracing::error!(
                    actor_kind = "context_actor",
                    context_id = %ctx_id,
                    "context actor crashed with no persisted snapshot; state is lost"
                );
                return self
                    .record_respawn_failure(
                        ctx_id,
                        ContextError::ActorCrashed(format!(
                            "{ctx_id} (no persisted snapshot — state lost)"
                        )),
                    )
                    .await;
            }
            Err(e) => {
                return self
                    .record_respawn_failure(
                        ctx_id,
                        ContextError::ActorCrashed(format!("{ctx_id} (snapshot load failed: {e})")),
                    )
                    .await;
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
            self.release_respawn_marker(ctx_id);
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
        if let Err(e) = handle.transition_to(&scp_protocol::context::ContextState::Active) {
            return self
                .record_respawn_failure(
                    ctx_id,
                    ContextError::ActorCrashed(format!(
                        "{ctx_id} (could not activate respawned context handle: {e})"
                    )),
                )
                .await;
        }
        let deps = match self.build_actor_deps(owning_did).await {
            Ok(deps) => deps,
            Err(e) => return self.record_respawn_failure(ctx_id, e).await,
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
        let restore_fut =
            deps.domains
                .lifecycle
                .restore_context(&deps, ctx_id, &handle, Some(snapshot.clone()));
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
            Ok(Err(e)) => self.record_respawn_failure(ctx_id, e).await,
            Err(_elapsed) => {
                self.record_respawn_failure(
                    ctx_id,
                    ContextError::TransportTimeout(format!(
                        "respawn restore_context exceeded {:?} budget for context {ctx_id}",
                        Self::LIFECYCLE_TIMEOUT
                    )),
                )
                .await
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
    ///
    /// Every respawn failure exit returns through this helper, which returns
    /// `Err(cause)`. A [`ContextError::SupervisorShutDown`] cause, or any cause
    /// once the closed flag is set, records no crash and sets no failed-respawn
    /// flag (ADR-049 Decision 16 item 2): it only releases the respawn marker,
    /// so the crash window `shutdown_sweep` reaped stays reaped.
    async fn record_respawn_failure(
        self: &Arc<Self>,
        ctx_id: &str,
        cause: ContextError,
    ) -> Result<(), ContextError> {
        if matches!(cause, ContextError::SupervisorShutDown(_)) {
            self.release_respawn_marker(ctx_id);
            return Err(cause);
        }
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
            |c| scp_clock::Clock::now_millis(c.as_ref()),
        );
        let Some((poisoned, _count)) = self.record_crash_while_open(ctx_id, now_ms, true) else {
            self.release_respawn_marker(ctx_id);
            return Err(cause);
        };
        if poisoned {
            self.despawn_actor(ctx_id).await;
        }
        Err(cause)
    }

    /// Clear the respawn marker `respawn_from_snapshot` set, on an exit that
    /// records no crash. A window that carries only that marker is removed, so
    /// a context with no crash history leaves no crash-window record; any
    /// other window keeps its crash history and loses only the marker.
    fn release_respawn_marker(&self, ctx_id: &str) {
        let reaped = self
            .crash_windows
            .remove_if(ctx_id, |_, w| w.is_empty_except_respawning())
            .is_some();
        if !reaped && let Some(mut entry) = self.crash_windows.get_mut(ctx_id) {
            entry.clear_respawning();
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

    /// Test fixture: poisons `context_id` the way the crash watchdog does, so a
    /// caller can observe a poisoned context without crashing an actor
    /// `CRASH_POISON_THRESHOLD` times.
    ///
    /// The fixture records `CRASH_POISON_THRESHOLD` crashes at one instant
    /// in the context's [`CrashWindow`], which sets the sticky `poisoned` flag,
    /// and then despawns the actor, which is the state the watchdog leaves
    /// behind once it stops respawning (ADR-049 §10). After this call
    /// [`Self::read_context_state`] reports
    /// [`ContextState::Poisoned`](scp_protocol::context::ContextState::Poisoned)
    /// and `Self::lookup` finds no actor. A context with no actor poisons the
    /// same way, because the watchdog's poison flag lives in `crash_windows`
    /// and not on the actor.
    ///
    /// `testing`-gated: no production build compiles it, no FFI bridge exports
    /// it, and only an in-process `Arc<Supervisor>` holder can call it.
    #[cfg(feature = "testing")]
    pub async fn test_poison_context(&self, context_id: &str) {
        let now_ms = self.crash_now_ms("context_actor", context_id);
        // Record every crash and drop the DashMap guard before the `.await`
        // below (the workspace denies `await_holding_lock`).
        {
            let mut entry = self.crash_windows.entry(context_id.to_owned()).or_default();
            for _ in 0..CRASH_POISON_THRESHOLD {
                entry.record(now_ms);
            }
        }
        self.despawn_actor(context_id).await;
    }

    /// Test fixture: leaves `context_id` in the respawn gap, the state
    /// `respawn_from_snapshot` holds between despawning a crashed actor and
    /// re-registering its replacement (ADR-049 §10).
    ///
    /// The fixture sets the transient respawn marker in the context's
    /// [`CrashWindow`] and despawns the actor, and never re-registers one.
    /// After this call `Self::lookup` finds no actor and
    /// [`Self::read_context_state_checked`] reports
    /// [`ContextError::ActorCrashed`].
    ///
    /// `testing`-gated: no production build compiles it, no FFI bridge exports
    /// it, and only an in-process `Arc<Supervisor>` holder can call it.
    #[cfg(feature = "testing")]
    pub async fn test_hold_context_mid_respawn(&self, context_id: &str) {
        // Drop the DashMap guard before the `.await` below (the workspace
        // denies `await_holding_lock`).
        self.crash_windows
            .entry(context_id.to_owned())
            .or_default()
            .mark_respawning();
        self.despawn_actor(context_id).await;
    }

    /// Test fixture: leaves `context_id` crashed with a failed last respawn
    /// and below the poison threshold, the "silently dead" state
    /// `record_respawn_failure` leaves behind (ADR-049 §10).
    ///
    /// The fixture sets the failed-respawn flag in the context's
    /// [`CrashWindow`], records no crash against the respawn budget, and
    /// despawns the actor. After this call `Self::lookup` finds no actor,
    /// `Self::is_context_poisoned` reports `false`, and
    /// [`Self::read_context_state_checked`] reports
    /// [`ContextError::ActorCrashed`].
    ///
    /// `testing`-gated: no production build compiles it, no FFI bridge exports
    /// it, and only an in-process `Arc<Supervisor>` holder can call it.
    #[cfg(feature = "testing")]
    pub async fn test_fail_context_respawn(&self, context_id: &str) {
        self.crash_windows
            .entry(context_id.to_owned())
            .or_default()
            .mark_respawn_failed();
        self.despawn_actor(context_id).await;
    }

    /// Test fixture: registers an actor handle for `context_id` whose mailbox
    /// no task drains, so a caller reaches the supervisor's registry and never
    /// reaches an actor.
    ///
    /// The fixture builds a command channel, drops the receiving half, and
    /// stores the sending half as `context_id`'s actor handle, replacing any
    /// handle the id already had. Every later command send fails with
    /// [`ContextError::ActorBusy`], which is the outcome a saturated mailbox
    /// produces once
    /// [`SEND_TIMEOUT`](crate::context::actor::SEND_TIMEOUT) elapses. After
    /// this call `Self::lookup` finds an actor for the id,
    /// [`Self::read_context_state_checked`] reports
    /// [`ContextError::ActorBusy`], and [`Self::read_context_state`] reports
    /// `None`.
    ///
    /// `testing`-gated: no production build compiles it, no FFI bridge exports
    /// it, and only an in-process `Arc<Supervisor>` holder can call it.
    #[cfg(feature = "testing")]
    pub fn test_make_actor_unreachable(&self, context_id: &str) {
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
        drop(rx);
        self.actors
            .insert(context_id.to_owned(), ContextActorHandle::from_sender(tx));
    }

    /// Test fixture: registers an actor handle for `context_id` whose mailbox
    /// accepts a command that no task ever handles, so a caller's command is
    /// enqueued and its reply never arrives: the actor turn stalls until
    /// [`REPLY_TIMEOUT`](crate::context::actor::handle::REPLY_TIMEOUT).
    ///
    /// Returns the mailbox's receiving half. Holding it keeps the stall;
    /// dropping it drops every queued command and its reply sender, so a
    /// waiting caller fails at once.
    ///
    /// `testing`-gated: no production build compiles it, no FFI bridge exports
    /// it, and only an in-process `Arc<Supervisor>` holder can call it.
    #[cfg(feature = "testing")]
    #[must_use = "dropping the receiver ends the stall"]
    pub fn test_stall_actor(&self, context_id: &str) -> Box<dyn std::any::Any + Send> {
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(1);
        self.actors
            .insert(context_id.to_owned(), ContextActorHandle::from_sender(tx));
        Box::new(rx)
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
        if let Some(window) = self.crash_windows.get(ctx_id)
            && window.actor_down()
        {
            return if window.is_poisoned() {
                ContextError::ContextPoisoned(ctx_id.to_owned())
            } else {
                ContextError::ActorCrashed(ctx_id.to_owned())
            };
        }
        ContextError::ContextNotRegistered(not_registered_msg)
    }

    /// Operator action (ADR-049 §10): clear a context's poison record and
    /// attempt ONE respawn from the persisted snapshot.
    ///
    /// This is the explicit recovery path for a poisoned context, for the
    /// operator, which holds the Supervisor. It is not on
    /// `SupervisorHandle`, the surface actors hold, so no actor turn reaches it: it waits for
    /// `bootstrap_spawn_lock`, whose holders wait on actor mailboxes. The
    /// alternative recovery path is a process restart, which re-runs
    /// `restore_all_contexts` and rebuilds every actor from persistence (the
    /// poison record lives only in memory, so it does not survive a
    /// restart).
    ///
    /// # Errors
    ///
    /// Surfaces any error from the respawn (e.g.
    /// [`ContextError::ActorCrashed`] when no snapshot exists). On a failed
    /// respawn the freshly-cleared window records the failure as a crash —
    /// a context that cannot be respawned does not silently re-poison from
    /// stale history, but also does not loop. While a
    /// [`Self::discard_joined_context`] of the id is in progress it returns
    /// [`ContextError::ContextNotRegistered`], and while a create, import or
    /// join of the id has not committed or rolled back its first state it
    /// returns [`ContextError::ActorBusy`]; both leave the poison record
    /// untouched. The errors of loading the wrapping key of `owning_did`
    /// return before the poison record is touched.
    pub async fn clear_poison(
        self: &Arc<Self>,
        ctx_id: &str,
        owning_did: &DID,
    ) -> Result<(), ContextError> {
        // An operator entry point: load the owner's wrapping key before any
        // lock, so no custody call runs under `bootstrap_spawn_lock` and the
        // respawn's lookup finds the key.
        self.load_wrapping_key(owning_did).await?;
        // Take `bootstrap_spawn_lock` BEFORE touching the window. While this
        // call waits for the lock the sticky poison flag still stands, so
        // `read_context_state_checked` reports the wait as `Poisoned`, never as
        // `Ok(None)`, the answer on which a caller that treats `Ok(None)` as
        // "already closed" (a bridge's `context_close`) would skip the
        // `ContextClose` check and release the context. Every writer of the respawn marker holds this lock, so no
        // create, import, or join bootstrap for the same id can clear the
        // marker set below.
        let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
        // Refuse before touching the window, so a refused call leaves the
        // poison record as it found it.
        self.refuse_pending_discard(ctx_id, &bootstrap_guard)?;
        self.refuse_pending_first_state(ctx_id, &bootstrap_guard)?;
        // Clear the window so the single retry starts from a clean budget.
        // `entry().or_default()` then `clear()` resets both the deque and the
        // sticky flag, and the same guard sets the respawn marker, so no read
        // falls between the clear and the marker.
        {
            let mut entry = self.crash_windows.entry(ctx_id.to_owned()).or_default();
            entry.clear();
            entry.mark_respawning();
        }
        self.respawn_from_snapshot_locked(ctx_id, owning_did, &bootstrap_guard)
            .await
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
    /// entry from `Self::actors` under the supervisor's
    /// `Self::write_lock` so a concurrent re-registration cannot
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
    /// `pub` — exposed through
    /// `SupervisorHandle::despawn_actor`
    /// so lifecycle bootstrap (`import_context`) can perform the
    /// despawn-then-respawn dance without holding `&Supervisor`
    /// directly. Called directly (on `&Supervisor`) by
    /// `crate::context::lifecycle_helpers::shutdown_all_contexts` to
    /// remove each actor's handle after `ShutdownSelf`, so the inbox
    /// closes and the actor task exits rather than lingering as a
    /// zombie. Also called by the FFI bridges as the COMPENSATING teardown
    /// when a post-irreversible-commit step of the Welcome-join fails (e.g.
    /// a concurrent close/leave removed the bridge state before the
    /// authenticated ceiling could be synced): the just-committed actor is
    /// despawned so no orphaned live actor lingers for a join that did not
    /// fully materialize. This is a silent local teardown — it drops the
    /// actor's inbox so the task exits, without any MLS leave ceremony or
    /// spurious `MemberLeft` event.
    pub async fn despawn_actor(&self, context_id: &str) -> bool {
        let _guard = self.write_lock.lock().await;
        let removed = self.actors.remove(context_id).is_some();
        if removed {
            self.note_push_routes_changed();
        }
        removed
    }

    /// Despawn the actor that `import_context` is replacing, and mark the
    /// replace gap in the context's [`CrashWindow`] (ADR-049 §10).
    ///
    /// Between this despawn and the registration of the imported actor the
    /// context exists but no actor serves it. Without the marker,
    /// [`Self::read_context_state_checked`] reports that gap as `Ok(None)`,
    /// and a caller that reads `Ok(None)` as a close that already happened (a
    /// bridge's `context_close`) skips the `CloseContext` dispatch, which
    /// carries the only `ContextClose` capability check, and releases its
    /// per-context state. With the marker the gap reads as
    /// [`ContextError::ActorCrashed`], the same answer a crash-respawn gap
    /// gives. The marker is set before the despawn so no read falls between
    /// the two. The [`BootstrapCrashWindow`] the supervisor's
    /// `ImportContext` arm holds clears it on every exit, after the imported
    /// actor registers or the import fails.
    pub(in crate::context) async fn despawn_for_replace(&self, context_id: &str) -> bool {
        // Drop the DashMap guard before the `.await` below (the workspace
        // denies `await_holding_lock`).
        self.crash_windows
            .entry(context_id.to_owned())
            .or_default()
            .mark_respawning();
        self.despawn_actor(context_id).await
    }

    /// Clear the respawn marker a bootstrap set ([`Self::begin_bootstrap_window`]
    /// or [`Self::despawn_for_replace`]), and drop the context's
    /// [`CrashWindow`] entry when the marker was its only content. A no-op
    /// when no entry exists (a bootstrap of an id with no crash history that
    /// replaced no actor). Called by [`BootstrapCrashWindow`]'s drop under
    /// `bootstrap_spawn_lock`. Every writer of the respawn marker holds that
    /// lock (`respawn_from_snapshot` and `clear_poison` included), so no
    /// respawn's marker is cleared here.
    fn end_bootstrap_window(&self, context_id: &str) {
        if let Some(mut window) = self.crash_windows.get_mut(context_id) {
            window.clear_respawning();
        }
        // The `get_mut` guard above is dropped before `remove_if` takes the
        // same shard lock.
        self.crash_windows
            .remove_if(context_id, |_, window| window.is_empty_except_respawning());
    }

    /// COMPLETE compensating teardown of a just-joined context (BLACK-2JF-01).
    ///
    /// Unlike [`Self::despawn_actor`] — which removes ONLY the in-memory actor
    /// handle — this fully reverses everything
    /// [`Self::spawn_actor_from_welcome`] materialized after the irreversible
    /// KeyPackage consume: it drops the actor handle (whose owned
    /// `PerContextState` holds the MLS crypto — #2148 birth-into-actor — so the
    /// sender key, the group's signer, and the group's provider-storage values
    /// ZEROIZE on drop when the actor task ends) AND deletes the persisted Class-S snapshot
    /// (`delete_context`).
    ///
    /// The FFI bridges call this as the compensating teardown when a
    /// post-irreversible-commit join step fails (e.g. a concurrent close/leave
    /// removed the bridge state before the authenticated ceiling could be
    /// synced). A bare `despawn_actor` there would leave the durable snapshot
    /// behind, so on restart the "torn-down" context would RESURRECT
    /// (FFI/runtime divergence) and the residual snapshot would block a fresh
    /// re-join via Precheck-D (first-writer-wins durable collision). Tearing
    /// down the handle, snapshot, and floor registry entry leaves the join
    /// strictly MORE recoverable: a re-join with a fresh KeyPackage reservation
    /// now succeeds.
    ///
    /// The single-use KeyPackage the join burned is NOT restored — that
    /// consume is irreversible by construction (a KeyPackage is one-shot), and
    /// re-joining draws a fresh reservation anyway.
    ///
    /// The floor reap, the stream-admission reap and the snapshot delete run
    /// only after the actor's `run()` has returned. The actor persists dirty
    /// state in its post-loop drain, after the last sender drops or `Shutdown`
    /// dispatches, and a command already queued from another clone of its
    /// handle can re-create a floor or tracker entry, so anything removed
    /// while it still runs can come back and the context resurrects on
    /// restart. Until the delete, the join's snapshot stays in place, so
    /// Precheck D refuses a re-join of the id in the meantime.
    ///
    /// The registry removal runs under `bootstrap_spawn_lock` and then
    /// `write_lock`, atomic with respect to concurrent register/despawn and
    /// to any respawn of the id. From the removal until the teardown
    /// finishes, the id is marked pending and every respawn of it refuses, so
    /// a crash watchdog cannot restore the context from the snapshot this
    /// call is about to delete. The exit wait runs outside both locks,
    /// because an actor handler can take `write_lock` (a TTL exit's
    /// self-despawn).
    ///
    /// When the actor has not exited within the reply bound, the wait moves to
    /// a task on the Supervisor's tracker that stops the actor with no time
    /// bound and then finishes the teardown, and this call returns the wait's
    /// error. Once shutdown has begun the tracker takes no task, so the call
    /// finishes the teardown inline instead and returns only after the actor
    /// has exited. Either way no write from the actor lands after the delete.
    /// One gap remains: if the process dies while a wedged actor is still
    /// running, the join's snapshot is still in place and the next start
    /// restores the context.
    ///
    /// Returns `Ok(true)` if a live actor handle was registered and removed,
    /// `Ok(false)` if no entry existed for `context_id`.
    ///
    /// # Errors
    ///
    /// The actor's exit-wait error (the teardown then finishes in the tracked
    /// task), the error from finishing the teardown
    /// (`Self::finish_discard`), or [`ContextError::ActorBusy`] when an
    /// earlier discard of the id has not finished its teardown.
    pub async fn discard_joined_context(
        self: &Arc<Self>,
        context_id: &str,
    ) -> Result<bool, ContextError> {
        // 1. Remove the in-memory actor handle. #2148 (ADR-049 birth-into-actor):
        //    the joiner's MLS crypto is OWNED by the actor's `PerContextState`
        //    (born owned at the WELCOME seam, never provider-resident), so once
        //    the actor task ends its state drops: the sender key ZEROIZES
        //    (`ZeroizeOnDrop`), the group's signer and its provider-storage
        //    values zeroize on drop. There is no provider map to also destroy
        //    (the deleted `destroy_mls_group` arm). Another clone of the handle
        //    (a bridge's cached one) keeps the actor alive, so step 2 stops it
        //    explicitly.
        //
        //    The removal and the pending mark run under `bootstrap_spawn_lock`
        //    as well as `write_lock` (the spawn paths' order), so they land
        //    either wholly before or wholly after any respawn of the id. A
        //    respawn that runs after them finds the mark and refuses
        //    (`refuse_pending_discard`); the watchdog's respawn also finds the
        //    crashed actor gone from the registry and stops
        //    (`respawn_crashed_actor`). A respawn that ran before them
        //    registered its actor first, and this removal takes that actor.
        let (handle, mark) = {
            let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
            let guard = self.write_lock.lock().await;
            if self.pending_discards.contains(context_id) {
                return Err(ContextError::ActorBusy(format!(
                    "discard of joined context '{context_id}': an earlier discard is still \
                     waiting for the actor to exit, and deletes the snapshot once it has"
                )));
            }
            let removed = self.actors.remove(context_id);
            if removed.is_some() {
                self.note_push_routes_changed();
            }
            let Some((_, handle)) = removed else {
                // No actor to wait for: tear down under the locks already
                // held, so no respawn of the id runs between the registry
                // check and the snapshot delete.
                self.finish_discard_locked(context_id, &bootstrap_guard, &guard)
                    .await?;
                return Ok(false);
            };
            self.pending_discards.insert(context_id.to_owned());
            (
                handle,
                PendingDiscardMark {
                    supervisor: self,
                    context_id,
                },
            )
        };
        // 2. Stop the actor and wait for its run loop to return, so its
        //    post-loop drain persist lands before step 3.
        let Err(wait_error) = handle.shutdown_and_await_exit().await else {
            let finished = self.finish_discard(context_id).await;
            drop(mark);
            finished?;
            return Ok(true);
        };
        let supervisor = Arc::downgrade(self);
        let persistence = self.persistence_ref().cloned();
        let id = context_id.to_owned();
        let moved = handle.clone();
        let spawned = self.spawn_tracked("discard_joined_context exit wait", async move {
            moved.stop_and_await_exit_unbounded().await;
            finish_discard_after_exit(&supervisor, persistence.as_ref(), &id).await;
        });
        if spawned.is_ok() {
            // The task now owns the mark and clears it after the teardown.
            std::mem::forget(mark);
        } else {
            // Shutdown has begun and the tracker takes no task: finish inline.
            handle.stop_and_await_exit_unbounded().await;
            let finished = self.finish_discard(context_id).await;
            drop(mark);
            finished?;
        }
        Err(wait_error)
    }

    /// Step 3 of [`Self::discard_joined_context`], run once the discarded
    /// actor has exited: drops the context's Class-M floor registry entry and
    /// its stream-admission tracker entry, then deletes the snapshot the join
    /// persisted.
    ///
    /// It holds `bootstrap_spawn_lock` and then `write_lock` (the spawn
    /// paths' order), so no spawn of the id runs between the registry check
    /// and the delete.
    ///
    /// # Errors
    ///
    /// [`ContextError::InvalidState`] when an actor is registered for the
    /// id again (a restore spawned it from the snapshot while the discarded
    /// actor was exiting): the snapshot is that live context's and stays.
    /// [`ContextError::PersistenceFailed`] when the snapshot delete fails.
    async fn finish_discard(&self, context_id: &str) -> Result<(), ContextError> {
        let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
        let guard = self.write_lock.lock().await;
        self.finish_discard_locked(context_id, &bootstrap_guard, &guard)
            .await
    }

    /// Body of [`Self::finish_discard`], run by a caller that already holds
    /// `bootstrap_spawn_lock` and `write_lock`; the guard parameters prove it.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::finish_discard`].
    async fn finish_discard_locked(
        &self,
        context_id: &str,
        _bootstrap_guard: &tokio::sync::MutexGuard<'_, ()>,
        _write_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<(), ContextError> {
        if self.actors.contains_key(context_id) {
            return Err(ContextError::InvalidState(format!(
                "discard of joined context '{context_id}': an actor was registered for the id \
                 again before the teardown finished; its snapshot is kept"
            )));
        }
        // The floor registry entry (ADR-049): a discarded welcome-join is
        // permanently gone (its actor-owned crypto freed when the actor task
        // ended — `SenderKey`s, the MLS group's signer, and its
        // provider-storage values zeroize on drop, and security model spec
        // §9.15 lists the copies no wipe reaches; its durable snapshot deleted
        // below), so the floors are moot and pruning is sound; see
        // `Supervisor::remove_context_floors` for the full permanent-vs-
        // transient safety argument.
        self.remove_context_floors(&crate::context::state::context_id_to_bytes(context_id));
        // The stream admission-tracker registry entry, on the same
        // permanent-teardown sweep (spec §5.4.5). An in-flight pump holding its
        // own Arc keeps the tracker alive; this only drops the registry's
        // reference.
        self.reap_stream_admission(context_id);
        // The durable Class-S snapshot, so a restart cannot resurrect the
        // context and Precheck D does not block a fresh re-join (mirrors the
        // `delete_context` rollback arm; the helper-persistence slot is the
        // same backend the join persisted to, an unset slot means nothing
        // durable was ever written).
        match self.persistence_ref() {
            Some(persistence) => persistence.delete_context(context_id).await.map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "discard of joined context '{context_id}': snapshot delete failed: {e}"
                ))
            }),
            None => Ok(()),
        }
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
    /// Only [`CrashWindow::clear`] (operator `clear_poison`), a (re)create,
    /// import, standing recreate, or Welcome join of the id whose bootstrap
    /// registers an actor ([`Self::begin_bootstrap_window`]), or a process
    /// restart removes a poison. A bootstrap that registers no actor puts
    /// the poisoned window back.
    ///
    /// It is NOT called on the respawn path: a respawn's internal despawn
    /// must preserve the running crash count so the budget accumulates across
    /// respawns (the loop must eventually poison a reliably-crashing
    /// snapshot).
    pub fn reap_crash_window(&self, context_id: &str) {
        // `remove_if` evaluates the predicate while holding the shard lock and
        // only removes when it returns true — so a concurrent poison-despawn
        // cannot have the entry removed out from under it.
        self.crash_windows
            .remove_if(context_id, |_, window| !window.is_poisoned());
    }

    /// Start a fresh crash budget for an explicit (re)create / import /
    /// standing-recreate / Welcome-join bootstrap of the id (ADR-049 §10).
    ///
    /// Deliberately (re)creating or importing a context id is a fresh start
    /// that resets the crash budget, poisoned or not. Without the reset, a
    /// re-created context with a deterministic id (e.g. a standing-pair id)
    /// would inherit the prior instance's sticky `poisoned = true` and
    /// re-poison on its very first panic, or inherit a partial crash count and
    /// poison early.
    ///
    /// When the id has a window, the reset swaps it for one that holds only
    /// the respawn marker, in one map operation, so from here until the
    /// bootstrap ends [`Self::read_context_state_checked`] reports the id as
    /// `ActorCrashed`, never as `Ok(None)`. An id with no window gets none
    /// here. The returned guard ends the
    /// window when it drops, reading whether any actor serves the id rather
    /// than whether this bootstrap registered one: when an actor serves the
    /// id, it clears the marker and reaps the now-empty window; when none
    /// does, it puts the prior window back, so a poisoned or respawn-failed
    /// context that a failed import or create left without an actor still
    /// reads as `Poisoned` or `ActorCrashed`. A bootstrap refused against a
    /// live actor that still serves the id takes the first branch, so that
    /// actor's earlier crash count is not restored.
    ///
    /// Called under `bootstrap_spawn_lock`, and the caller keeps the guard
    /// inside that lock's scope. Every writer of the respawn marker holds the
    /// same lock, so the guard never clears or restores over a marker another
    /// respawn set.
    pub(in crate::context) fn begin_bootstrap_window(
        &self,
        context_id: &str,
    ) -> BootstrapCrashWindow<'_> {
        let prior = match self.crash_windows.entry(context_id.to_owned()) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let mut fresh = CrashWindow::default();
                fresh.mark_respawning();
                Some(std::mem::replace(occupied.get_mut(), fresh))
            }
            dashmap::mapref::entry::Entry::Vacant(_) => None,
        };
        BootstrapCrashWindow {
            supervisor: self,
            context_id: context_id.to_owned(),
            prior,
        }
    }

    /// Dispatch a [`StandingCommand`] — mailbox-first for variants that
    /// map to an existing per-context actor, otherwise the supervisor-
    /// scoped `dispatch_standing_direct` path (ADR-049 §15 / plan
    /// row 11).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. Covers the
    /// contact-graph (standing context) paths from spec §5.12.6.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
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
            StandingCommand::StandingContext {
                local_did,
                peer_did,
                relay_urls,
                reply,
            } => {
                let fut = self.standing_context(&local_did, &peer_did, relay_urls);
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
        }
    }

    /// Dispatch a [`OutletsCommand`] to its per-context actor's mailbox
    /// (ADR-049 §15 / plan row 11).
    ///
    /// Covers the hard-rate-limit consume / refund helpers that FFI
    /// bridges call from their outlet-dispatch paths. The cross-context
    /// outlet-invocation saga (spec §6.2.4) is produced directly by
    /// [`Supervisor::start_cross_context_outlet_invocation_saga`](crate::context::supervisor::Supervisor::start_cross_context_outlet_invocation_saga),
    /// not via the actor mailbox: that saga's
    /// [`SagaSigners`]
    /// are borrowed (non-`'static`) `&ed25519_dalek::SigningKey`
    /// references that cannot move into a `'static` mailbox message,
    /// even though its executor is itself `Send + 'static`. Note that
    /// [`Supervisor::invoke_outlet_with_economy`](crate::context::supervisor::Supervisor::invoke_outlet_with_economy)
    /// is not migrated here for a distinct reason: its generic executor
    /// closure carries no `Send` bound, so it cannot cross the actor
    /// mailbox at all.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`] has
    ///   been attached yet.
    pub(in crate::context) async fn dispatch_outlets_command(
        &self,
        cmd: OutletsCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Try the actor mailbox first. Post-Step-B every valid context
        // has a registered actor, so the per-context outlets handlers run
        // on the actor. Reaching the fallback means no actor is
        // registered for the target context — surface a typed
        // `ContextNotRegistered` on the command's reply oneshot.
        if let Some(actor) = self.lookup(Self::outlets_command_context_id(&cmd)) {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Outlets(cmd)).await;
        }

        // No-actor settle backstop: a `SettleOutletEconomy` carries an
        // in-flight `OutletEconomyTicket` (held external payment escrow +
        // the `#[must_use]`/Drop balance invariant). The sync
        // `reply_outlets_not_registered` cannot `.await` to void the escrow
        // and would DROP the ticket. The primary defense is the no-actor
        // pre-check in `settle_outlet_economy_via_actor`; this handles the
        // residual TOCTOU where the actor is despawned between that
        // pre-check and here. Reclaim the ticket, void its external
        // escrow, consume it, and reply with the typed error.
        if let OutletsCommand::SettleOutletEconomy {
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
            // genuinely-unknown context keeps the rich SCP-OUTLET-6089
            // not-registered diagnostic (escrow already voided above, so the
            // ticket-balance invariant holds on every branch) (ADR-049 §10).
            let err = self.lookup_miss_error(
                &context_id,
                format!(
                    "SCP-OUTLET-6089: outlet-economy settle for context '{context_id}' found no \
                     registered actor (reserved generation {generation}); escrow voided, \
                     reservation not captured"
                ),
            );
            let sketch = standing_outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Ok(Outcome::err(sketch));
        }

        Ok(Self::reply_outlets_not_registered(cmd))
    }

    /// Reply to a [`OutletsCommand`] whose target context has no registered
    /// actor with a typed [`ContextError::ContextNotRegistered`] on the
    /// variant's reply oneshot.
    fn reply_outlets_not_registered(cmd: OutletsCommand) -> Outcome<()> {
        match cmd {
            OutletsCommand::TryConsumeHardRateLimit {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // `RefundHardRateLimit`, `ReleaseStreamCaveatCounter`, and
            // `ReverseStreamEscrow` share the
            // `oneshot::Sender<Result<(), ContextError>>` reply shape and the
            // identical not-registered response, so they collapse into one arm
            // (the reserve variants below each carry a distinct reply type and
            // stay separate). `ReverseStreamEscrow` carries no external escrow —
            // the §5.4.5 open-time hold is a budget-tracker debit only — so a
            // missing actor simply drops the (best-effort) refund: the torn-down
            // context's budget tracker is gone, so there is nothing to credit.
            OutletsCommand::RefundHardRateLimit {
                context_id, reply, ..
            }
            | OutletsCommand::ReleaseStreamCaveatCounter {
                context_id, reply, ..
            }
            | OutletsCommand::ReverseStreamEscrow {
                context_id, reply, ..
            }
            // Grant reverse-on-reject: a missing actor means the context was
            // torn down — the budget refund + record un-bump are MOOT (the
            // torn-down state is gone). Reply the typed error (best-effort, like
            // `ReverseStreamEscrow`).
            | OutletsCommand::ReverseStreamGrantEscrow {
                context_id, reply, ..
            }
            // Fix-D: `PersistStreamReservation` shares the `Result<(),
            // ContextError>` reply shape. A missing actor means the just-reserved
            // context was torn down before the record could persist — reply the
            // typed error; the open path logs it and proceeds (best-effort net).
            | OutletsCommand::PersistStreamReservation {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::ReconcileStreamReservations { context_id, reply } => {
                // Fix-D: the restore-time sweep targets a just-respawned actor; a
                // missing actor here means the context was despawned again between
                // restore and the sweep dispatch — reply the typed infra error
                // (`Result<usize, _>` reply shape, distinct from the arm above).
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::SettleOutletStream {
                settlement, reply, ..
            } => {
                // The common no-actor case is handled supervisor-side in
                // `settle_outlet_stream_via_actor` (which captures against the
                // open-time snapshot) BEFORE dispatch. Reaching here is the
                // residual TOCTOU where the actor was despawned between that
                // pre-check and here — reply with the typed error (no external
                // escrow to void, unlike the unary settle backstop).
                let err = ContextError::ContextNotRegistered(settlement.context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::ReserveOutletEconomy {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::ReserveOutletStreamEconomy {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::ReserveStreamGrantEscrow {
                context_id, reply, ..
            } => {
                // Distinct `Result<Amount, _>` reply shape. A missing actor for a
                // mid-stream grant reserve means the hosting context was torn
                // down — the grant cannot be escrowed; reply the typed error so
                // the bridge surfaces it and does NOT apply the credit grant.
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::ReserveStreamCaveatCounter {
                context_id, reply, ..
            } => {
                // Outer `Result` = infra outcome — a missing actor is an
                // infrastructure failure, not an admission decision.
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            OutletsCommand::SettleOutletEconomy {
                context_id,
                request,
                reply,
                ..
            } => {
                // Defense-in-depth backstop: `dispatch_outlets_command`
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
        }
    }

    /// Reply to a [`BroadcastCommand`] whose target context has no
    /// registered actor, with the poison-aware lookup-miss error
    /// ([`Self::lookup_miss_error`]): `ContextPoisoned` or `ActorCrashed`
    /// when the context's crash window says so, `ContextNotRegistered`
    /// otherwise.
    fn reply_broadcast_lookup_miss(&self, cmd: BroadcastCommand) -> Outcome<()> {
        let ctx_id = Self::broadcast_command_context_id(&cmd).to_owned();
        let err = self.lookup_miss_error(&ctx_id, ctx_id.clone());
        match cmd {
            BroadcastCommand::SubscribeBroadcast { reply, .. } => reply_lookup_miss(reply, err),
            BroadcastCommand::UnsubscribeBroadcast { reply, .. } => reply_lookup_miss(reply, err),
            BroadcastCommand::PublishBroadcast { reply, .. }
            | BroadcastCommand::PublishBroadcastContent { reply, .. } => {
                reply_lookup_miss(reply, err)
            }
            BroadcastCommand::BlockBroadcastSubscriber { reply, .. } => {
                reply_lookup_miss(reply, err)
            }
            BroadcastCommand::UnblockBroadcastSubscriber { reply, .. } => {
                reply_lookup_miss(reply, err)
            }
            BroadcastCommand::HandleBroadcastKeyRequest { reply, .. } => {
                reply_lookup_miss(reply, err)
            }
            BroadcastCommand::BroadcastSubscriberCount { reply, .. } => {
                reply_lookup_miss(reply, err)
            }
            BroadcastCommand::IsBroadcastSubscriber { reply, .. } => reply_lookup_miss(reply, err),
            BroadcastCommand::BroadcastAdmission { reply, .. } => reply_lookup_miss(reply, err),
            #[cfg(feature = "testing")]
            BroadcastCommand::SeedBroadcastAuthor { reply, .. } => reply_lookup_miss(reply, err),
        }
    }

    /// Dispatch a [`BroadcastCommand`] through the target context's actor
    /// mailbox.
    ///
    /// The publish variants carry the author's `CommandSigner` and sign
    /// inside the actor turn (ADR-049 Decision 7a).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] when the actor is registered but its
    ///   mailbox is full, closed, or times out. An absent, poisoned or
    ///   crashed actor is reported on the command's reply channel.
    pub async fn dispatch_broadcast_command(
        &self,
        cmd: BroadcastCommand,
    ) -> Result<Outcome<()>, ContextError> {
        if let Some(actor) = self.lookup(Self::broadcast_command_context_id(&cmd)) {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd)).await;
        }
        Ok(self.reply_broadcast_lookup_miss(cmd))
    }

    /// Start a cross-context saga. See plan §"Cross-context saga
    /// protocol".
    ///
    /// # Coordinator FSM
    ///
    /// ADR-049 §15 implements the `Initiated → PreparingA → PreparingB →
    /// Committing → Committed | Aborting → Aborted | NeedsRepair` state
    /// machine with journal durability. Each phase transition is
    /// persisted to the
    /// [`SagaJournal`]
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
    /// [`ContextError::ActorBusy`]
    /// with a `SagaBusy` reason. The reservation (`reserved_saga_contexts`)
    /// is held by an RAII guard for the saga's lifetime and released on
    /// EVERY terminal — Committed, Aborted, AND NeedsRepair — plus
    /// panic-unwind, so a stuck saga never wedges unrelated disjoint sagas.
    ///
    /// # Sole production saga
    ///
    /// `CrossContextOutletInvocation` is the only production saga — its
    /// end-to-end Prepare/Commit dispatch over the two co-resident participant
    /// actors lands here (spec §6.2.4); drive it via
    /// [`Self::start_cross_context_outlet_invocation_saga`], which supplies the
    /// supervisor-side outlet executor and the target's Active Signing Key.
    /// Calling `start_saga` directly with a `CrossContextOutletInvocation` input
    /// (no executor / signing key) is a misuse: the FSM aborts at Prepare-A with
    /// a typed [`ContextError::InvalidState`] because it has no way to execute
    /// the outlet or sign the receipt.
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
    /// - [`ContextError::InvalidState`] on the executor-less
    ///   `CrossContextOutletInvocation` misuse path, or on journal I/O failure.
    pub async fn start_saga(&self, input: SagaInput) -> Result<SagaOutput, ContextError> {
        // Per-participant-context-set reservation (ADR-049 §3a, spec §5.15.4):
        // acquire the gating reservation HERE on the start path (the gate
        // requires the reserve call to live in `start_saga`'s body), then drive
        // the FSM under it. No executor / signing key: the generic entry point
        // cannot drive a `CrossContextOutletInvocation` Commit (it has no way to
        // run the outlet or sign the receipt) — the cross-context arm's prepare
        // dispatch aborts with a typed error.
        let context_set = saga_participant_context_set(&input);
        let reservation = self
            .try_reserve_context_set(&context_set)
            .map_err(|r| r.actor_busy)?;
        // The generic entry point keeps the internal `ContextError` contract its
        // (test-only) callers depend on: mint the id, run, discard the
        // `needs_repair` flag, propagate the `ContextError`. The typed
        // `SagaError` lift lives only on the cross-context entry point.
        self.run_saga(SagaId::new(), input, None, reservation)
            .await
            .map_err(|e| e.error)
    }

    /// Drive a cross-context outlet-invocation saga (spec §6.2.4) end-to-end
    /// over the two co-resident participant context-actors (caller + target),
    /// blocking until the saga reaches a terminal state.
    ///
    /// The supervisor FSM dispatches `PrepareA` to the caller actor, `PrepareB`
    /// to the target actor, then (on Commit) `CommitBReserve` → runs the
    /// `executor` supervisor-side → `CommitBSettle` → `CommitA`. The outlet runs
    /// **exactly once** supervisor-side between the two Commit-B round-trips
    /// (the non-`Send` executor cannot cross the actor mailbox per ADR-049 §3).
    ///
    /// `signers` carries the two Active Signing Key signers named by role
    /// ([`SagaSigners`]): `target` signs the
    /// [`CrossContextOutletReceipt`]
    /// and the TARGET-side divergence marker on a one-sided `NeedsRepair`;
    /// `caller` signs the CALLER-side divergence marker on `NeedsRepair`. Each
    /// side signs its own marker into its own log. The named fields make a
    /// same-typed signer swap a compile-visible field-name error rather
    /// than a silent miscapture. The actor holds no custody key (ADR-049), so
    /// the caller supplies both per-call exactly as [`Self::send_heartbeat`] /
    /// [`Self::build_local_checkpoint`] do.
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
    ///    bidirectionally-approved `OutletInterface` to `target_context_id` for
    ///    `outlet_registration_id` (the §6.2.0.1 standing consent the §6.2.4
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
    /// # Caller authentication — bound at the FFI seam (§6.2.4)
    ///
    /// This saga's production callers are the FFI cross-context-saga exports
    /// (`outlet_invoke_cross_context_saga` in the PyO3, NAPI, and UniFFI
    /// bridges). Its channel-auth defenses — gate 1 above, the §6.2.4
    /// *Caller authentication* clause, the aggregate nonce-eviction replay
    /// bound (spec §6.2.4 *Cache-eviction bound*), and B's `InboundPolicy`
    /// role check — ALL rest on `caller_did` (and `caller_context_id`) being
    /// the AUTHENTICATED identity of the transport leg, never an
    /// envelope-asserted value. The supervisor here only verifies `is_member`
    /// (membership), which is NECESSARY but NOT SUFFICIENT: membership does not
    /// by itself prove the request leg is authenticated as that member.
    ///
    /// That binding IS enforced by each bridge BEFORE this entry point runs:
    /// `enforce_caller_principal_binding` (PyO3 `src/outlets.rs`, NAPI
    /// `napi/outlets.rs`, UniFFI `bridge.rs`) rejects unless `caller_did` is an
    /// identity THAT bridge instance hosts AND a member of `caller_context_id`
    /// — the §6.2.0 / §6.2.4 "channel-authenticated identity" requirement — so
    /// the saga never observes an unauthenticated caller (a mismatch surfaces
    /// the registered caller-axis terminal `SCP-SAGA-13050`). The co-resident
    /// core path has no untrusted leg; the FFI seam is where the authenticated
    /// principal is bound (per the ADR-049 §3a discipline and the AGENTS.md
    /// integration checklist: function → `Supervisor` → FFI → SDK →
    /// `pipeline_wiring` assertion).
    ///
    /// # Errors
    ///
    /// Returns the typed [`SagaError`] — the legible §6.2.4 terminal space the
    /// FFI saga surface (ADR-049 §3a) maps onto `SCP-SAGA-*` WITHOUT parsing
    /// message strings:
    ///
    /// - [`SagaError::Aborted`] on any Prepare-phase abort — the initiator
    ///   is not a member of `caller_context_id`, no established interface to
    ///   `target_context_id` exists for `outlet_registration_id`, a participant
    ///   actor is not co-resident, a participant actor is unavailable to
    ///   complete the Prepare exchange, or any §6.2.4 authorization / freshness
    ///   / rate-limit check rejects. The structured [`SagaAbortReason`]
    ///   distinguishes the three reasons: [`SagaAbortReason::RateLimited`]
    ///   (retryable, carrying `retry_after_ms`) and
    ///   [`SagaAbortReason::ParticipantUnavailable`] (transient / retryable,
    ///   code `SCP-SAGA-13068`) are both distinguished from the permanent
    ///   [`SagaAbortReason::Rejected`]; `code` carries the numeric
    ///   `SCP-SAGA-13xxx` discriminant.
    /// - [`SagaError::NeedsRepair`] (carrying the [`SagaId`]) if the saga's
    ///   Commit retries are exhausted (a possible divergence requiring operator
    ///   repair).
    /// - [`SagaError::Busy`] on a participant-context-set overlap with an
    ///   in-flight saga (spec §5.15.4).
    pub async fn start_cross_context_outlet_invocation_saga<F, Fut>(
        &self,
        request: CrossContextOutletInvocationRequest,
        signers: SagaSigners,
        executor: F,
    ) -> Result<SagaOutput, SagaError>
    where
        F: FnOnce(serde_json::Value) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>> + Send + 'static,
    {
        let CrossContextOutletInvocationRequest {
            caller_context_id,
            target_context_id,
            caller_did,
            outlet_registration_id,
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
            // Caller-axis authorize-before-reserve rejection ⇒ `Aborted`
            // (neither side committed). Carries the already-allocated supervisor
            // code so the bridge maps to `SCP-SAGA-13050` directly.
            return Err(SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13050,
                message: format!(
                    "cross-context saga initiator '{caller_did}' is not a member of caller \
                     context '{caller_hex}' — not authorized to initiate over it"
                ),
            });
        }

        // Authorize-before-reserve gate 2 (target axis, BLACK-624-02): the caller
        // context MUST hold a bidirectionally-approved interface to the named
        // target for this outlet (the §6.2.0.1 standing consent the §6.2.4
        // invocation rides — it does NOT create the interface). Without this, a
        // caller who is a member of its OWN context could name an arbitrary
        // victim target_context_id and reserve the victim's saga slot before any
        // target-side check ran (those run inside Prepare-B, AFTER reservation),
        // wedging legitimate sagas touching the victim with ActorBusy. Reject
        // WITHOUT reserving so the wedge is foreclosed.
        let target_hex = hex::encode(target_context_id);
        if !self
            .has_established_outlet_interface(&caller_hex, &target_hex, &outlet_registration_id)
            .await
        {
            // Target-axis authorize-before-reserve rejection ⇒ `Aborted`
            // (neither side committed). Carries the already-allocated supervisor
            // code so the bridge maps to `SCP-SAGA-13062` directly.
            return Err(SagaError::Aborted {
                reason: SagaAbortReason::Rejected,
                code: 13062,
                message: format!(
                    "cross-context saga from caller context '{caller_hex}' to target context \
                     '{target_hex}' has no established interface for outlet \
                     '{outlet_registration_id}' — not authorized to invoke (and not authorized to \
                     reserve the target's saga slot)"
                ),
            });
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
        let boxed_executor: SagaOutletExecutor<'_> =
            Box::new(move |v: serde_json::Value| Box::pin(executor(v)) as _);

        let ctx = CrossContextSagaCtx {
            caller_context_id,
            target_context_id,
            caller_did: caller_did.clone(),
            outlet_registration_id: outlet_registration_id.clone(),
            ucan_proof_id: ucan_proof_id.clone(),
            input: input.clone(),
            asserted_chain_depth,
            asserted_nonce,
            asserted_timestamp_ms,
            caller_source_role,
            target_signer: signers.target,
            caller_signer: signers.caller,
            executor: Some(boxed_executor),
            executor_output: None,
            prepared_a: None,
            prepared_b: None,
            committed: None,
            committed_b_outlet_invoked_event_id: None,
            reached_needs_repair: false,
        };

        let saga_input = SagaInput::CrossContextOutletInvocation {
            caller_context_id,
            target_context_id,
            caller_did,
            outlet_registration_id,
            ucan_proof_id,
            input,
            asserted_chain_depth,
            asserted_nonce,
            asserted_timestamp_ms,
            // This is the sole production construction site: the dedicated
            // entry point supplied the executor + signing keys above.
            _seal: CrossContextSagaSeal::new(),
        };

        // Per-participant-context-set reservation (ADR-049 §3a, spec §5.15.4):
        // acquire the gating reservation on the start path, then drive the FSM
        // under it. A contention lifts to the typed `SagaError::Busy` carrying
        // the contended context id read STRUCTURALLY from the reserve call.
        let context_set = saga_participant_context_set(&saga_input);
        let reservation =
            self.try_reserve_context_set(&context_set)
                .map_err(|r| SagaError::Busy {
                    message: format!(
                        "participant context set overlaps an in-flight saga at context {}",
                        r.contended_context
                    ),
                    contended_context: r.contended_context,
                })?;

        // Mint the durable saga id HERE so it is available to the boundary lift
        // even on the FSM error path — `SagaError::NeedsRepair` MUST carry the
        // real minted id (the operator-repair handle), and the `Ok` path's
        // `SagaOutput.saga_id` is the SAME id.
        let saga_id = SagaId::new();
        self.run_saga(saga_id.clone(), saga_input, Some(ctx), reservation)
            .await
            .map_err(|run_err| Self::lift_run_saga_error(saga_id, run_err))
    }

    /// The streaming-saga FSM driver (SCP-OUT-046 #134; ADR-061 seal phase).
    ///
    /// The streaming sibling of
    /// [`Self::start_cross_context_outlet_invocation_saga`]: it runs the SAME
    /// authorize-before-reserve gates + the SAME `{caller, target}` per-set
    /// reservation (ADR-049 §3a), but it does NOT drive the generic synchronous
    /// `Self::run_saga` FSM (which holds its reservation to a terminal). A
    /// streaming saga has no Prepare-A (the invoker pays via B's stream escrow,
    /// §5.4.5 "Cross-context economy" — NOT a caller-side reservation), so this
    /// driver runs Prepare-B (streaming) → the Commit-transition, then returns a
    /// [`StreamingSagaHandle`] PROMPTLY (AC1) while an off-mailbox seal task
    /// (`run_streaming_saga_seal_task`)
    /// pumps the durable frontier capture + the seal-close.
    ///
    /// At the Commit-transition it: opens B's pump via the shared
    /// `Self::open_outlet_stream_phase1` helper in SAGA MODE (`settlement_sink =
    /// None` AND `invoked_event_sink = None` — the seal settles from the durable
    /// ledger and records B's `OutletInvoked` itself, so the pump must do
    /// NEITHER, else B double-records); RELEASES the concurrency slot (AC2 —
    /// `drop(reservation)`) while the escrow stays reserved (AC3); journals
    /// `Committing` (AC6); and spawns the seal task, which reaches `Committed`
    /// asynchronously at stream-close.
    ///
    /// `caller_context_id` is the RECEIVING context A (the invoker's context);
    /// `target_context_id` is the OPERATING context B (which hosts the streaming
    /// outlet registration). `signers.target` signs the SCP-OUT-043
    /// streaming receipt at seal-close.
    ///
    /// # Errors
    ///
    /// [`SagaError::Aborted`] for an authorize-before-reserve rejection, a
    /// Prepare-B policy reject, or a B-side open rejection (neither side
    /// committed; the staged slot + journal are rolled back); [`SagaError::Busy`]
    /// when the `{caller, target}` set overlaps an in-flight saga.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn start_cross_context_streaming_outlet_invocation_saga<E>(
        self: &Arc<Self>,
        caller_context_id: [u8; 32],
        target_context_id: [u8; 32],
        caller_did: DID,
        outlet_registration_id: String,
        ucan_proof_id: Option<String>,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        asserted_chain_depth: u8,
        asserted_nonce: [u8; 16],
        asserted_timestamp_ms: u64,
        timeout_ms: Option<u32>,
        executor: Arc<E>,
        caveat_binding: Option<crate::context::outlets::invoke::InvocationCaveatBinding>,
        signers: SagaSigners,
        params: crate::context::outlets::dispatch::OpenStreamParams,
    ) -> Result<StreamingSagaHandle, SagaError>
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized + 'static,
    {
        // Boxed: the saga's state machine is above the `large_futures`
        // bound, so every caller would otherwise carry it inline.
        Box::pin(async move {
            use crate::context::actor::commands::{
                PrepareBOutcome, PrepareBStreamingFields, SagaPhaseMessage,
            };

            // Taken before any reserve, so a saga refused by shutdown has staged
            // and debited nothing. The pump and the seal task spawn through it onto
            // the tracker, so the drain waits for both (ADR-049 Decision 16).
            let spawner = self
                .tracked_spawner("start cross-context streaming saga")
                .map_err(|refused| SagaError::SupervisorShutDown {
                    // The variant's `Display` carries the code, so the message
                    // keeps only the detail, not `ContextError`'s coded `Display`.
                    message: match refused {
                        ContextError::SupervisorShutDown(detail) => detail,
                        other => other.to_string(),
                    },
                })?;

            let caller_hex = hex::encode(caller_context_id);
            let target_hex = hex::encode(target_context_id);

            // Authorize-before-reserve gate 1 (caller axis): the initiator MUST be a
            // member of the caller context it names (parity with the unary saga
            // gate; code `SCP-SAGA-13050`).
            if !self.is_member(&caller_hex, caller_did.as_ref()).await {
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13050,
                    message: format!(
                        "cross-context streaming saga initiator '{caller_did}' is not a member of \
                         caller context '{caller_hex}' — not authorized to initiate over it"
                    ),
                });
            }

            // Authorize-before-reserve gate 2 (target axis): the caller context MUST
            // hold a bidirectionally-approved interface to the target for this outlet
            // (code `SCP-SAGA-13062`). Reject WITHOUT reserving so a caller cannot
            // wedge a victim target's saga slot before any target-side check ran.
            if !self
                .has_established_outlet_interface(&caller_hex, &target_hex, &outlet_registration_id)
                .await
            {
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13062,
                    message: format!(
                        "cross-context streaming saga from caller context '{caller_hex}' to target \
                         context '{target_hex}' has no established interface for outlet \
                         '{outlet_registration_id}' — not authorized to invoke"
                    ),
                });
            }

            // Resolve the RECEIVING context A's shared event-log provider up front
            // (SCP-OUT-046 #135) — fail-closed WITHOUT reserving if it is missing,
            // since the atomic dual-log's A-side leaf cannot be recorded without it
            // (mirrors the best-effort bridge's early check).
            let Some(a_event_log) = self.event_log_ref().cloned() else {
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    message: "streaming saga: receiving-context event-log provider not configured"
                        .to_owned(),
                });
            };

            // Resolve the channel-authenticated caller's ROLE in the caller context
            // (spec §6.2.4) — authoritative only in the context gate 1 just proved,
            // carried to Prepare-B so B enforces `allowed_source_roles` against the
            // real role, never an envelope-asserted one.
            let caller_source_role = self
                .member_role(&caller_hex, caller_did.as_ref())
                .await
                .map(|assignment| assignment.role_name);

            // Per-participant-context-set reservation (ADR-049 §3a) over the SAME
            // `{caller, target}` set as the unary saga. Released at the
            // Commit-transition below (AC2) while the seal pumps off-mailbox.
            let context_set = vec![caller_hex.clone(), target_hex.clone()];
            let reservation =
                self.try_reserve_context_set(&context_set)
                    .map_err(|r| SagaError::Busy {
                        message: format!(
                            "participant context set overlaps an in-flight saga at context {}",
                            r.contended_context
                        ),
                        contended_context: r.contended_context,
                    })?;

            // Mint the durable saga id (the operator-repair handle a crash-recovery
            // resolution keys on; the id the seal seals under).
            let saga_id = SagaId::new();
            let participants = vec![caller_hex.clone(), target_hex.clone()];

            // Journal `Initiated`. A journal-write failure before any staging is a
            // clean abort (drop the reservation; nothing else was staged).
            if let Err(err) = self
                .append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
                .await
            {
                drop(reservation);
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    message: format!("streaming saga Initiated journal append failed: {err}"),
                });
            }

            // Phase-1 (SAGA MODE) — reserve the invoker's stream escrow IN the
            // operating context B + source B's authoritative caps/timing. The escrow
            // debit is guarded by `phase1.escrow_ticket`: every abort path below
            // passes it to `release_stream_escrow`, which reverses the hold. `caveat_binding` is borrowed so the
            // returned §7.3.8 check outlives `open_stream_session`.
            let phase1 = match self
                .open_outlet_stream_phase1(
                    &spawner,
                    &target_hex,
                    &caller_did,
                    caveat_binding.as_ref(),
                    params,
                )
                .await
            {
                Ok(p) => p,
                Err(rejection) => {
                    drop(reservation);
                    let _ = self
                        .saga_journal
                        .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, false)
                        .await;
                    return Err(stream_open_rejection_to_saga_error(
                        &rejection,
                        StreamingSagaOpenStep::EscrowReserve,
                    ));
                }
            };

            // Pin the §5.4.5 verification descriptor + validation schemas from the
            // governed registration / open — NEVER from delivery-time chunk input.
            // (Sourced from `phase1.params`, whose `operator_signer` / `identity` /
            // `request_id` are unchanged by Phase-1.)
            let Some(registration) = registry.get(outlet_id) else {
                self.release_stream_escrow(
                    &spawner,
                    phase1.escrow_ticket,
                    &target_hex,
                    &caller_did,
                )
                .await;
                drop(reservation);
                let _ = self
                    .saga_journal
                    .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, false)
                    .await;
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    message: format!(
                        "streaming saga: outlet '{outlet_id}' not found in the target registry"
                    ),
                });
            };
            let descriptor = crate::context::outlets::invoke::CrossContextVerificationDescriptor {
                operator_pk: *phase1.params.operator_signer.verifying_key(),
                operating_context_id: target_hex.clone(),
                outlet_id: outlet_id.clone(),
                caveats_binding: phase1.params.identity.caveats_binding,
                expected_request_id: phase1.params.request_id,
            };
            let output_schema = registration.schema.output_schema.clone();
            let aggregate_schema = registration.schema.aggregate_schema.clone();

            // Prepare-B (streaming): re-run the §6.2.4 validation gate ON the target
            // actor + stage the durable `SagaId`-keyed prepared slot (empty frontier +
            // the pinned escrow ledger `reserved` / `cost_per_chunk`). `reserved` is
            // the ACTUAL debited hold from Phase-1 (decision 2), so the seal settles
            // `reserved − billed` from the same durable ledger.
            let Some(target_actor) = self.lookup(&target_hex) else {
                self.release_stream_escrow(
                    &spawner,
                    phase1.escrow_ticket,
                    &target_hex,
                    &caller_did,
                )
                .await;
                drop(reservation);
                let _ = self
                    .saga_journal
                    .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, false)
                    .await;
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13053,
                    message: format!(
                        "streaming saga Prepare-B — target context '{target_hex}' is not a \
                         co-resident actor (cross-node child-bridge transport is future work)"
                    ),
                });
            };
            let prepare_fields = PrepareBStreamingFields {
                caller_context_id,
                target_context_id,
                caller_did: caller_did.clone(),
                outlet_registration_id: outlet_registration_id.clone(),
                ucan_proof_id: ucan_proof_id.clone(),
                input: input.clone(),
                asserted_chain_depth,
                asserted_nonce,
                asserted_timestamp_ms,
                caller_source_role: caller_source_role.clone(),
                reserved: phase1.reservation.reserved_escrow,
                cost_per_chunk: phase1.params.cost_per_chunk,
                request_id: phase1.params.request_id,
                // Raw policy (the `EconomicPolicySnapshot` wrapper is not
                // `Serialize`) — staged durably so the seal captures the billed
                // receipt even if B is torn down mid-stream (SCP-OUT-046).
                economic_policy: phase1
                    .params
                    .economic_policy_snapshot
                    .as_ref()
                    .map(|snap| snap.policy.clone()),
            };
            let prepare_saga_id = saga_id.clone();
            let prepare_outcome = target_actor
                .send(move |reply| {
                    crate::context::actor::ContextCommand::SagaPhase(
                        SagaPhaseMessage::PrepareBStreaming {
                            saga_id: prepare_saga_id,
                            fields: Box::new(prepare_fields),
                            reply,
                        },
                    )
                })
                .await;
            match prepare_outcome {
                Ok(PrepareBOutcome::Prepared(_)) => {}
                Ok(PrepareBOutcome::Rejected(reject)) => {
                    // A §6.2.4 policy reject — the slot was NOT staged, so no Abort is
                    // needed; just resolve the journal + reverse the hold.
                    self.release_stream_escrow(
                        &spawner,
                        phase1.escrow_ticket,
                        &target_hex,
                        &caller_did,
                    )
                    .await;
                    drop(reservation);
                    let _ = self
                        .saga_journal
                        .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, false)
                        .await;
                    return Err(SagaError::Aborted {
                        reason: SagaAbortReason::Rejected,
                        code: reject.code.unwrap_or(13067),
                        message: reject.error.to_string(),
                    });
                }
                Err(err) => {
                    self.release_stream_escrow(
                        &spawner,
                        phase1.escrow_ticket,
                        &target_hex,
                        &caller_did,
                    )
                    .await;
                    drop(reservation);
                    let _ = self
                        .saga_journal
                        .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, false)
                        .await;
                    let (reason, code) = match &err {
                        ContextError::ActorBusy(_) => {
                            (SagaAbortReason::ParticipantUnavailable, 13068)
                        }
                        _ => (SagaAbortReason::Rejected, 13067),
                    };
                    return Err(SagaError::Aborted {
                        reason,
                        code,
                        message: format!("streaming saga Prepare-B failed: {err}"),
                    });
                }
            }

            // Journal `PreparingB`, then `Committing` (AC6 — reached BEFORE the
            // receiver is returned). A journal failure after the slot is staged must
            // clear it (Abort) so crash recovery does not seal a never-opened stream.
            if let Err(err) = self
                .append_journal(&saga_id, SagaState::PreparingB, &participants, 1, &[])
                .await
            {
                self.abort_staged_streaming_saga(&saga_id, &target_hex)
                    .await;
                self.release_stream_escrow(
                    &spawner,
                    phase1.escrow_ticket,
                    &target_hex,
                    &caller_did,
                )
                .await;
                drop(reservation);
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    message: format!("streaming saga PreparingB journal append failed: {err}"),
                });
            }
            if let Err(err) = self
                .append_journal(&saga_id, SagaState::Committing, &participants, 2, &[])
                .await
            {
                self.abort_staged_streaming_saga(&saga_id, &target_hex)
                    .await;
                self.release_stream_escrow(
                    &spawner,
                    phase1.escrow_ticket,
                    &target_hex,
                    &caller_did,
                )
                .await;
                drop(reservation);
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    message: format!("streaming saga Committing journal append failed: {err}"),
                });
            }

            // Commit-transition — Phase-2 open of B's pump. SAGA MODE: `None` for
            // BOTH the settlement sink and the durable `OutletInvoked` sink (the seal
            // owns settlement + B's `OutletInvoked`); `None` for the three test-capture
            // sinks (mirrors the best-effort bridge).
            let OutletStreamPhase1 {
                reservation: econ_reservation,
                escrow_ticket,
                params,
                caveat_post_input_check,
                counter_reservation,
                admission,
                origin_admission,
                pump_semaphore,
            } = phase1;
            let open_result = crate::context::outlets::dispatch::open_stream_session(
                &econ_reservation.handle,
                registry,
                &econ_reservation.role_state,
                outlet_id,
                input,
                &caller_did,
                timeout_ms,
                executor,
                None,
                None,
                None,
                None,
                params,
                admission,
                origin_admission,
                pump_semaphore,
                caveat_post_input_check,
                counter_reservation,
                &|task| drop(spawner.spawn(task)),
                self.shutdown_token.clone(),
            )
            .await;
            let mut handle = match open_result {
                Ok(h) => h,
                Err(rejection) => {
                    self.abort_staged_streaming_saga(&saga_id, &target_hex)
                        .await;
                    self.release_stream_escrow(&spawner, escrow_ticket, &target_hex, &caller_did)
                        .await;
                    drop(reservation);
                    return Err(stream_open_rejection_to_saga_error(
                        &rejection.into(),
                        StreamingSagaOpenStep::StreamOpen,
                    ));
                }
            };
            let Some(inner_rx) = handle.receiver() else {
                self.abort_staged_streaming_saga(&saga_id, &target_hex)
                    .await;
                self.release_stream_escrow(&spawner, escrow_ticket, &target_hex, &caller_did)
                    .await;
                drop(reservation);
                return Err(SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    message: "streaming saga: B-side stream handle yielded no receiver".to_owned(),
                });
            };

            // Stage the §7.3.8 cumulative-counter reserve durably (SCP-OUT-046): it
            // is computed inside `open_stream_session`'s final gate, so it is folded
            // into the durable prepared slot NOW (post-open) so the seal — and crash
            // recovery — release the unspent counter at close from durable state. A
            // stage failure is best-effort (the seal then releases nothing —
            // conservative, the counter stays more-consumed, never an under-charge).
            let counter_reserve = handle.counter_reserve().clone();
            if counter_reserve.amount_cumulative_reserved > 0 {
                let stage_saga_id = saga_id.clone();
                let stage_amount = counter_reserve.amount_cumulative_reserved;
                let stage_chunks = counter_reserve.reserved_chunks;
                let stage_ucan = counter_reserve.ucan_cid.clone();
                if let Err(err) = target_actor
                    .send(move |reply| {
                        crate::context::actor::ContextCommand::SagaPhase(
                            SagaPhaseMessage::StreamStageCounterReserve {
                                saga_id: stage_saga_id,
                                amount_cumulative_reserved: stage_amount,
                                reserved_chunks: stage_chunks,
                                ucan_cid: stage_ucan,
                                reply,
                            },
                        )
                    })
                    .await
                {
                    tracing::warn!(
                        saga_id = %saga_id.0,
                        %err,
                        "streaming saga: durable counter-reserve stage failed — the seal will \
                         release no cumulative counter (conservative; never an under-charge)"
                    );
                }
            }

            // AC2 — release the per-participant-context-set concurrency slot at the
            // Commit-transition (the seal pumps off-mailbox). The escrow stays
            // RESERVED (AC3): it settles from the durable ledger at seal-close.
            drop(reservation);

            // Bounded (=1) outer channel so forward-N precedes request-N+1: the seal
            // task cannot pull chunk N+1 until chunk N is accepted by A's invoker.
            let (outer_tx, outer_rx) = tokio::sync::mpsc::channel(1);

            // Spawn the OFF-MAILBOX seal task (moves the escrow guard + B's inner
            // receiver + the pinned descriptor/schemas). It forwards each chunk,
            // durably folds it into B's frontier (StreamCaptureAppend), and seals at
            // close (CommitBStreamSettle).
            // The task spawns on the tracker so shutdown waits for its seal
            // (ADR-049 Decision 16).
            drop(spawner.spawn(
                crate::context::outlets::invoke::run_streaming_saga_seal_task(
                    Arc::downgrade(self),
                    target_hex.clone(),
                    saga_id.clone(),
                    signers.target,
                    inner_rx,
                    outer_tx,
                    escrow_ticket,
                    descriptor,
                    output_schema,
                    aggregate_schema,
                    a_event_log,
                ),
            ));

            // AC1 — return the receiver PROMPTLY (the journal is `Committing`; the
            // seal reaches `Committed` at stream-close, off the mailbox).
            Ok(StreamingSagaHandle {
                saga_id,
                receiver: outer_rx,
            })
        })
        .await
    }

    /// Roll back a streaming saga whose durable Prepare-B slot was staged but
    /// whose Commit-transition then aborted (SCP-OUT-046 #134): clear B's staged
    /// `saga_pending` slot via [`SagaPhaseMessage::Abort`](crate::context::actor::commands::SagaPhaseMessage::Abort) (target side ⇒
    /// `reservation: None`) and resolve the journal to `Aborted`. Best-effort —
    /// a missing actor / failed write leaves the slot for the crash-recovery
    /// sweep, which clears an unresolved `Committing`/`PreparingB` saga with no
    /// committed witness.
    async fn abort_staged_streaming_saga(&self, saga_id: &SagaId, target_hex: &str) {
        use crate::context::actor::commands::SagaPhaseMessage;
        if let Some(actor) = self.lookup(target_hex) {
            let abort_saga_id = saga_id.clone();
            let _ = actor
                .send(move |reply| {
                    crate::context::actor::ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
                        saga_id: abort_saga_id,
                        reservation: None,
                        reply,
                    })
                })
                .await;
        }
        let _ = self
            .saga_journal
            .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, false)
            .await;
    }

    /// Key-bearing streaming-saga crash-recovery truncated close (SCP-OUT-046
    /// #136 AC7). The REAL seal path for a saga that crashed with only a durable
    /// prefix (witness absent): given the target's Active Signing Key (supplied
    /// per-call — the runtime holds none autonomously). This seal driver lives
    /// here; the FFI-reconnect surface that AUTHENTICATES the caller and supplies
    /// the key is the FFI saga surface, whose deferral is authorized by ADR-049
    /// §3a (the general FFI-surface deferral authority; the concrete key-bearing
    /// reconnect driver + `caller_did` channel-auth binding are enumerated as ACs
    /// of SCP-OUT-047). The unit test supplies the key directly. It seals the
    /// RESTORED durable prefix and resolves the saga `Committed`.
    ///
    /// The target (B) actor rehydrated the `SagaId`-keyed frontier from its
    /// Class-S snapshot at respawn
    /// ([`CrossContextStreamingOutletInvocationSnapshot::into_prepared`](crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot::into_prepared)),
    /// so `frontier.root()` / `billed_count()` reproduce bit-identically over the
    /// durable prefix. This method dispatches [`SagaPhaseMessage::CommitBStreamSettle`](crate::context::actor::commands::SagaPhaseMessage::CommitBStreamSettle)
    /// (seal over the restored prefix, settle at the prefix `billed_count`), then
    /// APPLIES the settlement off-mailbox (recovery holds `Arc<Supervisor>`, so no
    /// re-entrant self-dispatch) against B's CURRENT generation, records the A-side
    /// `CrossContextOutletInvoked` dual-log leaf, and resolves the journal
    /// `Committed`.
    ///
    /// NEVER calls `open_outlet_stream` / never re-invokes the executor (re-invoking
    /// a non-deterministic LLM would break §6.2.4 replay determinism). A replayed
    /// close short-circuits on the `xctx_committed_stream_outputs` witness (the
    /// handler re-emits the stored capture with `settlement: None`, so the money
    /// never moves twice).
    ///
    /// # Errors
    ///
    /// [`SagaError::NeedsRepair`] carrying `saga_id` if the target is not resident
    /// or the seal dispatch fails (the saga stays unresolved for a later retry).
    pub async fn recover_streaming_saga_truncated_close(
        self: &Arc<Self>,
        saga_id: SagaId,
        target_context_id: [u8; 32],
        target_signer: crate::context::actor::signer::CommandSigner,
    ) -> Result<(), SagaError> {
        use crate::context::actor::commands::SagaPhaseMessage;
        use scp_protocol::context::outlets::stream::StreamTerminalStatus;

        let target_hex = hex::encode(target_context_id);
        let Some(actor) = self.lookup(&target_hex) else {
            return Err(SagaError::NeedsRepair {
                saga_id,
                message: format!(
                    "streaming saga truncated-close recovery — target context '{target_hex}' is \
                     not a resident actor"
                ),
            });
        };

        // Seal the RESTORED durable prefix. The truncated close carries an `Error`
        // terminal (the stream crashed without a clean `End`); the receipt attests
        // the manifest root of the durable prefix regardless of terminal status.
        let seal_saga_id = saga_id.clone();
        let outcome = match actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBStreamSettle {
                    saga_id: seal_saga_id,
                    terminal_status: StreamTerminalStatus::Error(
                        "SCP-OUT-046: streaming saga sealed over the durable prefix at crash \
                         recovery (truncated close)"
                            .to_owned(),
                    ),
                    cancel_ack_seq: None,
                    target_signer,
                    reply,
                })
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                return Err(SagaError::NeedsRepair {
                    saga_id,
                    message: format!(
                        "streaming saga truncated-close recovery — CommitBStreamSettle failed: \
                         {err}"
                    ),
                });
            }
        };

        // Record the A-side `CrossContextOutletInvoked` leaf FIRST (borrows the
        // whole `outcome` before the settlement move), using the SAME helper the
        // seal task uses. Best-effort (the durable witness is authoritative).
        if let Some(a_event_log) = self.event_log_ref().cloned() {
            crate::context::outlets::invoke::record_streaming_saga_a_event(
                &a_event_log,
                &saga_id,
                &outcome,
            )
            .await;
        }

        // Apply the settlement off-mailbox against B's CURRENT generation (the
        // reserve-time generation was lost in the crash; B respawned with the hold
        // restored). `None` on a replay — the money already moved (witness settled)
        // so recovery never double-settles. `witness_saga_id: Some` ⇒ the on-actor
        // settle flips `settled` atomically with the money move.
        if let Some(settlement) = outcome.settlement
            && let Err(err) = self
                .settle_outlet_stream_via_actor(
                    *settlement,
                    outcome.generation,
                    Some(saga_id.clone()),
                )
                .await
        {
            tracing::error!(
                saga_id = %saga_id.0,
                %err,
                "streaming saga truncated-close recovery — settlement apply failed; the \
                 durable reserve is reconciled by the restore-time sweep"
            );
        }

        let _ = self
            .saga_journal
            .mark_resolved(saga_id.clone(), SagaTerminalState::Committed, false)
            .await;
        tracing::info!(
            saga_id = %saga_id.0,
            billed_count = outcome.billed_count,
            manifest_root = %hex::encode(outcome.stream_manifest_hash),
            "streaming saga recovery — key-bearing truncated close sealed the durable prefix \
             (no re-invoke); resolved Committed"
        );
        Ok(())
    }

    /// Lift the private [`RunSagaError`] (the FSM's internal [`ContextError`] +
    /// the `needs_repair` flag) into the typed terminal [`SagaError`] the
    /// cross-context entry point returns (ADR-049 §3a):
    ///
    /// - `needs_repair` ⇒ [`SagaError::NeedsRepair`] carrying the minted
    ///   `saga_id` (the operator-repair handle).
    /// - otherwise an abort: [`SagaError::Aborted`]. A
    ///   [`ContextError::RateLimited`] becomes
    ///   [`SagaAbortReason::RateLimited`], propagating `retry_after_ms`
    ///   STRUCTURALLY off the variant as an `Option`: `Some(ms)` is the
    ///   §6.2.0.2 sliding-window's computed back-off; `None` means the limiter
    ///   has no precise back-off instant (the token-bucket hard limit — which
    ///   the Prepare-A `reserve_outlet_economy` path DOES reach as a saga abort)
    ///   and the caller should apply its own conservative back-off. The `None`
    ///   is propagated, never coerced to `0` (a `0` would read as "retry
    ///   immediately" and re-trip the same hard limit). A Prepare-phase
    ///   [`ContextError::ActorBusy`] becomes the unit
    ///   [`SagaAbortReason::ParticipantUnavailable`] + the dedicated retryable
    ///   code `13068` (the transient / neither-side-committed /
    ///   commit-phase-unreachable rationale lives on that variant's rustdoc, the
    ///   single authoritative home). Every other `ContextError` is a
    ///   [`SagaAbortReason::Rejected`].
    ///
    /// The reason/code resolution is a STRUCTURAL variant match — never a
    /// message-string parse. `code` is the numeric `SCP-SAGA-13xxx` discriminant
    /// carried off the reject path (the [`SagaReject`] the Prepare-axis sites
    /// build via the `saga_reject!` macro, threaded through
    /// [`RunSagaError::saga_code`]), falling back to the generic saga-abort code
    /// `13067` — NOT a specific reject code — when the terminal carries none
    /// (codeless aborts such as a Prepare-phase timeout, a token-bucket ECON rate
    /// limit, or journal I/O, whose message string carries the specific cause).
    fn lift_run_saga_error(saga_id: SagaId, run_err: RunSagaError) -> SagaError {
        let RunSagaError {
            error,
            needs_repair,
            saga_code,
        } = run_err;
        let message = error.to_string();
        if needs_repair {
            return SagaError::NeedsRepair { saga_id, message };
        }
        // Ordering note: `ActorBusy` resolves to `ParticipantUnavailable` /
        // code `13068` BEFORE the generic `unwrap_or(13067)` fallback below.
        // Rationale lives on `SagaAbortReason::ParticipantUnavailable`'s rustdoc.
        let fallback_code = saga_code.unwrap_or(13067);
        let (reason, code) = match &error {
            ContextError::ActorBusy(_) => (SagaAbortReason::ParticipantUnavailable, 13068),
            ContextError::RateLimited { retry_after_ms, .. } => (
                SagaAbortReason::RateLimited {
                    retry_after_ms: *retry_after_ms,
                },
                fallback_code,
            ),
            _ => (SagaAbortReason::Rejected, fallback_code),
        };
        SagaError::Aborted {
            reason,
            code,
            message,
        }
    }

    /// Drain the residual held Prepare-A reservation at a saga terminal
    /// (spec §6.2.4 "`NeedsRepair` reservation semantics"). Extracted verbatim
    /// from the [`Self::run_saga`] tail so the caller-side escrow-drain branch
    /// is exercisable in isolation with a NON-EMPTY escrow (the live Prepare-A
    /// stages an escrow-`None` ticket, which makes hold and void observationally
    /// identical).
    ///
    /// * `reached_needs_repair == true` — HOLD the escrow reserved for operator
    ///   repair. The [`OutletEconomyReservation`](crate::context::shared::outlets::OutletEconomyReservation)'s `#[must_use]` drop guard would
    ///   normally fire on an unbalanced drop, so
    ///   [`hold_external_for_repair`](crate::context::shared::outlets::OutletEconomyTicket::hold_external_for_repair)
    ///   marks the carrier consumed WITHOUT voiding the external escrow (the
    ///   operation may have partially committed — B executed and charged — so
    ///   auto-voiding here would be a free-execution exploit).
    /// * otherwise — the held Prepare-A reservation survived to a terminal
    ///   without a Commit-A settle, so void the external escrow and consume the
    ///   ticket (NEVER drop it unbalanced).
    async fn drain_terminal_reservation(
        &self,
        saga_id: &SagaId,
        reached_needs_repair: bool,
        prepared_a: &mut Option<crate::context::actor::commands::PreparedAFields>,
    ) {
        if reached_needs_repair {
            // Leave the reservation HELD for operator repair. The
            // `OutletEconomyReservation`'s `#[must_use]` drop guard would
            // normally fire on an unbalanced drop, so settle it as a
            // divergence-held escrow that defers to operator repair rather
            // than releasing or consuming it.
            if let Some(reservation) = prepared_a.take() {
                reservation.reservation.ticket.hold_external_for_repair();
                tracing::error!(
                    saga_id = %saga_id.0,
                    "cross-context saga NeedsRepair — Prepare-A escrow held for operator \
                     repair (NOT auto-voided; settled by the divergence marker + operator)"
                );
            }
        } else if let Some(reservation) = prepared_a.take() {
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

    /// Shared start-saga driver: run the FSM under an ALREADY-acquired
    /// participant-context-set reservation (ADR-049 §3a — the per-set gating
    /// reservation is acquired by each public entry point via
    /// [`Self::try_reserve_context_set`] so the gating is on the start path, not
    /// in this helper). `_reservation` is the RAII guard, held for the FSM scope
    /// and released on EVERY terminal (Committed / Aborted / NeedsRepair) AND on
    /// a panic-unwind through `run_saga_fsm`, so a stuck saga never wedges
    /// unrelated, disjoint sagas. `xctx` carries the cross-context executor +
    /// phase-data when the saga is a wired `CrossContextOutletInvocation`; it is
    /// `None` for the executor-less test inputs (the `TestForceNeedsRepair`
    /// variant, or a `CrossContextOutletInvocation` driven through the generic
    /// `start_saga` without an executor).
    async fn run_saga(
        &self,
        saga_id: SagaId,
        input: SagaInput,
        xctx: Option<CrossContextSagaCtx<'_>>,
        _reservation: SagaSetReservation<'_>,
    ) -> Result<SagaOutput, RunSagaError> {
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
            self.drain_terminal_reservation(
                &saga_id,
                ctx.reached_needs_repair,
                &mut ctx.prepared_a,
            )
            .await;
        }

        // Whether the FSM drove the saga to `NeedsRepair` (commit-retry
        // exhaustion) — read BEFORE `xctx` is consumed below. The public
        // boundary lift ([`Self::start_cross_context_outlet_invocation_saga`])
        // reads this to distinguish a `NeedsRepair` terminal (carrying the
        // `saga_id`) from a plain `Aborted` on the FSM error path. `false` for
        // the generic / test inputs that carry no `xctx`.
        let needs_repair = xctx.as_ref().is_some_and(|c| c.reached_needs_repair);

        match fsm_result {
            Ok(()) => {
                // Surface the committed receipt/output (cross-context arm only).
                let (receipt, output) = xctx
                    .and_then(|c| c.committed)
                    .map_or((None, None), |a| (Some(a.receipt), Some(a.output)));
                Ok(SagaOutput {
                    saga_id,
                    receipt,
                    output,
                })
            }
            // Carry the FSM's reject (its `ContextError` + the structural
            // `SCP-SAGA-13xxx` `code` off the [`SagaReject`] path) plus the
            // `needs_repair` flag up to the boundary. `start_saga` (generic)
            // discards both extras and propagates the `ContextError`; the
            // cross-context entry point lifts all three into the typed
            // [`SagaError`] (reading the code structurally, no message parse).
            Err(rej) => Err(RunSagaError {
                error: rej.error,
                needs_repair,
                saga_code: rej.code,
            }),
        }
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
    /// Returns a [`SagaReserveReject`] if the set overlaps an in-flight saga.
    /// The reject carries BOTH the structured `contended_context` (the
    /// overlapping participant id the cross-context entry point reads
    /// STRUCTURALLY to build [`SagaError::Busy`]) AND the pre-built generic
    /// `actor_busy` ([`ContextError::ActorBusy`] with a `SagaBusy` reason) the
    /// non-cross-context / test paths surface. Neither caller parses the id out
    /// of a message — both read it structurally.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "The lock guard intentionally spans the overlap check AND the \
                  insert loop — that atomic check-and-reserve IS the correctness \
                  property (shortening it reintroduces a TOCTOU). ADR-049 §3a."
    )]
    fn try_reserve_context_set(
        &self,
        context_set: &[String],
    ) -> Result<SagaSetReservation<'_>, SagaReserveReject> {
        let mut reserved = self
            .reserved_saga_contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Overlap check: a non-empty intersection with the in-flight set
        // means a shared participant context — serialize (spec §5.15.4:
        // "sharing a single context is sufficient to conflict").
        if let Some(contended) = context_set.iter().find(|id| reserved.contains(*id)) {
            let contended_context = contended.clone();
            // SagaBusy: the generic / test paths surface this as the typed
            // ContextError::ActorBusy; the cross-context entry reads
            // `contended_context` to build SagaError::Busy. Both read the id
            // STRUCTURALLY, never parsing it out of a message.
            let actor_busy = ContextError::ActorBusy(format!(
                "Supervisor::start_saga — participant context set overlaps an in-flight \
                 saga at context {contended_context} (SagaBusy)"
            ));
            return Err(SagaReserveReject {
                contended_context,
                actor_busy,
            });
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
    /// "in flight" without racing the (instantaneous, executor-less test) FSM. This
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
        self.try_reserve_context_set(&set).map_err(|r| r.actor_busy)
    }

    /// Test-only: the CANONICAL standing-context digest over
    /// `(local_did, peer_did)` — the raw-digest hex
    /// (`hex::encode(derive_standing_context_digest(..))`), NOT the
    /// `"standing-"`-prefixed actor-registry id. Lets a gating overlap test
    /// feed an arbitrary deterministic `[u8; 32]` context key into a
    /// `CrossContextOutletInvocation` saga's context field, proving overlap
    /// detection is pure set-membership (ADR-049 §3a, spec §5.15.4 / §5.15.8).
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn test_standing_pair_context_digest(local_did: &DID, peer_did: &DID) -> [u8; 32] {
        crate::context::shared::standing::derive_standing_context_digest(local_did, peer_did)
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
    /// On the production bootstrap this method is the SECOND leg of
    /// [`Self::restore_on_startup`] — it runs AFTER `restore_all_contexts`, in
    /// the §17.16.4 restore-then-replay order, so each recovery arm drives a
    /// now-resident participant. It is safe to call multiple times; each call
    /// loads the current unresolved set from the journal.
    ///
    /// **Ordering encoded in the type system (§17.16.4).** The `restored:
    /// &RestoredContexts` parameter is a WITNESS that `Self::restore_all_contexts`
    /// already ran: a [`RestoredContexts`] can only be minted by that restore, so
    /// a caller cannot replay BEFORE restoring — there would be no token to pass.
    /// This is the PRIMARY enforcement of the restore-then-replay order (the
    /// structural source-text gate `restore_on_startup_runs_restore_before_replay`
    /// is defense-in-depth). The recovery sweep consults the witness's restored
    /// set for an observability span field; the per-entry caller-residency /
    /// deletion decisions read durable persistence directly
    /// (`Self::caller_context_deleted_from_persistence`).
    ///
    /// **Visibility (`pub`, intentional).** Kept `pub` — not `pub(crate)` —
    /// because the saga FSM + crash-recovery integration suites
    /// (`crates/scp-runtime/tests/`, separate crates) drive replay in isolation
    /// to test each per-state recovery arm. They obtain the required witness via
    /// the `saga-witness-test-mint`-gated `RestoredContexts::for_test` (their
    /// `Supervisor::new` harness wires no helper persistence, so the real
    /// `restore_all_contexts` returns `PersistenceFailed` rather than an empty
    /// token). The production FFI bridges never
    /// call this directly; they route through [`Self::restore_on_startup`], and
    /// the `bridge_resume_path_routes_through_restore_on_startup` structural
    /// gate enforces that no bridge bypasses the combined entry point.
    ///
    /// # Compile-time ordering + forge-closure proofs
    ///
    /// Replay cannot be invoked without a `RestoredContexts` witness, so a
    /// "replay first, restore second" bootstrap does not compile (this only
    /// proves the witness is REQUIRED — the forge-closing doctests below prove
    /// the witness cannot be MANUFACTURED without a real restore):
    ///
    /// ```compile_fail
    /// # use scp_runtime_core::context::supervisor::Supervisor;
    /// # async fn demo(sup: &std::sync::Arc<Supervisor>) {
    /// // ERROR: `replay_unresolved_sagas` requires a `&RestoredContexts`, and the
    /// // only way to get one is to call `restore_all_contexts` FIRST. Calling
    /// // replay with no witness (replay-before-restore) fails to compile.
    /// sup.replay_unresolved_sagas().await.unwrap();
    /// # }
    /// ```
    ///
    /// The witness cannot be forged via `Default` — there is no `Default` impl,
    /// so `RestoredContexts::default()` is not a public zero-arg constructor (a
    /// `Default` would let any crate mint an empty witness and bypass restore):
    ///
    /// ```compile_fail
    /// # use scp_runtime_core::context::supervisor::{RestoredContexts, Supervisor};
    /// # async fn demo(sup: &Supervisor) {
    /// // ERROR[E0599]: no function or associated item named `default` found —
    /// // `RestoredContexts` derives no `Default`, so it cannot be forged this way.
    /// let forged = RestoredContexts::default();
    /// sup.replay_unresolved_sagas(&forged).await.unwrap();
    /// # }
    /// ```
    ///
    /// The witness cannot be forged via a struct literal — the `ids` field is
    /// private, so no external crate can name it:
    ///
    /// ```compile_fail
    /// # use scp_runtime_core::context::supervisor::{RestoredContexts, Supervisor};
    /// # async fn demo(sup: &Supervisor) {
    /// // ERROR[E0451]: field `ids` of `RestoredContexts` is private — an external
    /// // crate cannot construct the witness by naming its private payload.
    /// let forged = RestoredContexts { ids: Vec::new() };
    /// sup.replay_unresolved_sagas(&forged).await.unwrap();
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns the journal's error class (via `ContextError::InvalidState`)
    /// only if the journal cannot be enumerated (a backend `list_keys`
    /// failure). Per-entry faults do NOT abort the sweep: a corrupt or
    /// torn-write entry is skipped-and-flagged inside `load_unresolved` (it
    /// emits the `scp_saga_repair_needed_total` metric and a `tracing::error!`
    /// for operator repair, then continues), and a per-entry RECOVERY-arm error
    /// is logged via `tracing` here. Either way the remaining sagas are still
    /// reconciled — one poisoned entry never blinds recovery to the rest.
    pub async fn replay_unresolved_sagas(
        &self,
        restored: &RestoredContexts,
    ) -> Result<(), ContextError> {
        let entries = self.saga_journal.load_unresolved().await.map_err(|e| {
            ContextError::InvalidState(format!("saga journal load_unresolved failed: {e}"))
        })?;

        // Consult the restore witness: an unresolved entry is reconciled in the
        // SAME pass that restored its participants (§17.16.4 restore-then-replay).
        tracing::debug!(
            restored_contexts = restored.ids().len(),
            unresolved_sagas = entries.len(),
            "saga recovery replay — reconciling unresolved sagas after context restore"
        );

        for entry in entries {
            self.recover_saga_entry(entry).await;
        }
        Ok(())
    }

    async fn recover_saga_entry(&self, entry: JournalEntry) {
        match entry.state {
            SagaState::Initiated => {
                // Truly no remote side-effects: Prepare-A was never
                // dispatched. The FSM journals `Initiated` (seq 0) BEFORE the
                // first `dispatch_prepare_phase`, so an `Initiated` crash leaves
                // the durable economy untouched — discard by marking Aborted.
                // `secret_bearing` classifies the resolution marker for
                // secure-evidence overwrite.
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
                    "saga recovery — discarded (Initiated: Prepare-A never dispatched, no \
                     remote side-effects)"
                );
            }
            SagaState::PreparingA => {
                // Prepare-A DURABLY persisted the caller deduction + the
                // `CallerReservationRecord` (actor `prepare_a`) into the
                // per-context Class-S snapshot BEFORE the FSM appended the
                // `PreparingB` journal entry, so a crash in that window can
                // leave a LIVE durable reservation while the journal's latest
                // state is `PreparingA`. Marking terminal-`Aborted` here (which
                // asserts "fully compensated") would STRAND that deduction +
                // record forever (the §17.16.4 sweep re-drives only NON-terminal
                // journals → a permanent silent over-charge).
                //
                // A `PreparingA` xctx entry journals the SAME caller-provenance
                // triple as `PreparingB` (`saga_input_participants`), so route it
                // through the SAME record-keyed reversal-and-confirm path. With
                // empty `PreparingA` evidence (`&[]`), `reconstruct_xctx_prepared`
                // returns `None` → the path falls to
                // `xctx_caller_hex_from_participants` →
                // `redrive_caller_local_reversal`: it reverses the caller's LOCAL
                // economy from the durable record and marks terminal ONLY on a
                // confirmed `SettledOrAbsent` (or a persistence-deleted caller),
                // else leaves the journal non-terminal for a later sweep. A
                // non-xctx `PreparingA` (no caller participant triple) →
                // `SettledOrAbsent` → safe terminal.
                self.recover_preparing_b_entry(&entry).await;
            }
            SagaState::PreparingB => {
                self.recover_preparing_b_entry(&entry).await;
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
                // §17.16.4 operator-alerting metric: this entry is now
                // NeedsRepair and requires operator repair.
                scp_runtime_types::metrics::record_saga_repair_needed();
                tracing::error!(
                    saga_id = %entry.saga_id,
                    "saga recovery — Aborting observed; marked NeedsRepair for operator review"
                );
            }
            SagaState::NeedsRepair => {
                self.recover_needs_repair_entry(&entry);
            }
            SagaState::Committed | SagaState::Aborted => {
                // Terminal — not returned by load_unresolved but
                // defensively handled here.
            }
        }
    }

    /// §17.16.4 Prepare-in-progress recovery for a `PreparingA` OR `PreparingB`
    /// journal entry.
    ///
    /// Both states share the same record-keyed reversal-and-confirm reconciliation:
    /// `PreparingA` already DURABLY staged the caller deduction + reservation record
    /// (actor `prepare_a`, before the FSM's `PreparingB` journal append), so a crash
    /// at either state can leave a live durable reservation. The `recover_saga_entry`
    /// `PreparingA` arm routes here precisely because a `PreparingA` xctx entry
    /// journals the SAME caller-provenance triple as `PreparingB`; with empty
    /// `PreparingA` evidence the `reconstruct_xctx_prepared` path is skipped and the
    /// participant-keyed `redrive_caller_local_reversal` performs the reversal.
    ///
    /// Actor A (and possibly B) staged reservations but the Commit never left the
    /// coordinator. Abort the Prepared side(s) — releasing the staged
    /// rate/escrow/session reservations — and discard; NEVER re-Prepare. For a
    /// reconstructible cross-context entry this re-drives a real `Abort { None }`
    /// to the prepared actors (release); otherwise there is no caller reservation
    /// to reverse and the journal abort marker IS the rollback record.
    ///
    /// The terminal-`Aborted` marker asserts "fully compensated", so it MUST NOT
    /// be written while the caller's durable LOCAL-economy reversal is still
    /// outstanding — exactly the invariant [`Self::abort_saga`] enforces on the
    /// LIVE abort path. On the normal startup path
    /// ([`Self::restore_on_startup`]) the §17.16.4 restore-THEN-replay ordering
    /// has already made the caller RESIDENT before this runs, so the
    /// record-keyed `Abort { None }` re-drive is delivered in-pass and the
    /// journal reaches terminal-`Aborted` with the refund applied. The
    /// non-terminal-leave below is the genuinely-undeliverable fallback: if the
    /// caller context still is not resident (a `lookup` miss — e.g. it failed to
    /// restore) OR the `Abort { None }` send fails, the record-based reversal was
    /// NOT delivered, so leave the journal NON-terminal at `PreparingB` and carry
    /// it to the NEXT process start (whose restore-then-replay re-drives it).
    /// Marking terminal here would strand the caller's durable deduction forever
    /// (recovery re-drives ONLY non-terminal journals → a permanent over-charge).
    /// The ONE exception is a PERMANENTLY-DELETED caller context (absent from
    /// durable persistence): its reservation record died with the context, so
    /// there is nothing to reverse and the saga is reaped instead of looping
    /// forever — see [`Self::caller_context_deleted_from_persistence`].
    ///
    /// **Known limitation — external escrow hold on a context deleted
    /// mid-`PreparingB`.** When the caller context is reaped as permanently
    /// deleted (above), its caller LOCAL economy died with the snapshot, so there
    /// is nothing to reverse LOCALLY and terminal-`Aborted` is correct for the
    /// local ledger. But if the saga had staged an EXTERNAL escrow hold during
    /// Prepare-A, the `escrow_authorization` needed to RELEASE that external hold
    /// lives ONLY in the deleted context snapshot — it is NOT reconstructible from
    /// the journal evidence (the journal records the abort decision, not the
    /// escrow authorization secret). Such an external hold is therefore
    /// irrecoverable from journal evidence alone once the context is deleted;
    /// terminal-`Aborted` is the best available resolution (the saga cannot loop
    /// forever waiting for a context that will never return), and operator/
    /// external-system reconciliation is the only path to release the stranded
    /// external hold. This is a pre-existing boundary of the journal-evidence
    /// model, called out here so a future change does not silently assume the
    /// terminal marker also released the external escrow.
    async fn recover_preparing_b_entry(&self, entry: &JournalEntry) {
        // `caller_hex_from_participants` is `Some(hex)` iff THIS journal
        // entry names a caller context in `participants[0]` — i.e. it is a
        // real cross-context entry (per `saga_input_participants`, an xctx
        // entry is the triple `[hex(caller_context_id), caller_did,
        // outlet_registration_id]`: length 3 with a 64-hex first element).
        // This identity is carried by the PLAINTEXT participant record,
        // INDEPENDENT of the (separately-serialized) evidence blob, so it
        // survives an evidence that is corrupt / truncated / unparseable.
        let caller_hex_from_participants = Self::xctx_caller_hex_from_participants(entry);

        let caller_reversal = match Self::reconstruct_xctx_prepared(entry) {
            Some(prepared) => {
                self.redrive_xctx_prepare_in_progress(&entry.saga_id, &prepared)
                    .await
            }
            // Evidence did NOT reconstruct. Two sub-cases:
            //
            //   (a) a REAL xctx entry whose evidence blob is corrupt /
            //       truncated / unserializable. Its caller context is still
            //       named in `participants[0]` and its durable
            //       `CallerReservationRecord` may still be live, so a
            //       terminal-`Aborted` here (asserting "fully compensated")
            //       would STRAND the caller deduction. Drive the verdict via
            //       the RECORD-keyed `redrive_caller_local_reversal` (which
            //       reverses the caller's LOCAL economy from the durable
            //       record, independent of the evidence) — the same helper
            //       the reconstructible path's target-clearing redrive uses
            //       for its caller leg.
            //
            //   (b) a genuinely participant-less / non-xctx entry (standing
            //       pair / broadcast / test). There is no cross-context
            //       caller reservation to reverse, so the journal abort
            //       marker is the authoritative (and only needed) rollback
            //       record — safe to mark terminal.
            None => match caller_hex_from_participants.as_deref() {
                Some(caller_hex) => {
                    self.redrive_caller_local_reversal(&entry.saga_id, caller_hex)
                        .await
                }
                None => CallerAbortReversal::SettledOrAbsent,
            },
        };

        if matches!(caller_reversal, CallerAbortReversal::ReversalOutstanding) {
            // The caller reversal could not be confirmed delivered. Before
            // leaving the journal non-terminal (the wave-15 invariant),
            // distinguish a PERMANENTLY-DELETED caller context from a
            // merely not-yet-restored one — durable persistence is the
            // source of truth regardless of restore/spawn state:
            //
            //   - ABSENT from persistence ⇒ the context was deleted; its
            //     `CallerReservationRecord` died with it, so there is
            //     NOTHING left to reverse. Leaving the saga non-terminal
            //     would make it NEVER reap (every sweep re-misses the
            //     lookup). Mark it terminal-`Aborted` (reaped).
            //   - PRESENT in persistence ⇒ not-yet-restored. The reversal
            //     is genuinely still outstanding; leave the journal
            //     non-terminal so a later sweep (after the caller respawns)
            //     re-drives it from the durable record.
            //
            // The existence check is only meaningful for an entry that
            // NAMES a caller context AND only when a persistence backend is
            // configured (`persistence_ref`); absent either, fall through
            // to the conservative wave-15 leave-non-terminal.
            if let Some(caller_hex) = caller_hex_from_participants.as_deref()
                && self
                    .caller_context_deleted_from_persistence(caller_hex)
                    .await
            {
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
                    state = ?entry.state,
                    context = %caller_hex,
                    "saga recovery — Prepare-in-progress (PreparingA/PreparingB) observed but \
                     the caller context is ABSENT from durable persistence (permanently \
                     deleted): its caller reservation record died with the context, so \
                     there is nothing to reverse — reaping the saga as terminal-Aborted \
                     (NOT leaving it to never-reap)"
                );
                return;
            }

            // The producing site inside `redrive_caller_local_reversal`
            // already routed its verdict through `Self::reversal_outstanding()`
            // (incrementing the counter + emitting the stable
            // `event = "xctx_caller_reversal_outstanding"` warn). Re-emit the
            // SAME stable field here so a log query on it surfaces the
            // "left non-terminal" decision too, but do NOT re-increment the
            // counter (that would double-count a single stranded reversal).
            tracing::warn!(
                event = "xctx_caller_reversal_outstanding",
                saga_id = %entry.saga_id,
                state = ?entry.state,
                "saga recovery — Prepare-in-progress (PreparingA/PreparingB) observed but the \
                 caller-side LOCAL-economy reversal could not be delivered (caller not \
                 yet restored / backpressure); leaving the journal NON-terminal so a \
                 later crash-recovery sweep re-drives it (NOT marking terminal-Aborted \
                 with the caller refund outstanding)"
            );
            return;
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
            state = ?entry.state,
            "saga recovery — Prepare-in-progress (PreparingA/PreparingB) observed; aborted \
             the Prepared side(s), confirmed the caller reversal, and discarded (never \
             re-Prepared)"
        );
    }

    /// §17.16.4 `NeedsRepair` carryover recovery: re-surface the operator-repair
    /// alert at process start and rehydrate the supervisor-level divergence
    /// repair records (spec §6.2.4 "Dual event-log recording") so the
    /// unreachable-leg divergence account survives a supervisor restart. A
    /// NON-EMPTY `NeedsRepair` evidence is, by convention, the `MessagePack` of
    /// the full accumulated repair-record set (the plain `NeedsRepair` transition
    /// carries EMPTY evidence); `load_unresolved` returns the LATEST entry per
    /// saga, so this is the most complete set.
    fn recover_needs_repair_entry(&self, entry: &JournalEntry) {
        // §17.16.4 operator-alerting metric: a NeedsRepair saga is
        // re-surfaced at process start until an operator repairs it.
        scp_runtime_types::metrics::record_saga_repair_needed();
        tracing::error!(
            saga_id = %entry.saga_id,
            "saga recovery — NeedsRepair carryover; operator intervention required"
        );
        if !entry.evidence.is_empty() {
            match decode_repair_records_evidence(&entry.evidence) {
                Ok(records) if !records.is_empty() => {
                    self.saga_repair_records
                        .insert(entry.saga_id.clone(), records);
                }
                Ok(_) => {}
                Err(err) => tracing::error!(
                    saga_id = %entry.saga_id,
                    %err,
                    "saga recovery — NeedsRepair entry carried non-empty evidence that \
                     did not decode as a supervisor repair-record set; the durable \
                     divergence account could not be rehydrated"
                ),
            }
        }
    }

    /// §17.16.4 Commit-in-progress recovery for a `Committing` journal entry.
    /// Re-drives the idempotent Commit (NEVER re-invoking the outlet): B re-acks
    /// the existing `OutletInvoked` and re-emits the STORED output; A re-acks from
    /// the durable `xctx_committed_invocations` witness (keyed on the Class-S
    /// witness, NOT the in-memory reservation that died with the crash). If BOTH
    /// sides committed the saga is FULLY committed and resolves to `Committed`;
    /// only a genuinely-unresolvable divergence (one-sided commit / unreachable
    /// side / non-reconstructible entry) stays `NeedsRepair` for operator repair.
    async fn recover_committing_entry(&self, entry: &JournalEntry) {
        // Streaming saga (SCP-OUT-046 #136): keyless witness-based resolution. The
        // runtime holds NO signing key autonomously, so it cannot SEAL a truncated
        // prefix on the startup sweep. Three cases (see
        // `recover_streaming_committing_entry`): witness present & settled ⇒ confirm
        // Committed (money already moved); witness present & UNSETTLED ⇒ complete the
        // money move KEYLESSLY (pure budget/counter ops — refund + §7.3.8 release +
        // capture — flip `settled` atomically) then Committed; witness absent ⇒ hold
        // for the key-bearing recovery surface (NeedsRepair, escrow held).
        if let Some(target_hex) = Self::streaming_saga_target_hex(entry) {
            self.recover_streaming_committing_entry(entry, &target_hex)
                .await;
            return;
        }
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
                // Append a plain (empty-evidence) NeedsRepair terminal. This is
                // the divergence-class terminal for the NeedsRepair paths that do
                // NOT go through `record_supervisor_repair` — target unreachable,
                // `ReadyToExecute` (Commit-B never landed), a Commit-B reserve
                // send failure, or a non-reconstructible entry — where it is the
                // ONLY durable NeedsRepair record, so it MUST NOT be dropped. When
                // the divergence WAS one-sided, `redrive_commit_a_witness` already
                // wrote an evidence-bearing repair entry at a HIGHER seq (>= 5)
                // via `record_supervisor_repair`; `load_unresolved` selects the
                // max-seq entry per saga, so that richer entry supersedes this
                // empty one — the empty append is harmless (never the surviving
                // read), not authoritative. (Latest-per-saga = empty here does
                // NOT mean "no divergence detail": it means no side committed.)
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
                // §17.16.4 operator-alerting metric: commit-in-progress could
                // not confirm both sides; this saga is NeedsRepair.
                scp_runtime_types::metrics::record_saga_repair_needed();
                tracing::error!(
                    saga_id = %entry.saga_id,
                    "saga recovery — Commit-in-progress observed; re-drove the idempotent Commit-B \
                     (no re-invoke) but could not confirm both sides committed — marked \
                     NeedsRepair for operator review"
                );
            }
        }
    }

    /// Discriminant: returns the TARGET context id (raw-digest hex) iff the
    /// journal entry is a STREAMING saga (SCP-OUT-046 #136), else `None`.
    ///
    /// The streaming saga journals a 2-element `[caller_hex, target_hex]`
    /// participant set (both 64-char raw-digest hex) with EMPTY evidence (it
    /// journals public metadata only — no `MessagePack` prepared wire). The unary
    /// saga journals a 3-element `[caller_hex, caller_did, outlet_reg]` with
    /// NON-empty evidence, and `TestForceNeedsRepair` a single-element set — so
    /// "2 raw-digest-hex participants + empty evidence" is a sound structural
    /// discriminant that never collides with the other saga shapes.
    fn streaming_saga_target_hex(entry: &JournalEntry) -> Option<String> {
        const RAW_DIGEST_HEX_LEN: usize = 64;
        if !entry.evidence.is_empty() || entry.participants.len() != 2 {
            return None;
        }
        let is_raw_digest_hex =
            |s: &String| s.len() == RAW_DIGEST_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit());
        if is_raw_digest_hex(&entry.participants[0]) && is_raw_digest_hex(&entry.participants[1]) {
            Some(entry.participants[1].clone())
        } else {
            None
        }
    }

    /// Keyless streaming-saga `Committing` resolution on the startup sweep
    /// (SCP-OUT-046 CRITICAL; #136 AC7). Reads the durable witness via a READ-ONLY
    /// [`SagaPhaseMessage::StreamSettleCheckWitness`](crate::context::actor::commands::SagaPhaseMessage::StreamSettleCheckWitness) to the target (B) actor and
    /// resolves the saga per the witness state:
    ///
    /// - **witness present & `settled`** — B durably sealed AND the money move
    ///   already landed on the first pass. Resolve the journal `Committed`; a
    ///   replayed close re-emits idempotently, moving no money.
    /// - **witness present & NOT `settled`** — B sealed but crashed / was evicted
    ///   in the seal→settle window, so the escrow refund + §7.3.8 counter release
    ///   never ran (the xctx path has NO `stream_reservations` reconcile net).
    ///   Settlement is pure budget/counter ops — it needs NO signing key — so
    ///   recovery COMPLETES it here: reconstruct the A-side dual-log leaf
    ///   (best-effort, #135) and apply the rebuilt `StreamSettlement` via
    ///   [`Self::settle_outlet_stream_via_actor`] against B's CURRENT generation
    ///   (`witness_saga_id: Some` flips `settled` atomically with the money), then
    ///   resolve `Committed`. A deferral (B respawned again between the read and
    ///   the settle) leaves the journal `Committing` for the next sweep — the flag
    ///   makes the money move exactly once.
    /// - **witness absent** — only a durable prefix exists. The runtime holds no
    ///   signing key autonomously, so it CANNOT seal here. Append a `NeedsRepair`
    ///   terminal and HOLD the escrow (never auto-void — B may have rendered
    ///   service). The key-bearing
    ///   [`Self::recover_streaming_saga_truncated_close`] is the seal path
    ///   (the FFI-reconnect surface authenticates the caller + supplies the key;
    ///   the deferral of that FFI surface is authorized by ADR-049 §3a and the
    ///   driver is enumerated as an AC of SCP-OUT-047). An unreachable /
    ///   non-resident target is treated as unsealed (NeedsRepair).
    async fn recover_streaming_committing_entry(&self, entry: &JournalEntry, target_hex: &str) {
        use crate::context::actor::commands::{SagaPhaseMessage, StreamWitnessRecoveryStatus};
        let saga_id = &entry.saga_id;
        // Read the durable witness. A send failure / non-resident target is
        // treated as `Absent` (unsealed) → NeedsRepair.
        let status = if let Some(actor) = self.lookup(target_hex) {
            let check_saga_id = saga_id.clone();
            match actor
                .send(move |reply| {
                    ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                        saga_id: check_saga_id,
                        reply,
                    })
                })
                .await
            {
                Ok(status) => status,
                Err(err) => {
                    tracing::warn!(
                        saga_id = %saga_id,
                        %err,
                        "streaming saga recovery — StreamSettleCheckWitness send failed; \
                         treating as unsealed (NeedsRepair, escrow held)"
                    );
                    StreamWitnessRecoveryStatus::Absent
                }
            }
        } else {
            // Permanent-eviction case: a target that is not resident (evicted and
            // never respawned) cannot have its witness read, so recovery treats it
            // as `Absent` → NeedsRepair with the escrow HELD. The invoker's refund is
            // held (never lost, never double-moved) until the context is restored and
            // a subsequent sweep can read the durable witness and complete the money
            // move keylessly — the conservative fail-closed posture, identical to the
            // witness-absent NeedsRepair arm below.
            tracing::warn!(
                saga_id = %saga_id,
                target = %target_hex,
                "streaming saga recovery — target actor not resident; treating as unsealed \
                 (NeedsRepair, escrow held until the context is restored)"
            );
            StreamWitnessRecoveryStatus::Absent
        };

        match status {
            StreamWitnessRecoveryStatus::Absent => {
                // Witness absent → NeedsRepair, escrow HELD for the key-bearing close.
                let _ = self
                    .saga_journal
                    .append(JournalEntry {
                        saga_id: saga_id.clone(),
                        state: SagaState::NeedsRepair,
                        participants: entry.participants.clone(),
                        evidence: Zeroizing::new(Vec::new()),
                        timestamp_ms: current_timestamp_ms(),
                        seq_per_saga: entry.seq_per_saga.saturating_add(1),
                    })
                    .await;
                scp_runtime_types::metrics::record_saga_repair_needed();
                tracing::error!(
                    saga_id = %saga_id,
                    "streaming saga recovery — seal witness ABSENT; no autonomous signing key to \
                     seal the truncated prefix — NeedsRepair, escrow HELD for the key-bearing close"
                );
            }
            StreamWitnessRecoveryStatus::Settled => {
                // Money already moved on the first settle — resolve Committed.
                let _ = self
                    .saga_journal
                    .mark_resolved(saga_id.clone(), SagaTerminalState::Committed, false)
                    .await;
                tracing::info!(
                    saga_id = %saga_id,
                    "streaming saga recovery — seal witness present + settled; resolved Committed \
                     (idempotent, no re-invoke, no money move)"
                );
            }
            StreamWitnessRecoveryStatus::Unsettled {
                generation,
                settlement,
                a_event,
            } => {
                // Witness present but UNSETTLED — complete the money move keylessly.
                self.complete_unsettled_streaming_saga(saga_id, generation, settlement, a_event)
                    .await;
            }
        }
    }

    /// Complete a witness-present-but-UNSETTLED streaming saga on the keyless
    /// crash-recovery sweep (SCP-OUT-046 CRITICAL): the seal-close landed durably
    /// but the money move (escrow refund + §7.3.8 counter release) never ran (a
    /// crash / eviction in the seal→settle window). Settlement is pure
    /// budget/counter ops — NO signing key — so this reconstructs the best-effort
    /// A-side dual-log leaf (#135; convergent, dedup-able) and applies the rebuilt
    /// settlement against B's CURRENT generation (`witness_saga_id: Some` flips
    /// `settled` atomically with the money), then resolves `Committed`. A deferral
    /// (B respawned again between the witness read and the settle) leaves the
    /// journal `Committing` for the next sweep — the `settled` flag makes the money
    /// move exactly once.
    async fn complete_unsettled_streaming_saga(
        &self,
        saga_id: &SagaId,
        generation: u64,
        settlement: Box<crate::context::outlets::invoke::StreamSettlement>,
        a_event: Option<Box<crate::context::actor::commands::CommitBStreamSettleOutcome>>,
    ) {
        // First reconstruct the A-side dual-log leaf best-effort (#135) — the seal
        // task records it BEFORE the money move, so a crash in that window can
        // leave it absent. On the DEFER-then-recover path (the seal task recorded
        // the A-leaf, then deferred the settle, and recovery now re-records it) this
        // appends a byte-identical A-leaf TWICE. That double-append is BENIGN: the
        // leaves are convergent (same nonce, chain-depth, timestamp, and sealed
        // root), and the §9.9.3 per-sender `(count, root)` equivocation-dedup
        // substrate collapses them — a repeated (count, root) from the same sender
        // is de-duplicated, not treated as equivocation. So recovery may safely
        // re-record without a conditional "did the seal task already append?" check.
        if let (Some(a_event), Some(a_event_log)) =
            (a_event.as_ref(), self.event_log_ref().cloned())
        {
            crate::context::outlets::invoke::record_streaming_saga_a_event(
                &a_event_log,
                saga_id,
                a_event,
            )
            .await;
        }

        // The `Unsettled` variant always carries a rebuilt settlement, so there is
        // no "unsettled but nothing to settle" state to defend against here.
        match self
            .settle_outlet_stream_via_actor(*settlement, generation, Some(saga_id.clone()))
            .await
        {
            Ok(application) if application.applied => {
                let _ = self
                    .saga_journal
                    .mark_resolved(saga_id.clone(), SagaTerminalState::Committed, false)
                    .await;
                tracing::info!(
                    saga_id = %saga_id,
                    "streaming saga recovery — witness present + unsettled; completed the \
                     escrow refund + counter release keylessly and resolved Committed"
                );
            }
            Ok(_) => {
                // Deferred (B respawned again between the witness read and the
                // settle) — leave Committing; the next sweep retries. The `settled`
                // flag guarantees the money still moves exactly once.
                tracing::warn!(
                    saga_id = %saga_id,
                    "streaming saga recovery — settlement deferred (target replaced between \
                     read and settle); left Committing for the next sweep"
                );
            }
            Err(err) => {
                tracing::warn!(
                    saga_id = %saga_id,
                    %err,
                    "streaming saga recovery — settlement apply failed; left Committing for \
                     the next sweep"
                );
            }
        }
    }

    /// Reconstruct a cross-context outlet-invocation saga's prepared state from a
    /// journal entry's `evidence` (spec §6.2.4 "Crash recovery §17.16.4").
    ///
    /// The evidence is the `MessagePack` of the eight-field
    /// [`CrossContextOutletInvocationPrepared`](crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared)
    /// wire — carrying BOTH the `caller_context_id` AND the `target_context_id`
    /// (option (a) — closing the [`saga_input_participants`] caller-only gap) plus
    /// the staged provenance. Decoding it yields the FULL `{caller, target}`
    /// participant set and the prepared provenance the replay re-drive needs.
    /// Returns `None` if the entry is not a cross-context saga (its evidence
    /// does not decode), e.g. a test entry.
    fn reconstruct_xctx_prepared(entry: &JournalEntry) -> Option<XctxPrepared> {
        use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;
        if entry.evidence.is_empty() {
            return None;
        }
        CrossContextOutletInvocationPrepared::from_evidence_bytes(entry.evidence.as_slice()).ok()
    }

    /// Returns the caller context id (raw-digest hex) named in a journal
    /// entry's PLAINTEXT participant record iff the entry is a cross-context
    /// outlet-invocation saga, else `None`.
    ///
    /// Per [`saga_input_participants`], a `CrossContextOutletInvocation` entry's
    /// participants are exactly the triple
    /// `[hex(caller_context_id), caller_did, outlet_registration_id]` — length 3
    /// with a 64-char lowercase-hex first element (the caller's raw-digest
    /// context id, the canonical `lookup` / persistence key).
    /// `CrossContextOutletInvocation` is the only multi-context saga; the sole
    /// other input (`TestForceNeedsRepair`) records a single-element set.
    ///
    /// This is used ONLY on a `PreparingA` or `PreparingB` entry whose evidence
    /// FAILED to reconstruct as the xctx prepared wire (a `PreparingA` entry
    /// ALWAYS has empty evidence, so it always reaches this participant-keyed
    /// discriminant). The length-3 + 64-hex shape is therefore a sound
    /// discriminant for "a cross-context entry whose evidence is corrupt".
    fn xctx_caller_hex_from_participants(entry: &JournalEntry) -> Option<String> {
        const RAW_DIGEST_HEX_LEN: usize = 64;
        if entry.participants.len() != 3 {
            return None;
        }
        let first = &entry.participants[0];
        if first.len() == RAW_DIGEST_HEX_LEN && first.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(first.clone())
        } else {
            None
        }
    }

    /// Returns `true` iff a caller context (`caller_hex`, the raw-digest hex
    /// `lookup` / persistence key) is PERMANENTLY ABSENT from durable
    /// persistence — i.e. it was deleted, not merely not-yet-restored.
    ///
    /// Durable persistence is the source of truth for context existence
    /// regardless of in-memory spawn / restore state: a deleted context has had
    /// its snapshot removed (`load_context` ⇒ `Ok(None)`), while a context that
    /// merely has not been restored into an actor yet is still PRESENT in
    /// storage (`load_context` ⇒ `Ok(Some(_))`). This mirrors the existence
    /// check the actor-respawn path performs before re-hydrating
    /// ([`Self::respawn_from_snapshot`]).
    ///
    /// Conservative on uncertainty — returns `false` (treat as "still present")
    /// when no persistence backend is configured (`persistence_ref` is `None`,
    /// so existence is unknowable) OR when the `load_context` read itself errors
    /// (a transient storage failure must NOT be mistaken for deletion). In both
    /// cases the saga is left non-terminal for a later sweep, never reaped on a
    /// guess — reaping only on a CONFIRMED `Ok(None)` absence.
    ///
    /// **Backend assumption (`Ok(None)` ⇒ PERMANENTLY deleted).** Reaping on
    /// `Ok(None)` is sound ONLY because every durable backend in-tree
    /// distinguishes "absent" from "transiently unreadable": `Ok(None)` is
    /// returned strictly when the snapshot KEY does not exist, and any I/O /
    /// decode failure surfaces as `Err` (caught by the conservative arm above) —
    /// there is no stored-but-transiently-`None` window. A FUTURE lazy on-disk
    /// backend (e.g. one that returns `Ok(None)` for a not-yet-loaded shard, or
    /// during a compaction window, before the key is actually known absent) MUST
    /// preserve that contract — surfacing any uncertainty as `Err`, never
    /// `Ok(None)` — or this reaper could mis-read a recoverable caller as deleted
    /// and reap it, silently over-charging it (the durable
    /// `CallerReservationRecord` would never be reversed). When in doubt, a
    /// backend MUST err toward `Err` (leave non-terminal), never `Ok(None)`.
    async fn caller_context_deleted_from_persistence(&self, caller_hex: &str) -> bool {
        let Some(persistence) = self.persistence_ref() else {
            // No backend ⇒ existence is unknowable; do not reap on a guess.
            return false;
        };
        match persistence.load_context(caller_hex).await {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(err) => {
                tracing::warn!(
                    context = %caller_hex,
                    %err,
                    "saga recovery — durable persistence existence check for a permanently-deleted \
                     caller context errored; treating the context as STILL PRESENT (not reaping the \
                     saga) so a transient storage failure cannot be mistaken for deletion"
                );
                false
            }
        }
    }

    /// §17.16.4 Prepare-in-progress re-drive: abort the Prepared side(s) of a
    /// cross-context saga, releasing the staged reservations, then discard
    /// (NEVER re-Prepare). The carrier `PreparedAFields` died with the crashed
    /// coordinator, so BOTH legs are driven as `Abort { None }` — the actor
    /// reverses its OWN staged state keyed by `SagaId`.
    ///
    /// - CALLER side: drives the record-based `Abort { None }` through
    ///   [`Self::redrive_caller_local_reversal`] — the SAME helper the live
    ///   abort path uses — so the caller reverses its LOCAL economy (budget /
    ///   velocity / hard-rate-limit) from the durable `CallerReservationRecord`
    ///   Prepare-A staged. The returned [`CallerAbortReversal`] reflects whether
    ///   that reversal was CONFIRMED delivered: `SettledOrAbsent` iff the
    ///   `Abort { None }` was delivered-and-acked (or there was genuinely no
    ///   caller reservation to reverse — a clean record no-op);
    ///   `ReversalOutstanding` on a `lookup` miss (caller not yet restored) or a
    ///   send failure (persistent backpressure / closed inbox). This is the SOLE
    ///   input to the coordinator's terminal-marker decision: a terminal-`Aborted`
    ///   journal asserts "fully compensated" and MUST NOT be written while the
    ///   caller refund is still outstanding (symmetric with [`Self::abort_saga`]).
    ///
    /// - TARGET side: released best-effort via [`Self::abort_target_leg`]
    ///   (clears the staged `saga_pending` session slot). The target carries no
    ///   caller LOCAL economy, so its release is orthogonal to the returned
    ///   verdict — a failed/undelivered send strands nothing (the next sweep
    ///   clears the slot).
    ///
    /// Invoked by [`Self::recover_saga_entry`] on a `PreparingB` entry, which is
    /// driven by the startup replay loop
    /// ([`Self::replay_unresolved_sagas`]).
    async fn redrive_xctx_prepare_in_progress(
        &self,
        saga_id: &SagaId,
        prepared: &XctxPrepared,
    ) -> CallerAbortReversal {
        // CALLER side: record-based `Abort { None }` re-drive — reverses the
        // caller's LOCAL economy from the durable record and yields the verdict
        // that gates the terminal marker (warns + counts on miss/failure).
        let caller_hex = hex::encode(prepared.caller_context_id);
        let caller_reversal = self
            .redrive_caller_local_reversal(saga_id, &caller_hex)
            .await;

        // TARGET side: best-effort session-slot release, orthogonal to the
        // caller verdict (the target stages no caller LOCAL economy).
        self.abort_target_leg(saga_id, prepared.target_context_id)
            .await;

        caller_reversal
    }

    /// §17.16.4 Commit-in-progress re-drive: re-send the idempotent Commit-B,
    /// which re-acks the existing `OutletInvoked` and re-emits the STORED output —
    /// NEVER re-invoking the outlet (the exactly-once-execution guarantee survives
    /// a crash). Sends [`SagaPhaseMessage::CommitBReserve`](crate::context::actor::commands::SagaPhaseMessage::CommitBReserve); on a committed saga
    /// the actor replies `AlreadyCommitted` with the stored receipt/output, so
    /// the outlet is not re-run.
    ///
    /// Then re-acks the A side FROM THE DURABLE WITNESS: `commit_a` keys
    /// idempotency on the Class-S `xctx_committed_invocations` witness (not the
    /// in-memory reservation that died with the crash), so a Commit-A that
    /// durably landed before the crash is observable NOW. This re-drive queries
    /// the caller actor's witness ([`SagaPhaseMessage::CommitACheckWitness`](crate::context::actor::commands::SagaPhaseMessage::CommitACheckWitness)); if
    /// BOTH sides are committed (B `AlreadyCommitted` + the A witness present)
    /// the saga is FULLY committed and resolves to `Committed` — not a spurious
    /// `NeedsRepair`. Only a genuinely-unresolvable divergence (B committed but A
    /// did not, or a side is unreachable) stays `NeedsRepair`.
    ///
    /// Returns the resolution so [`Self::recover_saga_entry`] journals the right
    /// terminal. Invoked by `recover_saga_entry` on a `Committing` entry, driven
    /// by the startup replay loop ([`Self::replay_unresolved_sagas`]).
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
                // Commit-B had NOT durably landed before the crash; the outlet was
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
        use scp_protocol::context::outlets::cross_context_saga::CommittedSide;
        let caller_hex = hex::encode(prepared.caller_context_id);
        // This fn is only reached after Commit-B re-emitted `AlreadyCommitted` —
        // the TARGET side has durably committed `OutletInvoked`. Every arm below
        // that does NOT confirm Commit-A is therefore a genuine ONE-SIDED
        // commit (Target committed, Caller did not / cannot be confirmed). The
        // signing keys died with the crash, so the per-side signed
        // `CrossContextDivergenceMarker` cannot be appended — but the
        // supervisor-level repair journal IS available post-crash, so the
        // divergence MUST be recorded there before returning `NeedsRepair`
        // (spec §6.2.4 "Dual event-log recording" — "or a supervisor-level
        // repair journal if one side is unreachable"). The committed event id
        // is the SagaId-stable `OutletInvoked:{saga_id}` (the id B signed into the
        // receipt and wrote into its log); the nonce is B's staged
        // `recorded_nonce` reconstructed from the journal evidence.
        let committed_event_id = format!("OutletInvoked:{}", saga_id.0);
        let Some(caller) = self.lookup(&caller_hex) else {
            tracing::error!(
                saga_id = %saga_id.0,
                context = %caller_hex,
                "saga recovery — Commit-in-progress: caller actor unreachable; cannot confirm the \
                 A-side witness — recording supervisor repair (Target committed) and NeedsRepair"
            );
            self.record_supervisor_repair(
                saga_id,
                &caller_hex,
                CommittedSide::Target,
                &committed_event_id,
                prepared.recorded_nonce,
            )
            .await;
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
                     is absent (Commit-A never landed) — one-sided commit; recording supervisor \
                     repair and NeedsRepair"
                );
                self.record_supervisor_repair(
                    saga_id,
                    &caller_hex,
                    CommittedSide::Target,
                    &committed_event_id,
                    prepared.recorded_nonce,
                )
                .await;
                CommitInProgressResolution::NeedsRepair
            }
            Err(err) => {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "saga recovery — Commit-in-progress: A-side witness query failed; cannot \
                     confirm Commit-A — recording supervisor repair (Target committed) and \
                     NeedsRepair"
                );
                self.record_supervisor_repair(
                    saga_id,
                    &caller_hex,
                    CommittedSide::Target,
                    &committed_event_id,
                    prepared.recorded_nonce,
                )
                .await;
                CommitInProgressResolution::NeedsRepair
            }
        }
    }

    /// Terminal-resolve a saga that reached a FULLY SUCCESSFUL dual-commit:
    /// Commit-B settled, Commit-A settled (the escrow was already consumed by
    /// the Commit-A settle, so `ctx.prepared_a` is already `None`), and the
    /// committed receipt/output is staged on `ctx`. The ONLY remaining work is
    /// the durable terminal-resolved marker write.
    ///
    /// If `mark_resolved(Committed)` FAILS, both sides have already committed
    /// (the cross-context outlet EXECUTED + CHARGED and both event logs recorded).
    /// Propagating a bare error would lift the saga to `SagaError::Aborted`,
    /// whose contract is "NEITHER side committed" — a contract-honoring caller
    /// would then RETRY with a fresh `SagaId` (a new §6.2.4 idempotency key),
    /// re-executing and RE-CHARGING the outlet a second time. To prevent that we
    /// set `reached_needs_repair` BEFORE returning the error: the boundary lift
    /// then hands back the `saga_id` handle and crash-recovery
    /// (`recover_committing_entry`) reconciles the stuck marker to `Committed` on
    /// next open. NO escrow change is needed here — the escrow was already
    /// consumed by the Commit-A settle, so `ctx.prepared_a` is `None` and
    /// `run_saga`'s tail hold/void of it is a no-op on this path.
    ///
    /// The `reached_needs_repair` flag set here ONLY affects the boundary lift
    /// classification (`run_saga` reads it to choose `NeedsRepair` over
    /// `Aborted`); it does NOT trigger divergence-marker emission (those are
    /// emitted only in `run_saga_fsm`'s commit-exhausted `Err` arm, never in
    /// `run_saga`'s tail).
    async fn resolve_committed_or_needs_repair(
        &self,
        saga_id: &SagaId,
        secret_bearing: bool,
        xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        if let Err(e) = self
            .saga_journal
            .mark_resolved(
                saga_id.clone(),
                SagaTerminalState::Committed,
                secret_bearing,
            )
            .await
        {
            if let Some(ctx) = xctx {
                ctx.reached_needs_repair = true;
            }
            // §17.16.4 operator-alerting metric: a committed saga whose terminal
            // marker did not durably resolve needs operator reconciliation.
            scp_runtime_types::metrics::record_saga_repair_needed();
            tracing::error!(
                saga_id = %saga_id,
                %e,
                "saga coordinator — dual-commit succeeded but mark_resolved(Committed) failed; \
                 saga in NeedsRepair (do NOT retry — both sides already committed)"
            );
            return Err(ContextError::InvalidState(format!(
                "saga journal mark_resolved: {e}"
            )));
        }
        Ok(())
    }

    /// Run the saga FSM for a single saga. Returns `Ok(())` iff the
    /// saga reached `SagaState::Committed`. Every other terminal state
    /// (`Aborted`, `NeedsRepair`) returns a typed error that the caller
    /// surfaces.
    ///
    /// The FSM is saga-type-agnostic — it owns the journal write-ordering,
    /// phase transitions, commit-retry/back-off, `NeedsRepair` accounting, and
    /// abort sequencing. `xctx` threads the per-phase data hand-off for a
    /// `CrossContextOutletInvocation` saga (spec §6.2.4): Prepare-A's reservation,
    /// Prepare-B's recorded provenance, and Commit-B's captured receipt/output
    /// flow A→B→Commit through it. `None` for the executor-less test inputs.
    async fn run_saga_fsm(
        &self,
        saga_id: SagaId,
        input: &SagaInput,
        participants: Vec<String>,
        secret_bearing: bool,
        mut xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), SagaReject> {
        // Infrastructure `?` paths (journal append, abort, commit) carry a bare
        // `ContextError` and auto-wrap via `From<ContextError> for SagaReject`
        // (codeless → `None` → generic `13067`). A §6.2.4 POLICY reject arrives
        // already-typed as a `SagaReject` (its structural `SCP-SAGA-13xxx` code
        // preserved) from `dispatch_prepare_phase`.
        // 1. Initiated
        self.append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
            .await?;

        // 2. PreparingA — dispatch to the caller actor (a wired
        //    cross-context saga), succeed trivially (the `TestForceNeedsRepair`
        //    test variant), or fail `InvalidState` (a `CrossContextOutletInvocation`
        //    driven through `start_saga` without an executor). On failure the
        //    FSM transitions
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
        //    `CrossContextOutletInvocationPrepared` wire carries BOTH context ids,
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
        //    the staged `CrossContextOutletInvocationPrepared` from THIS evidence
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
                // Commit-phase terminal: any error here (e.g. a failed terminal
                // `mark_resolved` journal write) is a codeless infrastructure
                // failure — wrap via `From` (`None` → generic `13067`; the Ok
                // arm sets `reached_needs_repair` so the boundary lifts it to
                // `NeedsRepair` regardless of the code).
                self.resolve_committed_or_needs_repair(
                    &saga_id,
                    secret_bearing,
                    xctx.as_deref_mut(),
                )
                .await
                .map_err(SagaReject::from)
            }
            Err(err) => {
                // Commit retry exhausted — NeedsRepair (spec §6.2.4
                // "commit_with_retry exhausts (3×) → NeedsRepair").
                //
                // Mark the divergence BEFORE the fallible NeedsRepair journal
                // append. The divergence is a FACT the instant
                // `commit_with_retry` exhausts its retries: Commit-B may have
                // landed (and CHARGED) on the target side. The `?` on the
                // append below short-circuits the `Err` arm on a journal-
                // durability failure; if the flag were only set after the
                // append (inside the `if let Some(ctx) = xctx` block), a failed
                // append would leave `reached_needs_repair == false` — and
                // `run_saga`'s tail would then auto-void+consume the escrow (a
                // free-execution refund of a possibly-committed side) AND the
                // lift would mis-classify the diverged saga as a clean
                // `Aborted` ("neither side committed"). A journal-durability
                // failure must NEVER downgrade a diverged saga to a clean abort.
                if let Some(ctx) = xctx.as_deref_mut() {
                    ctx.reached_needs_repair = true;
                }
                // §17.16.4 operator-alerting metric. Fire it HERE — on the
                // in-memory divergence determination, BEFORE the fallible
                // NeedsRepair append below. The divergence is a FACT the instant
                // `commit_with_retry` exhausts; recording the metric only AFTER
                // the append's `?` meant a compound fault (divergence AND a
                // failed durable NeedsRepair append) short-circuited past this
                // call, skipping the live operator alert until a later reopen
                // re-derived it. UNCONDITIONAL (not gated on `xctx`) so the
                // executor-less `TestForceNeedsRepair` path still fires it.
                scp_runtime_types::metrics::record_saga_repair_needed();
                self.append_journal(&saga_id, SagaState::NeedsRepair, &participants, 4, &[])
                    .await
                    .inspect_err(|append_err| {
                        tracing::error!(saga_id = %saga_id, commit_error = %err, error = %append_err, "cross-context saga NeedsRepair — COMPOUND FAULT: the repair-need was recorded in-memory (metric fired; boundary lifts NeedsRepair) but the durable NeedsRepair journal append FAILED; the divergence is deferred to recover_committing_entry re-derivation on next supervisor open");
                    })?;
                tracing::error!(
                    saga_id = %saga_id,
                    %err,
                    "saga coordinator — commit retry exhausted, saga in NeedsRepair"
                );
                // Dual event-log recording (spec §6.2.4): on NeedsRepair both
                // sides MUST emit a signed `CrossContextDivergenceMarker` (into
                // each available log, or the supervisor-level repair journal if
                // a side is unreachable) so a one-sided commit is durably
                // auditable. Cross-context only; the executor-less test inputs
                // carry no `xctx`. `reached_needs_repair` was already set above
                // (before the fallible append) so `run_saga`'s tail leaves the
                // escrow RESERVED (NOT auto-voided) for operator repair; this
                // block only emits the divergence markers.
                if let Some(ctx) = xctx {
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
                // Codeless commit-exhaustion terminal: wrap via `From` (`None` →
                // generic `13067`). `reached_needs_repair` is already set, so the
                // boundary lifts this to `NeedsRepair` (code `13065`) regardless.
                Err(err.into())
            }
        }
    }

    /// Dispatch a single Prepare phase under the 30s per-phase timeout
    /// ([ADR-049](crate) §7; a timeout maps to
    /// [`ContextError::TransportTimeout`]).
    ///
    /// For `CrossContextOutletInvocation` the FSM routes the per-phase message to
    /// the co-resident participant actor and threads the reply into `xctx`:
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
    ) -> Result<(), SagaReject> {
        const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        let dispatch_fut = async {
            match input {
                SagaInput::CrossContextOutletInvocation { .. } => {
                    let Some(ctx) = xctx else {
                        // Supervisor-axis reject (code known locally): 13051.
                        return Err(saga_reject!(
                            13051,
                            InvalidState,
                            "saga Prepare{:?} — CrossContextOutletInvocation requires the \
                             supervisor-side executor + signing key; call \
                             start_cross_context_outlet_invocation_saga, not start_saga",
                            phase
                        ));
                    };
                    match phase {
                        SagaPhase::A => self.dispatch_xctx_prepare_a(saga_id, ctx).await,
                        SagaPhase::B => self.dispatch_xctx_prepare_b(saga_id, ctx).await,
                    }
                }
                // Streaming saga (ADR-061): never driven through the generic
                // synchronous `run_saga` FSM — its dedicated entry
                // `start_cross_context_streaming_outlet_invocation_saga` runs
                // Prepare-B + the async seal phase directly. Reaching here is a
                // misuse (someone routed a streaming input through `start_saga`).
                SagaInput::CrossContextStreamingOutletInvocation { .. } => Err(saga_reject!(
                    13055,
                    InvalidState,
                    "saga Prepare{:?} — CrossContextStreamingOutletInvocation is not driven by the \
                     generic run_saga FSM; call \
                     start_cross_context_streaming_outlet_invocation_saga",
                    phase
                )),
                // Test-only: Prepare always SUCCEEDS so the FSM advances to
                // Committing (where the test variant's Commit then fails,
                // driving NeedsRepair).
                #[cfg(any(test, feature = "testing"))]
                SagaInput::TestForceNeedsRepair { .. } => Ok(()),
            }
        };

        match tokio::time::timeout(PHASE_TIMEOUT, dispatch_fut).await {
            Ok(r) => r,
            // A phase timeout is a CODELESS transport failure (no saga policy
            // code) — wrap via `From` so the boundary lifts it to the generic
            // saga-abort code `13067`.
            Err(_elapsed) => Err(SagaReject::from(ContextError::TransportTimeout(format!(
                "saga Prepare{phase:?} exceeded 30s phase budget"
            )))),
        }
    }

    /// Prepare-A (caller side, spec §6.2.4): resolve the co-resident caller
    /// actor, send [`SagaPhaseMessage::PrepareA`](crate::context::actor::commands::SagaPhaseMessage::PrepareA), and hold the returned
    /// [`PreparedAFields`](crate::context::actor::commands::PreparedAFields) reservation in `ctx` for Commit-A / abort.
    async fn dispatch_xctx_prepare_a(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(), SagaReject> {
        use crate::context::actor::commands::SagaPhaseMessage;

        let caller_hex = hex::encode(ctx.caller_context_id);
        // Supervisor-axis reject (code known locally): 13052.
        let actor = self.lookup(&caller_hex).ok_or_else(|| {
            saga_reject!(
                13052,
                ContextNotRegistered,
                "cross-context saga Prepare-A — caller context '{}' is not a co-resident actor \
                 (cross-node child-bridge transport is future work)",
                caller_hex
            )
        })?;

        let saga_id = saga_id.clone();
        let caller_context_id = ctx.caller_context_id;
        let caller_did = ctx.caller_did.clone();
        let outlet_registration_id = ctx.outlet_registration_id.clone();

        // The mailbox `send` reply is `Result<PrepareAOutcome, ContextError>`: a
        // dropped receiver / mailbox failure auto-wraps codeless via `From`; a
        // §6.2.4 POLICY reject rides `Ok(Rejected(SagaReject))` carrying the
        // structural code.
        let outcome = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::PrepareA {
                    saga_id,
                    caller_context_id,
                    caller_did,
                    outlet_registration_id,
                    reply,
                })
            })
            .await?;
        match outcome {
            PrepareAOutcome::Prepared(prepared) => {
                ctx.prepared_a = Some(prepared);
                Ok(())
            }
            PrepareAOutcome::Rejected(reject) => Err(reject),
        }
    }

    /// Prepare-B (target side, spec §6.2.4): resolve the co-resident target
    /// actor, send [`SagaPhaseMessage::PrepareB`](crate::context::actor::commands::SagaPhaseMessage::PrepareB) with the caller-asserted
    /// envelope, and hold the returned [`PreparedBFields`](crate::context::actor::commands::PreparedBFields) in `ctx`.
    async fn dispatch_xctx_prepare_b(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(), SagaReject> {
        use crate::context::actor::commands::SagaPhaseMessage;

        let target_hex = hex::encode(ctx.target_context_id);
        // Supervisor-axis reject (code known locally): 13053.
        let actor = self.lookup(&target_hex).ok_or_else(|| {
            saga_reject!(
                13053,
                ContextNotRegistered,
                "cross-context saga Prepare-B — target context '{}' is not a co-resident actor \
                 (cross-node child-bridge transport is future work)",
                target_hex
            )
        })?;

        let saga_id = saga_id.clone();
        let caller_context_id = ctx.caller_context_id;
        let target_context_id = ctx.target_context_id;
        let caller_did = ctx.caller_did.clone();
        let outlet_registration_id = ctx.outlet_registration_id.clone();
        let ucan_proof_id = ctx.ucan_proof_id.clone();
        let input = ctx.input.clone();
        let asserted_chain_depth = ctx.asserted_chain_depth;
        let asserted_nonce = ctx.asserted_nonce;
        let asserted_timestamp_ms = ctx.asserted_timestamp_ms;
        let caller_source_role = ctx.caller_source_role.clone();

        // The mailbox `send` reply is `Result<PrepareBOutcome, ContextError>`: a
        // mailbox failure auto-wraps codeless via `From`; a §6.2.4 POLICY reject
        // rides `Ok(Rejected(SagaReject))` carrying the structural code.
        let outcome = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::PrepareB {
                    saga_id,
                    caller_context_id,
                    target_context_id,
                    caller_did,
                    outlet_registration_id,
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
        match outcome {
            PrepareBOutcome::Prepared(prepared) => {
                ctx.prepared_b = Some(prepared);
                Ok(())
            }
            PrepareBOutcome::Rejected(reject) => Err(reject),
        }
    }

    /// Commit with 3x retry: 500ms, 1s, 2s. Returns the final error after
    /// retries are exhausted (→ `NeedsRepair`). The `TestForceNeedsRepair`
    /// variant always fails (driving the retry-exhaustion path); a wired
    /// `CrossContextOutletInvocation` runs the real two-side Commit.
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

    /// Dispatch the Commit phase under the per-attempt
    /// [`COMMIT_PHASE_TIMEOUT`].
    ///
    /// For a wired `CrossContextOutletInvocation` this drives the §6.2.4 Commit:
    /// Commit-B reserve → run the executor supervisor-side → Commit-B settle →
    /// Commit-A, ordered B then A. `TestForceNeedsRepair` always fails.
    async fn dispatch_commit_phase(
        &self,
        saga_id: &SagaId,
        input: &SagaInput,
        xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        let dispatch_fut = async {
            match input {
                SagaInput::CrossContextOutletInvocation { .. } => {
                    let Some(ctx) = xctx else {
                        return Err(ContextError::InvalidState(
                            "SCP-SAGA-13054: saga Commit — CrossContextOutletInvocation requires \
                             the supervisor-side executor context (start_saga misuse)"
                                .to_owned(),
                        ));
                    };
                    self.dispatch_xctx_commit(saga_id, ctx).await
                }
                // Streaming saga (ADR-061): not driven through the generic FSM
                // Commit — the dedicated entry runs the async seal phase directly.
                SagaInput::CrossContextStreamingOutletInvocation { .. } => {
                    Err(ContextError::InvalidState(
                        "SCP-SAGA-13056: saga Commit — CrossContextStreamingOutletInvocation is \
                         not driven by the generic run_saga FSM; call \
                         start_cross_context_streaming_outlet_invocation_saga"
                            .to_owned(),
                    ))
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

        match tokio::time::timeout(COMMIT_PHASE_TIMEOUT, dispatch_fut).await {
            Ok(r) => r,
            Err(_elapsed) => Err(ContextError::TransportTimeout(format!(
                "saga Commit exceeded {COMMIT_PHASE_TIMEOUT:?} phase budget"
            ))),
        }
    }

    /// Drive the §6.2.4 Commit over the two co-resident actors, ordered B then
    /// A:
    ///
    /// 1. **Commit-B reserve** — ask the target actor whether to execute. On a
    ///    replay (`AlreadyCommitted`) it returns the STORED receipt/output and
    ///    the outlet is NOT re-invoked.
    /// 2. **Run the executor supervisor-side** — the non-`Send` outlet executor
    ///    runs off the actor mailbox (ADR-049 §3), producing the output.
    /// 3. **Commit-B settle** — hand the output to the target actor, which
    ///    signs the receipt through `target_signer`, appends `OutletInvoked`,
    ///    and durably captures the output keyed by `SagaId`.
    /// 4. **Commit-A** — hand the receipt/output + the held Prepare-A
    ///    reservation to the caller actor, which settles escrow and records
    ///    `CrossContextOutletInvoked` (sharing the nonce).
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

        // Verify-before-settle (spec §6.2.4 "Signer authorization"): before
        // Commit-A settles escrow + records the provenance edge, the FSM
        // re-verifies B's signature over the receipt against the SAME key it
        // gave B to sign with (`ctx.target_signer`). This is an in-saga
        // integrity check — it proves the receipt was not corrupted/forged in
        // transit back from Commit-B — NOT the spec's independent
        // signer-authorization (governance-resolution) step. That step — confirm
        // the signing key is in fact the Active Signing Key authorized to act for
        // `target_context_id`, resolved via that context's membership/governance
        // (§3, §7) — is the DOWNSTREAM receipt CONSUMER's burden (an auditor, or
        // A re-presenting the receipt as provenance), discharged at the FFI/SDK
        // boundary, not here: the FSM trivially holds the right key because it
        // just handed it to B, so this check cannot stand in for an independent
        // resolution. A verify failure aborts the Commit WITHOUT settling or
        // recording — a corrupted / tampered receipt must never charge the caller
        // or write a provenance edge. This also pins the bytes A records: the
        // verified receipt's SIGNED `output_hash` is what Commit-A binds, not an
        // independently recomputed hash.
        let parsed = Self::verify_commit_b_receipt(saga_id, ctx, &receipt)?;

        self.commit_a_settle(saga_id, ctx, &receipt, &parsed)
            .await?;
        ctx.committed = Some(CommittedSagaArtifacts { receipt, output });
        Ok(())
    }

    /// Verify B's signed [`CrossContextOutletReceipt`] against the Active Signing
    /// Key authorized for `target_context_id` (spec §6.2.4 "Signer
    /// authorization", normative MUST) and return the parsed receipt for the
    /// Commit-A binding.
    ///
    /// The FSM holds the resolved target signer (`ctx.target_signer` — the one
    /// it supplied to Commit-B for signing), so verifying the receipt's
    /// signature against `verifying_key()` is exactly "signed by the key
    /// authorized for `target_context_id`". On a parse or signature failure this
    /// returns a typed error BEFORE Commit-A runs, so a forged / tampered
    /// receipt never settles escrow or writes the provenance edge.
    fn verify_commit_b_receipt(
        saga_id: &SagaId,
        ctx: &CrossContextSagaCtx<'_>,
        receipt_bytes: &[u8],
    ) -> Result<CrossContextOutletReceipt, ContextError> {
        let receipt: CrossContextOutletReceipt =
            serde_json::from_slice(receipt_bytes).map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "SCP-SAGA-13063: cross-context saga Commit — target receipt for saga '{}' \
                     is not a decodable CrossContextOutletReceipt: {e}",
                    saga_id.0
                ))
            })?;
        let authorized_target_key = ctx.target_signer.verifying_key()?;
        receipt.verify(&authorized_target_key).map_err(|e| {
            ContextError::CryptoFailed(format!(
                "SCP-SAGA-13064: cross-context saga Commit — target receipt signature for saga \
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
            // Replay: the outlet already executed; re-use the stored capture. The
            // `outlet_invoked_event_id` is carried inside the signed receipt; we
            // ALSO record it in `ctx` so a subsequent Commit-A failure → NeedsRepair
            // knows the TARGET committed and which event id its
            // `CrossContextDivergenceMarker` must name (spec §6.2.4).
            CommitBReserveOutcome::AlreadyCommitted {
                receipt,
                output_bytes,
                outlet_invoked_event_id,
            } => {
                ctx.committed_b_outlet_invoked_event_id = Some(outlet_invoked_event_id);
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
    /// send [`SagaPhaseMessage::CommitBSettle`](crate::context::actor::commands::SagaPhaseMessage::CommitBSettle) with the captured output and the
    /// target's Active Signing Key.
    ///
    /// Retryable settle (review wave-1): the outlet runs only when no output is yet
    /// stashed (`ctx.executor_output == None`). Once it has run, the output is
    /// stashed; a transient settle FAILURE leaves `executor_output == Some` while
    /// the actor's persist-rolled-back capture makes the next reserve report
    /// `ReadyToExecute` again — so this is re-entered, but it RE-SENDS the settle
    /// with the stashed bytes rather than re-invoking the outlet (exactly-once
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
        // output is already stashed — NEVER re-invoke (the outlet had side
        // effects); re-send the settle with the stashed bytes.
        let exec_output_bytes = if let Some(stashed) = ctx.executor_output.clone() {
            stashed
        } else {
            let executor = ctx.executor.take().ok_or_else(|| {
                ContextError::InvalidState(
                    "SCP-SAGA-13056: cross-context saga Commit-B — executor already consumed but \
                     no output was stashed (a non-replay Commit attempt after the outlet ran is a \
                     coordinator bug)"
                        .to_owned(),
                )
            })?;
            let output_value =
                tokio::time::timeout(COMMIT_EXECUTOR_TIMEOUT, executor(ctx.input.clone()))
                    .await
                    .map_err(|_elapsed| {
                        ContextError::TransportTimeout(format!(
                            "saga Commit outlet executor exceeded {COMMIT_EXECUTOR_TIMEOUT:?} \
                             budget for saga '{}'",
                            saga_id.0
                        ))
                    })?
                    .map_err(|e| {
                        ContextError::CryptoFailed(format!(
                            "SCP-SAGA-13057: cross-context outlet executor failed for saga '{}': \
                             {e}",
                            saga_id.0
                        ))
                    })?;
            let bytes = serde_json::to_vec(&output_value).map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "SCP-SAGA-13058: cross-context outlet output is not serializable for saga \
                     '{}': {e}",
                    saga_id.0
                ))
            })?;
            // Stash BEFORE the settle send, so a settle failure (and the actor's
            // rolled-back capture) leaves the output recoverable for the retry —
            // the outlet is never re-invoked.
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
        let target_signer = ctx.target_signer.clone();
        let CommitBSettleOutcome {
            receipt,
            output_bytes,
            outlet_invoked_event_id,
        } = target
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBSettle {
                    saga_id: settle_saga_id,
                    output_bytes: exec_output_bytes,
                    target_signer,
                    reply,
                })
            })
            .await?;
        // Commit-B has landed durably: record the target's `OutletInvoked` event
        // id so a later Commit-A failure → NeedsRepair knows the TARGET side
        // committed and which event id the divergence marker must name.
        ctx.committed_b_outlet_invoked_event_id = Some(outlet_invoked_event_id);
        Ok((receipt, output_bytes))
    }

    /// Commit-A (caller side, §6.2.4): hand the held Prepare-A reservation +
    /// the target's VERIFIED receipt to the caller actor, which settles the
    /// escrow and records `CrossContextOutletInvoked` (sharing the nonce).
    ///
    /// Ticket-safe + witness-driven re-drive (review wave-1):
    ///
    /// - **Held reservation present** — the normal path. The `#[must_use]`
    ///   reservation (holding the `OutletEconomyTicket` whose `Drop` debug-asserts
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
        receipt: &CrossContextOutletReceipt,
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
        // INVARIANT (spec §6.2.4 *Staged nonce*): the caller-side
        // `CrossContextOutletInvoked` leaf and the `CrossContextDivergenceMarker`
        // form one `nonce`-joined provenance edge, so they MUST carry the same
        // nonce. `ctx.asserted_nonce` is byte-identical to B's
        // `prepared_b.recorded_nonce` (which the marker uses) because Prepare-B
        // copies the wire nonce verbatim into `recorded_nonce` (saga.rs, "B's
        // staged copy of the 16-byte wire nonce") — the nonce is a public
        // correlation token B copies, never derives. If B's `recorded_nonce`
        // ever stops being a verbatim copy, source this from
        // `prepared_b.recorded_nonce` too so both records share one origin.
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

    /// Extract the held Prepare-A reservation back out of a recovered
    /// (un-delivered) caller-side `Abort` command so the abort path can void its
    /// external escrow + consume the ticket. Returns `None` if the command is
    /// not an `Abort` carrying a reservation (unreachable for the command built
    /// in [`Self::abort_xctx_participants`]).
    fn extract_abort_reservation(
        cmd: Box<ContextCommand>,
    ) -> Option<crate::context::actor::commands::PreparedAFields> {
        use crate::context::actor::commands::SagaPhaseMessage;
        if let ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
            reservation: Some(reservation),
            ..
        }) = *cmd
        {
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
    ///    [`CrossContextSagaCtx::committed_b_outlet_invoked_event_id`]: `Some`
    ///    means Commit-B landed (the TARGET committed its `OutletInvoked`) and
    ///    Commit-A then failed — `committed_side = Target`, the committed event
    ///    id is the `OutletInvoked` id. `None` means Commit-B never landed; no
    ///    side committed, so there is NOTHING to record (the logs are clean —
    ///    no divergence). A clean no-commit `NeedsRepair` therefore emits no
    ///    markers; it is a transient commit failure the operator re-drives, not
    ///    a one-sided commit.
    /// 2. For each reachable participant actor (target + caller), resolves that
    ///    side's Active Signing Key (the FSM holds both — supplied per-call,
    ///    ADR-049) and sends [`SagaPhaseMessage::EmitDivergenceMarker`](crate::context::actor::commands::SagaPhaseMessage::EmitDivergenceMarker) so the
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
        use scp_protocol::context::outlets::cross_context_saga::CommittedSide;

        // The OWNED plan was extracted by the SYNC [`Self::divergence_marker_plan`]
        // at the (sync) FSM call site — NO `&CrossContextSagaCtx` borrow spans the
        // `.await`s below (the ctx carries the non-`Sync` boxed executor, which
        // would otherwise poison this future's `Send` bound). The loop holds only
        // owned values.
        let (committed_event_id, nonce, sides, committed_timestamp_secs) = plan;
        let committed_side = CommittedSide::Target;

        for (label, context_id, signer) in sides {
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
                            committed_timestamp_secs,
                            signer,
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
                        )
                        .await;
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
                )
                .await;
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
        let committed_event_id = ctx.committed_b_outlet_invoked_event_id.clone()?;
        // B's VERIFIED staged provenance is the ONLY admissible source for the
        // convergent marker-leaf nonce + timestamp. In the current FSM a
        // committed B (`committed_event_id` is `Some`) always implies Prepare-B
        // ran and `prepared_b` is set, so this `?` never trips on the live path.
        // But the invariant is enforced by TYPES here, not by call-ordering: a
        // future recovery path that runs this plan with `prepared_b: None` MUST
        // NOT be able to substitute the caller-ASSERTED (untrusted, proposer-
        // controlled) nonce / timestamp into a convergent durable leaf. Absent
        // B's verified provenance there is no honest convergent value to mark
        // with, so refuse to produce a marker plan — the caller already handles
        // the `None`/skip outcome (no committed side ⇒ no divergence to record).
        let prepared_b = ctx.prepared_b.as_ref()?;
        // Each side records the SAME (committed_side, committed_event_id, nonce)
        // — each into its own log under its OWN Active Signing Key. Only the
        // TARGET can have committed-then-diverged in the current FSM (Commit-B
        // lands first, then Commit-A).
        //
        // Keying off the B-committed event id alone is sound (no A-side symmetry
        // needed): an A-without-B divergence is STRUCTURALLY IMPOSSIBLE. Commit-A
        // (`commit_a`) appends its `CrossContextOutletInvoked` ONLY after its
        // idempotency-witness Class-S persist succeeds, which itself can only run
        // after Commit-B landed and forwarded the receipt — so a durable A-side
        // record can never exist without a durable B-side `OutletInvoked`. The
        // append-before-persist inverse (which would have produced a silent
        // A-without-B orphan on a persist failure) was the bug FIX corrected by
        // mirroring `commit_b_first_settle`'s witness-persist-before-append
        // ordering. A one-sided divergence is therefore always Target-committed.
        let sides = [
            ("target", ctx.target_context_id, ctx.target_signer.clone()),
            ("caller", ctx.caller_context_id, ctx.caller_signer.clone()),
        ];
        // Source the STAGED `recorded_nonce` (B's captured copy of the wire
        // value) for symmetry with the signed receipt, which draws its `nonce`
        // from the same staged value (spec §6.2.4 *Staged nonce and recorded
        // chain-depth*). Drawn from B's VERIFIED provenance only — never the
        // caller-asserted nonce (see the `prepared_b` guard above).
        let marker_nonce = prepared_b.recorded_nonce;
        // CONVERGENT marker-leaf timestamp: B's staged `recorded_timestamp_ms`
        // (the same value signed into the receipt and written into the
        // committed-side `OutletInvoked` leaf), in SECONDS. Drawing the marker
        // leaf's timestamp from this single convergent instant (rather than each
        // emitting actor's local clock — or, worse, the caller-asserted value)
        // keeps the marker leaf byte-identical across honest members (§7.3.1,
        // §9.9.3, §6.2.4 *Recorded timestamp*).
        let committed_timestamp_secs = prepared_b.recorded_timestamp_ms / 1000;
        Some((
            committed_event_id,
            marker_nonce,
            sides,
            committed_timestamp_secs,
        ))
    }

    /// Record a supervisor-level divergence repair witness for an UNREACHABLE
    /// (or append-failed) side of a `NeedsRepair` saga (spec §6.2.4 "Dual
    /// event-log recording" — "or a supervisor-level repair journal if one side
    /// is unreachable").
    ///
    /// Two-tier durability: pushes the record into the in-memory
    /// [`Self::saga_repair_records`] read cache (keyed by saga id; a single
    /// diverged saga may accumulate multiple records), AND durably appends the
    /// FULL accumulated record set for the saga as the `evidence` of a
    /// `NeedsRepair` [`JournalEntry`]. The durable write is the load-bearing
    /// half: without it a supervisor crash before an operator reads the cache
    /// would LOSE the unreachable-leg divergence account, weakening the spec's
    /// "durably auditable" guarantee for that leg. On restart the recovery path
    /// (`recover_saga_entry`'s `NeedsRepair` arm) decodes the latest such entry
    /// and rehydrates the cache. A durable-append failure is logged (the
    /// in-memory cache still holds the record for an operator reading a live
    /// supervisor) but cannot itself be repaired here — it is the same
    /// best-effort-then-surface posture the reachable-side marker append takes.
    async fn record_supervisor_repair(
        &self,
        saga_id: &SagaId,
        unreachable_context_hex: &str,
        committed_side: scp_protocol::context::outlets::cross_context_saga::CommittedSide,
        committed_event_id: &str,
        nonce: [u8; 16],
    ) {
        // Push into the in-memory read cache and snapshot the full accumulated
        // set + the per-saga append seq (vec length after the push) WITHOUT
        // holding the DashMap guard across the `.await` below.
        let (records, append_seq) = {
            let mut entry = self.saga_repair_records.entry(saga_id.clone()).or_default();
            entry.push(SagaDivergenceRepairRecord {
                unreachable_context_hex: unreachable_context_hex.to_owned(),
                committed_side,
                committed_event_id: committed_event_id.to_owned(),
                nonce,
            });
            // seq 4 is the plain NeedsRepair transition (empty evidence); the
            // repair-record appends follow it monotonically (5, 6, …), one per
            // accumulated record, so the LATEST-per-saga entry load_unresolved
            // returns carries the full set.
            (entry.clone(), 4 + entry.len() as u64)
        };

        let evidence = match encode_repair_records_evidence(&records) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::error!(
                    saga_id = %saga_id.0,
                    %err,
                    "cross-context saga NeedsRepair — failed to ENCODE the supervisor repair \
                     record set for the durable journal; the divergence stays in the in-memory \
                     read cache only"
                );
                return;
            }
        };

        // The participants are the two saga contexts; reuse the committed-side
        // event id linkage carried inside the evidence. Durably append.
        if let Err(err) = self
            .append_journal(
                saga_id,
                SagaState::NeedsRepair,
                &[unreachable_context_hex.to_owned()],
                append_seq,
                &evidence,
            )
            .await
        {
            tracing::error!(
                saga_id = %saga_id.0,
                %err,
                "cross-context saga NeedsRepair — failed to DURABLY journal the supervisor \
                 repair record; it remains in the in-memory read cache but will not survive a \
                 supervisor restart"
            );
        }
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

    /// TEST-ONLY: the latest journaled [`SagaState`] for `saga_id` while it is
    /// still unresolved, or `None` once it has been resolved
    /// (Committed / Aborted) or was never journaled — reading the supervisor's
    /// OWN durable saga journal via the SAME `load_unresolved` the crash-recovery
    /// sweep uses.
    ///
    /// This exists so an FFI-level e2e test (SCP-OUT-047 AC6) can observe the
    /// PRE-Committed (`Committing`) journal state a streaming-saga open leaves at
    /// the Commit-transition — before the off-mailbox seal task resolves it to
    /// `Committed` at stream-close — proving the FFI open returned promptly
    /// rather than blocking until the stream terminated. It reads the journal
    /// only (no actor mailbox, no mutation), so it is safe to call from any
    /// runtime. A `load_unresolved` error is folded to "not found" (`None`).
    #[cfg(any(test, feature = "testing"))]
    pub async fn test_saga_journal_state(&self, saga_id: &SagaId) -> Option<SagaState> {
        self.saga_journal
            .load_unresolved()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|e| &e.saga_id == saga_id)
            .map(|e| e.state)
    }

    /// Build the journal `evidence` bytes for a cross-context outlet-invocation
    /// saga — the `MessagePack` of the eight-field
    /// [`CrossContextOutletInvocationPrepared`](crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared)
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
    /// the recorded values). Returns `None` for a non-`CrossContextOutletInvocation`
    /// input (the test-only `TestForceNeedsRepair` variant carries no `xctx`).
    fn xctx_prepared_evidence_bytes(
        input: &SagaInput,
        ctx: &CrossContextSagaCtx<'_>,
    ) -> Option<Vec<u8>> {
        use crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared;
        // Only the cross-context variant journals prepared evidence.
        if !matches!(input, SagaInput::CrossContextOutletInvocation { .. }) {
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
        let prepared = CrossContextOutletInvocationPrepared {
            caller_context_id: ctx.caller_context_id,
            target_context_id: ctx.target_context_id,
            caller_did: ctx.caller_did.clone(),
            outlet_registration_id: ctx.outlet_registration_id.clone(),
            // The wire mirror carries a non-optional `ucan_proof_id`; an ungated
            // outlet (no proof) maps to the empty string (round-trips to `None`
            // semantics via an empty proof reference on reconstruction).
            ucan_proof_id: ctx.ucan_proof_id.clone().unwrap_or_default(),
            recorded_timestamp_ms,
            recorded_nonce,
            recorded_chain_depth,
        };
        prepared.to_evidence_bytes().ok()
    }

    /// Abort the saga (spec §6.2.4 "Reservation release on every terminal
    /// path"): release the staged participant reservations — for a cross-context
    /// saga, send [`SagaPhaseMessage::Abort`](crate::context::actor::commands::SagaPhaseMessage::Abort) to whichever side(s) prepared so
    /// the staged reservations are released (the caller side hands its held
    /// `PreparedAFields` back to reverse its LOCAL economy; the target side
    /// clears its staged slot) — and THEN, iff the caller-side LOCAL economy
    /// reversal was confirmed, mark the journal Aborting → Aborted.
    ///
    /// The reservation release runs BEFORE the `Aborting` transition so the
    /// terminal marker is never written while the caller refund is still
    /// outstanding (a terminal-`Aborted` journal asserts "fully compensated").
    /// If [`Self::abort_xctx_participants`] reports the caller reversal
    /// outstanding (send-failure + re-drive failure, unreachable actor, or a
    /// delivered-but-errored handler), the journal is LEFT non-terminal (at
    /// `PreparingB`) so the §17.16.4 crash-recovery sweep re-drives the
    /// record-based `Abort { None }` reversal — never an unconditional terminal.
    async fn abort_saga(
        &self,
        saga_id: &SagaId,
        participants: &[String],
        next_seq: u64,
        secret_bearing: bool,
        xctx: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        // Release any staged participant reservations FIRST — BEFORE the
        // `Aborting` journal transition — so the terminal marker is never
        // written while the caller's LOCAL economy reversal is still
        // outstanding. The caller-side budget / velocity / hard-rate-limit were
        // deducted + Class-S-persisted at Prepare-A and live in the caller
        // actor's `PerContextState`; they can ONLY be reversed BY that actor (a
        // delivered `Abort`). `mark_resolved(Aborted)` asserts "fully
        // compensated", so it MUST NOT precede the local reversal. See
        // [`Self::abort_xctx_participants`] for the per-side delivery contract
        // and the send-failure / unreachable re-drive that reverses the local
        // economy from the durable `CallerReservationRecord`.
        let caller_reversal = match xctx {
            Some(ctx) => self.abort_xctx_participants(saga_id, ctx).await,
            // Non-cross-context (test-only) saga: no caller-side local
            // economy to reverse, so the terminal marker is always safe.
            None => CallerAbortReversal::SettledOrAbsent,
        };

        // If the caller's local-economy reversal could NOT be confirmed (the
        // re-drive ALSO failed under persistent backpressure / a closed inbox),
        // do NOT write a terminal `Aborted` marker: that would durably assert
        // "fully compensated" while the caller stays over-charged forever (the
        // §17.16.4 sweep re-drives ONLY a non-terminal `PreparingB`, never an
        // `Aborted`). Leave the journal at its current pre-`Aborting` state
        // (`PreparingB` — carrying the full caller+target evidence) so the
        // startup crash-recovery sweep re-drives `Abort { None }` and reverses
        // the local economy from the durable record. The FSM still surfaces the
        // original abort error to its caller.
        if matches!(caller_reversal, CallerAbortReversal::ReversalOutstanding) {
            // Observability: the producing site inside `abort_xctx_participants` /
            // `redrive_caller_local_reversal` already routed its verdict through
            // `Self::reversal_outstanding()`, which incremented
            // `scp_saga_caller_reversal_outstanding_total` and (at the site) emitted
            // the stable `event = "xctx_caller_reversal_outstanding"` warn. This
            // coordinator branch re-emits the SAME stable field (so a log query on
            // it surfaces the terminal "left non-terminal" decision too) but does
            // NOT re-increment the counter — that would double-count a single
            // stranded reversal. Log-based alerting on that stable field
            // (thresholding the per-`saga_id` rate) is the intended signal.
            tracing::warn!(
                event = "xctx_caller_reversal_outstanding",
                saga_id = %saga_id.0,
                "cross-context saga abort — caller-side local-economy reversal could not be \
                 delivered (persistent backpressure / closed inbox); leaving the journal \
                 non-terminal so the crash-recovery sweep reconciles it (NOT marking \
                 terminal-Aborted with the caller refund outstanding)"
            );
            return Ok(());
        }

        self.append_journal(saga_id, SagaState::Aborting, participants, next_seq, &[])
            .await?;

        self.saga_journal
            .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, secret_bearing)
            .await
            .map_err(|e| ContextError::InvalidState(format!("saga journal mark_resolved: {e}")))
    }

    /// Record a stranded caller-side cross-context-saga reversal and return the
    /// [`CallerAbortReversal::ReversalOutstanding`] verdict. Bumps the
    /// `scp_saga_caller_reversal_outstanding_total` counter once per stranded
    /// reversal so log-based / metric alerting can threshold the rate (each call
    /// site additionally emits a stable `event = "xctx_caller_reversal_outstanding"`
    /// structured warn carrying `saga_id`). Centralizing the counter here keeps
    /// every producing site in lockstep — a new outstanding path cannot forget to
    /// count itself — and avoids double-counting at the coordinator that consumes
    /// the verdict.
    fn reversal_outstanding() -> CallerAbortReversal {
        scp_runtime_types::metrics::record_saga_caller_reversal_outstanding();
        CallerAbortReversal::ReversalOutstanding
    }

    /// Send [`SagaPhaseMessage::Abort`](crate::context::actor::commands::SagaPhaseMessage::Abort) to the prepared participant actors of a
    /// cross-context saga, reversing the caller-side LOCAL economy on every
    /// reachable leg.
    ///
    /// - CALLER side: if Prepare-A staged a reservation, hand the carrier back
    ///   via a `Abort { Some }` so the actor rolls the held escrow + LOCAL
    ///   budget / velocity / hard-rate-limit back (the generation-checked
    ///   carrier rollback). Taking it out of `ctx` ensures the
    ///   `OutletEconomyTicket` is settled-or-rolled-back exactly once.
    ///
    ///   If that send FAILS (mailbox full for the full `SEND_TIMEOUT`, or the
    ///   inbox is closed) the carrier never reached the actor, so its
    ///   per-context LOCAL rollback never ran — the carrier's escrow void alone
    ///   would leave the caller's LOCAL budget / velocity / hard-rate-limit
    ///   deducted forever (a durable over-charge). The actor-owned LOCAL economy
    ///   can ONLY be reversed BY the actor, so we recover the carrier, void +
    ///   consume its external escrow (idempotent), and then RE-DRIVE the abort
    ///   as `Abort { None }` — the SAME path the §17.16.4 crash-recovery sweep
    ///   uses — which reverses the LOCAL economy from the durable
    ///   `CallerReservationRecord` Prepare-A staged (and idempotently re-voids
    ///   the same escrow). If that re-drive ALSO fails, the caller refund is
    ///   STILL outstanding: we report [`CallerAbortReversal::ReversalOutstanding`]
    ///   so the coordinator leaves the journal non-terminal for the sweep to
    ///   reconcile — NEVER marking terminal-`Aborted` with the refund pending.
    ///
    ///   If the caller actor is UNREACHABLE (despawned — `lookup` miss), the
    ///   in-memory carrier rollback cannot run, but the durable
    ///   `CallerReservationRecord` survives in the persisted snapshot and the
    ///   restored actor will carry it; we void the carrier escrow + consume the
    ///   ticket (so its `#[must_use]` drop guard does not fire) and report
    ///   `ReversalOutstanding` so the journal stays non-terminal until a respawn
    ///   + sweep reverses the LOCAL economy from the record.
    ///
    ///   If `prepared_a` is `None` (the carrier never reached `ctx` — e.g. the
    ///   §6.2.4 30s Prepare-A phase-timeout dropped the supervisor's reply
    ///   receiver AFTER the actor durably persisted the deduction + record), this
    ///   does NOT mean nothing was prepared. The durable record is the source of
    ///   truth: we drive a record-based `Abort { None }` (via
    ///   [`Self::redrive_caller_local_reversal`]) so the caller reverses the
    ///   LOCAL economy from the record if present — a clean no-op (→
    ///   `SettledOrAbsent`) only for a genuinely-nothing-prepared saga. Without
    ///   this, a lost Prepare-A reply would strand the caller's durable deduction
    ///   under a terminal `Aborted` forever (the startup sweep re-drives only
    ///   non-terminal journals).
    ///
    /// - TARGET side: send `Abort` with `None` reservation so the actor clears
    ///   its staged `saga_pending` slot (releasing the session reservation).
    ///   Only meaningful if Prepare-B staged a slot. The target side carries no
    ///   caller LOCAL economy, so it never affects the returned reversal status.
    ///
    /// Returns whether the CALLER-side local-economy reversal is settled (the
    /// only input to the coordinator's terminal-marker decision); the target
    /// slot release is best-effort and orthogonal.
    async fn abort_xctx_participants(
        &self,
        saga_id: &SagaId,
        ctx: &mut CrossContextSagaCtx<'_>,
    ) -> CallerAbortReversal {
        use crate::context::actor::commands::SagaPhaseMessage;

        // CALLER side. A `Some` carrier is the LIVE-abort fast path (rolled back
        // BY the actor via the generation-checked carrier rollback). A `None`
        // carrier does NOT mean "nothing prepared": the deduction + durable
        // record land BEFORE the carrier reaches `ctx`, so a lost Prepare-A reply
        // leaves `None` over a real durable deduction — reconciled below via the
        // record-based `Abort { None }` re-drive.
        // Used by BOTH arms: the `Some` carrier path (lookup + `Abort { Some }`)
        // and the `None` record-reconcile path (the `Abort { None }` re-drive).
        let caller_hex = hex::encode(ctx.caller_context_id);
        let caller_reversal = if let Some(reservation) = ctx.prepared_a.take() {
            if let Some(caller) = self.lookup(&caller_hex) {
                let abort_saga_id = saga_id.clone();
                // The Abort command carries the `#[must_use]` reservation (whose
                // `OutletEconomyTicket` debug-asserts on an unbalanced drop). Use
                // `send_recover_on_failure` — NOT the plain `send`, which drops
                // the built command (and its ticket) INSIDE the send on a
                // full/closed mailbox → a Drop panic under `--features testing`
                // and an escrow leak in release. On a send failure we get the
                // un-delivered command back, extract the reservation, void its
                // external escrow, and then RE-DRIVE the abort as `Abort { None }`
                // so the actor reverses the LOCAL economy from the durable
                // record (the carrier never reached the actor, so its per-context
                // LOCAL rollback could not run).
                let send_result = caller
                    .send_recover_on_failure(move |reply| {
                        ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
                            saga_id: abort_saga_id,
                            reservation: Some(Box::new(reservation)),
                            reply,
                        })
                    })
                    .await;
                match send_result {
                    // Delivered: the actor owns + balanced the ticket AND reversed
                    // its LOCAL budget / velocity / hard-rate-limit via the
                    // generation-checked carrier rollback. Fully compensated.
                    Ok(()) => CallerAbortReversal::SettledOrAbsent,
                    // Send NEVER delivered: the carrier never reached the actor,
                    // so its LOCAL rollback never ran. Recover the carrier and
                    // void + consume its external escrow (idempotent), THEN
                    // re-drive `Abort { None }` so the actor reverses the LOCAL
                    // economy from the durable `CallerReservationRecord` (and
                    // idempotently re-voids the same escrow). The local reversal
                    // is settled ONLY if that re-drive is delivered.
                    Err((err, Some(recovered_cmd))) => {
                        if let Some(reservation) = Self::extract_abort_reservation(recovered_cmd) {
                            reservation
                                .reservation
                                .ticket
                                .void_external_and_consume(self.payment_adapter_ref())
                                .await;
                            tracing::warn!(
                                saga_id = %saga_id.0,
                                %err,
                                "cross-context saga abort — caller-side Abort send failed; \
                                 recovered the held reservation and voided its external escrow, \
                                 re-driving Abort{{None}} to reverse the caller's LOCAL economy \
                                 from the durable record (the carrier never reached the actor)"
                            );
                            self.redrive_caller_local_reversal(saga_id, &caller_hex)
                                .await
                        } else {
                            // Unreachable in practice: the recovered command IS
                            // the Abort we built (carrying `Some` reservation). If
                            // a future refactor changes that, the ticket has
                            // nowhere to go — log loudly rather than silently leak
                            // (the carrier's drop guard then surfaces the bug).
                            // The LOCAL economy was NOT reversed: report it
                            // outstanding so the journal stays non-terminal.
                            tracing::error!(
                                event = "xctx_caller_reversal_outstanding",
                                saga_id = %saga_id.0,
                                %err,
                                "cross-context saga abort — recovered a non-Abort (or \
                                 reservation-less) command on send failure; the held \
                                 reservation could not be balanced and the caller's LOCAL \
                                 economy reversal is outstanding"
                            );
                            Self::reversal_outstanding()
                        }
                    }
                    // Delivered but the handler errored (or dropped the reply):
                    // the actor owns/consumed the ticket, but the handler may have
                    // failed BEFORE durably persisting the reversal (e.g. a
                    // Class-S persist failure after the in-memory rollback). A
                    // crash in that window would resurrect the deduction from the
                    // still-durable record, so the reversal is NOT confirmed
                    // durable — report it outstanding so the journal stays
                    // non-terminal and the (idempotent) sweep re-drives it.
                    Err((err, None)) => {
                        tracing::warn!(
                            event = "xctx_caller_reversal_outstanding",
                            saga_id = %saga_id.0,
                            %err,
                            "cross-context saga abort — caller-side Abort delivered but the \
                             handler errored; the caller's LOCAL economy reversal is not \
                             confirmed durable, leaving the journal non-terminal for the sweep"
                        );
                        Self::reversal_outstanding()
                    }
                }
            } else {
                // Caller actor is gone (despawned — `lookup` miss): its in-memory
                // per-context rollback cannot run, but the durable
                // `CallerReservationRecord` survives in the persisted snapshot
                // and a restored actor carries it. Void the carrier escrow +
                // consume the ticket so its unbalanced-drop guard does not fire,
                // then report the LOCAL reversal outstanding so the journal stays
                // non-terminal until a respawn + the §17.16.4 sweep reverses the
                // LOCAL economy from the record (we cannot reverse actor-owned
                // economy from the supervisor).
                reservation
                    .reservation
                    .ticket
                    .void_external_and_consume(self.payment_adapter_ref())
                    .await;
                tracing::warn!(
                    event = "xctx_caller_reversal_outstanding",
                    saga_id = %saga_id.0,
                    "cross-context saga abort — caller actor not co-resident; voided the external \
                     escrow and consumed the reservation ticket, leaving the journal non-terminal \
                     so a respawn + crash-recovery sweep reverses the caller's LOCAL economy from \
                     the durable record"
                );
                Self::reversal_outstanding()
            }
        } else {
            // `ctx.prepared_a` is `None`. This does NOT prove "nothing was
            // prepared": Prepare-A DURABLY persists the caller's deduction + the
            // `xctx_caller_reservations` record BEFORE the in-memory carrier
            // reaches `ctx.prepared_a`, so the carrier is absent whenever the
            // Prepare-A REPLY was lost — e.g. the §6.2.4 `dispatch_prepare_phase`
            // 30s phase-timeout fired and dropped the supervisor's reply receiver
            // even though the caller actor already committed the deduction +
            // record. Keying the caller reversal solely on the volatile carrier
            // would then leave the caller over-charged forever under a terminal
            // `Aborted` (the §17.16.4 startup sweep re-drives only NON-terminal
            // journals). So the durable record — not the carrier — is the source
            // of truth: drive a record-based `Abort { None }` to the caller (the
            // SAME path `redrive_caller_local_reversal` uses — re-`lookup` +
            // `Abort { None }`), which reverses the LOCAL economy from the record
            // if one exists and is a clean no-op (→ `SettledOrAbsent`) for a
            // genuinely-nothing-prepared saga. Folding its outcome into the
            // verdict makes EVERY abort path reconcile the durable record before
            // `mark_resolved(Aborted)`.
            self.redrive_caller_local_reversal(saga_id, &caller_hex)
                .await
        };

        // TARGET side (only if Prepare-B may have staged a slot). The target
        // carries no caller LOCAL economy, so its release is best-effort and
        // orthogonal to the returned `caller_reversal`.
        if ctx.prepared_b.is_some() {
            self.abort_target_leg(saga_id, ctx.target_context_id).await;
        }

        caller_reversal
    }

    /// Best-effort TARGET-side leg of a cross-context-saga abort: send
    /// `Abort { reservation: None }` so the target actor clears its staged
    /// `saga_pending` slot (releasing the session reservation). The target stages
    /// no `OutletEconomyTicket`, so a failed/undelivered send strands nothing — the
    /// next §17.16.4 crash-recovery sweep clears the slot — hence this never
    /// affects the caller-side reversal verdict. A `lookup` miss is a clean no-op
    /// (the despawned actor's snapshot carries the staged slot for the sweep).
    async fn abort_target_leg(&self, saga_id: &SagaId, target_context_id: [u8; 32]) {
        use crate::context::actor::commands::SagaPhaseMessage;
        let target_hex = hex::encode(target_context_id);
        let Some(target) = self.lookup(&target_hex) else {
            return;
        };
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

    /// Re-drive a caller-side cross-context-saga abort as `Abort { None }` so the
    /// caller actor reverses its LOCAL economy (budget / velocity /
    /// hard-rate-limit) from the durable `CallerReservationRecord` Prepare-A
    /// staged — the SAME path the §17.16.4 crash-recovery sweep
    /// ([`Self::redrive_xctx_prepare_in_progress`]) uses.
    ///
    /// Invoked by [`Self::abort_xctx_participants`] ONLY after the carrier
    /// `Abort { Some }` send failed and its external escrow was already
    /// voided+consumed; the `None` re-drive carries no ticket, so the LOCAL
    /// reversal (idempotently re-voiding the same escrow) is the only effect. The
    /// actor consumes the record on reversal, so this is a clean no-op if the
    /// record was already drained.
    ///
    /// Re-`lookup`s the caller actor afresh by `context_id` (rather than reusing
    /// the handle whose send just failed): a busy / shutting-down caller actor
    /// may have been despawned + respawned from its persisted snapshot in the
    /// interim, and the restored instance carries the durable
    /// `CallerReservationRecord`. A lookup miss means the actor is gone — the
    /// reversal cannot run here and stays outstanding for a respawn + sweep.
    ///
    /// Returns [`CallerAbortReversal::SettledOrAbsent`] iff the `None` re-drive
    /// was DELIVERED (the actor reversed + persisted the LOCAL economy);
    /// otherwise [`CallerAbortReversal::ReversalOutstanding`] so the coordinator
    /// leaves the journal non-terminal for the crash-recovery sweep — NEVER
    /// marking terminal-`Aborted` with the caller refund still pending.
    async fn redrive_caller_local_reversal(
        &self,
        saga_id: &SagaId,
        caller_hex: &str,
    ) -> CallerAbortReversal {
        use crate::context::actor::commands::SagaPhaseMessage;
        let Some(caller) = self.lookup(caller_hex) else {
            tracing::warn!(
                event = "xctx_caller_reversal_outstanding",
                saga_id = %saga_id.0,
                context = %caller_hex,
                "cross-context saga abort — caller actor not co-resident on Abort{{None}} \
                 re-drive; the caller's LOCAL economy reversal is outstanding, leaving the \
                 journal non-terminal so a respawn + crash-recovery sweep reverses it from \
                 the durable record"
            );
            return Self::reversal_outstanding();
        };
        let abort_saga_id = saga_id.clone();
        let result = caller
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::Abort {
                    saga_id: abort_saga_id,
                    reservation: None,
                    reply,
                })
            })
            .await;
        match result {
            Ok(()) => CallerAbortReversal::SettledOrAbsent,
            Err(err) => {
                tracing::warn!(
                    event = "xctx_caller_reversal_outstanding",
                    saga_id = %saga_id.0,
                    %err,
                    "cross-context saga abort — caller-side Abort{{None}} re-drive also failed \
                     (persistent backpressure / closed inbox); the caller's LOCAL economy \
                     reversal is outstanding, leaving the journal non-terminal for the sweep"
                );
                Self::reversal_outstanding()
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

    /// Resolve a streaming-saga journal entry to `Committed` (SCP-OUT-046 #134).
    ///
    /// Called by the off-mailbox seal task
    /// ([`run_streaming_saga_seal_task`](crate::context::outlets::invoke::run_streaming_saga_seal_task))
    /// once [`SagaPhaseMessage::CommitBStreamSettle`](crate::context::actor::commands::SagaPhaseMessage::CommitBStreamSettle)
    /// has durably sealed the stream, so the autonomous crash-recovery sweep does
    /// not redrive a completed saga. `secret_bearing = false`: the streaming saga
    /// journals public metadata only (the manifest root + provenance, never chunk
    /// bytes or bearer material — [`saga_input_is_secret_bearing`] returns
    /// `false` for its input).
    ///
    /// # Errors
    ///
    /// [`ContextError::InvalidState`] wrapping the [`JournalError`](scp_runtime_types::context::supervisor::saga_journal::JournalError) if the
    /// durable `mark_resolved` write fails; the caller logs and defers to the
    /// crash-recovery sweep (the durable committed witness on B's actor is the
    /// authoritative resolution regardless).
    pub(in crate::context) async fn resolve_saga_committed(
        &self,
        saga_id: &SagaId,
    ) -> Result<(), ContextError> {
        self.saga_journal
            .mark_resolved(saga_id.clone(), SagaTerminalState::Committed, false)
            .await
            .map_err(|e| {
                ContextError::InvalidState(format!(
                    "streaming-saga journal mark_resolved(Committed) failed: {e}"
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
    // Each method forwards to its `*_helpers` free function
    // (`queries_helpers` / `lifecycle_helpers`), which holds the
    // supervisor-wide implementation. There is no manager indirection.
    // ---------------------------------------------------------------

    /// Register a DID as locally controlled by this node / SDK.
    ///
    /// Idempotent: registering the same DID twice is a no-op. Infallible: the
    /// registration is an insert into the supervisor-wide local-DID set.
    pub async fn register_local_did(&self, did: DID) {
        crate::context::shared::queries::register_local_did(self, did).await;
    }

    /// Returns `true` iff `did` is registered as locally controlled.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(_)`.
    pub async fn is_local_did(&self, did: &DID) -> Result<bool, ContextError> {
        Ok(crate::context::shared::queries::is_local_did(self, did).await)
    }

    /// Restore every persisted context from the configured persistence
    /// provider.
    ///
    /// Returns a [`RestoredContexts`] witness carrying the restored context IDs.
    /// Contexts in `Closing` / `Closed` / `Expired` states are skipped (only
    /// `Active` contexts are resurrected after a restart).
    ///
    /// The returned token is also the §17.16.4 ordering PROOF: it is the only
    /// way to obtain a [`RestoredContexts`], and [`Self::replay_unresolved_sagas`]
    /// requires one — so replay cannot run before this restore at the type level.
    /// Call [`RestoredContexts::ids`] / [`RestoredContexts::into_ids`] to read the
    /// IDs.
    ///
    /// **Visibility (`pub(crate)`, intentional — restore-implies-replay seal).**
    /// Narrowed from `pub` to `pub(crate)` so the bare restore leg cannot be
    /// reached cross-crate: a future bridge could otherwise call this directly,
    /// take [`RestoredContexts::into_ids`], and silently skip the §17.16.4
    /// saga-journal replay. Closing the visibility forces every cross-crate
    /// startup/resume caller through [`Self::restore_on_startup`], which runs
    /// restore THEN replay. The witness already enforces "no replay before
    /// restore" by construction; this `pub(crate)` closes the dual seam ("no
    /// restore without replay") at the compiler. In-crate callers
    /// ([`Self::restore_on_startup`] and the in-crate tests) are unaffected.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PersistenceFailed`] if the persistence
    ///   provider is unconfigured or `list_persisted_contexts` fails.
    pub(crate) async fn restore_all_contexts(
        self: &Arc<Self>,
    ) -> Result<RestoredContexts, ContextError> {
        let ids = self.domains.lifecycle.restore_all_contexts(self).await?;
        Ok(RestoredContexts::new(ids))
    }

    /// Single process-startup recovery entry point (ADR-049).
    ///
    /// Runs the two startup sweeps in the order §17.16.4 requires —
    /// **restore, THEN reconcile**:
    ///
    /// 1. `Self::restore_all_contexts` — rehydrate every persisted `Active`
    ///    context's actor from the persistence provider, so every participant a
    ///    recovery arm must drive is RESIDENT.
    /// 2. [`Self::replay_unresolved_sagas`] — sweep the durable saga journal and
    ///    reconcile every unresolved entry left by a crash mid-saga.
    ///
    /// **Restore MUST precede replay.** Every saga-recovery arm that has to
    /// reach a live actor — the cross-context caller whose LOCAL-economy
    /// reversal is re-driven (see `Self::recover_preparing_b_entry`), and a
    /// Commit-in-progress re-send to all participants — needs that actor
    /// resident; NO arm needs the inverse (observing a participant *before* it
    /// is restored). Restoring first makes the caller resident, so the
    /// record-keyed reversal (`Abort { None }`, idempotent: it consumes the
    /// durable caller reservation record exactly once and is a no-op if that
    /// record was already drained — the live RAII guard died with the crash)
    /// is delivered in this same pass and the journal reaches terminal-`Aborted`
    /// with the caller's refund applied. There is NO separate post-restore
    /// sweep; reconciliation runs once, here, after restore. A reversal is left
    /// NON-terminal for the NEXT process start only when it is genuinely
    /// undeliverable (caller context failed to restore, or its persistence
    /// existence cannot be confirmed). Folding both sweeps behind this one
    /// method makes it impossible for a bridge to invoke one without the other,
    /// or in the wrong order.
    ///
    /// Returns the list of restored context IDs (the `restore_all_contexts`
    /// result). Replay's per-entry outcomes are observable on the saga journal,
    /// not in the return value.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PersistenceFailed`] if the persistence provider is
    ///   unconfigured or `list_persisted_contexts` fails. Restore runs first, so
    ///   a restore failure short-circuits before any saga is reconciled (the
    ///   unresolved entries stay unresolved for the next process start — fail
    ///   closed).
    /// - Any [`ContextError`] surfaced by [`Self::replay_unresolved_sagas`]
    ///   (e.g. a saga-journal load failure) after a successful restore. Such a
    ///   replay failure surfaces; the still-unresolved sagas are carried to the
    ///   next restart.
    pub async fn restore_on_startup(self: &Arc<Self>) -> Result<Vec<String>, ContextError> {
        // §17.16.4: restore BEFORE replay. The order is enforced by the TYPE
        // SYSTEM, not just this line: `replay_unresolved_sagas` requires the
        // `&RestoredContexts` witness that `restore_all_contexts` returns, so a
        // reordered "replay first" body would have no token to pass and would not
        // compile (see the `compile_fail` doctest on `replay_unresolved_sagas`).
        // Recovery arms drive now-resident actors (the caller reversal, the
        // Commit re-send), so restore must make them resident first.
        let restored = self.restore_all_contexts().await?;
        self.replay_unresolved_sagas(&restored).await?;
        Ok(restored.into_ids())
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::restore_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Exports the full state of a context as a transferable, signed
    /// [`ContextExport`](crate::context::export_import::ContextExport)
    /// (§23.16.8, ADR-050).
    ///
    /// The per-context actor captures the snapshot and Merkle event-log data
    /// and signs the canonical snapshot digest
    /// (`SHA-256("SCP-CONTEXT-EXPORT-V1:" || scope-tag-byte || JCS(snapshot))`)
    /// through `signer` in the same turn (ADR-049 Decision 7a), so a custody
    /// that never answers fails the export after `SIGN_TIMEOUT`.
    ///
    /// The exporter MUST be the snapshot `creator_did` (the importer enforces
    /// `exporter_did == creator_did`), and `signer` holds that DID's key.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context does not exist, the actor reply
    /// channel closes, event-log export or Merkle verification fails, canonical
    /// hashing fails, or the sign fails: [`ContextError::Custody`] keeps the
    /// custody failure's kind (`TimedOut`, SCP-CRYPTO-4062, past
    /// `SIGN_TIMEOUT`), and [`ContextError::CryptoFailed`] names a signer that
    /// is not Ed25519.
    pub async fn export_context(
        self: &Arc<Self>,
        context_id: &str,
        exporter_did: DID,
        signer: &crate::context::actor::CommandSigner,
    ) -> Result<crate::context::export_import::ContextExport, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ExportContext {
            context_id: context_id.to_owned(),
            exporter_did,
            signer: signer.clone(),
            reply: tx,
        };
        self.dispatch_lifecycle_command(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::export_context — actor reply channel closed".to_owned(),
            )
        })?
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::import_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Flushes every context's snapshot to the configured persistence
    /// provider (ADR-049 Decision 9).
    ///
    /// No-op if no persistence provider is configured.
    ///
    /// # Errors
    ///
    /// The first context's flush failure when any flush did not land; see
    /// [`crate::context::shared::lifecycle::flush_all_contexts`].
    pub async fn flush_all_contexts(&self) -> Result<(), ContextError> {
        crate::context::shared::lifecycle::flush_all_contexts(self).await
    }

    /// Shut down every context the supervisor owns and wait for every task
    /// the supervisor spawned to exit (ADR-049 Decision 16, supervisor task
    /// drain; local cleanup only).
    ///
    /// In order: sets the closed flag; destroys each
    /// context's sender keys, MLS group, and event log through its actor
    /// (release secrets before tearing down structure; `SenderKey`s, the MLS
    /// group's signer, and its provider-storage values zeroize on drop) and
    /// removes the actor from the registry; stops every key-package actor and
    /// clears `key_package_stores`; clears the standing-context index, the
    /// local-DID registry, and the per-identity wrapping keys; closes the task
    /// tracker and awaits it. Returns only after every tracked task has
    /// exited, so the caller may then close the storage backend it passed to
    /// the supervisor (§17.6 of the persistence spec, One Opener per Durable
    /// Directory). Imposes no deadline of its own.
    ///
    /// Does NOT send leave messages or notify remote peers. A second call
    /// finds nothing left to stop and returns once the tracker is empty.
    ///
    /// Infallible: a per-context mailbox failure is logged and does not stop
    /// the sweep, because the actor is despawned either way, which closes its
    /// inbox. Returning means the drain finished.
    pub async fn shutdown_all_contexts(&self) {
        self.domains.lifecycle.shutdown_all_contexts(self).await;
    }

    /// Runs [`Self::shutdown_all_contexts`] and then `after_drain` on a task
    /// of their own, and waits for that task until `deadline`. The deadline
    /// bounds only the wait, never the drain: the task is never aborted, so
    /// `after_drain` (for example, closing the durable store) runs only once
    /// every tracked task has exited. The task holds this Supervisor until the
    /// drain returns and drops it before `after_drain` runs.
    ///
    /// When the deadline passes first, the task keeps running, `on_late`
    /// receives its result once it ends (`Err` carrying the payload-free
    /// [`JoinFailure`] when the drain task did not return), and this returns
    /// [`DrainWithDeadline::TimedOut`].
    pub async fn drain_with_deadline<T, A, L>(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
        after_drain: A,
        on_late: L,
    ) -> DrainWithDeadline<T>
    where
        T: Send + 'static,
        A: FnOnce() -> T + Send + 'static,
        L: FnOnce(Result<T, JoinFailure>) + Send + 'static,
    {
        let supervisor = Arc::clone(self);
        let mut drain = tokio::spawn(async move {
            supervisor.shutdown_all_contexts().await;
            drop(supervisor);
            after_drain()
        });
        match tokio::time::timeout_at(deadline, &mut drain).await {
            Ok(Ok(value)) => DrainWithDeadline::Finished(value),
            Ok(Err(join_error)) => {
                DrainWithDeadline::Failed(JoinFailure::from_join_error(&join_error))
            }
            Err(_elapsed) => {
                drop(tokio::spawn(async move {
                    on_late(
                        drain
                            .await
                            .map_err(|join_error| JoinFailure::from_join_error(&join_error)),
                    );
                }));
                DrainWithDeadline::TimedOut
            }
        }
    }

    /// Refuses `operation` with [`ContextError::SupervisorShutDown`] once
    /// [`Self::shutdown_all_contexts`] has begun (ADR-049 Decision 16). For a
    /// read of state that shutdown clears, so the caller reports shutdown
    /// rather than the cleared state's absence.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] once the closed flag is set.
    pub(in crate::context) fn refuse_if_shut_down(
        &self,
        operation: &str,
    ) -> Result<(), ContextError> {
        let closed = *self
            .spawn_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if closed {
            return Err(ContextError::SupervisorShutDown(format!(
                "{operation} refused: shutdown_all_contexts has begun"
            )));
        }
        Ok(())
    }

    /// Issues a [`SpawnPermit`] for the Supervisor's task tracker, or refuses
    /// once [`Self::shutdown_all_contexts`] has begun (ADR-049 Decision 16).
    ///
    /// `operation` names the refused spawn in the error. A poisoned flag lock
    /// is recovered: the flag is a plain `bool` that a panic cannot leave half
    /// written.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] once the closed flag is set.
    pub(in crate::context) fn spawn_permit(
        &self,
        operation: &str,
    ) -> Result<SpawnPermit<'_>, ContextError> {
        let closed = self
            .spawn_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *closed {
            return Err(ContextError::SupervisorShutDown(format!(
                "{operation} refused: the supervisor starts no task once \
                 shutdown_all_contexts has begun"
            )));
        }
        Ok(SpawnPermit {
            tracker: &self.task_tracker,
            _closed: closed,
        })
    }

    /// Spawns `future` onto the Supervisor's task tracker, or refuses once
    /// shutdown has begun (ADR-049 Decision 16). For a spawn that must also
    /// register state the drain reads, take a [`Self::spawn_permit`] and
    /// register under it instead.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] once the closed flag is set; the
    /// future is dropped without running.
    pub(in crate::context) fn spawn_tracked<F>(
        &self,
        operation: &str,
        future: F,
    ) -> Result<tokio::task::JoinHandle<F::Output>, ContextError>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.spawn_permit(operation)?;
        Ok(permit.spawn(future))
    }

    /// Spawns `future`, a hand-off of kind `kind`, onto the Supervisor's task
    /// tracker on `runtime`, for a caller that can run off any runtime thread
    /// (a `Drop`). Unlike [`Self::spawn_tracked`], it accepts the spawn after
    /// the closed flag is set when the caller is itself a tracked task: the
    /// tracker is not empty while the caller runs, so the drain awaits the
    /// spawned task. `kind` is a [`SinkHandoff`], so a caller can name only one
    /// of the two kinds ADR-049 Decision 16 item 2 admits after the flag is
    /// set.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] once the closed flag is set and the
    /// caller is not a tracked task; the future is dropped without running.
    pub(in crate::context) fn spawn_tracked_on<F>(
        &self,
        kind: SinkHandoff,
        future: F,
        runtime: &tokio::runtime::Handle,
    ) -> Result<tokio::task::JoinHandle<F::Output>, ContextError>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let gate = self
            .spawn_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *gate && !in_tracked_task(&self.task_tracker) {
            return Err(ContextError::SupervisorShutDown(format!(
                "{} refused: the supervisor starts no task for a caller \
                 outside its tracker once shutdown_all_contexts has begun",
                kind.label()
            )));
        }
        // The read guard is held across the spawn, so shutdown cannot set the
        // flag between the check and the spawn.
        let handle = self.task_tracker.spawn_on(
            tracked_task_marker().scope(self.task_tracker.clone(), future),
            runtime,
        );
        drop(gate);
        Ok(handle)
    }

    /// Issues a [`TrackedSpawner`] for an operation that spawns tasks after
    /// `.await`s of its own. Refused once the closed flag is set, from any
    /// caller: item 2's first exception covers handing a settlement or its
    /// `OutletInvokedEvent` append to a task, not starting an operation.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] once the closed flag is set.
    pub(in crate::context) fn tracked_spawner(
        &self,
        operation: &str,
    ) -> Result<TrackedSpawner, ContextError> {
        let gate = self
            .spawn_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *gate {
            return Err(ContextError::SupervisorShutDown(format!(
                "{operation} refused: the supervisor starts no operation once \
                 shutdown_all_contexts has begun"
            )));
        }
        // The token is taken under the read guard, and the drain sets the flag
        // before it waits, so the drain counts the token.
        let spawner = TrackedSpawner {
            tracker: self.task_tracker.clone(),
            _token: self.task_tracker.token(),
        };
        drop(gate);
        Ok(spawner)
    }

    /// Records one crash at `now_ms` in the crash window keyed `key` and
    /// returns `(poisoned, crash_count)`, or records nothing and returns `None`
    /// once the closed flag is set (ADR-049 Decision 16 item 2). With
    /// `respawn_failed`, it also sets the failed-respawn flag and clears the
    /// respawn marker. The two watchdogs and `record_respawn_failure` record a
    /// crash only through this method.
    ///
    /// The record is made under the flag's read guard, and
    /// [`Self::close_spawn_gate`] takes the write guard, so every record this
    /// method makes precedes the close.
    fn record_crash_while_open(
        &self,
        key: &str,
        now_ms: u64,
        respawn_failed: bool,
    ) -> Option<(bool, usize)> {
        let closed = self
            .spawn_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *closed {
            return None;
        }
        let mut entry = self.crash_windows.entry(key.to_owned()).or_default();
        if respawn_failed {
            entry.mark_respawn_failed();
            // The respawn attempt has resolved (in failure): clear the
            // transient mid-respawn marker so a subsequent lookup-miss reflects
            // the now-stable failed/poisoned state, not "respawning".
            entry.clear_respawning();
        }
        let poisoned = entry.record(now_ms);
        let count = entry.crash_count();
        drop(entry);
        drop(closed);
        Some((poisoned, count))
    }

    /// Sets the closed flag (ADR-049 Decision 16, step 2). Blocks only until
    /// every live [`SpawnPermit`] drops, and a permit is never held across an
    /// `.await`, so the wait is bounded by one synchronous spawn. Then cancels
    /// the shutdown token every streaming pump selects on.
    pub fn close_spawn_gate(&self) {
        *self
            .spawn_gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.shutdown_token.cancel();
    }

    /// The token [`Self::close_spawn_gate`] cancels when shutdown begins.
    /// A tracked task that can wait without bound selects on it, so
    /// `shutdown_all_contexts`, which awaits every tracked task, ends.
    pub(in crate::context) fn shutdown_signal(&self) -> tokio_util::sync::CancellationToken {
        self.shutdown_token.clone()
    }

    /// Stops every challenger-ledger actor and clears `challenger_ledgers`
    /// (ADR-049 Decision 16, step 3), as [`Self::stop_key_package_actors`]
    /// does for the key-package actors. The ledger is durable, so a stopped
    /// actor loses only its in-memory grading leases.
    pub async fn stop_challenger_ledger_actors(&self) {
        let handles: Vec<(
            String,
            crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerHandle,
        )> = {
            let _guard = self.write_lock.lock().await;
            let drained = self
                .challenger_ledgers
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect();
            self.challenger_ledgers.clear();
            drained
        };
        for (identity, handle) in handles {
            if let Err(e) = handle.send_shutdown().await {
                tracing::warn!(
                    identity = %identity,
                    error = %e,
                    "shutdown: challenger-ledger actor did not accept Shutdown; its inbox \
                     closes when the last handle drops"
                );
            }
        }
    }

    /// Stops every key-package actor and clears `key_package_stores`
    /// (ADR-049 Decision 16, step 3). The map is drained under the write lock
    /// so no resolver observes a half-cleared map; the shutdown commands are
    /// sent after the lock drops. A send that fails (inbox closed or full) is
    /// logged and is not fatal: dropping the last handle closes the actor's
    /// inbox, and the actor's run loop exits on the closed inbox.
    pub async fn stop_key_package_actors(&self) {
        let handles: Vec<(DID, KeyPackageStoreHandle)> = {
            let _guard = self.write_lock.lock().await;
            let drained = self
                .key_package_stores
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect();
            self.key_package_stores.clear();
            drained
        };
        for (identity, handle) in handles {
            if let Err(e) = handle.send_shutdown().await {
                tracing::warn!(
                    identity = %identity.0,
                    error = %e,
                    "shutdown: key-package actor did not accept Shutdown; its inbox closes \
                     when the last handle drops"
                );
            }
        }
    }

    /// Closes the task tracker and waits until every tracked task has exited
    /// (ADR-049 Decision 16, step 3). Call only after the closed flag is set
    /// and every actor was told to stop.
    ///
    /// Once the wait returns, removes every non-poison crash-window entry so
    /// none leaks past teardown (ADR-049 §10); a poisoned entry stays. The
    /// removal runs here rather than per swept id because a watchdog or
    /// respawn task can despawn its actor before the sweep's snapshot, or
    /// write a window after the sweep, and no such task remains once the wait
    /// returns.
    pub async fn await_tracked_tasks(&self) {
        self.task_tracker.close();
        self.task_tracker.wait().await;
        self.crash_windows.retain(|_, window| window.is_poisoned());
    }

    // -------------------------------------------------------------------
    // ADR-049 §15 — FFI passthrough surface.
    //
    // The 4 FFI bridges (PyO3, NAPI, UniFFI, common) hold an
    // `Arc<Supervisor>` and invoke the methods below directly. They cover
    // the small subset of supervisor operations the bridge functions
    // actually call (membership queries, event-log probes, hard-rate-
    // limit consumption, broadcast key resolution, outlet invocation,
    // lifecycle creation in tests).
    //
    // Each method is intentionally a thin one-liner over the equivalent
    // `*_helpers::X(&self, ...)` free function (or, where the op has a
    // per-context actor, the mailbox-routed dispatch). There is no
    // `ContextManager` indirection — these are direct helper / mailbox
    // calls.
    // -------------------------------------------------------------------

    /// Reads the current lifecycle
    /// [`ContextState`](scp_protocol::context::ContextState) for
    /// `context_id`, or `None` when this call got no answer from an actor
    /// for it: no actor serves the id, or the actor is busy, mid-respawn, or
    /// past a failed respawn (see the collapse paragraph below).
    ///
    /// Unlike the other query passthroughs, this does NOT route through
    /// [`Self::dispatch_query`]: that method falls through to
    /// `Self::dispatch_queries_direct` (which fabricates the legacy
    /// unknown-context default) when no actor is registered. The standing
    /// get-or-create path needs to distinguish "actor exists and is in
    /// state X" from "no actor at all", so this helper does the
    /// `Self::lookup` explicitly: a missing actor resolves to `None`
    /// (no mailbox, no reply), and a present actor's mailbox reply is
    /// surfaced as `Some(state)`.
    ///
    /// Close does NOT despawn the per-context actor, so
    /// `lookup(id).is_some()` alone cannot tell a live context from a
    /// terminal one — this query is the read-only lifecycle probe that
    /// makes that distinction without a `per-context-state Mutex`. A
    /// dropped reply or mailbox-send failure (actor shutting down)
    /// resolves to `None`, treated by callers as "no live context". A TTL
    /// expiry is the exception to the close rule: once the expiry's cleanup
    /// completes and the `Expired` state is durable, the actor despawns
    /// itself and the context reads `None`. While an incomplete expiry is
    /// retrying, the actor stays registered and answers `Some(Expired)`.
    ///
    /// This form collapses an unreachable actor into the same `None` a
    /// never-registered context reports, so a caller that reads `None` as
    /// "the context is gone" reads a saturated or wedged actor that way too.
    /// A caller whose decision turns on that difference calls
    /// [`Self::read_context_state_checked`], which reports an unreachable
    /// actor as [`ContextError::ActorBusy`].
    #[must_use]
    pub async fn read_context_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextState> {
        // A busy or crashed actor answers `Err` here. No caller of
        // this form treats `None` as an authorization: each reads it as "no
        // live Active context" and declines the Active-only work. The
        // reconnect sweep skips the id, and the outlet-stream saga gates on
        // all three bridges refuse the stream unless both states read
        // `Some(Active)`. Folding the error into `None` therefore grants
        // nothing. A new caller must hold the same property; a caller whose
        // decision turns on absence, such as the standing get-or-create
        // choosing to create or a close reading `None` as "the close already
        // happened", calls `read_context_state_checked` instead.
        self.read_context_state_checked(context_id)
            .await
            .unwrap_or(None)
    }

    /// Reads the current lifecycle
    /// [`ContextState`](scp_protocol::context::ContextState) for
    /// `context_id` and reports an actor this call could not reach as an
    /// error rather than as an absent actor.
    ///
    /// [`Self::read_context_state`] answers `None` for three different
    /// outcomes: the supervisor holds no actor for the id, the mailbox send
    /// failed or exceeded
    /// [`SEND_TIMEOUT`](crate::context::actor::SEND_TIMEOUT), and the actor
    /// accepted the command but did not answer within
    /// [`REPLY_TIMEOUT`](crate::context::actor::REPLY_TIMEOUT). A caller that
    /// treats `None` as proof that the supervisor stopped serving the context
    /// therefore draws that conclusion from a context whose actor is merely
    /// saturated or wedged. A caller that draws that conclusion to skip a
    /// dispatch whose capability check the actor runs, such as a bridge's
    /// `context_close` skipping the `CloseContext` dispatch that carries the
    /// only `ContextClose` check on its path, reads this form.
    ///
    /// `Ok(None)` means the supervisor holds no actor for `context_id`, no
    /// sticky poison flag for it, and no crash-window record that it is
    /// mid-respawn or that its last respawn failed. A context whose TTL
    /// expiry completed reads `Ok(None)`: its actor despawns itself once the
    /// cleanup completes and the `Expired` state is durable. While an
    /// incomplete expiry is retrying, the actor stays registered and the read
    /// returns `Ok(Some(Expired))`. `Ok(Some(state))` is the actor's own
    /// answer,
    /// or [`ContextState::Poisoned`](scp_protocol::context::ContextState::Poisoned)
    /// for a context the crash watchdog poisoned and despawned (ADR-049 §10).
    ///
    /// `Ok(None)` is the only absent answer. Every error below names a context
    /// the supervisor still serves or is recovering, so a caller that
    /// enumerates contexts keeps the id or fails on an error, and never drops
    /// the id as absent.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] when an actor is registered for
    ///   `context_id` and the mailbox send failed or timed out, or the actor
    ///   did not answer within `REPLY_TIMEOUT`.
    /// - [`ContextError::ActorCrashed`] when no actor is registered for
    ///   `context_id` because the crash watchdog despawned it and has not yet
    ///   re-registered the replacement, because an operator's `clear_poison`
    ///   cleared its poison flag and has not yet respawned it, because an
    ///   import despawned it and
    ///   has not yet registered the imported actor, or because its last
    ///   respawn failed and the context is not yet poisoned (ADR-049 §10).
    /// - Whatever error the `ReadContextState` handler itself returned.
    pub async fn read_context_state_checked(
        &self,
        context_id: &str,
    ) -> Result<Option<scp_protocol::context::ContextState>, ContextError> {
        let actor = if let Some(actor) = self.lookup(context_id) {
            actor
        } else {
            // No live actor. A poisoned context (ADR-049 §10) has been
            // despawned by the watchdog, so its state is no longer readable
            // from a mailbox — it lives in the sticky `crash_windows` poison
            // flag. Report `Poisoned` so a caller observes a poisoned
            // context as poisoned (ADR-049 §10: "`read_context_state`
            // reports `Poisoned`") rather than as "unknown" (`None`).
            // A context whose actor the watchdog despawned for a respawn it
            // has not finished, or whose last respawn failed below the poison
            // threshold, still exists (ADR-049 §10); `lookup_miss_error`
            // reports both as `ActorCrashed`, and so does this read, so that
            // no caller mistakes a crashed context for one the supervisor
            // stopped serving. Only an id with no actor and no crash-window
            // signal reads as `None`.
            //
            // The poison flag and the respawn markers are read from ONE
            // `crash_windows` guard. A failed bootstrap's
            // `BootstrapCrashWindow::drop` swaps a marker-only window for the
            // prior poisoned one in a single insert; two separate reads could
            // see the fresh window's clear poison flag and then the restored
            // window's clear markers, and report a poisoned context as absent.
            let crash_signal = self.crash_windows.get(context_id).map(|window| {
                (
                    window.is_poisoned(),
                    window.is_respawning() || window.last_respawn_failed(),
                )
            });
            match crash_signal {
                Some((true, _)) => {
                    return Ok(Some(scp_protocol::context::ContextState::Poisoned));
                }
                Some((false, true)) => {
                    return Err(ContextError::ActorCrashed(context_id.to_owned()));
                }
                Some((false, false)) | None => {}
            }
            // The reads above hold no lock across them, so the miss can be
            // stale: a respawn (`respawn_rebuild_and_restore`) or an
            // import-replace (`import_context`) that was in its gap when
            // `lookup` ran may have registered the replacement actor and then
            // cleared the respawn marker before `crash_windows` was read. Both
            // writers register the actor BEFORE they clear the marker, so a
            // clean window read here means a second `lookup` sees any actor
            // that closed the gap, and the read queries that actor instead of
            // reporting an Active context as absent.
            match self.lookup(context_id) {
                Some(actor) => actor,
                None => return Ok(None),
            }
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Queries(QueriesCommand::ReadContextState {
            context_id: context_id.to_owned(),
            reply: tx,
        });
        Self::dispatch_via_mailbox(&actor, cmd).await?;
        match bounded_reply_await(rx).await {
            Ok(Ok(state)) => Ok(Some(state)),
            Ok(Err(handler_error)) => Err(handler_error),
            Err(reply_error) => Err(ContextError::ActorBusy(format!(
                "context '{context_id}' has a live actor that did not answer a lifecycle-state \
                 read ({reply_error:?}); the supervisor still serves this context"
            ))),
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
    /// 2. Liveness check via [`Self::read_context_state_checked`]: if a
    ///    per-context actor exists AND its lifecycle state is
    ///    [`Active`](scp_protocol::context::ContextState::Active) or
    ///    [`Creating`](scp_protocol::context::ContextState::Creating),
    ///    track the peer and return the existing id. A terminal state
    ///    (`Closed` / `Expired` / `Closing` / `MigratingOut` /
    ///    `Tombstoned`), a dormant context (`Poisoned`, or no actor after a
    ///    failed respawn below the poison threshold), or an absent context
    ///    (`Ok(None)`) falls through to create — a dead standing context is
    ///    never reused, and nothing retries a failed respawn, so waiting
    ///    would only defer the recreate to a restart. Any other error means
    ///    the context is present but unreachable (a registered actor that
    ///    did not answer), so it is returned and nothing is created over the
    ///    context (ADR-049 §10).
    /// 3. Create a fresh bilateral-persistent context through the
    ///    actor-shape `scp_runtime_lifecycle::helpers::create_context`
    ///    (membership, roles, governance, owned-state actor spawn), with
    ///    `local_did` as creator — mirroring the
    ///    [`LifecycleCommand::CreateContext`]
    ///    deps build in [`Self::dispatch_lifecycle_direct`].
    /// 4. TOCTOU: a concurrent caller may have created the context
    ///    between the step-2 check and the step-3 create. On create
    ///    error, re-probe [`Self::read_context_state_checked`]; if it is now
    ///    `Active` / `Creating`, treat the create as idempotently
    ///    successful. Otherwise propagate
    ///    [`ContextError::TransportFailed`].
    /// 5. Track the peer in the supervisor standing index (ArcSwap +
    ///    `write_lock`, ADR-049 §Decision 12) and return the id.
    ///
    /// # Errors
    ///
    /// - Whatever error [`Self::read_context_state_checked`] returns at
    ///   step 2 for a context it does not recreate: [`ContextError::ActorBusy`]
    ///   for a registered actor that did not answer.
    /// - [`ContextError::TransportFailed`] if context creation fails and no
    ///   concurrent creation resolved the id.
    pub(in crate::context) async fn standing_context(
        self: &Arc<Self>,
        local_did: &DID,
        peer_did: &DID,
        relay_urls: Vec<String>,
    ) -> Result<String, ContextError> {
        use scp_protocol::context::ContextState;

        let context_id =
            crate::context::shared::standing::generate_standing_context_id(local_did, peer_did);

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
        // `track_standing_peer` / `spawn_actor_with_state`). The local
        // identity's wrapping key loads first, outside both locks, so no
        // custody call runs under either.
        self.load_wrapping_key(local_did).await?;
        let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;

        // Step 1/2: existence + liveness probe. The decision to create turns
        // on absence, so this reads the checked form (ADR-049 §10). Only
        // Active/Creating short-circuits to reuse; every terminal state and
        // `Ok(None)` (no actor, no crash signal) fall through to create.
        //
        // A dormant context also falls through, and the recreate revives it:
        // a poisoned one (`Poisoned`), and one with no actor whose last
        // respawn failed below the poison threshold (`ActorCrashed`). Nothing
        // retries a failed respawn: the watchdog is done with the id, no
        // further crash can reach the poison threshold without an actor, and
        // `clear_poison` has no operator surface (ADR-049 §10, "Recovery-
        // surface honesty"). Refusing the failed-respawn case would wedge the
        // pair until a restart while a poisoned pair, three crashes further
        // along, revives at once. Under `bootstrap_spawn_lock` no respawn
        // marker can be set (every marker writer holds the lock), so the
        // window read below is stable against the checked read's answer.
        //
        // Every other error is a present, unreachable context (`ActorBusy` for
        // a registered actor that did not answer), and it is returned rather
        // than creating over the id.
        let dormant = match self.read_context_state_checked(&context_id).await {
            Ok(Some(ContextState::Active | ContextState::Creating)) => {
                self.track_standing_peer(peer_did).await;
                return Ok(context_id);
            }
            Ok(Some(ContextState::Poisoned)) => Some("poisoned"),
            Ok(_) => None,
            Err(ContextError::ActorCrashed(_))
                if self.lookup(&context_id).is_none()
                    && self.crash_windows.get(&context_id).is_some_and(|window| {
                        window.last_respawn_failed() && !window.is_respawning()
                    }) =>
            {
                Some("respawn_failed")
            }
            Err(e) => return Err(e),
        };

        // Step 3: create a new bilateral-persistent context via the
        // actor-shape create flow. Mirrors the `CreateContext` arm of
        // `dispatch_lifecycle_direct`: build deps scoped to the creator,
        // then `lifecycle_helpers::create_context`. Recreating this
        // deterministic standing id is a fresh start: the recreated standing
        // actor begins with a clean budget, free of stale crash history and a
        // stale poison; a recreate that registers no actor restores that
        // history when `_crash_window` drops. A dormant standing context
        // (poisoned, or past a failed respawn) reaches here from the step-2
        // probe; the automatic recreate resets its budget, which is correct —
        // a standing pair re-contacting each other after a poison must get a
        // working context, not inherit a sticky poison (ADR-049 §10).
        //
        // Observability: a revive drops the dormant window for good, which
        // would defeat the operator-recovery property for deterministic-id
        // contexts if it were silent (a flapping standing pair would keep
        // auto-reviving with no audit trail). A distinct, payload-free
        // operator-audit warning records each revive once the recreate has
        // registered an actor; a recreate that registers none restores the
        // dormant window and logs no revive.
        //
        // FOLLOW-UP: rate-limited auto-revival (e.g. refusing to auto-revive a
        // standing id more than N times in a window, forcing operator
        // intervention on a persistently-flapping pair) is a future hardening;
        // today the recreate is unconditional but now observable.
        let crash_window = self.begin_bootstrap_window(&context_id);
        let params = scp_protocol::context::templates::template_params(
            &scp_protocol::context::TemplateId::BilateralPersistent,
        );
        let (create_result, first_state) = match self.build_actor_deps(local_did).await {
            Ok(deps) => {
                // A recreate that fails puts back what it wrote (ADR-029
                // Implementation), after the lock is released below.
                let first_state =
                    crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &context_id)?;
                let created = deps
                    .domains
                    .lifecycle
                    .create_context(
                        &deps,
                        crate::context::domains::CreateContextRequest {
                            context_id: context_id.clone(),
                            params,
                            creator_did: local_did.clone(),
                            local_pseudonym: None,
                            // §5.12.3.1: the local identity's relays host the
                            // recreated standing context (PUSH-025).
                            relay_urls,
                            first_state: &first_state,
                        },
                    )
                    .await
                    .map(|spawned| (deps.clone_for_spawn(), spawned))
                    .map_err(|e| match e {
                        scp_protocol::context::builder::ContextCreationError::StateTransition(
                            inner @ ContextError::SupervisorShutDown(_),
                        ) => inner,
                        other => ContextError::TransportFailed(other.to_string()),
                    });
                (created, Some(first_state))
            }
            // A shutdown refusal keeps its typed `SCP-CTX-2138` (ADR-049
            // Decision 16 item 2), as the create, import and restore arms do.
            Err(e @ ContextError::SupervisorShutDown(_)) => (Err(e), None),
            Err(e) => (Err(ContextError::TransportFailed(e.to_string())), None),
        };
        if let Some(dormant) = dormant
            && create_result.is_ok()
            && self.lookup(&context_id).is_some()
        {
            tracing::warn!(
                actor_kind = "context_actor",
                context_id = %context_id,
                dormant,
                "dormant standing context auto-revived on re-contact"
            );
        }

        // Step 4: TOCTOU re-check. A concurrent caller may have created
        // the context between our step-2 probe and the step-3 create. If
        // the context is now Active/Creating, treat the create as
        // idempotently successful; otherwise surface the create error. A
        // checked-read error also surfaces the create error: `crash_window`
        // still holds the respawn marker here, so an id with a prior crash
        // window reads `ActorCrashed` until the guard drops, and that answer
        // describes this bootstrap rather than why the create failed.
        let spawned = match create_result {
            Ok(spawned) => Ok(Some(spawned)),
            Err(create_err)
                if !matches!(
                    self.read_context_state_checked(&context_id).await,
                    Ok(Some(ContextState::Active | ContextState::Creating))
                ) =>
            {
                Err(create_err)
            }
            Err(_) => Ok(None),
        };
        drop(crash_window);
        // The post-spawn wiring waits on the new actor's mailbox, and the
        // rollback waits for abandoned writes, so both run after the lock is
        // released; the rollback retakes it for the restores. After a
        // committed create the rollback is a no-op.
        drop(bootstrap_guard);
        if let Some(first_state) = first_state
            && let Err(rollback) = first_state.rollback(self.bootstrap_spawn_lock.lock()).await
        {
            return Err(match spawned {
                Err(create_err) => {
                    crate::context::shared::lifecycle::fold_rollback_failure(&create_err, &rollback)
                }
                Ok(_) => rollback,
            });
        }
        if let Some((deps, spawned)) = spawned? {
            spawned.finalize(&deps).await?;
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
                let context_id = crate::context::shared::standing::generate_standing_context_id(
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
                            // ADR-056: resolve through the canonical resolver so
                            // the transport publish keys under the same bytes as
                            // `state.context_id`. A standing-pair id carries the
                            // `"standing-"` prefix (never bare 64-hex), so it
                            // hashes via the fallback exactly as before — this
                            // does NOT alter standing-context id derivation
                            // (a separately-tracked concern); it only unifies
                            // the resolver.
                            let context_id_bytes =
                                crate::context::state::context_id_to_bytes(&context_id);
                            self.transport_ref()
                                .ok_or_else(|| {
                                    ContextError::NotInitialized(
                                        crate::context::manager_methods::PROVIDER_NOT_INITIALIZED
                                            .to_owned(),
                                    )
                                })?
                                .publish_context(&context_id_bytes, &params)
                                .await
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
                        let cid = crate::context::shared::standing::generate_standing_context_id(
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
        match bounded_reply_await(rx).await {
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
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Builds (forces) a signed local consistency checkpoint for
    /// `context_id` from the current event-log state (§9.9.3). Routes
    /// through the actor mailbox via [`Self::dispatch_command`].
    ///
    /// Used by the reconnection driver's Phase 3 (`event_log_sync`): the
    /// caller supplies its locally-controlled `sender_did` + `signer`
    /// exactly as the application send path does.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler, including
    /// [`ContextError::Custody`] when the checkpoint sign is refused or times
    /// out (`SCP-CRYPTO-4062`); [`ContextError::TransportFailed`] if the reply
    /// channel is dropped.
    pub async fn build_local_checkpoint(
        &self,
        context_id: &str,
        sender_did: &DID,
        signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::BuildLocalCheckpoint {
            context_id: context_id.to_owned(),
            sender_did: sender_did.clone(),
            signer: signer.clone(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
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
    /// locally-controlled `sender_did` + `signer` exactly as the
    /// application send path does — the actor holds no key material.
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
        signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::SendHeartbeat {
            context_id: context_id.to_owned(),
            sender_did: sender_did.clone(),
            signer: signer.clone(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::send_heartbeat — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Rotates the local member's pseudonym in `context_id` to
    /// `new_routing_id` at `new_epoch` (spec 09 §9.10.4.1). Routes through
    /// the actor mailbox via [`Self::dispatch_command`].
    ///
    /// The caller (the bridge rotation driver) derives `new_routing_id` with
    /// `KeyCustody::derive_rotatable_pseudonym` at the epoch
    /// [`Self::local_routing_ids`] reports as `next_pseudonym_epoch`, and
    /// subscribes to it first. The actor persists the rotation fail-closed,
    /// emits `ContextEvent::LocalPseudonymRotated`, and announces.
    ///
    /// # Errors
    ///
    /// Propagates the typed [`ContextError`] of
    /// `scp_runtime_messaging::helpers::rotate_pseudonym`;
    /// [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn rotate_pseudonym(
        &self,
        context_id: &str,
        sender_did: &DID,
        signer: &crate::context::actor::signer::CommandSigner,
        new_epoch: u64,
        new_routing_id: [u8; 32],
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::RotatePseudonym {
            context_id: context_id.to_owned(),
            new_epoch,
            new_routing_id,
            sender_did: sender_did.clone(),
            signer: signer.clone(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::rotate_pseudonym — actor reply channel closed".to_owned(),
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
        bounded_reply_await(rx).await.map_err(|_| {
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::clear_needs_reconnect — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Issues an MLS Update proposal + self-Commit for `context_id`
    /// (§9.12 step 2), and publishes the Commit through the actor's Commit
    /// broadcast and retry queue (spec 23 §23.3 Phase 5). Routes through the actor
    /// mailbox via [`Self::dispatch_lifecycle_command`].
    ///
    /// Used by the reconnection driver's Phase 5 (`mls_update`).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler (e.g. `CryptoFailed`
    /// for a broadcast context or MLS failure, `TransportFailed` when the
    /// Commit's publish failed and the Commit sits queued for retry);
    /// [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn issue_mls_update(self: &Arc<Self>, context_id: &str) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::IssueMlsUpdate {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_lifecycle_command(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
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
    /// else, so the receive-path [`DeliverOutcome`](crate::context::actor::commands::DeliverOutcome)
    /// is collapsed back to `Option` here: a heartbeat encountered during
    /// catch-up is correctly treated as "no application content" (live
    /// heartbeat monitoring is the subscribe-loop's responsibility, not the
    /// reconnection driver's).
    ///
    /// `mode` decides whether the actor may send the sender-key answers the
    /// envelope queues: a push-wake pull passes
    /// [`DeliveryMode::PullOnly`](crate::context::actor::commands::DeliveryMode::PullOnly)
    /// (ADR-029 §2, push-wake pull mode, step 4).
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
        mode: crate::context::actor::commands::DeliveryMode,
    ) -> Result<Option<(Vec<u8>, String)>, ContextError> {
        use crate::context::actor::commands::DeliverOutcome;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DeliverIncoming {
            context_id: context_id.to_owned(),
            envelope_bytes,
            mode,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        let outcome = bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::deliver_commit_blob — actor reply channel closed".to_owned(),
            )
        })??;
        Ok(match outcome {
            DeliverOutcome::Application(msg) => Some(msg),
            DeliverOutcome::Heartbeat | DeliverOutcome::Handled => None,
        })
    }

    /// MLS-encrypts and sends every sender-key answer queued on the actor of
    /// `context_id` (§9.16.2). A full reconnection calls it for each context,
    /// because a push-wake pull leaves its answers queued (ADR-029 §2,
    /// push-wake pull mode, step 5). Routes through the actor mailbox via
    /// [`Self::dispatch_command`].
    ///
    /// Returns the report of the publish: the distributions a relay accepted,
    /// and a fault for each one that stays queued or was dropped (spec 09
    /// §9.16.9). A distribution that stays queued is not an error.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] (or the poison error) for an
    ///   unknown context; [`ContextError::ActorBusy`] from the mailbox send.
    /// - [`ContextError::TransportTimeout`] when the drain exceeds the handler
    ///   budget.
    /// - [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn send_queued_sender_keys(
        &self,
        context_id: &str,
    ) -> Result<crate::context::actor::state::DistributionReport, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::SendQueuedSenderKeys {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::send_queued_sender_keys — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// The number of sender-key answers queued on the actor of `context_id`
    /// (testing).
    ///
    /// # Errors
    ///
    /// The mailbox errors of [`Self::send_queued_sender_keys`].
    #[cfg(feature = "testing")]
    pub async fn queued_sender_key_count(&self, context_id: &str) -> Result<usize, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::QueuedSenderKeyCount {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::queued_sender_key_count — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// MLS-encrypts `message` as a §9.16.2 management message through the
    /// actor's group and returns the sealed bytes without sending them
    /// (testing). A harness posts them to a relay as a peer's
    /// `SenderKeyRequest` would arrive.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] for a context with no MLS group or a
    /// failed encrypt, and the mailbox errors of
    /// [`Self::send_queued_sender_keys`].
    #[cfg(feature = "testing")]
    pub async fn test_seal_management(
        &self,
        context_id: &str,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::TestSealManagement {
            context_id: context_id.to_owned(),
            message,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::test_seal_management — actor reply channel closed".to_owned(),
            )
        })?
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
        match bounded_reply_await(rx).await {
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
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Returns `true` iff the caller context `source_context_hex` holds a
    /// bidirectionally-approved `OutletInterface` to `target_context_hex` for
    /// `outlet_registration_id` (spec §6.2.0.1 standing consent). Routes through
    /// the CALLER context's actor mailbox via [`Self::dispatch_query`].
    ///
    /// The query is addressed to the caller context (the initiator is a member
    /// of it, already authorized) and reads that context's own
    /// `outlet_interfaces`, so it is the target-side authorize-before-reserve gate
    /// for [`Self::start_cross_context_outlet_invocation_saga`]: a caller cannot
    /// name a victim `target_context_id` it has no established interface with
    /// (spec §6.2.4 "Target-context binding" rides the §6.2.0.1 consent — it
    /// does NOT create it). `false` on an unknown context or no matching
    /// both-approved interface.
    #[must_use]
    pub async fn has_established_outlet_interface(
        &self,
        source_context_hex: &str,
        target_context_hex: &str,
        outlet_registration_id: &str,
    ) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::HasEstablishedOutletInterface {
            context_id: source_context_hex.to_owned(),
            source_context_hex: source_context_hex.to_owned(),
            target_context_hex: target_context_hex.to_owned(),
            outlet_registration_id: outlet_registration_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return false;
        }
        match bounded_reply_await(rx).await {
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
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the payment receipts captured in `context_id` (spec §19.11),
    /// optionally narrowed by `filter`. Empty `Vec` when the context is
    /// unknown, when no receipt matches, and when the actor could not be
    /// reached (busy, crashed, or poisoned), so an empty answer does not
    /// prove the context has no receipts. Routes through the actor mailbox
    /// via [`Self::dispatch_query`].
    ///
    /// Reads the actor-owned per-context local receipt buffer — `PaymentReceived`
    /// is per-payee application activity excluded from the canonical Merkle log
    /// (ADR-011 amendment exclusion taxonomy §2), so it is surfaced from the
    /// local buffer rather than the durable event log.
    #[must_use]
    pub async fn payment_history(
        &self,
        context_id: &str,
        filter: Option<scp_runtime_types::economy::receipt::ReceiptFilter>,
    ) -> Vec<scp_runtime_types::economy::adapter::PaymentReceipt> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::PaymentHistory {
            context_id: context_id.to_owned(),
            filter,
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return Vec::new();
        }
        match bounded_reply_await(rx).await {
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
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns a clone of the context's creation parameters, or `None`
    /// when the context is unknown or its actor could not be reached (busy,
    /// crashed, or poisoned); `None` alone does not prove the context is
    /// absent. Routes through the actor mailbox via [`Self::dispatch_query`].
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
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns the context's stored relay set (§5.12.3.1 `relay_urls`), or
    /// `None` when the context is unknown or its actor could not be reached.
    /// Routes through the actor mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn context_relay_urls(&self, context_id: &str) -> Option<Vec<String>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::RelayUrls {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns a clone of the context's role state, or `None` when no
    /// reachable actor answered. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    ///
    /// `None` does not mean the context is unknown. This form collapses an
    /// unreachable actor (a saturated or wedged mailbox that misses
    /// `SEND_TIMEOUT` or `REPLY_TIMEOUT`), a crashed context awaiting
    /// respawn, and a poisoned context into the same `None` a
    /// never-registered context reports. A caller whose decision turns on
    /// absence calls [`Self::get_role_state_checked`], which reports each of
    /// those outcomes as an error.
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
        match bounded_reply_await(rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Reads the context's role state and reports an actor this call could not
    /// reach as an error rather than as an absent context.
    ///
    /// [`Self::get_role_state`] answers `None` both when the supervisor serves
    /// no context for the id and when a saturated or wedged actor misses
    /// [`SEND_TIMEOUT`](crate::context::actor::SEND_TIMEOUT) or
    /// [`REPLY_TIMEOUT`](crate::context::actor::REPLY_TIMEOUT). A caller that
    /// authorizes against role state, such as an FFI bridge, must tell its
    /// own caller to retry a busy context instead of telling it the context
    /// does not exist, so it reads this form.
    ///
    /// `Ok(None)` has the meaning [`Self::read_context_state_checked`] gives
    /// it: no actor, no poison flag, and no crash-window record that the id is
    /// mid-respawn or that its last respawn failed. A window that only counts
    /// earlier crashes does not block an `Ok(None)`.
    /// It is the only absent answer. A busy or timed-out actor, a crashed
    /// context and a poisoned context each return an error below, so a caller
    /// that enumerates contexts, such as a member's context listing, keeps the
    /// id or fails on an error, and never drops the id as absent.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] when an actor is registered and the
    ///   mailbox send failed or timed out, the actor did not answer within
    ///   `REPLY_TIMEOUT`, or an actor registered for the id between this
    ///   read's two lookups.
    /// - [`ContextError::ContextPoisoned`] for a context the crash watchdog
    ///   poisoned and despawned (ADR-049 §10).
    /// - [`ContextError::ActorCrashed`] for a context that is mid-respawn or
    ///   whose last respawn failed (ADR-049 §10).
    /// - Whatever error the `GetRoleState` handler itself returned.
    pub async fn get_role_state_checked(
        &self,
        context_id: &str,
    ) -> Result<Option<scp_protocol::context::roles::ContextRoleState>, ContextError> {
        let Some(actor) = self.lookup(context_id) else {
            // No actor: classify the miss the way the lifecycle read does, so
            // a poisoned or crashed context never reads as absent.
            return match self.read_context_state_checked(context_id).await? {
                None => Ok(None),
                Some(scp_protocol::context::ContextState::Poisoned) => {
                    Err(ContextError::ContextPoisoned(context_id.to_owned()))
                }
                Some(_) => Err(ContextError::ActorBusy(format!(
                    "context '{context_id}' registered its actor while its role state was \
                     being read; retry"
                ))),
            };
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Queries(QueriesCommand::GetRoleState {
            context_id: context_id.to_owned(),
            reply: tx,
        });
        Self::dispatch_via_mailbox(&actor, cmd).await?;
        match bounded_reply_await(rx).await {
            Ok(answer) => answer,
            Err(reply_error) => Err(ContextError::ActorBusy(format!(
                "context '{context_id}' has a live actor that did not answer a role-state \
                 read: {reply_error:?}"
            ))),
        }
    }

    /// Get-or-spawn the attempt-ledger actor of `challenger` (spec 07
    /// §7.3.4), keyed by its canonical identifier so two spellings of one key
    /// can never hold two ledgers. A handle whose actor stopped is replaced;
    /// the replacement keeps the old [`ChallengerLedgerShared`] state, so
    /// permits held by unfinished gradings still count and no lease id is
    /// issued twice.
    ///
    /// [`ChallengerLedgerShared`]: crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerShared
    ///
    /// # Errors
    ///
    /// [`TrustError::NonCanonicalIdentifier`](scp_protocol::trust::TrustError::NonCanonicalIdentifier)
    /// for a non-canonical `challenger`; [`ContextError::NotInitialized`]
    /// without storage or a clock; the spawn gate's error during shutdown.
    async fn challenger_ledger_for(
        &self,
        challenger: &str,
    ) -> Result<
        crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerHandle,
        crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError,
    > {
        use crate::context::supervisor::challenger_ledger_actor::{
            ChallengerLedgerActor, ChallengerLedgerShared,
        };
        let identity = scp_protocol::trust::CanonicalIdentifier::parse(challenger)?;
        let key = identity.as_str().to_owned();
        if let Some(handle) = self.challenger_ledgers.get(&key)
            && !handle.is_closed()
        {
            return Ok(handle.value().clone());
        }
        let _guard = self.write_lock.lock().await;
        let shared = match self.challenger_ledgers.get(&key) {
            Some(handle) if !handle.is_closed() => return Ok(handle.value().clone()),
            Some(handle) => handle.shared(),
            None => ChallengerLedgerShared::new(),
        };
        let deps = self.build_challenger_ledger_deps()?;
        let permit = self.spawn_permit("spawn challenger-ledger actor")?;
        let (handle, _join) = ChallengerLedgerActor::spawn_through(&permit, identity, deps, shared);
        self.challenger_ledgers.insert(key, handle.clone());
        drop(permit);
        Ok(handle)
    }

    /// Assembles the ledger actor's collaborators from the supervisor's
    /// provider slots.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInitialized`] if storage or the clock is not wired.
    fn build_challenger_ledger_deps(
        &self,
    ) -> Result<
        crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerDeps,
        ContextError,
    > {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());
        Ok(
            crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerDeps {
                mls_storage: Arc::clone(self.mls_storage_ref().ok_or_else(not_init)?),
                clock: Arc::clone(self.clock_ref().ok_or_else(not_init)?),
            },
        )
    }

    /// Takes one of `challenger`'s `MAX_CONCURRENT_GRADINGS_PER_CHALLENGER`
    /// grading permits without waiting (spec 09 §9.18.C). The grading holds
    /// it until its future and every blocking closure it started finish.
    ///
    /// # Errors
    ///
    /// [`TrustError::GradingCapacityExhausted`](scp_protocol::trust::TrustError::GradingCapacityExhausted)
    /// when every permit is held; the errors of the ledger lookup.
    pub async fn challenge_grading_permit(
        &self,
        challenger: &str,
    ) -> Result<
        tokio::sync::OwnedSemaphorePermit,
        crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError,
    > {
        let handle = self.challenger_ledger_for(challenger).await?;
        handle.grading_semaphore().try_acquire_owned().map_err(|_| {
            scp_protocol::trust::TrustError::GradingCapacityExhausted {
                challenger: challenger.to_owned(),
                cause: scp_protocol::trust::GradingCapacityCause::GradingPermits,
            }
            .into()
        })
    }

    /// Persists a new challenge in `challenger`'s ledger and signs its
    /// request in the same ledger turn (spec 07 §7.3.4 step 1).
    ///
    /// # Errors
    ///
    /// The ledger's refusal ([`TrustError::ChallengeWindowOpen`](scp_protocol::trust::TrustError::ChallengeWindowOpen),
    /// [`TrustError::ChallengeNotOpen`](scp_protocol::trust::TrustError::ChallengeNotOpen),
    /// a verifier mismatch), a persistence or custody failure, or
    /// [`ContextError::ActorBusy`]. On any error no signed request exists.
    pub async fn dispatch_challenge_create(
        &self,
        challenger: &str,
        unsigned: scp_protocol::trust::UnsignedChallengeRequest,
        answer_key: scp_protocol::trust::AnswerKey,
        evaluator_context_id: Option<String>,
        signer: crate::context::actor::signer::CommandSigner,
    ) -> Result<
        scp_protocol::trust::ChallengeRequest,
        crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError,
    > {
        use crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerCommand;
        let handle = self.challenger_ledger_for(challenger).await?;
        handle
            .send(|reply| ChallengerLedgerCommand::Create {
                unsigned: Box::new(unsigned),
                answer_key,
                evaluator_context_id,
                signer,
                reply,
            })
            .await
    }

    /// Read-only: whether `challenger`'s ledger holds a live challenge with
    /// this id, request digest and subject, and, once that challenge is
    /// closed, an attempt graded from `response` (spec 07 §7.3.4 step 3,
    /// before any resolution). Takes no lease and writes nothing.
    ///
    /// # Errors
    ///
    /// [`TrustError::UnknownChallenge`](scp_protocol::trust::TrustError::UnknownChallenge)
    /// when no such challenge exists, or when it is closed and `response`
    /// is not one it graded (spec 07 §7.3.4 step 3.2); a non-canonical
    /// subject or an unencodable response; a load failure or
    /// [`ContextError::ActorBusy`].
    pub async fn dispatch_challenge_lookup(
        &self,
        challenger: &str,
        request: &scp_protocol::trust::ChallengeRequest,
        response: &scp_protocol::trust::ChallengeResponse,
    ) -> Result<(), crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError> {
        use crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerCommand;
        let request_digest = scp_protocol::trust::challenge_request_signing_digest(request)?;
        let response_digest = scp_protocol::trust::challenge_response_signing_digest(response)?;
        let subject = scp_protocol::trust::CanonicalIdentifier::parse(&request.subject)?;
        let handle = self.challenger_ledger_for(challenger).await?;
        handle
            .send(|reply| ChallengerLedgerCommand::Lookup {
                challenge_id: request.challenge_id,
                request_digest,
                subject,
                response_digest,
                reply,
            })
            .await
    }

    /// Begins grading an authenticated response (spec 07 §7.3.4 step 3
    /// Begin): a stored record for a resubmit, else the grading lease.
    ///
    /// # Errors
    ///
    /// The ledger's refusal (`UnknownChallenge`, the `check_attempt` errors,
    /// `GradingInProgress`), a load failure, or [`ContextError::ActorBusy`].
    pub async fn dispatch_challenge_begin_grade(
        &self,
        challenger: &str,
        auth: Arc<scp_protocol::trust::AuthenticatedResponse>,
    ) -> Result<
        crate::context::supervisor::challenger_ledger_actor::BeginOutcome,
        crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError,
    > {
        use crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerCommand;
        let handle = self.challenger_ledger_for(challenger).await?;
        handle
            .send(|reply| ChallengerLedgerCommand::BeginGrade { auth, reply })
            .await
    }

    /// Signs a graded attempt's record and records it (spec 07 §7.3.4 step
    /// 4).
    ///
    /// # Errors
    ///
    /// `GradingLeaseLost` with nothing written, the `check_attempt` errors at
    /// the commit time, a persistence or custody failure, or
    /// [`ContextError::ActorBusy`]. Every error but the last leaves nothing
    /// written and the attempt unused.
    pub async fn dispatch_challenge_commit(
        &self,
        challenger: &str,
        auth: Arc<scp_protocol::trust::AuthenticatedResponse>,
        lease_id: u64,
        outcome: scp_protocol::trust::GradeOutcome,
        signer: crate::context::actor::signer::CommandSigner,
    ) -> Result<
        crate::context::supervisor::challenger_ledger_actor::GradedAttempt,
        crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError,
    > {
        use crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerCommand;
        let handle = self.challenger_ledger_for(challenger).await?;
        handle
            .send(|reply| ChallengerLedgerCommand::Commit {
                auth,
                lease_id,
                outcome,
                signer,
                reply,
            })
            .await
    }

    /// Records a challenger fault for the grading of `auth` (spec 07 §7.3.4
    /// step 3). It uses no attempt and closes nothing; the cooldown restarts
    /// from it.
    ///
    /// # Errors
    ///
    /// `GradingLeaseLost` with nothing written when the lease is not live
    /// for this `(attempt, D_r)`, a persistence failure, or
    /// [`ContextError::ActorBusy`].
    pub async fn dispatch_challenge_fault(
        &self,
        challenger: &str,
        auth: Arc<scp_protocol::trust::AuthenticatedResponse>,
        lease_id: u64,
        fault: scp_protocol::trust::TrustError,
    ) -> Result<(), crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError> {
        use crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerCommand;
        let handle = self.challenger_ledger_for(challenger).await?;
        handle
            .send(|reply| ChallengerLedgerCommand::RecordFault {
                auth,
                lease_id,
                fault,
                reply,
            })
            .await
    }

    /// Releases the grading lease of `auth` and records nothing (spec 07
    /// §7.3.4 step 3): the grading was refused for capacity, so it uses no
    /// attempt, records no fault and starts no cooldown.
    ///
    /// # Errors
    ///
    /// `GradingLeaseLost` when the lease is not live for this
    /// `(attempt, D_r)`, a load failure, or [`ContextError::ActorBusy`].
    pub async fn dispatch_challenge_release(
        &self,
        challenger: &str,
        auth: Arc<scp_protocol::trust::AuthenticatedResponse>,
        lease_id: u64,
    ) -> Result<(), crate::context::supervisor::challenger_ledger_actor::ChallengeLedgerError> {
        use crate::context::supervisor::challenger_ledger_actor::ChallengerLedgerCommand;
        let handle = self.challenger_ledger_for(challenger).await?;
        handle
            .send(|reply| ChallengerLedgerCommand::Release {
                auth,
                lease_id,
                reply,
            })
            .await
    }

    /// Spawns a challenge evaluator's economy pipeline onto the Supervisor's
    /// task tracker (ADR-049 Decision 16), so a shutdown waits for the
    /// pipeline's settle and storage never closes under a reserve that has
    /// not settled.
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] once shutdown has begun; the
    /// future is dropped without running.
    pub fn spawn_evaluator_pipeline<F>(
        &self,
        future: F,
    ) -> Result<tokio::task::JoinHandle<F::Output>, ContextError>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_tracked("challenge evaluator pipeline", future)
    }

    /// Reads the context's live capability requirements (spec §8.10), the
    /// list a member must satisfy, as set by `ModifyCapabilityRequirements`.
    ///
    /// Fails closed: an unknown, crashed, poisoned or busy context is an
    /// error, never an empty list, because an empty list admits everyone.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] when the supervisor serves no
    ///   context for `context_id`.
    /// - [`ContextError::ContextPoisoned`] / [`ContextError::ActorCrashed`]
    ///   for a poisoned or respawning context (ADR-049 §10).
    /// - [`ContextError::ActorBusy`] when the actor's mailbox send or reply
    ///   timed out.
    pub async fn capability_requirements_checked(
        &self,
        context_id: &str,
    ) -> Result<scp_protocol::trust::CapabilityRequirements, ContextError> {
        let Some(actor) = self.lookup(context_id) else {
            return Err(
                self.lookup_miss_error(context_id, format!("context not registered: {context_id}"))
            );
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Queries(QueriesCommand::GetCapabilityRequirements {
            context_id: context_id.to_owned(),
            reply: tx,
        });
        Self::dispatch_via_mailbox(&actor, cmd).await?;
        match bounded_reply_await(rx).await {
            Ok(answer) => answer,
            Err(reply_error) => Err(ContextError::ActorBusy(format!(
                "context '{context_id}' has a live actor that did not answer a \
                 capability-requirements read: {reply_error:?}"
            ))),
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
        match bounded_reply_await(rx).await {
            Ok(Ok(events)) => events,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Drains ONLY the `EquivocationDetected` alerts from `context_id`'s
    /// receive buffer via the actor mailbox, leaving every other buffered
    /// event in place and in order.
    ///
    /// The reconnection driver uses this instead of
    /// [`Self::drain_events`] so that application traffic (messages,
    /// membership changes) buffered during catch-up is preserved for
    /// the SDK's normal receive polling rather than being silently
    /// discarded. Same soft-default contract as [`Self::drain_events`]:
    /// returns an empty `Vec` on unknown context, mailbox enqueue
    /// failure, or dropped reply channel.
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
        match bounded_reply_await(rx).await {
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
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::event_log_entries — event_log provider not configured".to_owned(),
            )
        })?;
        event_log.event_log_entries(context_id_bytes)
    }

    /// Returns the entry count and Merkle root of `context_id`'s event log,
    /// read from the same shared provider as [`Self::event_log_entries`].
    ///
    /// The provider reads both values from one state of the log
    /// ([`ContextEventLogProvider::event_log_summary`]), so an append that
    /// lands concurrently never pairs one tree's count with another tree's
    /// root. A context whose log exists and has no entries reports a count of
    /// 0 and the empty-tree root, `SHA-256("")` (spec §25.8 Vector 15).
    /// Synchronous for the reason [`Self::event_log_entries`] gives.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if no event-log provider is
    /// wired, and the provider's [`ContextError`] if the context has no event
    /// log or the provider cannot summarize it.
    pub fn event_log_summary(
        &self,
        context_id_bytes: &[u8; 32],
    ) -> Result<(usize, [u8; 32]), ContextError> {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::event_log_summary — event_log provider not configured".to_owned(),
            )
        })?;
        event_log.event_log_summary(context_id_bytes)
    }

    /// Computes the participation record (§7.3.2) for `subject_did` in
    /// `context_id` from the context's FULL event log.
    ///
    /// Gathers the context's UNFILTERED Merkle-log events and the log's Merkle
    /// root from the supervisor's shared event-log provider, then delegates to
    /// the pure-core
    /// [`compute_participation_record`](scp_protocol::trust::compute_participation_record).
    /// The full event set is required because
    /// `governance_actions_against` counts events where the subject is the
    /// projected TARGET (not the actor), so a query filtered to the subject's
    /// own events would undercount.
    ///
    /// # Attestation source (`accessible_attestations`)
    ///
    /// `attestation_count` is a credential-layer fact (§7.4) and is the one
    /// fact NOT derivable from the event log. The supervisor does NOT hold the
    /// trust [`AttestationCache`](scp_protocol::trust::aggregate::AttestationCache)
    /// / [`TrustProtocolRepository`](scp_protocol::trust::aggregate::TrustProtocolRepository):
    /// the raw `Storage` handle is consumed into the durable-providers pair at
    /// construction and is not re-exposed (ADR-049). The trust store is
    /// reconstructed at the FFI bridge layer (each bridge owns its
    /// `ProtocolRepository`), exactly as `aggregate_trust_input` does. The
    /// caller therefore threads the subject's accessible, currently-valid
    /// attestations IN — the bridge sources them from its own
    /// `AttestationCache::get_verified_attestations`. A caller with no
    /// attestation access honestly passes an empty slice (count 0,
    /// verifier-relative per §7.3.2), but this method itself never fabricates an
    /// empty set — it forwards whatever the caller supplies.
    ///
    /// Synchronous — reads the shared provider directly without a per-context
    /// lock or actor mailbox (stateless w.r.t. per-context state), mirroring
    /// [`Self::event_log_entries`]; the FFI sync paths that call it cannot
    /// `.await`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if the event-log provider or
    /// clock is not configured, [`ContextError`] if the provider fails, and
    /// surfaces [`TrustError`](scp_protocol::trust::TrustError) (e.g.
    /// `EmptyEventLog`) from the core computation as
    /// [`ContextError::InvalidState`].
    pub fn participation_record(
        &self,
        context_id: &str,
        subject_did: &str,
        accessible_attestations: &[scp_protocol::trust::attestation::Attestation],
    ) -> Result<scp_protocol::trust::ParticipationRecord, ContextError> {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::participation_record — event_log provider not configured".to_owned(),
            )
        })?;
        let now_secs = self
            .clock_ref()
            .ok_or_else(|| {
                ContextError::NotInitialized(
                    "Supervisor::participation_record — clock not configured".to_owned(),
                )
            })?
            .now_secs();

        let context_id_bytes = crate::context::state::context_id_to_bytes(context_id);
        // FULL, unfiltered event set — `governance_actions_against` needs
        // events where the subject is the projected target, not the actor.
        let events = event_log
            .event_log_entries(&context_id_bytes)?
            .unwrap_or_default();
        // FAIL CLOSED on the Merkle root (white-hat P2). A log that HAS events
        // must carry a real root: substituting `[0u8; 32]` would emit a record
        // with real participation facts bound to a zero root, which a verifier
        // could not distinguish from a genuinely-empty log. Only an empty log
        // tolerates an absent root — the core computation returns `EmptyEventLog`
        // for it below regardless, so the substituted zero root is never observed.
        let merkle_root = match event_log.event_log_merkle_root(&context_id_bytes) {
            Ok(root) => root,
            Err(_) if events.is_empty() => [0u8; 32],
            Err(e) => return Err(e),
        };

        scp_protocol::trust::compute_participation_record(
            &events,
            subject_did,
            context_id,
            merkle_root,
            now_secs,
            accessible_attestations,
        )
        .map_err(|e| match e {
            // Empty event log → distinct, machine-detectable variant so the FFI
            // bridges can surface a stable, dedicated error code instead of
            // collapsing it with genuine failures (Finding 3). A subject with no
            // recorded participation facts is a normal, branchable outcome.
            scp_protocol::trust::TrustError::EmptyEventLog => ContextError::NoParticipationFacts {
                subject_did: subject_did.to_owned(),
            },
            other => ContextError::InvalidState(format!(
                "participation record computation failed for {subject_did}: {other}"
            )),
        })
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::get_broadcast_key_for_local_author — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Async hard-rate-limit consume routed through the per-context
    /// actor mailbox.
    ///
    /// Builds a [`OutletsCommand::TryConsumeHardRateLimit`], dispatches it
    /// through [`Self::dispatch_outlets_command`] (which routes to the
    /// target context's actor — the actor owns its
    /// [`PerContextState`](crate::context::actor::state::PerContextState)
    /// hard-rate-limit bucket), and awaits the embedded reply oneshot.
    ///
    /// Returns `true` (pass-through) when a token was consumed OR when there
    /// is no live per-context bucket to enforce — the context is not
    /// registered, the handler replied `Err`, or the actor DROPPED the reply
    /// channel (terminated). This preserves the legacy
    /// `try_consume_hard_rate_limit_from_any_context` contract: an outlet
    /// invoked against a context with no live actor is not rate-limited here
    /// (absence of a bucket means "no per-context cap to enforce").
    ///
    /// Returns `false` (deny) when the context IS registered AND EITHER the
    /// sender is over budget OR the actor is ALIVE-but-wedged and does not
    /// reply within [`REPLY_TIMEOUT`](crate::context::actor::REPLY_TIMEOUT).
    /// The wedge case fails CLOSED on purpose: the bucket exists but is
    /// momentarily unreachable, so folding the timeout into the `true`
    /// pass-through would silently BYPASS the hard-rate cap for the whole
    /// reply-timeout window — exploitable in a cross-context topology where
    /// the caller-context actor is wedged but the target is healthy. Deny is
    /// the safe default; the caller retries. The `Dropped` (terminated actor,
    /// no live bucket) and `Elapsed` (wedged actor, unreachable bucket) cases
    /// are therefore deliberately NOT folded together — see
    /// [`hard_rate_limit_allow`].
    pub(crate) async fn try_consume_hard_rate_limit(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::TryConsumeHardRateLimit {
            context_id: context_id.to_owned(),
            did: did.clone(),
            now_secs,
            reply: reply_tx,
        };
        // Dispatch returns the dispatch-level Outcome; the typed answer
        // arrives on `reply_rx`. An unregistered context replies
        // `Err(ContextNotRegistered)` (see `reply_outlets_not_registered`)
        // which we fold to the legacy `true` pass-through.
        if self.dispatch_outlets_command(cmd).await.is_err() {
            return true;
        }
        // Fail CLOSED on a wedge (Elapsed): the bucket exists but is
        // unreachable, so denying is the safe default — never a silent
        // bypass. Terminated/unregistered (Dropped / handler `Err`) stays
        // pass-through: no live bucket to enforce. See `hard_rate_limit_allow`.
        hard_rate_limit_allow(&bounded_reply_await(reply_rx).await)
    }

    /// Async hard-rate-limit refund routed through the per-context actor
    /// mailbox. No-op when the target context has no live actor (legacy
    /// unknown-context contract).
    ///
    /// Mirrors [`Self::try_consume_hard_rate_limit`]; builds a
    /// [`OutletsCommand::RefundHardRateLimit`], dispatches it to the actor,
    /// and awaits the reply. The reply error (e.g. `ContextNotRegistered`)
    /// is swallowed — a refund against an absent bucket is a no-op, not a
    /// failure the caller can act on.
    pub(crate) async fn refund_hard_rate_limit(&self, context_id: &str, did: &DID) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::RefundHardRateLimit {
            context_id: context_id.to_owned(),
            did: did.clone(),
            reply: reply_tx,
        };
        if self.dispatch_outlets_command(cmd).await.is_err() {
            return;
        }
        let _ = bounded_reply_await(reply_rx).await;
    }

    /// Runtime-agnostic hard-rate-limit consumption used by FFI
    /// callers that may run inside or outside a tokio runtime.
    ///
    /// Returns `false` if the bucket is empty.
    ///
    /// # Sync-shape exception (ADR-049 §7)
    ///
    /// The method signature is `fn`, not `async fn` — FFI callers
    /// (the MCP `invoke_outlet` sync trait method in particular) invoke
    /// it from outside a tokio task and cannot `.await`. The body
    /// bridges sync → async: it inspects the ambient
    /// runtime and either `blocking`-bridges into the async
    /// `Self::try_consume_hard_rate_limit` actor-mailbox path, or
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
                        // ADR-049 §7 FFI sync rate-limit allowlist — the MCP `invoke_outlet`
                        // sync trait method cannot `.await`; the actor-mailbox consume is
                        // awaited on the ambient multi-thread runtime.
                        let fut = self.try_consume_hard_rate_limit(context_id, did, now_secs);
                        tokio::task::block_in_place(|| handle.block_on(fut)) // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (MCP invoke_outlet consume)
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
                        // ADR-049 §7 FFI sync rate-limit allowlist — the MCP `invoke_outlet`
                        // refund path is sync and cannot `.await`; the actor-mailbox refund
                        // is awaited on the ambient multi-thread runtime.
                        let fut = self.refund_hard_rate_limit(context_id, did);
                        tokio::task::block_in_place(|| handle.block_on(fut)); // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (MCP invoke_outlet refund)
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
                    drop(supervisor);
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
            // Release the Supervisor before replying, so the reference never
            // outlives the synchronous call the caller blocks on (ADR-049
            // Decision 16).
            drop(supervisor);
            let _ = tx.send(result);
        });
        rx.recv().unwrap_or(false)
    }

    /// Dispatch the Phase-1 [`OutletsCommand::ReserveOutletEconomy`] to the
    /// target context's actor and await the `Send` reservation.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered
    /// for `context_id`; otherwise any error the reserve handler emits.
    #[allow(clippy::too_many_arguments)]
    async fn reserve_outlet_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        caveat_binding: Option<crate::context::outlets::invoke::InvocationCaveatBinding>,
        input: serde_json::Value,
        now_secs: u64,
    ) -> Result<crate::context::shared::outlets::OutletEconomyReservation, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReserveOutletEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            spending_ucan: spending_ucan.map(|u| Box::new(u.clone())),
            caveat_binding: caveat_binding.map(Box::new),
            input: Box::new(input),
            now_secs,
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx)
            .await
            .map_err(|_| {
                ContextError::TransportFailed(
                    "Supervisor::reserve_outlet_economy_via_actor — actor reply channel closed"
                        .to_owned(),
                )
            })?
            .map(|boxed| *boxed)
    }

    /// Dispatch the streaming open-time [`OutletsCommand::ReserveOutletStreamEconomy`]
    /// to the target context's actor and await the `Send`
    /// [`StreamEconomyReservation`](crate::context::shared::outlets::StreamEconomyReservation).
    ///
    /// Mirrors [`Self::reserve_outlet_economy_via_actor`] for the
    /// streaming-native open path: the reserve runs inside the per-context
    /// actor on owned Class-S state (hard-rate + velocity + escrow debit +
    /// seq-authority-B allocation); the supervisor carries the returned
    /// reservation across the off-mailbox stream pump.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered for
    /// `context_id`; [`ContextError::TransportFailed`] if the actor reply
    /// channel closes; otherwise any error the reserve handler emits
    /// (rate-limit, not-a-member, escrow overflow / insufficient funds,
    /// persist failure).
    async fn reserve_outlet_stream_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        cost_per_chunk: scp_protocol::economy::types::Amount,
        estimated_chunk_count: u32,
        max_per_action: Option<scp_protocol::economy::types::Amount>,
        now_secs: u64,
    ) -> Result<crate::context::shared::outlets::StreamEconomyReservation, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReserveOutletStreamEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            cost_per_chunk,
            estimated_chunk_count,
            max_per_action,
            now_secs,
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx)
            .await
            .map_err(|_| {
                ContextError::TransportFailed(
                    "Supervisor::reserve_outlet_stream_economy_via_actor — actor reply channel \
                     closed"
                        .to_owned(),
                )
            })?
            .map(|boxed| *boxed)
    }

    /// §5.4.5 GRANT-time escrow top-up reserve — DEBITS `cost_per_chunk ×
    /// grant` from the invoker's `MemberBudgetTracker` inside the per-context
    /// actor, returning the reserved hold `Amount`.
    ///
    /// This is the runtime half of the FFI grant path: the bridge signs the
    /// `OutletStreamCredit` internally, calls THIS to reserve the incremental
    /// escrow, threads the returned hold into
    /// [`StreamSessionHandle::apply_credit_grant`](crate::context::outlets::dispatch::StreamSessionHandle::apply_credit_grant)
    /// as `reserved_top_up`, and — if that apply rejects — reverses the hold via
    /// [`Self::outlet_stream_reverse_grant`]. Together they uphold the §5.4.5
    /// atomicity invariant `billed + refund == reserved` across open + grants,
    /// closing the budget-cap under-enforcement where a grant used to extend the
    /// billable window with no debit.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered;
    /// [`ContextError::TransportFailed`] if the actor reply channel closes;
    /// `EscrowOverflow` / `InsufficientFunds` from the reserve handler.
    pub async fn outlet_stream_reserve_grant(
        &self,
        context_id: &str,
        invoker_did: &DID,
        request_id: scp_protocol::context::outlets::stream::RequestId,
        cost_per_chunk: scp_protocol::economy::types::Amount,
        grant: u32,
    ) -> Result<scp_protocol::economy::types::Amount, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReserveStreamGrantEscrow {
            context_id: context_id.to_owned(),
            member_did: invoker_did.clone(),
            request_id,
            cost_per_chunk,
            grant,
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::outlet_stream_reserve_grant — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Reverse a GRANT-time escrow hold reserved by
    /// [`Self::outlet_stream_reserve_grant`] when the subsequent credit-grant
    /// apply rejects (signature / replay / stream-closed).
    ///
    /// Dispatches [`OutletsCommand::ReverseStreamGrantEscrow`], which CREDITS the
    /// budget hold back AND un-bumps the durable crash-recovery record
    /// (`reserved_escrow`) keyed by `request_id`, ATOMICALLY — the two legs must
    /// move together or a crash between them would make the reconcile sweep
    /// double-refund. This is DISTINCT from the open-path escrow ticket's
    /// `reverse_stream_escrow` (budget only), because a grant that already bumped
    /// the record must also un-bump it. Both operations are saturating, so a
    /// reverse after a race that already refunded is a safe no-op.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered;
    /// [`ContextError::TransportFailed`] if the actor reply channel closes.
    pub async fn outlet_stream_reverse_grant(
        &self,
        context_id: &str,
        invoker_did: &DID,
        request_id: scp_protocol::context::outlets::stream::RequestId,
        amount: scp_protocol::economy::types::Amount,
    ) -> Result<(), ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReverseStreamGrantEscrow {
            context_id: context_id.to_owned(),
            member_did: invoker_did.clone(),
            request_id,
            amount,
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::outlet_stream_reverse_grant — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Dispatch the Phase-3 [`OutletsCommand::SettleOutletEconomy`] to the
    /// target context's actor and await the settle outcome.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered
    /// for `context_id`; otherwise any error the settle handler emits
    /// (payment-capture failure).
    async fn settle_outlet_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        request: crate::context::shared::outlets::OutletSettleRequest,
    ) -> Result<crate::context::shared::outlets::OutletSettleOutcome, ContextError> {
        // No-actor pre-check: the reserve→execute→settle split runs the
        // executor OFF the actor mailbox, so the owning actor can be
        // despawned (shutdown / node teardown / import replace) during
        // that window. If no actor is registered now, the per-context
        // settle can never run, and routing the command through
        // `dispatch_outlets_command` would hand the ticket to
        // `reply_outlets_not_registered`, which DROPS it — leaking the
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
            // genuinely-unknown context keeps the rich SCP-OUTLET-6089
            // not-registered diagnostic (escrow already voided above)
            // (ADR-049 §10).
            return Err(self.lookup_miss_error(
                context_id,
                format!(
                    "SCP-OUTLET-6089: outlet-economy settle for context '{context_id}' found no \
                     registered actor (reserved generation {generation}); escrow voided, \
                     reservation not captured"
                ),
            ));
        }

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::SettleOutletEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            request: Box::new(request),
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::settle_outlet_economy_via_actor — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Dispatch the streaming close-time [`OutletsCommand::SettleOutletStream`]
    /// to the target context's actor, with the supervisor-side no-actor fallback.
    ///
    /// The actor-mailbox analog of the reference `ContextManager::outlet_stream_settle`.
    /// Called from
    /// [`ActorStreamSettlementSink`](crate::context::outlets::stream_settlement_adapter::ActorStreamSettlementSink)
    /// via a spawned task (the sink's `settle` is a sync fire-and-forget).
    ///
    /// # No-actor fallback (mirrors [`Self::settle_outlet_economy_via_actor`])
    ///
    /// The reserve→pump→settle split runs the pump OFF the actor mailbox, so the
    /// owning actor can be despawned (shutdown / node teardown / import replace)
    /// mid-stream. If no actor is registered now, the counter release and escrow
    /// refund are MOOT — the actor-owned Class-S counter and the budget tracker
    /// were torn down with the context — but service WAS rendered (H8), so the
    /// billed `PaymentReceipt` is STILL captured here, supervisor-side, against
    /// the open-time
    /// [`EconomicPolicySnapshot`](crate::context::outlets::invoke::EconomicPolicySnapshot)
    /// (the payment adapter lives on the supervisor, not per-context, so it is
    /// reachable regardless of context liveness). A capture failure is logged
    /// (the non-durable `PaymentCaptureFailed` local event has no live receive
    /// buffer to land in once the context is gone).
    ///
    /// # Errors
    ///
    /// [`ContextError::TransportFailed`] if the actor reply channel closes;
    /// otherwise the dispatch error. The no-actor fallback never errors (it
    /// resolves to `applied: false` with a possibly-`None` receipt).
    pub(in crate::context) async fn settle_outlet_stream_via_actor(
        &self,
        settlement: crate::context::outlets::invoke::StreamSettlement,
        generation: u64,
        // SCP-OUT-046 CRITICAL — the cross-context streaming-saga witness key.
        // `Some` ⇒ the on-actor settle flips `settled` atomically with the money
        // move (the xctx double-refund guard), AND both this no-actor branch and
        // the on-actor generation-mismatch branch DEFER entirely (no capture) so
        // crash recovery completes the settlement exactly once (the durable debit
        // is NOT moot). `None` ⇒ the same-context pump path (unchanged behaviour:
        // capture the rendered bill supervisor-side, reserves left for the sweep).
        witness_saga_id: Option<SagaId>,
    ) -> Result<crate::context::actor::commands::StreamSettleApplication, ContextError> {
        use crate::context::actor::commands::StreamSettleApplication;
        // No-actor pre-check. When the context is gone, a same-context settle
        // captures against the open-time snapshot supervisor-side (release +
        // refund are moot — the owned state that held them was torn down). A
        // witness-bearing xctx settle instead DEFERS entirely (see below).
        if self.lookup(&settlement.context_id).is_none() {
            // SCP-OUT-046 CRITICAL — the xctx path: the escrow debit + §7.3.8
            // counter reserve are DURABLE (restored on respawn), so they are NOT
            // moot; capturing here would double-bill once recovery re-applies.
            // Defer the whole settlement (no capture) — the witness stays
            // unsettled and crash recovery completes it once against the restored
            // instance.
            if witness_saga_id.is_some() {
                tracing::debug!(
                    context_id = %settlement.context_id,
                    request_id = %hex::encode(settlement.request_id),
                    "outlet stream settlement (xctx saga): target gone mid-stream — deferring \
                     the whole settlement to crash recovery (witness left unsettled)"
                );
                return Ok(StreamSettleApplication {
                    receipt: None,
                    applied: false,
                });
            }
            let crate::context::outlets::invoke::StreamSettlement {
                context_id,
                invoker_did,
                billed_amount,
                request_id,
                economic_policy_snapshot,
                ..
            } = settlement;
            let (Some(adapter), Some(policy)) = (
                self.payment_adapter_ref(),
                economic_policy_snapshot.map(|snap| snap.policy),
            ) else {
                return Ok(StreamSettleApplication {
                    receipt: None,
                    applied: false,
                });
            };
            if billed_amount.value() == 0 {
                return Ok(StreamSettleApplication {
                    receipt: None,
                    applied: false,
                });
            }
            let receipt =
                match crate::context::shared::outlets::authorize_and_capture_stream_billed(
                    adapter.as_ref(),
                    &policy,
                    &invoker_did,
                    billed_amount,
                    request_id,
                    &context_id,
                )
                .await
                {
                    Ok(receipt) => {
                        tracing::debug!(
                            context_id = %context_id,
                            request_id = %hex::encode(request_id),
                            "outlet stream settlement: context gone mid-stream — captured \
                             PaymentReceipt against open-time economic snapshot"
                        );
                        Some(receipt)
                    }
                    Err(e) => {
                        // No live receive buffer to record the non-durable
                        // `PaymentCaptureFailed` into — surface the failure to the
                        // operator log only (matches the reference no-actor path).
                        tracing::warn!(
                            context_id = %context_id,
                            "outlet stream settlement (no-actor): payment capture failed: {e}"
                        );
                        None
                    }
                };
            return Ok(StreamSettleApplication {
                receipt,
                applied: false,
            });
        }

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::SettleOutletStream {
            settlement: Box::new(settlement),
            generation,
            witness_saga_id,
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::settle_outlet_stream_via_actor — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Fix-D — dispatch the restore-time streaming crash-recovery sweep
    /// ([`OutletsCommand::ReconcileStreamReservations`]) to a freshly-respawned
    /// actor and await the reconciled-record count.
    ///
    /// Called once per context from the restore path
    /// (`scp_runtime_lifecycle::helpers::restore_context`) after
    /// `spawn_actor_with_state`, mirroring the post-restore TTL re-arm. The
    /// handler refunds + releases the durable reserves of any stream whose
    /// off-mailbox pump survived the crash (its close-time settle lands on the
    /// bumped generation and is dropped) and clears the records. A context with
    /// no in-flight streaming reservations reconciles zero (the common case).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the actor reply channel closes or the
    /// dispatch misses (the just-respawned context was despawned again before
    /// the sweep). Callers treat this best-effort — a miss leaves the records
    /// for the next restart's sweep (idempotent).
    pub(in crate::context) async fn reconcile_stream_reservations_via_actor(
        &self,
        context_id: &str,
    ) -> Result<usize, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReconcileStreamReservations {
            context_id: context_id.to_owned(),
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::reconcile_stream_reservations_via_actor — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Dispatch the streaming open-time [`OutletsCommand::ReverseStreamEscrow`]
    /// to the target context's actor and await the persist outcome.
    ///
    /// The actor-mailbox analog of the reference
    /// `ContextManager::outlet_stream_reverse_spend`. Called from
    /// [`ActorEscrowRefundSink`](crate::context::outlets::stream_settlement_adapter::ActorEscrowRefundSink),
    /// which the escrow ticket's sink awaits in a task on the open's spawner
    /// when the [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
    /// drops unconsumed. A missing actor drops the best-effort refund (the torn-down
    /// context's budget tracker is gone).
    ///
    /// # Errors
    ///
    /// [`ContextError::TransportFailed`] if the actor reply channel closes;
    /// [`ContextError::ContextNotRegistered`] when no actor is registered;
    /// otherwise the persist error.
    pub(in crate::context) async fn reverse_stream_escrow_via_actor(
        &self,
        context_id: &str,
        member_did: &DID,
        amount: scp_protocol::economy::types::Amount,
    ) -> Result<(), ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = OutletsCommand::ReverseStreamEscrow {
            context_id: context_id.to_owned(),
            member_did: member_did.clone(),
            amount,
            reply: reply_tx,
        };
        self.dispatch_outlets_command(cmd).await?;
        bounded_reply_await(reply_rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::reverse_stream_escrow_via_actor — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Reverses a streaming open-time escrow hold through the target actor and
    /// consumes the ticket, for an abort path between the reserve's debit and
    /// the pump or seal spawn. The reversal runs as a task spawned through the
    /// operation's `spawner`. The ticket is consumed and the task spawned with
    /// no `.await` between them, so a caller that drops this future leaves the
    /// reversal running and gets no second refund from the ticket's `Drop`.
    /// This future waits for the task. A failed reversal logs at error and the
    /// hold stays debited.
    pub(in crate::context) async fn release_stream_escrow(
        self: &Arc<Self>,
        spawner: &TrackedSpawner,
        ticket: crate::context::outlets::dispatch::StreamEscrowTicket,
        context_id: &str,
        member_did: &DID,
    ) {
        let reserved = ticket.reserved();
        ticket.consume();
        if reserved.value() == 0 {
            return;
        }
        let supervisor = Arc::downgrade(self);
        let context_id = context_id.to_owned();
        let member_did = member_did.clone();
        let reversal = spawner.spawn(async move {
            let result = match supervisor.upgrade() {
                Some(supervisor) => {
                    supervisor
                        .reverse_stream_escrow_via_actor(&context_id, &member_did, reserved)
                        .await
                }
                None => Err(ContextError::SupervisorShutDown(
                    "the supervisor was dropped before the escrow reversal ran".to_owned(),
                )),
            };
            if let Err(err) = result {
                tracing::error!(
                    context_id,
                    %err,
                    reserved = reserved.value(),
                    "streaming open aborted and the open-time escrow reversal failed — \
                     the hold stays debited"
                );
            }
        });
        if let Err(err) = reversal.await {
            tracing::error!(
                reserved = reserved.value(),
                "{}",
                escrow_reversal_join_failure_message(&err)
            );
        }
    }

    /// Invoke a outlet under the full economy pipeline (actor model).
    ///
    /// Orchestrates the three-phase split through
    /// `crate::context::shared::outlets::invoke_outlet_with_economy`: the
    /// economy reserve (Phase 1) and settle (Phase 3) run inside the
    /// per-context actor on owned state via the
    /// [`OutletsCommand::ReserveOutletEconomy`] / [`OutletsCommand::SettleOutletEconomy`]
    /// mailbox commands; the non-`Send` `executor` closure (Phase 2) runs
    /// here, supervisor-side, BETWEEN the two mailbox round-trips. No
    /// per-context lock is held across the executor — the actor is free
    /// to process other commands while a outlet executes.
    ///
    /// # Errors
    ///
    /// Propagates every error variant the reserve / settle handlers and
    /// the executor emit (`ContextNotRegistered`, `PermissionDenied`,
    /// `RateLimited`, schema/economy/UCAN failures).
    #[allow(clippy::too_many_arguments)] // matches legacy signature 1:1
    pub async fn invoke_outlet_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        caveat_binding: Option<crate::context::outlets::invoke::InvocationCaveatBinding>,
        timeout_ms: Option<u32>,
        executor: F,
    ) -> Result<crate::context::shared::outlets::ManagedOutletInvocationOutput, ContextError>
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

        // §7.3.8 value-caveat enforcement. `caveat_binding` is resolved by the
        // CALLER (the FFI bridge) from the VALIDATED INVOCATION UCAN — the token
        // that grants the `outlet_call:*` / `outlet_query:*` capability — whose
        // signed `nb` field carries the VALIDATED-NARROWED effective caveats (a
        // delegation inherits its parents' value-caveats through `narrow()`, so
        // the leaf `nb` IS the effective narrowed set). The bridge captures them
        // at the `validate_outlet_invocation_ucan` site, where it has already
        // parsed and validated that token against the proof chain, and bundles
        // them with that token's revocation CID (the owned Class-S counter key)
        // so "caveats present ⟹ cid present" holds by construction. They are NOT
        // re-derived from `spending_ucan` — that is a SEPARATE economy token
        // (§19.5) whose `nb` does NOT carry invocation caveats. When the
        // invocation UCAN carried no caveats (or a surface authorizes purely via
        // role-state) the binding is `None` and the counter gate stays inert.
        //
        // The reserve phase needs the input to check it against the caveat's
        // `input_schema`; the executor phase (below) consumes the original, so
        // clone once for the reserve mailbox round-trip.
        let reserve_input = input.clone();

        crate::context::shared::outlets::invoke_outlet_with_economy(
            registry,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            // Phase 1 — reserve via the actor mailbox.
            || {
                self.reserve_outlet_economy_via_actor(
                    context_id,
                    invoker_did,
                    spending_ucan,
                    caveat_binding,
                    reserve_input,
                    now_secs,
                )
            },
            // Phase 3 — settle (capture / rollback) via the actor mailbox.
            |request| self.settle_outlet_economy_via_actor(context_id, invoker_did, request),
            executor,
        )
        .await
    }

    /// §5.4.5 streaming-native outlet invocation — the actor-model orchestrator
    /// (chunk 3e). The streaming counterpart of [`Self::invoke_outlet_with_economy`].
    ///
    /// Threads the reserve → off-mailbox pump → settle bracket:
    ///
    /// 1. **Reserve (mailbox).** `Self::reserve_outlet_stream_economy_via_actor`
    ///    runs the open-time economy reserve INSIDE the per-context actor on
    ///    owned Class-S state (hard-rate + velocity + `cost_per_chunk ×
    ///    estimated_chunk_count` escrow debit + seq-authority-B allocation),
    ///    returning the `Send` `StreamEconomyReservation`.
    /// 2. **Pump (off-mailbox).** [`dispatch::open_stream_session`](crate::context::outlets::dispatch::open_stream_session)
    ///    runs here, supervisor-side, driving the non-`Send` executor with the
    ///    reservation's `handle` + `role_state` snapshots (NOT caller-supplied —
    ///    the reserve snapshots them in-actor for a consistent lifecycle +
    ///    membership view), the actor-owned counter store, the per-context
    ///    admission tracker, and the node-level pump semaphore.
    /// 3. **Settle (mailbox).** The `ActorStreamSettlementSink`
    ///    fires from the pump's terminal-chunk block back onto the actor mailbox
    ///    to refund the unspent escrow, release the unspent cumulative counter
    ///    reserve, and capture the §19.15.5 `PaymentReceipt`.
    ///
    /// # Escrow refund on open failure
    ///
    /// The reserve DEBITS `reserved_escrow` before the pump spawns.
    /// `open_stream_session` refunds nothing on its own rejection paths — it
    /// rolls back only the admission slot / pump permit / counter it consumed.
    /// So this orchestrator guards the debited hold with a
    /// [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
    /// backed by a `SpawnerEscrowRefundSink`:
    /// on a successful open the ticket is `consume`d (the pump's close-time
    /// settlement now owns the unspent-portion refund); on ANY rejection the
    /// ticket's `Drop` reverses the full hold via
    /// [`OutletsCommand::ReverseStreamEscrow`]. Exactly one refund path fires,
    /// never both — the two are mutually exclusive (`settlement_sink` fires only
    /// once the pump spawns `Ok`, which is exactly when the ticket is consumed).
    ///
    /// # Sequence allocation
    ///
    /// The reserve allocates NO per-sender MLS send-sequence. Per §5.4.5 the
    /// pump's per-chunk cursor starts at `0` per `request_id` (`invoke.rs`
    /// "sequence starts at 0"), a DISTINCT counter from the message
    /// send-sequence. A's per-sender send-sequence is the A-context MLS re-seal's,
    /// reserved at the §9.16/§5.15.7 encrypt seam over A's PERSISTENT per-sender
    /// counter (SCP-OUT-047) — neither this open-time reserve nor the
    /// cross-context bridge mints a send-sequence.
    ///
    /// # Errors
    ///
    /// [`OutletStreamOpenError`](crate::context::outlets::invoke::OutletStreamOpenError).
    /// A shutdown refusal, of the spawner or of the reserve, is
    /// `SupervisorShutDown`. Any other reserve [`ContextError`] is
    /// reverse-mapped into the open-time
    /// [`OpenStreamRejection`](crate::context::outlets::dispatch::OpenStreamRejection)
    /// taxonomy via
    /// `reserve_error_to_open_rejection`
    /// and returned as `Rejected`; any rejection `open_stream_session` returns
    /// propagates as `Rejected`.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_outlet_stream<E>(
        self: &Arc<Self>,
        context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        timeout_ms: Option<u32>,
        executor: Arc<E>,
        invoked_event_sink: Option<
            Arc<dyn crate::context::outlets::invoke::OutletInvokedEventSink>,
        >,
        misdeclaration_sink: Option<
            Arc<dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        >,
        handler_panic_sink: Option<Arc<dyn crate::context::outlets::invoke::HandlerPanicSink>>,
        caveat_binding: Option<crate::context::outlets::invoke::InvocationCaveatBinding>,
        params: crate::context::outlets::dispatch::OpenStreamParams,
    ) -> Result<
        crate::context::outlets::dispatch::StreamSessionHandle,
        crate::context::outlets::invoke::OutletStreamOpenError,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized + 'static,
    {
        // Taken before the reserve, so an open refused by shutdown has debited
        // nothing. The pump spawns through it onto the tracker, so the drain
        // waits for the pump and its close-time settlement (ADR-049 Decision
        // 16).
        let spawner = self
            .tracked_spawner("open outlet stream")
            .map_err(|refused| {
                crate::context::shared::outlets::reserve_error_to_open_rejection(&refused)
            })?;
        self.open_outlet_stream_with_spawner(
            &spawner,
            context_id,
            registry,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            invoked_event_sink,
            misdeclaration_sink,
            handler_panic_sink,
            caveat_binding,
            params,
        )
        .await
    }

    /// Runs [`Self::open_outlet_stream`] after its spawner check, spawning the
    /// pump and the escrow reversal through `spawner`. A caller that already
    /// holds a spawner for the operation passes it here, so the operation has
    /// one shutdown refusal point.
    ///
    /// # Errors
    ///
    /// The rejections [`Self::open_outlet_stream`] returns, except the
    /// shutdown refusal of its spawner check.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn open_outlet_stream_with_spawner<E>(
        self: &Arc<Self>,
        spawner: &TrackedSpawner,
        context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        timeout_ms: Option<u32>,
        executor: Arc<E>,
        invoked_event_sink: Option<
            Arc<dyn crate::context::outlets::invoke::OutletInvokedEventSink>,
        >,
        misdeclaration_sink: Option<
            Arc<dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        >,
        handler_panic_sink: Option<Arc<dyn crate::context::outlets::invoke::HandlerPanicSink>>,
        caveat_binding: Option<crate::context::outlets::invoke::InvocationCaveatBinding>,
        params: crate::context::outlets::dispatch::OpenStreamParams,
    ) -> Result<
        crate::context::outlets::dispatch::StreamSessionHandle,
        crate::context::outlets::invoke::OutletStreamOpenError,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized + 'static,
    {
        use crate::context::outlets::dispatch;

        // Phase 1 — the shared, sink-agnostic pre-pump prologue (reserve →
        // escrow guard → §7.3.8 hook → `ContextParams` caps/timing →
        // admission/semaphore). `caveat_binding` is borrowed (not moved) so it
        // outlives the returned post-input check through `open_stream_session`
        // below. This same-context production open supplies BOTH sinks itself
        // (settlement + durable `OutletInvoked`); the SCP-OUT-046 streaming saga
        // passes neither (see [`OutletStreamPhase1`]).
        let OutletStreamPhase1 {
            reservation,
            escrow_ticket,
            params,
            caveat_post_input_check,
            counter_reservation,
            admission,
            origin_admission,
            pump_semaphore,
        } = self
            .open_outlet_stream_phase1(
                spawner,
                context_id,
                invoker_did,
                caveat_binding.as_ref(),
                params,
            )
            .await?;

        // Close-time settlement sink, holding the reservation's spawn-generation
        // (the confused-deputy guard compares it to the live actor's generation
        // at settle time, dropping a settlement aimed at a respawned instance).
        let settlement_sink: Arc<dyn crate::context::outlets::invoke::StreamSettlementSink> =
            Arc::new(
                crate::context::outlets::stream_settlement_adapter::ActorStreamSettlementSink::new(
                    Arc::downgrade(self),
                    reservation.generation,
                ),
            );

        // §5.4.5 / SCP-OUT-035 — the durable close-event sink, wired INTERNALLY
        // here (not by the FFI caller, which passes `None`) so the "ONE event
        // per stream at close" record is persisted in production and the full
        // §5.4.5:566 wire-rejection fires at the real log-insert boundary. A
        // caller-supplied `invoked_event_sink` (tests capturing the event) takes
        // precedence; otherwise the durable production sink is used.
        let durable_invoked_sink: Arc<dyn crate::context::outlets::invoke::OutletInvokedEventSink> =
            Arc::new(
                crate::context::outlets::stream_settlement_adapter::ActorOutletInvokedEventSink::new(
                    Arc::downgrade(self),
                    crate::context::state::context_id_to_bytes(context_id),
                    invoker_did.as_ref().to_owned(),
                ),
            );
        let invoked_event_sink = invoked_event_sink.or(Some(durable_invoked_sink));

        // Phase 2 — hand the executor + seams to the off-mailbox pump.
        let open_result = dispatch::open_stream_session(
            &reservation.handle,
            registry,
            &reservation.role_state,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            misdeclaration_sink,
            handler_panic_sink,
            invoked_event_sink,
            Some(settlement_sink),
            params,
            admission,
            origin_admission,
            pump_semaphore,
            caveat_post_input_check,
            counter_reservation,
            &|task| drop(spawner.spawn(task)),
            self.shutdown_token.clone(),
        )
        .await;

        match open_result {
            Ok(handle) => {
                // Pump spawned `Ok` — the close-time settlement now owns the
                // unspent-escrow refund, so the open-path guard must NOT refund.
                escrow_ticket.consume();
                Ok(handle)
            }
            Err(rejection) => {
                // The pump never spawned; reverse the reserve's debited hold
                // (the sole refund path on failure — the settlement sink never
                // fires).
                self.release_stream_escrow(spawner, escrow_ticket, context_id, invoker_did)
                    .await;
                Err(rejection.into())
            }
        }
    }

    /// Phase-1 (pre-pump) prologue shared by [`Self::open_outlet_stream`] and
    /// the SCP-OUT-046 cross-context streaming-saga producer: the in-actor
    /// economy reserve, the armed open-failure escrow guard, the actor-owned
    /// §7.3.8 counter store + post-input hook, and the authoritative
    /// `ContextParams` admission-caps / timing sourcing + admission/semaphore
    /// handles. Returns an [`OutletStreamPhase1`] the caller finishes with its
    /// OWN sink choice — the helper is deliberately sink-agnostic (see the
    /// struct doc for why the streaming saga needs both sinks OFF).
    ///
    /// Behavior is identical to the inline prologue it replaced: the escrow
    /// ticket is armed immediately after the debit, and EVERY fallible step
    /// below (the §7.3.8 hook build, the vanished-context early return) passes
    /// it to [`Self::release_stream_escrow`], which reverses the hold; on success the ticket is handed back for the caller to
    /// `consume`. The only reordering is that the two sink constructions moved
    /// OUT to the caller (both are pure `Arc::new` allocations with no side
    /// effects and no dependency on the caps read, so their relocation past the
    /// vanished-context early return is unobservable).
    ///
    /// # Errors
    ///
    /// `SupervisorShutDown` when the reserve is refused by shutdown; otherwise
    /// `Rejected` with the reserve's [`ContextError`] reverse-mapped to the
    /// open-time
    /// [`OpenStreamRejection`](crate::context::outlets::dispatch::OpenStreamRejection)
    /// taxonomy, a §7.3.8 hook build rejection; or the transport-fault admission
    /// slug when the hosting context vanished between the reserve and the
    /// authoritative caps read.
    async fn open_outlet_stream_phase1(
        self: &Arc<Self>,
        spawner: &TrackedSpawner,
        context_id: &str,
        invoker_did: &DID,
        caveat_binding: Option<&crate::context::outlets::invoke::InvocationCaveatBinding>,
        mut params: crate::context::outlets::dispatch::OpenStreamParams,
    ) -> Result<OutletStreamPhase1, crate::context::outlets::invoke::OutletStreamOpenError> {
        use crate::context::outlets::dispatch;
        use scp_protocol::context::outlets::error_codes;

        // `now_secs` from the injected clock. A missing clock fails the open
        // closed (no timestamp for the reserve's rate-limit / velocity /
        // counter bookkeeping), routed through the transport-fault admission
        // slug so the FFI surface shapes it like any other pre-open rejection.
        let now_secs = match self.clock_ref() {
            Some(clock) => {
                use scp_clock::Clock as _;
                clock.now_secs()
            }
            None => {
                return Err(dispatch::OpenStreamRejection::AdmissionRateLimited {
                    slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
                }
                .into());
            }
        };

        // The dispatch pump coerces the effective `estimated_chunk_count` from
        // `(declared_estimated_chunk_count, caveats)`; the reserve MUST debit
        // `cost_per_chunk × THE SAME estimate` or the escrow ledger the pump
        // bills against would disagree with the debited hold. Coerce once here
        // and thread the identical value into the reserve.
        let estimated_chunk_count =
            scp_runtime_types::context::outlets::stream::coerce_estimated_chunk_count(
                params.declared_estimated_chunk_count,
                &params.caveats,
            );

        // Phase 1 — reserve via the actor mailbox. `max_per_action` is `None`:
        // the streaming open surface negotiates no §19.5 SpendingCapability
        // (parity with the reference build hook, which passes no adapter /
        // target DID); cumulative spend is instead bounded by the §7.3.8
        // `amount_max_cumulative` counter reserve committed at the pump's final
        // gate.
        let reservation = self
            .reserve_outlet_stream_economy_via_actor(
                context_id,
                invoker_did,
                params.cost_per_chunk,
                estimated_chunk_count,
                None,
                now_secs,
            )
            .await
            .map_err(|err| {
                crate::context::shared::outlets::reserve_error_to_open_rejection(&err)
            })?;

        // Fill the manager-debited escrow hold + the acceptance-time economic
        // policy snapshot into `params` (the pump's Step 3 ledger + close-time
        // settlement read these). A caller-supplied snapshot wins (mirrors the
        // reference: a bridge that already computed it is not overridden).
        params.reserved_escrow = reservation.reserved_escrow;
        if params.economic_policy_snapshot.is_none() {
            params.economic_policy_snapshot = reservation
                .economic_policy
                .clone()
                .map(|policy| crate::context::outlets::invoke::EconomicPolicySnapshot { policy });
        }

        // Open-failure escrow guard (see the method doc). The reserve just
        // DEBITED `reserved_escrow`; arm the guard IMMEDIATELY — before any
        // fallible step between here and the pump spawn (the `?` on
        // `build_stream_post_input_hook` below, any early return). Each early
        // exit passes the ticket to `release_stream_escrow`, which reverses the
        // hold. Consumed on success — the pump's close-time settlement then
        // owns the unspent-portion refund.
        let escrow_refund_sink: Arc<dyn dispatch::StreamEscrowRefundSink> =
            Arc::new(SpawnerEscrowRefundSink::new(self, spawner));
        let escrow_ticket = dispatch::StreamEscrowTicket::new(
            escrow_refund_sink,
            context_id.to_owned(),
            invoker_did.clone(),
            reservation.reserved_escrow,
        );

        // The actor-owned durable caveat-counter store: routes the §7.3.8
        // counter CAS onto the target context's Class-S `caveat_counters` via
        // the mailbox. Always constructible in the actor architecture, so the
        // helper's "no store → fail closed" branch is unreachable here.
        let counter_store: Arc<dyn crate::trust::CaveatCounterApi> = Arc::new(
            crate::context::outlets::stream_counter_adapter::ActorClassSCaveatCounterAdapter::new(
                Arc::downgrade(self),
            ),
        );

        // §7.3.8 — build the synchronous local-check hook + the durable counter
        // reservation from the VALIDATED-NARROWED effective caveats bound to the
        // invocation UCAN. `None` binding ⇒ no post-input constraint ⇒ neither a
        // hook nor a reservation (parity with the non-streaming free path).
        // Caller-built `params.caveats` / `params.ucan_cid` mirror this binding
        // (both minted from the same validated UCAN), so the pump's estimate
        // coercion, `max_billable` ceiling, and counter-CAS key all agree.
        let (caveat_post_input_check, counter_reservation) = match caveat_binding {
            Some(binding) => match crate::context::shared::outlets::build_stream_post_input_hook(
                &binding.caveats,
                params.cost_per_chunk,
                Some(&counter_store),
            ) {
                Ok(built) => built,
                Err(rejection) => {
                    self.release_stream_escrow(spawner, escrow_ticket, context_id, invoker_did)
                        .await;
                    return Err(rejection.into());
                }
            },
            None => (None, None),
        };

        // §5.4.5 / §9.18.B — the three-tier concurrent-stream admission caps
        // are AUTHORITATIVE from the hosting context's live `ContextParams`,
        // NOT from the caller-supplied `params.caps`. Sourcing them here (the
        // production open entry point) means a caller cannot inflate its own
        // ceilings on the wire: the caps a stream is admitted against are
        // exactly what the context creator declared. Fetched through the actor
        // mailbox, the same path every other supervisor query uses. A vanished
        // context (raced close between the reserve and this read) fails the
        // open closed through the transport-fault admission slug, and the early
        // return reverses the reserve's debited hold.
        let Some(ctx_params) = self.context_params(context_id).await else {
            self.release_stream_escrow(spawner, escrow_ticket, context_id, invoker_did)
                .await;
            return Err(dispatch::OpenStreamRejection::AdmissionRateLimited {
                slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
            }
            .into());
        };
        params.caps = scp_runtime_types::context::outlets::stream::AdmissionCaps {
            per_invoker: ctx_params.max_concurrent_inbound_streams_per_invoker,
            per_origin_invoker: ctx_params.max_concurrent_inbound_streams_per_origin_invoker,
            per_outlet: ctx_params.max_concurrent_inbound_streams_per_outlet,
        };

        // §5.4.5 / SCP-OUT-034 — the four streaming timing/window policy fields
        // are ALSO server policy, sourced AUTHORITATIVELY from the hosting
        // context's live `ContextParams` (fetched above), NOT from anything the
        // caller supplied on `OpenStreamParams`. A caller must not set its own
        // initial credit window, credit-stall timeout, cancel-ack timeout, or
        // UCAN-recheck cadence: those are the context creator's declared
        // parameters, exactly like the admission caps overwritten just above.
        // Overwriting here (the production open entry point) makes the
        // caller-supplied values on `params` irrelevant — ContextParams wins.
        params.credit_window = ctx_params.stream_window_default;
        params.stream_credit_stall_secs = ctx_params.stream_credit_stall_secs;
        params.stream_cancel_ack_secs = ctx_params.stream_cancel_ack_secs;
        params.stream_ucan_recheck_secs = ctx_params.stream_ucan_recheck_secs;

        // Per-context admission tracker (per-invoker + per-outlet) +
        // operator-scoped origin admission tracker (per-origin-invoker,
        // §5.4.5) + node-level pump semaphore.
        let admission = self.outlet_stream_admission_for(context_id);
        let origin_admission = self.outlet_stream_origin_admission();
        let pump_semaphore = self.outlet_stream_pump_semaphore();

        Ok(OutletStreamPhase1 {
            reservation,
            escrow_ticket,
            params,
            caveat_post_input_check,
            counter_reservation,
            admission,
            origin_admission,
            pump_semaphore,
        })
    }

    /// Best-effort cross-context re-encrypting streaming bridge entry
    /// (SCP-OUT-036).
    ///
    /// Resolves the RECEIVING context A's shared event-log provider and drives
    /// `invoke_outlet_cross_context`,
    /// which opens the outlet stream in the OPERATING context B, forwards each
    /// operator-signed chunk to the shared-member invoker IN-PROCESS as
    /// PLAINTEXT (§6.2.0 — the invoker is a member of BOTH contexts, mirroring
    /// the same-context [`open_outlet_stream`](Self::open_outlet_stream)), and
    /// records A's own `OutletInvoked` at close over its independently
    /// reassembled chunk sequence. Returns A's plaintext
    /// `mpsc::Receiver<OutletStreamChunk>` PROMPTLY (the caller consumes chunks
    /// as produced) — identical to the same-context
    /// [`open_outlet_stream`](Self::open_outlet_stream): each chunk is the
    /// unmodified operator-signed
    /// [`OutletStreamChunk`](scp_protocol::context::outlets::stream::OutletStreamChunk),
    /// forwarded verbatim, and the bridge introduces no new send-sequence at this
    /// plaintext hand-off (§5.4.5). The SCP-OUT-045 gap-detector keys on
    /// `chunk.sequence`. Re-encryption for A's OTHER members is the SDK delivery
    /// seam (seal each still-operator-signed chunk under A's MLS group key over
    /// the existing §9.7/§9.8/§9.16 transport, its per-sender MLS send-sequence
    /// reserved at the §9.16/§5.15.7 encrypt seam over A's persistent counter —
    /// SCP-OUT-047), NOT this return type.
    ///
    /// Zero-escrow (§5.4.5 "Cross-context economy"; ADR-061): a paid Action
    /// outlet (`cost.amount > 0`) — or a positive billed `cost_per_chunk` — is
    /// rejected and no receiver is produced; a metered paid cross-context stream
    /// MUST use the streaming saga (SCP-OUT-046). B's `OutletInvoked` is recorded
    /// by the internal durable sink `open_outlet_stream` wires — never
    /// double-recorded here.
    ///
    /// `caveat_binding` is the validated-narrowed §7.3.8 value-caveat binding
    /// (`effective_caveats` + `ucan_cid`) threaded into `open_outlet_stream` so
    /// the durable cross-invocation counter CAS (`max_calls` /
    /// `amount_max_cumulative` / `rate_window`) is enforced for this open. It is
    /// `Some` when the invocation UCAN carries value caveats (supplied by the FFI
    /// caller / SCP-OUT-047) and `None` otherwise (no value-caveat gate). It is
    /// distinct from `params.identity.caveats_binding`, the 32-byte
    /// chunk-signature binding.
    ///
    /// # Errors
    ///
    /// Returns [`OutletOpenError`](crate::context::outlets::invoke::OutletOpenError):
    /// `SupervisorShutDown` once shutdown has begun, and `Invocation` when A's
    /// event-log provider is not configured, when the outlet is a paid
    /// Action outlet (or `cost_per_chunk > 0`), when a §7.3.8 counter cap in
    /// `caveat_binding` is exhausted, or when the B-side open is rejected.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_outlet_stream_cross_context<E>(
        self: &Arc<Self>,
        receiving_context_id: &str,
        operating_context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        timeout_ms: Option<u32>,
        executor: Arc<E>,
        incoming_open: &scp_protocol::context::outlets::stream::OutletStreamOpen,
        caveat_binding: Option<crate::context::outlets::invoke::InvocationCaveatBinding>,
        params: crate::context::outlets::dispatch::OpenStreamParams,
    ) -> Result<
        tokio::sync::mpsc::Receiver<scp_protocol::context::outlets::stream::OutletStreamChunk>,
        crate::context::outlets::invoke::OutletOpenError,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized + 'static,
    {
        // Resolve A's SHARED event-log provider (the off-mailbox durable log —
        // no per-context lock, ADR-049-safe). A missing provider fails the open
        // closed: the bridge cannot record A's `OutletInvoked` without it.
        let a_event_log = self.event_log_ref().cloned().ok_or_else(|| {
            crate::context::outlets::invoke::OutletOpenError::from(
                crate::context::outlets::invoke::InvocationError::ExecutionFailed {
                    message:
                        "cross-context bridge: receiving-context event-log provider not configured"
                            .to_owned(),
                },
            )
        })?;

        crate::context::outlets::invoke::invoke_outlet_cross_context(
            self,
            a_event_log,
            receiving_context_id,
            operating_context_id,
            registry,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            incoming_open,
            caveat_binding,
            params,
        )
        .await
    }

    // AXIS: bridge-external (ADR-049 §5 placement invariant). `create_context`
    // and its join-side peers `reserve_key_package` / `spawn_actor_from_welcome`
    // (below) are node-level bootstraps called by the trusted FFI/bridge
    // orchestrator: each takes a bare `DID`, with local-identity custody
    // enforced at the bridge, and returns only public / context state — never
    // per-identity secret crypto. Per-identity SECRET access lives on the
    // actor-internal `OwnedIdentityDid` axis instead (the
    // `SupervisorHandle::my_*` accessors), never as a bare-`DID` method here.

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
    /// fails, and
    /// [`ContextCreationError::StateTransition`](scp_protocol::context::builder::ContextCreationError::StateTransition)
    /// wrapping
    /// [`ContextError::CeilingRequired`]
    /// when `params.ceiling` is empty (construction.md M2); the context is
    /// not created. A dropped reply channel maps to
    /// [`ContextCreationError::CreationFailed`](scp_protocol::context::builder::ContextCreationError::CreationFailed).
    ///
    /// `relay_urls` names the relays that host the context (§5.12.3.1): the
    /// creator's relays. The actor stores the set (PUSH-025); an empty set
    /// states that no relay hosts the context.
    pub async fn create_context(
        self: &Arc<Self>,
        context_id: String,
        params: scp_protocol::context::ContextParams,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
        relay_urls: Vec<String>,
    ) -> Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::CreateContextPayload {
            context_id,
            params,
            creator_did,
            local_pseudonym,
            relay_urls,
        });
        let cmd = LifecycleCommand::CreateContext { payload, reply: tx };
        if let Err(e) = self.dispatch_lifecycle_command(cmd).await {
            return Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(format!(
                    "Supervisor::create_context — dispatch failed: {e}"
                )),
            );
        }
        bounded_reply_await(rx).await.unwrap_or_else(|_| {
            Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(
                    "Supervisor::create_context — actor reply channel closed".to_owned(),
                ),
            )
        })
    }

    /// Reserve one of this identity's pooled KeyPackages for a
    /// spawn-from-Welcome join, returning the `(ReservationId, public KP
    /// bytes)` pair. The reservation moves a KP into the KeyPackage actor's
    /// `reserved` map; the private signer-state never leaves that actor. The
    /// public bytes are for routing only — the creator adds them to its MLS
    /// group to produce the Welcome addressed to this KP, and the returned
    /// [`ReservationId`](crate::context::supervisor::key_package_actor::ReservationId)
    /// is handed back in the `WelcomeJoinRequest`'s `reservation_id` so the
    /// fused `ConfirmConsume` inside [`Self::spawn_actor_from_welcome`] can
    /// match the join.
    ///
    /// Bare-`DID` bootstrap entrypoint — the reserve half of the join-side peer
    /// of [`Self::create_context`]. Local-identity custody is enforced at the
    /// FFI bridge layer, not here (the same trust model as `create_context`).
    /// Get-or-spawns this identity's `KeyPackageStoreActor` and issues a SINGLE
    /// atomic [`KeyPackageCommand::ReserveAny`](crate::context::supervisor::key_package_actor::KeyPackageCommand::ReserveAny) — replenish-if-empty, pick the
    /// first pooled ref, and reserve it, all inside one command handler.
    ///
    /// Folding the reservation into one command (rather than composing
    /// `Replenish` → `ListPooled` → `Reserve` as three separate mailbox
    /// round-trips) closes a concurrency gap: two concurrent same-identity
    /// reserves that each `ListPooled` the same pool would both pick the same
    /// `kp_ref`, and the second `Reserve` would spuriously fail
    /// `InvalidState("already reserved")` even though distinct KPs were
    /// available. Because the actor owns `pool`/`reserved` and handlers run
    /// serialized on its mailbox loop, the atomic command guarantees the two
    /// reserves take DISTINCT KeyPackages.
    ///
    /// # Errors
    ///
    /// - Propagates any error from resolving the identity's
    ///   `KeyPackageStoreActor` (e.g.
    ///   [`ContextError::NotInitialized`]
    ///   when providers are absent, or a poisoned-KP-actor sticky error).
    /// - [`ContextError::ActorBusy`]
    ///   if the KeyPackage actor's mailbox is full or its reply channel drops.
    /// - [`ContextError::CreationFailed`] if the pool is still empty after a
    ///   replenish (no KP available to reserve).
    /// - [`ContextError::NotInitialized`] if the supervisor has no key
    ///   resolver.
    /// - [`ContextError::AttestationSignerActiveKeyUnresolved`] if
    ///   `owning_did`'s `#active` key does not resolve, and
    ///   [`ContextError::AttestationSignerNotActiveKey`] if `active_signer`
    ///   does not hold it; nothing is reserved.
    ///
    /// # Attestation
    ///
    /// Every pooled `KeyPackage` carries a `0xFF03` attestation (§9.7.1) signed
    /// through `active_signer`, the owner's `#active` custody signer. The
    /// store checks the signer against the owner's resolved `#active` key
    /// before it reserves, keeps it, and repeats the check before each mint.
    pub async fn reserve_key_package(
        self: &Arc<Self>,
        owning_did: DID,
        active_signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<
        (
            crate::context::supervisor::key_package_actor::ReservationId,
            Vec<u8>,
        ),
        ContextError,
    > {
        use crate::context::supervisor::key_package_actor::KeyPackageCommand;

        // Every KeyPackage publishes the owner's wrapping key; load it before
        // `key_package_store_for` takes `write_lock`.
        self.load_wrapping_key(&owning_did).await?;
        let signer = Arc::new(
            crate::crypto::mls::attestation_signer::KeyPackageAttestationSigner::resolve(
                owning_did.clone(),
                active_signer.clone(),
                self.key_resolver()?,
            )
            .await?,
        );
        let store = self.key_package_store_for(&owning_did).await?;
        store
            .send(|reply| KeyPackageCommand::ReserveAny { signer, reply })
            .await
    }

    /// Verifies `key_package` as an adder does before an Add (§9.7.1): it
    /// validates, its credential names `owner`, its leaf carries `0xFF01` and
    /// `0xFF03`, and the `0xFF03` attestation verifies against `owner`'s
    /// `#active` key resolved through this supervisor's key resolver. Returns
    /// the leaf's `0xFF01` wrapping key as a validated P-256 point.
    /// `invite_member` seals to that key only after this returns.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] when the supervisor has no key
    ///   resolver, crypto provider, or clock.
    /// - [`ContextError::InvalidKeyPackage`] when the `KeyPackage` does not
    ///   validate, names another identity, carries no `0xFF01` or no
    ///   `0xFF03`, its `0xFF01` is not a valid P-256 point, or its
    ///   attestation does not verify; the message ends with
    ///   the [`AttestationRuntimeVerifyError`](scp_runtime_types::crypto::mls::attestation_verification::AttestationRuntimeVerifyError)
    ///   in the last case.
    pub async fn verify_key_package_attestation(
        &self,
        owner: &DID,
        key_package: &[u8],
    ) -> Result<scp_protocol::crypto::hpke::p256::P256Point, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        use scp_runtime_types::crypto::mls::attestation_verification::verify_add_attestation;
        let resolver = self.key_resolver()?;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());
        let mls = Arc::clone(self.crypto_ref().ok_or_else(not_init)?.mls_backend());
        let clock = Arc::clone(self.clock_ref().ok_or_else(not_init)?);
        let validated = mls
            .validate_key_package(key_package, clock.as_ref())
            .await
            .map_err(|e| {
                ContextError::InvalidKeyPackage(format!("KeyPackage does not validate: {e}"))
            })?;
        if validated.credential_did != owner.0 {
            return Err(ContextError::InvalidKeyPackage(
                "KeyPackage credential does not name its owner".to_owned(),
            ));
        }
        let leaf = &validated.leaf;
        let wrapping_key = leaf.wrapping_key.ok_or_else(|| {
            ContextError::InvalidKeyPackage(
                "KeyPackage leaf carries no scp_wrapping_key (0xFF01)".to_owned(),
            )
        })?;
        let attestation = leaf.attestation.as_ref().ok_or_else(|| {
            ContextError::InvalidKeyPackage(
                "KeyPackage leaf carries no attestation (0xFF03)".to_owned(),
            )
        })?;
        verify_add_attestation(resolver, clock.as_ref(), leaf, &wrapping_key, attestation)
            .await
            .map_err(|e| {
                ContextError::InvalidKeyPackage(format!("KeyPackage attestation rejected: {e}"))
            })?;
        scp_protocol::crypto::hpke::p256::P256Point::try_from(wrapping_key).map_err(|e| {
            ContextError::InvalidKeyPackage(format!(
                "KeyPackage scp_wrapping_key (0xFF01) is not a valid P-256 point: {e}"
            ))
        })
    }

    /// Produces, signs, HPKE-seals, and (best-effort) delivers a §5.12.3 signed
    /// [`InvitationBundle`](scp_protocol::context::InvitationBundle) inviting
    /// `invitee_did` to the encrypted context `context_id` (ADR-049 Phase 2J,
    /// FFI-02 Option A — the creator-side peer of
    /// [`Self::spawn_actor_from_welcome`]).
    ///
    /// Steps (all creator-side, no per-identity secret returned):
    ///
    /// 1. Reads the context's LIVE genesis [`ContextParams`](scp_protocol::context::ContextParams) — the authenticated
    ///    authority source the joiner will enforce from. Encrypted-only: the
    ///    MLS-Welcome invitation flow stands up an encrypted context
    ///    (spawn-from-Welcome builds Encrypted mode and rejects Broadcast), so a
    ///    Broadcast context is refused here.
    /// 2. Verifies the invitee's KeyPackage (§9.7.1) through
    ///    [`Self::verify_key_package_attestation`]: its `0xFF03` attestation
    ///    must verify against the invitee's resolved `#active` key. The
    ///    HPKE recipient key is the leaf's attested `0xFF01` DHKEM(P-256)
    ///    wrapping key (§9.16.1).
    /// 3. Only a `SingleAdmin` context is supported (a voting model returns
    ///    `Err(ContextError::InvalidState)` up front — no proposal, no add —
    ///    because governed-context invitations are not yet implemented). Routes
    ///    the member-add through the context actor's
    ///    governance gate (`propose_governance_action_checked` → `AddMember`),
    ///    carrying `invitee_key_package` (the invitee's reserved KeyPackage bytes
    ///    from [`Self::reserve_key_package`]) on the actor command envelope. The
    ///    caller-as-admin auto-executes: the real MLS add for the carried
    ///    KeyPackage runs IN-ACTOR — updating `role_state`, minting access keys,
    ///    appending the event-log leaf, and broadcasting the epoch-advancing
    ///    Commit to existing members — and returns the Welcome. A non-admin
    ///    caller is rejected by the checked capability check / governance engine
    ///    (`?` surfaces the error, nothing is added). If any post-add step fails,
    ///    a compensating `RemoveMember` is routed through the same gate so no
    ///    added member is left without the sealed Welcome.
    /// 4. Assembles the bundle: genesis `context_params`, the visibility-filtered
    ///    [`MetadataSnapshot`](scp_protocol::context::metadata::MetadataSnapshot),
    ///    the context's stored `relay_urls`, and the §9.10.4.B
    ///    `context_metadata_key`.
    /// 5. Signs it over
    ///    [`invitation_bundle_signing_hash`](scp_protocol::context::InvitationBundle::invitation_bundle_signing_hash)
    ///    with the creator's `#active` key — the SAME `proposer_signing_key`
    ///    that authorized the governance `AddMember` in step 3. Using one key
    ///    for both makes it structurally impossible for the bundle's
    ///    authenticated `creator_did` to diverge from the DID the governance
    ///    gate authorized. The actor holds no custody key; the raw key is
    ///    supplied by the FFI boundary (same trust model as the governance
    ///    proposal path, which also takes a raw `&SigningKey`).
    /// 6. HPKE-seals the MessagePack-serialized bundle to the invitee's
    ///    `0xFF01` key (RFC 9180 Base mode, DHKEM(P-256), `info`/`aad` per
    ///    §5.12.3.1).
    /// 7. Fork C: publishes the sealed
    ///    [`SealedInvitation`](scp_runtime_types::context::invitation_helpers::SealedInvitation)
    ///    to the invitee's `scp-invitations` routing id when the transport
    ///    supports routing-id delivery; otherwise returns the `(enc, ct)` for the
    ///    caller to deliver (`delivered = false`).
    ///
    /// # Cryptographic notes
    ///
    /// - **`context_metadata_key` (§9.10.4.B).** Spec §9.10.4.B has the creator
    ///   generate this 32-byte key once at context creation and share it with all
    ///   members so their metadata routing IDs converge. The runtime create path
    ///   does not yet persist a genesis metadata key, so this method mints a
    ///   fresh `OsRng` key per invitation. It is cryptographically sound (CSPRNG,
    ///   signed into the bundle) and correct for a single-invitee (bilateral)
    ///   context, but multiple invitees will NOT converge on one metadata routing
    ///   ID until a genesis `context_metadata_key` is stored at creation and read
    ///   here. Metadata-routing publish is itself not yet wired, so this is inert
    ///   today.
    /// - **`sender_key_seed`.** `None` here: this flow is Encrypted-only (guarded
    ///   above), and Encrypted contexts carry no sender-key seed in the bundle
    ///   (§5.12.3.1). Broadcast admission is a separate flow.
    /// - **Actor serialization.** The MLS add-member runs IN-ACTOR via the
    ///   governance mailbox command (`propose_governance_action`), so it is
    ///   serialized against every other actor MLS operation — no off-mailbox
    ///   race. Only the read-only param/metadata gathering and the
    ///   bundle-seal/deliver happen on the caller task.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if `context_id` has no live
    ///   context; [`ContextError::InvalidState`] for a voting-governed context
    ///   (governed-context invitations are not yet implemented);
    ///   [`ContextError::InvalidKeyPackage`] if the invitee's KeyPackage does
    ///   not verify (see [`Self::verify_key_package_attestation`]);
    ///   [`ContextError::CryptoFailed`] for a Broadcast context, a signing or
    ///   HPKE-seal failure, or a serialization fault;
    ///   [`ContextError::MembershipFailed`] if the MLS add-member produces no
    ///   Welcome; [`ContextError::NotInitialized`] if no key resolver is wired;
    ///   or any non-"unsupported" transport error surfaced by the delivery.
    // The produce → assemble → sign → seal → deliver sequence reads clearer as one
    // linear method than split across helpers, hence the line-count allow (mirrors
    // `spawn_actor_from_welcome`, its join-side peer).
    #[allow(clippy::too_many_lines)]
    pub async fn invite_member(
        self: &Arc<Self>,
        context_id: String,
        creator_did: DID,
        invitee_did: DID,
        invitee_key_package: Vec<u8>,
        proposer_signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<InviteMemberOutcome, ContextError> {
        use rand::RngCore as _;
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::context::{InvitationBundle, InvitationKeyMaterial};
        use scp_protocol::crypto::envelope_seal;

        // 1. Live genesis params — the authenticated authority source.
        let params = self.context_params(&context_id).await.ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "invite_member: no live context '{context_id}'"
            ))
        })?;
        if params.mode != scp_protocol::context::ContextMode::Encrypted {
            return Err(ContextError::CryptoFailed(
                "invite_member supports only Encrypted contexts; Broadcast admission uses the \
                 sender-key distribution flow, not an MLS Welcome"
                    .to_owned(),
            ));
        }

        // Governed-context gate: only a `SingleAdmin` context authorizes a
        // UNILATERAL invite (the admin auto-executes the add). A voting model
        // (Threshold / Majority / Unanimity) requires a governance vote, so a
        // unilateral invite is NOT authorized. Refuse HERE — before proposing —
        // so we never leave a dead-on-arrival pending `AddMember` proposal, never
        // stage a KeyPackage, and never run an MLS add. Governed-context invites
        // (create + track a proposal, seal the Welcome once approved) are not yet
        // implemented, so this is an honest `Err` rather than a phantom-success
        // outcome that drops the invite while claiming it was deferred. When
        // governed invites land, this branch returns the future additive
        // `InviteMemberOutcome` variant carrying the tracked proposal id.
        if !matches!(
            params.governance,
            scp_protocol::context::params::GovernanceModel::SingleAdmin
        ) {
            return Err(ContextError::InvalidState(
                "invite_member: governed-context invitations are not yet implemented; only \
                 SingleAdmin contexts support a unilateral invite"
                    .to_owned(),
            ));
        }

        // The bundle carries the context's stored relay set (§5.12.3.1
        // `relay_urls`) and no caller-supplied list, so every member stores
        // the set the inviter holds.
        let relay_urls = self.context_relay_urls(&context_id).await.ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "invite_member: no live context '{context_id}'"
            ))
        })?;

        // V1. Verify the invitee's KeyPackage before anything is sealed or
        //     added (§9.7.1, the adder): it validates, its credential names
        //     the invitee, its leaf carries `0xFF01` and `0xFF03`, and the
        //     `0xFF03` attestation verifies against the invitee's resolved
        //     `#active` key. A supervisor without a key resolver refuses here,
        //     before any verification. `execute_add_member` validates the
        //     KeyPackage again in-actor; this pass is the attestation gate.
        // 2. The verified leaf's `0xFF01` is the HPKE recipient (§9.16.1).
        let recipient = self
            .verify_key_package_attestation(&invitee_did, &invitee_key_package)
            .await?;

        // 3. Drive the member-add THROUGH THE CONTEXT ACTOR's governance gate
        //    (structural — replaces the prior off-mailbox `deps.crypto.add_member`
        //    that bypassed the actor, dropping the epoch Commit, skipping the
        //    creator's `role_state` update, racing the mailbox, and enforcing NO
        //    authorization). Routing through `propose_governance_action_checked`:
        //    - AUTHORIZES by construction: the checked variant verifies the
        //      proposer's `governance:propose` capability in-lock, and
        //      `SingleAdminEngine::propose` rejects any proposer that is not the
        //      admin (`NotAdmin`). A non-admin caller is rejected here — nothing
        //      is added — so the `?` surfaces that authorization failure.
        //    - runs the REAL MLS add + `role_state` sync + access keys +
        //      event-log leaf ATOMICALLY in-actor (`execute_add_member`), and
        //      BROADCASTS the epoch-advancing Commit to existing members.
        //
        //    The invitee's reserved KeyPackage is carried on the actor command
        //    envelope (NOT on the signed/logged governance proposal) and threaded
        //    to `execute_add_member`, which binds it to the invitee DID and does
        //    the real add. On a propose failure nothing was added, so there is
        //    nothing to clean up.
        let outcome = self
            .propose_governance_action_checked_carrying_key_package(
                &context_id,
                &creator_did,
                GovernanceAction::AddMember {
                    // The joiner self-assigns the default "member" role in
                    // `build_welcome_joiner_state`; the creator-side add MUST
                    // match it, so this is protocol-fixed, not a free parameter.
                    did: invitee_did.clone(),
                    role: "member".to_owned(),
                },
                proposer_signer,
                Some(invitee_key_package),
            )
            .await?;

        let welcome_message = match outcome.execution_result {
            Some(crate::context::state::GovernanceActionResult::MemberAdded {
                welcome_bytes,
                ..
            }) => welcome_bytes.0,
            None => {
                // Gated to `SingleAdmin` above, so an auto-execute is expected.
                // No execution means the add did NOT run (e.g. governance frozen
                // or a conflict invalidated the proposal) — so NO member was
                // added. Surface an error; do NOT report a governance-approval
                // outcome (this is not a voting context) and do NOT compensate
                // (there is nothing to remove).
                return Err(ContextError::GovernanceFailed(
                    "invite_member: SingleAdmin AddMember did not auto-execute (governance frozen \
                     or the proposal was invalidated); no member was added"
                        .to_owned(),
                ));
            }
            Some(other) => {
                return Err(ContextError::GovernanceFailed(format!(
                    "invite_member: governance AddMember returned an unexpected result: {other:?}"
                )));
            }
        };

        // The member is now ADDED (real MLS add + role_state + broadcast Commit).
        // Every remaining step (sign / serialize / HPKE-seal / deliver) is
        // fallible, so run them in a fallible region; on ANY failure the group
        // would otherwise retain a member who never receives the sealed Welcome
        // (a zombie), so we dispatch a COMPENSATING remove through the same actor
        // governance gate (which broadcasts its own Commit, restoring epoch
        // consistency) before surfacing the error (FIX 4).
        let seal_result: Result<InviteMemberOutcome, ContextError> = async {
            if welcome_message.is_empty() {
                return Err(ContextError::MembershipFailed(
                    "invite_member: in-actor MLS add-member produced no Welcome message".to_owned(),
                ));
            }

            // 4. Assemble the visibility-filtered metadata snapshot + key material.
            let member_count = self
                .member_count(&context_id)
                .await
                .map(|n| u64::try_from(n).unwrap_or(u64::MAX));
            let facts = scp_runtime_types::context::invitation_helpers::SnapshotRuntimeFacts {
                member_count,
                creator_did: Some(creator_did.clone()),
                outlet_count: Some(u64::try_from(params.outlets.len()).unwrap_or(u64::MAX)),
                ..scp_runtime_types::context::invitation_helpers::SnapshotRuntimeFacts::default()
            };
            let metadata_snapshot =
                scp_runtime_types::context::invitation_helpers::build_metadata_snapshot(
                    &params, facts,
                );

            // The key is drawn into a `Zeroizing` buffer and copied once into
            // the bundle's `InvitationKeyMaterial`, which wipes itself on drop.
            let mut metadata_key = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(metadata_key.as_mut());
            let key_material = InvitationKeyMaterial {
                context_metadata_key: *metadata_key,
                sender_key_seed: None,
            };

            // 5. Build + sign the bundle through the creator's signer (ADR-049
            //    Decision 7a). The SAME signer just authorized (and signed) the
            //    governance `AddMember` proposal, so signing the bundle with it makes it
            //    STRUCTURALLY impossible for the authenticated `creator_did` on
            //    the bundle to diverge from the DID the governance gate authorized
            //    (a two-signing-input design could sign the proposal under admin A
            //    while sealing a bundle claiming creator B; the joiner would only
            //    catch it after burning its single-use KeyPackage). One key, one
            //    identity, checked up-front.
            let mut bundle = InvitationBundle {
                context_id: context_id.clone(),
                creator_did: creator_did.clone(),
                relay_urls,
                welcome_message,
                key_material,
                context_params: params,
                metadata_snapshot,
                signature: Vec::new(),
            };
            let bundle_hash = bundle.invitation_bundle_signing_hash().map_err(|e| {
                ContextError::CryptoFailed(format!("invite_member: bundle hash failed: {e}"))
            })?;
            // A custody refusal or timeout keeps its typed custody error.
            bundle.set_signature(proposer_signer.sign_bounded_ed25519(&bundle_hash).await?);

            // 6. HPKE-seal the serialized bundle to the invitee's `0xFF01`.
            //    `wire` carries the plaintext `context_metadata_key`
            //    (§9.10.4.B); `to_wire_bytes` writes it into one `Zeroizing`
            //    buffer that zeroes on drop.
            let wire = bundle.to_wire_bytes().map_err(|e| {
                ContextError::CryptoFailed(format!("invite_member: bundle serialize failed: {e}"))
            })?;
            let (ciphertext, enc) = envelope_seal::hpke_seal_invitation(
                &wire,
                &recipient,
                &context_id,
                creator_did.as_ref(),
            )
            .map_err(|e| {
                ContextError::CryptoFailed(format!("invite_member: HPKE seal failed: {e}"))
            })?;

            // 7. Fork C — deliver to the invitee's scp-invitations routing id when
            //    the transport supports routing-id delivery; otherwise the caller
            //    delivers.
            let sealed = scp_runtime_types::context::invitation_helpers::SealedInvitation {
                context_id: context_id.clone(),
                creator_did: creator_did.clone(),
                enc: enc.as_bytes().to_vec(),
                ciphertext,
            };
            let payload = sealed.to_wire_bytes().map_err(|e| {
                ContextError::CryptoFailed(format!("invite_member: delivery serialize failed: {e}"))
            })?;
            let routing_id = envelope_seal::derive_invitation_routing_id(invitee_did.as_ref());
            let delivered = match self.transport_ref() {
                Some(transport) => {
                    match transport
                        .send_to_routing_id(&routing_id, &payload, INVITATION_TTL_SECS)
                        .await
                    {
                        Ok(()) => true,
                        // A transport that does not support routing-id delivery (or
                        // is offline) returns TransportFailed; this is NON-FATAL:
                        // the (enc, ct) are returned for the caller to deliver, so
                        // the invitee still receives the sealed Welcome — no zombie,
                        // no compensating remove. Any OTHER transport error is
                        // fatal (the invitee gets nothing), so it propagates and
                        // triggers the compensating remove below.
                        Err(ContextError::TransportFailed(_)) => false,
                        Err(e) => return Err(e),
                    }
                }
                None => false,
            };

            Ok(InviteMemberOutcome::Sealed {
                bundle: sealed,
                delivered,
            })
        }
        .await;

        match seal_result {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                // FIX 4 — compensating remove: the member was added but the
                // invitation could not be sealed/delivered, so route a
                // RemoveMember through the SAME actor governance gate. The remove
                // runs in-actor (real MLS remove + role_state strip) and
                // broadcasts its own epoch-advancing Commit, so no member is left
                // who never received the Welcome and the group stays epoch-
                // consistent. Best-effort: if the compensation does not ACTUALLY
                // execute we log loudly (a member may linger) but still surface
                // the original sealing error.
                //
                // The remove is a rollback ONLY when it AUTO-EXECUTED: an `Ok`
                // with `execution_result == Some(MemberRemoved)`. A propose can
                // return `Ok` with `execution_result: None` — the proposal was
                // created but NOT auto-executed (e.g. governance froze via a
                // concurrent CloseContext in the yield window between the two
                // awaits) — in which case the member is STILL a member. Treating
                // that (or any non-`MemberRemoved` result, or an `Err`) as
                // success would mask exactly the zombie this compensation exists
                // to prevent, so only `Some(MemberRemoved)` logs a rollback; every
                // other shape takes the loud error branch.
                let compensation = self
                    .propose_governance_action_checked_carrying_key_package(
                        &context_id,
                        &creator_did,
                        GovernanceAction::RemoveMember {
                            did: invitee_did.clone(),
                            reason: Some(
                                "invitation could not be sealed/delivered after the add".to_owned(),
                            ),
                        },
                        proposer_signer,
                        None,
                    )
                    .await;
                match compensation {
                    Ok(outcome)
                        if matches!(
                            outcome.execution_result,
                            Some(crate::context::state::GovernanceActionResult::MemberRemoved)
                        ) =>
                    {
                        tracing::warn!(
                            context_id = %context_id,
                            invitee = %invitee_did,
                            error = %e,
                            "invite_member: sealing failed after the add; compensating remove \
                             executed — the added member was rolled back"
                        );
                    }
                    Ok(outcome) => {
                        // Propose succeeded but the remove did NOT auto-execute
                        // (e.g. governance froze in the window) — the member was
                        // NOT removed. This is a zombie; surface it loudly.
                        tracing::error!(
                            context_id = %context_id,
                            invitee = %invitee_did,
                            error = %e,
                            compensating_remove_status = ?outcome.status,
                            "invite_member: sealing failed after the add AND the compensating \
                             remove did NOT execute (proposal created but not auto-executed); the \
                             invitee remains a member without ever receiving the sealed Welcome; \
                             manual removal required"
                        );
                    }
                    Err(remove_err) => {
                        tracing::error!(
                            context_id = %context_id,
                            invitee = %invitee_did,
                            error = %e,
                            compensating_remove_error = %remove_err,
                            "invite_member: sealing failed after the add AND the compensating \
                             remove failed — the invitee may remain a member without ever \
                             receiving the sealed Welcome; manual removal required"
                        );
                    }
                }
                Err(e)
            }
        }
    }

    // (WelcomeJoinRequest is defined at module scope below the impl.)

    /// Spawns a per-context actor for a node that JOINED a context by
    /// processing a received Welcome (ADR-049 Phase 2J, spawn-from-Welcome;
    /// Deferred Work #1).
    ///
    /// Without this, a Welcome-joined node has a populated crypto provider (it
    /// can DECRYPT) but no actor-backed send [`ContextHandle`](crate::context::ContextHandle)
    /// and no event log — so any send fails closed with "context not found in
    /// node's handles". This entrypoint makes the joiner a real, send-capable
    /// participant.
    ///
    /// It is the join-side counterpart of `crate::context::lifecycle_helpers::create_context`,
    /// modeled as a special case of `restore`/`spawn_actor_with_state` **seeded
    /// from Welcome-derived state**:
    ///
    /// 1. Fuse the join through the joiner's
    ///    [`KeyPackageStoreActor`](crate::context::supervisor::key_package_actor::KeyPackageStoreActor)
    ///    (`ConfirmConsume(welcome)`), which produces the joined
    ///    [`ScpMlsGroup`](scp_mls::group::ScpMlsGroup) and durably
    ///    consumes the single-use KeyPackage (two independent single-use
    ///    anchors preserved).
    /// 2. INSTALL the joined group into the live crypto provider
    ///    ([`NodeMlsFactory::install_joined_group`](crate::crypto::mls::provider::NodeMlsFactory::install_joined_group)),
    ///    plus a locally-minted sender key (spec §9.16.1).
    /// 3. Build the joiner's Welcome-derived
    ///    [`PerContextState`](crate::context::actor::state::PerContextState)
    ///    (governance from the legible params, the joiner assigned the default
    ///    `"member"` role, the creator as admin, a fresh event log).
    /// 4. Write the initial Class-S snapshot to `mls_storage` **fail-closed,
    ///    BEFORE the spawn is acked** (mirrors the `restore_context` crypto-
    ///    restore fail-closed ordering). A persist failure returns `Err` and
    ///    tears the just-installed group back out — never leaving a live,
    ///    half-keyed actor.
    /// 5. Spawn the owned-state actor and register its send handle.
    ///
    /// # Key-injection crash-safety (Decision 1/8/9)
    ///
    /// The joiner's picked-up crypto (the joined MLS group + its own sender
    /// key) is **Class M** — it lives in the supervisor-owned crypto provider
    /// `Arc`, captured into the fail-closed snapshot's `mls_crypto_state` and
    /// max-merged on respawn (spec §23.17.2 Invariant 2). Because the snapshot
    /// is persisted fail-closed BEFORE the actor is reachable (its send handle
    /// is registered only in step 5), a crash between "keys injected" and "keys
    /// durably persisted" leaves either a fully-keyed snapshot (restore
    /// rehydrates the whole context) or none (nothing to resurrect) — never a
    /// half-keyed actor. The `welcome_scratchpad` is transient join-handshake
    /// state, consumed by the fused join; it is not persisted (there is nothing
    /// authorization-critical left in it once the join lands).
    ///
    /// # Errors
    ///
    /// - The `ConfirmConsume` error (bad/duplicate Welcome, single-use replay,
    ///   or a lost group on an own-prior-completion retry).
    /// - [`ContextError::CreationFailed`] if a group / actor is already
    ///   registered for `context_id` (first-writer-wins).
    /// - [`ContextError::PersistenceFailed`] if the fail-closed initial
    ///   snapshot persist fails (the installed group is rolled back).
    /// - Provider-init / governance-validation errors surfaced while building
    ///   the joiner state.
    // Genuinely `pub` — the bridge-external "spawn under a locally-custodied
    // identity" bootstrap, the join-side peer of `create_context`. It takes a
    // bare `DID` (local-identity custody is enforced at the FFI bridge layer,
    // the same trust model as `create_context`) and returns only a
    // `ContextHandle` — context state, never per-identity secret crypto — so it
    // sits on the bare-`DID` bootstrap axis, NOT the actor-internal
    // `OwnedIdentityDid` per-identity-secret axis (ADR-049 Decision 5).
    //
    // The heavily-commented crash-safety ladder (reversible prechecks → consume
    // → install → build → persist → crypto-durability check → spawn, each with
    // its rollback-on-error path) reads clearer as one linear sequence than split
    // across helpers, hence the line-count allow.
    #[allow(clippy::too_many_lines)]
    pub async fn spawn_actor_from_welcome(
        self: &Arc<Self>,
        owning_did: DID,
        req: WelcomeJoinRequest,
    ) -> Result<crate::context::ContextHandle, ContextError> {
        use crate::context::supervisor::key_package_actor::KeyPackageCommand;

        let WelcomeJoinRequest {
            context_id: hint_context_id,
            creator_did: hint_creator_did,
            sealed_bundle_enc,
            sealed_bundle_ct,
            reservation_id,
            local_pseudonym,
        } = req;

        // ---- OPEN the sealed §5.12.3 invitation bundle (§9.16.2 Open) --------
        // The open is the FIRST thing the join does, before any precheck, the
        // irreversible KeyPackage consume, or any state build, so authority
        // derives ONLY from the creator-signed, HPKE-sealed bundle, never from
        // attacker-injectable caller params (BLACK-2J10-001 admin-hijack).
        //
        // Every step of the open only reads, so it runs before
        // `bootstrap_spawn_lock`: a slow or hostile custody device cannot pin
        // that lock and wedge every other bootstrap node-wide. A concurrent
        // consume of the same reservation is still caught under the lock, by
        // the `ConfirmConsume` below. Each custody call is bounded by the
        // custody budget (`SIGN_TIMEOUT`, ADR-049 Decision 7a); a failure here
        // has consumed nothing.
        //
        // 1. The enc is validated before any custody call (§9.16.2 Open step
        //    1): a malformed point is rejected without touching the wrapping
        //    key or the reservation.
        let enc = scp_protocol::crypto::hpke::p256::validate_enc(&sealed_bundle_enc)
            .map_err(|e| ContextError::InvitationEncMalformed(e.to_string()))?;
        // 2. The joiner's wrapping key, loaded from its custody handle record.
        let wrapping_key = self.load_wrapping_key(&owning_did).await?;
        // 3. The `0xFF01` the inviter sealed to: the reserved KeyPackage's own.
        let reserved_wrapping_key = self
            .key_package_store_for(&owning_did)
            .await?
            .send(|reply| KeyPackageCommand::ReservedWrappingKey {
                reservation_id: reservation_id.clone(),
                reply,
            })
            .await?;
        // 4. The three keys must agree (§9.16.2 Open step 2): the reserved
        //    `0xFF01`, the public key custody reports for the wrapping handle
        //    (`pkRm`), and the supervisor's recorded wrapping key. A
        //    disagreement means the reservation, the custody, or the record
        //    names another key; nothing is opened or consumed. A custody
        //    public key that is not a valid 65-byte P-256 point disagrees too.
        let pk_rm = wrapping_key.read_public().await.map_err(|e| match e {
            ContextError::Custody(_) => e,
            other => ContextError::InvalidKeyPackage(format!(
                "spawn-from-Welcome: the custody wrapping key is not a P-256 point: {other}"
            )),
        })?;
        if reserved_wrapping_key.as_bytes() != &pk_rm || &pk_rm != wrapping_key.public() {
            return Err(ContextError::InvalidKeyPackage(
                "spawn-from-Welcome: the reserved KeyPackage's scp_wrapping_key, the custody \
                 wrapping key, and the recorded wrapping key disagree"
                    .to_owned(),
            ));
        }
        // 5. The KEM Diffie-Hellman runs inside custody on the wrapping handle;
        //    no wrapping scalar exists in the runtime.
        let dh = wrapping_key.agree(&enc).await?;
        // 6. The rest of the RFC 9180 open (`ExtractAndExpand`, `KeySchedule`,
        //    AEAD) is software. `info`/`aad` are rebuilt from the UNTRUSTED
        //    `hint_context_id` / `hint_creator_did`; a successful AEAD open
        //    PROVES the sealer used identical values, and the signed bundle is
        //    cross-checked against them below. `bundle_wire` holds the
        //    plaintext `context_metadata_key` (§9.10.4.B) and zeroes on drop.
        let bundle_wire =
            scp_protocol::crypto::envelope_seal::hpke_open_invitation_with_external_dh(
                &sealed_bundle_ct,
                &dh,
                &reserved_wrapping_key,
                &enc,
                &hint_context_id,
                hint_creator_did.as_ref(),
            )
            .map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "spawn-from-Welcome: invitation open failed: {e}"
                ))
            })?;
        drop(dh);

        // 7. Serialize the rest of the join against every other bootstrap for
        // this id (the `CreateContext` / `ImportContext` / `RestoreContext`
        // dispatch arms, the `standing_context` path, and the off-mailbox
        // watchdog `respawn_from_snapshot`) by holding `bootstrap_spawn_lock`
        // from here to the end of the entrypoint, exactly as those four peer
        // bootstraps do.
        //
        // Without this guard the off-mailbox watchdog `respawn_from_snapshot` can
        // race the join: a victim actor panics → the watchdog despawns it from
        // `self.actors` before `restore_context` re-inserts it → this join's
        // Precheck-A `lookup` MISSES the mid-despawn victim → both paths write
        // crypto (`restore_crypto_state` does a blind `contexts.insert`) and this
        // join's rollback `delete_context` can destroy the victim's freshly
        // restored snapshot. Taking the lock before Precheck A makes it (and
        // its durable companion below) atomic w.r.t. every other bootstrap + the
        // respawn, so the first writer wins deterministically.
        //
        // Lock order is always `bootstrap_spawn_lock` → `write_lock` (the register
        // in `spawn_actor_with_state` below takes `write_lock` INSIDE this guard,
        // identical to create/import/standing/respawn); neither `build_actor_deps`,
        // the crypto ops, nor `spawn_actor_with_state` re-acquires
        // `bootstrap_spawn_lock`, so this is re-entrancy- and deadlock-free. No
        // custody call for the wrapping key runs under either lock.
        let bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
        let bundle = scp_protocol::context::InvitationBundle::from_wire_bytes(&bundle_wire)
            .map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "spawn-from-Welcome: invitation bundle decode failed: {e}"
                ))
            })?;

        // Resolve the creator's #active key and VERIFY the creator signature —
        // the root of trust for ALL authority the joiner installs. A resolution
        // failure is treated as a permanent reject (fail-closed), matching the
        // import path: the `KeyResolver` returns `Option` with no transient
        // signal, so there is no retryable-vs-permanent distinction to model here.
        let creator_vk =
            scp_runtime_types::crypto::mls::attestation_verification::resolve_active_key(
                self.key_resolver()?,
                bundle.creator_did.clone(),
            )
            .await
            .map_err(|e| {
                ContextError::CryptoFailed(format!(
                    "spawn-from-Welcome: creator #active key resolution task failed: {e}"
                ))
            })?
            .ok_or_else(|| {
                ContextError::CryptoFailed(format!(
                    "spawn-from-Welcome: cannot resolve #active key for creator '{}'",
                    bundle.creator_did
                ))
            })?;
        bundle.verify(&creator_vk).map_err(|e| {
            ContextError::CryptoFailed(format!(
                "spawn-from-Welcome: invitation signature invalid: {e}"
            ))
        })?;
        // metadata_snapshot.structural must agree with the signed context_params
        // (both are under the same signature — a divergence is a signed
        // self-contradiction; spec §5.12.3.1 validation step 2).
        bundle.verify_structural_consistency().map_err(|e| {
            ContextError::CryptoFailed(format!(
                "spawn-from-Welcome: invitation metadata inconsistent with signed params: {e}"
            ))
        })?;

        // Cross-check the untrusted binding hints against the AUTHENTICATED
        // bundle. The AEAD open already guarantees equality with what the sealer
        // used; this is belt-and-suspenders (and makes the invariant explicit).
        if bundle.context_id != hint_context_id || bundle.creator_did != hint_creator_did {
            return Err(ContextError::CryptoFailed(
                "spawn-from-Welcome: invitation binding hints disagree with the signed bundle"
                    .to_owned(),
            ));
        }

        // From here on, ALL authority derives from the creator-signed bundle —
        // this is what closes FFI-02 / BLACK-2J10-001 (creator_did, governance,
        // ceiling, economic policy, consequence rules, outlets are creator-signed,
        // not attacker-injectable). The §5.13.3 `0xFF02` cross-check below
        // additionally binds these against the COMMITTED MLS group.
        let context_id = bundle.context_id.clone();
        let creator_did = bundle.creator_did.clone();
        let params = bundle.context_params.clone();
        // §5.12.3.1: the creator-signed bundle names the relays that host the
        // context; the joiner stores that set (PUSH-025).
        let relay_urls = bundle.relay_urls.clone();
        let welcome_bytes = bundle.welcome_message.clone();

        // ---- REVERSIBLE PRECHECKS (before the irreversible ConfirmConsume) ----
        // The KeyPackage burn in step 1 is a SINGLE-USE, irreversible cost. Every
        // check that can be made from the legible request alone runs FIRST, so a
        // collision or a malformed request fails WITHOUT consuming the anchor and
        // WITHOUT persisting anything (BLACK-2J-01 / BLACK-2J-02).

        // Precheck A (BLACK-2J-01) — up-front LIVE-actor existence check. A context
        // already has a registered actor if it is live in ANY mode, INCLUDING a
        // broadcast context (whose crypto lives in `broadcast_keys`, not the
        // `contexts` map `install_joined_group` guards — so the step-2 install
        // would NOT catch a broadcast collision, but this registry check does).
        // Refusing here, before the consume + persist, stops a griefing-via-
        // colliding-`context_id` join from overwriting a LIVE context's durable
        // snapshot. This is only HALF of first-writer-wins: `lookup` sees the live
        // `self.actors` registry, NOT durable storage, so a persisted-but-UNSPAWNED
        // same-id snapshot (a post-restart / non-Active / failed-restore window)
        // would slip past it. The durable companion below (after `build_actor_deps`
        // builds `deps.persistence`, still BEFORE the consume) closes that window;
        // the two together give first-writer-wins against both a live actor and an
        // on-disk snapshot, and — because the whole body holds
        // `bootstrap_spawn_lock` — against a concurrent same-id restore/respawn. The
        // step-5 atomic `spawn_actor_with_state` Vacant check remains the in-memory
        // race backstop.
        if self.lookup(&context_id).is_some() {
            return Err(ContextError::CreationFailed(format!(
                "spawn-from-Welcome refused: a context actor is already registered \
                 for '{context_id}' (first-writer-wins) — rejecting before consuming \
                 the single-use KeyPackage"
            )));
        }

        // Precheck B (BLACK-2J-04) — require a REAL §9.10.4 local pseudonym.
        // spawn-from-Welcome always stands up an ENCRYPTED context; the FFI
        // boundary derives the pseudonym via `KeyCustody::derive_pseudonym`
        // (§9.10.4) and the runtime holds no signing key to derive it here. A
        // `None` must NOT silently become the `[0u8; 32]` sentinel on the join
        // surface (a linkable constant / silent security default) — reject it.
        let local_pseudonym = local_pseudonym.ok_or_else(|| {
            ContextError::CreationFailed(
                "spawn-from-Welcome requires a real §9.10.4 local pseudonym for the \
                 encrypted context; received None (no silent [0u8; 32] sentinel on \
                 the join surface)"
                    .to_owned(),
            )
        })?;

        // Precheck C (BLACK-2J-02) — reversible legible-param validation. A
        // joiner's `params` arrive from a peer, and every check that reads only
        // `params` (not the joined group) runs here, before the consume, so
        // malformed params fail without burning the KeyPackage and a joiner
        // never persists params a later restore would refuse. This is the one
        // validator create, import, restore and governance call; the inviter's
        // params may be §5.10-promoted, so it runs with `Existing` and skips
        // the template check.
        crate::context::params_validation::validate_params(
            &params,
            crate::context::params_validation::ParamsOrigin::Existing,
        )
        .map_err(|e| ContextError::CreationFailed(e.to_string()))?;

        // Build the joiner's actor deps (crypto, transport, event log, KP store,
        // mls_storage, persistence, capability token) for the owning identity.
        let deps = self.build_actor_deps(&owning_did).await?;

        // Precheck D (BLACK-2J-06) — DURABLE first-writer-wins. Precheck A only
        // sees the LIVE `self.actors` registry; a persisted-but-unspawned same-id
        // snapshot (post-restart window, a non-Active snapshot, or a context whose
        // restore has not run yet) is invisible to it. spawn-from-Welcome is the
        // FIRST join for a NEW context, so an existing durable snapshot means either
        // a griefing victim (whose membership / governance / event-log root a blind
        // step-4 persist would OVERWRITE, resurrecting an attacker-influenced
        // context on the next restore) or the joiner's own stale/prior context
        // (which must be brought back via restore/reconnect, NOT re-joined). Either
        // way, refusing when a snapshot already exists is the correct fail-closed
        // stance. Run it here — under `bootstrap_spawn_lock` (atomic vs a concurrent
        // restore) and BEFORE the irreversible `ConfirmConsume` — so a collision
        // does not even burn the single-use KeyPackage. A storage READ fault is
        // treated as fail-closed (we cannot prove the id is free, so we refuse).
        match deps.persistence.load_context(&context_id).await {
            Ok(None) => {}
            Ok(Some(_)) => {
                return Err(ContextError::CreationFailed(format!(
                    "spawn-from-Welcome refused: a durable snapshot already exists for \
                     '{context_id}' (first-writer-wins) — an existing context must be \
                     recovered via restore/reconnect, not re-joined; rejecting before \
                     consuming the single-use KeyPackage"
                )));
            }
            Err(e) => {
                return Err(ContextError::PersistenceFailed(format!(
                    "spawn-from-Welcome: cannot verify durable first-writer-wins for \
                     '{context_id}' (snapshot existence read failed: {e}) — refusing \
                     fail-closed before consuming the single-use KeyPackage"
                )));
            }
        }

        // ADR-056: the crypto keys under the canonical 32-byte DIGEST.
        let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);

        // The first-state guard lives outside the timeout, so a join that fails
        // or times out after step 4 puts back what it wrote (ADR-029
        // Implementation).
        let first_state =
            crate::context::shared::lifecycle::FirstStateRollback::new(&deps, &context_id)?;

        // Bound the whole locked long-running region under `LIFECYCLE_TIMEOUT`,
        // exactly as the `CreateContext` / `ImportContext` / `RestoreContext`
        // dispatch arms and `respawn_from_snapshot` bound theirs. This region runs
        // under the GLOBAL `bootstrap_spawn_lock` and contains an UNBOUNDED wait:
        // the step-1 `ConfirmConsume` send blocks on MLS processing of
        // attacker-supplied `welcome_bytes` with NO reply timeout. Without this
        // bound a slow or crafted Welcome would pin the global lock and wedge every
        // other bootstrap (create / join / import / restore / respawn) node-wide —
        // a node-scale bootstrap + crash-recovery DoS. The reversible prechecks
        // (A–D) above are fast and stay OUTSIDE the bound; nothing has been
        // consumed or persisted before this point, so an early elapse there is
        // impossible. On elapse the rollback arm tears down any installed group +
        // persisted snapshot, then the function returns (dropping
        // `_bootstrap_guard`), releasing the global lock after at most
        // `LIFECYCLE_TIMEOUT` instead of forever. The `ConfirmConsume` KP burn is
        // irreversible: if the elapse lands AFTER the consume the KeyPackage is
        // already spent (the same accepted cost as a crash), but the rollback still
        // leaves no half-keyed crypto or orphaned durable snapshot resident.
        let spawn_outcome: Result<crate::context::ContextHandle, ContextError> =
            match tokio::time::timeout(
                Self::LIFECYCLE_TIMEOUT,
                // `Box::pin` the (large, ~16 KB) join future off the stack —
                // mirrors the `Box::pin` the create / import / restore dispatch
                // arms apply to their delegated lifecycle futures.
                Box::pin(async {
                    // 1. Fuse the join through the KeyPackage actor: this runs the
                    //    consumed-init-key-backstopped `join_from_welcome` and durably
                    //    consumes the single-use KP, returning the joined group. A failed
                    //    join keeps the reservation intact for retry/cancel (the KP is not
                    //    burned) and surfaces here as `Err`. From this point the ONLY
                    //    irreversible cost of a late failure is the burned KeyPackage — every
                    //    error path below rolls the crypto AND the durable snapshot back.
                    let joined_group = deps
                        .key_package_store
                        .send(|reply| KeyPackageCommand::ConfirmConsume {
                            reservation_id,
                            welcome_bytes,
                            reply,
                        })
                        .await?;

                    // The joined group is already at its real ABSOLUTE MLS epoch (a Welcome
                    // for a creator@0 → add-member Commit group is epoch ≥ 1). Read it BEFORE
                    // the group moves into `install_joined_group`, so the joiner seeds its
                    // `EpochState.mls_epoch` to the true group epoch — not a `0` placeholder
                    // that would stamp wrong epochs into checkpoints / recovery envelopes /
                    // governance events (bug-catcher F1).
                    let joined_epoch = joined_group.epoch().map_err(|e| {
                        ContextError::CryptoFailed(format!(
                            "spawn-from-Welcome: failed to read the joined group's MLS epoch: {e}"
                        ))
                    })?;

                    // 1b. FFI-02 (§5.13.3): verify the caller-supplied `params`
                    //     against the parameters the CREATOR cryptographically
                    //     committed into the joined group's `scp_context_params`
                    //     (`0xFF02`) group_context extension — folded into the MLS
                    //     key schedule, so it is the group's own attestation of its
                    //     governance model, capability ceiling, ceiling policy, mode,
                    //     context_id, and — rule 8 — its GENESIS creator/admin DID.
                    //     The creator binding is the sole anchor of admin identity
                    //     for a DID-less governance model (SingleAdmin, whose
                    //     `governance_policy_hash` is a constant): the joiner refuses
                    //     unless the bundle's authenticated `creator_did` equals the
                    //     one the group committed at creation, so a signed bundle
                    //     naming a DIFFERENT admin installs NO `SingleAdminEngine`
                    //     (BLACK-2J10-001-R). `WelcomeJoinRequest.params` is UNTRUSTED
                    //     caller input: a malicious inviter can present benign params
                    //     while the real group differs. Run this HERE — after the
                    //     KeyPackage is (irreversibly) consumed but BEFORE
                    //     `install_joined_group`, `build_welcome_joiner_state`, the
                    //     persist, and the spawn — so a mismatch installs NO crypto,
                    //     persists NO snapshot, and registers NO actor; the only spent
                    //     cost is the already-burned single-use KeyPackage (the same
                    //     accepted cost as any post-consume failure). The rejected
                    //     `joined_group` is dropped here, which FREES its key material
                    //     (MlsGroup secrets + Ed25519 signer + MemoryStorage), and the
                    //     signer's private key zeroizes on drop; disposing
                    //     explicitly here would be inert since it drops immediately —
                    //     nothing half-installed to roll back. Passing verifies
                    //     that `build_welcome_joiner_state` below only ever builds
                    //     authority the group itself attests. A group with no `0xFF02`
                    //     (not an SCP context) or any rule 2-6 mismatch is refused
                    //     (§5.13.3 rule 1 + rules 2-6). So is a group whose
                    //     committed `creation_timestamp_secs` is missing, above
                    //     2^53 − 1, or later than this joiner's clock plus the §9.8.2
                    //     future bound (rule 9). The returned committed `T0` is the
                    //     joiner's pseudonym-rotation base and TTL base (rule 9).
                    let committed_t0 = crate::context::restored_crypto::verify_scp_context_binding(
                        joined_group
                            .group_context_extension()
                            .map_err(|e| e.to_string()),
                        &context_id,
                        creator_did.as_ref(),
                        &params,
                        deps.clock.now_secs(),
                        None,
                        "spawn-from-Welcome",
                    )
                    .map_err(ContextError::CryptoFailed)?;

                    // 2. #2148 (ADR-049 birth-into-actor) WELCOME seam: BIRTH the
                    //    joiner's crypto as OWNED material — the joined group (moved in
                    //    here, consuming `joined_group`) plus a locally-minted sender key
                    //    (spec §9.16.1; the Welcome carries no sender key). This touches
                    //    NO provider map: there is no insert-then-`take_crypto_state`
                    //    round-trip and no cross-map check-then-insert to race (#2167
                    //    TOCTOU is impossible by construction). The crypto is held in the
                    //    local `owned` binding until it is seeded onto `state` at 2b; a
                    //    failure on any early-return between here and the spawn DROPS it
                    //    with `state` (the `SenderKey` zeroizes via `ZeroizeOnDrop`; the
                    //    `ScpMlsGroup`'s signer zeroizes on both the bare drop and the
                    //    explicit `dispose_secrets`/`destroy_group` rollback branches,
                    //    since `SignatureKeyPair` holds its private key in `SecretVLBytes`).
                    //    Double-birth / durable-divergence is guarded by the whole
                    //    entrypoint running under the global `bootstrap_spawn_lock`
                    //    together with Precheck A (live-actor) + Precheck D (durable
                    //    first-writer-wins); the registry write-lock insert at step 5
                    //    guards only the in-memory registry slot, NOT durability (this
                    //    path PERSISTS at step 4, BEFORE it registers at step 5 — see
                    //    step 5's note).
                    let mut owned = deps.crypto.install_joined_group(joined_group);

                    // 3. Build the Welcome-derived PerContextState (EMPTY encrypted mode).
                    //    On failure, dispose `owned` FIRST (#2148 F6) — it is the live
                    //    owner of the born crypto here (not yet seeded onto `state`). A
                    //    bare drop already zeroizes the joined group's provider-storage
                    //    values and the Ed25519 signer; `dispose_secrets` (`destroy_group`)
                    //    releases the same material eagerly (the `SenderKey` zeroizes on
                    //    its own drop).
                    //    On this branch `owned` drops immediately after, so the dispose is
                    //    equivalent to that drop. Nothing is provider-resident
                    //    and no durable snapshot exists yet, so there is nothing else to
                    //    tear down.
                    let mut state = match Self::build_welcome_joiner_state(
                        &deps,
                        WelcomeBundleFacts {
                            context_id: &context_id,
                            params: &params,
                            creator_did: &creator_did,
                            relay_urls: &relay_urls,
                        },
                        committed_t0,
                        &owning_did,
                        local_pseudonym,
                        joined_epoch,
                    ) {
                        Ok(state) => state,
                        Err(e) => {
                            owned.dispose_secrets();
                            return Err(e);
                        }
                    };

                    // 2b. SEED the owned crypto onto the actor `state`.
                    //     `build_welcome_joiner_state` deliberately built an EMPTY
                    //     encrypted mode; `seed` installs the owned group + sender key and
                    //     resumes `send_sequence` via `from_persisted` (a freshly-born
                    //     joiner group starts at 0). From here the actor `state` is the
                    //     SOLE crypto authority — the durability check (3b) and the
                    //     fail-closed persist (4) read the export off `state`. Every
                    //     early-return below now DROPS the seeded crypto with `state`
                    //     (the `SenderKey` and the MLS group's signer zeroize on drop), so
                    //     no provider teardown is needed and a retry
                    //     re-drives a fresh Welcome.
                    state.seed_encrypted_crypto_from_owned(owned);

                    let handle = state.handle.clone();

                    // 3a. Activate the joiner's lifecycle handle. A freshly-built
                    //     handle is `Creating` (`ContextHandle::new`); the create and
                    //     restore paths transition to `Active` once their group is
                    //     installed, and a Welcome-JOINER is equally live at this point
                    //     — its MLS group is installed (step 2) and its authority is
                    //     verified (step 1b). Without this transition the joined context
                    //     is stuck in `Creating`, so every `Active`-gated operation
                    //     (send, governance, TTL) fails closed with `ContextNotActive`
                    //     — i.e. the "live send-capable actor" this entrypoint is
                    //     documented to stand up (§9(b)) could receive but never send.
                    //     `state.handle` and this `handle` clone share one
                    //     `Arc<ArcSwap<ContextState>>`, so the actor's own handle observes
                    //     `Active` too. On a transition failure dispose the seeded `state`
                    //     FIRST (#2148 F6): `state` owns the born crypto here.
                    //     `dispose_secrets` (`destroy_group`) eagerly frees the group NOW;
                    //     the signer zeroizes on drop — same as the bare drop
                    //     that follows this early return (the `SenderKey` zeroizes on its
                    //     own drop), so the call is equivalent to that drop. Nothing is
                    //     persisted or
                    //     registered yet.
                    if let Err(e) =
                        handle.transition_to(&scp_protocol::context::ContextState::Active)
                    {
                        // #2199: rollback path — no attestation is built here, so discard
                        // the observed `DisposalOutcome` (the `#[must_use]` guards that the
                        // honest signal is consumed on the seams that DO build one).
                        let _ = state.dispose_secrets();
                        return Err(e);
                    }

                    // 3b. Entrypoint-level crypto durability check — BEFORE the persist
                    //     (BLACK-2J-03 / crypto L2 / simplifier). `build_snapshot_for_persist`
                    //     is FAIL-OPEN by design for existing members: if `export_crypto_state`
                    //     errors it persists an EMPTY crypto blob with `needs_reconnect = true`
                    //     and the persist SUCCEEDS, so an existing member restores and re-enters
                    //     the §23.11 reconnection pipeline. A Welcome-JOINER cannot
                    //     reconnect-derive — it would need a fresh Welcome — so a keyless
                    //     snapshot means a live send-capable actor with NO durable keys. The
                    //     snapshot's crypto blob is a 1:1 copy of `export_crypto_state`, and the
                    //     export is DETERMINISTIC between the seed above and here (no mutation
                    //     in between), so re-reading the live export tells us exactly what a
                    //     snapshot WOULD carry. Check it here, BEFORE persisting: on a
                    //     non-durable export dispose the seeded `state` FIRST (#2148 F6) —
                    //     `state` owns the born crypto. `dispose_secrets` (`destroy_group`)
                    //     eagerly frees the group NOW; the signer zeroizes on drop — same
                    //     as the bare drop that follows this early return (the
                    //     `SenderKey` zeroizes on its own drop), so the call is equivalent to
                    //     that drop.
                    //     Nothing has been persisted yet, so there is no durable snapshot to
                    //     delete (strictly cleaner than persist-then-delete, same
                    //     fail-closed guarantee).
                    // ADR-049 PR-6 (read-authority switch): floors sourced from
                    // the AUTHORITATIVE Supervisor-owned Class-M registry
                    // (`deps.supervisor.export_*`) and threaded into
                    // `export_crypto_state` as the durable-blob params; the
                    // provider floor mirrors are deleted.
                    // #2148 (ADR-049 birth-into-actor) WELCOME seam: the crypto is
                    // OWNED by the seeded actor `state` (born owned at step 2), so read
                    // the export off `state` — identical to what
                    // `build_snapshot_for_persist` (step 4) will persist.
                    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the crypto move relocated
                    // `export_crypto_state` onto the actor `state`, so the former
                    // provider `arm_export_failure_once` seam no longer sits on
                    // this path. The supervisor-resident one-shot seam
                    // (`force_welcome_export_failure_once`, armed pre-spawn by the
                    // durability test) forces THIS actor-export read to be treated
                    // as non-durable. Production builds compile it to a constant
                    // `false` (the field and the branch are gated away).
                    #[cfg(any(test, feature = "testing"))]
                    let forced_non_durable = self
                        .force_welcome_export_failure_once
                        .swap(false, std::sync::atomic::Ordering::SeqCst);
                    #[cfg(not(any(test, feature = "testing")))]
                    let forced_non_durable = false;
                    if forced_non_durable
                        || !crate::context::snapshot::welcome_snapshot_crypto_is_durable(
                            &state.export_crypto_state(
                                self.export_sender_key_epochs(&context_id_bytes),
                                self.export_recv_sequence_floors(&context_id_bytes),
                            ),
                        )
                    {
                        // #2199: rollback path — no attestation is built here, so discard
                        // the observed `DisposalOutcome` (the `#[must_use]` guards that the
                        // honest signal is consumed on the seams that DO build one).
                        let _ = state.dispose_secrets();
                        return Err(ContextError::PersistenceFailed(format!(
                            "spawn-from-Welcome: the joined group for '{context_id}' produces no \
                         durable MLS crypto export (export failed / needs_reconnect) — a \
                         joiner cannot reconnect-derive, so the spawn fails closed BEFORE \
                         persisting rather than standing up a keyless send-capable actor"
                        )));
                    }

                    // 4. Write the joiner's first `last_relay_contact` (ADR-029
                    //    Implementation), then persist the initial Class-S snapshot
                    //    FAIL-CLOSED, both BEFORE the spawn is acked: the member's history
                    //    starts at the Welcome. The snapshot captures the seeded actor MLS
                    //    crypto state (`build_snapshot_for_persist` reads
                    //    `state.export_crypto_state`), so a crash after this point
                    //    rehydrates a fully-keyed context. A failed write returns `Err`,
                    //    and `first_state` puts back both records after the timed region;
                    //    before the early return, dispose the seeded `state`'s crypto — the
                    //    call is equivalent to the bare drop that follows — never a live
                    //    half-keyed actor and never an orphaned/clobbered durable snapshot.
                    if let Err(e) = crate::context::shared::lifecycle::persist_first_state(
                        &state,
                        &deps,
                        &context_id,
                        &first_state,
                    )
                    .await
                    {
                        // #2199: rollback path — no attestation is built here, so discard
                        // the observed `DisposalOutcome` (the `#[must_use]` guards that the
                        // honest signal is consumed on the seams that DO build one).
                        let _ = state.dispose_secrets();
                        return Err(e);
                    }

                    // 5. Spawn the owned-state actor + register its send handle. On failure
                    //    (e.g. a racing duplicate registration) delete the durable snapshot
                    //    so no orphaned durable state survives the `Err`; `spawn_actor_with_state`
                    //    consumes `state`, and its dup-registration reject arm disposes the
                    //    seeded crypto (eager free; the signer zeroizes on drop) before
                    //    dropping it — it never returns to any provider. IMPORTANT: this path PERSISTS at
                    //    step 4 BEFORE it registers here, so durable double-birth correctness
                    //    rests on the whole entrypoint running under the global
                    //    `bootstrap_spawn_lock` with Precheck A (live-actor) + Precheck D
                    //    (durable first-writer-wins) rejecting a duplicate BEFORE the step-4
                    //    persist — NOT on this step-5 write-lock insert, which guards only the
                    //    in-memory registry slot. (The deleted provider `taken_context_ids` /
                    //    `Entry::Vacant` guard was a redundant re-check of the durable
                    //    property those prechecks own; #2167 subsumed.) The persist-before-
                    //    register order (step 4 then step 5) is deliberate and durability-safe
                    //    under `bootstrap_spawn_lock` + Precheck A/D; it must NOT be reordered
                    //    (a persist-after-register would open a crash window that loses the
                    //    context). Start a fresh crash window for this id FIRST (under
                    //    `bootstrap_spawn_lock`, mirroring the create / import / standing
                    //    bootstraps): a previously-poisoned+despawned same-id context must
                    //    not leave the freshly-spawned joiner actor inheriting a sticky
                    //    poison window. A failed spawn gets the prior window back.
                    let _crash_window = self.begin_bootstrap_window(&context_id);
                    let owned_deps = deps.clone_for_spawn();
                    self.spawn_actor_with_state(state, owned_deps, None).await?;
                    first_state.commit();

                    Ok(handle)
                }),
            )
            .await
            {
                Ok(inner) => inner,
                Err(_elapsed) => {
                    // Timeout elapsed while the global `bootstrap_spawn_lock` was held.
                    // The timed future is CANCELLED at the elapse, dropping any in-flight
                    // seeded `state` (and with it the owned crypto). This outer arm cannot
                    // reach into the cancelled future to `dispose_secrets`, so the born
                    // crypto is bare-dropped here: the `SenderKey` and the OpenMLS Ed25519
                    // signer zeroize on drop (`SignatureKeyPair` holds its private key in
                    // `SecretVLBytes`), and the group's provider-storage values zeroize
                    // on drop. There
                    // is no provider-resident crypto to tear down (#2148 birth-into-actor).
                    // `first_state` below puts back any record step 4 wrote: a no-op when
                    // the elapse landed before step 4 ran, so it is safe regardless of how
                    // far the timed region progressed.
                    // Mirrors the `TransportTimeout` the import / restore / respawn
                    // bootstraps return on their own `LIFECYCLE_TIMEOUT` elapse. The actor
                    // is registered only by step 5's `spawn_actor_with_state`, which
                    // resolves the timed future to `Ok(..)` (never `Elapsed`) once it
                    // returns, so this arm is reached only with NO registered actor for
                    // `context_id`.
                    Err(ContextError::TransportTimeout(format!(
                        "spawn-from-Welcome exceeded {:?} budget for context {context_id}",
                        Self::LIFECYCLE_TIMEOUT
                    )))
                }
            };
        // The post-spawn wiring waits on the new actor's mailbox, and the
        // rollback waits for abandoned writes, so both run with the lock
        // released; the rollback retakes it for the restores.
        drop(bootstrap_guard);
        // A failed or timed-out join puts back what step 4 wrote; a no-op after
        // the spawn committed or when step 4 never ran.
        let spawn_outcome = match spawn_outcome {
            Err(e) => match first_state.rollback(self.bootstrap_spawn_lock.lock()).await {
                Ok(()) => Err(e),
                Err(rollback) => Err(crate::context::shared::lifecycle::fold_rollback_failure(
                    &e, &rollback,
                )),
            },
            ok => ok,
        };
        // Propagate a step-internal error or the timeout error; on success bind the
        // joiner handle and run the (bounded, local) post-spawn finalization OUTSIDE
        // the timeout — the actor is now registered, so the elapse rollback above
        // (which tears the group + snapshot down) must never be able to fire against
        // a LIVE actor.
        let handle = spawn_outcome?;

        // Finalization: the gauge refresh and the TTL timer, the same
        // post-spawn wiring a create runs, after the lock is released because
        // the TTL install waits on the new actor's mailbox. The joiner arms
        // with no explicit deadline: the actor derives the convergent expiry
        // deadline on the same creator-assigned `creation_timestamp_secs +
        // params.ttl` basis the creator used.
        crate::context::shared::lifecycle::SpawnedContext::at_create_base(handle)
            .finalize(&deps)
            .await
    }

    /// Build the Welcome-derived [`PerContextState`](crate::context::actor::state::PerContextState)
    /// for a joiner (ADR-049 Phase 2J). Mirrors the fresh-context field set that
    /// `scp_runtime_lifecycle::helpers::create_context` builds, but with the
    /// caller as a `"member"` and `creator_did` as the context creator/admin.
    ///
    /// The MLS crypto (group + sender key) is NOT stored here — it lives in the
    /// crypto provider (installed by the caller); the actor-state
    /// `ContextCryptoState` stays in its default (empty) shape, exactly as the
    /// create path leaves it. The per-member access-key store starts empty: a
    /// joiner's access key is minted by the inviter with a random key (§9.17.2)
    /// and delivered out-of-band, not regenerable locally.
    ///
    /// `committed_t0` is the `creation_timestamp_secs` the joined group's
    /// `0xFF02` extension commits, as `verify_scp_context_binding` returned it:
    /// the joiner's `T0` and TTL base (spec 05 §5.13.3 rule 9).
    // Called only from `spawn_actor_from_welcome`, which the FFI slice (pull
    // request #2036) wired to production bridge consumers.
    #[allow(clippy::too_many_lines)]
    fn build_welcome_joiner_state(
        deps: &crate::context::actor::deps::ActorDeps,
        bundle: WelcomeBundleFacts<'_>,
        committed_t0: u64,
        joiner_did: &DID,
        local_pseudonym: [u8; 32],
        joined_epoch: u64,
    ) -> Result<crate::context::actor::state::PerContextState, ContextError> {
        use scp_protocol::context::roles::{CapabilityCeiling, ContextRoleState};
        use std::collections::{HashMap, HashSet, VecDeque};

        let WelcomeBundleFacts {
            context_id,
            params,
            creator_did,
            relay_urls,
        } = bundle;

        // NOTE: the reversible legible-param validations
        // (`check_version_compatibility` / `validate_governance_model`) are run by
        // the `spawn_actor_from_welcome` entrypoint BEFORE the irreversible
        // KeyPackage consume (BLACK-2J-02) — not here, after the group is already
        // joined and installed.

        // §5.13.3 rule 9: the TTL base is the committed `T0`, never this
        // joiner's clock, so the joiner's convergent deadline
        // (`creation_timestamp_secs + params.ttl`) equals the creator's.
        let creation_timestamp_secs = committed_t0;

        let governance_engine = crate::context::state::create_governance_engine(
            &params.governance,
            creator_did,
            Arc::clone(&deps.key_resolver),
        )
        .map_err(|e| ContextError::CreationFailed(e.to_string()))?;

        // Role state: creator is the admin/creator; the joiner is added as a
        // "member". `system_assign_role` requires the member to be present in
        // the role state's member set first.
        let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
        let mut role_state = ContextRoleState::new(
            context_id,
            creator_did.as_ref(),
            ceiling,
            vec![],
            &*deps.clock,
        )
        .map_err(|e| ContextError::CreationFailed(e.to_string()))?;
        role_state.members.insert(joiner_did.as_ref().to_owned());
        let joiner_tokens = role_state
            .system_assign_role(joiner_did.as_ref(), "member", &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

        // Membership tracking: the admin (creator) and this member (joiner).
        let mut membership = scp_protocol::context::membership::MembershipState::new();
        let creator_tokens = role_state
            .assignments
            .get(creator_did.as_ref())
            .map(|a| a.tokens.clone())
            .unwrap_or_default();
        membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);
        membership.add_member(joiner_did.clone(), "member".into(), joiner_tokens);

        let initial_members: HashSet<DID> = membership.members().map(|m| m.did.clone()).collect();

        // Encrypted mode: the live MLS group lives in the crypto provider
        // (installed by the caller); the actor-state crypto stays default.
        let mode = crate::context::actor::state::ContextModeState::Encrypted(Box::<
            crate::context::actor::state::ContextCryptoState,
        >::default());
        // §9.10.4: a REAL local pseudonym (the entrypoint rejects `None` before
        // the consume — see Precheck B), never the `[0u8; 32]` sentinel.
        let routing =
            crate::context::actor::state::ContextRouting::for_mode(false, local_pseudonym);

        let per_context = crate::context::actor::state::PerContextState {
            context_id: crate::context::state::context_id_to_bytes(context_id),
            created_at: deps.clock.now_secs(),
            creation_timestamp_secs,
            generation: 0,
            handle: crate::context::ContextHandle::new(context_id.to_owned(), params.clone()),
            membership,
            members: initial_members.clone(),
            // Shared fresh-context governance bucket — identical to the create
            // path (see `state::fresh_governance_state`), so the two cannot drift.
            governance: crate::context::state::fresh_governance_state(
                governance_engine,
                params,
                initial_members,
                context_id,
                Arc::clone(&deps.clock),
                // A joiner arrives at an arbitrary later epoch, and `params` is the
                // frozen genesis declaration, which records no outlet that
                // governance removed after genesis. The joiner's registry
                // therefore starts empty and STAYS empty: the creator's
                // `OutletRegistered`/`OutletRemoved` leaves carry the
                // registrations and the removals, but no runtime path replays
                // another member's log into `registered_outlets`, so outlet
                // invocation on this joiner fails closed. See
                // `OutletRegistrySeed::AwaitingLeafReplication` (GitHub #2250).
                crate::context::state::OutletRegistrySeed::AwaitingLeafReplication,
            ),
            role_state,
            receive_buffer: scp_protocol::context::membership::ReceiveBuffer::new(),
            payment_receipts: VecDeque::new(),
            broadcast_context: None,
            migration_state: None,
            epoch: crate::context::state::EpochState {
                // The ABSOLUTE joined-group MLS epoch (read from the group before
                // it moved into `install_joined_group`) — a Welcome-joined group
                // is already at epoch ≥ 1, not 0 (bug-catcher F1).
                mls_epoch: joined_epoch,
                coordinator:
                    scp_protocol::context::governance::mls_integration::EpochCoordinator::new(),
                grace_store: scp_mls::epoch_grace::EpochGraceStore::with_clock(
                    std::sync::Arc::new(scp_clock::SystemClock),
                ),
                needs_reconnect: false,
            },
            access: crate::context::state::AccessControlState {
                read_exclusion_list: HashSet::new(),
                // A joiner's own access key is random (§9.17.2) and delivered
                // out-of-band, not regenerable locally — start empty.
                access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
            },
            ttl: crate::context::state::TtlState {
                timer: crate::context::ttl::TtlTimer::with_clock(Arc::clone(&deps.clock)),
                extension: None,
            },
            sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
            reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
            pending_commits: VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: deps.clock.now_secs(),
            checkpoints: Vec::new(),
            last_seen_remote_checkpoint: std::collections::HashMap::new(),
            routing,
            // §5.12.3.1: the bundle's relays host the context (PUSH-025).
            relay_urls: crate::context::shared::lifecycle::normalize_relay_urls(
                relay_urls.to_vec(),
            ),
            send_tracker: scp_runtime_types::context::actor::sequence::SendSequenceTracker::new(),
            recv_tracker: crate::context::actor::state::RecvSequenceTracker::new(),
            xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
            class_s: crate::context::actor::state::ClassSState {
                saga_pending: HashMap::new(),
                xctx_committed_outputs: HashMap::new(),
                xctx_committed_stream_outputs: HashMap::new(),
                xctx_committed_invocations: std::collections::HashSet::new(),
                xctx_caller_reservations: std::collections::HashMap::new(),
                xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::with_ttl(
                    crate::context::actor::state::SAGA_NONCE_DEDUP_TTL_SECS,
                ),
                // §7.3.8 value-caveat counters: a fresh joiner carries none.
                caveat_counters: HashMap::new(),
                // Fix-D streaming reservation recovery: a fresh joiner carries none.
                stream_reservations: HashMap::new(),
                // §9.10.4.1 "First v2 derivation": under a policy a joiner's
                // first rotation, to v2 at the schedule index counted from the
                // committed T0 (§5.13.3 rule 9), is due at once, so the joiner
                // follows the members' shared interval boundaries.
                pseudonym_rotation:
                    crate::context::actor::pseudonym_rotation::PseudonymRotationState::joined(
                        params.pseudonym_rotation.as_ref(),
                        Some(committed_t0),
                        deps.clock.now_secs(),
                    ),
            },
            // Transient join-handshake state; the fused join already consumed
            // it, so a fresh joiner state carries none.
            welcome_scratchpad: None,
            lifecycle_state: crate::context::actor::state::ContextLifecycleState::Open,
            event_log: None,
            mode,
        };

        Ok(per_context)
    }

    /// Creates a context from a flat [`ContextConfig`](scp_runtime_types::context::config::ContextConfig)
    /// (ADR-052 / construction.md).
    ///
    /// This is the options-object front-end over [`Self::create_context`]: it
    /// lowers `config` into
    /// [`ContextParams`](scp_protocol::context::ContextParams) via
    /// [`ContextConfig::into_params`](scp_runtime_types::context::config::ContextConfig::into_params)
    /// and calls the existing creation engine. The Rust SDK thereby gains the
    /// same options-object shape Python/TypeScript/Swift already use.
    ///
    /// # Bilateral peer
    ///
    /// [`ContextCreation::Template`](scp_runtime_types::context::config::ContextCreation::Template)
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
    /// from [`Self::create_context`], including the
    /// [`ContextError::CeilingRequired`]
    /// rejection of an empty ceiling.
    pub async fn create(
        self: &Arc<Self>,
        context_id: String,
        config: scp_runtime_types::context::config::ContextConfig,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
        relay_urls: Vec<String>,
    ) -> Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>
    {
        // Fail loud, never silent (AGENTS.md "no silent" tenet): a supplied
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
        self.create_context(context_id, params, creator_did, local_pseudonym, relay_urls)
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
        bounded_reply_await(rx).await.map_err(|_| {
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::leave_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Encrypts and broadcasts a payload through the context's MLS
    /// group via the actor mailbox.
    ///
    /// `signer` ([`MessageSigner`]) pairs the custody-backed signer with the
    /// verification method it is signed under (ADR-039):
    /// [`MessageSigner::Active`] for human-originated sends,
    /// [`MessageSigner::Agent`] for agent-autonomous sends. The persona is
    /// stamped into the inner envelope's `signing_key_id` from the same enum
    /// variant that carries the signer, so the recipient resolves the matching
    /// public key (`#active` / `#agent`) from the sender's DID document and the
    /// stamp can never disagree with the key that signed. Every send path
    /// requires a signer, so it is non-optional.
    ///
    /// Every per-context method on `Supervisor` builds a typed
    /// `ContextCommand` carrying an embedded reply oneshot, enqueues it
    /// via [`Self::dispatch_command`], and awaits the actor's typed
    /// reply. Dispatch is mailbox-only: the command routes through the
    /// per-context actor mailbox, and when no actor is registered for the
    /// target context the call returns a lookup-miss
    /// [`ContextError`] on the reply
    /// oneshot rather than mutating supervisor state directly.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if the supervisor's provider
    ///   slots are empty (the supervisor was constructed via
    ///   `Self::for_query_shim`).
    /// - Other [`ContextError`] variants propagated from the handler.
    /// - [`ContextError::TransportFailed`] if the mailbox reply channel
    ///   is dropped before the handler completes (handler crash /
    ///   actor shutdown).
    pub async fn send_message(
        &self,
        handle: &crate::context::ContextHandle,
        sender_did: &DID,
        payload: &[u8],
        signer: MessageSigner<'_>,
        source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Single construction point: both `signer` and `signing_key_id`
        // are derived from the one `MessageSigner` so the persona stamped on the
        // wire cannot diverge from the key that signs (ADR-039). The owned
        // payload keeps two fields to cross the actor mailbox, but they are set
        // together here — there is no cross-crate seam to set them
        // inconsistently.
        let payload_box = Box::new(crate::context::actor::commands::SendMessagePayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            sender_did: sender_did.clone(),
            payload: payload.to_vec(),
            signer: signer.signer().clone(),
            signing_key_id: signer.signing_key_id(),
            source_provenance: source_provenance.cloned(),
            spending_ucan: spending_ucan.cloned(),
        });
        let cmd = MessagingCommand::SendMessage {
            payload: payload_box,
            reply: tx,
        };
        self.dispatch_command(handle.context_id(), cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::seed_peer_pseudonym — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Registers an additional DID as a broadcast author on an existing
    /// broadcast context, bypassing the governance round-trip — test-only.
    ///
    /// Single-node integration tests that need a multi-author broadcast
    /// context cannot drive genuine governance (the bridge key-resolver only
    /// sees one actor's custody). This seam populates the author registry
    /// mirroring the author-publish/add path, so multi-author KEA-leaf and
    /// checkpoint-counter tests can exercise the real code path instead of
    /// being limited to the creator-only case.
    ///
    /// Mirrors [`Self::seed_peer_pseudonym`] in purpose and gating. Gated
    /// behind `testing` — never compiled into production builds, never
    /// reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::MembershipFailed`] if the context is not a
    ///   broadcast context.
    /// - [`ContextError::PermissionDenied`] if `author_did` is already
    ///   registered.
    /// - [`ContextError::ContextNotRegistered`] if the context has no actor.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn seed_broadcast_author(
        &self,
        context_id: &str,
        author_did: DID,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::SeedBroadcastAuthor {
            context_id: context_id.to_owned(),
            author_did,
            reply: tx,
        };
        self.dispatch_broadcast_command(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::seed_broadcast_author — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Reads a context's `checkpoint_events_since` counter through the actor
    /// mailbox — test-only.
    ///
    /// §9.9.3 of the security-model spec compares members' Merkle roots at an
    /// equal event count, so every durable leaf a helper appends must credit
    /// the counter exactly once. A test that counts leaves in the event log
    /// cannot see a missed or doubled credit; a test that reads this counter
    /// and compares its delta against the event-log delta can. Gated behind
    /// `testing` — never compiled into production builds, never reachable from
    /// any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context has no actor.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn checkpoint_events_since(&self, context_id: &str) -> Result<u64, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::CheckpointEventsSince {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_query(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::checkpoint_events_since — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Installs a member's §9.17 access key directly into a context's access
    /// key store via the actor mailbox — test-only.
    ///
    /// The full-stack test harness uses this to land an access key it obtained
    /// through the REAL §9.17 pull (`request_access_key` →
    /// `handle_access_key_request` → `open_access_key_response` over the harness's
    /// simulated transport) into a Welcome-joiner's actor store, so the joiner
    /// can wrap content CEKs for its peers on send. The production actor-loop
    /// distribution this simulates is deferred and tracked (#2050). Gated behind
    /// the `testing` feature — never compiled into production, never reachable
    /// from any FFI bridge.
    ///
    /// # Expiry
    ///
    /// This seam EXPIRES with #2050. When production §9.17 distribution lands,
    /// DELETE this method, the [`MessagingCommand::TestInstallAccessKey`]
    /// variant + its handler, and the harness
    /// `FullStackNode::pull_access_keys_from_creator` driver that calls it — then
    /// confirm the Python/TS bidirectional tripwires still pass on the *production*
    /// distribution path (not the harness stand-in). It is safe to carry until
    /// then because it is `testing`-gated (never in a production build), has no
    /// FFI wrapper, and is reachable only by in-process `Arc<Supervisor>` callers
    /// (the full-stack harness), so no untrusted or cross-process caller can drive
    /// it even in the `testing` build the tripwires use.
    ///
    /// # Errors
    ///
    /// - [`ContextError`] if the context is inactive or the actor reply channel
    ///   closes.
    #[cfg(feature = "testing")]
    pub async fn test_install_access_key(
        &self,
        context_id: &str,
        member_did: &str,
        key: scp_protocol::crypto::access_keys::AccessKey,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::TestInstallAccessKey {
            context_id: context_id.to_owned(),
            member_did: member_did.to_owned(),
            key,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::test_install_access_key — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Arms the one-shot rotation fault seam of `context_id`: the next local
    /// sender-key rotation there fails before it mutates anything.
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] if the context has no encrypted crypto.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn test_arm_rotation_failure(&self, context_id: &str) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::TestArmRotationFailure {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::test_arm_rotation_failure — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Inserts a member directly into a context's role state via the actor
    /// mailbox — test-only.
    ///
    /// Records `member_did` in `role_state.members` and assigns `role`,
    /// bypassing the MLS Welcome / governance round-trip. Single-node tests
    /// that need a multi-member context (e.g. exporter selection over a 2+
    /// member membership map) cannot drive a genuine join: the bridge
    /// governance key resolver only resolves DID-document-published
    /// identities, and in-memory test identities are never published.
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::MembershipFailed`] if the role is undefined / the
    ///   context is inactive.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn test_insert_member(
        &self,
        context_id: &str,
        member_did: DID,
        role: &str,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::TestInsertMember {
            context_id: context_id.to_owned(),
            member_did,
            role: role.to_owned(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::test_insert_member — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Answers a §9.16.2 sender-key PULL request on the OWNED actor crypto state
    /// via the actor mailbox — test-only (ADR-049 PR-7 / SCP-CRYPTOMOVE-001).
    ///
    /// The steady-state ANSWER half moved off the provider onto
    /// `ContextCryptoState::handle_sender_key_request`;
    /// a taken (actor-owned) context can no longer answer through the emptied
    /// provider. This routes the answer to the actor by `context_id` and returns
    /// the ephemeral-sealed response (`Some`) or `None` for a blocked requester.
    /// The full-stack harness drives the requester side externally with its own
    /// custody (actor-loop request INITIATION is deferred #2049).
    ///
    /// Gated behind the `testing` feature — never compiled into production,
    /// never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] on signature / freshness / replay /
    ///   membership rejection of the request.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn handle_sender_key_request(
        &self,
        context_id: &str,
        request_bytes: &[u8],
        requester_public_key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::HandleSenderKeyRequest {
            context_id: context_id.to_owned(),
            request_bytes: request_bytes.to_vec(),
            requester_public_key: *requester_public_key,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::handle_sender_key_request — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Lands a §9.16.2 pull-response sender key onto the OWNED actor sender-key
    /// store via the actor mailbox — test-only (ADR-049 PR-7 /
    /// SCP-CRYPTOMOVE-001).
    ///
    /// GATE-BEFORE-INSTALL: the actor handler gates the authenticated
    /// `(sender_did, epoch)` against the Class-M floor registry
    /// (`check_and_advance_sender_epoch`, FAIL-CLOSED) and then installs the key
    /// onto `cs.sender_key_store`. The provider store is empty on a taken context,
    /// so the install MUST land on the actor; the requester (harness) already
    /// HPKE-opened the ephemeral-sealed response with its own wrapping secret.
    ///
    /// Gated behind the `testing` feature — never compiled into production,
    /// never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] if the epoch fails the Class-M floor gate
    ///   or no crypto state is resident.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn land_sender_key_response(
        &self,
        context_id: &str,
        sender_did: &str,
        sender_key: scp_protocol::crypto::sender_keys::SenderKey,
        epoch: u64,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::LandSenderKeyResponse {
            context_id: context_id.to_owned(),
            sender_did: sender_did.to_owned(),
            sender_key,
            epoch,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::land_sender_key_response — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// READ-ONLY inner-envelope inspection on the OWNED actor crypto state via
    /// the actor mailbox — test-only (ADR-049 PR-7 / SCP-CRYPTOMOVE-001).
    ///
    /// Decrypts a captured outer-envelope blob through the context actor and
    /// returns the raw decrypted
    /// [`InnerEnvelope`](scp_protocol::envelope::inner::InnerEnvelope) WITHOUT
    /// unwrapping the §9.17 access-key content layer, so a test can read the
    /// wire-level `message_type` / `sequence` (e.g. assert a sent heartbeat is
    /// tagged `MessageType::Heartbeat` and carries sequence `0`, and that a
    /// heartbeat does NOT advance the per-sender application sequence — §9.9.2).
    /// This is the actor twin of the deleted provider `open` inspection twin;
    /// the taken (actor-owned) context can no longer be opened through the
    /// emptied provider.
    ///
    /// # Non-mutating receive-state invariant (§9)
    ///
    /// The actor handler drives ONLY
    /// `ContextCryptoState::open`
    /// — a PURE decrypt that surfaces `env.receive_floor` but runs NONE of the
    /// receive-side anti-replay enforcement (`check_and_advance_recv_sequence`,
    /// the Class-M floor registry, `nonce_dedup`, epoch advance) that lives at
    /// the messaging seam. The only state change is the MLS decryption-ratchet
    /// advance intrinsic to any decrypt. Inspecting a blob therefore never
    /// consumes an anti-replay slot, so the same wire bytes remain re-openable by
    /// the real receive path.
    ///
    /// Gated behind the `testing` feature — never compiled into production,
    /// never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::CryptoFailed`] if the blob decodes to a Control /
    ///   Management result rather than an application envelope, or on any MLS /
    ///   sender-key / decode failure.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "testing")]
    pub async fn inspect_incoming_inner(
        &self,
        context_id: &str,
        envelope_bytes: Vec<u8>,
    ) -> Result<scp_protocol::envelope::inner::InnerEnvelope, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::InspectIncomingInner {
            context_id: context_id.to_owned(),
            envelope_bytes,
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::inspect_incoming_inner — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Grants a §7.2.2 Tier-2 capability (e.g. `"outlet_call:*"`) directly into
    /// a member's `role_state.member_capabilities` cache, bypassing the
    /// governance role-assignment round-trip — test-only.
    ///
    /// The runtime outlet-invocation gate requires the invoker to hold
    /// `OutletCall(outlet_id)` / `OutletCallAll` (or the Query stem) in role
    /// state as defense-in-depth alongside the UCAN gate, and the default
    /// `admin` / `member` roles grant only `messages:*`. Single-node outlet
    /// tests use this to authorize a member the same way the runtime fixture
    /// `authorizing_role_state` does. This is an AUTHORITY-ESCALATION primitive,
    /// so it is gated behind the dedicated `outlet-capability-test-grant`
    /// feature — deliberately NOT `testing`, which leaks into every
    /// bridge test build and would compile the primitive
    /// into a test-harness binary. The dedicated feature is enabled ONLY
    /// by the outlet-stream live-flow test, and the seam has ZERO FFI/SDK
    /// exports (only that test calls it).
    ///
    /// # Errors
    ///
    /// - [`ContextError::MembershipFailed`] if the context is inactive or the
    ///   capability stem is unrecognized.
    /// - [`ContextError::TransportFailed`] if the actor reply channel closes.
    #[cfg(feature = "outlet-capability-test-grant")]
    pub async fn test_grant_member_capability(
        &self,
        context_id: &str,
        member_did: DID,
        capability: &str,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::TestGrantMemberCapability {
            context_id: context_id.to_owned(),
            member_did,
            capability: capability.to_owned(),
            reply: tx,
        };
        self.dispatch_command(context_id, cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::test_grant_member_capability — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Appends a typed event directly to the supervisor-owned event-log
    /// provider for `context_id` — test-only.
    ///
    /// The provider's `event_log_entries` (read by the FFI `event_log_query`
    /// manager path) is the same store this writes to, so a leaf appended here
    /// is observable on the manager path without driving a full governance
    /// round-trip. Used by the NAPI bridge's manager-path projection tests to
    /// seed a `RoleAssigned`/`GovernanceActionExecuted` leaf carrying a typed
    /// payload. Synchronous — the provider's `append_event` mutates its own
    /// shared store and needs no actor mailbox.
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no event-log provider is wired.
    /// - [`ContextError::EventLogFailed`] if the provider has no log for the
    ///   context or the append fails.
    #[cfg(any(test, feature = "testing"))]
    pub async fn test_append_event_log(
        &self,
        context_id_bytes: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), ContextError> {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::test_append_event_log — event_log provider not configured".to_owned(),
            )
        })?;
        event_log
            .append_event(
                context_id_bytes,
                event_type,
                actor_did,
                payload,
                timestamp_secs,
            )
            .await
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))
    }

    /// Releases `context_id`'s in-memory event log while its actor keeps
    /// running — test-only.
    ///
    /// Shutdown releases the log the same way but also stops the actor, and
    /// the FFI reads refuse a context that is not `Active` before they reach
    /// the log. This leaves the context `Active`, so a bridge read reaches
    /// the provider's "not loaded" answer (spec section 17.3, "Event log
    /// write failures").
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInitialized`] if no event-log provider is wired.
    #[cfg(any(test, feature = "testing"))]
    pub fn test_release_event_log(&self, context_id_bytes: &[u8; 32]) -> Result<(), ContextError> {
        self.event_log_ref()
            .ok_or_else(|| {
                ContextError::NotInitialized(
                    "Supervisor::test_release_event_log — event_log provider not configured"
                        .to_owned(),
                )
            })?
            .release_event_log(context_id_bytes);
        Ok(())
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
        bounded_reply_await(rx).await.map_err(|_| {
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
        bounded_reply_await(rx).await.map_err(|_| {
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
        signer: &crate::context::actor::signer::CommandSigner,
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
                signer: signer.clone(),
                // The unchecked propose path never carries an invitee KeyPackage
                // (the invitation path uses the checked variant).
                key_package: None,
            },
        );
        let cmd = GovernanceCommand::ProposeGovernanceAction { payload, reply: tx };
        self.dispatch_governance_command(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
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
        signer: &crate::context::actor::signer::CommandSigner,
    ) -> Result<crate::context::state::ProposalOutcome, ContextError> {
        self.propose_governance_action_checked_carrying_key_package(
            context_id,
            proposer_did,
            action,
            signer,
            None,
        )
        .await
    }

    /// [`Self::propose_governance_action_checked`] carrying an optional invitee
    /// `KeyPackage` on the in-process actor command envelope.
    ///
    /// The `KeyPackage` rides the actor command (NOT the signed/logged
    /// [`GovernanceAction`](scp_protocol::context::governance::GovernanceAction)
    /// wire type) and is threaded to `execute_add_member` for an `AddMember`
    /// auto-execute, so the governance add performs a REAL MLS add (§5.12.3).
    /// Only [`Self::invite_member`] supplies `Some(..)`; the public
    /// [`Self::propose_governance_action_checked`] (the generic FFI governance
    /// path) delegates here with `None`.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    async fn propose_governance_action_checked_carrying_key_package(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: scp_protocol::context::governance::GovernanceAction,
        signer: &crate::context::actor::signer::CommandSigner,
        key_package: Option<Vec<u8>>,
    ) -> Result<crate::context::state::ProposalOutcome, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(
            crate::context::actor::commands::ProposeGovernanceActionPayload {
                context_id: context_id.to_owned(),
                proposer_did: proposer_did.clone(),
                action,
                signer: signer.clone(),
                key_package,
            },
        );
        let cmd = GovernanceCommand::ProposeGovernanceActionChecked { payload, reply: tx };
        self.dispatch_governance_command(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
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
        signer: &crate::context::actor::signer::CommandSigner,
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
            signer: signer.clone(),
        });
        let cmd = GovernanceCommand::VoteOnProposal {
            payload,
            approve,
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
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
        bounded_reply_await(rx).await.map_err(|_| {
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
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::local_pseudonym — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Dispatch a read-only [`PushCommand`] to `ctx_id`'s actor mailbox, where
    /// `handlers::push::dispatch` answers it from `push_helpers`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`], [`ContextError::ContextPoisoned`]
    ///   or [`ContextError::ActorCrashed`] when no actor serves `ctx_id`.
    /// - [`ContextError::ActorBusy`] from the mailbox send.
    pub async fn dispatch_push_command(
        &self,
        ctx_id: &str,
        cmd: PushCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            self.lookup_miss_error(
                ctx_id,
                format!("dispatch_push_command — no actor registered for context_id `{ctx_id}`"),
            )
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::Push(cmd)).await
    }

    /// Returns the routing IDs this device registers for push wakes, grouped by
    /// canonical relay URL (`10-infrastructure-and-self-hosting.md` §10.7.1,
    /// `09-security-model.md` §9.18.2).
    ///
    /// Asks every context in [`Self::known_context_ids`] for its push routes
    /// through [`Self::dispatch_push_command`], concurrently. Each context adds
    /// its shared routing ID and, in an encrypted context, this device's
    /// current pseudonym routing ID (§9.10.4) under the canonical form of every
    /// relay in its relay set, so two spellings of one relay share one key.
    /// The result holds no context ID. A context that is `Closed`, `Expired`
    /// or `Tombstoned`, or whose actor was removed with no crash record after
    /// the IDs were read, adds nothing.
    ///
    /// # Errors
    ///
    /// Fails rather than return a partial set, because a registration built
    /// from a partial set would silently drop the wakes for the missing
    /// contexts:
    /// - [`ContextError::ContextPoisoned`] or [`ContextError::ActorCrashed`]
    ///   when a context's actor is down;
    /// - [`ContextError::ActorBusy`] from a mailbox send;
    /// - [`ContextError::TransportFailed`] when an actor drops its reply or
    ///   does not answer within the reply bound.
    ///
    /// A relay URL with no §9.18.2 canonical form gets no entry, because
    /// §9.18.2 derives no reserved push routing ID for it. The query still
    /// returns the routing IDs of every other relay and context.
    pub async fn push_routing_ids(
        &self,
    ) -> Result<
        std::collections::BTreeMap<String, std::collections::BTreeSet<[u8; 32]>>,
        ContextError,
    > {
        let replies = futures::future::join_all(self.known_context_ids().into_iter().map(
            |ctx_id| async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                match self
                    .dispatch_push_command(&ctx_id, PushCommand::Routes { reply: tx })
                    .await
                {
                    Ok(_) => {}
                    Err(ContextError::ContextNotRegistered(_)) => return Ok(None),
                    Err(err) => return Err(err),
                }
                bounded_reply_await(rx).await.map_err(|_| {
                    ContextError::TransportFailed(format!(
                        "Supervisor::push_routing_ids — no reply from the actor of `{ctx_id}`"
                    ))
                })
            },
        ))
        .await;
        let mut by_relay =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<[u8; 32]>>::new();
        for routes in replies {
            let Some(routes) = routes? else { continue };
            for relay_url in routes.relay_urls {
                // §9.18.2: a URL that a step rejects has no canonical URL, so
                // the client derives no reserved push routing ID for it.
                let Ok(canonical) = scp_did::canonical_node_url(&relay_url) else {
                    continue;
                };
                by_relay
                    .entry(canonical)
                    .or_default()
                    .extend(routes.routing_ids.iter().copied());
            }
        }
        Ok(by_relay)
    }

    /// Returns the push-wake pull target of every `Active` context (ADR-029
    /// §2, push-wake pull mode): its ID, persisted relay set, and the routing
    /// IDs the pull queries, the shared and the current pseudonym routing ID.
    /// A routing ID on the query-only list is left to reconnect catch-up.
    ///
    /// Asks every context in [`Self::known_context_ids`] concurrently through
    /// [`Self::dispatch_push_command`]. A context that is not `Active`, or
    /// whose actor was removed with no crash record after the IDs were read,
    /// yields no target.
    ///
    /// # Errors
    ///
    /// Fails rather than return a partial set, because a wake that skips a
    /// context reports `NoData` for traffic it never pulled:
    /// - [`ContextError::ContextPoisoned`] or [`ContextError::ActorCrashed`]
    ///   when a context's actor is down;
    /// - [`ContextError::ActorBusy`] from a mailbox send;
    /// - [`ContextError::TransportFailed`] when an actor drops its reply or
    ///   does not answer within the reply bound.
    pub async fn wake_targets(
        &self,
    ) -> Result<Vec<crate::context::push_routes::ContextWakeTarget>, ContextError> {
        let replies = futures::future::join_all(self.known_context_ids().into_iter().map(
            |ctx_id| async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                match self
                    .dispatch_push_command(&ctx_id, PushCommand::WakeTarget { reply: tx })
                    .await
                {
                    Ok(_) => {}
                    Err(ContextError::ContextNotRegistered(_)) => return Ok(None),
                    Err(err) => return Err(err),
                }
                bounded_reply_await(rx).await.map_err(|_| {
                    ContextError::TransportFailed(format!(
                        "Supervisor::wake_targets — no reply from the actor of `{ctx_id}`"
                    ))
                })
            },
        ))
        .await;
        let mut targets = Vec::new();
        for reply in replies {
            if let Some(target) = reply? {
                targets.push(target);
            }
        }
        Ok(targets)
    }

    /// Whether any context is resident or down with a crash record
    /// ([`Self::known_context_ids`]). A push wake that finds none restores the
    /// persisted contexts first (ADR-029 §2 push-wake pull mode, step 2).
    #[must_use]
    pub fn has_known_contexts(&self) -> bool {
        !self.known_context_ids().is_empty()
    }

    /// The persisted contexts whose snapshot is `Active` and that are neither
    /// resident nor down with a crash record ([`Self::known_context_ids`]):
    /// the contexts whose restore failed. A push wake fails when this is not
    /// empty, because its pull cannot reach them (ADR-029 §2 push-wake pull
    /// mode, step 2).
    ///
    /// # Errors
    ///
    /// [`ContextError::PersistenceFailed`] when no persistence provider is
    /// configured, or when listing the persisted contexts or loading one of
    /// their snapshots fails.
    pub async fn unrestored_active_contexts(&self) -> Result<Vec<String>, ContextError> {
        let persistence = self.persistence_ref().ok_or_else(|| {
            ContextError::PersistenceFailed("no persistence provider configured".to_owned())
        })?;
        let known: std::collections::BTreeSet<String> =
            self.known_context_ids().into_iter().collect();
        let persisted = persistence.list_persisted_contexts().await.map_err(|e| {
            ContextError::PersistenceFailed(format!("failed to list persisted contexts: {e}"))
        })?;
        let mut unrestored = Vec::new();
        for context_id in persisted {
            if known.contains(&context_id) {
                continue;
            }
            let snapshot = persistence.load_context(&context_id).await.map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "failed to load the snapshot of `{context_id}`: {e}"
                ))
            })?;
            if snapshot.is_some_and(|s| s.state == scp_protocol::context::ContextState::Active) {
                unrestored.push(context_id);
            }
        }
        Ok(unrestored)
    }

    /// Restores every context [`Self::unrestored_active_contexts`] lists, one
    /// [`Self::restore_context`] each, and returns the contexts that are still
    /// unrestored afterwards (ADR-029 §2 push-wake pull mode step 2).
    ///
    /// The restore runs no saga-journal replay. This entry is for a live
    /// process whose startup pass ([`Self::restore_on_startup`]) already ran:
    /// a replay here would reconcile sagas that are in flight as if a crash
    /// had orphaned them. A reversal that a failed restore left undeliverable
    /// stays non-terminal until the next process start, as
    /// [`Self::restore_on_startup`] documents.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::unrestored_active_contexts`]. A failure to
    /// restore one context is not an error; that context is returned.
    pub async fn restore_unrestored_contexts(
        self: &Arc<Self>,
    ) -> Result<Vec<String>, ContextError> {
        let persistence = self.persistence_ref().ok_or_else(|| {
            ContextError::PersistenceFailed("no persistence provider configured".to_owned())
        })?;
        for context_id in self.unrestored_active_contexts().await? {
            let snapshot = match persistence.load_context(&context_id).await {
                Ok(Some(snapshot)) => snapshot,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(context_id = %context_id, error = %e, "loading an unrestored context failed");
                    continue;
                }
            };
            let handle =
                crate::context::ContextHandle::new(context_id.clone(), snapshot.context_params);
            if let Err(e) = self.restore_context(&context_id, &handle).await {
                tracing::warn!(context_id = %context_id, error = %e, "restoring an unrestored context failed");
            }
        }
        self.unrestored_active_contexts().await
    }

    /// Returns the local member's routing IDs and rotation state (spec 09
    /// §9.10.4.1) for `context_id`: the current routing ID, the live
    /// query-only routing IDs, the epoch, the epoch the next rotation must
    /// carry, and whether an announcement is pending. Routes through the
    /// actor mailbox via [`Self::dispatch_query`].
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotPseudonymousContext`] for a broadcast context.
    /// - [`ContextError::ContextNotRegistered`] (or the poison error) for an
    ///   unknown context.
    /// - [`ContextError::TransportFailed`] if the reply channel is dropped.
    pub async fn local_routing_ids(
        &self,
        context_id: &str,
    ) -> Result<crate::context::actor::pseudonym_rotation::LocalRoutingIds, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::LocalRoutingIds {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_query(cmd).await?;
        bounded_reply_await(rx).await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::local_routing_ids — actor reply channel closed".to_owned(),
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
        match bounded_reply_await(rx).await {
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
        match bounded_reply_await(rx).await {
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
        let _ = bounded_reply_await(rx).await;
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
    /// Returns `None` for [`LifecycleCommand::ImportContext`] (the export envelope
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
            // rewritten to surface that derivation. Sweep commands
            // (`FlushSnapshot`, `ShutdownSelf`) are dispatched per-actor
            // by the supervisor's iterating entry points in
            // `lifecycle_helpers`; routing target is decided at the
            // iteration site.
            LifecycleCommand::ImportContext { .. }
            | LifecycleCommand::FlushSnapshot { .. }
            | LifecycleCommand::ShutdownSelf { .. }
            | LifecycleCommand::ReportBufferLen { .. } => None,
        }
    }

    /// Extract the target context_id from a [`BroadcastCommand`]. Every
    /// variant names its context.
    fn broadcast_command_context_id(cmd: &BroadcastCommand) -> &str {
        match cmd {
            BroadcastCommand::SubscribeBroadcast { payload, .. } => payload.context_id.as_str(),
            BroadcastCommand::UnsubscribeBroadcast { payload, .. } => payload.context_id.as_str(),
            BroadcastCommand::PublishBroadcast { payload, .. } => payload.context_id.as_str(),
            BroadcastCommand::PublishBroadcastContent { payload, .. } => {
                payload.context_id.as_str()
            }
            BroadcastCommand::BlockBroadcastSubscriber { payload, .. }
            | BroadcastCommand::UnblockBroadcastSubscriber { payload, .. } => {
                payload.context_id.as_str()
            }
            BroadcastCommand::HandleBroadcastKeyRequest { context_id, .. }
            | BroadcastCommand::BroadcastSubscriberCount { context_id, .. }
            | BroadcastCommand::IsBroadcastSubscriber { context_id, .. }
            | BroadcastCommand::BroadcastAdmission { context_id, .. } => context_id.as_str(),
            #[cfg(feature = "testing")]
            BroadcastCommand::SeedBroadcastAuthor { context_id, .. } => context_id.as_str(),
        }
    }

    /// Extract the target context_id from a [`TtlCloseCommand`].
    ///
    /// Every per-context variant surfaces its `context_id` so the dispatch
    /// helper can route through the per-context actor's mailbox. The
    /// boxed-payload variants (`StartTtlTimer` / `ResetTtlTimer` /
    /// `ExecuteTtlClose` / `FinalizeClose`) destructure their payloads to
    /// expose the embedded `context_id`. Every variant carries a routable
    /// `context_id` (the former `FireTimer` variant was retired — TTL
    /// expiry is now an actor-owned arm, ADR-049 finding A3), so this is
    /// total (unlike the sibling `governance_command_context_id`).
    const fn ttl_close_command_context_id(cmd: &TtlCloseCommand) -> &str {
        match cmd {
            TtlCloseCommand::ExtendTtl { context_id, .. } => context_id.as_str(),
            TtlCloseCommand::StartTtlTimer { payload, .. }
            | TtlCloseCommand::ResetTtlTimer { payload, .. } => payload.context_id.as_str(),
            TtlCloseCommand::ExecuteTtlClose { payload, .. }
            | TtlCloseCommand::FinalizeClose { payload, .. } => payload.context_id.as_str(),
        }
    }

    /// Extract the target context_id from a [`GovernanceCommand`].
    ///
    /// Every per-context variant — including the boxed-payload propose
    /// / vote / execute variants — surfaces its `context_id` so the
    /// dispatch helper can route through the per-context actor's
    /// mailbox. The sweep / timeout-task variants return `None` (no
    /// routable target — see the arm comment).
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
            // (The former `EvaluateTimeouts` / `StartTimeoutTask` variants
            // were retired: governance timeouts are now an actor-owned arm,
            // ADR-049 finding A3.)
            GovernanceCommand::EvaluatePeriodicConsequences { .. }
            | GovernanceCommand::ProcessPendingCommits { .. } => None,
        }
    }

    /// Extract the target context_id from a [`StandingCommand`].
    ///
    /// Every current variant is supervisor-scoped (get-or-create / count /
    /// has / register / reconnect-all): they touch the
    /// supervisor's standing index or the get-or-create path directly, not a
    /// pre-existing per-context actor's state, so they return `None` and
    /// dispatch routes them to the SupervisorHandle.
    ///
    /// Returns an owned `String` (rather than `&str`) so a future variant that
    /// carries both `local_did` and `peer_did` can derive its context_id on
    /// demand via
    /// [`crate::context::shared::standing::generate_standing_context_id`]
    /// and route through an already-spawned per-context actor.
    const fn standing_command_context_id(cmd: &StandingCommand) -> Option<String> {
        match cmd {
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
            | StandingCommand::StandingContextCount { .. }
            | StandingCommand::HasStandingContext { .. }
            | StandingCommand::RegisterStandingContext { .. }
            | StandingCommand::ReconnectAllStanding { .. } => None,
        }
    }

    /// Extract the target context_id from a [`OutletsCommand`].
    ///
    /// Not `const`: [`OutletsCommand::SettleOutletStream`] carries its
    /// `context_id` inside a boxed `StreamSettlement`, and `Box` deref is not
    /// available in a `const fn`.
    fn outlets_command_context_id(cmd: &OutletsCommand) -> &str {
        match cmd {
            OutletsCommand::TryConsumeHardRateLimit { context_id, .. }
            | OutletsCommand::RefundHardRateLimit { context_id, .. }
            | OutletsCommand::ReserveOutletEconomy { context_id, .. }
            | OutletsCommand::ReserveOutletStreamEconomy { context_id, .. }
            | OutletsCommand::ReserveStreamGrantEscrow { context_id, .. }
            | OutletsCommand::ReverseStreamGrantEscrow { context_id, .. }
            | OutletsCommand::ReserveStreamCaveatCounter { context_id, .. }
            | OutletsCommand::ReleaseStreamCaveatCounter { context_id, .. }
            | OutletsCommand::ReverseStreamEscrow { context_id, .. }
            | OutletsCommand::PersistStreamReservation { context_id, .. }
            | OutletsCommand::ReconcileStreamReservations { context_id, .. }
            | OutletsCommand::SettleOutletEconomy { context_id, .. } => context_id.as_str(),
            OutletsCommand::SettleOutletStream { settlement, .. } => settlement.context_id.as_str(),
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
            | QueriesCommand::GetCapabilityRequirements { context_id, .. }
            | QueriesCommand::LocalRoutingIds { context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { context_id, .. }
            | QueriesCommand::MemberCount { context_id, .. }
            | QueriesCommand::IsMember { context_id, .. }
            | QueriesCommand::MemberDids { context_id, .. }
            | QueriesCommand::MemberRole { context_id, .. }
            | QueriesCommand::ContextParams { context_id, .. }
            | QueriesCommand::RelayUrls { context_id, .. }
            | QueriesCommand::GetRoleState { context_id, .. }
            | QueriesCommand::HasEstablishedOutletInterface { context_id, .. }
            | QueriesCommand::PendingCommits { context_id, .. }
            | QueriesCommand::CommitFault { context_id, .. }
            | QueriesCommand::LocalMlsEpoch { context_id, .. }
            | QueriesCommand::NeedsReconnect { context_id, .. }
            | QueriesCommand::PaymentHistory { context_id, .. } => Some(context_id.as_str()),
            QueriesCommand::EventLogEntries { .. } => None,
            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { context_id, .. }
            | QueriesCommand::GetAllAccessKeys { context_id, .. }
            | QueriesCommand::RemainingBudgetForTest { context_id, .. }
            | QueriesCommand::VelocityForTest { context_id, .. }
            | QueriesCommand::CheckpointEventsSince { context_id, .. } => Some(context_id.as_str()),
        }
    }
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// supervisor's [`Outcome`] sink — mirrors the per-handler
/// `outcome_error_sketch` pattern used in `handlers::*`. Kept in
/// `supervisor.rs` to scope the helper to the standing-direct dispatch
/// path; the actor handlers each carry their own equivalent sketch.
/// Sends `err` on a broadcast command's reply channel and returns the
/// matching error outcome.
fn reply_lookup_miss<T>(
    reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
    err: ContextError,
) -> Outcome<()> {
    let sketch = standing_outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

/// A copy of `err` for the outcome while `err` itself goes on the reply
/// channel. A variant with no field-wise copy becomes `CryptoFailed` carrying
/// the error text.
#[must_use]
pub fn standing_outcome_error_sketch(err: &ContextError) -> ContextError {
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
        ContextError::SupervisorShutDown(msg) => ContextError::SupervisorShutDown(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// Saga FSM helpers
// ---------------------------------------------------------------------------

/// Typed overlap-reject from the saga reservation critical section
/// ([`Supervisor::try_reserve_context_set`]). Carries BOTH the structured
/// `contended_context` (the overlapping participant id, read STRUCTURALLY by
/// the cross-context entry to build [`SagaError::Busy`]) AND the pre-built
/// generic [`ContextError::ActorBusy`] (the `SagaBusy` reason the
/// non-cross-context / test paths surface). Keeping the typed rejection in the
/// reservation critical section is the per-set gating invariant (ADR-049 §3a).
struct SagaReserveReject {
    contended_context: String,
    actor_busy: ContextError,
}

/// RAII release for a saga's per-participant-context-set reservation
/// (ADR-049 §3a, spec §5.15.4). Holds the exact set of context IDs THIS
/// saga reserved; on drop it synchronously re-locks
/// `Supervisor::reserved_saga_contexts` and removes precisely those ids.
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
        SagaInput::CrossContextOutletInvocation {
            caller_context_id,
            // `target_context_id` is part of the gating participant set
            // (see `saga_participant_context_set`), NOT the journal
            // provenance record: this extractor intentionally records only
            // the caller side plus the DID + outlet id. Leave the journal
            // shape UNCHANGED. The Prepare-B envelope fields (input,
            // ucan_proof_id, asserted freshness/depth, declared_cost) are
            // never journaled — only the caller-side provenance triple is.
            caller_did,
            outlet_registration_id,
            ..
        } => vec![
            hex::encode(caller_context_id),
            caller_did.to_string(),
            outlet_registration_id.clone(),
        ],
        // Streaming saga (ADR-061): same caller-side provenance triple shape as
        // the unary variant (target is in the gating set, not the journal record).
        SagaInput::CrossContextStreamingOutletInvocation {
            caller_context_id,
            caller_did,
            outlet_registration_id,
            ..
        } => vec![
            hex::encode(caller_context_id),
            caller_did.to_string(),
            outlet_registration_id.clone(),
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
/// mixed bag of DIDs, context IDs, and outlet IDs — the durable evidence of
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
/// `hex::encode([u8; 32])` — which is the canonical wire form
/// (spec §5.15.8: the `derived_context_id` is "the raw digest before prefix
/// and hex"; §6.2.4 for the cross-context wire ids).
/// The gating reservation key is canonicalized to the raw-digest hex (NOT any
/// prefixed actor-registry id) so that two sagas which share the SAME
/// underlying context reserve the IDENTICAL key and therefore OVERLAP
/// (defeating it otherwise would let two sagas touch the shared context
/// concurrently, breaking the §5.15.4 serialization the §5.15.8 anti-griefing
/// argument depends on).
///
/// - `CrossContextOutletInvocation` → `{caller, target}` context ids.
fn saga_participant_context_set(input: &SagaInput) -> Vec<String> {
    let raw: Vec<String> = match input {
        SagaInput::CrossContextOutletInvocation {
            caller_context_id,
            target_context_id,
            ..
        } => vec![
            hex::encode(caller_context_id),
            hex::encode(target_context_id),
        ],
        // Streaming saga (ADR-061): the same `{caller, target}` participant set —
        // the reservation the dedicated entry acquires, then RELEASES at the
        // Commit-transition (ADR-049 §3a(b)) while the seal pumps off-mailbox.
        SagaInput::CrossContextStreamingOutletInvocation {
            caller_context_id,
            target_context_id,
            ..
        } => vec![
            hex::encode(caller_context_id),
            hex::encode(target_context_id),
        ],
        #[cfg(any(test, feature = "testing"))]
        SagaInput::TestForceNeedsRepair { context_id } => vec![hex::encode(context_id)],
    };
    // De-dup: a saga must never self-conflict. Two ids that collapse to one
    // (caller == target) reserve a single slot.
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
        SagaInput::CrossContextOutletInvocation { .. } => false,
        // The streaming saga journals only public provenance + the manifest root
        // (never chunk bytes) — no bearer material (ADR-061 "Receipt (streaming)").
        SagaInput::CrossContextStreamingOutletInvocation { .. } => false,
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

/// Maps a bounded hard-rate-limit reply into an allow (`true`) / deny
/// (`false`) decision for [`Supervisor::try_consume_hard_rate_limit`].
///
/// SECURITY (fail-closed): the `Elapsed` arm — an ALIVE-but-wedged actor
/// whose per-context bucket exists but is momentarily unreachable — MUST deny
/// (`false`). Folding it into the `true` pass-through would silently bypass
/// the hard-rate cap for the full [`REPLY_TIMEOUT`](crate::context::actor::REPLY_TIMEOUT)
/// window (exploitable when the caller-context actor is wedged but the target
/// is healthy). Only the "no live bucket to enforce" cases pass through:
/// - `Ok(Ok(consumed))` — the handler's real verdict.
/// - `Ok(Err(_))` — handler error (e.g. `ContextNotRegistered`): no bucket.
/// - `Err(Dropped)` — the actor terminated (reply channel closed): no bucket.
/// - `Err(Elapsed)` — the actor is alive but wedged: bucket unreachable → DENY.
#[must_use]
pub const fn hard_rate_limit_allow(
    reply: &Result<Result<bool, ContextError>, BoundedReplyError>,
) -> bool {
    match reply {
        Ok(Ok(consumed)) => *consumed,
        Ok(Err(_)) | Err(BoundedReplyError::Dropped) => true,
        Err(BoundedReplyError::Elapsed) => false,
    }
}

// ---------------------------------------------------------------------------
// No-op SagaJournal — test-only. The `NoOpContextPersistence` counterpart lives
// in [`crate::context::persistence`].
// ---------------------------------------------------------------------------

/// No-op saga journal — every operation is a no-op success. Used by the
/// test-only [`Supervisor::with_providers`] and `Supervisor::for_query_shim`.
/// Compiled only under `test` or the `testing` feature: a journal that stores
/// nothing nullifies crash-recovery replay (§17.17 `SCP-CAPSEL-8000`).
#[cfg(any(test, feature = "testing"))]
pub struct NoOpSagaJournal;

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl SagaJournal for NoOpSagaJournal {
    async fn append(
        &self,
        _entry: scp_runtime_types::context::supervisor::saga_journal::JournalEntry,
    ) -> Result<(), scp_runtime_types::context::supervisor::saga_journal::JournalError> {
        Ok(())
    }

    async fn load_unresolved(
        &self,
    ) -> Result<
        Vec<scp_runtime_types::context::supervisor::saga_journal::JournalEntry>,
        scp_runtime_types::context::supervisor::saga_journal::JournalError,
    > {
        Ok(Vec::new())
    }

    async fn mark_resolved(
        &self,
        _saga_id: SagaId,
        _terminal: scp_runtime_types::context::supervisor::saga_journal::SagaTerminalState,
        _secret_bearing: bool,
    ) -> Result<(), scp_runtime_types::context::supervisor::saga_journal::JournalError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Soft-default helpers — synthesise the "context unknown" reply for each
// query variant when no per-context actor is registered.
// ---------------------------------------------------------------------------

/// Send the "context unknown" soft-default reply on a query variant's
/// oneshot when the context isn't registered. Synthesises the documented
/// unknown-context return value for each query variant.
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
        | QueriesCommand::LocalRoutingIds { .. }
        | QueriesCommand::GetBroadcastKeyForLocalAuthor { .. } => {
            debug_assert!(false, "hard-error variant routed through soft-default path");
        }
        // No soft default exists: an empty requirements list would admit
        // every member, so a misrouted read fails closed.
        QueriesCommand::GetCapabilityRequirements { reply, context_id } => {
            debug_assert!(false, "hard-error variant routed through soft-default path");
            let _ = reply.send(Err(ContextError::ContextNotRegistered(format!(
                "context not registered: {context_id}"
            ))));
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
        // An unknown context has no stored relay set.
        QueriesCommand::RelayUrls { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `get_role_state` returns `None`.
        QueriesCommand::GetRoleState { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // An unknown caller context holds no established interface.
        QueriesCommand::HasEstablishedOutletInterface { reply, .. } => {
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
        // An unknown context has no payment receipts (empty `Vec`).
        QueriesCommand::PaymentHistory { reply, .. } => {
            let _ = reply.send(Ok(Vec::new()));
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
        // Hard-error variant: routed through `reply_with_error`, never here.
        #[cfg(feature = "testing")]
        QueriesCommand::CheckpointEventsSince { .. } => {
            debug_assert!(false, "hard-error variant routed through soft-default path");
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
        QueriesCommand::LocalRoutingIds { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        QueriesCommand::GetBroadcastKeyForLocalAuthor { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        QueriesCommand::GetCapabilityRequirements { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::CheckpointEventsSince { reply, .. } => {
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

/// What a verified §5.12.3.1 `InvitationBundle` tells a Welcome joiner about
/// the context it joins: the id, the genesis parameters, the creator, and the
/// relays that host it. `Supervisor::build_welcome_joiner_state` builds the
/// joiner's actor state from these facts.
#[derive(Clone, Copy)]
struct WelcomeBundleFacts<'a> {
    context_id: &'a str,
    params: &'a scp_protocol::context::ContextParams,
    creator_did: &'a DID,
    relay_urls: &'a [String],
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The owned arguments of a recovery notification sent to a context with
/// no registered actor.
struct RecoveryNotification {
    context_id: String,
    sender_did: String,
    payload: Vec<u8>,
    sequence: u64,
    signer: crate::context::actor::signer::CommandSigner,
}

impl RecoveryNotification {
    fn new(
        context_id: &str,
        sender_did: &str,
        payload: &[u8],
        sequence: u64,
        signer: &crate::context::actor::signer::CommandSigner,
    ) -> Self {
        Self {
            context_id: context_id.to_owned(),
            sender_did: sender_did.to_owned(),
            payload: payload.to_vec(),
            sequence,
            signer: signer.clone(),
        }
    }
}

/// Only a real (64-hex) context id, decodable by the ADR-056 chokepoint
/// `context_id_to_bytes`, can be respawned. The synthetic
/// `identity-private-state` pseudo-context (PSK rotation, spec §9.12 step 6)
/// is never a registered actor, has no persisted snapshot, and in production
/// has no MLS group, so it gets the "no MLS group" error the retired
/// provider seal produced, a best-effort no-op, before any lock is taken. The
/// 64-hex-lowercase predicate mirrors `context_id_to_bytes`'s canonical
/// branch.
///
/// # Errors
///
/// [`ContextError::CryptoFailed`] for any other id.
fn recovery_notification_target_is_real(context_id: &str) -> Result<(), ContextError> {
    let is_real_context_id = context_id.len() == 64
        && context_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if is_real_context_id {
        Ok(())
    } else {
        Err(ContextError::CryptoFailed(
            "no MLS group for this context".to_string(),
        ))
    }
}

/// Keeps `supervisor` alive for the rest of the test process.
///
/// `ActorDeps` holds only a `Weak` back-reference (ADR-049 Decision 16), so a
/// fixture that builds a Supervisor, returns only its `ActorDeps`, and drops
/// the `Arc` would leave every supervisor operation failing with
/// `SupervisorShutDown`. Those fixtures call this to model a live owner.
#[cfg(any(test, feature = "testing"))]
pub fn leak_for_test(supervisor: &Arc<Supervisor>) {
    std::mem::forget(Arc::clone(supervisor));
}
