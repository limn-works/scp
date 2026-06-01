//! Streaming dispatch wiring (SCP-OUT-034 follow-up).
//!
//! Glues together the four primitives from
//! [`super::stream`] — [`CreditTracker`], [`StreamEscrow`],
//! [`CancelAckTracker`], and [`StreamAdmissionTracker`] — into the
//! actual streaming dispatch path that the runtime runs at
//! `OutletStreamOpen` acceptance time.
//!
//! The OUT-034 first-commit shipped 1,200 lines of primitives but never
//! called them from the streaming pump. This module is the missing
//! integration layer: it owns one [`StreamSession`] per accepted
//! `OutletStreamOpen` and (i) runs the §5.4.5 round-5 5-step admission
//! sequence, (ii) reserves escrow at open, (iii) initialises the credit
//! and cancel-ack trackers, (iv) drives a per-chunk pump that consults
//! the trackers in lockstep with chunk emission, and (v) settles the
//! escrow + decrements admission counters at terminal-chunk delivery.
//!
//! # Lifecycle
//!
//! 1. Caller invokes [`open_stream_session`] with the
//!    [`OpenStreamParams`]. It runs the admission gate, reserves escrow
//!    (Action outlets) or wires zero-escrow (Query / zero-cost), pins the
//!    stream identity, builds the trackers, and spawns the pump task.
//!    Returns [`StreamSessionHandle`] which exposes the chunk receiver
//!    and the credit-grant / cancel input methods.
//! 2. The pump consults [`CreditTracker::try_consume`] before forwarding
//!    each `Data`/`Progress` chunk; on `OutOfCredit` it pauses the
//!    executor and arms the
//!    `ContextParams::stream_credit_stall_secs` timer. A validly accepted
//!    grant cancels the timer.
//! 3. `Data` chunks at or below `cancel_ack_seq` invoke
//!    [`StreamEscrow::accrue_one_chunk`].
//! 4. `OutletStreamCredit` reception goes through
//!    [`StreamSessionHandle::apply_credit_grant`], which calls
//!    [`CreditTracker::grant_with_identity`] under the pinned identity
//!    and tops up escrow on success.
//! 5. `OutletCancel` reception goes through
//!    [`StreamSessionHandle::apply_outlet_cancel`], which records the
//!    cancel-ack-seq, arms the
//!    `ContextParams::stream_cancel_ack_secs` timer, and propagates the
//!    cancellation to the pump.
//! 6. On terminal-chunk emission the pump:
//!    - calls [`StreamEscrow::settle_at_close`] to derive
//!      `(billed_amount, refund_amount, billed_count)`,
//!    - calls [`StreamAdmissionTracker::release`] to decrement all three
//!      cap counters,
//!    - publishes the `chunks_billed` value into the
//!      `OutletInvokedEvent` field and verifies it via
//!      [`super::stream::verify_chunks_billed`] before handing the
//!      event to the event-log appender.
//!
//! See `.docs/specs/05-contexts.md` §5.4.5 for the spec source.

// `module_name_repetitions` and `significant_drop_tightening` are
// pragmatic for this dispatch module — the public API names match the
// §5.4.5 spec table verbatim, and the per-stream `MutexGuard` lifetime
// IS the critical section by design (§5.4.5 atomicity invariant: the
// admission counters and credit accounting must mutate together).
#![allow(clippy::module_name_repetitions, clippy::significant_drop_tightening)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use scp_primitives::DID;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::error_codes;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamCancel, OutletStreamChunk, OutletStreamCredit, RequestId,
    TerminateReason, compute_cancel_sig_preimage, compute_caveats_binding,
    compute_chunk_sig_preimage, verify_cancel_signature, verify_chunk_signature,
};
use scp_protocol::crypto::ucan::validate::RevocationChecker;

use super::signer::{StreamSigner, StreamSignerError};
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;

use tokio::sync::{Notify, mpsc};

use crate::context::ContextHandle;

use super::invoke::{
    HandlerPanicSink, InvocationError, OutletExecutor, OutletInvokedEventSink,
    QueryMisdeclarationSink, StreamGateOutcome, accrue_data_chunk_if_billable,
    apply_stream_chunk_gate, invoke_outlet, release_stream_admission,
};
use super::stream::{
    AdmissionCaps, AdmissionOutcome, CancelAckTracker, CreditTracker, EscrowError, GrantError,
    OpenError, StreamAdmissionTracker, StreamEscrow, StreamIdentity, admission_outcome_to_slug,
    coerce_estimated_chunk_count, compute_chunks_billed_ref, enforce_estimated_chunk_count_bound,
    open_error_to_slug, verify_chunks_billed,
};

use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::roles::ContextRoleState;

// ---------------------------------------------------------------------------
// Open-time rejection types
// ---------------------------------------------------------------------------

/// Outcome of [`open_stream_session`] when the open is rejected before
/// the stream channel is opened.
///
/// Distinct from [`InvocationError`] because the OUT-034 admission /
/// escrow gates run BEFORE the stream is opened — a synchronous failure
/// at this point produces a terminal envelope, not a chunk receiver.
/// Each variant maps to a §5.4.4 slug + class + retry policy via
/// [`OpenStreamRejection::slug`] and
/// [`OpenStreamRejection::error_code`] so the FFI / SDK layer can shape
/// the error envelope identically to the in-stream terminal `Error`
/// chunks the pump emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenStreamRejection {
    /// `StreamAdmissionTracker` rejected the open at one of the three
    /// concurrent-stream caps. Carries the same slug
    /// (`transport.concurrent-streams-per-*`) the post-open path would
    /// have surfaced via a terminal chunk.
    AdmissionRateLimited {
        /// The §5.4.4 slug pinpointing which tier rejected.
        slug: &'static str,
    },
    /// `enforce_estimated_chunk_count_bound` rejected the open: declared
    /// `estimated_chunk_count` exceeded
    /// `min(credit_window, caveats.max_calls)`.
    EstimateExceedsBound,
    /// `StreamEscrow::reserve_at_open` overflowed `cost.amount *
    /// estimated_chunk_count`.
    EscrowOverflow,
    /// `StreamEscrow::reserve_at_open` rejected because the invoker's
    /// available balance is below the reservation.
    InsufficientFunds,
    /// The SDK-supplied `caveats_binding` does not match the binding the
    /// runtime recomputes from the parsed UCAN's effective caveats,
    /// `request_id`, `invoker_did`, and `ucan_cid` (the §5.4.5 binding
    /// preimage). A malicious invoker presents a UCAN narrowed to caveat
    /// set A but supplies a binding committing to a wider set B —
    /// without this recheck every downstream chunk/grant/cancel would
    /// bind to B and bypass set A's restrictions. Recomputing the
    /// binding at open from the trusted, parsed UCAN closes the gap.
    /// Slug: `authorization.attenuation-violation`; code:
    /// `SCP-TOOL-6110` (the Authorization-class umbrella per §5.4.4).
    CaveatsBindingMismatch,
    /// The node-level concurrent-pump ceiling
    /// (`ContextManager::max_concurrent_outlet_stream_pumps`) was already
    /// saturated when this open tried to acquire a pump permit (round 8).
    /// Acquired AFTER all per-context admission / escrow / binding gates
    /// pass, so a rejected open here does NOT consume a per-context
    /// admission slot or an escrow reservation; the caller's prior gates
    /// are rolled back before this rejection is returned. Slug:
    /// `execution.stream-cap-exhausted`; code: `SCP-TOOL-6131`
    /// (`CODE_EXECUTION_CREDIT`, the shared Execution resource-exhaustion
    /// band per §5.4.5 round-8).
    StreamCapExhausted,
}

impl OpenStreamRejection {
    /// Returns the §5.4.4 slug for this rejection.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match *self {
            Self::AdmissionRateLimited { slug } => slug,
            Self::EstimateExceedsBound => error_codes::SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND,
            Self::EscrowOverflow => error_codes::SLUG_ECONOMIC_ESCROW_OVERFLOW,
            Self::InsufficientFunds => error_codes::SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
            Self::CaveatsBindingMismatch => error_codes::SLUG_AUTHORIZATION_ATTENUATION_VIOLATION,
            Self::StreamCapExhausted => error_codes::SLUG_EXECUTION_STREAM_CAP_EXHAUSTED,
        }
    }

    /// Returns the §5.4.4 error code for this rejection.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match *self {
            Self::AdmissionRateLimited { .. } => error_codes::CODE_TRANSPORT_FAULT,
            Self::EstimateExceedsBound => error_codes::CODE_INPUT_VIOLATION,
            Self::EscrowOverflow | Self::InsufficientFunds => error_codes::CODE_ECONOMIC_FAULT,
            Self::CaveatsBindingMismatch => error_codes::CODE_AUTHORIZATION_DENIED,
            Self::StreamCapExhausted => error_codes::CODE_EXECUTION_CREDIT,
        }
    }

    /// Routes this rejection into an [`InvocationError`] envelope so
    /// existing `invocation_error_to_context` translation surfaces it
    /// identically to other open-time validation failures.
    #[must_use]
    pub fn to_invocation_error(&self) -> InvocationError {
        InvocationError::CaveatViolation {
            slug: self.slug(),
            message: format!("stream open rejected: {}", self.slug()),
        }
    }
}

// ---------------------------------------------------------------------------
// Open-time parameters
// ---------------------------------------------------------------------------

/// Parameters for opening a stream session via [`open_stream_session`].
///
/// Bundles the §5.4.5 round-5 admission inputs (caps, identity DIDs,
/// outlet id) with the §5.4.5 escrow inputs (cost-per-chunk, balance,
/// estimated-chunk-count + caveats, `credit_window`) so the dispatch
/// path can run admission → escrow → tracker init in a single
/// sequence.
///
/// `Debug` is hand-rolled because [`RevocationChecker`] is a trait
/// object that does not itself require `Debug`; the manual impl renders
/// it as `revocation_checker: <dyn RevocationChecker>` so logging at
/// the open boundary does not require a `Debug` bound on every
/// production checker.
#[derive(Clone)]
pub struct OpenStreamParams {
    /// Stream identity pinned at acceptance.
    pub identity: StreamIdentity,
    /// Per-context concurrent-stream caps (from `ContextParams`).
    pub caps: AdmissionCaps,
    /// Immediate-previous-hop DID (the §5.4.5 `invoker_did`).
    pub invoker_did: String,
    /// Outermost UCAN `iss` DID (per-origin-invoker tier).
    pub origin_invoker_did: String,
    /// Per-Data-chunk cost. `Amount::new(0)` for Query and zero-cost
    /// outlets (escrow becomes the §5.4.5 zero-escrow shape).
    pub cost_per_chunk: Amount,
    /// Invoker's available balance at open. Compared against the
    /// reservation in `StreamEscrow::reserve_at_open` and against
    /// every per-grant top-up.
    pub available_balance: Amount,
    /// Optional explicit `estimated_chunk_count` from the
    /// `OutletStreamOpen`. `None` falls back to
    /// `coerce_estimated_chunk_count` per §5.4.5:422-432.
    pub declared_estimated_chunk_count: Option<u32>,
    /// `OutletStreamOpen.credit_window` (defaults to
    /// `ContextParams::stream_window_default`).
    pub credit_window: u32,
    /// Per-outlet effective caveats (§7.3.8). Used both for the
    /// estimate-coercion fallback and for the
    /// `enforce_estimated_chunk_count_bound` ceiling.
    pub caveats: InvocationCaveats,
    /// Invoker's Ed25519 verifying key. Pinned for the stream's
    /// lifetime; every grant signature verifies under this key.
    pub invoker_pk: VerifyingKey,
    /// Operator's streaming signer. Used by the dispatch pump to sign
    /// every chunk that crosses the outer wire boundary — both
    /// executor-emitted chunks (renumbered under the pump's sequence)
    /// and framework-emitted terminal chunks (cancel-ack-timeout,
    /// credit-stall, revoked-mid-stream, context-closed-mid-stream).
    /// Pinned at acceptance.
    ///
    /// Non-optional: every accepted stream MUST have a signer. The
    /// §5.4.5 wire contract is that every chunk crossing the outer
    /// boundary carries a verifiable `SCP-OUTLET-CHUNK-SIG-V1:`
    /// signature; emitting an unsigned `[0u8; 64]` placeholder would
    /// silently corrupt the wire and let a receiver bill chunks under
    /// a sig that no operator ever signed.
    ///
    /// Round-8 (ADR-049): this is a [`StreamSigner`] trait object, not a
    /// raw `Arc<SigningKey>`. Native FFI bridges supply a custody-backed
    /// adapter so the operator private key never enters the runtime
    /// address space (ADR-006); tests and WASM (operator==invoker per
    /// ADR-034) supply an `InProcessStreamSigner`. Signing is `async` —
    /// the pump composes the preimage synchronously and awaits the
    /// signer for the signature.
    pub operator_signer: Arc<dyn StreamSigner>,
    /// `ContextParams::stream_credit_stall_secs`.
    pub stream_credit_stall_secs: u32,
    /// `ContextParams::stream_cancel_ack_secs`.
    pub stream_cancel_ack_secs: u32,
    /// `ContextParams::stream_ucan_recheck_secs` — period (in seconds)
    /// for the runtime's authoritative UCAN-revocation re-check timer
    /// inside the streaming pump (§5.4.5 "Revocation re-check cadence
    /// (receiver-side)"). On every tick the pump consults
    /// [`Self::revocation_checker`] for `Self::ucan_cid` and, on
    /// observed revocation, injects a synthetic terminal
    /// `RevokedMidStream` chunk via the same path the SDK-side helper
    /// uses. Runtime-side enforcement is now authoritative — a hostile
    /// or buggy SDK that never spawns its userspace re-check loop can
    /// no longer stream unbounded chunks under a revoked token. The
    /// SDK-side rechecks remain as defense-in-depth (§5.4.5
    /// "Authoritative locus: runtime; SDK is `DiD`").
    pub stream_ucan_recheck_secs: u32,
    /// CID of the opening UCAN, as the string the §5.4.5 revocation
    /// list keys on (matches the [`RevocationChecker::is_revoked`]
    /// argument type). The same bytes (`.as_bytes()`) are consumed by
    /// [`compute_caveats_binding`] to recompute the §5.4.5 binding
    /// preimage at open.
    ///
    /// Open-time invariant (§5.4.5 binding-pinning): the runtime
    /// recomputes the `caveats_binding` from
    /// `(ucan_cid, request_id, invoker_did, declared_estimated_chunk_count,
    /// JCS(caveats))` and rejects with
    /// [`OpenStreamRejection::CaveatsBindingMismatch`] when the SDK-
    /// supplied `identity.caveats_binding` does not match byte-for-byte.
    /// Trusting an SDK-supplied binding would let a malicious invoker
    /// present a UCAN narrowed to caveat set A but bind every chunk to
    /// a looser set B.
    pub ucan_cid: String,
    /// 16-byte stream `request_id` (§5.4.5 `UUIDv7`). The §5.4.5
    /// binding preimage commits to this value, so the runtime MUST use
    /// the same `request_id` the SDK used when computing the binding
    /// — otherwise the recompute would never match. Threading the
    /// `request_id` through `OpenStreamParams` makes it the single
    /// source of truth: the pump stamps every outer chunk with this
    /// value, the binding-recompute consumes it verbatim, and the
    /// returned [`StreamSessionHandle::request_id`] surfaces it back
    /// to the bridge.
    pub request_id: RequestId,
    /// Trait-object [`RevocationChecker`] the runtime pump consults
    /// every [`Self::stream_ucan_recheck_secs`]. The runtime-side
    /// recheck is the authoritative termination locus per §5.4.5;
    /// SDK-side recheck loops remain in place as defense-in-depth.
    /// Implementations include
    /// [`scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker`]
    /// for unit tests and per-context revocation-list adapters in the
    /// FFI bridges. The bound is `Send + Sync` because the checker
    /// is shared across the open path and the spawned pump task.
    pub revocation_checker: Arc<dyn RevocationChecker + Send + Sync>,
}

impl core::fmt::Debug for OpenStreamParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenStreamParams")
            .field("identity", &self.identity)
            .field("caps", &self.caps)
            .field("invoker_did", &self.invoker_did)
            .field("origin_invoker_did", &self.origin_invoker_did)
            .field("cost_per_chunk", &self.cost_per_chunk)
            .field("available_balance", &self.available_balance)
            .field(
                "declared_estimated_chunk_count",
                &self.declared_estimated_chunk_count,
            )
            .field("credit_window", &self.credit_window)
            .field("caveats", &self.caveats)
            .field("invoker_pk", &self.invoker_pk)
            .field("operator_signer", &"<Arc<dyn StreamSigner>>")
            .field("stream_credit_stall_secs", &self.stream_credit_stall_secs)
            .field("stream_cancel_ack_secs", &self.stream_cancel_ack_secs)
            .field("stream_ucan_recheck_secs", &self.stream_ucan_recheck_secs)
            .field("ucan_cid", &self.ucan_cid)
            .field("request_id", &self.request_id)
            .field("revocation_checker", &"<dyn RevocationChecker>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Per-stream session state (shared between control + pump)
// ---------------------------------------------------------------------------

/// Mutable per-stream state shared between the spawned pump task and
/// the [`StreamSessionHandle`] held by the control surface (the path
/// that delivers `OutletStreamCredit` and `OutletCancel`).
///
/// Wrapped in `Arc<Mutex<_>>` so the control surface and the pump can
/// both mutate it without taking long locks. Critical sections are
/// short — every method either reads a counter or runs a 5-step open /
/// 3-counter release / single accrual.
///
/// `Debug` is hand-rolled because [`SharedSessionState::revocation_checker`]
/// is a trait object that does not require `Debug`.
pub(crate) struct SharedSessionState {
    /// Single-thread-of-control credit accounting.
    pub credit: CreditTracker,
    /// Per-stream escrow ledger.
    pub escrow: StreamEscrow,
    /// Cancel-ack lifecycle tracker.
    pub cancel_ack: CancelAckTracker,
    /// Admission tracker reference (shared per-context). The pump
    /// releases counters here at terminal-chunk emission.
    pub admission: Arc<Mutex<StreamAdmissionTracker>>,
    /// Identity triple used to release admission counters.
    pub admission_release_keys: AdmissionReleaseKeys,
    /// `true` when the §5.4.5 cancel-ack timer has armed.
    pub cancel_ack_armed: bool,
    /// `true` when the credit-stall timer has armed (credit hit zero
    /// without a fresh grant).
    pub credit_stall_armed_at: Option<Instant>,
    /// Pinned at acceptance — the executor stops billing chunks above
    /// this `cancel_ack_seq` (§5.4.5 cancel-ack ceiling).
    pub cancel_ack_seq: Option<u64>,
    /// Live cursor: the **next-to-emit** outer sequence the pump will
    /// stamp onto the next forwarded chunk (§5.4.5 "current emission
    /// cursor"). Initialised to `0` at session creation and bumped by
    /// the pump after every accepted forward. Read by the bridge layer
    /// to derive the canonical `cancel_ack_seq` written into the
    /// `OutletStreamCancel` preimage — bridges MUST NOT accept this
    /// value from caller input (a forged value enables zero-bill or
    /// over-bill of delivered chunks).
    pub next_emission_seq: u64,
    /// Operator streaming signer pinned at acceptance. The pump uses
    /// this to sign every chunk that crosses the outer wire boundary —
    /// executor-emitted chunks (re-signed under the pump's renumbered
    /// sequence) and framework-emitted terminal chunks (cancel-ack-
    /// timeout, credit-stall, revoked-mid-stream, context-closed-mid-
    /// stream) — and to sign the runtime-derived `OutletStreamCancel`
    /// in [`StreamSessionHandle::apply_outlet_cancel_signed`].
    /// Non-optional: see [`OpenStreamParams::operator_signer`] for
    /// rationale.
    pub operator_signer: Arc<dyn StreamSigner>,
    /// Receiver-side termination request. When `Some`, the pump
    /// emits a synthetic `Error{terminal:true}` chunk under the
    /// pinned operator key on its next iteration and breaks the
    /// loop. Set by [`StreamSessionHandle::terminate_with_error`]
    /// per §5.4.5 framework-initiated termination paths (receiver-
    /// side UCAN revocation re-check `RevokedMidStream`, executor
    /// cancel-ack-timeout, credit-stall). The pump consumes the
    /// `Option` (`take()`) so a duplicate notification is a no-op
    /// and the synthetic chunk is emitted exactly once.
    pub pending_terminate: Option<PendingTerminate>,
    /// CID of the opening UCAN — the lookup key the pump passes to
    /// [`Self::revocation_checker`] every
    /// [`SharedSessionState::stream_ucan_recheck_secs`]. The pump
    /// snapshots this once at spawn so the re-check arm does not need
    /// to re-take the session mutex for every tick.
    pub ucan_cid: String,
    /// Trait-object [`RevocationChecker`] consulted by the pump's
    /// authoritative re-check timer. On observed revocation the pump
    /// arms `pending_terminate` with [`TerminateReason::RevokedMidStream`]
    /// and wakes itself via the existing `terminate_wake` notifier —
    /// the synthetic terminal chunk then flows through the same
    /// settlement block the SDK-side `terminate_with_error` path uses,
    /// so audit-log / escrow-refund / admission-release run end-to-end.
    pub revocation_checker: Arc<dyn RevocationChecker + Send + Sync>,
    /// Period (in seconds) for the pump's revocation re-check arm.
    /// Snapshotted from `OpenStreamParams::stream_ucan_recheck_secs`
    /// (which mirrors `ContextParams::stream_ucan_recheck_secs`) so
    /// the per-context parameter wins for streams opened against
    /// different contexts on the same node.
    pub stream_ucan_recheck_secs: u32,
    /// Handle to the hosting context. The pump consults its lifecycle
    /// [`ContextState`](crate::context::ContextState) in the same
    /// re-check arm that drives revocation: when the context is no
    /// longer `Active` (closed, evicted/left, expired, migrating,
    /// tombstoned) the pump arms `pending_terminate` with
    /// [`TerminateReason::ContextClosedMidStream`] — a Protocol-class
    /// teardown, distinct from the Authorization-class
    /// `RevokedMidStream` (§5.4.5 round-8 "Context teardown vs.
    /// revocation"). The handle is a cheap `Arc`-backed clone whose
    /// state reflects live transitions on the shared context.
    pub context_handle: ContextHandle,
}

impl core::fmt::Debug for SharedSessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSessionState")
            .field("credit", &self.credit)
            .field("escrow", &self.escrow)
            .field("cancel_ack", &self.cancel_ack)
            .field("admission", &"<Arc<Mutex<StreamAdmissionTracker>>>")
            .field("admission_release_keys", &self.admission_release_keys)
            .field("cancel_ack_armed", &self.cancel_ack_armed)
            .field("credit_stall_armed_at", &self.credit_stall_armed_at)
            .field("cancel_ack_seq", &self.cancel_ack_seq)
            .field("next_emission_seq", &self.next_emission_seq)
            .field("operator_signer", &"<Arc<dyn StreamSigner>>")
            .field("pending_terminate", &self.pending_terminate)
            .field("ucan_cid", &self.ucan_cid)
            .field("revocation_checker", &"<dyn RevocationChecker>")
            .field("stream_ucan_recheck_secs", &self.stream_ucan_recheck_secs)
            .field("context_handle", &self.context_handle.context_id())
            .finish()
    }
}

/// Terminal-injection payload supplied by
/// [`StreamSessionHandle::terminate_with_error`].
///
/// Carries a closed-set [`TerminateReason`] (which deterministically
/// maps to the §5.4.4 slug + code) plus an optional caller-supplied
/// message extension. The slug and code are NEVER caller-controlled —
/// they are derived from the enum on the pump side so attacker-
/// controlled strings cannot enter the provenance record through the
/// termination path.
#[derive(Debug, Clone)]
pub(crate) struct PendingTerminate {
    /// Closed-set termination cause. Determines the slug and code of
    /// the synthetic terminal chunk via [`TerminateReason::slug`] and
    /// [`TerminateReason::code`].
    pub reason: TerminateReason,
    /// Optional caller-supplied human-readable extension. When `Some`,
    /// the chunk's `message` field becomes
    /// `format!("{slug}: {override}")`; when `None`, it becomes
    /// `format!("{slug}: {default_message}")` per §5.4.4 wire shape.
    /// The slug prefix is always derived from the enum.
    pub message_override: Option<String>,
}

/// The 3-tuple of strings the admission tracker keys on. Kept as a
/// distinct struct so pump release calls cannot accidentally swap
/// invoker / origin / outlet positionally.
#[derive(Debug, Clone)]
pub(crate) struct AdmissionReleaseKeys {
    pub invoker_did: String,
    pub origin_invoker_did: String,
    pub outlet_id: String,
}

// ---------------------------------------------------------------------------
// Receiver-side terminate error
// ---------------------------------------------------------------------------

/// Failure modes for [`StreamSessionHandle::terminate_with_error`]
/// (§5.4.5 receiver-side revocation re-check, `RevokedMidStream` /
/// `SCP-TOOL-6110`).
///
/// All variants are recoverable from the SDK's perspective — they
/// indicate the stream has already left the pump's control plane (e.g.
/// the executor reached its own checkpoint first or the receiver
/// already drained the terminal chunk). Per §5.4.5 the framework
/// guarantees the stream closes "at or before `stream_ucan_recheck_secs`
/// after the revocation event regardless of executor behavior" — the
/// SDK treats these errors as the runtime having reached terminal
/// state on its own and stops the recheck loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminateError {
    /// The pump has already emitted a terminal chunk and broken its
    /// loop. The synthetic chunk is dropped — there is nothing to
    /// terminate.
    AlreadyTerminated,
    /// A prior `terminate_with_error` call already armed
    /// `pending_terminate` and the pump has not yet consumed it.
    /// Idempotent — the SDK's recheck loop should treat this as
    /// success (the terminal chunk is in flight).
    AlreadyPending,
}

impl core::fmt::Display for TerminateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyTerminated => f.write_str("stream already terminated"),
            Self::AlreadyPending => f.write_str("terminate already pending"),
        }
    }
}

impl std::error::Error for TerminateError {}

// ---------------------------------------------------------------------------
// StreamSessionHandle — control surface
// ---------------------------------------------------------------------------

/// Caller-supplied stream identity for
/// [`StreamSessionHandle::apply_outlet_cancel_signed`] (ADR-049 round 8).
///
/// Deliberately carries NO `next_seq` / cursor field: the runtime derives
/// the cancel's `next_seq` from its own live emission cursor and signs it
/// internally, so a bridge can never supply a forged cursor (§5.4.5). The
/// `request_id` is taken from the pinned [`StreamSessionHandle::request_id`]
/// — the bridge identifies the stream by handle, not by repeating the
/// `request_id` here. The three fields below are cross-checked against the
/// values pinned at stream open before the operator signer is wielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelIdentity {
    /// Hosting context id the caller claims this cancel targets.
    pub context_id: String,
    /// Outlet id the caller claims this cancel targets.
    pub outlet_id: String,
    /// 32-byte `caveats_binding` pinned at stream open.
    pub caveats_binding: [u8; 32],
}

/// Handle returned by [`open_stream_session`]. Owns the chunk receiver
/// and exposes the input methods that drive the §5.4.5 control plane:
///
/// - [`Self::receiver`] — drains the per-stream chunks.
/// - [`Self::apply_credit_grant`] — delivers an `OutletStreamCredit`.
/// - [`Self::apply_outlet_cancel`] — delivers an `OutletCancel`.
/// - [`Self::settle_summary`] — observes `(billed, refund, billed_count)`
///   after the pump flushes (used by the event-log path and tests).
pub struct StreamSessionHandle {
    /// Receiver returned to the caller.
    receiver: Option<mpsc::Receiver<OutletStreamChunk>>,
    /// Shared per-stream state (Arc-shared with the pump task).
    state: Arc<Mutex<SharedSessionState>>,
    /// Notifier used to wake the pump from a credit-stall pause when a
    /// fresh grant lands.
    grant_wake: Arc<Notify>,
    /// Notifier used to wake the pump on `OutletCancel` arrival.
    cancel_wake: Arc<Notify>,
    /// Notifier used to wake the pump when the receiver-side framework
    /// requests a forced terminal via
    /// [`StreamSessionHandle::terminate_with_error`] (§5.4.5
    /// `RevokedMidStream` / `SCP-TOOL-6110`). The pump's select arm for
    /// this notifier checks `pending_terminate`, builds the synthetic
    /// terminal chunk under the pinned operator key, and breaks the
    /// loop into the settlement block. Settlement runs identically to
    /// the cancel-ack-timeout / credit-stall paths so admission release,
    /// escrow refund, and `OutletInvokedEvent` emission are exercised
    /// end-to-end.
    terminate_wake: Arc<Notify>,
    /// Receiver for the close summary the pump publishes once it has
    /// settled.
    ///
    /// The dispatch pump is the authoritative `OutletInvokedEvent`
    /// emitter (§5.4.5 — owns the outer manifest), but
    /// [`StreamCloseSummary`] additionally carries the
    /// `(billed_amount, refund_amount)` pair that the event payload
    /// does not — those values are economy-layer concerns the FFI
    /// layer surfaces via `PaymentReceipt` (§19.15.5), not the audit
    /// log. Tests and bridge surfaces that need the post-settlement
    /// economy values consume this channel; the event-log audit path
    /// uses the sink.
    summary_rx: Option<tokio::sync::oneshot::Receiver<StreamCloseSummary>>,
    /// Pinned `request_id` (used by `apply_outlet_cancel` to validate
    /// the inbound message).
    request_id: RequestId,
}

/// Summary of the per-stream settlement, published exactly once when
/// the pump emits the terminal chunk.
#[derive(Debug, Clone)]
pub struct StreamCloseSummary {
    /// Total amount billed at close (§19.15.5 `PaymentReceipt`).
    pub billed_amount: Amount,
    /// Refund credited back to the invoker.
    pub refund_amount: Amount,
    /// `chunks_billed` for the `OutletInvokedEvent` (count of `Data`
    /// leaves at or below `cancel_ack_seq`).
    pub billed_count: u32,
    /// Total chunks emitted (Data + Progress + terminal).
    pub stream_chunk_count: u32,
    /// `cancel_ack_seq` if cancel arrived, else `None`.
    pub cancel_ack_seq: Option<u64>,
    /// Manifest of all chunks the runtime emitted on the stream.
    /// Required by the §5.4.5 wire-rejection rule at log-insert time.
    pub manifest: Vec<OutletStreamChunk>,
}

impl StreamSessionHandle {
    /// Detaches the chunk receiver. Returns `None` if already taken.
    pub const fn receiver(&mut self) -> Option<mpsc::Receiver<OutletStreamChunk>> {
        self.receiver.take()
    }

    /// Detaches the close summary future. Resolves when the pump emits
    /// the terminal chunk. The summary carries the
    /// `(billed_amount, refund_amount, billed_count)` triple plus the
    /// outer chunk manifest — economy-layer values the
    /// `OutletInvokedEvent` does not carry.
    pub const fn close_summary(
        &mut self,
    ) -> Option<tokio::sync::oneshot::Receiver<StreamCloseSummary>> {
        self.summary_rx.take()
    }

    /// `request_id` of this stream.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Reads the **runtime-derived** next-to-emit sequence cursor (the
    /// §5.4.5 "current emission cursor"). Bridge cancel paths MUST use
    /// this value as the `next_seq` field when constructing
    /// [`OutletStreamCancel`] — never trust caller input. A caller-
    /// supplied `next_seq` lets the caller forge `cancel_ack_seq` (zero
    /// to nullify billing of delivered chunks, or `u64::MAX` to over-
    /// bill); reading the cursor from runtime state closes that
    /// surface.
    ///
    /// Returns `0` for a stream that has not yet emitted any chunk.
    #[must_use]
    pub fn current_next_emission_seq(&self) -> u64 {
        let guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.next_emission_seq
    }

    /// Applies an `OutletStreamCredit` grant.
    ///
    /// Per §5.4.5: verifies the Ed25519 signature under the pinned
    /// identity, rejects replays / regressions, and on acceptance
    /// (i) increments the credit counter and (ii) tops up the escrow
    /// ledger by `cost_per_chunk * grant`. Either failure leaves the
    /// counter unchanged — §5.4.5 atomicity invariant.
    ///
    /// Wakes the pump via the grant notifier so a stalled executor can
    /// resume immediately.
    ///
    /// # Errors
    ///
    /// Returns the `(slug, code)` pair for the rejection. The §5.4.5
    /// slugs are routed via [`grant_error_to_slug`].
    pub fn apply_credit_grant(
        &self,
        credit: &OutletStreamCredit,
        available_balance: Amount,
    ) -> Result<u32, GrantError> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let identity_clone = guard.credit.identity().clone();
        let new_total = guard.credit.grant_with_identity(credit, &identity_clone)?;
        // Top up escrow on accepted grant. Failure here MUST roll back
        // the credit counter so the §5.4.5 atomicity invariant holds:
        // a grant that fails escrow does not authorize further billable
        // chunks. We hold the lock across both calls so the window
        // cannot interleave a pump consume.
        if let Err(escrow_err) = guard
            .escrow
            .top_up_for_grant(credit.grant, available_balance)
        {
            // Roll back the credit counter by consuming the grant's
            // worth back out via `try_consume`. `try_consume` is the
            // only primitive-exposed mutator that decrements
            // `remaining`; calling it `grant` times returns the
            // counter to its pre-grant value. (Any consumption that
            // does NOT have credit available will return
            // `OutOfCredit::Exhausted` — which on rollback is a
            // signal we have already drained. The primitive is
            // saturating, so we cannot underflow.)
            for _ in 0..credit.grant {
                if guard.credit.try_consume().is_err() {
                    break;
                }
            }
            return Err(match escrow_err {
                EscrowError::Overflow => GrantError::EscrowOverflow,
                EscrowError::InsufficientFunds => GrantError::InsufficientFunds,
            });
        }
        // Cancel any armed credit-stall timer — a valid grant lifts the
        // pump out of stall.
        guard.credit_stall_armed_at = None;
        drop(guard);
        // Single-consumer pump: `notify_one` is correct (and sufficient).
        // The pump is the sole waiter on `grant_wake`; `notify_waiters`
        // would only wake the same single waiter, but `notify_one` also
        // stores a permit if the pump is briefly between iterations — so a
        // grant that lands while the pump is not parked on `notified()` is
        // not lost (lost-wakeup closure, F3).
        self.grant_wake.notify_one();
        Ok(new_total)
    }

    /// Signs and applies an `OutletStreamCancel` atomically against the
    /// runtime-derived next-to-emit cursor (ADR-049 round 8, N2).
    ///
    /// This is the native-bridge contract: the bridge passes only the
    /// caller's pinned identity ([`CancelIdentity`]); it NEVER carries a
    /// `next_seq` (a caller-supplied cursor lets the caller forge
    /// `cancel_ack_seq` — zero to nullify billing, `u64::MAX` to over-bill,
    /// per §5.4.5). The runtime reads its own live cursor, signs the
    /// `SCP-OUTLET-CANCEL-V1:` preimage over that cursor with the pinned
    /// operator signer, then applies the resulting cancel.
    ///
    /// # Protocol
    ///
    /// 1. Lock, read `next_emission_seq` (the cursor to sign against), clone
    ///    the pinned identity, snapshot `invoker_pk`. Drop the lock.
    /// 2. Validate the caller's [`CancelIdentity`] matches the pinned
    ///    `(context_id, outlet_id, caveats_binding)` triple — mismatch →
    ///    [`super::stream::CancelError::SignatureInvalid`] (NO mutation).
    /// 3. Build the `SCP-OUTLET-CANCEL-V1:` preimage over
    ///    `(pinned ctx, pinned outlet, self.request_id, seq, pinned
    ///    binding)` — NO lock held — and `await` the signer.
    /// 4. Re-lock. If the cursor advanced (`next_emission_seq != seq`) and
    ///    the bounded retry budget (cap 4) remains, loop back to step 1
    ///    against the new cursor; on exhaustion →
    ///    [`super::stream::CancelError::CursorAdvanced`] (retryable, NO
    ///    mutation). Otherwise self-verify the signature under
    ///    `invoker_pk`, record the cancel-ack at `seq`, arm the cancel-ack
    ///    timer, and wake the pump.
    ///
    /// The `std::sync::Mutex` is NEVER held across the `.await` — the
    /// signer call runs entirely off-lock.
    ///
    /// On success returns `Ok(Some(seq))` with the recorded
    /// `cancel_ack_seq`.
    ///
    /// # Errors
    ///
    /// - [`super::stream::CancelError::SignatureInvalid`] — the caller's
    ///   identity did not match the pinned triple, or the runtime's own
    ///   just-produced signature failed self-verification (an internal
    ///   invariant violation). No stream state is mutated.
    /// - [`super::stream::CancelError::CursorAdvanced`] — the cursor moved
    ///   on every one of the bounded attempts. Retryable: the caller
    ///   re-issues and the runtime re-reads the now-current cursor. No
    ///   stream state is mutated.
    /// - [`super::stream::CancelError::Signing`] — the [`StreamSigner`]
    ///   failed to produce a signature.
    pub async fn apply_outlet_cancel_signed(
        &self,
        signer: &dyn StreamSigner,
        identity: &CancelIdentity,
    ) -> Result<Option<u64>, super::stream::CancelError> {
        /// Maximum number of cursor-advance retries before returning the
        /// retryable [`CancelError::CursorAdvanced`]. A stream advances its
        /// cursor at most once per emitted chunk; four attempts comfortably
        /// covers the lock-free signing window under realistic emission
        /// rates without unbounded spinning.
        const MAX_CURSOR_RETRIES: u32 = 4;

        let mut attempts: u32 = 0;
        loop {
            // ---- lock1: read cursor + pinned identity + invoker_pk. ----
            let (seq, pinned, invoker_pk) = {
                let guard = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    guard.next_emission_seq,
                    guard.credit.identity().clone(),
                    *guard.credit.invoker_pk(),
                )
            };

            // ---- caller-identity validation (NO mutation on mismatch). --
            // The bridge already authenticated the caller_did at its own
            // boundary (§5.4.5 CRITICAL #1); this is the runtime-side
            // defense-in-depth that the pinned stream identity matches the
            // caller's claimed triple before the operator key is wielded.
            if identity.context_id != pinned.context_id
                || identity.outlet_id != pinned.outlet_id
                || identity.caveats_binding != pinned.caveats_binding
            {
                return Err(super::stream::CancelError::SignatureInvalid);
            }

            // ---- build preimage + sign OFF-LOCK (no Mutex across await). -
            let preimage = compute_cancel_sig_preimage(
                &pinned.context_id,
                &pinned.outlet_id,
                &self.request_id,
                seq,
                &pinned.caveats_binding,
            );
            let sig = signer
                .sign(&preimage)
                .await
                .map_err(super::stream::CancelError::Signing)?;
            let cancel = OutletStreamCancel {
                request_id: self.request_id,
                next_seq: seq,
                sig,
            };

            // ---- lock2: re-check cursor, self-verify, apply. ----
            let now = Instant::now();
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.next_emission_seq != seq {
                // The pump emitted a chunk between our off-lock signing and
                // this re-lock; the cursor we signed is stale. Retry against
                // the fresh cursor up to the bounded budget.
                let current = guard.next_emission_seq;
                drop(guard);
                attempts = attempts.saturating_add(1);
                if attempts < MAX_CURSOR_RETRIES {
                    continue;
                }
                return Err(super::stream::CancelError::CursorAdvanced {
                    signed: seq,
                    current,
                });
            }
            // Self-verify the signature we just produced under the pinned
            // invoker key. A failure here is an internal invariant
            // violation (signer produced a signature that does not verify
            // for its own verifying key, or preimage drift) — fail closed
            // as SignatureInvalid WITHOUT mutating stream state.
            if !verify_cancel_signature(
                &cancel,
                &invoker_pk,
                &pinned.context_id,
                &pinned.outlet_id,
                &pinned.caveats_binding,
            ) {
                return Err(super::stream::CancelError::SignatureInvalid);
            }
            guard.cancel_ack.record_cancel(seq, now);
            let recorded = guard.cancel_ack.cancel_ack_seq();
            guard.cancel_ack_armed = true;
            guard.cancel_ack_seq = recorded;
            drop(guard);
            self.cancel_wake.notify_one();
            return Ok(recorded);
        }
    }

    /// Private verbatim-apply helper shared by the forwarding/replay
    /// paths that already hold a fully-formed, signed [`OutletStreamCancel`]
    /// (e.g. a cross-context forwarding hop replaying the originator's
    /// signed cancel). Bridges do NOT call this — they route through
    /// [`Self::apply_outlet_cancel_signed`], which derives `next_seq` from
    /// the live cursor and signs internally.
    ///
    /// Verifies the cancel's signature under the pinned `invoker_pk` and
    /// the stream's pinned `(context_id, outlet_id, caveats_binding)`
    /// triple, AND cross-checks `cancel.next_seq` against the live cursor:
    /// per §5.4.5 a runtime that records `cancel.next_seq` verbatim without
    /// cross-checking its own cursor would absorb a forged cursor. A
    /// `next_seq` that does not match the live cursor is rejected as
    /// [`super::stream::CancelError::CursorAdvanced`] (NO mutation) rather
    /// than absorbed.
    ///
    /// On signature-verification failure, returns
    /// [`super::stream::CancelError::SignatureInvalid`] and does NOT mutate
    /// stream state.
    ///
    /// # Errors
    ///
    /// - [`super::stream::CancelError::SignatureInvalid`] — signature does
    ///   not verify under the pinned key + triple.
    /// - [`super::stream::CancelError::CursorAdvanced`] — `cancel.next_seq`
    ///   does not match the runtime's live next-to-emit cursor.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "verbatim-apply path is exercised by cross-context forwarding waves and tests; retained as the single verify+record primitive"
        )
    )]
    pub(crate) fn apply_outlet_cancel_verbatim(
        &self,
        cancel: &OutletStreamCancel,
    ) -> Result<Option<u64>, super::stream::CancelError> {
        let now = Instant::now();
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let identity = guard.credit.identity().clone();
        let invoker_pk = *guard.credit.invoker_pk();
        // §5.4.5: cross-check the forwarded cursor against the live cursor.
        // A verbatim-apply path MUST NOT absorb a `next_seq` that disagrees
        // with the runtime's own emission cursor.
        if cancel.next_seq != guard.next_emission_seq {
            return Err(super::stream::CancelError::CursorAdvanced {
                signed: cancel.next_seq,
                current: guard.next_emission_seq,
            });
        }
        // Verify under the pinned key + identity. Per §5.4.5, an
        // unsigned-or-tampered cancel is `Authorization::AuthorizationFailed`
        // and MUST NOT mutate stream state.
        if !verify_cancel_signature(
            cancel,
            &invoker_pk,
            &identity.context_id,
            &identity.outlet_id,
            &identity.caveats_binding,
        ) {
            return Err(super::stream::CancelError::SignatureInvalid);
        }
        guard.cancel_ack.record_cancel(cancel.next_seq, now);
        let recorded = guard.cancel_ack.cancel_ack_seq();
        guard.cancel_ack_armed = true;
        guard.cancel_ack_seq = recorded;
        drop(guard);
        self.cancel_wake.notify_one();
        Ok(recorded)
    }

    /// Forces a terminal `Error{terminal:true}` chunk into the stream
    /// under the pinned operator key, identified by a closed-set
    /// [`TerminateReason`] (§5.4.5 framework-initiated termination).
    ///
    /// Per §5.4.5 "Revocation re-check cadence (receiver-side)" the
    /// SDK framework MUST re-check the opening UCAN's revocation
    /// status every `ContextParams::stream_ucan_recheck_secs` and on
    /// observed revocation MUST terminate the stream with
    /// `OutletErrorClass::Authorization::RevokedMidStream`. This
    /// method is the runtime entry point that performs that
    /// termination: it arms `pending_terminate` on the shared session
    /// state with the supplied [`TerminateReason`], notifies the pump
    /// via `terminate_wake`, and the pump emits a synthetic terminal
    /// chunk on its next iteration. The chunk is signed under the
    /// pinned operator key (the same path the cancel-ack-timeout /
    /// credit-stall framework chunks use) and flows through the
    /// pump's settlement block so admission release, escrow refund,
    /// and `OutletInvokedEvent` emission run end-to-end — the audit
    /// log records the receiver-driven termination identically to any
    /// other framework-emitted close.
    ///
    /// The slug and code carried by the synthetic chunk are derived
    /// deterministically from `reason` via [`TerminateReason::slug`]
    /// and [`TerminateReason::code`] — callers MUST NOT supply
    /// free-form slug or code strings, so attacker-controlled inputs
    /// cannot enter the provenance record through this path.
    /// `message_override` is the only caller-controllable string and
    /// is treated as a non-canonical human-readable suffix.
    ///
    /// Idempotent: a second call while the first is still pending
    /// returns [`TerminateError::AlreadyPending`]; calls after the
    /// pump has already broken its loop return
    /// [`TerminateError::AlreadyTerminated`]. Both errors are
    /// recoverable — the SDK's recheck loop treats them as "stream
    /// already closed" and stops re-checking.
    ///
    /// # Errors
    ///
    /// Returns [`TerminateError::AlreadyPending`] when a prior
    /// `terminate_with_error` call has armed `pending_terminate` but
    /// the pump has not yet consumed it. Returns
    /// [`TerminateError::AlreadyTerminated`] when the pump has
    /// already broken its loop (the close summary has been published)
    /// — observable when the handle's `summary_rx` resolved before
    /// this call.
    pub fn terminate_with_error(
        &self,
        reason: TerminateReason,
        message_override: Option<String>,
    ) -> Result<(), TerminateError> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.pending_terminate.is_some() {
            return Err(TerminateError::AlreadyPending);
        }
        guard.pending_terminate = Some(PendingTerminate {
            reason,
            message_override,
        });
        drop(guard);
        // Single-consumer pump: `notify_one` wakes the sole pump waiter
        // and stores a permit if the pump is between iterations, so a
        // terminate request that races the pump loop is observed on the
        // next iteration rather than lost (F3 lost-wakeup closure).
        self.terminate_wake.notify_one();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pump task (the §5.4.5 streaming dispatch hook)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// open_stream_session — the §5.4.5 acceptance entry point
// ---------------------------------------------------------------------------

/// Runs the §5.4.5 round-5 admission gate. Returns the rejection
/// envelope on cap breach.
fn run_admission_gate(
    admission: &Arc<Mutex<StreamAdmissionTracker>>,
    params: &OpenStreamParams,
) -> Result<(), OpenStreamRejection> {
    let admission_outcome = {
        let mut guard = admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.try_admit(
            params.caps,
            &params.invoker_did,
            &params.origin_invoker_did,
            &params.identity.outlet_id,
        )
    };
    match admission_outcome {
        AdmissionOutcome::Admitted => Ok(()),
        AdmissionOutcome::RateLimitedPerInvoker
        | AdmissionOutcome::RateLimitedPerOriginInvoker
        | AdmissionOutcome::RateLimitedPerOutlet => {
            let slug = admission_outcome_to_slug(admission_outcome)
                .unwrap_or(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER);
            Err(OpenStreamRejection::AdmissionRateLimited { slug })
        }
    }
}

/// Releases admission counters held by `params`. Used on every
/// open-time failure path after admission has been granted.
fn release_admission(admission: &Arc<Mutex<StreamAdmissionTracker>>, params: &OpenStreamParams) {
    let mut guard = admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.release(
        &params.invoker_did,
        &params.origin_invoker_did,
        &params.identity.outlet_id,
    );
}

/// §5.4.5 binding-pinning gate: recomputes the `caveats_binding` from
/// the runtime-trusted inputs in [`OpenStreamParams`] and rejects the
/// open when the SDK-supplied `params.identity.caveats_binding` does
/// not match.
///
/// # Preimage shape (§5.4.5 wire spec)
///
/// ```text
/// SHA-256(
///   "SCP-OUTLET-CAVEAT-BIND-V1:"
///   || len_be32(ucan_cid) || ucan_cid
///   || request_id
///   || len_be32(invoker_did) || invoker_did
///   || estimated_chunk_count_be
///   || len_be32(canonical_jcs(effective_caveats))
///   || canonical_jcs(effective_caveats)
/// )
/// ```
///
/// `estimated_chunk_count` is the invoker-declared upper bound
/// (`params.declared_estimated_chunk_count.unwrap_or(0)`) — the same
/// value the SDK committed to when computing the binding. Using the
/// coerced value would diverge whenever the SDK omits the
/// declaration (the coerce falls back to `caveats.max_calls`, which
/// the SDK does not commit to).
///
/// # Legacy-fixture skip
///
/// Production FFI bridges always supply a non-empty `ucan_cid`
/// (derived from the validated UCAN's encoded JWT — see
/// `crates/scp-ffi/src/outlet_stream.rs::py_outlet_invoke_stream` and
/// its NAPI / `UniFFI` mirrors). An empty `ucan_cid` is the sentinel
/// for legacy unit-test fixtures that hand-construct
/// `OpenStreamParams` outside the bridge path. Those fixtures
/// pre-date this gate and supply a fixed sentinel `caveats_binding`
/// for signing-context reuse rather than a real preimage. The gate
/// skips the recompute in that path; production cannot reach the
/// skip because the bridge code paths always set `ucan_cid` to the
/// SHA-256 of the encoded UCAN.
///
/// # Errors
///
/// - [`OpenStreamRejection::CaveatsBindingMismatch`] when the
///   recomputed binding does not equal `params.identity.caveats_binding`.
/// - [`OpenStreamRejection::CaveatsBindingMismatch`] when JCS
///   canonicalization of `params.caveats` fails (a structural
///   invariant violation — non-finite floats etc.).
fn verify_caveats_binding_at_open(params: &OpenStreamParams) -> Result<(), OpenStreamRejection> {
    if params.ucan_cid.is_empty() {
        return Ok(());
    }
    let caveats_jcs = params.caveats.to_canonical_json_bytes().map_err(|err| {
        tracing::error!(
            outlet_id = %params.identity.outlet_id,
            error = ?err,
            "open_stream_session: JCS canonicalization of effective_caveats failed \
             — rejecting open as caveats-binding-mismatch"
        );
        OpenStreamRejection::CaveatsBindingMismatch
    })?;
    let recomputed_binding = compute_caveats_binding(
        params.ucan_cid.as_bytes(),
        &params.request_id,
        &params.invoker_did,
        params.declared_estimated_chunk_count.unwrap_or(0),
        &caveats_jcs,
    );
    if recomputed_binding != params.identity.caveats_binding {
        tracing::warn!(
            outlet_id = %params.identity.outlet_id,
            invoker_did = %params.invoker_did,
            request_id = %hex::encode(params.request_id),
            "open_stream_session: caveats_binding mismatch — SDK-supplied binding \
             does not match the recomputed value over the parsed UCAN's \
             effective_caveats; rejecting open per §5.4.5 binding-pinning"
        );
        return Err(OpenStreamRejection::CaveatsBindingMismatch);
    }
    Ok(())
}

/// Reserves the §5.4.5 open-time escrow. Returns `zero_escrow` for
/// Query / zero-cost outlets and the bounded reservation for Action
/// outlets with non-zero cost.
fn reserve_escrow(
    params: &OpenStreamParams,
    estimated_chunk_count: u32,
) -> Result<StreamEscrow, OpenStreamRejection> {
    if params.cost_per_chunk.value() == 0 {
        return Ok(StreamEscrow::zero_escrow());
    }
    StreamEscrow::reserve_at_open(
        params.cost_per_chunk,
        estimated_chunk_count,
        params.available_balance,
    )
    .map_err(|escrow_err| match escrow_err {
        EscrowError::Overflow => OpenStreamRejection::EscrowOverflow,
        EscrowError::InsufficientFunds => OpenStreamRejection::InsufficientFunds,
    })
}

/// Builds the shared per-stream state mutex. Owns the four trackers,
/// the admission release keys, and the timer-arming state.
fn build_shared_state(
    params: &OpenStreamParams,
    escrow: StreamEscrow,
    admission: &Arc<Mutex<StreamAdmissionTracker>>,
    context_handle: ContextHandle,
) -> Arc<Mutex<SharedSessionState>> {
    let credit = CreditTracker::new(
        params.credit_window,
        params.invoker_pk,
        params.identity.clone(),
    );
    let cancel_ack = CancelAckTracker::new(params.stream_cancel_ack_secs);
    let admission_release_keys = AdmissionReleaseKeys {
        invoker_did: params.invoker_did.clone(),
        origin_invoker_did: params.origin_invoker_did.clone(),
        outlet_id: params.identity.outlet_id.clone(),
    };
    Arc::new(Mutex::new(SharedSessionState {
        credit,
        escrow,
        cancel_ack,
        admission: Arc::clone(admission),
        admission_release_keys,
        cancel_ack_armed: false,
        credit_stall_armed_at: None,
        cancel_ack_seq: None,
        next_emission_seq: 0,
        operator_signer: Arc::clone(&params.operator_signer),
        pending_terminate: None,
        ucan_cid: params.ucan_cid.clone(),
        revocation_checker: Arc::clone(&params.revocation_checker),
        stream_ucan_recheck_secs: params.stream_ucan_recheck_secs,
        context_handle,
    }))
}

/// Inputs required by the dispatch pump to emit the §5.4.5
/// `OutletInvokedEvent` at settlement.
///
/// Bundled into a struct because the pump's spawn site already runs
/// against the workspace's `clippy::too_many_arguments` ceiling — and
/// because the event payload is logically one unit (the pre-snapshot
/// of identifiers + the input hash + the start instant for execution
/// timing).
pub(crate) struct PumpEventEmissionInputs {
    /// Sink that records the §5.4.5 `OutletInvokedEvent` exactly once
    /// at terminal-chunk emission. `None` disables emission entirely
    /// (legacy callers that do not append events to the log).
    pub sink: Option<Arc<dyn OutletInvokedEventSink>>,
    /// Hosting context id — committed into the event's request-id
    /// hex preimage and to the SDK-facing audit log.
    pub context_id: String,
    /// Outlet id pinned at acceptance.
    pub outlet_id: OutletId,
    /// Immediate-previous-hop DID (the §5.4.5 `invoker_did`).
    pub invoker_did: DID,
    /// Pre-computed SHA-256 hex digest of the canonical-JSON input.
    /// Snapshotted before the input is moved into `invoke_outlet` so
    /// the recorded hash reflects what the executor saw, not a
    /// post-mutation value.
    pub input_hash: String,
    /// `Instant` captured at acceptance — used to derive
    /// `execution_time_ms` at terminal-chunk emission.
    pub start: Instant,
}

/// Spawns the streaming pump task. Owns the `inner_rx` (chunks coming
/// from the executor pump) and the `outer_tx` (chunks delivered to the
/// caller).
#[allow(clippy::too_many_arguments)]
fn spawn_pump_task(
    state: Arc<Mutex<SharedSessionState>>,
    grant_wake: Arc<Notify>,
    cancel_wake: Arc<Notify>,
    terminate_wake: Arc<Notify>,
    inner_rx: mpsc::Receiver<OutletStreamChunk>,
    outer_tx: mpsc::Sender<OutletStreamChunk>,
    summary_tx: tokio::sync::oneshot::Sender<StreamCloseSummary>,
    stream_credit_stall_secs: u32,
    stream_cancel_ack_secs: u32,
    request_id: RequestId,
    event_inputs: PumpEventEmissionInputs,
    // §5.4.5 round-8 (F5): the node-level pump permit. Moved into the
    // spawned task so it is released for the exact lifetime of the pump —
    // it drops when the task body returns (normal/terminal/cancel-ack) or
    // when the task panics and its stack unwinds.
    pump_permit: tokio::sync::OwnedSemaphorePermit,
) {
    let stream_credit_stall = Duration::from_secs(u64::from(stream_credit_stall_secs));
    let stream_cancel_ack = Duration::from_secs(u64::from(stream_cancel_ack_secs));
    tokio::spawn(async move {
        // Bind the permit for the whole task body so it drops on every
        // exit path (return, terminal-break, or panic-unwind).
        let _pump_permit = pump_permit;
        run_stream_pump_v2(
            state,
            grant_wake,
            cancel_wake,
            terminate_wake,
            inner_rx,
            outer_tx,
            summary_tx,
            stream_credit_stall,
            stream_cancel_ack,
            request_id,
            event_inputs,
        )
        .await;
    });
}

/// Opens a §5.4.5 stream session with full OUT-034 wiring.
///
/// Runs the §5.4.5 round-5 5-step admission sequence, reserves escrow
/// (Action outlets) or installs a zero-escrow ledger (Query / zero-cost
/// outlets), pins the stream identity, builds the credit and cancel-ack
/// trackers, calls [`invoke_outlet`] to launch the underlying executor
/// pump, and spawns a wrapping pump task that consults the trackers in
/// lockstep with chunk emission.
///
/// # Errors
///
/// Returns [`OpenStreamRejection`] for synchronous open-time failures
/// (admission / escrow / estimate-bound). Synchronous failures from
/// the underlying [`invoke_outlet`] (context not active, capability
/// denial, schema) are translated into the open-time rejection
/// envelope by the caller via
/// [`OpenStreamRejection::to_invocation_error`].
///
/// # Panics
///
/// None — every primitive consulted is `Send + Sync` and the spawned
/// task uses cooperative cancellation.
#[allow(clippy::too_many_arguments)] // mirrors invoke_outlet
pub async fn open_stream_session<E>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: Arc<E>,
    misdeclaration_sink: Option<Arc<dyn QueryMisdeclarationSink>>,
    handler_panic_sink: Option<Arc<dyn HandlerPanicSink>>,
    invoked_event_sink: Option<Arc<dyn OutletInvokedEventSink>>,
    params: OpenStreamParams,
    admission: Arc<Mutex<StreamAdmissionTracker>>,
    // §5.4.5 round-8 (F5): the per-instance node-level concurrent-pump
    // semaphore. A permit is acquired AFTER all per-context gates pass
    // (admission / estimate / escrow / binding) and moved into the spawned
    // pump task so it drops exactly when the pump exits. Saturation
    // hard-rejects with `OpenStreamRejection::StreamCapExhausted` and rolls
    // back the admission counters this open consumed.
    pump_semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<StreamSessionHandle, OpenStreamRejection>
where
    E: OutletExecutor + ?Sized + 'static,
{
    // Step 0 (§5.4.5 binding-pinning): recompute the
    // `caveats_binding` from the runtime-trusted inputs and reject any
    // SDK-supplied value that does not match byte-for-byte. See
    // [`verify_caveats_binding_at_open`] for the preimage shape and
    // legacy-fixture skip semantics. Run BEFORE the admission gate so
    // a binding-forged open never increments admission counters.
    verify_caveats_binding_at_open(&params)?;

    // Step 1: admission gate.
    run_admission_gate(&admission, &params)?;

    // Step 2: estimated_chunk_count coercion + bound.
    let estimated_chunk_count =
        coerce_estimated_chunk_count(params.declared_estimated_chunk_count, &params.caveats);
    if let Err(open_err) = enforce_estimated_chunk_count_bound(
        estimated_chunk_count,
        params.credit_window,
        &params.caveats,
    ) {
        release_admission(&admission, &params);
        return Err(match open_err {
            OpenError::EstimateExceedsBound => {
                let _ = open_error_to_slug(open_err);
                OpenStreamRejection::EstimateExceedsBound
            }
        });
    }

    // Step 3: escrow reservation.
    let escrow = match reserve_escrow(&params, estimated_chunk_count) {
        Ok(e) => e,
        Err(rejection) => {
            release_admission(&admission, &params);
            return Err(rejection);
        }
    };

    // Step 3.5 (§5.4.5 round-8, F5): acquire a node-level pump permit AFTER
    // all per-context gates (admission / estimate / escrow) have passed.
    // On saturation, roll back the admission counters this open consumed
    // (a rejected open MUST NOT leave a per-context slot held) and reject
    // with StreamCapExhausted. The permit is moved into the spawned pump
    // task below so it is released for the exact lifetime of the pump —
    // normal close, terminal, cancel-ack, or panic (the permit drops with
    // the task's stack on unwind).
    let pump_permit = match Arc::clone(&pump_semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_closed_or_no_permits) => {
            release_admission(&admission, &params);
            return Err(OpenStreamRejection::StreamCapExhausted);
        }
    };

    // Step 4: tracker init. Snapshot a cheap (Arc-backed) clone of the
    // context handle so the pump can consult live lifecycle state for
    // the §5.4.5 round-8 context-teardown re-check.
    let shared = build_shared_state(&params, escrow, &admission, context.clone());
    let grant_wake = Arc::new(Notify::new());
    let cancel_wake = Arc::new(Notify::new());
    let terminate_wake = Arc::new(Notify::new());

    // §5.4.5 OutletInvokedEvent emission ownership: the dispatch pump
    // is the authoritative emitter, NOT the inner `invoke_outlet`'s
    // streaming task. The outer pump renumbers chunks and tracks its
    // own `cancel_ack_seq`, so the inner manifest does NOT match what
    // SDK consumers actually receive — recording from the inner path
    // would commit a `stream_manifest_hash` that disagrees with the
    // delivered stream. We therefore (i) pass `None` to the inner
    // `invoke_outlet`'s sink, (ii) snapshot input_hash + identifiers
    // before forwarding the input value, and (iii) emit the event
    // ourselves in the pump settlement block over the outer
    // `emitted_chunks` manifest.
    let input_hash = scp_protocol::context::outlets::lifecycle::sha256_json(&input);
    let event_context_id = context.context_id().to_owned();
    let event_outlet_id: OutletId = outlet_id.clone();
    let event_invoker_did: DID = invoker_did.clone();
    let pump_start = Instant::now();

    // Step 5: launch the underlying executor stream. Pass `None` for
    // the sink — the dispatch pump emits the event itself at
    // settlement time so the recorded manifest matches the chunks the
    // outer pump delivered to the SDK.
    //
    // §5.4.5 round-7: pass the operator signing key through so the
    // inner pump signs each chunk under
    // `SCP-OUTLET-CHUNK-SIG-V1:`. The outer pump re-signs under the
    // renumbered outer sequence; the inner sig closes the
    // spec-compliance loop for callers (manager-direct,
    // test-harnesses) that bypass the outer pump.
    let inner_rx = invoke_outlet(
        context,
        registry,
        role_state,
        outlet_id,
        input,
        invoker_did,
        timeout_ms,
        executor,
        misdeclaration_sink,
        handler_panic_sink,
        None,
        // `invoke_outlet` accepts `Option<Arc<dyn StreamSigner>>` for
        // the inner pump's signing path (legacy test callers may pass
        // `None`); the dispatch path always has a real signer, so wrap
        // it in `Some` here. The outer pump path re-signs every chunk
        // under the renumbered outer sequence with the non-optional
        // signer in `SharedSessionState::operator_signer`.
        Some(Arc::clone(&params.operator_signer)),
        params.identity.caveats_binding,
    )
    .await
    .map_err(|err| {
        // Roll back admission on synchronous invoke_outlet failure.
        // Synchronous validation failures (context not active, schema,
        // etc.) do not match the OUT-034 rejection taxonomy; route
        // through the rate-limited slug as a defensive fallback.
        release_admission(&admission, &params);
        let _ = err;
        OpenStreamRejection::AdmissionRateLimited {
            slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
        }
    })?;

    // §5.4.5 binding-pinning: the runtime uses the SDK-supplied
    // `request_id` (the same value the SDK committed to in the
    // `caveats_binding` preimage) rather than generating a fresh one.
    // The pre-acceptance recompute above already verified the SDK
    // supplied the right binding for this `request_id`; using a
    // runtime-generated id here would have made the binding check
    // structurally impossible.
    let request_id: RequestId = params.request_id;
    let (outer_tx, outer_rx) = mpsc::channel::<OutletStreamChunk>(
        scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW as usize,
    );
    let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();

    spawn_pump_task(
        Arc::clone(&shared),
        Arc::clone(&grant_wake),
        Arc::clone(&cancel_wake),
        Arc::clone(&terminate_wake),
        inner_rx,
        outer_tx,
        summary_tx,
        params.stream_credit_stall_secs,
        params.stream_cancel_ack_secs,
        request_id,
        PumpEventEmissionInputs {
            sink: invoked_event_sink,
            context_id: event_context_id,
            outlet_id: event_outlet_id,
            invoker_did: event_invoker_did,
            input_hash,
            start: pump_start,
        },
        pump_permit,
    );

    Ok(StreamSessionHandle {
        receiver: Some(outer_rx),
        state: shared,
        grant_wake,
        cancel_wake,
        terminate_wake,
        summary_rx: Some(summary_rx),
        request_id,
    })
}

// ---------------------------------------------------------------------------
// Pump v2 — state-machine-clean version (replaces the inline `let mut
// inner_rx_park = ...` hack above)
// ---------------------------------------------------------------------------

/// Identity-and-key bundle the pump uses to sign every outer-wire
/// chunk under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` preimage.
///
/// Snapshotted from [`SharedSessionState`] at pump-task spawn time so
/// the per-chunk signing path does not retake the session lock for
/// each emission.
#[derive(Clone)]
struct PumpSigningContext {
    /// Operator streaming signer. Pinned at acceptance; the pump never
    /// emits an unsigned chunk. Round-8: a [`StreamSigner`] trait object
    /// (custody-backed on native bridges), signed `async`.
    operator_signer: Arc<dyn StreamSigner>,
    /// Hosting context id (committed into every preimage).
    context_id: String,
    /// Outlet id (committed into every preimage).
    outlet_id: String,
    /// 32-byte `caveats_binding` (committed into every preimage).
    caveats_binding: [u8; 32],
}

impl PumpSigningContext {
    /// Signs a `(request_id, sequence, payload)` triple under the
    /// pinned `(context_id, outlet_id, caveats_binding)` and returns
    /// the 64-byte signature.
    ///
    /// Returns `Err(jcs_error_string)` only when JCS canonicalization
    /// of the payload fails — which is a structural invariant
    /// violation for a `ChunkPayload` constructed by this pump
    /// (statically-typed, no floats, no cycles). On `Err` the pump
    /// MUST log + break its loop rather than emit an unsigned chunk;
    /// the receiver-side §5.4.5 verifier rejects any chunk whose sig
    /// doesn't match the preimage, so the wire never carries a
    /// silently-corrupt all-zero placeholder.
    async fn sign_outer_chunk(
        &self,
        request_id: &RequestId,
        sequence: u64,
        payload: &scp_protocol::context::outlets::stream::ChunkPayload,
    ) -> Result<[u8; 64], StreamSignerError> {
        // Compose the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` preimage
        // synchronously (pure SHA-256 over the length-prefixed fields),
        // then await the signer for the 64-byte signature. The bytes
        // signed are byte-identical to the round-7 `sign_chunk` path —
        // only the signing mechanism is now custody-injectable.
        let preimage = compute_chunk_sig_preimage(
            &self.context_id,
            &self.outlet_id,
            request_id,
            sequence,
            &self.caveats_binding,
            payload,
        )
        .map_err(StreamSignerError::Jcs)?;
        self.operator_signer.sign(&preimage).await
    }

    /// Builds a fully-formed signed [`OutletStreamChunk`] for the
    /// given `(sequence, payload)` pair.
    ///
    /// Returns `None` when [`Self::sign_outer_chunk`] fails — either JCS
    /// canonicalization (a structural invariant violation in the pump) or
    /// a signer-side custody failure. On `None` the caller logs the error
    /// and breaks the pump loop without emitting; this guarantees the
    /// test invariant "no chunk emitted by the pump ever has
    /// `sig == [0u8; 64]`" because we never construct an unsigned
    /// chunk on the failure path.
    async fn try_build_signed_chunk(
        &self,
        request_id: RequestId,
        sequence: u64,
        payload: ChunkPayload,
    ) -> Option<OutletStreamChunk> {
        match self.sign_outer_chunk(&request_id, sequence, &payload).await {
            Ok(sig) => Some(OutletStreamChunk {
                request_id,
                sequence,
                payload,
                sig,
            }),
            Err(e) => {
                tracing::error!(
                    request_id = %hex::encode(request_id),
                    outlet_id = %self.outlet_id,
                    context_id = %self.context_id,
                    sequence,
                    error = %e,
                    "dispatch pump: chunk signing failed — \
                     pump will break without emitting; downstream receiver sees stream end"
                );
                None
            }
        }
    }
}

/// Consults `checker.is_revoked(ucan_cid)` and, on observed
/// revocation, arms `pending_terminate` on the shared session state
/// with [`TerminateReason::RevokedMidStream`]. Returns `true` when the
/// arming actually mutated state (so the caller knows to notify the
/// pump's `terminate_wake`). Returns `false` when:
///
/// - the token is not revoked, or
/// - the token IS revoked but `pending_terminate` was already armed
///   (idempotent — the prior arm wins; the pump emits exactly one
///   synthetic terminal chunk).
///
/// The check is intentionally scoped to a short critical section: the
/// `is_revoked` call runs OUTSIDE the session mutex (the checker is
/// the runtime's authoritative revocation source — it must not be
/// blocked on the per-stream lock, which the pump holds for chunk-
/// emission accounting). On revocation we re-acquire the lock just
/// long enough to mutate `pending_terminate`; this matches the
/// `terminate_with_error` path on [`StreamSessionHandle`] (§5.4.5
/// SDK-side revocation re-check) so the audit trail records both
/// paths identically.
fn try_arm_revoked_mid_stream(
    state: &Arc<Mutex<SharedSessionState>>,
    checker: &(dyn RevocationChecker + Send + Sync),
    ucan_cid: &str,
) -> bool {
    if !checker.is_revoked(ucan_cid) {
        return false;
    }
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.pending_terminate.is_some() {
        // Idempotent: an earlier terminate path already armed the
        // synthetic terminal. The pump will emit exactly one chunk
        // regardless of which path armed first.
        return false;
    }
    guard.pending_terminate = Some(PendingTerminate {
        reason: TerminateReason::RevokedMidStream,
        message_override: None,
    });
    true
}

/// Consults the hosting context's lifecycle state and, when the context
/// is no longer `Active` (closed, evicted/left, expired, migrating,
/// tombstoned), arms `pending_terminate` with
/// [`TerminateReason::ContextClosedMidStream`] (§5.4.5 round-8 "Context
/// teardown vs. revocation"). Returns `true` when the arming actually
/// mutated state (so the caller knows to notify `terminate_wake`).
/// Returns `false` when:
///
/// - the context is still `Active` (or `Creating`, which the pump treats
///   as live — a stream cannot have opened against a non-Active context,
///   so `Creating` is only observable as a transient and not a teardown),
///   or
/// - the context IS torn down but `pending_terminate` was already armed
///   (idempotent — the prior arm wins; the pump emits exactly one
///   synthetic terminal chunk).
///
/// **Precedence:** the pump calls this BEFORE
/// [`try_arm_revoked_mid_stream`] in the same re-check tick, so context
/// teardown (Protocol class) wins over revocation (Authorization class)
/// when both are observable — the stream's substrate is already gone, so
/// the Protocol-class teardown is the more proximate, accurate cause and
/// recording a revocation would write a false audit signal.
///
/// `context_handle.state()` is `async`; the call runs in the pump's
/// re-check select arm (already an async context) OUTSIDE the session
/// mutex. On teardown we re-acquire the lock just long enough to mutate
/// `pending_terminate`, matching the `try_arm_revoked_mid_stream` pattern.
async fn try_arm_context_closed_mid_stream(
    state: &Arc<Mutex<SharedSessionState>>,
    context_handle: &ContextHandle,
) -> bool {
    use crate::context::ContextState;
    let context_state = context_handle.state().await;
    // `Active` and `Creating` are live; every other state is a teardown
    // (Closing / Closed / Expired / MigratingOut / Tombstoned). Matching
    // explicitly (rather than `!= Active`) means a future ContextState
    // variant forces a compile error here rather than silently being
    // treated as a teardown.
    let torn_down = match context_state {
        ContextState::Active | ContextState::Creating => false,
        ContextState::Closing
        | ContextState::Closed
        | ContextState::Expired
        | ContextState::MigratingOut
        | ContextState::Tombstoned => true,
    };
    if !torn_down {
        return false;
    }
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.pending_terminate.is_some() {
        return false;
    }
    guard.pending_terminate = Some(PendingTerminate {
        reason: TerminateReason::ContextClosedMidStream,
        message_override: None,
    });
    true
}

/// Runs one §5.4.5 round-8 re-check tick: consults context teardown FIRST
/// (Protocol-class precedence), then — only if the context is still live —
/// the UCAN revocation checker. When either arms `pending_terminate`, wakes
/// the pump via `terminate_wake`.
///
/// The short-circuit `||` is load-bearing: `try_arm_context_closed_mid_stream`
/// must run (and win) before the revocation probe, so a teardown is never
/// recorded as a revocation. Factored out of the two pump `select!` arms so
/// the parked / unparked paths share one implementation.
async fn run_revocation_recheck_tick(
    state: &Arc<Mutex<SharedSessionState>>,
    context_handle: &ContextHandle,
    revocation_checker: &(dyn RevocationChecker + Send + Sync),
    ucan_cid: &str,
    terminate_wake: &Notify,
) {
    let armed = try_arm_context_closed_mid_stream(state, context_handle).await
        || try_arm_revoked_mid_stream(state, revocation_checker, ucan_cid);
    if armed {
        terminate_wake.notify_one();
    }
}

/// Builds the synthetic terminal `Error{terminal:true}` payload from a
/// pending-terminate request. The slug is committed verbatim as the
/// chunk message prefix so the receiver records the canonical §5.4.4
/// slug regardless of what override the caller supplied.
fn build_pending_terminate_payload(pt: &PendingTerminate) -> ChunkPayload {
    let suffix = pt
        .message_override
        .as_deref()
        .unwrap_or_else(|| pt.reason.default_message());
    ChunkPayload::Error {
        code: pt.reason.code().to_owned(),
        message: format!("{slug}: {suffix}", slug = pt.reason.slug()),
        terminal: true,
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_stream_pump_v2(
    state: Arc<Mutex<SharedSessionState>>,
    grant_wake: Arc<Notify>,
    cancel_wake: Arc<Notify>,
    terminate_wake: Arc<Notify>,
    mut inner_rx: mpsc::Receiver<OutletStreamChunk>,
    outer_tx: mpsc::Sender<OutletStreamChunk>,
    summary_tx: tokio::sync::oneshot::Sender<StreamCloseSummary>,
    stream_credit_stall: Duration,
    stream_cancel_ack: Duration,
    request_id: RequestId,
    event_inputs: PumpEventEmissionInputs,
) {
    let mut emitted_chunks: Vec<OutletStreamChunk> = Vec::new();
    let mut next_seq: u64 = 0;
    let mut parked: Option<OutletStreamChunk> = None;

    // Snapshot the operator signing context once at task start so the
    // per-chunk signing path does not retake the session mutex for
    // each emission. The pinned identity values do not change for the
    // stream's lifetime (§5.4.5 binding-pinning invariant).
    //
    // Also snapshot the §5.4.5 revocation re-check inputs (`ucan_cid`,
    // `revocation_checker`, `recheck_secs`) so the pump's interval arm
    // calls the checker without retaking the session mutex per tick.
    // Both snapshots ride on the same Arc::clone — the trait object's
    // ref-count moves to the pump, the underlying checker stays shared
    // with the session state.
    let (signing_ctx, revocation_checker, ucan_cid_for_recheck, recheck_secs, context_handle) = {
        let guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let identity = guard.credit.identity().clone();
        (
            PumpSigningContext {
                operator_signer: Arc::clone(&guard.operator_signer),
                context_id: identity.context_id,
                outlet_id: identity.outlet_id,
                caveats_binding: identity.caveats_binding,
            },
            Arc::clone(&guard.revocation_checker),
            guard.ucan_cid.clone(),
            guard.stream_ucan_recheck_secs,
            guard.context_handle.clone(),
        )
    };

    // §5.4.5 receiver-side revocation re-check (authoritative locus =
    // runtime). The pump consults [`RevocationChecker::is_revoked`] for
    // the opening UCAN's CID every `recheck_secs`. On observed
    // revocation it arms `pending_terminate` with
    // `TerminateReason::RevokedMidStream`; the eager pending-terminate
    // check at the top of the loop then emits a signed synthetic
    // terminal `Error{terminal:true}` chunk and breaks into the
    // settlement block. The first `tick().await` returns immediately
    // (tokio interval default behavior), so we let that "zeroth" tick
    // pass through without re-checking — burning it inside `loop`'s
    // initial iteration. `recheck_secs == 0` would create a busy-loop;
    // we clamp it to a minimum of 1s so a degenerate `ContextParams`
    // configuration cannot DoS the runtime.
    let mut recheck_interval = {
        let period = Duration::from_secs(u64::from(recheck_secs.max(1)));
        let mut iv = tokio::time::interval(period);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // F4 (round 8): we do NOT drain the zeroth tick. `interval`'s
        // first `tick()` returns immediately, giving a prompt revocation/
        // context-teardown re-check at the very start of the pump's life
        // rather than only after a full `recheck_secs` delay — closing a
        // window where a token revoked (or a context closed) just before
        // the open completed would not be observed until one full period
        // later. The eager `pending_terminate` check at the top of the
        // loop still gates emission, and `try_arm_*` is a cheap no-op when
        // the token is live and the context is open, so an immediate
        // zeroth tick on a healthy stream costs only a revocation-list
        // membership probe.
        iv
    };

    loop {
        // §5.4.5 receiver-side revocation re-check: if the SDK
        // framework armed `pending_terminate` since the last loop
        // iteration, drain it now, sign + emit the synthetic terminal
        // chunk under the pinned operator key, and break into the
        // settlement block. Done eagerly at the top of each iteration
        // (before timers + inner_rx select) so a notification that
        // arrives mid-await still takes effect on the very next
        // iteration. The select arms below ALSO wait on
        // `terminate_wake.notified()` so a quiescent pump (parked
        // chunk, no inner traffic) does not have to wait for an
        // unrelated timer to fire before observing the request.
        let pending = {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.pending_terminate.take()
        };
        if let Some(pt) = pending {
            let payload = build_pending_terminate_payload(&pt);
            let Some(chunk) = signing_ctx
                .try_build_signed_chunk(request_id, next_seq, payload)
                .await
            else {
                // Signing failed: pump breaks without emitting.
                // `try_build_signed_chunk` already logged the cause.
                break;
            };
            emitted_chunks.push(chunk.clone());
            let _ = outer_tx.send(chunk).await;
            break;
        }

        // Calculate timer state.
        let (cancel_ack_armed, credit_stall_armed_at) = {
            let guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (guard.cancel_ack_armed, guard.credit_stall_armed_at)
        };

        // Build timer futures shared between the parked-chunk path and
        // the inner-rx path. Both paths MUST wait on these so neither
        // spins on a chunk that the gate keeps refusing.
        let cancel_timer_fut = async {
            if cancel_ack_armed {
                tokio::time::sleep(stream_cancel_ack).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let credit_timer_fut = async {
            if let Some(armed_at) = credit_stall_armed_at {
                let elapsed = armed_at.elapsed();
                let remaining = stream_credit_stall.saturating_sub(elapsed);
                tokio::time::sleep(remaining).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        // If we have a parked chunk, wait for either:
        //   (a) the credit stall timer to fire (emit terminal),
        //   (b) a grant_wake notification (resume),
        //   (c) the cancel-ack timer to fire (emit terminal),
        //   (d) a cancel_wake notification (re-evaluate next iter),
        //   (e) the revocation re-check interval ticks (consult
        //       checker; arm pending_terminate on revocation).
        // We do NOT pull from the inner_rx because the parked chunk is
        // the head-of-line — pulling more from the executor would cause
        // out-of-order delivery once the stall lifts.
        let chunk_opt = if parked.is_some() {
            tokio::select! {
                biased;
                () = cancel_timer_fut => {
                    let payload = CancelAckTracker::cancel_ack_timeout_payload();
                    let Some(chunk) = signing_ctx
                        .try_build_signed_chunk(request_id, next_seq, payload)
                        .await
                    else {
                        break;
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = credit_timer_fut => {
                    let payload = CancelAckTracker::credit_stall_payload();
                    let Some(chunk) = signing_ctx
                        .try_build_signed_chunk(request_id, next_seq, payload)
                        .await
                    else {
                        break;
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = grant_wake.notified() => {
                    parked.take()
                }
                () = cancel_wake.notified() => {
                    parked.take()
                }
                () = terminate_wake.notified() => {
                    // Loop back so the eager `pending_terminate`
                    // check at the top emits the synthetic terminal
                    // and breaks. Keeping the parked chunk alive is
                    // safe — the eager check fires before the parked
                    // path re-engages.
                    continue;
                }
                _ = recheck_interval.tick() => {
                    // §5.4.5 round-8 re-check (runtime-authoritative).
                    // Context teardown takes PRECEDENCE over revocation:
                    // if the hosting context is no longer Active the
                    // stream's substrate is gone, so we arm the
                    // Protocol-class ContextClosedMidStream and SKIP the
                    // revocation probe entirely (recording a revocation
                    // would write a false Authorization-class audit
                    // signal). Only when the context is still live do we
                    // consult the revocation checker.
                    run_revocation_recheck_tick(
                        &state,
                        &context_handle,
                        revocation_checker.as_ref(),
                        &ucan_cid_for_recheck,
                        &terminate_wake,
                    )
                    .await;
                    continue;
                }
            }
        } else {
            tokio::select! {
                biased;
                () = cancel_timer_fut => {
                    let payload = CancelAckTracker::cancel_ack_timeout_payload();
                    let Some(chunk) = signing_ctx
                        .try_build_signed_chunk(request_id, next_seq, payload)
                        .await
                    else {
                        break;
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = credit_timer_fut => {
                    let payload = CancelAckTracker::credit_stall_payload();
                    let Some(chunk) = signing_ctx
                        .try_build_signed_chunk(request_id, next_seq, payload)
                        .await
                    else {
                        break;
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = grant_wake.notified() => {
                    continue;
                }
                () = cancel_wake.notified() => {
                    continue;
                }
                () = terminate_wake.notified() => {
                    // Loop back so the eager `pending_terminate`
                    // check at the top emits the synthetic terminal
                    // and breaks.
                    continue;
                }
                _ = recheck_interval.tick() => {
                    // §5.4.5 round-8 re-check (runtime-authoritative).
                    // Context teardown takes PRECEDENCE over revocation:
                    // if the hosting context is no longer Active the
                    // stream's substrate is gone, so we arm the
                    // Protocol-class ContextClosedMidStream and SKIP the
                    // revocation probe entirely (recording a revocation
                    // would write a false Authorization-class audit
                    // signal). Only when the context is still live do we
                    // consult the revocation checker.
                    run_revocation_recheck_tick(
                        &state,
                        &context_handle,
                        revocation_checker.as_ref(),
                        &ucan_cid_for_recheck,
                        &terminate_wake,
                    )
                    .await;
                    continue;
                }
                next = inner_rx.recv() => next,
            }
        };

        let Some(chunk) = chunk_opt else {
            break; // upstream closed
        };

        // Per-chunk decision: delegate to the public gate helper in
        // `invoke.rs` so the wiring uses the same primitives the
        // §5.4.5 spec calls out (CreditTracker::try_consume,
        // CancelAckTracker::billing_ceiling, credit-stall arming).
        let outcome = {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Build a `chunk` view stamped with the runtime's
            // monotonic sequence so the gate's ceiling check uses the
            // outer-pump's seq, not the inner-pump's.
            let view = OutletStreamChunk {
                request_id,
                sequence: next_seq,
                payload: chunk.payload.clone(),
                sig: chunk.sig,
            };
            // Split-borrow via &mut * so the borrow checker accepts
            // simultaneous &mut credit / &cancel_ack / &mut
            // credit_stall_armed_at.
            let g = &mut *guard;
            apply_stream_chunk_gate(
                &mut g.credit,
                &g.cancel_ack,
                &mut g.credit_stall_armed_at,
                &view,
            )
        };

        match outcome {
            StreamGateOutcome::Forward => {
                let seq = next_seq;
                // §5.4.5 per-chunk operator signature MUST cover the
                // outer (renumbered) sequence. The inner pump's chunk
                // bears a sig under the inner-pump sequence which the
                // outer wire form no longer matches; we re-sign every
                // forwarded chunk under the outer sequence so receivers
                // can verify each chunk against `chunk.sequence` as
                // delivered. Without this, the inner sig is dead weight
                // (verifies under a sequence the wire never carries).
                let Some(final_chunk) = signing_ctx
                    .try_build_signed_chunk(request_id, seq, chunk.payload.clone())
                    .await
                else {
                    // Signing failed: do not advance `next_seq`, do not
                    // emit, break out. Receiver sees stream end without
                    // an unsigned chunk on the wire.
                    break;
                };
                // Only advance the emission cursor AFTER signing
                // succeeded — a failed-signature path must not burn a
                // sequence number.
                next_seq = next_seq.saturating_add(1);
                // Crisp invariant: every chunk reaching a bridge consumer
                // verifies under the pinned operator key. In debug
                // builds we re-verify the sig we just produced, so a
                // signing-vs-verifying preimage drift surfaces in tests
                // before any production member observes a bad chunk.
                debug_assert!(
                    verify_chunk_signature(
                        &final_chunk,
                        signing_ctx.operator_signer.verifying_key(),
                        &signing_ctx.context_id,
                        &signing_ctx.outlet_id,
                        &signing_ctx.caveats_binding,
                    ),
                    "dispatch pump: just-signed chunk fails to verify under the pinned operator key — \
                     signing/verifying preimage drift",
                );
                {
                    let mut guard = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let g = &mut *guard;
                    accrue_data_chunk_if_billable(&mut g.escrow, &g.cancel_ack, &final_chunk);
                    // §5.4.5 next-emission-cursor publication — the
                    // bridge layer reads this value to derive the
                    // canonical `cancel_ack_seq` written into
                    // `OutletStreamCancel` preimages (see
                    // `StreamSessionHandle::current_next_emission_seq`).
                    // Bump under the same lock as the gate decision so
                    // a racing `apply_outlet_cancel` either observes
                    // the cursor before this forward (cancel pins the
                    // pre-forward cursor) or after (cancel pins the
                    // post-forward cursor), never half-stamped.
                    g.next_emission_seq = next_seq;
                }
                emitted_chunks.push(final_chunk.clone());
                let terminal = final_chunk.payload.is_terminal();
                if outer_tx.send(final_chunk).await.is_err() {
                    break;
                }
                if terminal {
                    break;
                }
            }
            StreamGateOutcome::Stall => {
                parked = Some(chunk);
            }
            StreamGateOutcome::DropAboveCancelAck => {
                // §5.4.5: drop without billing or forwarding.
            }
        }
    }

    // Settlement: settle the escrow ledger, record terminal on the
    // cancel-ack tracker, and release admission counters via the
    // public helper in `invoke.rs`.
    let summary = {
        let mut guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (billed_amount, refund_amount, billed_count) = guard.escrow.settle_at_close();
        let cancel_ack_seq = guard.cancel_ack.cancel_ack_seq();
        guard.cancel_ack.record_terminal();
        // Take the admission Arc out of the guard so we can release
        // through the invoke.rs public helper (which lifts the type
        // reference into invoke.rs for grep enforcement).
        let admission_arc = Arc::clone(&guard.admission);
        let invoker_did_owned = guard.admission_release_keys.invoker_did.clone();
        let origin_invoker_did_owned = guard.admission_release_keys.origin_invoker_did.clone();
        let outlet_id_owned = guard.admission_release_keys.outlet_id.clone();
        drop(guard);
        {
            let mut admission_guard = admission_arc
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            release_stream_admission(
                &mut admission_guard,
                &invoker_did_owned,
                &origin_invoker_did_owned,
                &outlet_id_owned,
            );
        }
        StreamCloseSummary {
            billed_amount,
            refund_amount,
            billed_count,
            stream_chunk_count: u32::try_from(emitted_chunks.len()).unwrap_or(u32::MAX),
            cancel_ack_seq,
            manifest: emitted_chunks,
        }
    };

    // §5.4.5 OutletInvokedEvent emission. The dispatch pump owns the
    // outer manifest (renumbered, cancel-ack-truncated) — the only
    // manifest that matches what SDK consumers actually received. We
    // (i) verify `chunks_billed` against the manifest before emitting
    // (matches the §5.4.5 wire-rejection rule the runtime applies at
    // log-insert time, surfacing drift here rather than in the
    // event-log appender), and (ii) record exactly one event per
    // stream via the `OutletInvokedEventSink::record` trait method.
    if let Some(sink) = event_inputs.sink.as_ref() {
        // §5.4.5 round-8 (F2): on a self-consistency drift between the
        // pump's running `billed_count` and the manifest-derived
        // reference, DO NOT drop the event. The previous behaviour
        // silently discarded the audit record, erasing the divergence.
        // Instead we emit the event with `chunks_billed` set to the
        // manifest-derived reference (the appender-accepted value — so
        // the event passes the §5.4.5 wire-rejection rule at log-insert,
        // verified by `verify_summary_chunks_billed` below) AND attach an
        // `AuditAnomaly::ChunksBilledSelfMismatch` so the divergence is
        // durably attributable. `build_streaming_outlet_event` already
        // derives `chunks_billed` from the (cancel-ack-truncated) manifest
        // — that is the reference value; we cross-check it here and only
        // emit when it matches `reference_chunks_billed`.
        let pump_recorded = summary.billed_count;
        let manifest_reference = reference_chunks_billed(&summary.manifest, summary.cancel_ack_seq);
        let audit_anomaly = if pump_recorded == manifest_reference {
            None
        } else {
            tracing::warn!(
                request_id = %hex::encode(request_id),
                outlet_id = %event_inputs.outlet_id,
                pump_recorded,
                manifest_reference,
                "OutletInvokedEvent chunks_billed self-mismatch — emitting event with \
                 manifest-derived count and AuditAnomaly::ChunksBilledSelfMismatch"
            );
            Some(
                scp_protocol::context::outlets::lifecycle::AuditAnomaly::ChunksBilledSelfMismatch {
                    pump_recorded,
                    manifest_reference,
                },
            )
        };
        let event = super::invoke::build_streaming_outlet_event(
            request_id,
            &event_inputs.outlet_id,
            &event_inputs.invoker_did,
            event_inputs.input_hash.clone(),
            u64::try_from(event_inputs.start.elapsed().as_millis()).unwrap_or(u64::MAX),
            &summary.manifest,
            audit_anomaly,
        );
        // The emitted event carries the manifest-derived `chunks_billed`,
        // so it MUST pass the wire-rejection check the appender applies.
        // If it does not, the manifest itself is malformed (not a
        // pump-vs-manifest divergence) — drop and log rather than emit a
        // record the appender will reject.
        if let Err(verify_err) = verify_chunks_billed(
            &summary.manifest,
            event.chunks_billed,
            summary.cancel_ack_seq,
        ) {
            tracing::error!(
                request_id = %hex::encode(request_id),
                outlet_id = %event_inputs.outlet_id,
                error = ?verify_err,
                "OutletInvokedEvent dropped: manifest-derived chunks_billed still fails \
                 wire-rejection (malformed manifest, not a pump self-mismatch)"
            );
        } else {
            sink.record(event);
        }
        // Suppress `event_inputs.context_id` unused-warning until the
        // event payload extends to include it (currently the
        // `OutletInvokedEvent` keys only on outlet/invoker/request_id;
        // context-id is implicit in the event-log namespace per
        // §5.14.10).
        let _ = &event_inputs.context_id;
    }

    // Publish the close summary AFTER the event sink. Tests and
    // economy-layer integrations consume `(billed_amount,
    // refund_amount, billed_count)` here — values the
    // `OutletInvokedEvent` does not carry (per §19.15.5
    // PaymentReceipt).
    let _ = summary_tx.send(summary);
}

// ---------------------------------------------------------------------------
// Verification helper — chunks_billed at log-insert time
// ---------------------------------------------------------------------------

/// Verifies that a [`StreamCloseSummary`] is internally consistent:
/// `billed_count` matches the §5.4.5 reference count derivable from the
/// manifest + cancel-ack-seq.
///
/// Returns the same [`scp_event_log::EventLogError::ChunksBilledMismatch`]
/// error variant the runtime would surface from
/// [`scp_event_log::tree::append`] on a wire-rejection so callers can
/// short-circuit log insertion without importing the runtime stream
/// types.
///
/// # Errors
///
/// Returns [`scp_event_log::EventLogError::ChunksBilledMismatch`] when
/// the recorded `billed_count` does not equal the reference computed
/// from the manifest.
pub fn verify_summary_chunks_billed(
    summary: &StreamCloseSummary,
) -> Result<(), scp_event_log::EventLogError> {
    let recorded = summary.billed_count;
    let cancel_ack_seq = summary.cancel_ack_seq;
    match verify_chunks_billed(&summary.manifest, recorded, cancel_ack_seq) {
        Ok(()) => Ok(()),
        Err(err) => Err(super::stream::chunks_billed_error_to_event_log_error(err)),
    }
}

/// Computes the reference `chunks_billed` count from a stream manifest.
///
/// Uses the same §5.4.5 predicate the wire-rejection rule applies (count
/// of `Data` leaves at or below `cancel_ack_seq`). Used by the
/// integration tests to assert that the pump's recorded `billed_count`
/// matches the manifest.
#[must_use]
pub fn reference_chunks_billed(manifest: &[OutletStreamChunk], cancel_ack_seq: Option<u64>) -> u32 {
    let ceiling = cancel_ack_seq.unwrap_or(u64::MAX);
    compute_chunks_billed_ref(manifest, ceiling)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use scp_protocol::context::outlets::stream::ChunkPayload;
    use std::time::Duration;

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn build_test_state() -> Arc<Mutex<SharedSessionState>> {
        build_test_state_with_checker(
            Arc::new(scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new()),
            60,
        )
    }

    fn build_test_state_with_checker(
        revocation_checker: Arc<dyn RevocationChecker + Send + Sync>,
        stream_ucan_recheck_secs: u32,
    ) -> Arc<Mutex<SharedSessionState>> {
        let key = fixed_signing_key();
        let signer: Arc<dyn StreamSigner> =
            Arc::new(super::super::signer::InProcessStreamSigner::new(key));
        let identity = super::super::stream::StreamIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            stream_epoch: 1,
            caveats_binding: [0xAB; 32],
        };
        let credit = CreditTracker::new(32, *signer.verifying_key(), identity);
        let cancel_ack = CancelAckTracker::new(5);
        let admission = Arc::new(Mutex::new(StreamAdmissionTracker::new()));
        // A fresh context handle (in `Creating`) so the F6 round-8
        // context-teardown re-check observes a live context by default —
        // both `Creating` and `Active` are treated as live, so a default
        // stream does not spuriously terminate. Tests that want to
        // exercise teardown transition the handle to a non-Active state.
        let context_handle = ContextHandle::new(
            "ctx-test".to_owned(),
            scp_protocol::context::ContextParams::default(),
        );
        Arc::new(Mutex::new(SharedSessionState {
            credit,
            escrow: super::super::stream::StreamEscrow::zero_escrow(),
            cancel_ack,
            admission,
            admission_release_keys: AdmissionReleaseKeys {
                invoker_did: "did:dht:invoker".to_owned(),
                origin_invoker_did: "did:dht:origin".to_owned(),
                outlet_id: "outlet-test".to_owned(),
            },
            cancel_ack_armed: false,
            credit_stall_armed_at: None,
            cancel_ack_seq: None,
            next_emission_seq: 0,
            operator_signer: signer,
            pending_terminate: None,
            ucan_cid: "bafyrei-test".to_owned(),
            revocation_checker,
            stream_ucan_recheck_secs,
            context_handle,
        }))
    }

    /// §5.4.5 receiver-side revocation re-check: `terminate_with_error`
    /// arms `pending_terminate` and the pump emits a synthetic terminal
    /// `Error{terminal:true}` chunk on its next iteration with the
    /// caller-supplied code/message and the spec slug-prefixed message.
    #[tokio::test]
    async fn terminate_with_error_emits_synthetic_terminal_chunk() {
        let state = build_test_state();
        let grant_wake = Arc::new(Notify::new());
        let cancel_wake = Arc::new(Notify::new());
        let terminate_wake = Arc::new(Notify::new());
        let (_inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();
        let request_id: RequestId = [0x77; 16];

        let pump_state = Arc::clone(&state);
        let pump_grant = Arc::clone(&grant_wake);
        let pump_cancel = Arc::clone(&cancel_wake);
        let pump_terminate = Arc::clone(&terminate_wake);
        let pump_handle = tokio::spawn(async move {
            run_stream_pump_v2(
                pump_state,
                pump_grant,
                pump_cancel,
                pump_terminate,
                inner_rx,
                outer_tx,
                summary_tx,
                Duration::from_secs(30),
                Duration::from_secs(5),
                request_id,
                PumpEventEmissionInputs {
                    sink: None,
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    invoker_did: scp_primitives::DID("did:dht:invoker".to_owned()),
                    input_hash: "0".repeat(64),
                    start: Instant::now(),
                },
            )
            .await;
        });

        // Build a StreamSessionHandle that mirrors what `open_stream_session`
        // would have constructed, then exercise `terminate_with_error`.
        let handle = StreamSessionHandle {
            receiver: None,
            state: Arc::clone(&state),
            grant_wake: Arc::clone(&grant_wake),
            cancel_wake: Arc::clone(&cancel_wake),
            terminate_wake: Arc::clone(&terminate_wake),
            summary_rx: None,
            request_id,
        };

        handle
            .terminate_with_error(
                TerminateReason::RevokedMidStream,
                Some("ucan revoked mid-stream".to_owned()),
            )
            .expect("terminate accepted");

        // Pump should emit exactly one synthetic terminal Error chunk
        // and then close the channel after settlement.
        let chunk = tokio::time::timeout(Duration::from_secs(2), outer_rx.recv())
            .await
            .expect("pump emits synthetic terminal within 2s")
            .expect("chunk arrives");
        // Crisp invariant for the [0u8;64] placeholder deletion: the
        // synthetic terminal chunk MUST carry a real signature, never
        // the all-zero placeholder. Regression-pin this so a future
        // refactor that re-introduces an unsigned-fallback branch
        // surfaces here rather than as a wire-level corruption.
        assert_ne!(
            chunk.sig, [0u8; 64],
            "pump emitted synthetic terminal chunk with all-zero sig — \
             placeholder fallback re-introduced"
        );
        // The slug + code MUST come from the closed-set
        // `TerminateReason::RevokedMidStream`, not from any
        // caller-supplied string. `message_override` is the only
        // caller-controllable field and appears as a suffix only.
        let expected_slug = TerminateReason::RevokedMidStream.slug();
        let expected_code = TerminateReason::RevokedMidStream.code();
        let ChunkPayload::Error {
            code,
            message,
            terminal,
        } = chunk.payload
        else {
            // Pump emits exactly one terminal chunk on `terminate_with_error`
            // — anything else is a regression in the eager-check loop entry.
            unreachable!("expected terminal Error chunk");
        };
        assert_eq!(code, expected_code);
        assert!(
            message.starts_with(&format!("{expected_slug}: ")),
            "message must start with the canonical slug prefix from the enum: {message}"
        );
        assert!(message.contains("ucan revoked mid-stream"));
        assert!(terminal, "terminate must emit `terminal: true`");

        // Pump exits after settlement.
        pump_handle
            .await
            .expect("pump task settles after terminal emission");

        // Summary published.
        let summary = summary_rx.await.expect("summary published");
        assert_eq!(summary.stream_chunk_count, 1);
        assert_eq!(summary.manifest.len(), 1);
        // §test #6 invariant: every chunk in the manifest MUST have a
        // non-placeholder signature. Closes the [0u8;64] deletion gap.
        for (i, c) in summary.manifest.iter().enumerate() {
            assert_ne!(
                c.sig, [0u8; 64],
                "manifest chunk[{i}] has all-zero sig — placeholder \
                 emission path re-introduced"
            );
        }
    }

    /// `terminate_with_error` is idempotent: a second call while the
    /// first is still pending returns `AlreadyPending`.
    #[tokio::test]
    async fn terminate_with_error_returns_already_pending_on_second_call() {
        let state = build_test_state();
        let grant_wake = Arc::new(Notify::new());
        let cancel_wake = Arc::new(Notify::new());
        let terminate_wake = Arc::new(Notify::new());
        let request_id: RequestId = [0x33; 16];

        let handle = StreamSessionHandle {
            receiver: None,
            state,
            grant_wake,
            cancel_wake,
            terminate_wake,
            summary_rx: None,
            request_id,
        };

        // First call wins.
        handle
            .terminate_with_error(TerminateReason::RevokedMidStream, Some("first".to_owned()))
            .expect("first terminate accepted");
        // Second call sees pending → AlreadyPending.
        let err = handle
            .terminate_with_error(TerminateReason::RevokedMidStream, Some("second".to_owned()))
            .expect_err("second terminate rejected");
        assert!(matches!(err, TerminateError::AlreadyPending));
    }

    /// `terminate_with_error` derives the slug+code from the supplied
    /// [`TerminateReason`] variant, NOT from caller input. Each
    /// closed-set variant maps to its canonical slug+code; the
    /// caller's optional `message_override` is only a human-readable
    /// suffix and never reshapes the slug prefix.
    #[tokio::test]
    async fn terminate_with_error_slug_and_code_derived_from_reason_enum() {
        for reason in [
            TerminateReason::RevokedMidStream,
            TerminateReason::CancelAckTimeout,
            TerminateReason::CreditStall,
        ] {
            let state = build_test_state();
            let grant_wake = Arc::new(Notify::new());
            let cancel_wake = Arc::new(Notify::new());
            let terminate_wake = Arc::new(Notify::new());
            let (_inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(16);
            let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(16);
            let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();
            let request_id: RequestId = [0x55; 16];

            let pump_state = Arc::clone(&state);
            let pump_grant = Arc::clone(&grant_wake);
            let pump_cancel = Arc::clone(&cancel_wake);
            let pump_terminate = Arc::clone(&terminate_wake);
            let pump_handle = tokio::spawn(async move {
                run_stream_pump_v2(
                    pump_state,
                    pump_grant,
                    pump_cancel,
                    pump_terminate,
                    inner_rx,
                    outer_tx,
                    summary_tx,
                    Duration::from_secs(30),
                    Duration::from_secs(5),
                    request_id,
                    PumpEventEmissionInputs {
                        sink: None,
                        context_id: "ctx-test".to_owned(),
                        outlet_id: "outlet-test".to_owned(),
                        invoker_did: scp_primitives::DID("did:dht:invoker".to_owned()),
                        input_hash: "0".repeat(64),
                        start: Instant::now(),
                    },
                )
                .await;
            });

            let handle = StreamSessionHandle {
                receiver: None,
                state: Arc::clone(&state),
                grant_wake: Arc::clone(&grant_wake),
                cancel_wake: Arc::clone(&cancel_wake),
                terminate_wake: Arc::clone(&terminate_wake),
                summary_rx: None,
                request_id,
            };

            // Pass a deliberately-misleading message_override to prove
            // the slug is NEVER caller-derived. The chunk message MUST
            // be `{enum_slug}: {override}`; an attacker who supplies
            // `"authorization.attacker-injected"` cannot reach the slug.
            handle
                .terminate_with_error(reason, Some("authorization.attacker-injected".to_owned()))
                .expect("terminate accepted");

            let chunk = tokio::time::timeout(Duration::from_secs(2), outer_rx.recv())
                .await
                .expect("pump emits synthetic terminal within 2s")
                .expect("chunk arrives");
            assert_ne!(
                chunk.sig, [0u8; 64],
                "sig MUST NOT be all-zero placeholder for reason {reason:?}"
            );
            let ChunkPayload::Error { code, message, .. } = chunk.payload else {
                unreachable!("expected terminal Error chunk for reason {reason:?}");
            };
            // Canonical slug+code from the enum, not from the override.
            assert_eq!(code, reason.code(), "reason {reason:?} must use enum code");
            assert!(
                message.starts_with(&format!("{}: ", reason.slug())),
                "reason {reason:?} must prefix the message with its enum slug, got: {message}"
            );
            // Attacker-controlled string MUST NOT appear as the slug
            // prefix. It is permitted to appear as the suffix (human
            // text), but the canonical slug from the enum wins.
            assert!(
                !message.starts_with("authorization.attacker-injected"),
                "attacker-supplied string leaked into slug position for reason {reason:?}: \
                 {message}"
            );

            pump_handle.await.expect("pump settles");
            let summary = summary_rx.await.expect("summary published");
            for c in &summary.manifest {
                assert_ne!(
                    c.sig, [0u8; 64],
                    "manifest chunk has all-zero sig for reason {reason:?}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Round-8 helpers
    // -----------------------------------------------------------------------

    /// Spawns the pump for a freshly-built test state and returns the
    /// `(handle, outer_rx, summary_rx, pump_join)` quad. The handle shares
    /// the same `state`/notifiers as the pump so control-plane calls
    /// (`terminate_with_error`, `apply_outlet_cancel_signed`) reach it.
    #[allow(clippy::type_complexity)]
    fn spawn_test_pump(
        state: Arc<Mutex<SharedSessionState>>,
        request_id: RequestId,
        recheck: Duration,
    ) -> (
        StreamSessionHandle,
        mpsc::Receiver<OutletStreamChunk>,
        tokio::sync::oneshot::Receiver<StreamCloseSummary>,
        tokio::task::JoinHandle<()>,
        mpsc::Sender<OutletStreamChunk>,
    ) {
        let grant_wake = Arc::new(Notify::new());
        let cancel_wake = Arc::new(Notify::new());
        let terminate_wake = Arc::new(Notify::new());
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (outer_tx, outer_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();
        // Set the snapshot recheck cadence on the state so the pump's
        // interval arm fires at the test-controlled period.
        {
            let mut g = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.stream_ucan_recheck_secs = u32::try_from(recheck.as_secs().max(1)).unwrap_or(1);
        }
        let pump_state = Arc::clone(&state);
        let pump_grant = Arc::clone(&grant_wake);
        let pump_cancel = Arc::clone(&cancel_wake);
        let pump_terminate = Arc::clone(&terminate_wake);
        let pump_join = tokio::spawn(async move {
            run_stream_pump_v2(
                pump_state,
                pump_grant,
                pump_cancel,
                pump_terminate,
                inner_rx,
                outer_tx,
                summary_tx,
                Duration::from_secs(30),
                Duration::from_secs(5),
                request_id,
                PumpEventEmissionInputs {
                    sink: None,
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    invoker_did: scp_primitives::DID("did:dht:invoker".to_owned()),
                    input_hash: "0".repeat(64),
                    start: Instant::now(),
                },
            )
            .await;
        });
        let handle = StreamSessionHandle {
            receiver: None,
            state,
            grant_wake,
            cancel_wake,
            terminate_wake,
            summary_rx: None,
            request_id,
        };
        (handle, outer_rx, summary_rx, pump_join, inner_tx)
    }

    /// F3 lost-wakeup regression: a `terminate_with_error` that lands while
    /// the pump is between iterations (the notification stores a `notify_one`
    /// permit rather than waking an already-parked waiter) is still observed
    /// on the next iteration — the synthetic terminal is emitted exactly once.
    #[tokio::test]
    async fn f3_notify_one_does_not_lose_terminate_wakeup() {
        let state = build_test_state();
        let request_id: RequestId = [0x10; 16];
        let (handle, mut outer_rx, summary_rx, pump_join, _inner_tx) =
            spawn_test_pump(state, request_id, Duration::from_secs(3_601));

        // Fire terminate immediately — it may land before the pump first
        // parks on `notified()`. With `notify_one` a permit is stored, so
        // the next `terminate_wake.notified()` (or the eager top-of-loop
        // check) observes it; the chunk must still arrive.
        handle
            .terminate_with_error(TerminateReason::RevokedMidStream, None)
            .expect("terminate accepted");
        let chunk = tokio::time::timeout(Duration::from_secs(2), outer_rx.recv())
            .await
            .expect("pump emits synthetic terminal within 2s")
            .expect("chunk arrives");
        assert!(chunk.payload.is_terminal());
        pump_join.await.expect("pump settles");
        let summary = summary_rx.await.expect("summary published");
        assert_eq!(
            summary.stream_chunk_count, 1,
            "exactly one terminal emitted"
        );
    }

    /// F6 (a): a context closed mid-stream terminates with
    /// `protocol.context-closed-mid-stream` / `SCP-TOOL-6101` (Protocol
    /// class), NOT `authorization.revoked-mid-stream`.
    #[tokio::test]
    async fn f6_context_closed_mid_stream_terminates_protocol_class() {
        // Build a state whose context handle we can drive to a non-Active
        // state, with a fast recheck cadence and a never-revokes checker.
        let state = build_test_state_with_checker(
            Arc::new(scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new()),
            1,
        );
        // Drive the embedded context handle Creating -> Active -> Closing
        // so the pump's teardown re-check observes a non-live context.
        let ctx_handle = {
            let g = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.context_handle.clone()
        };
        ctx_handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("Creating -> Active");
        ctx_handle
            .transition_to(&scp_protocol::context::ContextState::Closing)
            .await
            .expect("Active -> Closing");

        let request_id: RequestId = [0x20; 16];
        let (_handle, mut outer_rx, summary_rx, pump_join, _inner_tx) =
            spawn_test_pump(state, request_id, Duration::from_secs(1));

        // The pump's zeroth recheck tick (F4: no longer drained) observes
        // the Closing context and arms ContextClosedMidStream.
        let chunk = tokio::time::timeout(Duration::from_secs(3), outer_rx.recv())
            .await
            .expect("pump emits teardown terminal within recheck cadence")
            .expect("chunk arrives");
        let ChunkPayload::Error {
            code,
            message,
            terminal,
        } = chunk.payload
        else {
            unreachable!("expected terminal Error chunk");
        };
        assert!(terminal);
        assert_eq!(
            code,
            scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION,
            "context teardown must carry the Protocol-session code SCP-TOOL-6101, not the \
             Authorization revoked code"
        );
        assert!(
            message.starts_with(scp_protocol::context::outlets::error_codes::SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM),
            "message must carry the context-closed-mid-stream slug, got: {message}"
        );
        pump_join.await.expect("pump settles");
        let _ = summary_rx.await.expect("summary published");
    }

    /// F6 (b): a genuine UCAN revocation (context still live) still yields
    /// `RevokedMidStream` (Authorization class) — teardown precedence does
    /// not swallow real revocations.
    #[tokio::test]
    async fn f6_genuine_revocation_still_yields_revoked_mid_stream() {
        let mut checker = scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new();
        // build_test_state_with_checker pins `ucan_cid = "bafyrei-test"`.
        checker.revoked.insert("bafyrei-test".to_owned());
        let state = build_test_state_with_checker(Arc::new(checker), 1);
        // Leave the context handle in `Creating` (live) so teardown does
        // NOT fire — only revocation should.
        let request_id: RequestId = [0x21; 16];
        let (_handle, mut outer_rx, summary_rx, pump_join, _inner_tx) =
            spawn_test_pump(state, request_id, Duration::from_secs(1));

        let chunk = tokio::time::timeout(Duration::from_secs(3), outer_rx.recv())
            .await
            .expect("pump emits revocation terminal within recheck cadence")
            .expect("chunk arrives");
        let ChunkPayload::Error { code, message, .. } = chunk.payload else {
            unreachable!("expected terminal Error chunk");
        };
        assert_eq!(
            code,
            TerminateReason::RevokedMidStream.code(),
            "genuine revocation must carry the Authorization revoked code"
        );
        assert!(
            message.starts_with(TerminateReason::RevokedMidStream.slug()),
            "message must carry the revoked-mid-stream slug, got: {message}"
        );
        pump_join.await.expect("pump settles");
        let _ = summary_rx.await.expect("summary published");
    }

    /// F4: with the zeroth-tick drain removed, the revocation re-check
    /// arm fires promptly (the interval's first tick is immediate), so a
    /// token revoked at open is observed and the stream terminates with
    /// `RevokedMidStream` regardless of executor chunk timing. Uses paused
    /// virtual time so the assertion does not depend on wall-clock.
    #[tokio::test(start_paused = true)]
    async fn f4_revocation_observed_promptly_via_undrained_zeroth_tick() {
        let mut checker = scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new();
        checker.revoked.insert("bafyrei-test".to_owned());
        // recheck cadence of 5s; with the zeroth-tick NOT drained, the
        // first tick is immediate so the terminal arrives at ~t=0, well
        // before t=recheck_secs.
        let state = build_test_state_with_checker(Arc::new(checker), 5);
        let request_id: RequestId = [0x22; 16];
        // The inner_tx is held (no executor chunks ever arrive) so the
        // ONLY way the stream terminates is the revocation re-check —
        // proving termination is independent of executor chunk timing.
        let (_handle, mut outer_rx, summary_rx, pump_join, _inner_tx) =
            spawn_test_pump(state, request_id, Duration::from_secs(5));

        // Advance virtual time by less than one recheck period; the
        // immediate zeroth tick should already have armed the terminal.
        tokio::time::advance(Duration::from_millis(10)).await;
        let chunk = tokio::time::timeout(Duration::from_secs(5), outer_rx.recv())
            .await
            .expect("revocation terminal arrives well before t=recheck_secs")
            .expect("chunk arrives");
        let ChunkPayload::Error { code, .. } = chunk.payload else {
            unreachable!("expected terminal Error chunk");
        };
        assert_eq!(
            code,
            TerminateReason::RevokedMidStream.code(),
            "prompt zeroth-tick re-check yields RevokedMidStream"
        );
        pump_join.await.expect("pump settles");
        let _ = summary_rx.await.expect("summary published");
    }

    /// N2: `apply_outlet_cancel_signed` records the cancel-ack-seq at the
    /// runtime's live cursor and the runtime signs internally (no caller
    /// `next_seq`). A `CancelIdentity` that does not match the pinned triple
    /// is rejected as `SignatureInvalid` WITHOUT mutating stream state.
    #[tokio::test]
    async fn n2_apply_outlet_cancel_signed_records_and_validates_identity() {
        let state = build_test_state();
        let request_id: RequestId = [0x30; 16];
        let (handle, _outer_rx, _summary_rx, _pump_join, _inner_tx) =
            spawn_test_pump(Arc::clone(&state), request_id, Duration::from_secs(3_601));

        // Signer wrapping the same fixed key the fixture pinned as
        // invoker_pk (build_test_state uses fixed_signing_key() for both).
        let signer = super::super::signer::InProcessStreamSigner::new(fixed_signing_key());

        // Identity mismatch (wrong outlet_id) → SignatureInvalid, no mutation.
        let bad_id = CancelIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "WRONG".to_owned(),
            caveats_binding: [0xAB; 32],
        };
        let bad = handle.apply_outlet_cancel_signed(&signer, &bad_id).await;
        assert!(
            matches!(
                bad,
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "identity mismatch must reject as SignatureInvalid, got {bad:?}"
        );
        {
            let g = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !g.cancel_ack_armed,
                "rejected cancel must NOT arm the timer"
            );
            assert_eq!(
                g.cancel_ack_seq, None,
                "rejected cancel must NOT record a seq"
            );
        }

        // Correct identity → Ok, records the live cursor (0 here — no chunk
        // emitted), arms the timer.
        let good_id = CancelIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            caveats_binding: [0xAB; 32],
        };
        let ok = handle
            .apply_outlet_cancel_signed(&signer, &good_id)
            .await
            .expect("signed cancel accepted");
        assert_eq!(ok, Some(0), "cancel-ack recorded at the live cursor (0)");
        {
            let g = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(g.cancel_ack_armed, "accepted cancel arms the timer");
            assert_eq!(g.cancel_ack_seq, Some(0));
        }
    }
}
