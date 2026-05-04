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

use ed25519_dalek::{SigningKey, VerifyingKey};
use scp_primitives::DID;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::error_codes;
use scp_protocol::context::outlets::stream::{
    OutletStreamCancel, OutletStreamChunk, OutletStreamCredit, RequestId, sign_chunk,
    verify_cancel_signature, verify_chunk_signature,
};
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
        }
    }

    /// Returns the §5.4.4 error code for this rejection.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match *self {
            Self::AdmissionRateLimited { .. } => error_codes::CODE_TRANSPORT_FAULT,
            Self::EstimateExceedsBound => error_codes::CODE_INPUT_VIOLATION,
            Self::EscrowOverflow | Self::InsufficientFunds => error_codes::CODE_ECONOMIC_FAULT,
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
#[derive(Debug, Clone)]
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
    /// Operator's Ed25519 signing key. Used by the dispatch pump to
    /// sign every chunk that crosses the outer wire boundary — both
    /// executor-emitted chunks (renumbered under the pump's sequence)
    /// and framework-emitted terminal chunks (cancel-ack-timeout,
    /// credit-stall). Pinned at acceptance.
    ///
    /// `None` is reserved for legacy / test callers that have no key
    /// to sign with. When `None` the pump emits the all-zero signature
    /// placeholder and logs a `tracing::error!` so the gap is visible
    /// in production telemetry — preferred over silently corrupting
    /// the wire form. Production native FFI bridges always pass
    /// `Some`; WASM passes the invoker key (operator==invoker per
    /// ADR-034, single-process bridge).
    pub operator_signing_key: Option<Arc<SigningKey>>,
    /// `ContextParams::stream_credit_stall_secs`.
    pub stream_credit_stall_secs: u32,
    /// `ContextParams::stream_cancel_ack_secs`.
    pub stream_cancel_ack_secs: u32,
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
#[derive(Debug)]
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
    /// Operator signing key pinned at acceptance. The pump uses this
    /// to sign every chunk that crosses the outer wire boundary —
    /// executor-emitted chunks (re-signed under the pump's renumbered
    /// sequence) and framework-emitted terminal chunks (cancel-ack-
    /// timeout, credit-stall). `None` only for legacy / test callers
    /// that do not supply a key — the pump emits the all-zero sig
    /// placeholder and logs a `tracing::error!` so the gap is visible.
    pub operator_signing_key: Option<Arc<SigningKey>>,
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
// StreamSessionHandle — control surface
// ---------------------------------------------------------------------------

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
        self.grant_wake.notify_waiters();
        Ok(new_total)
    }

    /// Applies a signed `OutletStreamCancel` (round-7 cancel-auth).
    /// Records `cancel_ack_seq = cancel.next_seq`, arms the
    /// `stream_cancel_ack_secs` timer, and wakes the pump so the
    /// executor can emit a terminal chunk within the window. Per
    /// §5.4.5 the recorded `cancel_ack_seq` is the runtime's
    /// next-to-emit cursor at the moment the cancel arrives.
    ///
    /// Verifies the cancel's signature under the invoker's pinned
    /// `invoker_pk` recorded by the `CreditTracker` at acceptance.
    /// On signature-verification failure, returns
    /// [`super::stream::CancelError::SignatureInvalid`]
    /// and does NOT mutate stream state — neither the cancel-ack timer
    /// arms nor `cancel_ack_seq` is recorded. This is the §5.4.5
    /// `Authorization::AuthorizationFailed` path the spec round-7
    /// cancel-auth tightening introduces.
    ///
    /// On success, returns `Ok(Some(seq))` with the recorded
    /// `cancel_ack_seq`. If the stream had already closed (terminal
    /// chunk delivered), returns `Ok(None)` and the cancel is ignored
    /// per §5.4.5 idempotency rule.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`super::stream::CancelError::SignatureInvalid`]
    /// when the cancel's signature does not verify under the pinned
    /// invoker key + the stream's pinned `(context_id, outlet_id,
    /// caveats_binding)` triple.
    pub fn apply_outlet_cancel(
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
        self.cancel_wake.notify_waiters();
        Ok(recorded)
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
        operator_signing_key: params.operator_signing_key.clone(),
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
    inner_rx: mpsc::Receiver<OutletStreamChunk>,
    outer_tx: mpsc::Sender<OutletStreamChunk>,
    summary_tx: tokio::sync::oneshot::Sender<StreamCloseSummary>,
    stream_credit_stall_secs: u32,
    stream_cancel_ack_secs: u32,
    request_id: RequestId,
    event_inputs: PumpEventEmissionInputs,
) {
    let stream_credit_stall = Duration::from_secs(u64::from(stream_credit_stall_secs));
    let stream_cancel_ack = Duration::from_secs(u64::from(stream_cancel_ack_secs));
    tokio::spawn(async move {
        run_stream_pump_v2(
            state,
            grant_wake,
            cancel_wake,
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
) -> Result<StreamSessionHandle, OpenStreamRejection>
where
    E: OutletExecutor + ?Sized + 'static,
{
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

    // Step 4: tracker init.
    let shared = build_shared_state(&params, escrow, &admission);
    let grant_wake = Arc::new(Notify::new());
    let cancel_wake = Arc::new(Notify::new());

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
        params.operator_signing_key.clone(),
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

    let request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
    let (outer_tx, outer_rx) = mpsc::channel::<OutletStreamChunk>(
        scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW as usize,
    );
    let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();

    spawn_pump_task(
        Arc::clone(&shared),
        Arc::clone(&grant_wake),
        Arc::clone(&cancel_wake),
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
    );

    Ok(StreamSessionHandle {
        receiver: Some(outer_rx),
        state: shared,
        grant_wake,
        cancel_wake,
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
    /// Operator signing key. `None` for legacy / test callers; see
    /// [`OpenStreamParams::operator_signing_key`].
    operator_signing_key: Option<Arc<SigningKey>>,
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
    /// Returns the all-zero placeholder + logs `tracing::error!` when
    /// the operator key is `None` — this preserves the wire shape but
    /// makes the gap visible to operators (the receiver will reject
    /// such a chunk under the §5.4.5 verifier; the placeholder is a
    /// last-ditch fallback for legacy / test callers that never wired
    /// the key, never the production path).
    fn sign_outer_chunk(
        &self,
        request_id: &RequestId,
        sequence: u64,
        payload: &scp_protocol::context::outlets::stream::ChunkPayload,
    ) -> [u8; 64] {
        let Some(key) = self.operator_signing_key.as_ref() else {
            tracing::error!(
                request_id = %hex::encode(request_id),
                outlet_id = %self.outlet_id,
                context_id = %self.context_id,
                sequence,
                "dispatch pump: operator_signing_key is None — emitting unsigned chunk (legacy/test path)"
            );
            return [0u8; 64];
        };
        match sign_chunk(
            key,
            &self.context_id,
            &self.outlet_id,
            request_id,
            sequence,
            &self.caveats_binding,
            payload,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                // JCS canonicalization should never fail for a valid
                // ChunkPayload; if it ever does, surface the error and
                // fall back to the placeholder rather than panic the
                // pump task.
                tracing::error!(
                    request_id = %hex::encode(request_id),
                    outlet_id = %self.outlet_id,
                    context_id = %self.context_id,
                    sequence,
                    error = %e,
                    "dispatch pump: failed to sign chunk — emitting unsigned placeholder"
                );
                [0u8; 64]
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_stream_pump_v2(
    state: Arc<Mutex<SharedSessionState>>,
    grant_wake: Arc<Notify>,
    cancel_wake: Arc<Notify>,
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
    let signing_ctx = {
        let guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let identity = guard.credit.identity().clone();
        PumpSigningContext {
            operator_signing_key: guard.operator_signing_key.clone(),
            context_id: identity.context_id,
            outlet_id: identity.outlet_id,
            caveats_binding: identity.caveats_binding,
        }
    };

    loop {
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
        //   (d) a cancel_wake notification (re-evaluate next iter).
        // We do NOT pull from the inner_rx because the parked chunk is
        // the head-of-line — pulling more from the executor would cause
        // out-of-order delivery once the stall lifts.
        let chunk_opt = if parked.is_some() {
            tokio::select! {
                biased;
                () = cancel_timer_fut => {
                    let payload = CancelAckTracker::cancel_ack_timeout_payload();
                    let sig = signing_ctx.sign_outer_chunk(&request_id, next_seq, &payload);
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig,
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = credit_timer_fut => {
                    let payload = CancelAckTracker::credit_stall_payload();
                    let sig = signing_ctx.sign_outer_chunk(&request_id, next_seq, &payload);
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig,
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
            }
        } else {
            tokio::select! {
                biased;
                () = cancel_timer_fut => {
                    let payload = CancelAckTracker::cancel_ack_timeout_payload();
                    let sig = signing_ctx.sign_outer_chunk(&request_id, next_seq, &payload);
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig,
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = credit_timer_fut => {
                    let payload = CancelAckTracker::credit_stall_payload();
                    let sig = signing_ctx.sign_outer_chunk(&request_id, next_seq, &payload);
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig,
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
                next_seq = next_seq.saturating_add(1);
                // §5.4.5 per-chunk operator signature MUST cover the
                // outer (renumbered) sequence. The inner pump's chunk
                // bears a sig under the inner-pump sequence which the
                // outer wire form no longer matches; we re-sign every
                // forwarded chunk under the outer sequence so receivers
                // can verify each chunk against `chunk.sequence` as
                // delivered. Without this, the inner sig is dead weight
                // (verifies under a sequence the wire never carries).
                let sig = signing_ctx.sign_outer_chunk(&request_id, seq, &chunk.payload);
                let final_chunk = OutletStreamChunk {
                    request_id,
                    sequence: seq,
                    payload: chunk.payload.clone(),
                    sig,
                };
                // Crisp invariant: every chunk reaching a bridge consumer
                // verifies under the pinned operator key. In debug
                // builds we re-verify the sig we just produced, so a
                // signing-vs-verifying preimage drift surfaces in tests
                // before any production member observes a bad chunk.
                debug_assert!(
                    signing_ctx.operator_signing_key.as_ref().is_none_or(|key| {
                        verify_chunk_signature(
                            &final_chunk,
                            &key.verifying_key(),
                            &signing_ctx.context_id,
                            &signing_ctx.outlet_id,
                            &signing_ctx.caveats_binding,
                        )
                    }),
                    "dispatch pump: just-signed chunk fails to verify under the pinned operator key — \
                     signing/verifying preimage drift",
                );
                {
                    let mut guard = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let g = &mut *guard;
                    accrue_data_chunk_if_billable(&mut g.escrow, &g.cancel_ack, &final_chunk);
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
        if let Err(verify_err) = verify_summary_chunks_billed(&summary) {
            // Self-consistency drift between the pump's recorded
            // `billed_count` and the manifest-derivable reference. This
            // would otherwise be a wire-rejection at event-log insert
            // time (§5.4.5). Drop the event rather than emit a bogus
            // record — the SDK already received the chunks, so the
            // audit log staying silent is preferable to recording a
            // self-inconsistent event the verifier will reject.
            tracing::error!(
                request_id = %hex::encode(request_id),
                outlet_id = %event_inputs.outlet_id,
                error = ?verify_err,
                "OutletInvokedEvent dropped: chunks_billed mismatch against manifest"
            );
        } else {
            let event = super::invoke::build_streaming_outlet_event(
                request_id,
                &event_inputs.outlet_id,
                &event_inputs.invoker_did,
                event_inputs.input_hash.clone(),
                u64::try_from(event_inputs.start.elapsed().as_millis()).unwrap_or(u64::MAX),
                &summary.manifest,
            );
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
// Tests live under tests/ — see crates/scp-runtime/tests/streaming_dispatch_*.
// ---------------------------------------------------------------------------
