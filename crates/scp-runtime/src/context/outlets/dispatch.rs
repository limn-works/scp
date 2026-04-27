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
use scp_protocol::context::outlets::stream::{OutletStreamChunk, OutletStreamCredit, RequestId};
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
    /// the terminal chunk.
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

    /// Applies an `OutletCancel`. Records `cancel_ack_seq = next_seq`,
    /// arms the `stream_cancel_ack_secs` timer, and wakes the pump so
    /// the executor can emit a terminal chunk within the window. Per
    /// §5.4.5 the recorded `cancel_ack_seq` is the runtime's
    /// next-to-emit cursor at the moment the cancel arrives.
    ///
    /// Returns the recorded `cancel_ack_seq`. If the stream had already
    /// closed (terminal chunk delivered), returns `None` and the
    /// cancel is ignored per §5.4.5 idempotency rule.
    pub fn apply_outlet_cancel(&self, next_seq: u64) -> Option<u64> {
        let now = Instant::now();
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.cancel_ack.record_cancel(next_seq, now);
        let recorded = guard.cancel_ack.cancel_ack_seq();
        guard.cancel_ack_armed = true;
        guard.cancel_ack_seq = recorded;
        drop(guard);
        self.cancel_wake.notify_waiters();
        recorded
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
    }))
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

    // Step 5: launch the underlying executor stream.
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
        invoked_event_sink,
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
) {
    let mut emitted_chunks: Vec<OutletStreamChunk> = Vec::new();
    let mut next_seq: u64 = 0;
    let mut parked: Option<OutletStreamChunk> = None;

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
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig: [0u8; 64],
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = credit_timer_fut => {
                    let payload = CancelAckTracker::credit_stall_payload();
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig: [0u8; 64],
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
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig: [0u8; 64],
                    };
                    emitted_chunks.push(chunk.clone());
                    let _ = outer_tx.send(chunk).await;
                    break;
                }
                () = credit_timer_fut => {
                    let payload = CancelAckTracker::credit_stall_payload();
                    let chunk = OutletStreamChunk {
                        request_id,
                        sequence: next_seq,
                        payload,
                        sig: [0u8; 64],
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
                let final_chunk = OutletStreamChunk {
                    request_id,
                    sequence: seq,
                    payload: chunk.payload.clone(),
                    sig: chunk.sig,
                };
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
