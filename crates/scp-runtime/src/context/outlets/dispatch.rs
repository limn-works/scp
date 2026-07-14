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
//!      cap counters — the per-invoker + per-outlet counters on the
//!      per-context tracker and the per-origin-invoker counter on the
//!      operator-scoped [`OriginAdmissionTracker`] (§05-contexts.md:448),
//!      both under the sanctioned lock order,
//!    - publishes the frontier-derived `chunks_billed` value into the
//!      `OutletInvokedEvent` field; the event-local wire-invariant
//!      `chunks_billed <= stream_chunk_count` is then enforced at the
//!      event-log append boundary via
//!      [`super::stream::verify_outlet_invoked_event_local`].
//!
//! See `.docs/specs/05-contexts.md` §5.4.5 for the spec source.

// `module_name_repetitions` and `significant_drop_tightening` are
// pragmatic for this dispatch module — the public API names match the
// §5.4.5 spec table verbatim, and the per-stream `RwLockWriteGuard`
// lifetime IS the critical section by design (§5.4.5 atomicity
// invariant: the admission counters and credit accounting must mutate
// together).
//
// Synchronisation primitive (ADR-049 §Decision 12): scp-runtime's
// `clippy.toml` bans `std::sync::Mutex` on runtime paths. This module runs
// OFF the actor mailbox (the pump runs supervisor-side), so it legitimately
// owns its own shared per-stream state — but it uses `std::sync::RwLock`
// (NOT banned; the sanctioned off-mailbox pattern also used by
// `bridge::credentials`), always acquired via `.write()` for exclusive
// access (semantically identical to a `Mutex`). The guard is NEVER held
// across an `.await`, so `await_holding_lock` does not fire — the signer
// call in `apply_outlet_cancel_signed` runs entirely off-lock.
#![allow(clippy::module_name_repetitions, clippy::significant_drop_tightening)]

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use scp_did::DID;
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
    QueryMisdeclarationSink, StreamGateOutcome, StreamSettlement, StreamSettlementSink,
    accrue_data_chunk_if_billable, apply_stream_chunk_gate, ingest_stream_chunk, invoke_outlet,
    release_stream_admission,
};
use super::stream::{
    AdmissionCaps, AdmissionOutcome, CancelAckTracker, CreditTracker, GrantError, OpenError,
    OriginAdmissionTracker, StreamAdmissionTracker, StreamEscrow, StreamIdentity,
    admission_outcome_to_slug, coerce_estimated_chunk_count, cumulative_reserve_amount,
    effective_max_billable_chunks, enforce_estimated_chunk_count_bound, open_error_to_slug,
};

use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::roles::ContextRoleState;

// ---------------------------------------------------------------------------
// Open-path escrow refund guard (E2 remediation)
// ---------------------------------------------------------------------------

/// Reverses a §5.4.5 streaming escrow hold or top-up that was DEBITED.
///
/// This is the runtime-side seam the [`StreamEscrowTicket`] Drop-guard fires
/// through to refund a hold that was debited against the invoker's
/// `MemberBudgetTracker` but never settled.
///
/// `reverse_spend` is async (it takes the per-context lock), and a `Drop`
/// impl cannot `.await`, so the production sink the native bridges supply
/// holds a [`tokio::runtime::Handle`] and `Handle::spawn`s the async
/// `ContextManager::outlet_stream_reverse_spend`. The trait is the seam
/// that lets `dispatch.rs` (below the `ContextManager` in the dependency
/// graph) refund a hold without depending on the manager type.
///
/// Implementations MUST be cheap and non-blocking — `refund` runs from a
/// `Drop`, possibly on the open path's thread.
pub trait StreamEscrowRefundSink: Send + Sync {
    /// Refunds `amount` to `member_did`'s budget in `context_id` — a
    /// best-effort, fire-and-forget reversal. Saturates at zero on the
    /// budget tracker, so a double-refund (Drop after an explicit reverse)
    /// is a safe no-op.
    fn refund(&self, context_id: &str, member_did: &DID, amount: Amount);
}

/// Refund guard for the §5.4.5 open-time escrow HOLD (E2 remediation).
///
/// The native bridges debit the open-time hold against the invoker's
/// `MemberBudgetTracker` via
/// [`crate::context::manager::ContextManager::outlet_stream_reserve_escrow`]
/// BEFORE the stream pump is spawned. Between that debit and a successful
/// spawn there are several fallible steps (admission gate, estimate
/// bound, pump-permit acquisition, `invoke_outlet` launch) — any of which
/// can early-return. Without a guard, the debited hold would be stranded:
/// the invoker is charged the full estimate with no refund path.
///
/// This ticket mirrors the [`crate::context::manager::economy`]
/// `EconomyTicket` Drop-guard discipline: it is `#[must_use]`, and its
/// `Drop` impl refunds the hold (via [`StreamEscrowRefundSink::refund`])
/// when the ticket was NOT consumed. The pump-spawn path calls
/// [`Self::consume`] exactly once the pump is spawned `Ok` — from that
/// point the close-time settlement (`outlet_stream_settle`) owns the
/// refund of the unspent portion, so the open-path guard must NOT also
/// refund. Every early-return between reserve and spawn drops the ticket
/// → refund. This is INDEPENDENT of `release_admission` (both roll back
/// on the same error paths).
///
/// A zero-amount ticket (Query / zero-cost stream, where the manager
/// performed no debit) is a no-op on both `consume` and `Drop`.
#[must_use = "a StreamEscrowTicket must be consumed once the pump spawns Ok, or dropped to refund the debited hold"]
pub struct StreamEscrowTicket {
    sink: Arc<dyn StreamEscrowRefundSink>,
    context_id: String,
    member_did: DID,
    reserved: Amount,
    consumed: bool,
}

impl StreamEscrowTicket {
    /// Creates a ticket guarding a `reserved` hold already debited for
    /// `member_did` in `context_id`. The `sink` performs the async
    /// reversal on Drop when the ticket is not consumed.
    pub fn new(
        sink: Arc<dyn StreamEscrowRefundSink>,
        context_id: String,
        member_did: DID,
        reserved: Amount,
    ) -> Self {
        Self {
            sink,
            context_id,
            member_did,
            reserved,
            consumed: false,
        }
    }

    /// Marks the hold as handed off to the stream's close-time settlement.
    /// Call exactly once when the pump has spawned `Ok` — the
    /// `outlet_stream_settle` path now owns the unspent-portion refund, so
    /// the Drop-guard must NOT also refund.
    pub fn consume(mut self) {
        self.consumed = true;
    }

    /// Read-only accessor for the guarded hold amount (test introspection).
    #[must_use]
    pub const fn reserved(&self) -> Amount {
        self.reserved
    }
}

impl Drop for StreamEscrowTicket {
    fn drop(&mut self) {
        if !self.consumed && self.reserved.value() > 0 {
            // The pump never spawned (or an early-return fired between the
            // manager debit and the spawn). Refund the full hold via the
            // sink — mirrors the EconomyTicket rollback discipline. The
            // debug-assert surfaces an un-consumed non-zero ticket loudly
            // in tests so a future error branch that forgets to consume on
            // the success path fails CI rather than silently refunding a
            // live stream's escrow.
            tracing::warn!(
                context_id = %self.context_id,
                member_did = %self.member_did,
                reserved = self.reserved.value(),
                "StreamEscrowTicket dropped unconsumed — refunding debited open-time escrow hold"
            );
            self.sink
                .refund(&self.context_id, &self.member_did, self.reserved);
        }
    }
}

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
    /// `SCP-OUTLET-6110` (the Authorization-class umbrella per §5.4.4).
    CaveatsBindingMismatch,
    /// The node-level concurrent-pump ceiling
    /// (`ContextManager::max_concurrent_outlet_stream_pumps`) was already
    /// saturated when this open tried to acquire a pump permit (round 8).
    /// Acquired AFTER all per-context admission / escrow / binding gates
    /// pass, so a rejected open here does NOT consume a per-context
    /// admission slot or an escrow reservation; the caller's prior gates
    /// are rolled back before this rejection is returned. Slug:
    /// `execution.stream-cap-exhausted`; code: `SCP-OUTLET-6131`
    /// (`CODE_EXECUTION_CREDIT`, the shared Execution resource-exhaustion
    /// band per §5.4.5 round-8).
    StreamCapExhausted,
    /// The §7.3.8 caveat post-input check
    /// ([`CaveatPostInputCheck`](super::invoke::CaveatPostInputCheck))
    /// rejected the open. The stream validates its input ONCE at open
    /// (§5.4.5), so this gate runs the same `check_invocation_local`
    /// (`amount_max_per_call` / `allowed_adapters` / `allowed_target_dids`
    /// / `input_schema`) plus the counter-store CAS
    /// (`max_calls` / `amount_max_cumulative` / `rate_window`) the
    /// non-streaming `invoke` path runs — before the pump spawns. Carries
    /// the precise §5.4.4 slug from the rule that fired so the FFI / SDK
    /// surface routes identically to the non-streaming caveat path. The
    /// slug determines the class: `input.schema-violation` →
    /// `SCP-OUTLET-6120`, every other caveat slug → `SCP-OUTLET-6110`.
    CaveatPostInputViolation {
        /// The §5.4.4 slug of the violated caveat rule.
        ///
        /// Reconciled to `String` (the source pump carried `&'static str`):
        /// on this branch [`InvocationError::CaveatViolation`] carries an
        /// owned `String` slug (the §7.3.8 hook returns the precise runtime
        /// rule slug), so this variant carries it verbatim to preserve the
        /// exact slug the non-streaming caveat path surfaces — matching the
        /// branch's slug representation rather than interning to a static.
        slug: String,
    },
}

impl OpenStreamRejection {
    /// Returns the §5.4.4 slug for this rejection.
    ///
    /// Borrows for the receiver's lifetime rather than returning
    /// `&'static str` (the source pump's shape): the
    /// [`Self::CaveatPostInputViolation`] slug is an owned runtime `String`
    /// on this branch, so a single accessor over all variants borrows.
    #[must_use]
    pub fn slug(&self) -> &str {
        match self {
            // Both carry a precomputed slug verbatim (the admission tier's
            // rate-limit slug / the §7.3.8 caveat rule's slug).
            Self::AdmissionRateLimited { slug } => slug,
            Self::CaveatPostInputViolation { slug } => slug,
            Self::EstimateExceedsBound => error_codes::SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND,
            Self::EscrowOverflow => error_codes::SLUG_ECONOMIC_ESCROW_OVERFLOW,
            Self::InsufficientFunds => error_codes::SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
            Self::CaveatsBindingMismatch => error_codes::SLUG_AUTHORIZATION_ATTENUATION_VIOLATION,
            Self::StreamCapExhausted => error_codes::SLUG_EXECUTION_STREAM_CAP_EXHAUSTED,
        }
    }

    /// Returns the §5.4.4 error code for this rejection.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::AdmissionRateLimited { .. } => error_codes::CODE_TRANSPORT_FAULT,
            Self::EstimateExceedsBound => error_codes::CODE_INPUT_VIOLATION,
            Self::EscrowOverflow | Self::InsufficientFunds => error_codes::CODE_ECONOMIC_FAULT,
            Self::CaveatsBindingMismatch => error_codes::CODE_AUTHORIZATION_DENIED,
            Self::StreamCapExhausted => error_codes::CODE_EXECUTION_CREDIT,
            // Mirror `caveat_violation_chunk`'s slug→code routing: the
            // input-schema slug is Input-class (`SCP-OUTLET-6120`), every
            // other caveat slug is Authorization-class (`SCP-OUTLET-6110`).
            Self::CaveatPostInputViolation { slug } => {
                if slug.as_str() == error_codes::SLUG_INPUT_SCHEMA_VIOLATION {
                    error_codes::CODE_INPUT_VIOLATION
                } else {
                    error_codes::CODE_AUTHORIZATION_DENIED
                }
            }
        }
    }

    /// Routes this rejection into an [`InvocationError`] envelope so
    /// existing `invocation_error_to_context` translation surfaces it
    /// identically to other open-time validation failures.
    #[must_use]
    pub fn to_invocation_error(&self) -> InvocationError {
        InvocationError::CaveatViolation {
            slug: self.slug().to_owned(),
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
    /// Invoker's available balance at open. Retained for the legacy /
    /// test open paths that still gate via
    /// [`crate::context::outlets::stream::StreamEscrow::reserve_at_open`].
    /// The production native-bridge path no longer consults this — the
    /// manager debits the hold under its own lock and passes the result
    /// in `reserved_escrow` (E2 remediation).
    pub available_balance: Amount,
    /// The open-time escrow hold the caller has ALREADY reserved (DEBITED)
    /// against the invoker's `MemberBudgetTracker` via
    /// [`crate::context::manager::ContextManager::outlet_stream_reserve_escrow`]
    /// (E2 remediation). `reserve_escrow` builds the
    /// [`crate::context::outlets::stream::StreamEscrow`] directly from this
    /// value (`reserved == reserved_escrow`, `billed == 0`) — the
    /// `InsufficientFunds` / `Overflow` balance decision lives entirely in the
    /// manager (the only lock holder), so the dispatch path no longer
    /// re-decides balance. `Amount::new(0)` for Query / zero-cost streams.
    pub reserved_escrow: Amount,
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
    /// §5.4.5 MED-HIGH — the economic policy snapshotted at acceptance so
    /// close-time settlement can capture the `PaymentReceipt` for rendered
    /// service even if the hosting context is closed / evicted mid-stream
    /// (ADR-048 per-instance snapshot; H8 "service rendered is billed").
    /// Carried verbatim into the [`StreamSettlement`] the pump emits.
    /// `None` for zero-cost / Query streams and callers without an
    /// economic policy at open.
    pub economic_policy_snapshot: Option<super::invoke::EconomicPolicySnapshot>,
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
            .field("reserved_escrow", &self.reserved_escrow)
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
            .field("economic_policy_snapshot", &self.economic_policy_snapshot)
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
/// Wrapped in `Arc<RwLock<_>>` so the control surface and the pump can
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
    /// releases the per-invoker + per-outlet counters here at
    /// terminal-chunk emission.
    pub admission: Arc<RwLock<StreamAdmissionTracker>>,
    /// Operator-scoped origin admission tracker (§05-contexts.md:448):
    /// a SINGLE instance shared across every context the operator hosts.
    /// The pump releases the per-origin-invoker counter here at
    /// terminal-chunk emission, in lock-step with `admission`.
    pub origin_admission: Arc<RwLock<OriginAdmissionTracker>>,
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
    /// `true` once the pump has left its loop and published the close
    /// summary in the settlement block. Set under the state lock at
    /// settlement. A `terminate_with_error` observing this flag returns
    /// [`TerminateError::AlreadyTerminated`]: the pump can no longer
    /// consume `pending_terminate`, so arming it would silently strand
    /// the request. This is the only authoritative signal that the
    /// pump's control plane is gone — `pending_terminate` alone cannot
    /// distinguish "not yet armed" from "pump already exited".
    pub pump_exited: bool,
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
            .field("admission", &"<Arc<RwLock<StreamAdmissionTracker>>>")
            .field("origin_admission", &"<Arc<RwLock<OriginAdmissionTracker>>>")
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
            .field("pump_exited", &self.pump_exited)
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
/// `SCP-OUTLET-6110`).
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
    state: Arc<RwLock<SharedSessionState>>,
    /// Notifier used to wake the pump from a credit-stall pause when a
    /// fresh grant lands.
    grant_wake: Arc<Notify>,
    /// Notifier used to wake the pump on `OutletCancel` arrival.
    cancel_wake: Arc<Notify>,
    /// Notifier used to wake the pump when the receiver-side framework
    /// requests a forced terminal via
    /// [`StreamSessionHandle::terminate_with_error`] (§5.4.5
    /// `RevokedMidStream` / `SCP-OUTLET-6110`). The pump's select arm for
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
    /// `chunks_billed` as counted by the ESCROW LEDGER (`settle_at_close`).
    /// This is the runtime's economic self-tally; it is cross-checked
    /// against the manifest-derived [`Self::manifest_billed`] at close and,
    /// on divergence, the event records the manifest value + an
    /// `AuditAnomaly` (§5.4.5 round-8 F2). Count of `Data` leaves at or
    /// below `cancel_ack_seq`.
    pub billed_count: u32,
    /// Total chunks emitted (Data + Progress + terminal) — the running
    /// `MerkleFrontier::leaf_count`.
    pub stream_chunk_count: u32,
    /// `cancel_ack_seq` if cancel arrived, else `None`.
    pub cancel_ack_seq: Option<u64>,
    /// RFC-6962 manifest Merkle root over the emitted chunk sequence,
    /// produced incrementally by the [`MerkleFrontier`](scp_protocol::context::outlets::stream::MerkleFrontier).
    /// Equal to `compute_chunk_manifest_root` over the same sequence
    /// (ADR-061 seal-phase artifact). Replaces the retained chunk Vec.
    pub manifest_root: [u8; 32],
    /// Manifest-derived `chunks_billed` — the frontier's `billed_count`
    /// (`Data` leaves at/below the cancel-ack ceiling). This is the
    /// §5.4.5-authoritative billed value the `OutletInvokedEvent` and the
    /// settlement receipt anchor to; the escrow ledger's
    /// [`Self::billed_count`] is cross-checked against it.
    pub manifest_billed: u32,
    /// Terminal-derived event fields (`output_hash`,
    /// `stream_terminal_status`, legacy `status`), folded incrementally.
    pub terminal_summary: super::invoke::StreamTerminalSummary,
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
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.next_emission_seq
    }

    /// Applies an `OutletStreamCredit` grant.
    ///
    /// Per §5.4.5: verifies the Ed25519 signature under the pinned
    /// identity, rejects replays / regressions, and on acceptance
    /// (i) increments the credit counter and (ii) extends the escrow
    /// ledger by `reserved_top_up`. A signature / replay failure leaves
    /// both the counter and the escrow unchanged — §5.4.5 atomicity
    /// invariant.
    ///
    /// `reserved_top_up` is the `cost_per_chunk × grant` amount the caller
    /// (the FFI bridge) has ALREADY reserved (DEBITED) against the
    /// invoker's `MemberBudgetTracker` via
    /// [`Supervisor::outlet_stream_reserve_grant`](crate::context::supervisor::Supervisor::outlet_stream_reserve_grant)
    /// BEFORE invoking this method (E2 remediation). The
    /// `InsufficientFunds` / `Overflow` decision therefore lives entirely in
    /// the actor — the only lock holder. If THIS method rejects the
    /// grant (signature / replay) after the caller already reserved, the
    /// caller MUST reverse the debit via
    /// [`Supervisor::outlet_stream_reverse_grant`](crate::context::supervisor::Supervisor::outlet_stream_reverse_grant)
    /// — the §5.4.5 atomicity invariant is upheld jointly by the
    /// (actor debit) → (handle apply) → (actor reverse on apply-reject)
    /// sequence.
    ///
    /// Wakes the pump via the grant notifier so a stalled executor can
    /// resume immediately.
    ///
    /// # Errors
    ///
    /// Returns the `(slug, code)` pair for the rejection. The §5.4.5
    /// slugs are routed via [`grant_error_to_slug`]. A returned error
    /// means NO escrow extension happened — the caller reverses its
    /// reserved top-up.
    pub fn apply_credit_grant(
        &self,
        credit: &OutletStreamCredit,
        reserved_top_up: Amount,
    ) -> Result<u32, GrantError> {
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // §5.4.4:426 grant-after-close lifecycle gate. A grant that arrives
        // after the pump has exited (terminal chunk, channel close, or
        // forced terminate) is a Protocol-class session-lifecycle violation
        // — reject with `GrantError::StreamClosed` BEFORE the
        // signature / replay / escrow path so a post-terminal grant never
        // mutates the credit counter or escrow ledger. The caller reverses
        // any top-up it reserved (the §5.4.5 atomicity invariant) exactly as
        // it does for the signature / replay rejections below. Mirrors the
        // `pump_exited` gate in `terminate_with_error`.
        if guard.pump_exited {
            return Err(GrantError::StreamClosed);
        }
        let identity_clone = guard.credit.identity().clone();
        // Signature / replay verification FIRST. On rejection we return
        // before touching escrow — the caller reverses the top-up it
        // reserved against the budget tracker.
        let new_total = guard.credit.grant_with_identity(credit, &identity_clone)?;
        // The top-up was already gated AND debited by the manager under
        // the context lock; record it on the ledger so the per-chunk
        // accrual and close-time refund see the extended ceiling. This
        // cannot fail (no balance re-check, saturating add).
        guard.escrow.apply_reserved_top_up(reserved_top_up);
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
    /// The `std::sync::RwLock` is NEVER held across the `.await` — the
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
                    .write()
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

            // ---- build preimage + sign OFF-LOCK (no lock across await). --
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
                .write()
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
    // `allow` (not `expect`): the verbatim-apply path is the single
    // verify+record primitive for cross-context forwarding waves, which —
    // with their tests — land in a later chunk, so it currently has no
    // caller in either cfg on this branch. `allow` tolerates the later
    // caller without churn; `expect` would then fire "unfulfilled".
    #[allow(
        dead_code,
        reason = "retained as the single verify+record primitive; cross-context forwarding callers + tests land in a later chunk"
    )]
    pub(crate) fn apply_outlet_cancel_verbatim(
        &self,
        cancel: &OutletStreamCancel,
    ) -> Result<Option<u64>, super::stream::CancelError> {
        let now = Instant::now();
        let mut guard = self
            .state
            .write()
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
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The pump has already broken its loop and published the close
        // summary: there is no consumer left to drain `pending_terminate`,
        // so honor the documented `AlreadyTerminated` contract rather than
        // silently arming a request that will never fire.
        if guard.pump_exited {
            return Err(TerminateError::AlreadyTerminated);
        }
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
    admission: &Arc<RwLock<StreamAdmissionTracker>>,
    origin_admission: &Arc<RwLock<OriginAdmissionTracker>>,
    params: &OpenStreamParams,
) -> Result<(), OpenStreamRejection> {
    let admission_outcome = {
        // LOCK ORDER (§05-contexts.md:448 split): the per-context
        // `admission` lock is ALWAYS acquired before the operator-scoped
        // `origin_admission` lock. `origin_admission` is a single leaf
        // lock always taken innermost, so no acquisition cycle is
        // possible even under concurrent opens across different contexts.
        // Holding both across `try_admit` keeps the 3-tier check-and-
        // increment a single atomic critical section (partial increments
        // across tiers are forbidden).
        let mut guard = admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut origin_guard = origin_admission
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.try_admit(
            &mut origin_guard,
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
fn release_admission(
    admission: &Arc<RwLock<StreamAdmissionTracker>>,
    origin_admission: &Arc<RwLock<OriginAdmissionTracker>>,
    params: &OpenStreamParams,
) {
    // Same LOCK ORDER as `run_admission_gate`: per-context `admission`
    // first, operator-scoped `origin_admission` second.
    let mut guard = admission
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut origin_guard = origin_admission
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.release(
        &mut origin_guard,
        &params.invoker_did,
        &params.origin_invoker_did,
        &params.identity.outlet_id,
    );
}

/// The durable counter reservation a streaming open commits at the FINAL
/// open-time gate.
///
/// R4 HIGH-1 / HIGH-2 — committed after the pump permit is acquired AND
/// `invoke_outlet` returns `Ok`, not in the early synchronous hook.
///
/// HIGH-2: the durable `CaveatCounterStore` CAS used to commit inside the
/// open-time hook (before pump-permit acquisition + executor launch). A
/// rejected open that failed LATER (`StreamCapExhausted` at the pump permit,
/// or an `invoke_outlet` error) never reverted that commit, so each rejected
/// open permanently burned `max_calls` / `rate_window` / `amount_cumulative`
/// capacity — a `DoS` where saturating the node pump ceiling could exhaust a
/// victim's authorization. The fix moves the CAS to the last gate: it commits
/// ONLY when the open will actually succeed, so a `StreamCapExhausted` /
/// `invoke_outlet` failure leaves the counters untouched.
///
/// Cumulative-value cap reserve: a stream emits up to its EFFECTIVE billable
/// ceiling (`min(max_calls, floor(cap / cost_per_chunk))`, the §5.4.5:758
/// ceiling AND-folded with the value cap — no grant can raise it), so the cap
/// must be reserved over the WORST-CASE spend at open — NOT over the
/// invoker-declared `estimated_chunk_count`, which the invoker can set as low
/// as `1` while `max_calls = 50` to evade the cap cross-stream. The gate
/// RESERVES
/// [`super::stream::cumulative_reserve_amount`]
/// (`cost_per_chunk × effective_max_billable_chunks`, `<= cap` by construction)
/// against the [`CaveatKind::AmountCumulative`] counter; close-time settlement
/// releases the unspent `reserved − billed_count × cost_per_chunk` via
/// [`crate::trust::CaveatCounterApi::release`]. The invariant: a stream can
/// never bill more cumulative value than it reserved here.
pub struct StreamCounterReservation {
    /// The durable per-(context, ucan) caveat counter store.
    pub counter_store: Arc<dyn crate::trust::CaveatCounterApi>,
    /// The VALIDATED-NARROWED effective caveats (the same set bound at open).
    /// Only the counter-bearing fields (`max_calls`, `amount_max_cumulative`,
    /// `rate_window`) are consulted here.
    pub caveats: scp_protocol::trust::caveats::InvocationCaveats,
}

/// Outcome of committing the durable counter reservation at the final gate.
struct CounterCommitOutcome {
    /// The cumulative amount RESERVED against the `AmountCumulative` counter —
    /// the WORST-CASE billable spend from
    /// [`super::stream::cumulative_reserve_amount`]
    /// (`cost_per_chunk × effective_max_billable_chunks`, `<= cap` by
    /// construction). Recorded so close-time settlement releases the unspent
    /// portion (`reserved − billed_count × cost_per_chunk`). `0` when the cap is
    /// absent or `cost_per_chunk == 0`.
    amount_cumulative_reserved: u64,
    /// The invoker-declared `estimated_chunk_count` the open bounded. Carried
    /// for diagnostics / event reporting only — close-time reconciliation is
    /// now AMOUNT-based (`unspent = reserved − billed_count × cost_per_chunk`),
    /// so this is NOT the chunk count the reserve was computed over.
    reserved_chunks: u32,
}

/// Commits the durable counter CAS for a streaming open at the FINAL gate.
///
/// Order is fixed `max_calls → amount_max_cumulative → rate_window` so the
/// rejection slug stays deterministic when more than one counter caveat would
/// fail — mirroring the non-streaming `build_post_input_hook` OUT-021 branch.
///
/// On the FIRST genuinely-exhausted counter this returns the precise
/// `OpenStreamRejection::CaveatPostInputViolation { slug }`. Any counters
/// already incremented earlier in the same call are rolled back via
/// [`crate::trust::CaveatCounterApi::release`] so a partial commit never
/// leaves capacity stranded (e.g. `max_calls` committed, then
/// `amount_cumulative` exhausted → release the `max_calls` increment).
///
/// Cumulative-cap reserve: the `AmountCumulative` charge is the WORST-CASE
/// billable spend from
/// [`super::stream::cumulative_reserve_amount`] —
/// `cost_per_chunk × effective_max_billable_chunks` (the §5.4.5:758 ceiling
/// AND-folded with `floor(cap / cost)`), `<= cap` by construction. It is
/// deliberately INDEPENDENT of the invoker-declared `estimated_chunk_count`
/// (`estimated_chunk_count` still drives ESCROW reserve and the per-grant escrow
/// top-up, but the durable cumulative cap reserves the worst case so a small
/// declared estimate can never under-count the cap). The same effective ceiling
/// is pinned into the `CreditTracker`, so the per-chunk gate physically blocks
/// billing past it — the reserve and the runtime billing ceiling agree.
async fn commit_counter_reservation(
    reservation: &StreamCounterReservation,
    context_id: &str,
    ucan_cid: &str,
    cost_per_chunk: Amount,
    estimated_chunk_count: u32,
) -> Result<CounterCommitOutcome, OpenStreamRejection> {
    use scp_protocol::trust::CaveatKind;

    let store = reservation.counter_store.as_ref();
    let caveats = &reservation.caveats;
    let mut max_calls_committed = false;
    let mut amount_cumulative_reserved: u64 = 0;

    // 1. max_calls — one invocation (the open) per counter increment.
    if let Some(max) = caveats.max_calls
        && let Err(err) = store
            .check_and_increment(context_id, ucan_cid, CaveatKind::MaxCalls, 1, max, 0)
            .await
    {
        return Err(counter_error_to_open_rejection(&err));
    }
    if caveats.max_calls.is_some() {
        max_calls_committed = true;
    }

    // 2. amount_max_cumulative — RESERVE the WORST-CASE billable spend, NOT
    //    the invoker-declared `estimated_chunk_count`. The declared estimate is
    //    invoker-controlled and may be as low as 1 even when `max_calls = 50`,
    //    so reserving over it lets a stream bill up to its effective ceiling
    //    while the cumulative cap is debited for only the tiny declared estimate
    //    — the cap is evaded cross-stream. `cumulative_reserve_amount` instead
    //    reserves `cost_per_chunk × effective_max_billable_chunks` (the
    //    §5.4.5:758 ceiling AND-folded with `floor(cap / cost)`), which is
    //    `<= cap` by construction. The same effective ceiling is pinned into the
    //    `CreditTracker` (`build_shared_state`), so the per-chunk gate physically
    //    blocks billing past it. Close-time settlement releases the unspent
    //    portion, so the counter ends at exactly the billed spend. The
    //    invariant: a stream can never bill more cumulative value than it
    //    reserved here.
    if let Some(reserve) = cumulative_reserve_amount(cost_per_chunk, caveats)
        && let Some(max) = caveats.amount_max_cumulative
    {
        if let Err(err) = store
            .check_and_increment(
                context_id,
                ucan_cid,
                CaveatKind::AmountCumulative,
                reserve,
                max.value(),
                0,
            )
            .await
        {
            // Roll back the max_calls increment so the rejected open
            // leaves NO counter consumed.
            if max_calls_committed {
                let _ = store
                    .release(context_id, ucan_cid, CaveatKind::MaxCalls, 1)
                    .await;
            }
            return Err(counter_error_to_open_rejection(&err));
        }
        amount_cumulative_reserved = reserve;
    }

    // 3. rate_window — admission by count within the sliding window.
    if let Some(window) = caveats.rate_window
        && let Err(err) = store
            .check_and_increment(
                context_id,
                ucan_cid,
                CaveatKind::RateWindow,
                0,
                u64::from(window.max),
                window.window_secs,
            )
            .await
    {
        // Roll back the earlier increments (max_calls + cumulative reserve)
        // so the rejected open leaves NO counter consumed.
        if max_calls_committed {
            let _ = store
                .release(context_id, ucan_cid, CaveatKind::MaxCalls, 1)
                .await;
        }
        if amount_cumulative_reserved > 0 {
            let _ = store
                .release(
                    context_id,
                    ucan_cid,
                    CaveatKind::AmountCumulative,
                    amount_cumulative_reserved,
                )
                .await;
        }
        return Err(counter_error_to_open_rejection(&err));
    }

    Ok(CounterCommitOutcome {
        amount_cumulative_reserved,
        reserved_chunks: estimated_chunk_count,
    })
}

/// Test-only re-export of [`commit_counter_reservation`].
///
/// Lets the `stream_caveat_post_input_tests` in the manager module drive the
/// final-gate CAS exactly as `open_stream_session`'s Step 5.5 does, without
/// standing up a full stream open.
///
/// # Errors
///
/// Returns [`OpenStreamRejection::CaveatPostInputViolation`] when a
/// counter-bearing caveat is exhausted, mirroring the production gate.
#[cfg(test)]
pub async fn commit_counter_reservation_for_test(
    reservation: &StreamCounterReservation,
    context_id: &str,
    ucan_cid: &str,
    cost_per_chunk: Amount,
    estimated_chunk_count: u32,
) -> Result<(u64, u32), OpenStreamRejection> {
    let outcome = commit_counter_reservation(
        reservation,
        context_id,
        ucan_cid,
        cost_per_chunk,
        estimated_chunk_count,
    )
    .await?;
    Ok((outcome.amount_cumulative_reserved, outcome.reserved_chunks))
}

/// Maps a durable-counter [`CounterError`](crate::trust::CounterError) into the
/// open-time [`OpenStreamRejection::CaveatPostInputViolation`] carrying the
/// precise §7.3.8 slug, so a final-gate counter exhaustion routes identically
/// to the early-hook caveat rejections.
fn counter_error_to_open_rejection(err: &crate::trust::CounterError) -> OpenStreamRejection {
    use scp_protocol::context::outlets::error_codes;

    // Slug choices MIRROR the non-streaming
    // `caveat_counter_error_to_invocation_error` mapping verbatim so the two
    // open paths route identically: MaxCalls -> `authorization.denied`,
    // AmountCumulative -> `authorization.cumulative-exceeded`, RateWindow ->
    // `authorization.rate-exceeded`.
    let slug = match err {
        crate::trust::CounterError::Exhausted(exhausted) => match exhausted {
            crate::trust::CounterExhausted::MaxCalls { .. } => {
                error_codes::SLUG_AUTHORIZATION_DENIED
            }
            crate::trust::CounterExhausted::AmountCumulative { .. } => {
                error_codes::SLUG_AUTHORIZATION_CUMULATIVE_EXCEEDED
            }
            crate::trust::CounterExhausted::RateWindow { .. } => {
                error_codes::SLUG_AUTHORIZATION_RATE_EXCEEDED
            }
        },
        // A storage failure cannot enforce the cap — fail closed as an
        // authorization denial rather than silently admit.
        crate::trust::CounterError::Store(_) => error_codes::SLUG_AUTHORIZATION_DENIED,
    };
    // `slug` is a canonical `&'static str` constant; the variant carries an
    // owned `String` on this branch (see `CaveatPostInputViolation`).
    OpenStreamRejection::CaveatPostInputViolation {
        slug: slug.to_owned(),
    }
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
/// `crates/scp-ffi/src/outlet_stream.rs::outlet_stream_open` and
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

/// Builds the §5.4.5 open-time [`StreamEscrow`] ledger from the hold the
/// caller has ALREADY reserved (DEBITED) against the invoker's
/// `MemberBudgetTracker` (E2 remediation).
///
/// The `InsufficientFunds` / `Overflow` balance decision moved entirely into
/// [`crate::context::manager::ContextManager::outlet_stream_reserve_escrow`]
/// — the only lock holder — so this is now infallible: it records the
/// pinned `cost_per_chunk` (for per-grant top-ups and per-chunk accrual)
/// and the manager-debited `reserved_escrow`. For Query / zero-cost
/// outlets the manager returns `reserved == 0` and this builds the
/// zero-escrow shape.
const fn reserve_escrow(params: &OpenStreamParams) -> StreamEscrow {
    if params.cost_per_chunk.value() == 0 {
        return StreamEscrow::zero_escrow();
    }
    StreamEscrow::from_reserved(params.cost_per_chunk, params.reserved_escrow)
}

/// Builds the shared per-stream state mutex. Owns the four trackers,
/// the admission release keys, and the timer-arming state.
fn build_shared_state(
    params: &OpenStreamParams,
    escrow: StreamEscrow,
    admission: &Arc<RwLock<StreamAdmissionTracker>>,
    origin_admission: &Arc<RwLock<OriginAdmissionTracker>>,
    context_handle: ContextHandle,
) -> Arc<RwLock<SharedSessionState>> {
    // §5.4.5:758 HARD billable-chunk ceiling = the EFFECTIVE ceiling: the
    // VALIDATED-NARROWED `caveats.max_calls` AND-folded with the
    // `amount_max_cumulative` value cap (`floor(cap / cost_per_chunk)`). `None`
    // = unbounded (no `max_calls` AND no value-cap constraint). Folding the
    // value cap in here is what physically prevents a stream from billing more
    // cumulative value than the cap permits: the per-chunk gate terminates the
    // stream once `billed_emitted` reaches this ceiling, regardless of available
    // credit — so an invoker who declared a tiny `estimated_chunk_count` still
    // cannot bill past `floor(cap / cost)` chunks. The `params.caveats` here are
    // the post-narrowing effective caveats (`TokenNbCaveatResolver`).
    let max_billable: Option<u32> =
        effective_max_billable_chunks(params.cost_per_chunk, &params.caveats);
    let credit = CreditTracker::new(
        params.credit_window,
        params.invoker_pk,
        params.identity.clone(),
        max_billable,
    );
    let cancel_ack = CancelAckTracker::new(params.stream_cancel_ack_secs);
    let admission_release_keys = AdmissionReleaseKeys {
        invoker_did: params.invoker_did.clone(),
        origin_invoker_did: params.origin_invoker_did.clone(),
        outlet_id: params.identity.outlet_id.clone(),
    };
    Arc::new(RwLock::new(SharedSessionState {
        credit,
        escrow,
        cancel_ack,
        admission: Arc::clone(admission),
        origin_admission: Arc::clone(origin_admission),
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
        pump_exited: false,
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
    /// Sink that performs the §5.4.5 close-time economic settlement
    /// exactly once at terminal-chunk emission (E1 remediation): refund
    /// the unspent escrow, issue the §19.15.5 `PaymentReceipt`, and append
    /// the close event. Fired under the same `pump_exited` gate as the
    /// event sink so it cannot double-settle. `None` disables settlement
    /// (legacy / test callers without a `ContextManager` handle).
    pub settlement_sink: Option<Arc<dyn StreamSettlementSink>>,
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
    /// §5.4.5 MED-HIGH — economic policy snapshotted at acceptance.
    /// Carried into the [`StreamSettlement`] the pump emits so close-time
    /// settlement survives a mid-stream context teardown. `None` for
    /// zero-cost / Query / legacy callers.
    pub economic_policy_snapshot: Option<super::invoke::EconomicPolicySnapshot>,
    /// R4 HIGH-1 — the open-time cumulative-counter reserve, carried into the
    /// [`StreamSettlement`] so close-time settlement releases the unspent
    /// portion back to the durable counter.
    pub counter_reserve: CounterReserveSettlement,
}

/// The open-time cumulative-counter reservation the close-time settlement
/// uses to release the unspent reserve (R4 HIGH-1).
///
/// Carries the data needed to give back the UNSPENT portion of a stream's
/// reserved [`CaveatKind::AmountCumulative`](scp_protocol::trust::CaveatKind)
/// charge at settlement.
///
/// At the open-time final gate the runtime reserves the WORST-CASE billable
/// spend `amount_cumulative_reserved` (= `cost_per_chunk ×
/// effective_max_billable_chunks`, `<= cap` by construction) against the
/// cumulative counter ([`commit_counter_reservation`] via
/// [`super::stream::cumulative_reserve_amount`]). At
/// close the stream billed only `billed_count` chunks, so
/// `amount_cumulative_reserved − billed_count × cost_per_chunk` (saturating) is
/// given back to the counter — the cap ends up debited by exactly the billed
/// spend, regardless of how small the declared estimate was.
#[derive(Debug, Clone)]
pub struct CounterReserveSettlement {
    /// The worst-case cumulative amount reserved at open (`0` when no cap / no
    /// store / `cost_per_chunk == 0`).
    pub amount_cumulative_reserved: u64,
    /// Invoker-declared `estimated_chunk_count` (diagnostics / event field
    /// only). NOT the count the reserve was computed over — the reserve is the
    /// worst-case spend and the close-time release reconciles by AMOUNT.
    pub reserved_chunks: u32,
    /// Opening UCAN CID — the cumulative counter's key.
    pub ucan_cid: String,
    /// Per-billable-chunk cost — the unit the release multiplies by.
    pub cost_per_chunk: Amount,
}

impl CounterReserveSettlement {
    /// A reserve that releases nothing — for zero-cost / Query streams and
    /// legacy / test callers with no durable counter reservation.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            amount_cumulative_reserved: 0,
            reserved_chunks: 0,
            ucan_cid: String::new(),
            cost_per_chunk: Amount::new(0),
        }
    }

    /// The UNSPENT portion of the open-time worst-case reserve to release back
    /// to the durable `AmountCumulative` counter at close: `reserved −
    /// billed_count × cost_per_chunk` (saturating). After the release the
    /// counter is debited by exactly the billed cumulative spend, regardless of
    /// the (worst-case) amount reserved at open.
    ///
    /// AMOUNT-based, so it is correct regardless of the effective ceiling the
    /// open reserved over (`cost × effective_max_billable_chunks`). A degenerate
    /// `billed_count × cost_per_chunk` overflow FAILS CLOSED — releases nothing,
    /// leaving the counter conservatively over-charged (never under-charged).
    #[must_use]
    pub fn unspent_release_amount(&self, billed_count: u32) -> u64 {
        u64::from(billed_count)
            .checked_mul(self.cost_per_chunk.value())
            .map_or(0, |billed_amount| {
                self.amount_cumulative_reserved
                    .saturating_sub(billed_amount)
            })
    }
}

/// §5.4.5 LOW (stranded-hold guard) — a `Drop`-time safety net that runs
/// the escrow settlement if the pump body unwinds (panics) before reaching
/// its normal settlement block.
///
/// The pump's normal close path settles the escrow, marks `pump_exited`,
/// and fires the settlement sink. A panic anywhere in the pump body would
/// otherwise skip ALL of that — the open-time escrow hold (already DEBITED
/// against the invoker's `MemberBudgetTracker`) would never be refunded,
/// stranding the hold permanently. This guard lives on the pump task's
/// stack: on a panic the stack unwinds through its `Drop`, which — if the
/// normal settlement has NOT already run (`settled == false`) — fires the
/// settlement sink with the current escrow state so the unspent hold is
/// refunded (budget net zero for an un-billed panic).
///
/// On the normal close path the pump sets [`Self::settled`] `= true` after
/// the settlement block completes, so `Drop` is a no-op and the escrow is
/// never double-settled.
///
/// Pairs with the `catch_unwind` wrapper at the spawn site
/// ([`spawn_pump_task`]): the wrapper contains the panic so the task does
/// not abort the runtime and the owned pump permit drops cleanly, while
/// THIS guard performs the economic refund as the stack unwinds.
struct PumpEscrowGuard {
    /// Shared session state — the escrow ledger + `pump_exited` flag.
    state: Arc<RwLock<SharedSessionState>>,
    /// Settlement sink fired on the panic path (same sink the normal close
    /// uses). `None` disables panic-path settlement (legacy / test callers
    /// without a `ContextManager` handle — the escrow ledger is still
    /// surfaced via `StreamCloseSummary` on the normal path, and a panic
    /// without a sink has no economic hold to strand).
    settlement_sink: Option<Arc<dyn StreamSettlementSink>>,
    /// Settlement inputs needed to build the `StreamSettlement` on the
    /// panic path. Cloned at pump start so the guard owns them
    /// independently of `event_inputs` (which is consumed by the normal
    /// settlement block).
    context_id: String,
    invoker_did: DID,
    request_id: RequestId,
    outlet_id: OutletId,
    economic_policy_snapshot: Option<super::invoke::EconomicPolicySnapshot>,
    /// R4 HIGH-1 — the open-time cumulative-counter reserve, so the panic-path
    /// settlement also releases the unspent reserve back to the counter.
    counter_reserve: CounterReserveSettlement,
    /// `true` once the normal settlement block has run. When set, `Drop` is
    /// a no-op (the escrow was already settled exactly once).
    settled: bool,
}

impl Drop for PumpEscrowGuard {
    fn drop(&mut self) {
        if self.settled {
            // Normal close already settled — nothing to do.
            return;
        }
        // Panic path: the pump body unwound before its settlement block.
        // Settle the escrow now so the open-time hold is refunded rather
        // than stranded. Guard against double-settle via `pump_exited`
        // under the lock — a concurrent terminate that observed
        // `pump_exited == false` cannot have run settlement.
        let settlement = {
            let mut guard = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.pump_exited {
                // Settlement already ran (or is running) elsewhere.
                return;
            }
            let (billed_amount, refund_amount, billed_count) = guard.escrow.settle_at_close();
            guard.pump_exited = true;
            let reserved = scp_protocol::economy::types::Amount::new(
                billed_amount.value().saturating_add(refund_amount.value()),
            );
            StreamSettlement {
                context_id: self.context_id.clone(),
                invoker_did: self.invoker_did.clone(),
                reserved,
                billed_amount,
                refund_amount,
                billed_count,
                request_id: self.request_id,
                outlet_id: self.outlet_id.clone(),
                economic_policy_snapshot: self.economic_policy_snapshot.clone(),
                // R4 HIGH-1 — release the unspent cumulative reserve on the
                // panic path too (billed_count is whatever the escrow ledger
                // recorded before the unwind).
                amount_cumulative_reserved: self.counter_reserve.amount_cumulative_reserved,
                reserved_chunks: self.counter_reserve.reserved_chunks,
                ucan_cid: self.counter_reserve.ucan_cid.clone(),
                cost_per_chunk: self.counter_reserve.cost_per_chunk,
            }
        };
        if let Some(sink) = self.settlement_sink.as_ref() {
            // `settle` is non-blocking (spawns the async reconcile onto a
            // runtime handle), so firing it from a `Drop` is safe.
            tracing::warn!(
                request_id = %hex::encode(self.request_id),
                outlet_id = %self.outlet_id,
                "outlet stream pump panicked — refunding escrow via the stranded-hold guard"
            );
            sink.settle(settlement);
        }
    }
}

/// Spawns the streaming pump task. Owns the `inner_rx` (chunks coming
/// from the executor pump) and the `outer_tx` (chunks delivered to the
/// caller).
#[allow(clippy::too_many_arguments)]
fn spawn_pump_task(
    state: Arc<RwLock<SharedSessionState>>,
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
        // §5.4.5 LOW (stranded-hold guard): wrap the pump body in
        // `catch_unwind` so a panic in the OUTER pump (NOT the executor,
        // which is already guarded) is contained at the task boundary —
        // the task does not abort the runtime and the owned `_pump_permit`
        // above drops cleanly. The economic refund on the panic path is
        // performed by the `PumpEscrowGuard` inside `run_stream_pump_v2`
        // as the stack unwinds; this wrapper only contains the panic and
        // logs it. `AssertUnwindSafe` is sound here: the only state shared
        // across the unwind boundary is the `Arc<RwLock<_>>` session state,
        // which the guard re-locks and leaves consistent
        // (`pump_exited == true`, escrow settled) before the unwind
        // completes.
        let pump = std::panic::AssertUnwindSafe(run_stream_pump_v2(
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
        ));
        if futures::future::FutureExt::catch_unwind(pump)
            .await
            .is_err()
        {
            tracing::error!(
                request_id = %hex::encode(request_id),
                "outlet stream pump panicked — escrow refunded by the stranded-hold guard; \
                 stream closed"
            );
        }
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
#[allow(clippy::too_many_lines)] // §5.4.5 ordered open sequence (binding → admission → estimate → caveat hook → escrow → permit → spawn); splitting masks the spec ordering
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
    // §5.4.5 close-time economic settlement (E1). Fired once at terminal
    // chunk to refund unspent escrow + issue the §19.15.5 PaymentReceipt +
    // append the close event. `None` for legacy / test callers without a
    // `ContextManager` handle.
    settlement_sink: Option<Arc<dyn StreamSettlementSink>>,
    params: OpenStreamParams,
    admission: Arc<RwLock<StreamAdmissionTracker>>,
    // §05-contexts.md:448: the operator-scoped origin admission tracker,
    // a SINGLE instance the supervisor owns and shares across every
    // context it hosts. Carries the per-origin-invoker dimension so a
    // caller cannot fan out across N of the operator's contexts to open
    // `N × per_origin_invoker` streams. Consulted alongside the
    // per-context `admission` tracker in `run_admission_gate` /
    // `release_admission` and stored in `SharedSessionState` for the
    // pump's close-time release.
    origin_admission: Arc<RwLock<OriginAdmissionTracker>>,
    // §5.4.5 round-8 (F5): the per-instance node-level concurrent-pump
    // semaphore. A permit is acquired AFTER all per-context gates pass
    // (admission / estimate / escrow / binding) and moved into the spawned
    // pump task so it drops exactly when the pump exits. Saturation
    // hard-rejects with `OpenStreamRejection::StreamCapExhausted` and rolls
    // back the admission counters this open consumed.
    pump_semaphore: Arc<tokio::sync::Semaphore>,
    // §7.3.8 caveat post-input check (crypto-MED). A stream validates its
    // input ONCE at open (§5.4.5), so this hook — built exactly as the
    // non-streaming `invoke` path builds it (`amount_max_per_call` /
    // `allowed_adapters` / `allowed_target_dids` / `input_schema` +
    // counter-store CAS for `max_calls` / `amount_max_cumulative` /
    // `rate_window`) — runs ONCE at the open-time validation point, BEFORE
    // the pump spawns. `None` for callers that do not enforce §7.3.8
    // caveats at open (legacy / test paths; bridge call sites pass `None`
    // until Phase 2 wires the builder). On failure the open is rejected
    // with `OpenStreamRejection::CaveatPostInputViolation` carrying the
    // precise slug.
    caveat_post_input_check: Option<super::invoke::CaveatPostInputCheck<'_>>,
    // R4 HIGH-1 / HIGH-2: the durable counter reservation, committed at the
    // FINAL open-time gate (after pump-permit acquisition AND `invoke_outlet`
    // returns `Ok`) rather than in the early `caveat_post_input_check` hook.
    // `None` for callers without a counter store (legacy / test paths, and
    // any open whose effective caveats carry no counter-bearing cap). When
    // `Some`, `commit_counter_reservation` performs the `max_calls` /
    // `amount_max_cumulative` (RESERVED at `cost_per_chunk × est_chunks`) /
    // `rate_window` CAS and returns the reserved cumulative amount for the
    // close-time release. A failure here rolls back admission + drops the
    // pump permit so no capacity is stranded by a rejected open.
    counter_reservation: Option<StreamCounterReservation>,
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
    run_admission_gate(&admission, &origin_admission, &params)?;

    // Step 2: estimated_chunk_count coercion + bound.
    let estimated_chunk_count =
        coerce_estimated_chunk_count(params.declared_estimated_chunk_count, &params.caveats);
    if let Err(open_err) = enforce_estimated_chunk_count_bound(
        estimated_chunk_count,
        params.credit_window,
        &params.caveats,
    ) {
        release_admission(&admission, &origin_admission, &params);
        return Err(match open_err {
            OpenError::EstimateExceedsBound => {
                let _ = open_error_to_slug(open_err);
                OpenStreamRejection::EstimateExceedsBound
            }
        });
    }

    // Step 2.5 (§7.3.8 caveat post-input check, crypto-MED): a stream
    // validates its input ONCE at open. Run the §7.3.8 hook — built the
    // same way the non-streaming `invoke` path builds it — at this single
    // open-time validation point, BEFORE escrow reservation and the pump
    // spawn. This is the only locus where the §7.3.8 synchronous local
    // checks (`amount_max_per_call`, `allowed_adapters`,
    // `allowed_target_dids`, `input_schema`) and the counter-store CAS
    // (`max_calls`, `amount_max_cumulative`, `rate_window`) run for a
    // stream; per-chunk re-validation is neither performed nor required
    // (§5.4.5 "checked ONCE at open"). On rejection, roll back the
    // admission counters this open consumed (mirroring the
    // estimate-bound path) and surface the precise slug.
    if let Some(check) = caveat_post_input_check
        && let Err(invocation_err) = check(&input).await
    {
        release_admission(&admission, &origin_admission, &params);
        // The §7.3.8 hook returns `CaveatViolation { slug }` for caveat
        // rules and `InputValidationFailed` for schema failures. Map both
        // to the open-time caveat-violation rejection carrying the precise
        // slug so the FFI / SDK surface routes identically to the
        // non-streaming path.
        // `CaveatViolation.slug` is an owned `String` on this branch, so the
        // arms yield `String` (the schema / default arms allocate their
        // canonical constant) to preserve the precise rule slug verbatim.
        let slug: String = match invocation_err {
            InvocationError::CaveatViolation { slug, .. } => slug,
            InvocationError::InputValidationFailed { .. } => {
                error_codes::SLUG_INPUT_SCHEMA_VIOLATION.to_owned()
            }
            // Any other variant from the hook is an authorization-class
            // denial by §5.4.4 default routing.
            _ => error_codes::SLUG_AUTHORIZATION_DENIED.to_owned(),
        };
        return Err(OpenStreamRejection::CaveatPostInputViolation { slug });
    }

    // Step 3: escrow ledger from the manager-debited hold (E2). The
    // InsufficientFunds / Overflow decision already happened in the
    // manager's `outlet_stream_reserve_escrow` under the context lock —
    // this just records the debited `reserved_escrow` on the ledger.
    let escrow = reserve_escrow(&params);

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
            release_admission(&admission, &origin_admission, &params);
            return Err(OpenStreamRejection::StreamCapExhausted);
        }
    };

    // Step 4: tracker init. Snapshot a cheap (Arc-backed) clone of the
    // context handle so the pump can consult live lifecycle state for
    // the §5.4.5 round-8 context-teardown re-check.
    let shared = build_shared_state(
        &params,
        escrow,
        &admission,
        &origin_admission,
        context.clone(),
    );
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
    // ourselves in the pump settlement block from the outer pump's
    // incremental `MerkleFrontier` (manifest_root + manifest_billed).
    let input_hash = scp_protocol::context::outlets::lifecycle::sha256_json(&input);
    let event_context_id = context.context_id().to_owned();
    let event_outlet_id: OutletId = outlet_id.clone();
    let event_invoker_did: DID = invoker_did.clone();
    let pump_start = Instant::now();
    // §5.4.5 MED-HIGH — clone the open-time economic policy snapshot so the
    // pump's settlement can capture the receipt even if the context is torn
    // down mid-stream. Cloned here (before `params` fields are consumed by
    // the spawn) so it travels with the pump's event-emission inputs.
    let economic_policy_snapshot = params.economic_policy_snapshot.clone();

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
        release_admission(&admission, &origin_admission, &params);
        let _ = err;
        OpenStreamRejection::AdmissionRateLimited {
            slug: error_codes::SLUG_TRANSPORT_RATE_LIMITED,
        }
    })?;

    // Step 5.5 (R4 HIGH-1 / HIGH-2): commit the durable counter CAS HERE —
    // the LAST open-time gate, after the pump permit was acquired AND
    // `invoke_outlet` returned `Ok`. Committing earlier (in the synchronous
    // `caveat_post_input_check` hook) burned `max_calls` / `amount_cumulative`
    // / `rate_window` capacity on opens that then failed at the pump-permit
    // (`StreamCapExhausted`) or executor-launch gate, with no compensating
    // revert — a DoS vector. By the time we reach here both later gates have
    // already passed, so a successful CAS commits exactly once for an open
    // that WILL run; a genuine counter exhaustion at this gate rolls back
    // admission and drops the pump permit (returning early drops the owned
    // `pump_permit` before it is moved into the pump task), leaving the node
    // ceiling slot free. HIGH-1: the cumulative reserve is
    // `cost_per_chunk × estimated_chunk_count`, returned here so the pump's
    // settlement can release the unspent portion at close.
    let counter_commit = match counter_reservation.as_ref() {
        Some(reservation) => commit_counter_reservation(
            reservation,
            context.context_id(),
            &params.ucan_cid,
            params.cost_per_chunk,
            estimated_chunk_count,
        )
        .await
        .inspect_err(|rejection| {
            // CAS genuinely exhausted (or storage failed): roll back the
            // admission slot this open consumed and let `pump_permit` drop
            // here (it has not yet been moved into the pump task), freeing
            // the node-level concurrent-pump slot.
            //
            // §7.3.8 / §5.4.5 fail-closed denial. Emit an alertable
            // `tracing::warn!` (symmetric with the settlement-failure
            // logging) so defenders can detect a stream open denied by a
            // counter exhaustion or counter-store fault. ADR-049 §4: log
            // only the registered `outlet_id` slug + `context_id` and the
            // rejection's static slug — NEVER the UCAN token or input bytes.
            tracing::warn!(
                context_id = %context.context_id(),
                outlet_id = %params.identity.outlet_id,
                slug = rejection.slug(),
                "outlet stream open denied: durable counter CAS exhausted or \
                 counter-store fault — rejected fail-closed (§7.3.8 / §5.4.5)"
            );
            release_admission(&admission, &origin_admission, &params);
        })?,
        None => CounterCommitOutcome {
            amount_cumulative_reserved: 0,
            reserved_chunks: estimated_chunk_count,
        },
    };

    // R4 HIGH-1 — bundle the open-time cumulative reserve so the pump's
    // close-time settlement can release the unspent portion back to the
    // durable counter. Captured before `params` fields are consumed by the
    // spawn below.
    let counter_reserve = CounterReserveSettlement {
        amount_cumulative_reserved: counter_commit.amount_cumulative_reserved,
        reserved_chunks: counter_commit.reserved_chunks,
        ucan_cid: params.ucan_cid.clone(),
        cost_per_chunk: params.cost_per_chunk,
    };

    // §5.4.5 binding-pinning: the runtime uses the SDK-supplied
    // `request_id` (the same value the SDK committed to in the
    // `caveats_binding` preimage) rather than generating a fresh one.
    // The pre-acceptance recompute above already verified the SDK
    // supplied the right binding for this `request_id`; using a
    // runtime-generated id here would have made the binding check
    // structurally impossible.
    let request_id: RequestId = params.request_id;

    // Fix-D — persist the durable crash-recovery record NOW: both open-time
    // reservations are durable (the escrow hold was debited on the mailbox
    // during `reserve_outlet_stream_economy`; the §7.3.8 cumulative counter was
    // just reserved at Step 5.5 above), and the long-lived off-mailbox pump is
    // about to spawn. The pump is a SEPARATE `tokio` task that SURVIVES an actor
    // crash + respawn — its close-time settle then lands on the bumped
    // generation and is dropped — so without this record the escrow hold +
    // counter reserve would be stranded on a crash-restore. The restore-time
    // `ReconcileStreamReservations` sweep releases them from this record; the
    // clean close-time settle clears it. Only escrow-or-counter-bearing streams
    // need a record (a zero-cost / Query stream holds no durable reserve).
    //
    // Awaited so the record is durable before the pump bills. Best-effort: a
    // persist hiccup logs and PROCEEDS — the reserves are already durable and
    // the pump's normal settle reconciles them in the common case; only a crash
    // DURING this stream loses the recovery net (the pre-Fix-D behaviour) —
    // rather than denying an otherwise-valid open. (A KEEP-persist error still
    // leaves the record in memory for the run-loop coalesce, so only a true
    // dispatch miss to the just-reserved live context loses it.)
    if let Some(sink) = settlement_sink.as_ref()
        && (params.reserved_escrow.value() > 0 || counter_commit.amount_cumulative_reserved > 0)
    {
        let record = super::invoke::StreamReservationRecord {
            invoker_did: invoker_did.clone(),
            ucan_cid: params.ucan_cid.clone(),
            cost_per_chunk: params.cost_per_chunk,
            amount_cumulative_reserved: counter_commit.amount_cumulative_reserved,
            reserved_escrow: params.reserved_escrow,
            // Stamped by the sink with the reservation's spawn-generation.
            generation: 0,
        };
        if let Err(err) = sink
            .persist_reservation(context.context_id(), request_id, record)
            .await
        {
            tracing::warn!(
                request_id = %hex::encode(request_id),
                "Fix-D: streaming reservation recovery record persist failed \
                 (crash-recovery net unavailable for this stream): {err}"
            );
        }
    }

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
            settlement_sink,
            context_id: event_context_id,
            outlet_id: event_outlet_id,
            invoker_did: event_invoker_did,
            input_hash,
            start: pump_start,
            economic_policy_snapshot,
            counter_reserve,
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
    state: &Arc<RwLock<SharedSessionState>>,
    checker: &(dyn RevocationChecker + Send + Sync),
    ucan_cid: &str,
) -> bool {
    if !checker.is_revoked(ucan_cid) {
        return false;
    }
    let mut guard = state
        .write()
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
/// `context_handle.state()` is a synchronous lock-free `ArcSwap` load on
/// this branch (ADR-049 §Decision 12); the call runs in the pump's re-check
/// select arm OUTSIDE the session lock. On teardown we re-acquire the lock
/// just long enough to mutate `pending_terminate`, matching the
/// `try_arm_revoked_mid_stream` pattern.
// `async` for API parity with `run_revocation_recheck_tick`'s call site and
// the `try_arm_revoked_mid_stream` sibling; the body emits no `.await` on this
// branch because `ContextHandle::state()` is synchronous here.
#[allow(clippy::unused_async)]
async fn try_arm_context_closed_mid_stream(
    state: &Arc<RwLock<SharedSessionState>>,
    context_handle: &ContextHandle,
) -> bool {
    use crate::context::ContextState;
    let context_state = context_handle.state();
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
        | ContextState::Tombstoned
        // `Poisoned` (ADR-049 §10): the actor exhausted its respawn budget
        // and no actor is serving the context — dormant, not live. A stream
        // running against it cannot continue, so it is a teardown (arms the
        // Protocol-class `ContextClosedMidStream`) exactly like the other
        // non-Active states.
        | ContextState::Poisoned => true,
    };
    if !torn_down {
        return false;
    }
    let mut guard = state
        .write()
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
    state: &Arc<RwLock<SharedSessionState>>,
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
    state: Arc<RwLock<SharedSessionState>>,
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
    // §5.4.5 / ADR-061: fold each emitted (renumbered, re-signed) chunk
    // into the O(log n) RFC-6962 Merkle frontier + O(1) terminal summary
    // as it is emitted — the pump NEVER retains the full payload set for
    // the manifest (ADR-061: "never accumulates the full payload set in
    // memory"). The frontier's billing ceiling is unbounded
    // (`MerkleFrontier::new`): the pump drops `Data` chunks at
    // `sequence >= cancel_ack_seq` at the gate BEFORE they reach
    // `ingest_stream_chunk` (§5.4.5:530(3) — the cancel-ack slot holds the
    // terminal), so every pushed `Data` chunk is STRICTLY below the
    // cancel-ack sequence and the unbounded ceiling yields the same billed
    // count as the pinned one (equivalently,
    // `compute_chunks_billed_ref(emitted_manifest, cancel_ack_seq)` over the
    // emitted set — whose `Data` all sit below the ceiling).
    let mut frontier = scp_protocol::context::outlets::stream::MerkleFrontier::new();
    let mut terminal_summary = super::invoke::StreamTerminalSummary::default();
    let mut next_seq: u64 = 0;
    let mut parked: Option<OutletStreamChunk> = None;

    // §5.4.5 LOW (stranded-hold guard): arm the escrow safety net BEFORE
    // any pump work runs. If the pump body panics, this guard's `Drop`
    // refunds the open-time escrow hold as the stack unwinds. On the
    // normal close path it is disarmed (`settled = true`) after the
    // settlement block, so it never double-settles. Holds an independent
    // clone of the settlement inputs so it is unaffected by
    // `event_inputs` being consumed by the normal settlement block.
    let mut escrow_guard = PumpEscrowGuard {
        state: Arc::clone(&state),
        settlement_sink: event_inputs.settlement_sink.clone(),
        context_id: event_inputs.context_id.clone(),
        invoker_did: event_inputs.invoker_did.clone(),
        request_id,
        outlet_id: event_inputs.outlet_id.clone(),
        economic_policy_snapshot: event_inputs.economic_policy_snapshot.clone(),
        counter_reserve: event_inputs.counter_reserve.clone(),
        settled: false,
    };

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
            .write()
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
                .write()
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
            ingest_stream_chunk(&mut frontier, &mut terminal_summary, &chunk);
            let _ = outer_tx.send(chunk).await;
            break;
        }

        // Calculate timer state.
        let (cancel_ack_armed, credit_stall_armed_at) = {
            let guard = state
                .write()
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
                    ingest_stream_chunk(&mut frontier, &mut terminal_summary, &chunk);
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
                    ingest_stream_chunk(&mut frontier, &mut terminal_summary, &chunk);
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
                    ingest_stream_chunk(&mut frontier, &mut terminal_summary, &chunk);
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
                    ingest_stream_chunk(&mut frontier, &mut terminal_summary, &chunk);
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
                .write()
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
                let terminal = final_chunk.payload.is_terminal();
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
                // §5.4.5:530(3) cancel-boundary atomicity (round-9 F1). The
                // per-chunk gate above ran in an EARLIER `state.write()`
                // window; the operator-signature build between then and here
                // is an off-lock `.await`. An `OutletCancel` delivered on a
                // SEPARATE task (`apply_outlet_cancel_signed`) can acquire the
                // lock DURING that signing await and pin `cancel_ack_seq` at or
                // below this chunk's `seq`. Re-read the LIVE ceiling under the
                // accrual lock and mirror the gate's `>=` drop, so the
                // drop-decision, the escrow/credit bill, the frontier ingest,
                // and the emission-cursor bump are ALL atomic with respect to
                // `record_cancel`. Without this re-check the gate (which saw
                // `ceiling == u64::MAX`) would Forward an in-flight `Data` that
                // the freshly-pinned ceiling now reserves for the terminal
                // cancel-ack chunk — silently over-billing by one and recording
                // a `cancel_ack_seq` the sealed manifest contradicts.
                let dropped = {
                    let mut guard = state
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let g = &mut *guard;
                    if !terminal && seq >= g.cancel_ack.billing_ceiling() {
                        // Drop-and-not-bill, exactly as the gate's
                        // `DropAboveCancelAck` arm would have: NO accrual, NO
                        // frontier ingest, NO forward, and — critically — DO
                        // NOT advance the emission cursor. The terminal
                        // cancel-ack chunk takes this `seq` slot next.
                        true
                    } else {
                        // Advance the emission cursor ONLY for a chunk we will
                        // actually bill/emit — a dropped (or failed-sign) chunk
                        // must not burn a sequence number.
                        next_seq = next_seq.saturating_add(1);
                        accrue_data_chunk_if_billable(&mut g.escrow, &g.cancel_ack, &final_chunk);
                        // §5.4.5:758 cumulative ceiling: advance
                        // `billed_emitted` for THIS forwarded chunk iff it is
                        // billable (Data, at/below the cancel-ack ceiling) —
                        // the SAME `is_billable_chunk` predicate the escrow
                        // accrual above uses, so the cumulative counter and the
                        // escrow ledger can never disagree on what was billed.
                        if super::invoke::is_billable_chunk(
                            &final_chunk,
                            g.cancel_ack.billing_ceiling(),
                        ) {
                            g.credit.record_billed_emission();
                        }
                        // §5.4.5 next-emission-cursor publication — the bridge
                        // layer reads this value to derive the canonical
                        // `cancel_ack_seq` written into `OutletStreamCancel`
                        // preimages (see
                        // `StreamSessionHandle::current_next_emission_seq`).
                        // Bumped under the SAME lock as the bill decision so a
                        // racing `apply_outlet_cancel` either observes the
                        // cursor before this forward (cancel pins the
                        // pre-forward cursor) or after (post-forward cursor),
                        // never half-stamped.
                        g.next_emission_seq = next_seq;
                        false
                    }
                };
                if dropped {
                    // A cancel pinned the ceiling at/below this chunk's slot
                    // during signing. Loop back for the next upstream chunk;
                    // the terminal cancel-ack chunk will occupy `next_seq`
                    // (== the pinned `cancel_ack_seq`).
                    continue;
                }
                ingest_stream_chunk(&mut frontier, &mut terminal_summary, &final_chunk);
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
            StreamGateOutcome::CreditExhausted => {
                // §5.4.5:758 cumulative billable ceiling reached
                // (`min(credit_window, max_calls)`). Drop this chunk
                // (it must NOT be forwarded or billed) and arm a
                // framework-driven terminal `Error{terminal:true}` with
                // `TerminateReason::CreditExhausted`. The loop-top drain
                // signs + emits the synthetic terminal chunk under the
                // pinned operator key on the next iteration, then breaks
                // into settlement — escrow refund, audit event, and
                // admission release all run end-to-end. The slug/code
                // (`execution.credit-exhausted` / `SCP-OUTLET-6131`) are
                // derived from the enum, never caller-controlled.
                {
                    let mut guard = state
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if guard.pending_terminate.is_none() {
                        guard.pending_terminate = Some(PendingTerminate {
                            reason: TerminateReason::CreditExhausted,
                            message_override: None,
                        });
                    }
                }
                // Fall through to the loop top, which drains
                // `pending_terminate` and emits the terminal chunk.
            }
        }
    }

    // Settlement: settle the escrow ledger, record terminal on the
    // cancel-ack tracker, and release admission counters via the
    // public helper in `invoke.rs`.
    let summary = {
        let mut guard = state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (billed_amount, refund_amount, billed_count) = guard.escrow.settle_at_close();
        let cancel_ack_seq = guard.cancel_ack.cancel_ack_seq();
        guard.cancel_ack.record_terminal();
        // Mark the pump's control plane as gone under the same lock as
        // settlement: any `terminate_with_error` racing past this point
        // observes `pump_exited == true` and returns
        // `TerminateError::AlreadyTerminated` rather than arming a
        // `pending_terminate` no consumer will ever drain.
        guard.pump_exited = true;
        // Take both admission Arcs out of the guard so we can release
        // through the invoke.rs public helper (which lifts the type
        // reference into invoke.rs for grep enforcement). The
        // operator-scoped `origin_admission` MUST be decremented here too
        // (§05-contexts.md:448) — else the origin's operator-wide count
        // leaks and permanently caps the origin.
        let admission_arc = Arc::clone(&guard.admission);
        let origin_admission_arc = Arc::clone(&guard.origin_admission);
        let invoker_did_owned = guard.admission_release_keys.invoker_did.clone();
        let origin_invoker_did_owned = guard.admission_release_keys.origin_invoker_did.clone();
        let outlet_id_owned = guard.admission_release_keys.outlet_id.clone();
        drop(guard);
        {
            // Same LOCK ORDER as the open-path gate: per-context
            // `admission` first, operator-scoped `origin_admission` second.
            let mut admission_guard = admission_arc
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut origin_admission_guard = origin_admission_arc
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            release_stream_admission(
                &mut admission_guard,
                &mut origin_admission_guard,
                &invoker_did_owned,
                &origin_invoker_did_owned,
                &outlet_id_owned,
            );
        }
        StreamCloseSummary {
            billed_amount,
            refund_amount,
            billed_count,
            stream_chunk_count: u32::try_from(frontier.leaf_count()).unwrap_or(u32::MAX),
            cancel_ack_seq,
            manifest_root: frontier.root(),
            manifest_billed: u32::try_from(frontier.billed_count()).unwrap_or(u32::MAX),
            terminal_summary,
        }
    };

    // §5.4.5 manifest-derived reference `chunks_billed` (count of `Data`
    // leaves at or below `cancel_ack_seq`). Produced by the RFC-6962
    // Merkle frontier as chunks were emitted (`frontier.billed_count`, now
    // carried on the summary) — the pump drops above-cancel-ack `Data`
    // chunks before ingest, so this equals
    // `compute_chunks_billed_ref(emitted_manifest, cancel_ack_seq)` over
    // the operator-signed emitted set WITHOUT retaining that set. BOTH the
    // audit event AND the money-moving settlement receipt anchor to this
    // SAME value. The pump's running `summary.billed_count` (escrow ledger)
    // agrees on the honest path and diverges only on a runtime
    // self-mismatch — precisely the case where neither the event nor the
    // receipt may out-run the signed manifest.
    let manifest_reference = summary.manifest_billed;

    // §5.4.5 OutletInvokedEvent emission. The dispatch pump owns the
    // outer manifest (renumbered, cancel-ack-truncated) — the only
    // manifest that matches what SDK consumers actually received. We record
    // exactly one event per stream via the `OutletInvokedEventSink::record`
    // trait method, handing it the retained ADR-061 Merkle-frontier
    // commitment. The FULL §5.4.5:566 frontier wire-invariant is enforced
    // ONCE, at the durable log-insert boundary
    // (`ContextEventLogProvider::append_outlet_invoked_verified`, fed this
    // same frontier as its `Frontier` source) — the canonical enforcement
    // path. We do NOT also re-run a near-tautological frontier check inline
    // here (the event was built from this frontier), to avoid a dead
    // duplicate of the append-boundary check.
    if let Some(sink) = event_inputs.sink.as_ref() {
        // §5.4.5 round-8 (F2): on a self-consistency drift between the
        // pump's running `billed_count` (escrow ledger) and the
        // frontier-derived reference, DO NOT drop the event. The previous
        // behaviour silently discarded the audit record, erasing the
        // divergence. Instead we emit the event with `chunks_billed` set to
        // the frontier-derived reference (the appender-accepted value) AND
        // attach an `AuditAnomaly::ChunksBilledSelfMismatch` so the
        // divergence is durably attributable.
        let pump_recorded = summary.billed_count;
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
            summary.stream_chunk_count,
            manifest_reference,
            summary.manifest_root,
            &summary.terminal_summary,
            audit_anomaly,
            // §5.4.5:558-566 — the pinned cancel-ack sequence (the billing
            // ceiling) written into the event alongside `stream_terminal_status`.
            // `None` when the stream terminated without a cancel-ack.
            summary.cancel_ack_seq,
        );
        // The retained ADR-061 frontier commitment (root + billable/leaf
        // counts) the pump folded over the emitted sequence. The durable sink
        // routes this into `append_outlet_invoked_verified` as the `Frontier`
        // source, so the FULL §5.4.5:566 equality (`stream_manifest_hash ==
        // root`, `chunks_billed == billed_count`, `stream_chunk_count ==
        // leaf_count`) plus the durable event-local `<=` backstop both fire at
        // the real log-insert boundary — against the frontier the pump built,
        // not the event's self-reported fields.
        let manifest = super::invoke::StreamManifestCommitment {
            root: summary.manifest_root,
            billed_count: u64::from(manifest_reference),
            leaf_count: u64::from(summary.stream_chunk_count),
        };
        sink.record(event, manifest);
    }

    // §5.4.5 close-time economic settlement (E1). Fire the settlement sink
    // EXACTLY ONCE, AFTER event emission. The `pump_exited` flag set in the
    // settlement block above gates double-settlement: this code path runs
    // only when the pump loop has broken (terminal chunk, channel close, or
    // forced terminate), and the pump body runs once per spawn.
    //
    // `reserved == billed_amount + refund_amount` (the total hold the
    // manager debited at open + grants); the sink refunds `refund_amount`
    // so net spent == `billed_amount`, issues the §19.15.5 PaymentReceipt
    // for `billed_amount`, and appends the close event. For a zero-cost /
    // Query stream all three amounts are zero and the sink's refund + receipt
    // are no-ops.
    if let Some(settlement_sink) = event_inputs.settlement_sink.as_ref() {
        let reserved = scp_protocol::economy::types::Amount::new(
            summary
                .billed_amount
                .value()
                .saturating_add(summary.refund_amount.value()),
        );
        // §5.4.5 round-9 (Fix-B, crypto MED) — anchor the RECEIPT to the
        // operator-signed manifest exactly as the OutletInvokedEvent above is.
        // See `anchor_settlement_receipt_to_manifest` for the full rationale.
        let cost_per_chunk = event_inputs.counter_reserve.cost_per_chunk;
        let (manifest_billed_amount, manifest_refund_amount) =
            anchor_settlement_receipt_to_manifest(manifest_reference, cost_per_chunk, reserved);
        settlement_sink.settle(StreamSettlement {
            context_id: event_inputs.context_id.clone(),
            invoker_did: event_inputs.invoker_did.clone(),
            reserved,
            billed_amount: manifest_billed_amount,
            refund_amount: manifest_refund_amount,
            billed_count: manifest_reference,
            request_id,
            outlet_id: event_inputs.outlet_id.clone(),
            // §5.4.5 MED-HIGH — carry the open-time economic snapshot so
            // settlement survives a mid-stream context teardown.
            economic_policy_snapshot: event_inputs.economic_policy_snapshot.clone(),
            // R4 HIGH-1 — carry the open-time cumulative reserve so the
            // manager releases the unspent `(reserved − billed) × cost`
            // portion back to the durable counter at close.
            amount_cumulative_reserved: event_inputs.counter_reserve.amount_cumulative_reserved,
            reserved_chunks: event_inputs.counter_reserve.reserved_chunks,
            ucan_cid: event_inputs.counter_reserve.ucan_cid.clone(),
            cost_per_chunk,
        });
    }

    // Publish the close summary AFTER the event sink + settlement. Tests and
    // economy-layer integrations consume `(billed_amount,
    // refund_amount, billed_count)` here — values the
    // `OutletInvokedEvent` does not carry (per §19.15.5
    // PaymentReceipt).
    let _ = summary_tx.send(summary);

    // §5.4.5 LOW (stranded-hold guard): the normal close path has now run
    // settlement (escrow settled, `pump_exited` set, settlement sink
    // fired). Disarm the guard so its `Drop` is a no-op — the escrow is
    // settled exactly once. Reached only on the normal return path; a
    // panic before this line leaves `settled == false`, so the guard's
    // `Drop` performs the refund as the stack unwinds.
    escrow_guard.settled = true;
}

/// Re-derives the settlement receipt's `(billed_amount, refund_amount)` split
/// from the operator-signed manifest reference count (§5.4.5 Fix-B).
///
/// The settlement receipt is the money-moving, non-repudiation billing
/// artifact — unlike the lower-stakes audit event, it MUST bill only what the
/// operator-signed chunk manifest supports, never the pump's un-verified
/// escrow-ledger self-count. The dispatch pump therefore hands this the
/// frontier-derived `manifest_billed` (the SAME value the event's
/// [`AuditAnomaly::ChunksBilledSelfMismatch`] check keys off) rather than the
/// ledger's running `billed_count`, and this re-derives the billed/refund split
/// from it:
///
/// - `billed = cost_per_chunk × manifest_reference`, with a `cost × count`
///   overflow FAILING CLOSED to `0` (bill nothing rather than a bogus amount),
///   then capped at the total `reserved` hold. The cap ensures the receipt can
///   neither OUT-RUN the manifest (the divergence where the ledger over-counted)
///   NOR exceed the escrow the manager actually debited (the divergence where
///   the manifest over-counts the hold).
/// - `refund = reserved − billed` (saturating), preserving the conservation
///   identity `billed + refund == reserved` in EVERY case, so a corrected
///   (lower) bill returns the difference to the invoker rather than stranding it.
///
/// On the honest path `manifest_reference == ledger billed_count`, so
/// `cost × manifest_reference == ledger billed_amount ≤ reserved` and the result
/// is byte-identical to the escrow ledger's own `settle_at_close` split. Only
/// the runtime-self-mismatch case changes: the receipt follows the signed
/// manifest, not the ledger. Mirrors the money-conservation cap the sink-side
/// [`crate::context::outlets_helpers::settle_outlet_stream`] already applies.
#[must_use]
pub fn anchor_settlement_receipt_to_manifest(
    manifest_reference: u32,
    cost_per_chunk: Amount,
    reserved: Amount,
) -> (Amount, Amount) {
    let billed = Amount::new(
        cost_per_chunk
            .value()
            .checked_mul(u64::from(manifest_reference))
            .unwrap_or(0)
            .min(reserved.value()),
    );
    let refund = Amount::new(reserved.value().saturating_sub(billed.value()));
    (billed, refund)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::match_wildcard_for_single_variants,
    clippy::match_wild_err_arm,
    clippy::significant_drop_in_scrutinee
)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use scp_protocol::context::outlets::stream::ChunkPayload;
    use std::time::Duration;

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn build_test_state() -> Arc<RwLock<SharedSessionState>> {
        build_test_state_with_checker(
            Arc::new(scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new()),
            60,
        )
    }

    fn build_test_state_with_checker(
        revocation_checker: Arc<dyn RevocationChecker + Send + Sync>,
        stream_ucan_recheck_secs: u32,
    ) -> Arc<RwLock<SharedSessionState>> {
        let key = fixed_signing_key();
        let signer: Arc<dyn StreamSigner> =
            Arc::new(super::super::signer::InProcessStreamSigner::new(key));
        let identity = super::super::stream::StreamIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            stream_epoch: 1,
            caveats_binding: [0xAB; 32],
        };
        let credit = CreditTracker::new(32, *signer.verifying_key(), identity, None);
        let cancel_ack = CancelAckTracker::new(5);
        let admission = Arc::new(RwLock::new(StreamAdmissionTracker::new()));
        let origin_admission = Arc::new(RwLock::new(OriginAdmissionTracker::new()));
        // A fresh context handle (in `Creating`) so the F6 round-8
        // context-teardown re-check observes a live context by default —
        // both `Creating` and `Active` are treated as live, so a default
        // stream does not spuriously terminate. Tests that want to
        // exercise teardown transition the handle to a non-Active state.
        let context_handle = ContextHandle::new(
            "ctx-test".to_owned(),
            scp_protocol::context::ContextParams::default(),
        );
        Arc::new(RwLock::new(SharedSessionState {
            credit,
            escrow: super::super::stream::StreamEscrow::zero_escrow(),
            cancel_ack,
            admission,
            origin_admission,
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
            pump_exited: false,
            context_handle,
        }))
    }

    /// §5.4.5 Fix-B (crypto MED) — the settlement RECEIPT (the money-moving,
    /// non-repudiation billing artifact) MUST bill the manifest-derived count,
    /// exactly as the audit event is anchored, NOT the pump's escrow-ledger
    /// self-count. On the honest path the two agree; a runtime self-mismatch is
    /// the ONLY case where they diverge — and it is precisely then that the
    /// receipt must follow the operator-signed manifest, not the ledger.
    ///
    /// This unit-tests `anchor_settlement_receipt_to_manifest` — the pump→sink
    /// boundary logic that re-derives the receipt's `(billed, refund)` split
    /// from the manifest reference — across the honest path and both divergence
    /// directions, since the honest pump keeps ledger and manifest consistent by
    /// construction (a genuine self-mismatch cannot be driven through it, only
    /// simulated by feeding a reference that differs from what the ledger
    /// accrued).
    #[test]
    fn settlement_receipt_anchored_to_manifest_not_ledger_self_count() {
        let cost_per_chunk = Amount::new(7);

        // ---- Honest path: ledger count == manifest reference ----
        // Ledger accrued 10 chunks: billed 70, reserved 70, refund 0.
        // The manifest reference is also 10 → receipt identical to the ledger.
        let reserved = Amount::new(70);
        let (billed, refund) = anchor_settlement_receipt_to_manifest(10, cost_per_chunk, reserved);
        assert_eq!(
            (billed.value(), refund.value()),
            (70, 0),
            "honest path: receipt == escrow-ledger split (byte-identical)"
        );

        // ---- Divergence, ledger OVER-counts (the finding's core case) ----
        // Simulate a self-mismatch: the escrow ledger self-counted 10 billable
        // chunks (ledger billed_amount would be 70), but the operator-signed
        // manifest only supports 8 (e.g. a cancel-ack truncation the ledger
        // failed to honor). The receipt MUST bill the MANIFEST count (8 × 7 =
        // 56), NOT the inflated ledger count (70), and refund the difference so
        // no money is stranded.
        let (billed, refund) = anchor_settlement_receipt_to_manifest(8, cost_per_chunk, reserved);
        assert_eq!(
            billed.value(),
            56,
            "divergence: receipt bills the MANIFEST-derived count (8×7), not the \
             inflated escrow-ledger self-count (70)"
        );
        assert_eq!(
            refund.value(),
            14,
            "divergence: the over-counted difference is refunded, not stranded"
        );
        assert_eq!(
            billed.value() + refund.value(),
            reserved.value(),
            "conservation identity billed + refund == reserved holds under divergence"
        );

        // ---- Divergence, manifest OVER-counts the hold ----
        // A manifest reference that would bill MORE than the escrow the manager
        // actually debited is capped at `reserved` — the receipt can never
        // exceed the hold. billed capped at 70, refund 0.
        let (billed, refund) = anchor_settlement_receipt_to_manifest(100, cost_per_chunk, reserved);
        assert_eq!(
            (billed.value(), refund.value()),
            (70, 0),
            "receipt capped at the reserved hold — never bills more than was debited"
        );

        // ---- Overflow fails closed ----
        // A `cost × count` multiplication overflow bills NOTHING (rather than a
        // bogus wrapped amount) and refunds the whole hold.
        let (billed, refund) =
            anchor_settlement_receipt_to_manifest(u32::MAX, Amount::new(u64::MAX), reserved);
        assert_eq!(
            (billed.value(), refund.value()),
            (0, 70),
            "overflow fails closed: bill nothing, refund the full hold"
        );

        // ---- Zero-cost stream ----
        let (billed, refund) =
            anchor_settlement_receipt_to_manifest(5, Amount::new(0), Amount::new(0));
        assert_eq!(
            (billed.value(), refund.value()),
            (0, 0),
            "zero-cost stream settles to (0, 0)"
        );
    }

    /// §5.4.4:426 grant-after-close lifecycle gate (HIGH-1). A credit
    /// grant arriving after the pump has exited
    /// (`pump_exited == true`) is rejected with
    /// [`GrantError::StreamClosed`] BEFORE any signature / replay / escrow
    /// mutation, and the escrow ledger is left unchanged.
    #[test]
    fn apply_credit_grant_after_close_rejects_stream_closed_escrow_unchanged() {
        let state = build_test_state();
        // Install a non-zero escrow so we can prove it is NOT mutated by a
        // post-close grant.
        {
            let mut guard = state.write().unwrap();
            guard.escrow =
                super::super::stream::StreamEscrow::from_reserved(Amount::new(7), Amount::new(70));
            // Drive the stream to its terminal state.
            guard.pump_exited = true;
        }
        let reserved_before = state.write().unwrap().escrow.reserved();
        let billed_count_before = state.write().unwrap().escrow.billed_count();
        let seen_seq_before = state.write().unwrap().credit.seen_seq();

        let handle = StreamSessionHandle {
            receiver: None,
            state: Arc::clone(&state),
            grant_wake: Arc::new(Notify::new()),
            cancel_wake: Arc::new(Notify::new()),
            terminate_wake: Arc::new(Notify::new()),
            summary_rx: None,
            request_id: [0x77; 16],
        };

        // The grant content is irrelevant — the gate fires before the
        // signature / replay path, so an all-zero sig is sufficient.
        let credit = OutletStreamCredit {
            request_id: [0x77; 16],
            grant: 100,
            monotonic_seq: 1,
            sig: [0u8; 64],
        };

        let err = handle
            .apply_credit_grant(&credit, Amount::new(700))
            .expect_err("grant after close must reject");
        assert_eq!(err, GrantError::StreamClosed, "post-close grant slug");
        assert_eq!(
            super::super::stream::grant_error_to_slug(err),
            scp_protocol::context::outlets::error_codes::SLUG_PROTOCOL_STREAM_ALREADY_CLOSED,
            "StreamClosed routes to protocol.stream-already-closed",
        );
        assert_eq!(
            super::super::stream::grant_error_to_code(err),
            scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION,
            "StreamClosed routes to the Protocol-class SCP-OUTLET-6101 code",
        );

        // Escrow and credit state must be byte-for-byte unchanged.
        let guard = state.write().unwrap();
        assert_eq!(
            guard.escrow.reserved(),
            reserved_before,
            "reserved unchanged"
        );
        assert_eq!(
            guard.escrow.billed_count(),
            billed_count_before,
            "billed_count unchanged",
        );
        assert_eq!(
            guard.credit.seen_seq(),
            seen_seq_before,
            "credit counter (seen_seq) did not advance",
        );
    }

    /// §5.4.5 LOW (stranded-hold guard): a panic in the OUTER pump body
    /// (here injected via a signer that panics in `sign`) is contained by
    /// the `catch_unwind` wrapper at the spawn, and the `PumpEscrowGuard`'s
    /// `Drop` fires the settlement sink as the stack unwinds — so the
    /// open-time escrow hold is refunded (budget net zero) rather than
    /// stranded. Without the guard the panic would skip settlement and the
    /// consumed escrow ticket could never refund.
    #[tokio::test]
    async fn pump_panic_refunds_escrow_via_stranded_hold_guard() {
        use ed25519_dalek::SigningKey;

        /// A `StreamSigner` that panics on the first `sign` call —
        /// injecting a panic into the OUTER pump body's chunk-signing path.
        struct PanickingSigner {
            verifying_key: ed25519_dalek::VerifyingKey,
        }
        #[async_trait::async_trait]
        impl super::super::signer::StreamSigner for PanickingSigner {
            async fn sign(
                &self,
                _preimage: &[u8],
            ) -> Result<[u8; 64], super::super::signer::StreamSignerError> {
                panic!("injected pump-body panic for stranded-hold guard test");
            }
            fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
                &self.verifying_key
            }
        }

        /// Settlement sink that records the single settlement it receives.
        #[derive(Default)]
        struct RecordingSettlementSink {
            settlement: RwLock<Option<super::super::invoke::StreamSettlement>>,
        }
        impl super::super::invoke::StreamSettlementSink for RecordingSettlementSink {
            fn settle(&self, settlement: super::super::invoke::StreamSettlement) {
                *self
                    .settlement
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(settlement);
            }
            fn persist_reservation<'a>(
                &'a self,
                _context_id: &str,
                _request_id: scp_protocol::context::outlets::stream::RequestId,
                _record: super::super::invoke::StreamReservationRecord,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<(), scp_protocol::context::ContextError>,
                        > + Send
                        + 'a,
                >,
            > {
                // Test sink: no durable store — the crash-recovery record is
                // exercised by the actor-backed integration tests, not here.
                Box::pin(async { Ok(()) })
            }
        }

        // Build a state whose operator signer panics, with a non-zero
        // escrow hold (reserved 70, billed 0) so the refund is observable.
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing.verifying_key();
        let signer: Arc<dyn StreamSigner> = Arc::new(PanickingSigner { verifying_key });
        let identity = super::super::stream::StreamIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            stream_epoch: 1,
            caveats_binding: [0xAB; 32],
        };
        let credit = CreditTracker::new(32, verifying_key, identity, None);
        let admission = Arc::new(RwLock::new(StreamAdmissionTracker::new()));
        let origin_admission = Arc::new(RwLock::new(OriginAdmissionTracker::new()));
        let context_handle = ContextHandle::new(
            "ctx-test".to_owned(),
            scp_protocol::context::ContextParams::default(),
        );
        let state = Arc::new(RwLock::new(SharedSessionState {
            credit,
            escrow: super::super::stream::StreamEscrow::from_reserved(
                Amount::new(7),
                Amount::new(70),
            ),
            cancel_ack: CancelAckTracker::new(5),
            admission,
            origin_admission,
            admission_release_keys: AdmissionReleaseKeys {
                invoker_did: "did:dht:invoker".to_owned(),
                origin_invoker_did: "did:dht:origin".to_owned(),
                outlet_id: "outlet-test".to_owned(),
            },
            cancel_ack_armed: false,
            credit_stall_armed_at: None,
            cancel_ack_seq: None,
            next_emission_seq: 0,
            operator_signer: Arc::clone(&signer),
            pending_terminate: None,
            ucan_cid: "bafyrei-test".to_owned(),
            revocation_checker: Arc::new(
                scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
            ),
            stream_ucan_recheck_secs: 3_600,
            pump_exited: false,
            context_handle,
        }));

        let sink = Arc::new(RecordingSettlementSink::default());
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (outer_tx, _outer_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (summary_tx, _summary_rx) = tokio::sync::oneshot::channel();
        let request_id: RequestId = [0x99; 16];
        let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
        let permit = Arc::clone(&semaphore).try_acquire_owned().unwrap();

        spawn_pump_task(
            Arc::clone(&state),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            inner_rx,
            outer_tx,
            summary_tx,
            30,
            5,
            request_id,
            PumpEventEmissionInputs {
                sink: None,
                settlement_sink: Some(
                    sink.clone() as Arc<dyn super::super::invoke::StreamSettlementSink>
                ),
                context_id: "ctx-test".to_owned(),
                outlet_id: "outlet-test".to_owned(),
                invoker_did: scp_did::DID("did:dht:invoker".to_owned()),
                input_hash: "0".repeat(64),
                start: Instant::now(),
                economic_policy_snapshot: None,
                counter_reserve: CounterReserveSettlement::zero(),
            },
            permit,
        );

        // Send one Data chunk — the pump's signing path will panic.
        inner_tx
            .send(OutletStreamChunk {
                request_id,
                sequence: 0,
                payload: ChunkPayload::Data {
                    value: serde_json::json!({ "x": 1 }),
                },
                sig: [0u8; 64],
            })
            .await
            .expect("inner send");

        // Wait until the guard fires the settlement sink (the panic unwinds
        // through `PumpEscrowGuard::Drop`).
        let settlement = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(s) = sink
                    .settlement
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                {
                    break s;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("stranded-hold guard fires settlement within 2s after pump panic");

        // No chunk was billed (the panic struck during signing of the first
        // chunk, before any billable accrual), so the full hold is refunded:
        // billed 0, refund == reserved (70) → budget net zero.
        assert_eq!(settlement.billed_amount.value(), 0, "panic before any bill");
        assert_eq!(
            settlement.refund_amount.value(),
            70,
            "full escrow hold refunded — no stranded hold"
        );
        // `pump_exited` was set by the guard so a late terminate would
        // observe AlreadyTerminated.
        assert!(
            state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pump_exited,
            "guard marks pump_exited on the panic path"
        );
        // The semaphore permit was released when the panicking task
        // unwound (the owned permit drops with the task stack).
        assert_eq!(
            semaphore.available_permits(),
            4,
            "pump permit released on panic"
        );
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
                    settlement_sink: None,
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    invoker_did: scp_did::DID("did:dht:invoker".to_owned()),
                    input_hash: "0".repeat(64),
                    start: Instant::now(),
                    economic_policy_snapshot: None,
                    counter_reserve: CounterReserveSettlement::zero(),
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
        // The frontier folded exactly the one emitted chunk, so the
        // manifest root is a real (non-empty) RFC-6962 root, not the
        // all-zero empty-stream sentinel.
        assert_ne!(
            summary.manifest_root, [0u8; 32],
            "single-chunk stream must have a non-empty manifest root"
        );
        // The terminal chunk was non-Data (Error), so nothing is billed.
        assert_eq!(summary.manifest_billed, 0, "terminal Error is never billed");
        // §test #6 invariant: the emitted terminal chunk MUST carry a
        // non-placeholder signature — asserted above on the chunk received
        // via `outer_rx` (the exact chunk the frontier folded), which is
        // the SDK-facing wire form. Closes the [0u8;64] deletion gap
        // without retaining the manifest Vec.
    }

    /// Once the pump has broken its loop and published the close
    /// summary, a late `terminate_with_error` MUST return
    /// [`TerminateError::AlreadyTerminated`] — not silently succeed by
    /// arming a `pending_terminate` no consumer will drain. This pins
    /// the `pump_exited` settlement flag wired in the settlement block.
    #[tokio::test]
    async fn terminate_with_error_returns_already_terminated_after_pump_exit() {
        let state = build_test_state();
        let grant_wake = Arc::new(Notify::new());
        let cancel_wake = Arc::new(Notify::new());
        let terminate_wake = Arc::new(Notify::new());
        let (_inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(16);
        let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();
        let request_id: RequestId = [0x99; 16];

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
                    settlement_sink: None,
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    invoker_did: scp_did::DID("did:dht:invoker".to_owned()),
                    input_hash: "0".repeat(64),
                    start: Instant::now(),
                    economic_policy_snapshot: None,
                    counter_reserve: CounterReserveSettlement::zero(),
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

        // Drive the stream to pump exit: the first terminate arms the
        // synthetic terminal chunk, the pump emits it and breaks its
        // loop, runs settlement (setting `pump_exited`), and ends.
        handle
            .terminate_with_error(TerminateReason::RevokedMidStream, Some("first".to_owned()))
            .expect("first terminate accepted");
        let _terminal = tokio::time::timeout(Duration::from_secs(2), outer_rx.recv())
            .await
            .expect("pump emits synthetic terminal within 2s")
            .expect("chunk arrives");
        pump_handle.await.expect("pump task settles after exit");
        // Confirm the pump fully settled (summary published) before the
        // late terminate — otherwise we could be racing `pump_exited`.
        let _summary = summary_rx.await.expect("summary published");

        // Late terminate: the pump is gone, so this MUST report
        // `AlreadyTerminated` rather than no-op with `Ok(())`. No panic.
        let err = handle
            .terminate_with_error(TerminateReason::RevokedMidStream, Some("late".to_owned()))
            .expect_err("late terminate after pump exit must error");
        assert!(
            matches!(err, TerminateError::AlreadyTerminated),
            "expected AlreadyTerminated after pump exit, got {err:?}"
        );
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
                        settlement_sink: None,
                        context_id: "ctx-test".to_owned(),
                        outlet_id: "outlet-test".to_owned(),
                        invoker_did: scp_did::DID("did:dht:invoker".to_owned()),
                        input_hash: "0".repeat(64),
                        start: Instant::now(),
                        economic_policy_snapshot: None,
                        counter_reserve: CounterReserveSettlement::zero(),
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
            // The emitted terminal chunk's non-placeholder signature is
            // asserted above on the chunk received via `outer_rx` (the exact
            // chunk the frontier folded). The manifest root is non-empty
            // (one chunk folded), and a terminal Error bills nothing.
            assert_ne!(
                summary.manifest_root, [0u8; 32],
                "single-chunk stream must have a non-empty manifest root for reason {reason:?}"
            );
            assert_eq!(
                summary.manifest_billed, 0,
                "terminal Error is never billed for reason {reason:?}"
            );
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
        state: Arc<RwLock<SharedSessionState>>,
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
                .write()
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
                    settlement_sink: None,
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    invoker_did: scp_did::DID("did:dht:invoker".to_owned()),
                    input_hash: "0".repeat(64),
                    start: Instant::now(),
                    economic_policy_snapshot: None,
                    counter_reserve: CounterReserveSettlement::zero(),
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

    /// §5.4.5:758 cumulative ceiling (HIGH-2): with `credit_window=32` but a
    /// pinned `max_billable=10`, the pump forwards at most 10 billable Data
    /// chunks regardless of how much credit is granted, then emits a
    /// terminal `Error{terminal:true}` with `execution.credit-exhausted` /
    /// `SCP-OUTLET-6131`. The executor here floods 100 Data chunks; only 10
    /// reach the consumer before the cumulative cap fires.
    #[tokio::test]
    async fn pump_enforces_cumulative_max_calls_ceiling() {
        let state = build_test_state();
        // Re-pin the credit tracker with a max_billable of 10 (credit_window
        // 32 is clamped to 10 at construction).
        {
            let mut g = state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let identity = g.credit.identity().clone();
            let pk = *g.credit.invoker_pk();
            g.credit = CreditTracker::new(32, pk, identity, Some(10));
        }
        let request_id: RequestId = [0x3C; 16];
        let (_handle, mut outer_rx, summary_rx, pump_join, inner_tx) =
            spawn_test_pump(state, request_id, Duration::from_secs(3_601));

        // Flood 100 Data chunks. The inner sig is irrelevant — the pump
        // re-signs every forwarded chunk under the pinned operator key.
        let flood = tokio::spawn(async move {
            for seq in 0..100u64 {
                let chunk = OutletStreamChunk {
                    request_id,
                    sequence: seq,
                    payload: ChunkPayload::Data {
                        value: serde_json::json!({ "i": seq }),
                    },
                    sig: [0u8; 64],
                };
                if inner_tx.send(chunk).await.is_err() {
                    break;
                }
            }
            // Hold the sender open until the pump terminates on its own.
            inner_tx
        });

        // Collect every chunk the pump forwards until the channel closes.
        let mut data_chunks = 0u32;
        let mut terminal: Option<ChunkPayload> = None;
        loop {
            match tokio::time::timeout(Duration::from_secs(2), outer_rx.recv()).await {
                Ok(Some(chunk)) => match chunk.payload {
                    ChunkPayload::Data { .. } => data_chunks += 1,
                    payload @ ChunkPayload::Error { .. } => {
                        terminal = Some(payload);
                        break;
                    }
                    _ => {}
                },
                Ok(None) => break,
                Err(_elapsed) => panic!("pump did not terminate within 2s"),
            }
        }

        assert_eq!(
            data_chunks, 10,
            "exactly max_calls (10) billable Data chunks forwarded, not credit_window (32) or 100"
        );
        let ChunkPayload::Error {
            code,
            message,
            terminal: is_terminal,
        } = terminal.expect("pump emits a terminal Error chunk at the cumulative cap")
        else {
            unreachable!("matched Error above");
        };
        assert!(is_terminal, "credit-exhausted chunk is terminal");
        assert_eq!(
            code,
            scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT,
            "cumulative cap maps to SCP-OUTLET-6131",
        );
        assert!(
            message.starts_with(&format!(
                "{}: ",
                scp_protocol::context::outlets::error_codes::SLUG_EXECUTION_CREDIT_EXHAUSTED
            )),
            "message carries the execution.credit-exhausted slug prefix, got: {message}",
        );

        pump_join.await.expect("pump settles");
        let summary = summary_rx.await.expect("summary published");
        // Only the 10 forwarded Data chunks are billable; the terminal
        // Error is not billed.
        assert_eq!(summary.billed_count, 10, "billed_count == max_calls");
        drop(flood.await.expect("flood task joins"));
    }

    /// F6 (a): a context closed mid-stream terminates with
    /// `protocol.context-closed-mid-stream` / `SCP-OUTLET-6101` (Protocol
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
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.context_handle.clone()
        };
        ctx_handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("Creating -> Active");
        ctx_handle
            .transition_to(&scp_protocol::context::ContextState::Closing)
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
            "context teardown must carry the Protocol-session code SCP-OUTLET-6101, not the \
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
                .write()
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
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(g.cancel_ack_armed, "accepted cancel arms the timer");
            assert_eq!(g.cancel_ack_seq, Some(0));
        }
    }

    /// FIX 2(a): `apply_outlet_cancel_signed` rejects a `CancelIdentity`
    /// whose `context_id` OR `caveats_binding` diverges from the pinned
    /// triple as `SignatureInvalid`, WITHOUT mutating stream state. The
    /// pinned values are `("ctx-test", "outlet-test", [0xAB; 32])`. The
    /// `outlet_id` dimension is covered by
    /// `n2_apply_outlet_cancel_signed_records_and_validates_identity`;
    /// this test fills the remaining two dimensions so all three
    /// cross-checked fields have a direct negative-path assertion.
    #[tokio::test]
    async fn apply_outlet_cancel_signed_rejects_context_and_caveats_mismatch() {
        // Each case keeps two fields correct and corrupts exactly one so
        // the failing dimension is unambiguous.
        let mismatches = [
            (
                "context_id",
                CancelIdentity {
                    context_id: "WRONG-CTX".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    caveats_binding: [0xAB; 32],
                },
            ),
            (
                "caveats_binding",
                CancelIdentity {
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    caveats_binding: [0xCD; 32],
                },
            ),
        ];

        for (dimension, bad_id) in mismatches {
            let state = build_test_state();
            let request_id: RequestId = [0x31; 16];
            let (handle, _outer_rx, _summary_rx, _pump_join, _inner_tx) =
                spawn_test_pump(Arc::clone(&state), request_id, Duration::from_secs(3_601));
            // Signer wraps the correctly-pinned key — the ONLY thing wrong
            // here is the claimed identity, so the rejection comes from the
            // identity cross-check, not the self-verify.
            let signer = super::super::signer::InProcessStreamSigner::new(fixed_signing_key());

            let res = handle.apply_outlet_cancel_signed(&signer, &bad_id).await;
            assert!(
                matches!(
                    res,
                    Err(super::super::stream::CancelError::SignatureInvalid)
                ),
                "{dimension} mismatch must reject as SignatureInvalid, got {res:?}"
            );
            let g = state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !g.cancel_ack_armed,
                "{dimension} mismatch must NOT arm the cancel-ack timer"
            );
            assert_eq!(
                g.cancel_ack_seq, None,
                "{dimension} mismatch must NOT record a cancel-ack seq"
            );
        }
    }

    /// FIX 2(b): a signer wrapping a key that differs from the pinned
    /// `invoker_pk` produces a signature that fails the runtime's own
    /// self-verify under the pinned key. The identity triple matches, so
    /// the rejection is forced through the self-verify branch (an internal
    /// invariant violation), surfacing as `SignatureInvalid` WITHOUT
    /// mutating stream state. The fixture pins `[0x42; 32]` as `invoker_pk`;
    /// the signer here wraps `[0x11; 32]`.
    #[tokio::test]
    async fn apply_outlet_cancel_signed_rejects_signer_key_mismatch() {
        let state = build_test_state();
        let request_id: RequestId = [0x32; 16];
        let (handle, _outer_rx, _summary_rx, _pump_join, _inner_tx) =
            spawn_test_pump(Arc::clone(&state), request_id, Duration::from_secs(3_601));

        // Wrong key: the fixture pinned `fixed_signing_key()` ([0x42; 32])
        // as the invoker key, but this signer wraps a different key. The
        // produced signature cannot verify under the pinned verifying key.
        let wrong_key = SigningKey::from_bytes(&[0x11; 32]);
        debug_assert_ne!(
            wrong_key.verifying_key(),
            fixed_signing_key().verifying_key(),
            "test misconfigured: wrong key must differ from the pinned key"
        );
        let signer = super::super::signer::InProcessStreamSigner::new(wrong_key);

        // Identity triple is correct — the ONLY thing wrong is the key, so
        // the rejection is driven by the post-signing self-verify branch.
        let good_id = CancelIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            caveats_binding: [0xAB; 32],
        };

        let res = handle.apply_outlet_cancel_signed(&signer, &good_id).await;
        assert!(
            matches!(
                res,
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "wrong signer key must fail self-verify as SignatureInvalid, got {res:?}"
        );
        let g = state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !g.cancel_ack_armed,
            "self-verify failure must NOT arm the cancel-ack timer"
        );
        assert_eq!(
            g.cancel_ack_seq, None,
            "self-verify failure must NOT record a cancel-ack seq"
        );
    }

    // =================================================================
    // SCP-OUT-034/035 — pump-level economic + event-capture ACs.
    //
    // These drive the real `run_stream_pump_v2` end-to-end with an
    // `OutletInvokedEventSink` and a `StreamSettlementSink` wired so the
    // close-time event and settlement are observable. `build_test_state`
    // pins the SAME fixed key as both operator signer AND invoker credit
    // key, so signed credit grants / cancels verify under the pinned key.
    // =================================================================

    /// Captures every close-time `OutletInvokedEvent` over an unbounded
    /// channel (Mutex-free — Mutex is banned in scp-runtime).
    struct CapturingInvokedSink {
        tx: tokio::sync::mpsc::UnboundedSender<
            scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
        >,
    }
    impl OutletInvokedEventSink for CapturingInvokedSink {
        fn record(
            &self,
            event: scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
            _manifest: super::super::invoke::StreamManifestCommitment,
        ) {
            let _ = self.tx.send(event);
        }
    }

    /// Captures every close-time `StreamSettlement` over an unbounded channel.
    struct CapturingSettlementSink {
        tx: tokio::sync::mpsc::UnboundedSender<StreamSettlement>,
    }
    impl super::super::invoke::StreamSettlementSink for CapturingSettlementSink {
        fn settle(&self, settlement: StreamSettlement) {
            let _ = self.tx.send(settlement);
        }
        fn persist_reservation<'a>(
            &'a self,
            _context_id: &str,
            _request_id: scp_protocol::context::outlets::stream::RequestId,
            _record: super::super::invoke::StreamReservationRecord,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), scp_protocol::context::ContextError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(()) })
        }
    }

    /// Everything a capturing-pump test drives + observes.
    struct CapturingPump {
        handle: StreamSessionHandle,
        outer_rx: mpsc::Receiver<OutletStreamChunk>,
        summary_rx: tokio::sync::oneshot::Receiver<StreamCloseSummary>,
        pump_join: tokio::task::JoinHandle<()>,
        inner_tx: mpsc::Sender<OutletStreamChunk>,
        event_rx: tokio::sync::mpsc::UnboundedReceiver<
            scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
        >,
        settle_rx: tokio::sync::mpsc::UnboundedReceiver<StreamSettlement>,
    }

    /// Overwrites the escrow ledger so per-`Data` accrual + close-time refund
    /// operate over a known `(cost_per_chunk, reserved)` hold.
    fn set_escrow(state: &Arc<RwLock<SharedSessionState>>, cost_per_chunk: u64, reserved: u64) {
        let mut g = state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.escrow = super::super::stream::StreamEscrow::from_reserved(
            Amount::new(cost_per_chunk),
            Amount::new(reserved),
        );
    }

    /// Re-pins the credit tracker with a fresh `(credit_window, max_calls)`.
    fn set_credit(
        state: &Arc<RwLock<SharedSessionState>>,
        credit_window: u32,
        max_calls: Option<u32>,
    ) {
        let mut g = state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let identity = g.credit.identity().clone();
        let pk = *g.credit.invoker_pk();
        g.credit = CreditTracker::new(credit_window, pk, identity, max_calls);
    }

    /// Spawns `run_stream_pump_v2` with capturing event + settlement sinks and
    /// the given stall / cancel-ack timer durations + counter-reserve cost.
    fn spawn_capturing_pump(
        state: Arc<RwLock<SharedSessionState>>,
        request_id: RequestId,
        stall: Duration,
        cancel_ack: Duration,
        cost_per_chunk: u64,
        amount_cumulative_reserved: u64,
    ) -> CapturingPump {
        let grant_wake = Arc::new(Notify::new());
        let cancel_wake = Arc::new(Notify::new());
        let terminate_wake = Arc::new(Notify::new());
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(64);
        let (outer_tx, outer_rx) = mpsc::channel::<OutletStreamChunk>(64);
        let (summary_tx, summary_rx) = tokio::sync::oneshot::channel();
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let (settle_tx, settle_rx) = tokio::sync::mpsc::unbounded_channel();
        let event_sink: Arc<dyn OutletInvokedEventSink> =
            Arc::new(CapturingInvokedSink { tx: event_tx });
        let settlement_sink: Arc<dyn super::super::invoke::StreamSettlementSink> =
            Arc::new(CapturingSettlementSink { tx: settle_tx });

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
                stall,
                cancel_ack,
                request_id,
                PumpEventEmissionInputs {
                    sink: Some(event_sink),
                    settlement_sink: Some(settlement_sink),
                    context_id: "ctx-test".to_owned(),
                    outlet_id: "outlet-test".to_owned(),
                    invoker_did: scp_did::DID("did:dht:invoker".to_owned()),
                    input_hash: "0".repeat(64),
                    start: Instant::now(),
                    economic_policy_snapshot: None,
                    counter_reserve: CounterReserveSettlement {
                        amount_cumulative_reserved,
                        reserved_chunks: 0,
                        ucan_cid: "bafyrei-test".to_owned(),
                        cost_per_chunk: Amount::new(cost_per_chunk),
                    },
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
        CapturingPump {
            handle,
            outer_rx,
            summary_rx,
            pump_join,
            inner_tx,
            event_rx,
            settle_rx,
        }
    }

    /// Sends one `Data` chunk with the given per-stream `sequence` on the inner
    /// channel (the pump re-numbers under its own outer cursor).
    async fn send_inner_data(inner_tx: &mpsc::Sender<OutletStreamChunk>, seq: u64) {
        inner_tx
            .send(OutletStreamChunk {
                request_id: [0u8; 16],
                sequence: seq,
                payload: ChunkPayload::Data {
                    value: serde_json::json!({ "i": seq }),
                },
                sig: [0u8; 64],
            })
            .await
            .expect("inner send");
    }

    /// Sends a terminal `End` chunk on the inner channel.
    async fn send_inner_end(inner_tx: &mpsc::Sender<OutletStreamChunk>, seq: u64) {
        use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        inner_tx
            .send(OutletStreamChunk {
                request_id: [0u8; 16],
                sequence: seq,
                payload: ChunkPayload::End {
                    aggregate: serde_json::Value::Null,
                    provenance: DataProvenance {
                        source_context: "ctx-test".to_owned(),
                        source_type: SourceType::Persistent,
                        counterparties: Vec::new(),
                        purpose: None,
                        discovery_method: DiscoveryMethod::OutOfBand,
                        age: Duration::from_secs(0),
                        memory_scope: scp_protocol::context::params::MemoryScope::Full,
                        chain_depth: 0,
                        chain_path: None,
                        payment_amount: None,
                        payment_adapter: None,
                        payment_receipt_id: None,
                    },
                    execution_time_ms: 0,
                },
                sig: [0u8; 64],
            })
            .await
            .expect("inner send end");
    }

    /// Drains `outer_rx`, returning `(data_count, terminal_payload)`.
    async fn drain_outer(
        outer_rx: &mut mpsc::Receiver<OutletStreamChunk>,
    ) -> (u32, Option<ChunkPayload>) {
        let mut data = 0u32;
        let mut terminal = None;
        while let Ok(Some(chunk)) =
            tokio::time::timeout(Duration::from_secs(5), outer_rx.recv()).await
        {
            let is_terminal = chunk.payload.is_terminal();
            match chunk.payload {
                ChunkPayload::Data { .. } => data += 1,
                other if is_terminal => {
                    terminal = Some(other);
                    break;
                }
                _ => {}
            }
        }
        (data, terminal)
    }

    /// A [`StreamSigner`] that delegates to an in-process key but BLOCKS the
    /// `block_on_call`-th `sign` invocation on a barrier — modelling the
    /// off-lock signing `.await` window during which a concurrent
    /// `OutletCancel` can land (round-9 F1). Produces a VALID signature under
    /// the pinned operator key on release (delegates to the inner signer), so
    /// the pump's just-signed `debug_assert!` self-verify still holds.
    struct BarrierSigner {
        inner: super::super::signer::InProcessStreamSigner,
        calls: std::sync::atomic::AtomicUsize,
        block_on_call: usize,
        sign_started: Arc<Notify>,
        release: Arc<Notify>,
    }
    #[async_trait::async_trait]
    impl super::super::signer::StreamSigner for BarrierSigner {
        async fn sign(
            &self,
            preimage: &[u8],
        ) -> Result<[u8; 64], super::super::signer::StreamSignerError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n == self.block_on_call {
                // Announce the boundary chunk is mid-sign, then park until the
                // test has recorded the concurrent cancel.
                self.sign_started.notify_one();
                self.release.notified().await;
            }
            self.inner.sign(preimage).await
        }
        fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
            self.inner.verifying_key()
        }
    }

    /// **round-9 F1** — cancel-boundary billing TOCTOU. A concurrent
    /// `OutletCancel` that lands DURING the off-lock signing `.await` of an
    /// in-flight boundary `Data` chunk (whose per-chunk gate already returned
    /// `Forward` under `ceiling == u64::MAX`) must NOT be billed. The
    /// post-signing re-check mirrors the gate's `>=` drop, so the in-flight
    /// `Data` is dropped-not-billed, `chunks_billed` stays correct, and the
    /// terminal chunk occupies the pinned `cancel_ack_seq` slot. Before the
    /// fix, the second (accrual) lock window re-read a ceiling of 5 and billed
    /// the boundary `Data` at seq 5 (`5 <= 5`), silently over-billing by one.
    #[tokio::test]
    async fn pump_cancel_during_signing_drops_boundary_data_not_billed_round9_f1() {
        let state = build_test_state();
        set_credit(&state, 32, None);
        set_escrow(&state, 10, 1_000);

        let sign_started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        {
            let mut g = state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.operator_signer = Arc::new(BarrierSigner {
                inner: super::super::signer::InProcessStreamSigner::new(fixed_signing_key()),
                calls: std::sync::atomic::AtomicUsize::new(0),
                // seq 0..=4 sign non-blocking (calls 1..=5); the sixth Data
                // (outer seq 5) blocks mid-sign.
                block_on_call: 6,
                sign_started: Arc::clone(&sign_started),
                release: Arc::clone(&release),
            });
        }

        let state_for_cancel = Arc::clone(&state);
        let request_id: RequestId = [0xC9; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_secs(30),
            Duration::from_secs(30),
            10,
            0,
        );

        // Five billable Data chunks (outer seq 0..=4); drain each so the
        // emission cursor advances to 5 (five sign calls completed).
        for seq in 0..5 {
            send_inner_data(&pump.inner_tx, seq).await;
            let chunk = tokio::time::timeout(Duration::from_secs(5), pump.outer_rx.recv())
                .await
                .expect("data chunk forwarded")
                .expect("stream open");
            assert!(matches!(chunk.payload, ChunkPayload::Data { .. }));
            assert_eq!(chunk.sequence, seq);
        }

        // Sixth Data: its gate returns Forward (no cancel yet), then its signing
        // blocks on the barrier.
        send_inner_data(&pump.inner_tx, 5).await;
        tokio::time::timeout(Duration::from_secs(5), sign_started.notified())
            .await
            .expect("boundary chunk reached the signing barrier");

        // Concurrent cancel lands DURING signing, pinning cancel_ack_seq at the
        // live emission cursor (5) — exactly what apply_outlet_cancel_signed
        // does to the tracker.
        {
            let mut g = state_for_cancel
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let cursor = g.next_emission_seq;
            assert_eq!(cursor, 5, "five chunks emitted before the cancel");
            g.cancel_ack.record_cancel(cursor, Instant::now());
            g.cancel_ack_seq = g.cancel_ack.cancel_ack_seq();
            g.cancel_ack_armed = true;
        }

        // Release the signature; the post-signing re-check must DROP the
        // in-flight boundary Data (seq 5 >= ceiling 5).
        release.notify_one();

        // Deliver the terminal End; it takes the pinned cancel_ack_seq slot (5).
        send_inner_end(&pump.inner_tx, 6).await;

        let mut extra_data = 0u32;
        let mut terminal_seq = None;
        while let Ok(Some(chunk)) =
            tokio::time::timeout(Duration::from_secs(5), pump.outer_rx.recv()).await
        {
            if chunk.payload.is_terminal() {
                terminal_seq = Some(chunk.sequence);
                break;
            }
            if matches!(chunk.payload, ChunkPayload::Data { .. }) {
                extra_data += 1;
            }
        }
        assert_eq!(
            extra_data, 0,
            "the in-flight boundary Data must be dropped, never forwarded"
        );
        assert_eq!(
            terminal_seq,
            Some(5),
            "the terminal chunk occupies the pinned cancel_ack_seq slot"
        );

        pump.pump_join.await.expect("pump settles");
        let summary = pump.summary_rx.await.expect("summary published");
        assert_eq!(
            summary.billed_count, 5,
            "exactly five Data chunks billed — the boundary in-flight Data is NOT over-billed"
        );
        assert_eq!(summary.cancel_ack_seq, Some(5));

        let events: Vec<_> = std::iter::from_fn(|| pump.event_rx.try_recv().ok()).collect();
        assert_eq!(events.len(), 1, "exactly one OutletInvokedEvent");
        assert_eq!(events[0].chunks_billed, 5, "event bills five, not six");
        assert_eq!(events[0].cancel_ack_seq, Some(5));
        assert_eq!(
            events[0].stream_chunk_count, 6,
            "five Data + one terminal End leaves"
        );

        let settlements: Vec<_> = std::iter::from_fn(|| pump.settle_rx.try_recv().ok()).collect();
        assert_eq!(settlements.len(), 1);
        assert_eq!(
            settlements[0].billed_count, 5,
            "settlement bills five — no over-bill of the dropped boundary Data"
        );
    }

    /// **034 AC11** — a terminal `Error{terminal:true}` emitted with ZERO
    /// credit still closes the stream successfully; terminal chunks bypass the
    /// credit gate (they are never billed), so `chunks_billed == 0`.
    #[tokio::test]
    async fn pump_terminal_error_with_zero_credit_succeeds_034_ac11() {
        let state = build_test_state();
        set_credit(&state, 0, None); // zero credit window
        set_escrow(&state, 1, 0);
        let request_id: RequestId = [0xA1; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_secs(30),
            Duration::from_secs(5),
            1,
            0,
        );

        // Send a terminal Error with 0 credit available.
        pump.inner_tx
            .send(OutletStreamChunk {
                request_id: [0u8; 16],
                sequence: 0,
                payload: ChunkPayload::Error {
                    code: scp_protocol::context::outlets::error_codes::CODE_EXECUTION_FAULT
                        .to_owned(),
                    message: "operator terminal error".to_owned(),
                    terminal: true,
                },
                sig: [0u8; 64],
            })
            .await
            .expect("inner send error");

        let (data, terminal) = drain_outer(&mut pump.outer_rx).await;
        assert_eq!(data, 0, "no Data chunks were sent");
        assert!(
            matches!(terminal, Some(ChunkPayload::Error { terminal: true, .. })),
            "terminal Error forwarded despite zero credit"
        );
        pump.pump_join.await.expect("pump settles");
        let summary = pump.summary_rx.await.expect("summary published");
        assert_eq!(summary.billed_count, 0, "terminal chunks are never billed");

        let events: Vec<_> = std::iter::from_fn(|| pump.event_rx.try_recv().ok()).collect();
        assert_eq!(events.len(), 1, "exactly one OutletInvokedEvent");
        assert_eq!(events[0].chunks_billed, 0);
    }

    /// **034 AC23** — a 10-`Data` + `End` stream bills exactly `10 × cost`: the
    /// event records `chunks_billed == 10` and the settlement receipt bills
    /// `10 × cost_per_chunk` with zero refund.
    #[tokio::test]
    async fn pump_ten_data_bills_ten_times_cost_034_ac23() {
        let state = build_test_state();
        // credit_window 32 (default) admits all 10; escrow holds 10 × cost=1.
        set_escrow(&state, 1, 10);
        let request_id: RequestId = [0xA2; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_secs(30),
            Duration::from_secs(5),
            1,  // cost_per_chunk
            10, // amount_cumulative_reserved
        );

        for seq in 0..10u64 {
            send_inner_data(&pump.inner_tx, seq).await;
        }
        send_inner_end(&pump.inner_tx, 10).await;

        let (data, terminal) = drain_outer(&mut pump.outer_rx).await;
        assert_eq!(data, 10, "all 10 Data chunks forwarded");
        assert!(
            matches!(terminal, Some(ChunkPayload::End { .. })),
            "closes on End"
        );
        pump.pump_join.await.expect("pump settles");
        let summary = pump.summary_rx.await.expect("summary published");
        assert_eq!(summary.billed_count, 10, "10 Data chunks billed");

        let events: Vec<_> = std::iter::from_fn(|| pump.event_rx.try_recv().ok()).collect();
        assert_eq!(events.len(), 1, "exactly one event");
        assert_eq!(events[0].chunks_billed, 10, "event bills 10 Data chunks");
        assert_eq!(
            events[0].stream_chunk_count, 11,
            "11 total chunks (10 Data + terminal End)"
        );

        let settlements: Vec<_> = std::iter::from_fn(|| pump.settle_rx.try_recv().ok()).collect();
        assert_eq!(settlements.len(), 1, "exactly one settlement");
        assert_eq!(
            settlements[0].billed_amount.value(),
            10,
            "settlement bills 10 × cost_per_chunk(1)"
        );
        assert_eq!(settlements[0].billed_count, 10);
        assert_eq!(settlements[0].refund_amount.value(), 0, "nothing unspent");
    }

    /// **034 AC9** — 100 `Data` chunks flow under `credit_window = 32` when the
    /// invoker issues a fresh signed grant after each window drains; the stream
    /// completes with all 100 delivered plus the terminal `End`.
    #[tokio::test]
    async fn pump_hundred_chunks_with_periodic_grants_complete_034_ac9() {
        use scp_protocol::context::outlets::stream::{CreditGrantSigningInputs, sign_credit_grant};
        let state = build_test_state();
        set_credit(&state, 32, Some(1_000)); // window 32, generous hard cap
        set_escrow(&state, 0, 0); // zero-cost stream — focus on credit flow
        let request_id: RequestId = [0xA9; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_secs(30),
            Duration::from_secs(5),
            0,
            0,
        );

        // Pinned identity for signing grants (build_test_state fixture values).
        let identity = super::super::stream::StreamIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            stream_epoch: 1,
            caveats_binding: [0xAB; 32],
        };
        let signing_key = fixed_signing_key();
        let make_grant = |grant: u32, monotonic_seq: u64| {
            let sig = sign_credit_grant(
                &signing_key,
                &CreditGrantSigningInputs {
                    context_id: &identity.context_id,
                    outlet_id: &identity.outlet_id,
                    request_id: &request_id,
                    grant,
                    monotonic_seq,
                    stream_epoch: identity.stream_epoch,
                    caveats_binding: &identity.caveats_binding,
                },
            );
            OutletStreamCredit {
                request_id,
                grant,
                monotonic_seq,
                sig,
            }
        };

        // Feeder: push 100 Data then End.
        let feeder_tx = pump.inner_tx.clone();
        let feeder = tokio::spawn(async move {
            for seq in 0..100u64 {
                if feeder_tx
                    .send(OutletStreamChunk {
                        request_id: [0u8; 16],
                        sequence: seq,
                        payload: ChunkPayload::Data {
                            value: serde_json::json!({ "i": seq }),
                        },
                        sig: [0u8; 64],
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            send_inner_end(&feeder_tx, 100).await;
        });

        // Consumer: drain, granting +32 credit each time the delivered count
        // crosses a fresh window boundary. The initial window is 32.
        let mut data = 0u32;
        let mut terminal = None;
        let mut monotonic_seq = 1u64;
        let mut next_grant_at = 32u32;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), pump.outer_rx.recv()).await {
                Ok(Some(chunk)) => {
                    let is_terminal = chunk.payload.is_terminal();
                    match chunk.payload {
                        ChunkPayload::Data { .. } => {
                            data += 1;
                            // Replenish BEFORE the window fully drains so the
                            // executor never stalls permanently.
                            if data >= next_grant_at.saturating_sub(4) {
                                pump.handle
                                    .apply_credit_grant(
                                        &make_grant(32, monotonic_seq),
                                        Amount::new(0),
                                    )
                                    .expect("grant accepted");
                                monotonic_seq += 1;
                                next_grant_at = next_grant_at.saturating_add(32);
                            }
                        }
                        other if is_terminal => {
                            terminal = Some(other);
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(_) => panic!("pump stalled — grants did not replenish credit"),
            }
        }

        assert_eq!(
            data, 100,
            "all 100 Data chunks delivered across credit windows"
        );
        assert!(
            matches!(terminal, Some(ChunkPayload::End { .. })),
            "stream completes with terminal End"
        );
        feeder.await.expect("feeder joins");
        pump.pump_join.await.expect("pump settles");
        let summary = pump.summary_rx.await.expect("summary published");
        assert_eq!(summary.billed_count, 100, "100 Data chunks billed");
    }

    /// **034 AC13** — an `OutletCancel` followed by executor silence forces the
    /// cancel-ack timeout: the framework emits its own terminal
    /// `Error{code: SCP-OUTLET-6135}` at the cancel-ack sequence and flushes
    /// stream state.
    #[tokio::test]
    async fn pump_cancel_then_silence_forces_cancel_ack_timeout_034_ac13() {
        let state = build_test_state();
        set_escrow(&state, 1, 10);
        let request_id: RequestId = [0x13; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_secs(30),    // stall timer — not exercised
            Duration::from_millis(150), // short cancel-ack window
            1,
            10,
        );

        // Apply a signed cancel at the live cursor (0 — no chunk emitted yet),
        // then stay silent so the executor never emits a terminal chunk.
        let signer = super::super::signer::InProcessStreamSigner::new(fixed_signing_key());
        let cancel_id = CancelIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            caveats_binding: [0xAB; 32],
        };
        let recorded = pump
            .handle
            .apply_outlet_cancel_signed(&signer, &cancel_id)
            .await
            .expect("signed cancel accepted");
        assert_eq!(recorded, Some(0), "cancel-ack pinned at the live cursor");

        // The cancel-ack timer fires → framework terminal Error(6135).
        let (_data, terminal) = drain_outer(&mut pump.outer_rx).await;
        let ChunkPayload::Error {
            code,
            terminal: is_terminal,
            ..
        } = terminal.expect("framework emits a forced terminal on cancel-ack timeout")
        else {
            unreachable!("expected terminal Error");
        };
        assert!(is_terminal);
        assert_eq!(
            code,
            scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
            "cancel-ack timeout maps to SCP-OUTLET-6135",
        );
        pump.pump_join.await.expect("pump settles");
        let _ = pump
            .summary_rx
            .await
            .expect("summary published — stream state flushed");
    }

    /// **034 AC25** — a credit stall after 3 `Data` chunks (credit window = 3,
    /// no further grant) forces the credit-stall timeout: `chunks_billed == 3`
    /// and the unspent escrow (`reserved − 3 × cost`) is refunded.
    #[tokio::test]
    async fn pump_credit_stall_after_three_data_refunds_unspent_034_ac25() {
        let state = build_test_state();
        set_credit(&state, 3, Some(1_000)); // window 3, high hard cap → Stall not CreditExhausted
        set_escrow(&state, 1, 10); // reserve 10, only 3 will bill
        let request_id: RequestId = [0x25; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_millis(150), // short credit-stall window
            Duration::from_secs(30),
            1,
            10,
        );

        // Flood 6 Data — only 3 fit in the credit window; the 4th stalls.
        for seq in 0..6u64 {
            let _ = pump
                .inner_tx
                .send(OutletStreamChunk {
                    request_id: [0u8; 16],
                    sequence: seq,
                    payload: ChunkPayload::Data {
                        value: serde_json::json!({ "i": seq }),
                    },
                    sig: [0u8; 64],
                })
                .await;
        }

        let (data, terminal) = drain_outer(&mut pump.outer_rx).await;
        assert_eq!(
            data, 3,
            "exactly credit_window(3) Data chunks delivered before stall"
        );
        let ChunkPayload::Error {
            code,
            terminal: is_terminal,
            ..
        } = terminal.expect("credit-stall timer emits a forced terminal")
        else {
            unreachable!("expected terminal Error");
        };
        assert!(is_terminal);
        assert_eq!(
            code,
            scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT_STALL,
            "credit stall maps to SCP-OUTLET-6133",
        );
        pump.pump_join.await.expect("pump settles");
        let summary = pump.summary_rx.await.expect("summary published");
        assert_eq!(
            summary.billed_count, 3,
            "only the 3 delivered Data chunks billed"
        );

        let settlements: Vec<_> = std::iter::from_fn(|| pump.settle_rx.try_recv().ok()).collect();
        assert_eq!(settlements.len(), 1, "exactly one settlement");
        assert_eq!(settlements[0].billed_amount.value(), 3, "3 × cost billed");
        assert_eq!(
            settlements[0].refund_amount.value(),
            7,
            "unspent escrow (10 − 3) refunded — chain-depth slot + escrow released",
        );
    }

    /// **035 AC3 / 034 AC24** — a mid-stream cancel truncates billing: the
    /// event records `cancel_ack_seq == Some(k)` and the chunks emitted ABOVE
    /// the cancel-ack sequence are NOT billed, so `chunks_billed` reflects the
    /// pinned ceiling — strictly fewer than the total `Data` chunks the
    /// executor pushed — and the unspent escrow is refunded.
    ///
    /// NOTE on the §5.4.5:566 predicate `chunks_billed_ref = |{ i : @type ==
    /// data && i <= cancel_ack_seq }|`: with `cancel_ack_seq = 5` the pinned
    /// sequence slot `5` belongs to the **terminal cancel-ack chunk**
    /// (§5.4.5:530(3)), NOT to a billable `Data`. The gate drops every
    /// non-terminal chunk at `sequence >= 5` (`DropAboveCancelAck`, the `>=`
    /// boundary), so the sealed manifest carries `Data` only at outer sequences
    /// `0..=4` — FIVE chunks. The inclusive `i <= cancel_ack_seq` predicate
    /// therefore counts exactly those five (there is no `Data` at slot `5`; the
    /// terminal `End` occupies it), and the three post-cancel in-flight `Data`
    /// the executor pushes at sequences `>= 5` are never emitted or billed —
    /// the load-bearing protective property (chunks at/after the cancel-ack are
    /// not billed). This asserts the deterministic terminal-occupies-the-slot
    /// behavior the implementation encodes: `chunks_billed == 5`.
    #[tokio::test]
    async fn pump_midstream_cancel_truncates_billing_035_ac3_034_ac24() {
        let state = build_test_state();
        set_escrow(&state, 1, 8); // reserve for the 8 Data the executor pushes
        let request_id: RequestId = [0x24; 16];
        let mut pump = spawn_capturing_pump(
            state,
            request_id,
            Duration::from_secs(30),
            Duration::from_secs(30),
            1,
            8,
        );

        // Deliver 5 Data (outer cursor advances to 5) before cancelling.
        for seq in 0..5u64 {
            send_inner_data(&pump.inner_tx, seq).await;
        }
        for _ in 0..5 {
            let chunk = tokio::time::timeout(Duration::from_secs(5), pump.outer_rx.recv())
                .await
                .expect("chunk within 5s")
                .expect("chunk present");
            assert!(matches!(chunk.payload, ChunkPayload::Data { .. }));
        }

        // Cancel at the live cursor (5). The runtime reads its own cursor.
        let signer = super::super::signer::InProcessStreamSigner::new(fixed_signing_key());
        let cancel_id = CancelIdentity {
            context_id: "ctx-test".to_owned(),
            outlet_id: "outlet-test".to_owned(),
            caveats_binding: [0xAB; 32],
        };
        let recorded = pump
            .handle
            .apply_outlet_cancel_signed(&signer, &cancel_id)
            .await
            .expect("signed cancel accepted");
        assert_eq!(recorded, Some(5), "cancel-ack pinned at emission cursor 5");

        // Executor pushes 3 more Data (8 produced total) then a terminal End.
        // §5.4.5:530(3): `cancel_ack_seq=5` is the terminal cancel-ack chunk's
        // slot, so the framework's terminal `End` takes outer seq 5 and every
        // one of the 3 post-cancel in-flight Data (gate `sequence >= 5`) is
        // dropped-and-not-billed (§5.4.5:530(1)). Net: Data seq 0..4 billed
        // (5); seq 5 = terminal; seq 6,7 never emitted.
        for seq in 5..8u64 {
            send_inner_data(&pump.inner_tx, seq).await;
        }
        send_inner_end(&pump.inner_tx, 8).await;

        // Drain remaining until terminal.
        let (more_data, terminal) = drain_outer(&mut pump.outer_rx).await;
        assert_eq!(
            more_data, 0,
            "no post-cancel Data reaches the wire — all dropped at the gate (seq >= cancel_ack_seq)"
        );
        assert!(
            matches!(terminal, Some(ChunkPayload::End { .. })),
            "terminal End (the cancel-ack terminal chunk) closes the stream"
        );
        pump.pump_join.await.expect("pump settles");
        let summary = pump.summary_rx.await.expect("summary published");
        assert_eq!(
            summary.cancel_ack_seq,
            Some(5),
            "cancel-ack sequence recorded on the summary",
        );
        assert_eq!(
            summary.billed_count, 5,
            "§5.4.5:530(3): the terminal occupies seq 5, post-cancel Data (seq >= 5) are dropped, \
             so only Data seq 0..4 are billed (5) — not the 8 the executor produced"
        );
        assert_eq!(
            summary.stream_chunk_count, 6,
            "sealed manifest = Data seq 0..4 (5) + the terminal End at seq 5 = 6 leaves"
        );

        let events: Vec<_> = std::iter::from_fn(|| pump.event_rx.try_recv().ok()).collect();
        assert_eq!(events.len(), 1, "exactly one event");
        assert_eq!(
            events[0].cancel_ack_seq,
            Some(5),
            "035 AC3: the close event records the cancel-ack ceiling",
        );
        // 035 AC3: a graceful cancel-ack close (cancel observed + terminal
        // `End`) records the dedicated `Cancelled` terminal status, not `Ok`.
        assert_eq!(
            events[0].stream_terminal_status,
            scp_protocol::context::outlets::stream::StreamTerminalStatus::Cancelled,
            "035 AC3: graceful cancel-ack close records Cancelled terminal status",
        );
        assert_eq!(
            events[0].status,
            scp_protocol::context::outlets::OutletStatus::Cancelled,
            "035 AC3: legacy status mirrors the Cancelled terminal status",
        );
        assert_eq!(
            events[0].chunks_billed, 5,
            "event bills the truncated set: Data seq 0..4 (5), not the 8 produced"
        );

        let settlements: Vec<_> = std::iter::from_fn(|| pump.settle_rx.try_recv().ok()).collect();
        assert_eq!(settlements.len(), 1);
        assert_eq!(settlements[0].billed_amount.value(), 5, "5 × cost billed");
        assert_eq!(
            settlements[0].refund_amount.value(),
            3,
            "unspent escrow (8 reserved − 5 billed) refunded",
        );
    }
}
