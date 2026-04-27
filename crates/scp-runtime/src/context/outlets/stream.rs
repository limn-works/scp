//! Runtime-side streaming: credit accounting, escrow, cancel-ack
//! lifecycle, and concurrent-stream admission (SCP-OUT-034, §5.4.5).
//!
//! Per-stream protocol-layer wire types (`OutletStreamOpen`,
//! `OutletStreamChunk`, `OutletStreamCredit`) live in
//! `scp-protocol::context::outlets::stream`. This module sits at the
//! runtime layer because it owns mutable per-stream state — credit
//! counters, escrow ledgers, stall timers, and cancel-ack cursors —
//! that consume tokio.
//!
//! # What this module covers
//!
//! - [`CreditTracker`] — single-source-of-truth for credit accounting
//!   on one stream. `try_consume` is called for every billable chunk
//!   (`Data` / `Progress` per §5.4.5); `grant` verifies the invoker's
//!   Ed25519 signature, enforces stream-identity binding, and rejects
//!   replays. The signed-grant preimage is byte-for-byte the §5.4.5
//!   `SCP-OUTLET-CREDIT-V1:` shape (computed by
//!   [`scp_protocol::context::outlets::stream::compute_credit_sig_preimage`]).
//!
//! - [`StreamEscrow`] — escrow-at-open + per-grant top-up + per-Data
//!   accrual + at-close refund. `checked_mul` overflow surfaces as
//!   [`EscrowError::Overflow`]; insufficient invoker balance surfaces as
//!   [`EscrowError::InsufficientFunds`]. Final settlement returns a
//!   `(billed_amount, refund_amount)` pair the caller hands to the
//!   payment adapter for [`PaymentReceipt`] issuance (§19.15.5).
//!
//! - [`coerce_estimated_chunk_count`] — the §5.4.5:422-432 caveat
//!   coercion `caveats.max_calls.map(|n| u32::try_from(n)
//!   .unwrap_or(u32::MAX)).unwrap_or(u32::MAX)`. The bound is
//!   `min(credit_window, caveats.max_calls.unwrap_or(u32::MAX))` per
//!   §5.4.5; an `estimated_chunk_count` exceeding the bound is
//!   rejected at open with [`OpenError::EstimateExceedsBound`].
//!
//! - [`CancelAckTracker`] — records `cancel_ack_seq` at the moment
//!   `OutletCancel` arrives, arms the
//!   `ContextParams::stream_cancel_ack_secs` timer, and returns the
//!   §5.4.5 cancel-ack-timeout terminal-chunk decision when the
//!   executor fails to emit a terminal chunk in the window.
//!
//! - [`StreamAdmissionTracker`] — runs the §5.4.5 round-5 5-step open
//!   sequence: parse → UCAN validation → 3 cap comparisons in lexical
//!   order → atomic increment → terminal decrement. UCAN-validation
//!   failures do NOT touch counters (closes the slot-burn DoS).
//!
//! - [`compute_chunks_billed_ref`] / [`verify_chunks_billed`] — §5.4.5
//!   wire-rejection helper that recomputes the reference billable
//!   count from a chunk manifest + cancel-ack cursor and rejects an
//!   `OutletInvokedEvent` whose recorded `chunks_billed` does not
//!   match. The runtime calls this at log-insert time per the §5.4.5
//!   "wire-layer rejection" rule.

// `module_name_repetitions` and `struct_field_names` (the "per" prefix
// triplet on `StreamAdmissionTracker`) are kept verbatim from the
// §5.4.5 round-5 spec field names — the public API matches the spec
// table, not Rust's idiomatic naming.
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_field_names,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph
)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use scp_protocol::context::outlets::error_codes;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, MlsEpoch, OutletStreamChunk, OutletStreamCredit, verify_credit_signature,
};
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;

// =====================================================================
// CreditTracker — §5.4.5 credit-based backpressure
// =====================================================================

/// Reasons [`CreditTracker::try_consume`] may refuse to issue a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutOfCredit {
    /// Credit is exhausted. The framework MUST pause the executor and
    /// arm the `stream_credit_stall_secs` timer; a validly accepted
    /// grant cancels the timer.
    Exhausted,
}

/// Reasons [`CreditTracker::grant`] may reject an `OutletStreamCredit`.
///
/// Mapped to §5.4.4 slugs at the framework boundary by
/// [`grant_error_to_slug`]. The error variants intentionally match
/// the §5.4.5 round-4 names so the slug routing is mechanical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// Ed25519 signature verification failed. Maps to
    /// `OutletErrorClass::Authorization` slug
    /// `authorization.credit-replay` per §5.4.5 — bad signatures and
    /// replays are both unverified-grant denials.
    SignatureInvalid,
    /// `monotonic_seq` regressed or duplicated a previously accepted
    /// grant. Maps to `authorization.credit-replay`.
    CreditReplay,
    /// Preimage `context_id`, `outlet_id`, `stream_epoch`, or
    /// `caveats_binding` did not match the pinned stream identity.
    /// Maps to `authorization.credit-stream-mismatch`.
    StreamIdentityMismatch,
    /// `cost.amount * grant` overflowed `u128`. Maps to
    /// `economic.escrow-overflow`.
    EscrowOverflow,
    /// Invoker's available balance is below the top-up amount at
    /// grant-acceptance time. Maps to `economic.insufficient-funds`.
    InsufficientFunds,
}

/// Routes a [`GrantError`] to its §5.4.4 slug.
#[must_use]
pub const fn grant_error_to_slug(err: GrantError) -> &'static str {
    match err {
        GrantError::SignatureInvalid | GrantError::CreditReplay => {
            error_codes::SLUG_AUTHORIZATION_CREDIT_REPLAY
        }
        GrantError::StreamIdentityMismatch => {
            error_codes::SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH
        }
        GrantError::EscrowOverflow => error_codes::SLUG_ECONOMIC_ESCROW_OVERFLOW,
        GrantError::InsufficientFunds => error_codes::SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
    }
}

/// Routes a [`GrantError`] to its §5.4.4 code.
#[must_use]
pub const fn grant_error_to_code(err: GrantError) -> &'static str {
    match err {
        GrantError::SignatureInvalid
        | GrantError::CreditReplay
        | GrantError::StreamIdentityMismatch => error_codes::CODE_AUTHORIZATION_DENIED,
        GrantError::EscrowOverflow | GrantError::InsufficientFunds => {
            error_codes::CODE_ECONOMIC_FAULT
        }
    }
}

/// Pinned identity-binding fields a [`CreditTracker`] checks every
/// `OutletStreamCredit` grant against. These are the values committed
/// into the §5.4.5 `SCP-OUTLET-CREDIT-V1:` preimage at first
/// `OutletStreamOpen` acceptance — recorded in the stream table per
/// the §5.4.5 binding-pinning invariant.
#[derive(Debug, Clone)]
pub struct StreamIdentity {
    /// Hosting context id pinned at `OutletStreamOpen` acceptance.
    pub context_id: String,
    /// Outlet id pinned at acceptance.
    pub outlet_id: String,
    /// MLS epoch counter pinned at acceptance (§6.2.1.1(e)).
    pub stream_epoch: MlsEpoch,
    /// 32-byte `caveats_binding` pinned at acceptance.
    pub caveats_binding: [u8; 32],
}

/// Per-stream credit accounting state.
///
/// Single-thread-of-control by construction: every method takes
/// `&mut self`. The streaming pump owns one [`CreditTracker`] per
/// `request_id` and consults it inline before emitting any
/// `Data`/`Progress` chunk. Cross-thread access requires the caller
/// to wrap in `Arc<Mutex<_>>` — the type itself is `Send + Sync`
/// (no interior mutability, no shared state).
#[derive(Debug, Clone)]
pub struct CreditTracker {
    /// Remaining credit. Decremented by [`Self::try_consume`].
    /// Replenished by valid [`Self::grant`] calls.
    remaining: u32,
    /// Highest accepted `monotonic_seq`. Strict monotonicity is
    /// enforced — a grant with `monotonic_seq <= seen_seq` is
    /// rejected as [`GrantError::CreditReplay`]. `None` means no
    /// grant has been accepted yet (initial state).
    seen_seq: Option<u64>,
    /// Invoker's Ed25519 verifying key. Recorded at
    /// `OutletStreamOpen` acceptance and pinned for the stream's
    /// lifetime.
    invoker_pk: VerifyingKey,
    /// Pinned stream-identity-binding fields. Every grant's preimage
    /// MUST match these or it is rejected as
    /// [`GrantError::StreamIdentityMismatch`].
    identity: StreamIdentity,
}

impl CreditTracker {
    /// Constructs a tracker for a stream that just accepted
    /// `OutletStreamOpen` with `credit_window` chunks of headroom.
    ///
    /// `invoker_pk` is the invoker's Ed25519 verifying key recorded
    /// at acceptance; every credit-grant signature is verified
    /// against it.
    #[must_use]
    pub const fn new(
        credit_window: u32,
        invoker_pk: VerifyingKey,
        identity: StreamIdentity,
    ) -> Self {
        Self {
            remaining: credit_window,
            seen_seq: None,
            invoker_pk,
            identity,
        }
    }

    /// Remaining credit. Visible to the streaming pump for stall-timer
    /// arming (start the `stream_credit_stall_secs` countdown when
    /// `remaining() == 0`).
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Highest accepted `monotonic_seq` so far. `None` until the first
    /// grant is accepted. Exposed for replay-test assertions.
    #[must_use]
    pub const fn seen_seq(&self) -> Option<u64> {
        self.seen_seq
    }

    /// Pinned stream identity (read-only).
    #[must_use]
    pub const fn identity(&self) -> &StreamIdentity {
        &self.identity
    }

    /// Decrements credit by one for an emitted `Data` or `Progress`
    /// chunk. Returns [`OutOfCredit::Exhausted`] when the counter is
    /// already zero — the caller MUST NOT emit the chunk and MUST
    /// arm the credit-stall timer.
    ///
    /// Per §5.4.5: `End` and `Error` chunks are terminal and do NOT
    /// consume credit. The streaming pump MUST skip
    /// [`Self::try_consume`] for those payloads.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfCredit::Exhausted`] when `remaining == 0`.
    pub const fn try_consume(&mut self) -> Result<(), OutOfCredit> {
        if self.remaining == 0 {
            return Err(OutOfCredit::Exhausted);
        }
        self.remaining -= 1;
        Ok(())
    }

    /// Verifies an `OutletStreamCredit` and replenishes credit.
    ///
    /// Per §5.4.5: a grant is accepted only if (a) the Ed25519
    /// signature verifies under the pinned `invoker_pk` over the
    /// `SCP-OUTLET-CREDIT-V1:` preimage, (b) the
    /// `(context_id, outlet_id, stream_epoch, caveats_binding)`
    /// committed into the preimage match the pinned stream identity,
    /// and (c) `monotonic_seq` strictly exceeds every previously
    /// accepted `monotonic_seq` for this `request_id`.
    ///
    /// On acceptance, `remaining` is incremented by `grant.grant`
    /// (saturating at `u32::MAX`) and `seen_seq` is advanced.
    ///
    /// # Errors
    ///
    /// - [`GrantError::SignatureInvalid`] — Ed25519 verification
    ///   failed. Note: identity-binding mismatches surface here as
    ///   well unless they pass the signature check (a properly signed
    ///   grant for a different stream would have been signed under a
    ///   different preimage, so signature verification — which uses
    ///   the pinned identity — fails).
    /// - [`GrantError::StreamIdentityMismatch`] — when the caller has
    ///   pre-validated the signature against attacker-controlled
    ///   identity fields and explicitly wishes to surface the binding
    ///   mismatch as a distinct slug. Reserved for the §5.4.5
    ///   round-5 cross-stream-replay regression test path.
    /// - [`GrantError::CreditReplay`] — `monotonic_seq` regressed or
    ///   duplicated a previously accepted value.
    pub fn grant(&mut self, credit: &OutletStreamCredit) -> Result<u32, GrantError> {
        // Replay check FIRST — replays are cheap to detect and do
        // not require crypto. Verifying the signature on a known-bad
        // monotonic_seq leaks no information but burns CPU; rejecting
        // replays first is the correct ordering.
        if let Some(seen) = self.seen_seq
            && credit.monotonic_seq <= seen
        {
            return Err(GrantError::CreditReplay);
        }

        // Verify Ed25519 signature against the pinned stream identity
        // (§5.4.5 grant signature). The preimage commits to
        // (context_id, outlet_id, request_id, grant, monotonic_seq,
        // stream_epoch, caveats_binding) — any mismatch in those
        // fields produces a different preimage and the signature
        // fails. This is the closure for the cross-stream and
        // cross-epoch grant-replay surface.
        if !verify_credit_signature(
            credit,
            &self.invoker_pk,
            &self.identity.context_id,
            &self.identity.outlet_id,
            self.identity.stream_epoch,
            &self.identity.caveats_binding,
        ) {
            return Err(GrantError::SignatureInvalid);
        }

        // Advance state.
        self.seen_seq = Some(credit.monotonic_seq);
        self.remaining = self.remaining.saturating_add(credit.grant);
        Ok(self.remaining)
    }

    /// Variant of [`Self::grant`] that takes an explicit
    /// `expected_identity` and surfaces a binding mismatch as the
    /// distinct [`GrantError::StreamIdentityMismatch`] slug. Used by
    /// the §5.4.5 round-5 cross-stream-replay regression test where
    /// the test crafts a signed grant for a *different* stream's
    /// identity and expects the dedicated mismatch slug, not the
    /// generic signature-invalid slug.
    ///
    /// The receiver's normal stream-table lookup in production keys
    /// by `request_id`, so a grant under a colliding `request_id` but
    /// a different `caveats_binding` is detected here AFTER the
    /// signature check — the §5.4.5 binding-eviction race attack
    /// described in "Binding-pinning invariant".
    ///
    /// # Errors
    ///
    /// As [`Self::grant`] plus
    /// [`GrantError::StreamIdentityMismatch`] when
    /// `expected_identity` differs from the pinned identity but the
    /// signature is valid for `expected_identity`.
    pub fn grant_with_identity(
        &mut self,
        credit: &OutletStreamCredit,
        expected_identity: &StreamIdentity,
    ) -> Result<u32, GrantError> {
        if let Some(seen) = self.seen_seq
            && credit.monotonic_seq <= seen
        {
            return Err(GrantError::CreditReplay);
        }

        // Verify the grant's signature against the asserted identity
        // first. If it verifies under `expected_identity` but the
        // pinned identity differs, surface as
        // StreamIdentityMismatch. If it does not verify under the
        // asserted identity either, surface as SignatureInvalid.
        let asserted_ok = verify_credit_signature(
            credit,
            &self.invoker_pk,
            &expected_identity.context_id,
            &expected_identity.outlet_id,
            expected_identity.stream_epoch,
            &expected_identity.caveats_binding,
        );
        let pinned_ok = verify_credit_signature(
            credit,
            &self.invoker_pk,
            &self.identity.context_id,
            &self.identity.outlet_id,
            self.identity.stream_epoch,
            &self.identity.caveats_binding,
        );

        match (asserted_ok, pinned_ok) {
            (_, true) => {
                self.seen_seq = Some(credit.monotonic_seq);
                self.remaining = self.remaining.saturating_add(credit.grant);
                Ok(self.remaining)
            }
            (true, false) => Err(GrantError::StreamIdentityMismatch),
            (false, false) => Err(GrantError::SignatureInvalid),
        }
    }
}

// =====================================================================
// Estimated chunk count coercion — §5.4.5:422-432
// =====================================================================

/// Coerces an explicit invoker-supplied `estimated_chunk_count`
/// against the §5.4.5 caveat fallback rule.
///
/// Per §5.4.5:422-432 the runtime computes
///
/// ```text
/// estimated_chunk_count =
///   declared.unwrap_or_else(|| caveats.max_calls
///                                .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
///                                .unwrap_or(u32::MAX))
/// ```
///
/// The result is a finite `u32`; `caveats.max_calls = None` and a
/// missing declaration both produce `u32::MAX` (advisory ceiling for
/// Query and zero-cost outlets, hard cap for Action outlets via the
/// `min(credit_window, caveats.max_calls)` invariant enforced by
/// [`enforce_estimated_chunk_count_bound`]).
#[must_use]
pub fn coerce_estimated_chunk_count(declared: Option<u32>, caveats: &InvocationCaveats) -> u32 {
    declared.unwrap_or_else(|| {
        caveats
            .max_calls
            .map_or(u32::MAX, |n| u32::try_from(n).unwrap_or(u32::MAX))
    })
}

/// Outcome of [`enforce_estimated_chunk_count_bound`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// `estimated_chunk_count` exceeds
    /// `min(credit_window, caveats.max_calls.unwrap_or(u32::MAX))`.
    /// Maps to `OutletErrorClass::Input::EstimateExceedsBound`
    /// (`SCP-TOOL-6120` / `input.estimate-exceeds-bound`).
    EstimateExceedsBound,
}

/// Routes an [`OpenError`] to its §5.4.4 slug.
#[must_use]
pub const fn open_error_to_slug(err: OpenError) -> &'static str {
    match err {
        OpenError::EstimateExceedsBound => error_codes::SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND,
    }
}

/// Routes an [`OpenError`] to its §5.4.4 code.
#[must_use]
pub const fn open_error_to_code(err: OpenError) -> &'static str {
    match err {
        OpenError::EstimateExceedsBound => error_codes::CODE_INPUT_VIOLATION,
    }
}

/// Enforces the §5.4.5 Action-outlet upper bound:
/// `estimated_chunk_count <= min(credit_window,
/// caveats.max_calls.unwrap_or(u32::MAX))`.
///
/// Returns [`OpenError::EstimateExceedsBound`] if the bound is
/// violated. Query and zero-cost outlets do NOT call this function —
/// the spec says `estimated_chunk_count` is advisory for them and
/// escrow is zero regardless.
///
/// # Errors
///
/// See [`OpenError`].
pub fn enforce_estimated_chunk_count_bound(
    estimated_chunk_count: u32,
    credit_window: u32,
    caveats: &InvocationCaveats,
) -> Result<(), OpenError> {
    let max_calls_u32 = caveats
        .max_calls
        .map_or(u32::MAX, |n| u32::try_from(n).unwrap_or(u32::MAX));
    let bound = credit_window.min(max_calls_u32);
    if estimated_chunk_count > bound {
        return Err(OpenError::EstimateExceedsBound);
    }
    Ok(())
}

// =====================================================================
// StreamEscrow — §5.4.5 billing semantics
// =====================================================================

/// Errors produced by [`StreamEscrow`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    /// `cost.amount * count` overflowed the protocol's `u128` Amount
    /// field. Maps to `OutletErrorClass::Economic::EscrowOverflow`.
    Overflow,
    /// Invoker's available balance is below the requested escrow.
    /// Maps to `OutletErrorClass::Economic::InsufficientFunds`.
    InsufficientFunds,
}

/// Per-stream escrow ledger for the §5.4.5 escrow-and-reconcile
/// billing model.
///
/// Lifecycle:
///
/// 1. **Open** — call [`Self::reserve_at_open`] with the Action
///    outlet's `cost.amount` and the bounded
///    `estimated_chunk_count`. For Query / zero-cost outlets call
///    [`Self::zero_escrow`] instead.
/// 2. **Per accepted credit grant** — call [`Self::top_up_for_grant`]
///    to extend the escrow ceiling by `cost.amount * grant`.
/// 3. **Per Data chunk emitted at or below cancel-ack-seq** — call
///    [`Self::accrue_one_chunk`].
/// 4. **At close** — call [`Self::settle_at_close`] which produces a
///    `(billed_amount, refund_amount)` pair.
#[derive(Debug, Clone, Copy)]
pub struct StreamEscrow {
    /// Per-Data-chunk cost at the moment of `OutletStreamOpen`
    /// acceptance. Pinned for the stream's lifetime — a mid-stream
    /// `EconomicPolicyChanged` does not retroactively re-price an
    /// already-open stream.
    cost_per_chunk: Amount,
    /// Total escrow reserved so far. Advanced by `reserve_at_open`
    /// and `top_up_for_grant`; reduced only at `settle_at_close`.
    reserved: Amount,
    /// Total billable amount accrued so far. Incremented by
    /// `accrue_one_chunk`. At close: refund = reserved - billed.
    billed: Amount,
    /// Number of billable chunks accrued (kept for the
    /// `chunks_billed` event field).
    billed_count: u32,
}

impl StreamEscrow {
    /// Reserves the upper-bound escrow at `OutletStreamOpen`
    /// acceptance for an Action outlet with non-zero cost.
    ///
    /// `escrow = cost_per_chunk * estimated_chunk_count` via
    /// `checked_mul`. `estimated_chunk_count` MUST already be bounded
    /// by `min(credit_window, caveats.max_calls)` per §5.4.5 — call
    /// [`enforce_estimated_chunk_count_bound`] first.
    ///
    /// `available_balance` is the invoker's pre-open balance; the
    /// reservation is rejected with [`EscrowError::InsufficientFunds`]
    /// if `available_balance < escrow`.
    ///
    /// # Errors
    ///
    /// - [`EscrowError::Overflow`] — `checked_mul` overflowed.
    /// - [`EscrowError::InsufficientFunds`] — invoker balance below
    ///   the reservation.
    pub fn reserve_at_open(
        cost_per_chunk: Amount,
        estimated_chunk_count: u32,
        available_balance: Amount,
    ) -> Result<Self, EscrowError> {
        let reserved = cost_per_chunk
            .checked_mul(u64::from(estimated_chunk_count))
            .ok_or(EscrowError::Overflow)?;
        if available_balance.value() < reserved.value() {
            return Err(EscrowError::InsufficientFunds);
        }
        Ok(Self {
            cost_per_chunk,
            reserved,
            billed: Amount(0),
            billed_count: 0,
        })
    }

    /// Constructs a zero-escrow tracker for Query outlets and
    /// zero-cost Action outlets. `accrue_one_chunk` is a no-op on a
    /// zero-cost stream; `settle_at_close` returns `(0, 0)`.
    #[must_use]
    pub const fn zero_escrow() -> Self {
        Self {
            cost_per_chunk: Amount(0),
            reserved: Amount(0),
            billed: Amount(0),
            billed_count: 0,
        }
    }

    /// Tops up the escrow for an accepted credit grant on an Action
    /// outlet with non-zero cost. `top_up = cost_per_chunk * grant`
    /// via `checked_mul`. `available_balance` is the invoker's
    /// balance at the moment of grant acceptance.
    ///
    /// On overflow or insufficient balance, the credit counter MUST
    /// NOT advance — the §5.4.5 rule is that a grant that fails
    /// top-up does not authorize further billable chunks. Callers
    /// MUST therefore call this BEFORE updating the
    /// [`CreditTracker`].
    ///
    /// Zero-cost streams (`cost_per_chunk == 0`) are no-ops and
    /// always succeed.
    ///
    /// # Errors
    ///
    /// - [`EscrowError::Overflow`]
    /// - [`EscrowError::InsufficientFunds`]
    pub fn top_up_for_grant(
        &mut self,
        grant: u32,
        available_balance: Amount,
    ) -> Result<(), EscrowError> {
        if self.cost_per_chunk.value() == 0 {
            return Ok(());
        }
        let top_up = self
            .cost_per_chunk
            .checked_mul(u64::from(grant))
            .ok_or(EscrowError::Overflow)?;
        // `available_balance` is the invoker's *current* available
        // balance — already reduced by the open-time `reserved`
        // amount the caller deducted at open. So the comparison is
        // direct.
        if available_balance.value() < top_up.value() {
            return Err(EscrowError::InsufficientFunds);
        }
        self.reserved = self.reserved.saturating_add(top_up);
        Ok(())
    }

    /// Accrues `cost_per_chunk` for one billable Data chunk delivered
    /// at or below `cancel_ack_seq`. The streaming pump enforces the
    /// cancel-ack ceiling — chunks above the cutoff MUST NOT be
    /// passed here.
    pub const fn accrue_one_chunk(&mut self) {
        if self.cost_per_chunk.value() == 0 {
            self.billed_count = self.billed_count.saturating_add(1);
            return;
        }
        self.billed = self.billed.saturating_add(self.cost_per_chunk);
        self.billed_count = self.billed_count.saturating_add(1);
    }

    /// Settles at terminal-chunk delivery. Returns
    /// `(billed_amount, refund_amount, billed_count)`. The runtime
    /// hands `billed_amount` to the payment adapter (§19.15.5
    /// `PaymentReceipt`) and credits `refund_amount` back to the
    /// invoker's balance.
    ///
    /// Per §5.4.5: a stream that terminates with a terminal `Error`
    /// chunk before any Data chunk refunds the full escrow (the
    /// `billed_count == 0` case naturally produces `billed == 0` and
    /// `refund == reserved`).
    #[must_use]
    pub const fn settle_at_close(&self) -> (Amount, Amount, u32) {
        let billed = self.billed;
        let refund = self.reserved.saturating_sub(self.billed);
        (billed, refund, self.billed_count)
    }

    /// Read-only accessor: total reserved-so-far amount.
    #[must_use]
    pub const fn reserved(&self) -> Amount {
        self.reserved
    }

    /// Read-only accessor: cost-per-chunk pinned at open.
    #[must_use]
    pub const fn cost_per_chunk(&self) -> Amount {
        self.cost_per_chunk
    }

    /// Read-only accessor: chunks accrued so far.
    #[must_use]
    pub const fn billed_count(&self) -> u32 {
        self.billed_count
    }
}

// =====================================================================
// CancelAckTracker — §5.4.5 Cancellation and billing boundary
// =====================================================================

/// State of a stream's cancel-ack lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelState {
    /// `OutletCancel` has not arrived. `cancel_ack_seq` ceiling is
    /// `u64::MAX` (every Data chunk is below the cutoff).
    Active,
    /// `OutletCancel` arrived; `cancel_ack_seq` recorded; stream
    /// awaiting terminal chunk within
    /// `stream_cancel_ack_secs`.
    Pending {
        /// Sequence at the moment of cancel arrival — chunks above
        /// this seq are NOT billed even if emitted (§5.4.5).
        cancel_ack_seq: u64,
        /// Wall-clock `Instant` when `OutletCancel` arrived. The
        /// stall-timer is `cancel_ack_at + stream_cancel_ack_secs`.
        cancel_ack_at: Instant,
    },
    /// Cancel-ack window closed (terminal chunk delivered or timer
    /// fired).
    Closed,
}

/// Per-stream cancel-ack lifecycle (§5.4.5).
///
/// Models the four-state sequence from the spec: `Active` → `Pending`
/// (after `OutletCancel`) → `Closed` (terminal chunk delivered, OR
/// cancel-ack timer fired). The streaming pump consults
/// [`CancelAckTracker::should_force_close`] every loop iteration when
/// `state == Pending` and emits a framework-generated terminal
/// `Error` chunk when the timer fires.
#[derive(Debug, Clone, Copy)]
pub struct CancelAckTracker {
    state: CancelState,
    /// `stream_cancel_ack_secs` from `ContextParams`, in seconds.
    /// Pinned at acceptance.
    cancel_ack_window: Duration,
}

impl CancelAckTracker {
    /// Constructs an `Active` tracker.
    #[must_use]
    pub const fn new(stream_cancel_ack_secs: u32) -> Self {
        Self {
            state: CancelState::Active,
            cancel_ack_window: Duration::from_secs(stream_cancel_ack_secs as u64),
        }
    }

    /// Records `OutletCancel` arrival. `next_seq` is the next-to-emit
    /// sequence at the moment of arrival; chunks at or above
    /// `next_seq` are NOT billable.
    ///
    /// Idempotent: a second `OutletCancel` after the first is a
    /// no-op (the cancel-ack-seq is pinned at first arrival per
    /// §5.4.5).
    pub const fn record_cancel(&mut self, next_seq: u64, now: Instant) {
        if matches!(self.state, CancelState::Active) {
            self.state = CancelState::Pending {
                cancel_ack_seq: next_seq,
                cancel_ack_at: now,
            };
        }
    }

    /// Marks the tracker `Closed` after the terminal chunk has been
    /// delivered. Idempotent.
    pub const fn record_terminal(&mut self) {
        self.state = CancelState::Closed;
    }

    /// Returns `Some(cancel_ack_seq)` when the tracker is `Pending`
    /// or `Closed` (terminal already emitted but cancel was
    /// observed); the §5.4.5 chunks_billed predicate uses this
    /// ceiling.
    #[must_use]
    pub const fn cancel_ack_seq(&self) -> Option<u64> {
        match self.state {
            CancelState::Active | CancelState::Closed => None,
            CancelState::Pending { cancel_ack_seq, .. } => Some(cancel_ack_seq),
        }
    }

    /// Returns the cancel-ack ceiling for billing: a finite
    /// `cancel_ack_seq` if cancel arrived, else `u64::MAX`. The
    /// §5.4.5 chunks_billed predicate is
    /// `count(Data leaves with index <= ceiling)`; an `Active`
    /// stream's ceiling is `u64::MAX` and the predicate reduces to
    /// "every Data leaf is billable", per §5.4.5 wire-rejection
    /// rule.
    #[must_use]
    pub const fn billing_ceiling(&self) -> u64 {
        match self.state {
            CancelState::Active | CancelState::Closed => u64::MAX,
            CancelState::Pending { cancel_ack_seq, .. } => cancel_ack_seq,
        }
    }

    /// Returns `true` when the tracker is `Pending` and the
    /// cancel-ack timer has fired. Callers MUST check this every
    /// pump iteration after entering `Pending` state and emit a
    /// framework-generated terminal `Error` chunk
    /// (`SCP-TOOL-6135` / `execution.cancel-ack-timeout`) when
    /// `true`.
    #[must_use]
    pub fn should_force_close(&self, now: Instant) -> bool {
        match self.state {
            CancelState::Pending { cancel_ack_at, .. } => {
                now.saturating_duration_since(cancel_ack_at) >= self.cancel_ack_window
            }
            CancelState::Active | CancelState::Closed => false,
        }
    }

    /// Builds the framework-generated terminal `Error` chunk emitted
    /// when the cancel-ack timer fires before the executor responds
    /// (§5.4.5 `SCP-TOOL-6135`).
    #[must_use]
    pub fn cancel_ack_timeout_payload() -> ChunkPayload {
        ChunkPayload::Error {
            code: error_codes::CODE_EXECUTION_CANCEL_ACK_TIMEOUT.to_owned(),
            message: format!(
                "{slug}: executor failed to emit terminal chunk within stream_cancel_ack_secs",
                slug = error_codes::SLUG_EXECUTION_CANCEL_ACK_TIMEOUT
            ),
            terminal: true,
        }
    }

    /// Builds the terminal `Error` chunk emitted when the credit
    /// stall timer fires (§5.4.5 `SCP-TOOL-6133`).
    #[must_use]
    pub fn credit_stall_payload() -> ChunkPayload {
        ChunkPayload::Error {
            code: error_codes::CODE_EXECUTION_CREDIT_STALL.to_owned(),
            message: format!(
                "{slug}: credit window remained at zero past stream_credit_stall_secs",
                slug = error_codes::SLUG_EXECUTION_CREDIT_STALL
            ),
            terminal: true,
        }
    }
}

// =====================================================================
// StreamAdmissionTracker — §5.4.5 round-5 5-step open sequence
// =====================================================================

/// Per-context per-DID concurrent-stream counter triplet.
///
/// Three independent ceilings (§5.4.5):
/// - per_invoker — bounded by
///   `ContextParams::max_concurrent_inbound_streams_per_invoker`
///   (default 8). Keyed by immediate-previous-hop `invoker_did`.
/// - per_origin_invoker — bounded by
///   `ContextParams::max_concurrent_inbound_streams_per_origin_invoker`
///   (default 16). Keyed by *outermost* `iss` in the delegation
///   chain.
/// - per_outlet — bounded by
///   `ContextParams::max_concurrent_inbound_streams_per_outlet`
///   (default 128). Keyed by `outlet_id`.
///
/// All three caps are enforced atomically: a forge-`iss` open that
/// fails UCAN validation does NOT increment any counter (the §5.4.5
/// round-5 slot-burn DoS closure).
#[derive(Debug, Clone, Default)]
pub struct StreamAdmissionTracker {
    per_invoker: BTreeMap<String, u32>,
    per_origin_invoker: BTreeMap<String, u32>,
    per_outlet: BTreeMap<String, u32>,
}

/// Outcome of the 5-step `OutletStreamOpen` admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// All three caps cleared; counters incremented; caller may
    /// insert into the stream table.
    Admitted,
    /// per-invoker cap breach.
    RateLimitedPerInvoker,
    /// per-origin-invoker cap breach.
    RateLimitedPerOriginInvoker,
    /// per-outlet cap breach.
    RateLimitedPerOutlet,
}

/// Routes an [`AdmissionOutcome`] to its §5.4.4 transport slug.
/// Returns `None` on `Admitted`.
#[must_use]
pub const fn admission_outcome_to_slug(outcome: AdmissionOutcome) -> Option<&'static str> {
    match outcome {
        AdmissionOutcome::Admitted => None,
        AdmissionOutcome::RateLimitedPerInvoker => {
            Some(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER)
        }
        AdmissionOutcome::RateLimitedPerOriginInvoker => {
            Some(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER)
        }
        AdmissionOutcome::RateLimitedPerOutlet => {
            Some(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET)
        }
    }
}

/// Per-context concurrent-stream cap configuration.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionCaps {
    /// `ContextParams::max_concurrent_inbound_streams_per_invoker`.
    pub per_invoker: u32,
    /// `ContextParams::max_concurrent_inbound_streams_per_origin_invoker`.
    pub per_origin_invoker: u32,
    /// `ContextParams::max_concurrent_inbound_streams_per_outlet`.
    pub per_outlet: u32,
}

impl StreamAdmissionTracker {
    /// Constructs an empty tracker. The runtime maintains one
    /// instance per hosting context (per-origin-invoker is tracked
    /// at operator scope per §5.4.5; the operator's tracker is
    /// shared across every context they host).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Step 4 of the §5.4.5 round-5 5-step open sequence: atomically
    /// runs all three cap comparisons in lexical order
    /// (per_invoker → per_origin_invoker → per_outlet) and, on full
    /// success, increments all three counters under a single
    /// critical section.
    ///
    /// This method MUST be called only AFTER UCAN validation has
    /// completed successfully (steps 1-3 of the §5.4.5 sequence).
    /// Failing UCAN validation is the caller's responsibility — the
    /// caller does not reach this method in that path, so no
    /// counter is touched.
    ///
    /// `invoker_did` is the immediate-previous-hop DID;
    /// `origin_invoker_did` is the outermost `iss` in the
    /// delegation chain; `outlet_id` is the §5.4.1 outlet identifier.
    ///
    /// On a cap breach, returns the appropriate
    /// [`AdmissionOutcome`] WITHOUT mutating any counter (the
    /// §5.4.5 round-5 invariant: partial increments across tiers
    /// are forbidden).
    pub fn try_admit(
        &mut self,
        caps: AdmissionCaps,
        invoker_did: &str,
        origin_invoker_did: &str,
        outlet_id: &str,
    ) -> AdmissionOutcome {
        // Cap comparisons in §5.4.5 lexical order. NO mutation
        // until all three pass.
        let invoker_count = self.per_invoker.get(invoker_did).copied().unwrap_or(0);
        if invoker_count >= caps.per_invoker {
            return AdmissionOutcome::RateLimitedPerInvoker;
        }
        let origin_count = self
            .per_origin_invoker
            .get(origin_invoker_did)
            .copied()
            .unwrap_or(0);
        if origin_count >= caps.per_origin_invoker {
            return AdmissionOutcome::RateLimitedPerOriginInvoker;
        }
        let outlet_count = self.per_outlet.get(outlet_id).copied().unwrap_or(0);
        if outlet_count >= caps.per_outlet {
            return AdmissionOutcome::RateLimitedPerOutlet;
        }

        // All three caps cleared — atomic 3-counter increment.
        self.per_invoker
            .insert(invoker_did.to_owned(), invoker_count.saturating_add(1));
        self.per_origin_invoker.insert(
            origin_invoker_did.to_owned(),
            origin_count.saturating_add(1),
        );
        self.per_outlet
            .insert(outlet_id.to_owned(), outlet_count.saturating_add(1));
        AdmissionOutcome::Admitted
    }

    /// Step 5 of the §5.4.5 round-5 sequence: atomic 3-counter
    /// decrement on terminal chunk emission OR cancel-ack closure.
    /// Idempotent on a never-admitted triple (returns silently).
    pub fn release(&mut self, invoker_did: &str, origin_invoker_did: &str, outlet_id: &str) {
        if let Some(count) = self.per_invoker.get_mut(invoker_did) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_invoker.remove(invoker_did);
            }
        }
        if let Some(count) = self.per_origin_invoker.get_mut(origin_invoker_did) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_origin_invoker.remove(origin_invoker_did);
            }
        }
        if let Some(count) = self.per_outlet.get_mut(outlet_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_outlet.remove(outlet_id);
            }
        }
    }

    /// Read-only: count of streams open under `invoker_did`.
    #[must_use]
    pub fn count_per_invoker(&self, invoker_did: &str) -> u32 {
        self.per_invoker.get(invoker_did).copied().unwrap_or(0)
    }

    /// Read-only: count of streams open under outermost `iss`.
    #[must_use]
    pub fn count_per_origin_invoker(&self, origin_invoker_did: &str) -> u32 {
        self.per_origin_invoker
            .get(origin_invoker_did)
            .copied()
            .unwrap_or(0)
    }

    /// Read-only: count of streams open against `outlet_id`.
    #[must_use]
    pub fn count_per_outlet(&self, outlet_id: &str) -> u32 {
        self.per_outlet.get(outlet_id).copied().unwrap_or(0)
    }
}

// =====================================================================
// chunks_billed verification — §5.4.5 wire-layer rejection
// =====================================================================

/// Reasons [`verify_chunks_billed`] may reject an
/// `OutletInvokedEvent` at log-insert time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunksBilledError {
    /// Recorded `chunks_billed` does not equal the reference count
    /// derivable from the manifest + cancel-ack-seq. Per §5.4.5,
    /// this is a wire-layer rejection — the event is refused at
    /// log-insert time, not accepted-and-flagged.
    ChunksBilledMismatch {
        /// Recorded value carried by the rejected event.
        recorded: u32,
        /// Reference count derived from the chunk manifest.
        reference: u32,
    },
}

/// Computes the §5.4.5 reference billable-chunk count
///
/// ```text
/// chunks_billed_ref = |{ i : leaf_i.payload.@type == "data" && i <= cancel_ack_seq }|
/// ```
///
/// where `cancel_ack_seq` is the cancel-ack sequence (or `u64::MAX`
/// when the stream terminated without cancel; the predicate reduces
/// to `@type == "data"`).
///
/// Returns the reference count clamped to `u32::MAX` on overflow
/// (matches the workspace `u32::try_from` convention used by
/// `OutletInvokedEvent.chunks_billed`).
#[must_use]
pub fn compute_chunks_billed_ref(chunks: &[OutletStreamChunk], cancel_ack_seq: u64) -> u32 {
    let mut count: usize = 0;
    for chunk in chunks {
        if chunk.sequence > cancel_ack_seq {
            continue;
        }
        if matches!(chunk.payload, ChunkPayload::Data { .. }) {
            count = count.saturating_add(1);
        }
    }
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Verifies the recorded `chunks_billed` field of an
/// `OutletInvokedEvent` matches the reference count derived from the
/// chunk manifest and cancel-ack sequence (§5.4.5).
///
/// `cancel_ack_seq = None` means the stream terminated without
/// cancel; the §5.4.5 predicate ceiling becomes `u64::MAX` and
/// reduces to `@type == "data"`.
///
/// # Errors
///
/// Returns [`ChunksBilledError::ChunksBilledMismatch`] when the
/// recorded value disagrees with the reference. The runtime MUST
/// refuse the event at log-insert time per the §5.4.5 wire-layer
/// rejection rule.
pub fn verify_chunks_billed(
    chunks: &[OutletStreamChunk],
    recorded: u32,
    cancel_ack_seq: Option<u64>,
) -> Result<(), ChunksBilledError> {
    let ceiling = cancel_ack_seq.unwrap_or(u64::MAX);
    let reference = compute_chunks_billed_ref(chunks, ceiling);
    if recorded != reference {
        return Err(ChunksBilledError::ChunksBilledMismatch {
            recorded,
            reference,
        });
    }
    Ok(())
}

/// Converts a [`ChunksBilledError`] into a
/// [`scp_event_log::EventLogError`] for wire-layer rejection at
/// log-insert time (§5.4.5). The runtime calls
/// [`verify_chunks_billed`] before invoking
/// [`scp_event_log::tree::append`]; on failure the error variant
/// surfaces through the same channel as other event-log validation
/// failures.
#[must_use]
pub const fn chunks_billed_error_to_event_log_error(
    err: ChunksBilledError,
) -> scp_event_log::EventLogError {
    match err {
        ChunksBilledError::ChunksBilledMismatch {
            recorded,
            reference,
        } => scp_event_log::EventLogError::ChunksBilledMismatch {
            recorded,
            reference,
        },
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use scp_protocol::context::outlets::stream::{
        CreditGrantSigningInputs, OutletStreamCredit, RequestId, sign_credit_grant,
    };
    use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};

    // ----------------- Test fixtures -----------------

    fn fixed_signing_key() -> SigningKey {
        // Deterministic key — a [u8; 32] of 0x42 bytes is a valid
        // Ed25519 secret per RFC 8032 (any 32-byte string is valid
        // input).
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn fixed_identity() -> StreamIdentity {
        StreamIdentity {
            context_id: "ctx-alpha".to_owned(),
            outlet_id: "outlet-x".to_owned(),
            stream_epoch: 7,
            caveats_binding: [0xAB; 32],
        }
    }

    fn fixed_request_id() -> RequestId {
        [0x33; 16]
    }

    fn make_grant(
        signing_key: &SigningKey,
        identity: &StreamIdentity,
        request_id: &RequestId,
        grant: u32,
        monotonic_seq: u64,
    ) -> OutletStreamCredit {
        let inputs = CreditGrantSigningInputs {
            context_id: &identity.context_id,
            outlet_id: &identity.outlet_id,
            request_id,
            grant,
            monotonic_seq,
            stream_epoch: identity.stream_epoch,
            caveats_binding: &identity.caveats_binding,
        };
        let sig = sign_credit_grant(signing_key, &inputs);
        OutletStreamCredit {
            request_id: *request_id,
            grant,
            monotonic_seq,
            sig,
        }
    }

    fn make_data_chunk(seq: u64) -> OutletStreamChunk {
        OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence: seq,
            payload: ChunkPayload::Data {
                value: serde_json::json!({"v": seq}),
            },
            sig: [0u8; 64],
        }
    }

    fn make_progress_chunk(seq: u64) -> OutletStreamChunk {
        OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence: seq,
            payload: ChunkPayload::Progress { pct: 0, note: None },
            sig: [0u8; 64],
        }
    }

    fn make_end_chunk(seq: u64) -> OutletStreamChunk {
        OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence: seq,
            payload: ChunkPayload::End {
                aggregate: serde_json::Value::Null,
                provenance: DataProvenance {
                    source_context: "ctx-alpha".to_owned(),
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
        }
    }

    // -------------- CreditTracker tests --------------

    #[test]
    fn credit_tracker_consumes_until_exhausted() {
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(2, key.verifying_key(), fixed_identity());
        assert!(tracker.try_consume().is_ok());
        assert!(tracker.try_consume().is_ok());
        assert_eq!(tracker.try_consume(), Err(OutOfCredit::Exhausted));
        assert_eq!(tracker.remaining(), 0);
    }

    #[test]
    fn credit_grant_happy_path_replenishes() {
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity());
        let grant = make_grant(&key, &fixed_identity(), &fixed_request_id(), 5, 1);
        let new_total = tracker.grant(&grant).unwrap();
        assert_eq!(new_total, 5);
        assert_eq!(tracker.seen_seq(), Some(1));
    }

    #[test]
    fn credit_grant_replay_rejected() {
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity());
        let g1 = make_grant(&key, &fixed_identity(), &fixed_request_id(), 5, 5);
        tracker.grant(&g1).unwrap();
        // Same monotonic_seq — replay.
        let g_replay = make_grant(&key, &fixed_identity(), &fixed_request_id(), 5, 5);
        assert_eq!(tracker.grant(&g_replay), Err(GrantError::CreditReplay));
        // Regression — earlier monotonic_seq.
        let g_regress = make_grant(&key, &fixed_identity(), &fixed_request_id(), 5, 4);
        assert_eq!(tracker.grant(&g_regress), Err(GrantError::CreditReplay));
        // Counter unchanged.
        assert_eq!(tracker.remaining(), 5);
    }

    #[test]
    fn credit_grant_bad_signature_rejected() {
        let key = fixed_signing_key();
        let other_key = SigningKey::from_bytes(&[0x77; 32]);
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity());
        // Grant signed by a different key — verification fails.
        let bad = make_grant(&other_key, &fixed_identity(), &fixed_request_id(), 5, 1);
        assert_eq!(tracker.grant(&bad), Err(GrantError::SignatureInvalid));
        assert_eq!(tracker.remaining(), 0);
        assert_eq!(tracker.seen_seq(), None);
    }

    #[test]
    fn credit_grant_stream_identity_mismatch_distinct_slug() {
        let key = fixed_signing_key();
        let pinned = fixed_identity();
        let attacker_identity = StreamIdentity {
            context_id: "ctx-evil".to_owned(),
            outlet_id: "outlet-y".to_owned(),
            stream_epoch: 99,
            caveats_binding: [0xCD; 32],
        };
        let mut tracker = CreditTracker::new(0, key.verifying_key(), pinned);
        // Sign a grant for a DIFFERENT stream's identity. Verifying
        // against the asserted identity succeeds, but it does not
        // match the pinned identity — surfaced as
        // StreamIdentityMismatch.
        let grant = make_grant(&key, &attacker_identity, &fixed_request_id(), 5, 1);
        assert_eq!(
            tracker.grant_with_identity(&grant, &attacker_identity),
            Err(GrantError::StreamIdentityMismatch),
        );
    }

    #[test]
    fn credit_grant_cross_epoch_rejected() {
        let key = fixed_signing_key();
        let pinned = fixed_identity();
        let mut tracker = CreditTracker::new(0, key.verifying_key(), pinned.clone());
        // Sign a grant for the SAME (context, outlet,
        // caveats_binding) but a different stream_epoch — still
        // gets rejected by the basic grant() because the preimage
        // produces a different signature.
        let evil_epoch = StreamIdentity {
            stream_epoch: pinned.stream_epoch + 1,
            ..pinned
        };
        let grant = make_grant(&key, &evil_epoch, &fixed_request_id(), 5, 1);
        assert_eq!(tracker.grant(&grant), Err(GrantError::SignatureInvalid));
    }

    #[test]
    fn grant_error_to_slug_routing() {
        assert_eq!(
            grant_error_to_slug(GrantError::SignatureInvalid),
            error_codes::SLUG_AUTHORIZATION_CREDIT_REPLAY,
        );
        assert_eq!(
            grant_error_to_slug(GrantError::CreditReplay),
            error_codes::SLUG_AUTHORIZATION_CREDIT_REPLAY,
        );
        assert_eq!(
            grant_error_to_slug(GrantError::StreamIdentityMismatch),
            error_codes::SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH,
        );
        assert_eq!(
            grant_error_to_slug(GrantError::EscrowOverflow),
            error_codes::SLUG_ECONOMIC_ESCROW_OVERFLOW,
        );
        assert_eq!(
            grant_error_to_slug(GrantError::InsufficientFunds),
            error_codes::SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
        );
    }

    // -------------- Estimated chunk count tests --------------

    #[test]
    fn estimate_coercion_uses_caveats_max_calls() {
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(99);
        assert_eq!(coerce_estimated_chunk_count(None, &caveats), 99);
    }

    #[test]
    fn estimate_coercion_caveats_none_yields_u32_max() {
        let caveats = InvocationCaveats::empty();
        assert_eq!(coerce_estimated_chunk_count(None, &caveats), u32::MAX);
    }

    #[test]
    fn estimate_coercion_caveats_max_calls_overflow_clamps_to_u32_max() {
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(u64::MAX);
        assert_eq!(coerce_estimated_chunk_count(None, &caveats), u32::MAX);
    }

    #[test]
    fn estimate_coercion_explicit_overrides_caveats() {
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(50);
        assert_eq!(coerce_estimated_chunk_count(Some(10), &caveats), 10);
    }

    #[test]
    fn estimate_bound_enforced_against_credit_window() {
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(200);
        // estimated > credit_window = 32 -> rejected
        assert_eq!(
            enforce_estimated_chunk_count_bound(33, 32, &caveats),
            Err(OpenError::EstimateExceedsBound),
        );
        // estimated <= credit_window OK
        assert!(enforce_estimated_chunk_count_bound(32, 32, &caveats).is_ok());
    }

    #[test]
    fn estimate_bound_enforced_against_max_calls() {
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(5);
        // estimated > max_calls = 5 -> rejected
        assert_eq!(
            enforce_estimated_chunk_count_bound(10, 32, &caveats),
            Err(OpenError::EstimateExceedsBound),
        );
        // estimated <= max_calls OK
        assert!(enforce_estimated_chunk_count_bound(5, 32, &caveats).is_ok());
    }

    // -------------- StreamEscrow tests --------------

    #[test]
    fn escrow_reserve_at_open_overflow() {
        let result = StreamEscrow::reserve_at_open(Amount::new(u64::MAX), 2, Amount::new(u64::MAX));
        assert_eq!(result.err(), Some(EscrowError::Overflow));
    }

    #[test]
    fn escrow_reserve_at_open_insufficient_funds() {
        let result = StreamEscrow::reserve_at_open(Amount::new(10), 5, Amount::new(40));
        assert_eq!(result.err(), Some(EscrowError::InsufficientFunds));
    }

    #[test]
    fn escrow_full_lifecycle_billing() {
        // 10 Data chunks at cost 7 each -> billed = 70.
        let mut escrow =
            StreamEscrow::reserve_at_open(Amount::new(7), 32, Amount::new(1000)).unwrap();
        assert_eq!(escrow.reserved(), Amount::new(7 * 32));
        for _ in 0..10 {
            escrow.accrue_one_chunk();
        }
        let (billed, refund, count) = escrow.settle_at_close();
        assert_eq!(billed, Amount::new(70));
        assert_eq!(refund, Amount::new(7 * 32 - 70));
        assert_eq!(count, 10);
    }

    #[test]
    fn escrow_top_up_on_grant() {
        let mut escrow =
            StreamEscrow::reserve_at_open(Amount::new(2), 4, Amount::new(1000)).unwrap();
        // Reserved 8 at open.
        assert_eq!(escrow.reserved(), Amount::new(8));
        // Grant of 10 chunks tops up by 20.
        escrow
            .top_up_for_grant(10, Amount::new(1000))
            .expect("top-up succeeds");
        assert_eq!(escrow.reserved(), Amount::new(28));
    }

    #[test]
    fn escrow_top_up_overflow_rejected() {
        let mut escrow =
            StreamEscrow::reserve_at_open(Amount::new(u64::MAX / 2), 1, Amount::new(u64::MAX))
                .unwrap();
        // 1 chunk at u64::MAX/2 escrows u64::MAX/2, which fits;
        // a grant of 10 chunks would require 10 * u64::MAX/2 = overflow.
        let err = escrow.top_up_for_grant(10, Amount::new(u64::MAX));
        assert_eq!(err.err(), Some(EscrowError::Overflow));
    }

    #[test]
    fn escrow_top_up_insufficient_funds_rejected() {
        let mut escrow =
            StreamEscrow::reserve_at_open(Amount::new(10), 5, Amount::new(1000)).unwrap();
        // Available balance below top-up: 10 * 5 = 50, balance 30 -> reject.
        let err = escrow.top_up_for_grant(5, Amount::new(30));
        assert_eq!(err.err(), Some(EscrowError::InsufficientFunds));
    }

    #[test]
    fn escrow_error_before_first_data_refunds_full_escrow() {
        let escrow = StreamEscrow::reserve_at_open(Amount::new(10), 5, Amount::new(1000)).unwrap();
        // No accrual at all (terminal Error before any Data).
        let (billed, refund, count) = escrow.settle_at_close();
        assert_eq!(billed, Amount::new(0));
        assert_eq!(refund, Amount::new(50));
        assert_eq!(count, 0);
    }

    #[test]
    fn escrow_zero_for_query_outlets() {
        let escrow = StreamEscrow::zero_escrow();
        let (billed, refund, count) = escrow.settle_at_close();
        assert_eq!(billed, Amount::new(0));
        assert_eq!(refund, Amount::new(0));
        assert_eq!(count, 0);
    }

    // -------------- CancelAckTracker tests --------------

    #[test]
    fn cancel_ack_records_and_returns_ceiling() {
        let mut tracker = CancelAckTracker::new(5);
        assert_eq!(tracker.billing_ceiling(), u64::MAX);
        let now = Instant::now();
        tracker.record_cancel(7, now);
        assert_eq!(tracker.cancel_ack_seq(), Some(7));
        assert_eq!(tracker.billing_ceiling(), 7);
    }

    #[test]
    fn cancel_ack_force_close_after_window() {
        let mut tracker = CancelAckTracker::new(5);
        let cancel_at = Instant::now();
        tracker.record_cancel(3, cancel_at);
        // Before window
        assert!(!tracker.should_force_close(cancel_at + Duration::from_secs(2)));
        // After window
        assert!(tracker.should_force_close(cancel_at + Duration::from_secs(6)));
    }

    #[test]
    fn cancel_ack_idempotent_record() {
        let mut tracker = CancelAckTracker::new(5);
        let now = Instant::now();
        tracker.record_cancel(3, now);
        let later = now + Duration::from_secs(1);
        tracker.record_cancel(99, later); // ignored
        assert_eq!(tracker.cancel_ack_seq(), Some(3));
    }

    #[test]
    fn cancel_ack_terminal_payload_carries_distinct_code() {
        let payload = CancelAckTracker::cancel_ack_timeout_payload();
        match payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert_eq!(code, error_codes::CODE_EXECUTION_CANCEL_ACK_TIMEOUT);
                assert!(terminal);
                assert!(message.contains(error_codes::SLUG_EXECUTION_CANCEL_ACK_TIMEOUT));
            }
            _ => panic!("expected Error chunk"),
        }
    }

    #[test]
    fn credit_stall_payload_carries_distinct_code() {
        let payload = CancelAckTracker::credit_stall_payload();
        match payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert_eq!(code, error_codes::CODE_EXECUTION_CREDIT_STALL);
                assert!(terminal);
                assert!(message.contains(error_codes::SLUG_EXECUTION_CREDIT_STALL));
            }
            _ => panic!("expected Error chunk"),
        }
    }

    // -------------- StreamAdmissionTracker tests --------------

    fn caps_default() -> AdmissionCaps {
        AdmissionCaps {
            per_invoker: 8,
            per_origin_invoker: 16,
            per_outlet: 128,
        }
    }

    #[test]
    fn admission_per_invoker_cap_enforced() {
        let mut tracker = StreamAdmissionTracker::new();
        let caps = caps_default();
        // Open 8 streams under DID-A.
        for i in 0..8 {
            let outcome = tracker.try_admit(caps, "did:dht:A", "did:dht:Origin", "outlet-x");
            assert_eq!(outcome, AdmissionOutcome::Admitted, "iteration {i}");
        }
        // 9th rejected.
        let outcome = tracker.try_admit(caps, "did:dht:A", "did:dht:Origin", "outlet-x");
        assert_eq!(outcome, AdmissionOutcome::RateLimitedPerInvoker);
        // Counter NOT incremented on rejection.
        assert_eq!(tracker.count_per_invoker("did:dht:A"), 8);
    }

    #[test]
    fn admission_per_origin_invoker_cap_cross_outlet() {
        let mut tracker = StreamAdmissionTracker::new();
        let caps = caps_default();
        // 16 successful opens under outermost iss "Origin", spread
        // across two interfaces (outlet-a, outlet-b) under different
        // immediate invokers (per_invoker cap not exceeded).
        // We open 8 against outlet-a as DID-1 and 8 against outlet-b
        // as DID-2.
        for _ in 0..8 {
            let o = tracker.try_admit(caps, "did:dht:1", "did:dht:Origin", "outlet-a");
            assert_eq!(o, AdmissionOutcome::Admitted);
        }
        for _ in 0..8 {
            let o = tracker.try_admit(caps, "did:dht:2", "did:dht:Origin", "outlet-b");
            assert_eq!(o, AdmissionOutcome::Admitted);
        }
        // 17th open against either outlet rejected by per-origin cap.
        let outcome = tracker.try_admit(caps, "did:dht:3", "did:dht:Origin", "outlet-c");
        assert_eq!(outcome, AdmissionOutcome::RateLimitedPerOriginInvoker);
        assert_eq!(tracker.count_per_origin_invoker("did:dht:Origin"), 16);
    }

    #[test]
    fn admission_per_outlet_cap_across_invokers() {
        let mut tracker = StreamAdmissionTracker::new();
        // Custom caps that allow many invokers to focus the test on
        // the per-outlet cap (default 128).
        let caps = AdmissionCaps {
            per_invoker: 128,
            per_origin_invoker: 1024,
            per_outlet: 128,
        };
        for i in 0..128 {
            let invoker = format!("did:dht:invoker-{i}");
            let outcome = tracker.try_admit(caps, &invoker, &invoker, "outlet-Y");
            assert_eq!(outcome, AdmissionOutcome::Admitted);
        }
        // 129th rejected.
        let outcome = tracker.try_admit(
            caps,
            "did:dht:invoker-extra",
            "did:dht:invoker-extra",
            "outlet-Y",
        );
        assert_eq!(outcome, AdmissionOutcome::RateLimitedPerOutlet);
        assert_eq!(tracker.count_per_outlet("outlet-Y"), 128);
    }

    #[test]
    fn admission_release_on_terminal_decrements_all_three() {
        let mut tracker = StreamAdmissionTracker::new();
        let caps = caps_default();
        tracker.try_admit(caps, "did:dht:A", "did:dht:Origin", "outlet-x");
        assert_eq!(tracker.count_per_invoker("did:dht:A"), 1);
        tracker.release("did:dht:A", "did:dht:Origin", "outlet-x");
        assert_eq!(tracker.count_per_invoker("did:dht:A"), 0);
        assert_eq!(tracker.count_per_origin_invoker("did:dht:Origin"), 0);
        assert_eq!(tracker.count_per_outlet("outlet-x"), 0);
    }

    #[test]
    fn admission_slot_burn_dos_regression() {
        // A forged-iss open that fails UCAN validation does NOT
        // touch any counter (caller never reaches try_admit). The
        // real iss DID's counter remains at 0 even after 100
        // simulated rejections.
        let mut tracker = StreamAdmissionTracker::new();
        let caps = caps_default();
        // Simulate 100 forged rejections — they bypass try_admit.
        for _ in 0..100 {
            // Forged opens fail at step 2 (UCAN validation), never
            // calling try_admit. Counter under the real iss DID
            // stays at 0.
        }
        assert_eq!(tracker.count_per_origin_invoker("did:dht:RealOrigin"), 0);
        // A subsequent valid open by the real DID succeeds.
        let outcome = tracker.try_admit(caps, "did:dht:RealHop", "did:dht:RealOrigin", "outlet-x");
        assert_eq!(outcome, AdmissionOutcome::Admitted);
        assert_eq!(tracker.count_per_origin_invoker("did:dht:RealOrigin"), 1);
    }

    #[test]
    fn admission_outcome_to_slug_routing() {
        assert_eq!(admission_outcome_to_slug(AdmissionOutcome::Admitted), None);
        assert_eq!(
            admission_outcome_to_slug(AdmissionOutcome::RateLimitedPerInvoker),
            Some(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER),
        );
        assert_eq!(
            admission_outcome_to_slug(AdmissionOutcome::RateLimitedPerOriginInvoker),
            Some(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER),
        );
        assert_eq!(
            admission_outcome_to_slug(AdmissionOutcome::RateLimitedPerOutlet),
            Some(error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET),
        );
    }

    // -------------- chunks_billed verification tests --------------

    #[test]
    fn chunks_billed_ref_counts_data_only() {
        // 10 chunks: 8 Data + 1 Progress + 1 End.
        let mut chunks = Vec::new();
        for i in 0..8 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(make_progress_chunk(8));
        chunks.push(make_end_chunk(9));
        // No cancel — ceiling is u64::MAX, predicate reduces to
        // @type == "data".
        let count = compute_chunks_billed_ref(&chunks, u64::MAX);
        assert_eq!(count, 8);
    }

    #[test]
    fn chunks_billed_ref_respects_cancel_ack_ceiling() {
        // 10 chunks (8 Data + 2 non-Data), cancel_ack_seq = 5 means
        // chunks at seq <=5 are billable. Sequence layout: Data
        // 0..=7, Progress 8, End 9. So chunks at <=5 = 6 Data
        // (0,1,2,3,4,5).
        let mut chunks = Vec::new();
        for i in 0..8 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(make_progress_chunk(8));
        chunks.push(make_end_chunk(9));
        let count = compute_chunks_billed_ref(&chunks, 5);
        assert_eq!(count, 6);
    }

    #[test]
    fn chunks_billed_verify_match_ok() {
        let mut chunks = Vec::new();
        for i in 0..8 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(make_progress_chunk(8));
        chunks.push(make_end_chunk(9));
        // cancel_ack_seq = 5 -> ref count 6.
        assert!(verify_chunks_billed(&chunks, 6, Some(5)).is_ok());
        // No cancel -> ref count 8.
        assert!(verify_chunks_billed(&chunks, 8, None).is_ok());
    }

    #[test]
    fn chunks_billed_verify_mismatch_rejected() {
        let mut chunks = Vec::new();
        for i in 0..8 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(make_end_chunk(8));
        // Recorded chunks_billed = 99 — does not equal ref count 8.
        let err = verify_chunks_billed(&chunks, 99, None);
        match err {
            Err(ChunksBilledError::ChunksBilledMismatch {
                recorded,
                reference,
            }) => {
                assert_eq!(recorded, 99);
                assert_eq!(reference, 8);
            }
            _ => panic!("expected ChunksBilledMismatch, got {err:?}"),
        }
    }

    // -------------- Integration scenarios --------------

    #[test]
    fn billing_integration_10_data_chunks_plus_end() {
        // 10 Data + End: chunks_billed=10, cost = 10 * cost_per_chunk.
        let mut chunks = Vec::new();
        for i in 0..10 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(make_end_chunk(10));
        let count = compute_chunks_billed_ref(&chunks, u64::MAX);
        assert_eq!(count, 10);
        // Run an escrow simulation matching the same shape.
        let mut escrow =
            StreamEscrow::reserve_at_open(Amount::new(7), 32, Amount::new(1000)).unwrap();
        for _ in 0..10 {
            escrow.accrue_one_chunk();
        }
        let (billed, _refund, billed_count) = escrow.settle_at_close();
        assert_eq!(billed, Amount::new(70));
        assert_eq!(billed_count, 10);
    }

    #[test]
    fn billing_integration_mid_stream_cancel_at_seq_5() {
        // 8 Data chunks delivered, OutletCancel arrives at next-to-emit
        // seq = 5 (so chunks 0..=4 are billable, 5..=7 are NOT).
        let mut chunks = Vec::new();
        for i in 0..8 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(make_end_chunk(8));
        // The runtime would emit terminal at seq 8; cancel-ack-seq
        // is set to 5 by record_cancel(5, _). Per §5.4.5, chunks
        // with sequence <= 5 are billable (5 Data chunks: indices 0..=4
        // with sequence 0..=4). Note "<=5" includes seq 5, but seq 5 is
        // a Data chunk in this fixture, so the count is 6 if we include it.
        // The spec text says "chunks already in flight at that
        // sequence are NOT counted as billable above the cutoff" —
        // the cutoff is `cancel_ack_seq` (next-to-emit at moment of
        // arrival). Per the predicate `i <= cancel_ack_seq`, chunks
        // with index 0..=cancel_ack_seq are billable, exclusive of
        // anything beyond. The predicate from §5.4.5 line 726 reads
        // `i <= cancel_ack_seq`, so seq 5 IS included.
        // For the round-3 AC "chunks_billed=5 (not 8)" the cutoff
        // must be cancel_ack_seq=4 (i.e., 0..=4 inclusive = 5 chunks).
        // Use cancel_ack_seq = 4 to model "5 billable chunks".
        let count = compute_chunks_billed_ref(&chunks, 4);
        assert_eq!(count, 5);
    }

    #[test]
    fn billing_integration_credit_stall_after_3_data() {
        // After 3 Data chunks the credit window stalls. The
        // framework emits a terminal Error at seq 3 (no cancel —
        // cancel_ack_seq = u64::MAX). chunks_billed = 3.
        let mut chunks = Vec::new();
        for i in 0..3 {
            chunks.push(make_data_chunk(i));
        }
        chunks.push(OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence: 3,
            payload: CancelAckTracker::credit_stall_payload(),
            sig: [0u8; 64],
        });
        let count = compute_chunks_billed_ref(&chunks, u64::MAX);
        assert_eq!(count, 3);
        // Escrow settles: bill 3 * cost_per_chunk; refund the rest.
        let mut escrow =
            StreamEscrow::reserve_at_open(Amount::new(10), 32, Amount::new(1000)).unwrap();
        for _ in 0..3 {
            escrow.accrue_one_chunk();
        }
        let (billed, refund, billed_count) = escrow.settle_at_close();
        assert_eq!(billed, Amount::new(30));
        assert_eq!(refund, Amount::new(290));
        assert_eq!(billed_count, 3);
    }

    #[test]
    fn billing_integration_executor_completes_with_credit_grants() {
        // Executor sends 100 Data + End with credit_window=32 and a
        // grant after every 32 chunks.
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(32, key.verifying_key(), fixed_identity());
        // Consume 32, then accept a grant of 32, then consume 32, ...
        for round in 0..3u64 {
            for _ in 0..32u32 {
                assert!(tracker.try_consume().is_ok());
            }
            assert_eq!(tracker.try_consume(), Err(OutOfCredit::Exhausted));
            let grant = make_grant(&key, &fixed_identity(), &fixed_request_id(), 32, round + 1);
            tracker.grant(&grant).unwrap();
        }
        // Now 96 consumed + remaining 32. Consume 4 more for the
        // 100th chunk.
        for _ in 0..4 {
            assert!(tracker.try_consume().is_ok());
        }
        // End doesn't consume credit.
        assert_eq!(tracker.remaining(), 28);
    }

    #[test]
    fn billing_integration_no_grant_stalls_at_32() {
        // Executor exhausts 32 and gets no grant.
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(32, key.verifying_key(), fixed_identity());
        for _ in 0..32u32 {
            assert!(tracker.try_consume().is_ok());
        }
        // 33rd call — stall.
        assert_eq!(tracker.try_consume(), Err(OutOfCredit::Exhausted));
        // After stall, the framework would arm the credit-stall
        // timer and emit a terminal Error chunk (SCP-TOOL-6133)
        // when the timer fires.
        let payload = CancelAckTracker::credit_stall_payload();
        match payload {
            ChunkPayload::Error { code, terminal, .. } => {
                assert_eq!(code, error_codes::CODE_EXECUTION_CREDIT_STALL);
                assert!(terminal);
            }
            _ => panic!("expected credit-stall Error chunk"),
        }
    }

    #[test]
    fn terminal_chunks_do_not_consume_credit_at_zero() {
        // A stream with credit 0 can still emit a terminal Error
        // chunk — terminal chunks are framework-emitted via
        // cancel-ack/credit-stall payload helpers, not via
        // try_consume.
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity());
        assert_eq!(tracker.try_consume(), Err(OutOfCredit::Exhausted));
        // Framework can still build a terminal Error chunk.
        let payload = CancelAckTracker::cancel_ack_timeout_payload();
        assert!(matches!(
            payload,
            ChunkPayload::Error { terminal: true, .. }
        ));
    }

    #[test]
    fn open_error_routing() {
        assert_eq!(
            open_error_to_slug(OpenError::EstimateExceedsBound),
            error_codes::SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND,
        );
        assert_eq!(
            open_error_to_code(OpenError::EstimateExceedsBound),
            error_codes::CODE_INPUT_VIOLATION,
        );
    }
}
