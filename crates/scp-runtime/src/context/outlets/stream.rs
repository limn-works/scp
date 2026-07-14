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
    ChunkPayload, MlsEpoch, OutletStreamChunk, OutletStreamCredit, compute_chunk_manifest_root,
    verify_credit_signature,
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
    /// The stream's pump has already exited (terminal chunk emitted,
    /// channel closed, or forced terminate) — a credit grant arriving
    /// after the stream reached its terminal state is a session-lifecycle
    /// violation, not an authorization denial. Maps to the Protocol-class
    /// `protocol.stream-already-closed` slug (`SCP-OUTLET-6101`,
    /// `CODE_PROTOCOL_SESSION`) per §5.4.4:426. Gated in
    /// `apply_credit_grant` BEFORE the signature/replay checks run, so a
    /// grant against a closed stream never mutates escrow or the credit
    /// counter. Distinct from the Authorization-class `SCP-OUTLET-6110`
    /// band: the caller's right to grant was never withdrawn; the stream's
    /// substrate is simply gone.
    StreamClosed,
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
        GrantError::StreamClosed => error_codes::SLUG_PROTOCOL_STREAM_ALREADY_CLOSED,
    }
}

/// Reasons a streaming `OutletStreamCancel` may be rejected.
///
/// [`Self::SignatureInvalid`] maps to
/// `OutletErrorClass::Authorization::AuthorizationFailed` per §5.4.5
/// round-7 — the runtime collapses the granular reasons to the uniform
/// authorization-denied slug so an unauthenticated cancel does not leak
/// whether the failure was signature-invalid vs identity-mismatch vs
/// unknown-stream.
///
/// [`Self::CursorAdvanced`] and [`Self::Signing`] are round-8 additions for
/// the [`StreamSessionHandle::apply_outlet_cancel_signed`] atomic primitive
/// (the runtime signs the cancel itself, deriving `next_seq` from the live
/// cursor): `CursorAdvanced` is a **retryable** race signal (the cursor
/// moved between the lock-free preimage build and the re-lock), `Signing`
/// wraps a signer-side failure.
///
/// [`StreamSessionHandle::apply_outlet_cancel_signed`]:
///   super::dispatch::StreamSessionHandle::apply_outlet_cancel_signed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelError {
    /// Ed25519 signature verification failed under the pinned
    /// `invoker_pk`, or the caller identity did not match the pinned
    /// `(context_id, outlet_id, caveats_binding)` triple. Maps to
    /// `authorization.denied`. No stream state is mutated.
    SignatureInvalid,
    /// The runtime's next-to-emit cursor advanced between reading it (to
    /// build the cancel preimage off-lock) and re-acquiring the lock to
    /// apply the cancel, and the bounded retry budget was exhausted.
    /// **Retryable** — the bridge SHOULD re-issue the cancel, which
    /// re-reads the now-current cursor. `signed` is the cursor the
    /// exhausted attempt signed against; `current` is the live cursor
    /// observed at the final re-lock.
    CursorAdvanced {
        /// The next-to-emit cursor the exhausted attempt signed against.
        signed: u64,
        /// The live next-to-emit cursor observed at the final re-lock.
        current: u64,
    },
    /// The [`StreamSigner`] failed to produce the cancel signature.
    /// Carries the signer error for diagnostics.
    ///
    /// [`StreamSigner`]: super::signer::StreamSigner
    Signing(super::signer::StreamSignerError),
}

/// Routes a [`CancelError`] to its §5.4.4 slug.
#[must_use]
pub const fn cancel_error_to_slug(err: &CancelError) -> &'static str {
    match err {
        // SignatureInvalid + an internal signing failure both collapse to
        // the uniform authorization-denied slug on the wire so a cancel
        // failure does not leak which internal stage failed. CursorAdvanced
        // is a transport-class retryable race, mapped to the rate-limited
        // slug (the bridge re-issues rather than surfacing a hard denial).
        CancelError::SignatureInvalid | CancelError::Signing(_) => {
            error_codes::SLUG_AUTHORIZATION_DENIED
        }
        CancelError::CursorAdvanced { .. } => error_codes::SLUG_TRANSPORT_RATE_LIMITED,
    }
}

/// Routes a [`CancelError`] to its §5.4.4 code.
#[must_use]
pub const fn cancel_error_to_code(err: &CancelError) -> &'static str {
    match err {
        CancelError::SignatureInvalid | CancelError::Signing(_) => {
            error_codes::CODE_AUTHORIZATION_DENIED
        }
        CancelError::CursorAdvanced { .. } => error_codes::CODE_TRANSPORT_FAULT,
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
        // §5.4.4:426 — a control-plane call against an already-terminal
        // stream is a Protocol-class session-lifecycle violation
        // (`SCP-OUTLET-6101`), NOT the Authorization-class `SCP-OUTLET-6110`.
        GrantError::StreamClosed => error_codes::CODE_PROTOCOL_SESSION,
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
    /// §5.4.5:758 HARD cumulative billable-chunk ceiling, pinned at
    /// acceptance to the VALIDATED-NARROWED `max_calls` caveat (coerced to
    /// `u32`; `None` means no `max_calls` constraint — unbounded). This is
    /// the protocol's upper limit on how many billable (Data) chunks CAN
    /// flow over the stream's lifetime "regardless of executor behavior":
    /// no quantity of credit grants can raise it. [`Self::grant`] clamps
    /// every replenishment so `billed_emitted + remaining` never exceeds
    /// `max_billable`, and the per-chunk gate refuses any billable chunk
    /// once `billed_emitted` reaches it.
    max_billable: Option<u32>,
    /// Count of billable (Data, at/below the cancel-ack ceiling) chunks
    /// emitted so far. Monotonically increasing; never reset. Compared
    /// against [`Self::max_billable`] to enforce the §5.4.5:758 cumulative
    /// ceiling. Incremented exactly once per forwarded billable Data chunk
    /// by [`Self::record_billed_emission`].
    billed_emitted: u32,
}

impl CreditTracker {
    /// Constructs a tracker for a stream that just accepted
    /// `OutletStreamOpen` with `credit_window` chunks of headroom.
    ///
    /// `invoker_pk` is the invoker's Ed25519 verifying key recorded
    /// at acceptance; every credit-grant signature is verified
    /// against it.
    ///
    /// `max_billable` is the §5.4.5:758 HARD cumulative billable-chunk
    /// ceiling — the VALIDATED-NARROWED `caveats.max_calls` coerced to
    /// `u32` (`None` = unbounded). The initial `credit_window` is itself
    /// clamped to this ceiling so a stream can never start with more
    /// headroom than `max_calls` permits.
    #[must_use]
    pub fn new(
        credit_window: u32,
        invoker_pk: VerifyingKey,
        identity: StreamIdentity,
        max_billable: Option<u32>,
    ) -> Self {
        // The initial window cannot exceed the cumulative ceiling: at open
        // `billed_emitted == 0`, so the headroom is clamped to
        // `max_billable` directly.
        let remaining = max_billable.map_or(credit_window, |cap| credit_window.min(cap));
        Self {
            remaining,
            seen_seq: None,
            invoker_pk,
            identity,
            max_billable,
            billed_emitted: 0,
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

    /// Pinned invoker Ed25519 verifying key (read-only).
    ///
    /// Exposed so downstream callers (the dispatch pump's cancel-auth
    /// path) can verify `OutletStreamCancel` signatures against the
    /// same key the credit tracker pinned at acceptance — closing the
    /// round-7 cancel-auth gap without duplicating the pinned key in a
    /// second piece of state.
    #[must_use]
    pub const fn invoker_pk(&self) -> &VerifyingKey {
        &self.invoker_pk
    }

    /// §5.4.5:758 HARD cumulative billable-chunk ceiling (read-only).
    /// `None` means no `max_calls` constraint (unbounded).
    #[must_use]
    pub const fn max_billable(&self) -> Option<u32> {
        self.max_billable
    }

    /// Count of billable Data chunks emitted so far (read-only). Compared
    /// against [`Self::max_billable`] by the per-chunk gate to enforce the
    /// §5.4.5:758 cumulative ceiling.
    #[must_use]
    pub const fn billed_emitted(&self) -> u32 {
        self.billed_emitted
    }

    /// `true` when the §5.4.5:758 cumulative billable ceiling has been
    /// reached — `billed_emitted >= max_billable`. Always `false` when
    /// `max_billable` is `None` (unbounded). The per-chunk gate consults
    /// this BEFORE consuming credit so a stream that has already emitted
    /// `max_calls` billable chunks forwards no further billable chunk
    /// regardless of available credit.
    #[must_use]
    pub const fn cumulative_ceiling_reached(&self) -> bool {
        match self.max_billable {
            Some(cap) => self.billed_emitted >= cap,
            None => false,
        }
    }

    /// Records that one billable Data chunk was emitted, advancing
    /// `billed_emitted` toward the §5.4.5:758 cumulative ceiling.
    /// Saturating — the counter never wraps. Called exactly once per
    /// forwarded billable Data chunk (at or below the cancel-ack ceiling).
    pub const fn record_billed_emission(&mut self) {
        self.billed_emitted = self.billed_emitted.saturating_add(1);
    }

    /// Replenishes `remaining` by `grant`, CLAMPED so the stream's
    /// cumulative billable headroom never exceeds the §5.4.5:758
    /// `max_billable` ceiling: after the clamp,
    /// `billed_emitted + remaining <= max_billable`.
    ///
    /// The clamp does NOT reject the grant — partial headroom up to the
    /// ceiling is still made available (a grant whose full amount would
    /// overshoot is honored up to the remaining cumulative budget). The
    /// invariant it preserves is that no number of grants can raise the
    /// cumulative ceiling "regardless of executor behavior": the most a
    /// stream can ever bill is `max_billable`. When `max_billable` is
    /// `None` (unbounded) the grant is a plain saturating add.
    const fn replenish_clamped(&mut self, grant: u32) {
        let raw = self.remaining.saturating_add(grant);
        self.remaining = match self.max_billable {
            // Headroom that remains under the cumulative ceiling, given how
            // many billable chunks have already been emitted. Saturating
            // sub so an already-exhausted stream clamps to zero.
            Some(cap) => {
                let cumulative_headroom = cap.saturating_sub(self.billed_emitted);
                if raw < cumulative_headroom {
                    raw
                } else {
                    cumulative_headroom
                }
            }
            None => raw,
        };
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

        // Advance state. Replenishment is CLAMPED to the §5.4.5:758
        // cumulative ceiling so no grant can raise the maximum billable
        // chunk count beyond the pinned `max_billable`.
        self.seen_seq = Some(credit.monotonic_seq);
        self.replenish_clamped(credit.grant);
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
    /// Lifecycle note: this method is PURE — it never inspects stream
    /// liveness. The §5.4.4:426 grant-after-close gate
    /// (`GrantError::StreamClosed`) lives in the dispatch layer's
    /// `apply_credit_grant`, which checks `SharedSessionState::pump_exited`
    /// under the session lock BEFORE calling this method. A post-terminal
    /// grant is rejected there and never reaches the credit counter.
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
                // Replenishment CLAMPED to the §5.4.5:758 cumulative
                // ceiling — see [`Self::replenish_clamped`].
                self.seen_seq = Some(credit.monotonic_seq);
                self.replenish_clamped(credit.grant);
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

/// The EFFECTIVE hard billable-chunk ceiling for a stream — the §5.4.5:758
/// [`CreditTracker::max_billable`] AND-folded with the `amount_max_cumulative`
/// value cap.
///
/// Two independent caveats jointly bound how many billable (Data) chunks a
/// stream may ever emit:
/// - `max_calls` bounds the chunk COUNT directly (coerced to `u32`).
/// - `amount_max_cumulative` bounds the cumulative VALUE; at `cost_per_chunk`
///   per chunk, that is at most `floor(cap / cost_per_chunk)` billable chunks.
///
/// The effective ceiling is the MINIMUM of the two. Folding the value cap into
/// the chunk ceiling is what physically prevents a stream from billing more
/// cumulative value than the cap permits: the per-chunk gate
/// ([`crate::context::outlets::invoke::apply_stream_chunk_gate`]) consults
/// [`CreditTracker::cumulative_ceiling_reached`] and terminates the stream once
/// `billed_emitted` reaches this ceiling, regardless of available credit or how
/// small the invoker-declared `estimated_chunk_count` was. `credit_window` only
/// bounds the INITIAL window — grants extend billing up to this ceiling (clamped
/// by [`CreditTracker::replenish_clamped`]) but never past it.
///
/// Returns `None` (unbounded) only when BOTH `max_calls` is absent AND there is
/// no value-cap constraint (no `amount_max_cumulative`, or `cost_per_chunk == 0`
/// so cumulative value is always zero). A zero-cost stream with `max_calls`
/// still returns that `max_calls` ceiling.
#[must_use]
pub fn effective_max_billable_chunks(
    cost_per_chunk: Amount,
    caveats: &InvocationCaveats,
) -> Option<u32> {
    let max_calls_ceiling = caveats
        .max_calls
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
    // The value cap constrains the chunk count only when chunks actually bill
    // (cost > 0). `floor(cap / cost)` is the most billable chunks whose
    // cumulative value stays at/under the cap.
    let cost = cost_per_chunk.value();
    let cap_ceiling = match caveats.amount_max_cumulative {
        Some(cap) if cost > 0 => Some(u32::try_from(cap.value() / cost).unwrap_or(u32::MAX)),
        _ => None,
    };
    match (max_calls_ceiling, cap_ceiling) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// Computes the cumulative-counter reserve amount for a streaming open
/// (§5.4.5 `amount_max_cumulative`).
///
/// The reserve is the WORST-CASE billable spend a stream can incur — the
/// EFFECTIVE billable-chunk ceiling ([`effective_max_billable_chunks`], which
/// already folds the value cap into the chunk ceiling) times `cost_per_chunk`.
/// Reserving over this worst case — NOT over the invoker-declared
/// `estimated_chunk_count`, which an invoker can declare as low as `1` while
/// `max_calls = 50` — means the durable
/// [`CaveatKind::AmountCumulative`](scp_protocol::trust::CaveatKind) counter can
/// never be billed for more than it reserved. Close-time settlement releases the
/// unspent portion, so the counter ends at exactly the billed spend.
///
/// Because the chunk ceiling already incorporates `floor(cap / cost)`, the
/// reserve `cost × ceiling` is `<= cap` by construction (no overflow, no clamp
/// needed).
///
/// Returns `None` when there is no `amount_max_cumulative` cap to enforce (the
/// caller skips the cumulative CAS entirely), or `Some(0)` for a zero-cost
/// stream that has a cap (it never bills, so the reservation is zero).
#[must_use]
pub fn cumulative_reserve_amount(
    cost_per_chunk: Amount,
    caveats: &InvocationCaveats,
) -> Option<u64> {
    // No value cap ⇒ no cumulative reservation at all.
    caveats.amount_max_cumulative?;
    let cost = cost_per_chunk.value();
    if cost == 0 {
        // Zero-cost streams never bill against the cumulative counter.
        return Some(0);
    }
    // With a value cap AND non-zero cost, `effective_max_billable_chunks` always
    // yields a bounded ceiling (the `floor(cap / cost)` term). Fall back to
    // `floor(cap / cost)` directly so this never silently reserves 0. Reserve
    // `cost × ceiling`, which is `<= cap` by construction; `saturating_mul`
    // guards the degenerate `u32::MAX` ceiling defensively.
    let cap = caveats.amount_max_cumulative.map_or(0, Amount::value);
    let ceiling = effective_max_billable_chunks(cost_per_chunk, caveats)
        .unwrap_or_else(|| u32::try_from(cap / cost).unwrap_or(u32::MAX));
    Some(u64::from(ceiling).saturating_mul(cost))
}

/// Outcome of [`enforce_estimated_chunk_count_bound`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// `estimated_chunk_count` exceeds
    /// `min(credit_window, caveats.max_calls.unwrap_or(u32::MAX))`.
    /// Maps to `OutletErrorClass::Input::EstimateExceedsBound`
    /// (`SCP-OUTLET-6120` / `input.estimate-exceeds-bound`).
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

    /// Constructs the escrow ledger from a hold that has ALREADY been
    /// reserved (DEBITED) against the invoker's `MemberBudgetTracker` by
    /// [`crate::context::manager::ContextManager::outlet_stream_reserve_escrow`].
    ///
    /// This is the production constructor (E2 remediation). The
    /// InsufficientFunds / Overflow balance decision now lives entirely in
    /// the manager — the only lock holder — so the dispatch path no longer
    /// re-checks balance: it simply records the `reserved` hold the manager
    /// debited and the `cost_per_chunk` needed for per-grant top-ups and
    /// per-chunk accrual. `reserved == Amount(0)` for Query / zero-cost
    /// streams (where the manager performed no debit).
    ///
    /// [`Self::reserve_at_open`] is retained for the existing unit tests
    /// that exercise the pure check-and-reserve arithmetic in isolation,
    /// but it is NO LONGER the production gate.
    #[must_use]
    pub const fn from_reserved(cost_per_chunk: Amount, reserved: Amount) -> Self {
        Self {
            cost_per_chunk,
            reserved,
            billed: Amount(0),
            billed_count: 0,
        }
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

    /// Extends the escrow ceiling by a top-up that has ALREADY been
    /// reserved (DEBITED) against the invoker's `MemberBudgetTracker` by
    /// [`crate::context::manager::ContextManager::outlet_stream_reserve_grant`].
    ///
    /// This is the production per-grant path (E2 remediation): the
    /// overflow / insufficient-funds decision happened in the manager
    /// under the context lock, so this method neither re-multiplies nor
    /// re-checks balance — it records the already-debited `top_up`.
    /// `saturating_add` guards the (manager-already-rejected) overflow
    /// edge defensively. A zero `top_up` (zero-cost stream) is a no-op.
    pub const fn apply_reserved_top_up(&mut self, top_up: Amount) {
        self.reserved = self.reserved.saturating_add(top_up);
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
    /// sequence at the moment of arrival and becomes the cancel-ack
    /// sequence (`cancel_ack_seq`). Per §5.4.5:530(3) that sequence slot
    /// belongs to the **terminal cancel-ack chunk**, and per §5.4.5:530(1)
    /// any `Data`/`Progress` still in flight at `sequence >= cancel_ack_seq`
    /// is dropped-and-not-billed by the pump gate
    /// ([`super::invoke::apply_stream_chunk_gate`], `>=` boundary). The
    /// §5.4.5:558/563 `chunks_billed` formula
    /// (`compute_chunks_billed_ref`) stays **inclusive** (`sequence <=
    /// cancel_ack_seq`); it yields the correct count because the sealed
    /// manifest carries only `Data` at `sequence < cancel_ack_seq` (the
    /// cancel-ack slot holds the non-`Data` terminal). See
    /// [`Self::billing_ceiling`] and `compute_chunks_billed_ref`.
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
    /// (`SCP-OUTLET-6135` / `execution.cancel-ack-timeout`) when
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
    /// (§5.4.5 `SCP-OUTLET-6135`).
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
    /// stall timer fires (§5.4.5 `SCP-OUTLET-6133`).
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

/// Per-context per-DID concurrent-stream counters.
///
/// Two of the three §5.4.5 ceilings are per-context and live here; the
/// third — per-origin-invoker — is tracked at OPERATOR scope in
/// [`OriginAdmissionTracker`], NOT in this per-context tracker:
/// - per_invoker — bounded by
///   `ContextParams::max_concurrent_inbound_streams_per_invoker`
///   (default 8). Keyed by immediate-previous-hop `invoker_did`.
/// - per_outlet — bounded by
///   `ContextParams::max_concurrent_inbound_streams_per_outlet`
///   (default 128). Keyed by `outlet_id`.
///
/// The per-origin-invoker ceiling
/// (`max_concurrent_inbound_streams_per_origin_invoker`, default 16,
/// keyed by the *outermost* `iss` in the delegation chain) is
/// deliberately ABSENT from this per-context tracker. §05-contexts.md:448
/// mandates it be tracked at operator scope — "shared across every
/// context the operator hosts" — so a caller cannot fan out across a
/// cluster of interfaces hosted by the same operator to bypass the
/// per-context limit. Keying it per-context (as the other two are)
/// would reset the origin counter per context, letting one origin DID
/// open `per_origin_invoker` streams in EACH of N contexts and fan out
/// `N × cap` streams against a single operator — saturating the
/// node-wide pump semaphore (§5.4.5 round-8) and mounting a node-wide
/// DoS the spec's named defense is designed to prevent. That dimension
/// therefore lives in the operator-owned [`OriginAdmissionTracker`];
/// [`Self::try_admit`] and [`Self::release`] consult BOTH trackers
/// under a single combined critical section (per-context lock acquired
/// before the operator-scoped lock) so the §5.4.5 "partial increments
/// across tiers are forbidden" invariant is preserved across the split.
///
/// All three caps are enforced atomically: a forge-`iss` open that
/// fails UCAN validation does NOT increment any counter (the §5.4.5
/// round-5 slot-burn DoS closure).
#[derive(Debug, Clone, Default)]
pub struct StreamAdmissionTracker {
    per_invoker: BTreeMap<String, u32>,
    per_outlet: BTreeMap<String, u32>,
}

/// Operator-scoped concurrent-stream counter for the per-origin-invoker
/// ceiling (§05-contexts.md:448).
///
/// Keyed by the *outermost* `iss` in the delegation chain. A single
/// instance is owned by the supervisor (operator) and shared across
/// EVERY context that supervisor hosts — this is precisely what enforces
/// the spec's operator-scope mandate: the count for an origin DID is the
/// SUM of its open streams across all of the operator's contexts, so a
/// caller cannot open `per_origin_invoker` streams in each of N contexts
/// to fan out `N × cap` streams against one operator.
///
/// Bounded by
/// `ContextParams::max_concurrent_inbound_streams_per_origin_invoker`
/// (default 16, range [1, 1024]). Maintained in lock-step with the
/// per-context [`StreamAdmissionTracker`]:
/// [`StreamAdmissionTracker::try_admit`] increments this on admit and
/// [`StreamAdmissionTracker::release`] decrements it on stream close,
/// both under a combined critical section. Entries self-remove at zero,
/// so the map is naturally bounded by the number of origins with a live
/// stream — no teardown reap is required.
#[derive(Debug, Clone, Default)]
pub struct OriginAdmissionTracker {
    per_origin_invoker: BTreeMap<String, u32>,
}

impl OriginAdmissionTracker {
    /// Constructs an empty operator-scoped origin tracker. The runtime
    /// maintains exactly ONE instance per supervisor (operator).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current concurrent-stream count for `origin_invoker_did` summed
    /// across every context the operator hosts.
    #[must_use]
    pub fn count_per_origin_invoker(&self, origin_invoker_did: &str) -> u32 {
        self.per_origin_invoker
            .get(origin_invoker_did)
            .copied()
            .unwrap_or(0)
    }

    /// Increments the origin count. The caller MUST have already
    /// confirmed headroom against the per-origin cap inside the same
    /// combined critical section (see [`StreamAdmissionTracker::try_admit`]).
    fn increment(&mut self, origin_invoker_did: &str) {
        let count = self.count_per_origin_invoker(origin_invoker_did);
        self.per_origin_invoker
            .insert(origin_invoker_did.to_owned(), count.saturating_add(1));
    }

    /// Decrements the origin count, removing the entry at zero.
    /// Idempotent on a never-admitted origin (returns silently).
    fn decrement(&mut self, origin_invoker_did: &str) {
        if let Some(count) = self.per_origin_invoker.get_mut(origin_invoker_did) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_origin_invoker.remove(origin_invoker_did);
            }
        }
    }
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
    /// Constructs an empty per-context tracker. The runtime maintains
    /// one instance per hosting context for the per-invoker and
    /// per-outlet ceilings. The per-origin-invoker ceiling is tracked
    /// separately at operator scope in [`OriginAdmissionTracker`] (a
    /// single instance shared across every context the operator hosts),
    /// per §05-contexts.md:448.
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
        origin: &mut OriginAdmissionTracker,
        caps: AdmissionCaps,
        invoker_did: &str,
        origin_invoker_did: &str,
        outlet_id: &str,
    ) -> AdmissionOutcome {
        // Cap comparisons in §5.4.5 lexical order (per_invoker →
        // per_origin_invoker → per_outlet). NO mutation until all three
        // pass. The middle tier reads the OPERATOR-scoped `origin`
        // tracker (§05-contexts.md:448), not a per-context map; the
        // caller holds both this per-context lock and the operator-scoped
        // `origin` lock across this whole method so the three-tier check
        // and increment remain a single atomic critical section.
        let invoker_count = self.per_invoker.get(invoker_did).copied().unwrap_or(0);
        if invoker_count >= caps.per_invoker {
            return AdmissionOutcome::RateLimitedPerInvoker;
        }
        let origin_count = origin.count_per_origin_invoker(origin_invoker_did);
        if origin_count >= caps.per_origin_invoker {
            return AdmissionOutcome::RateLimitedPerOriginInvoker;
        }
        let outlet_count = self.per_outlet.get(outlet_id).copied().unwrap_or(0);
        if outlet_count >= caps.per_outlet {
            return AdmissionOutcome::RateLimitedPerOutlet;
        }

        // All three caps cleared — atomic 3-counter increment across the
        // per-context tracker (per_invoker + per_outlet) and the
        // operator-scoped origin tracker.
        self.per_invoker
            .insert(invoker_did.to_owned(), invoker_count.saturating_add(1));
        origin.increment(origin_invoker_did);
        self.per_outlet
            .insert(outlet_id.to_owned(), outlet_count.saturating_add(1));
        AdmissionOutcome::Admitted
    }

    /// Step 5 of the §5.4.5 round-5 sequence: atomic 3-counter
    /// decrement on terminal chunk emission OR cancel-ack closure.
    /// Idempotent on a never-admitted triple (returns silently).
    pub fn release(
        &mut self,
        origin: &mut OriginAdmissionTracker,
        invoker_did: &str,
        origin_invoker_did: &str,
        outlet_id: &str,
    ) {
        if let Some(count) = self.per_invoker.get_mut(invoker_did) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_invoker.remove(invoker_did);
            }
        }
        // Decrement the OPERATOR-scoped origin counter (§05-contexts.md:448)
        // so a closed stream frees the origin's operator-wide capacity —
        // else the origin count leaks and permanently caps the origin.
        origin.decrement(origin_invoker_did);
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
// Event-local wire-invariant — enforced at the event-log APPEND boundary
// =====================================================================

/// Enforces the §5.4.5 `chunks_billed` wire-invariant that is verifiable
/// from an [`OutletInvokedEvent`] **alone** — the form the event-log
/// appender holds, which does NOT carry the chunk sequence.
///
/// # What §5.4.5 grants an event-local appender
///
/// §5.4.5 ("`chunks_billed` is verifiable from the manifest") states the
/// FULL check — `chunks_billed == chunks_billed_ref` — is derivable from
/// "the manifest root, the sealed chunk sequence, and the cancel-ack
/// sequence." The appender has only the **event**: it holds the manifest
/// *root* (`stream_manifest_hash`) but neither the chunk *sequence* (needed
/// to re-hash leaves and count `@type == "data"`) nor the `cancel_ack_seq`
/// (the event's [`StreamTerminalStatus::Cancelled`] is a bare unit variant
/// — the cancel-ack sequence is NOT a field of `OutletInvokedEvent`).
/// Therefore the appender CANNOT re-derive `chunks_billed_ref`; claiming to
/// would be dishonest.
///
/// # The invariant it CAN and MUST enforce
///
/// §5.4.5 defines `chunks_billed` as "the count of `Data` chunks at or
/// below the cancel-ack sequence" and `stream_chunk_count` as "the total
/// chunk count \[which\] includes Progress/End/Error". The billable set is
/// a strict **subset** of the total, so
///
/// ```text
/// chunks_billed <= stream_chunk_count
/// ```
///
/// holds for EVERY well-formed event — and this bound uses only two fields
/// the event carries. An event that records more billable `Data` chunks
/// than the total number of chunks it claims to have emitted is
/// structurally impossible; it is a wire-layer violation the appender
/// refuses at log-insert time (§5.4.5: "refused at log-insert time, not
/// accepted-and-flagged"), so ANY malformed `OutletInvokedEvent` — from any
/// source — is durably rejected. The non-streaming/unary case (no chunks)
/// is covered by the same bound: `stream_chunk_count == 0` forces
/// `chunks_billed == 0`.
///
/// The tighter, manifest-derived equality remains enforced UPSTREAM at
/// chunk-emission time (the dispatch pump's gate drops above-cancel-ack
/// `Data` chunks before they are billed or committed to the manifest
/// frontier); this function is the durable event-local backstop, not a
/// replacement for it.
///
/// # Errors
///
/// Returns [`ChunksBilledError::ChunksBilledMismatch`] when
/// `chunks_billed > stream_chunk_count`. The `reference` field carries the
/// event-local ceiling (`stream_chunk_count`) that `chunks_billed`
/// exceeded.
pub const fn verify_outlet_invoked_event_local(
    event: &scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
) -> Result<(), ChunksBilledError> {
    if event.chunks_billed > event.stream_chunk_count {
        return Err(ChunksBilledError::ChunksBilledMismatch {
            recorded: event.chunks_billed,
            reference: event.stream_chunk_count,
        });
    }
    Ok(())
}

// =====================================================================
// Full manifest-derived wire-invariant — §5.4.5:566 equality
// =====================================================================

/// Source from which the full §5.4.5:566 manifest-derived `chunks_billed`
/// reference is re-derived at log-insert time.
///
/// `Copy` (both variants hold only a shared slice + `Copy` scalars) so the
/// verification entry points take it by value without a borrow dance.
#[derive(Clone, Copy)]
pub enum ChunksBilledSource<'a> {
    /// A retained chunk sequence (one-shot 2-chunk manifest, xctx reassembly,
    /// import). The reference is recomputed by re-hashing leaves and counting
    /// `@type == "data"` at/below the cancel-ack ceiling.
    Sequence(&'a [OutletStreamChunk]),
    /// The O(log n) frontier the dispatch pump retains (ADR-061) instead of
    /// the payload set: the running root + billed/leaf counts.
    Frontier {
        /// RFC-6962 manifest root the pump folded over the emitted sequence.
        root: [u8; 32],
        /// Billable `Data`-chunk count at/below the cancel-ack ceiling.
        billed_count: u64,
        /// Total leaf (chunk) count including the terminal chunk.
        leaf_count: u64,
    },
}

/// Enforces the FULL §5.4.5:566 `chunks_billed` equality (manifest root +
/// sealed sequence + cancel-ack) that [`verify_outlet_invoked_event_local`]
/// (the event-local `<=` backstop) cannot.
///
/// For [`ChunksBilledSource::Sequence`], re-derives `chunks_billed_ref` via
/// [`verify_chunks_billed`] AND checks
/// `stream_manifest_hash == compute_chunk_manifest_root(chunks)` and
/// `stream_chunk_count == chunks.len()`. For [`ChunksBilledSource::Frontier`],
/// checks the event's three stream aggregates equal the frontier's.
///
/// # Errors
///
/// Returns [`ChunksBilledError::ChunksBilledMismatch`] when the recorded
/// `chunks_billed` disagrees with the manifest-derived reference, when the
/// recorded manifest root / leaf count diverge from the re-derived (or
/// frontier-carried) values, or when the chunk sequence cannot be
/// JCS-canonicalized into a manifest root. The runtime MUST refuse the event
/// at log-insert time per the §5.4.5 wire-layer rejection rule.
pub fn verify_outlet_invoked_event_manifest(
    event: &scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
    source: ChunksBilledSource<'_>,
) -> Result<(), ChunksBilledError> {
    match source {
        ChunksBilledSource::Sequence(chunks) => {
            // (1) Full manifest-derived `chunks_billed` equality — the tighter
            // check the event-local backstop cannot make.
            verify_chunks_billed(chunks, event.chunks_billed, event.cancel_ack_seq)?;
            // The manifest-derived reference for divergence reporting below.
            // Equal to `event.chunks_billed` once (1) passes.
            let reference =
                compute_chunks_billed_ref(chunks, event.cancel_ack_seq.unwrap_or(u64::MAX));
            let mismatch = || ChunksBilledError::ChunksBilledMismatch {
                recorded: event.chunks_billed,
                reference,
            };
            // (2) Manifest root + sealed-sequence binding: the recorded root
            // and leaf count MUST match what re-hashing the sequence yields.
            let root = compute_chunk_manifest_root(chunks).map_err(|_jcs_err| mismatch())?;
            let leaf_count = u64::try_from(chunks.len()).unwrap_or(u64::MAX);
            if event.stream_manifest_hash != root
                || u64::from(event.stream_chunk_count) != leaf_count
            {
                return Err(mismatch());
            }
            Ok(())
        }
        ChunksBilledSource::Frontier {
            root,
            billed_count,
            leaf_count,
        } => {
            if event.stream_manifest_hash != root
                || u64::from(event.chunks_billed) != billed_count
                || u64::from(event.stream_chunk_count) != leaf_count
            {
                return Err(ChunksBilledError::ChunksBilledMismatch {
                    recorded: event.chunks_billed,
                    reference: u32::try_from(billed_count).unwrap_or(u32::MAX),
                });
            }
            Ok(())
        }
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
    use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
    use scp_protocol::context::outlets::stream::{
        CreditGrantSigningInputs, OutletStreamCredit, RequestId, StreamTerminalStatus,
        sign_credit_grant,
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
        let mut tracker = CreditTracker::new(2, key.verifying_key(), fixed_identity(), None);
        assert!(tracker.try_consume().is_ok());
        assert!(tracker.try_consume().is_ok());
        assert_eq!(tracker.try_consume(), Err(OutOfCredit::Exhausted));
        assert_eq!(tracker.remaining(), 0);
    }

    #[test]
    fn credit_grant_happy_path_replenishes() {
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity(), None);
        let grant = make_grant(&key, &fixed_identity(), &fixed_request_id(), 5, 1);
        let new_total = tracker.grant(&grant).unwrap();
        assert_eq!(new_total, 5);
        assert_eq!(tracker.seen_seq(), Some(1));
    }

    #[test]
    fn credit_grant_replay_rejected() {
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity(), None);
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
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity(), None);
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
        let mut tracker = CreditTracker::new(0, key.verifying_key(), pinned, None);
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
        let mut tracker = CreditTracker::new(0, key.verifying_key(), pinned.clone(), None);
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

    // -------- Effective billable ceiling + cumulative reserve --------

    #[test]
    fn effective_ceiling_folds_value_cap_below_max_calls() {
        // max_calls = 50 but cap 100 / cost 10 = 10 → ceiling 10.
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(50);
        caveats.amount_max_cumulative = Some(Amount::new(100));
        assert_eq!(
            effective_max_billable_chunks(Amount::new(10), &caveats),
            Some(10)
        );
    }

    #[test]
    fn effective_ceiling_max_calls_binds_when_below_value_cap() {
        // cap 1000 / cost 2 = 500, but max_calls = 5 → ceiling 5.
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(5);
        caveats.amount_max_cumulative = Some(Amount::new(1_000));
        assert_eq!(
            effective_max_billable_chunks(Amount::new(2), &caveats),
            Some(5)
        );
    }

    #[test]
    fn effective_ceiling_value_cap_only_when_max_calls_absent() {
        // No max_calls; cap 100 / cost 10 = 10 → ceiling 10 (NOT unbounded).
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(100));
        assert_eq!(
            effective_max_billable_chunks(Amount::new(10), &caveats),
            Some(10)
        );
    }

    #[test]
    fn effective_ceiling_unbounded_when_no_constraint() {
        // No max_calls, no value cap → unbounded.
        let caveats = InvocationCaveats::empty();
        assert_eq!(
            effective_max_billable_chunks(Amount::new(10), &caveats),
            None
        );
    }

    #[test]
    fn effective_ceiling_zero_cost_ignores_value_cap() {
        // Zero cost: cumulative value is always 0, so the cap does not bound
        // chunks. max_calls still binds.
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(7);
        caveats.amount_max_cumulative = Some(Amount::new(100));
        assert_eq!(
            effective_max_billable_chunks(Amount::new(0), &caveats),
            Some(7)
        );
        // Zero cost AND no max_calls → unbounded (the cap on a free stream
        // never bites).
        let mut only_cap = InvocationCaveats::empty();
        only_cap.amount_max_cumulative = Some(Amount::new(100));
        assert_eq!(
            effective_max_billable_chunks(Amount::new(0), &only_cap),
            None
        );
    }

    #[test]
    fn cumulative_reserve_none_without_value_cap() {
        // No `amount_max_cumulative` → no cumulative reservation at all.
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(50);
        assert_eq!(cumulative_reserve_amount(Amount::new(10), &caveats), None);
    }

    #[test]
    fn cumulative_reserve_is_worst_case_spend_over_effective_ceiling() {
        // cap 100, cost 10, max_calls 50 → effective ceiling 10 → reserve 100.
        // The reserve is INDEPENDENT of any declared estimate; it always equals
        // `cost × effective_ceiling`, never `cost × estimated_chunk_count`.
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(50);
        caveats.amount_max_cumulative = Some(Amount::new(100));
        assert_eq!(
            cumulative_reserve_amount(Amount::new(10), &caveats),
            Some(100)
        );
        // The reserve never exceeds the cap.
        let reserve = cumulative_reserve_amount(Amount::new(10), &caveats).unwrap();
        assert!(reserve <= 100, "reserve {reserve} must be <= cap 100");
    }

    #[test]
    fn cumulative_reserve_max_calls_binds_below_cap() {
        // cap 1000, cost 2, max_calls 5 → effective ceiling 5 → reserve 10.
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(5);
        caveats.amount_max_cumulative = Some(Amount::new(1_000));
        assert_eq!(
            cumulative_reserve_amount(Amount::new(2), &caveats),
            Some(10)
        );
    }

    #[test]
    fn cumulative_reserve_unbounded_max_calls_reserves_up_to_cap() {
        // No max_calls; cap 95, cost 10 → floor(95/10) = 9 chunks → reserve 90
        // (the largest multiple of cost at/under the cap). The leftover 5 < cost
        // can never be billed (a 10th chunk would exceed the cap, and the
        // per-chunk gate blocks it).
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(95));
        assert_eq!(
            cumulative_reserve_amount(Amount::new(10), &caveats),
            Some(90)
        );
    }

    #[test]
    fn cumulative_reserve_zero_cost_is_zero() {
        // Zero-cost stream with a cap → reserves nothing (never bills).
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(100));
        caveats.max_calls = Some(50);
        assert_eq!(cumulative_reserve_amount(Amount::new(0), &caveats), Some(0));
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
        let mut origin = OriginAdmissionTracker::new();
        let caps = caps_default();
        // Open 8 streams under DID-A.
        for i in 0..8 {
            let outcome =
                tracker.try_admit(&mut origin, caps, "did:dht:A", "did:dht:Origin", "outlet-x");
            assert_eq!(outcome, AdmissionOutcome::Admitted, "iteration {i}");
        }
        // 9th rejected.
        let outcome =
            tracker.try_admit(&mut origin, caps, "did:dht:A", "did:dht:Origin", "outlet-x");
        assert_eq!(outcome, AdmissionOutcome::RateLimitedPerInvoker);
        // Counter NOT incremented on rejection.
        assert_eq!(tracker.count_per_invoker("did:dht:A"), 8);
    }

    #[test]
    fn admission_per_origin_invoker_cap_cross_outlet() {
        let mut tracker = StreamAdmissionTracker::new();
        let mut origin = OriginAdmissionTracker::new();
        let caps = caps_default();
        // 16 successful opens under outermost iss "Origin", spread
        // across two interfaces (outlet-a, outlet-b) under different
        // immediate invokers (per_invoker cap not exceeded).
        // We open 8 against outlet-a as DID-1 and 8 against outlet-b
        // as DID-2.
        for _ in 0..8 {
            let o = tracker.try_admit(&mut origin, caps, "did:dht:1", "did:dht:Origin", "outlet-a");
            assert_eq!(o, AdmissionOutcome::Admitted);
        }
        for _ in 0..8 {
            let o = tracker.try_admit(&mut origin, caps, "did:dht:2", "did:dht:Origin", "outlet-b");
            assert_eq!(o, AdmissionOutcome::Admitted);
        }
        // 17th open against either outlet rejected by per-origin cap.
        let outcome =
            tracker.try_admit(&mut origin, caps, "did:dht:3", "did:dht:Origin", "outlet-c");
        assert_eq!(outcome, AdmissionOutcome::RateLimitedPerOriginInvoker);
        assert_eq!(origin.count_per_origin_invoker("did:dht:Origin"), 16);
    }

    /// §05-contexts.md:448 core assertion: the per-origin-invoker cap is
    /// OPERATOR-scoped, NOT per-context. One origin DID fanning across N
    /// distinct per-context trackers (each a separate hosted context)
    /// shares ONE operator-scoped `OriginAdmissionTracker`, so it hits
    /// the per-origin cap at 16 total — NOT 16 × N. This is the defense
    /// against a caller fanning out across a cluster of the operator's
    /// interfaces to saturate the node-wide pump semaphore.
    #[test]
    fn admission_per_origin_cap_operator_scoped_across_contexts() {
        // The operator's single origin tracker, shared across all
        // contexts it hosts.
        let mut origin = OriginAdmissionTracker::new();
        // Four distinct per-context trackers (four hosted contexts).
        let mut ctx_a = StreamAdmissionTracker::new();
        let mut ctx_b = StreamAdmissionTracker::new();
        let mut ctx_c = StreamAdmissionTracker::new();
        let mut ctx_d = StreamAdmissionTracker::new();
        // per_origin_invoker = 16, per_invoker = 8, per_outlet = 128.
        let caps = caps_default();

        let origin_did = "did:dht:FanoutOrigin";
        let mut admitted = 0u32;
        let mut rejected_by_origin = 0u32;

        // 5 opens in EACH of the 4 contexts (20 total) by the SAME origin
        // DID. Per context, 5 <= per_invoker(8) and 5 <= per_outlet(128),
        // so neither PER-CONTEXT cap binds. Only the OPERATOR-scoped
        // per-origin cap (16) can stop these — and it must, at 16 total.
        // If the per-origin dimension were (wrongly) per-context, every
        // context would independently admit all 5 → 20 admits → the
        // §05-contexts.md:448 fan-out DoS.
        for (i, ctx) in [&mut ctx_a, &mut ctx_b, &mut ctx_c, &mut ctx_d]
            .into_iter()
            .enumerate()
        {
            let outlet = format!("outlet-{i}");
            let invoker = format!("did:dht:hop-{i}");
            for _ in 0..5 {
                match ctx.try_admit(&mut origin, caps, &invoker, origin_did, &outlet) {
                    AdmissionOutcome::Admitted => admitted += 1,
                    AdmissionOutcome::RateLimitedPerOriginInvoker => rejected_by_origin += 1,
                    other => panic!("unexpected per-context rejection: {other:?}"),
                }
            }
        }

        // Exactly the operator-scoped cap admitted — NOT 4 × per-context.
        assert_eq!(
            admitted, 16,
            "operator-scoped per-origin cap must bound the origin to 16 streams \
             TOTAL across all contexts (§05-contexts.md:448)"
        );
        assert_eq!(
            rejected_by_origin, 4,
            "20 attempts - 16 admits = 4 rejections by the per-origin cap"
        );
        assert_eq!(origin.count_per_origin_invoker(origin_did), 16);
    }

    #[test]
    fn admission_per_outlet_cap_across_invokers() {
        let mut tracker = StreamAdmissionTracker::new();
        let mut origin = OriginAdmissionTracker::new();
        // Custom caps that allow many invokers to focus the test on
        // the per-outlet cap (default 128).
        let caps = AdmissionCaps {
            per_invoker: 128,
            per_origin_invoker: 1024,
            per_outlet: 128,
        };
        for i in 0..128 {
            let invoker = format!("did:dht:invoker-{i}");
            let outcome = tracker.try_admit(&mut origin, caps, &invoker, &invoker, "outlet-Y");
            assert_eq!(outcome, AdmissionOutcome::Admitted);
        }
        // 129th rejected.
        let outcome = tracker.try_admit(
            &mut origin,
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
        let mut origin = OriginAdmissionTracker::new();
        let caps = caps_default();
        tracker.try_admit(&mut origin, caps, "did:dht:A", "did:dht:Origin", "outlet-x");
        assert_eq!(tracker.count_per_invoker("did:dht:A"), 1);
        assert_eq!(origin.count_per_origin_invoker("did:dht:Origin"), 1);
        tracker.release(&mut origin, "did:dht:A", "did:dht:Origin", "outlet-x");
        assert_eq!(tracker.count_per_invoker("did:dht:A"), 0);
        assert_eq!(origin.count_per_origin_invoker("did:dht:Origin"), 0);
        assert_eq!(tracker.count_per_outlet("outlet-x"), 0);
    }

    /// §05-contexts.md:448: a closed stream frees the origin's
    /// operator-wide capacity. Fill the per-origin cap across two
    /// contexts, close one stream, and confirm the origin can open one
    /// more (the released slot is reusable, in ANY of the operator's
    /// contexts).
    #[test]
    fn admission_origin_release_frees_operator_capacity() {
        let mut origin = OriginAdmissionTracker::new();
        let mut ctx_a = StreamAdmissionTracker::new();
        let mut ctx_b = StreamAdmissionTracker::new();
        // Cap the per-origin dimension low to keep the test tight;
        // per-invoker/per-outlet high so only the origin cap binds.
        let caps = AdmissionCaps {
            per_invoker: 100,
            per_origin_invoker: 2,
            per_outlet: 100,
        };
        // Two opens by the same origin, one in each context — fills the
        // operator-wide per-origin cap of 2.
        assert_eq!(
            ctx_a.try_admit(&mut origin, caps, "did:dht:h", "did:dht:O", "outlet-a"),
            AdmissionOutcome::Admitted
        );
        assert_eq!(
            ctx_b.try_admit(&mut origin, caps, "did:dht:h", "did:dht:O", "outlet-b"),
            AdmissionOutcome::Admitted
        );
        assert_eq!(origin.count_per_origin_invoker("did:dht:O"), 2);
        // A third open (any context) is rejected — origin cap saturated.
        assert_eq!(
            ctx_a.try_admit(&mut origin, caps, "did:dht:h", "did:dht:O", "outlet-a2"),
            AdmissionOutcome::RateLimitedPerOriginInvoker
        );
        // Close the ctx-a stream — frees one operator-wide origin slot.
        ctx_a.release(&mut origin, "did:dht:h", "did:dht:O", "outlet-a");
        assert_eq!(origin.count_per_origin_invoker("did:dht:O"), 1);
        // The freed slot is reusable — even in a DIFFERENT context.
        assert_eq!(
            ctx_b.try_admit(&mut origin, caps, "did:dht:h", "did:dht:O", "outlet-b2"),
            AdmissionOutcome::Admitted
        );
        assert_eq!(origin.count_per_origin_invoker("did:dht:O"), 2);
    }

    #[test]
    fn admission_slot_burn_dos_regression() {
        // A forged-iss open that fails UCAN validation does NOT
        // touch any counter (caller never reaches try_admit). The
        // real iss DID's counter remains at 0 even after 100
        // simulated rejections.
        let mut tracker = StreamAdmissionTracker::new();
        let mut origin = OriginAdmissionTracker::new();
        let caps = caps_default();
        // Simulate 100 forged rejections — they bypass try_admit.
        for _ in 0..100 {
            // Forged opens fail at step 2 (UCAN validation), never
            // calling try_admit. Counter under the real iss DID
            // stays at 0.
        }
        assert_eq!(origin.count_per_origin_invoker("did:dht:RealOrigin"), 0);
        // A subsequent valid open by the real DID succeeds.
        let outcome = tracker.try_admit(
            &mut origin,
            caps,
            "did:dht:RealHop",
            "did:dht:RealOrigin",
            "outlet-x",
        );
        assert_eq!(outcome, AdmissionOutcome::Admitted);
        assert_eq!(origin.count_per_origin_invoker("did:dht:RealOrigin"), 1);
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

    // -------------- Event-local wire-invariant (C1) --------------

    fn outlet_invoked_event(stream_chunk_count: u32, chunks_billed: u32) -> OutletInvokedEvent {
        OutletInvokedEvent {
            request_id: "req".to_owned(),
            outlet_id: "outlet".to_owned(),
            invoker_did: scp_did::DID("did:dht:z6MkInvoker".to_owned()),
            status: scp_protocol::context::outlets::OutletStatus::Success,
            execution_time_ms: 1,
            input_hash: "0".repeat(64),
            output_hash: None,
            cost: None,
            stream_chunk_count,
            chunks_billed,
            stream_manifest_hash: [0u8; 32],
            stream_terminal_status: StreamTerminalStatus::Ok,
            cancel_ack_seq: None,
            audit_anomaly: None,
        }
    }

    #[test]
    fn event_local_invariant_accepts_billed_le_count() {
        // billed < count, billed == count, and the zero/unary case all pass.
        verify_outlet_invoked_event_local(&outlet_invoked_event(5, 3)).unwrap();
        verify_outlet_invoked_event_local(&outlet_invoked_event(4, 4)).unwrap();
        verify_outlet_invoked_event_local(&outlet_invoked_event(0, 0)).unwrap();
    }

    #[test]
    fn event_local_invariant_rejects_billed_over_count() {
        let err = verify_outlet_invoked_event_local(&outlet_invoked_event(5, 6));
        match err {
            Err(ChunksBilledError::ChunksBilledMismatch {
                recorded,
                reference,
            }) => {
                assert_eq!(recorded, 6, "recorded = tampered chunks_billed");
                assert_eq!(
                    reference, 5,
                    "reference = event-local ceiling stream_chunk_count"
                );
            }
            _ => panic!("expected ChunksBilledMismatch, got {err:?}"),
        }
        // Even a single over-count (billed == count + 1) is rejected.
        assert!(verify_outlet_invoked_event_local(&outlet_invoked_event(0, 1)).is_err());
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
        // 034 AC24: an executor produces 8 Data, but an OutletCancel arrives
        // at the next-to-emit cursor 5, so `cancel_ack_seq = 5`. Per
        // §5.4.5:530(3) that sequence slot belongs to the TERMINAL cancel-ack
        // chunk, and per §5.4.5:530(1) the pump gate
        // (`apply_stream_chunk_gate`, `sequence >= cancel_ack_seq`) drops the
        // 3 post-cancel in-flight Data (seq 5,6,7) without billing them. So
        // the SEALED MANIFEST the runtime actually commits is `Data[0..5]`
        // followed by the terminal `End` AT seq 5 — no Data ever occupies the
        // cancel-ack slot. The §5.4.5:558/563 `chunks_billed` formula stays
        // INCLUSIVE (`i <= cancel_ack_seq`); over this spec-compliant sealed
        // manifest it counts the 5 Data at seq 0..4 (the `End` at seq 5 is
        // non-Data) and yields 5 with `cancel_ack_seq = 5` — no fudge to 4.
        let mut chunks = Vec::new();
        for i in 0..5 {
            chunks.push(make_data_chunk(i));
        }
        // Terminal cancel-ack chunk occupies `cancel_ack_seq` (= 5).
        chunks.push(make_end_chunk(5));
        let count = compute_chunks_billed_ref(&chunks, 5);
        assert_eq!(
            count, 5,
            "inclusive i<=5 over the sealed manifest (Data seq 0..4 + terminal End at seq 5) = 5"
        );
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
        let mut tracker = CreditTracker::new(32, key.verifying_key(), fixed_identity(), None);
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

    /// §5.4.5:758 grant clamp (HIGH-2): a `CreditTracker` pinned with
    /// `max_billable = Some(10)` never exposes more cumulative headroom
    /// than the ceiling, no matter how large a grant arrives. The grant is
    /// NOT rejected — partial headroom up to the ceiling is still usable —
    /// but the cumulative cap cannot be raised.
    #[test]
    fn grant_clamps_remaining_to_cumulative_max_calls_ceiling() {
        let key = fixed_signing_key();
        // credit_window 32 is clamped to max_billable 10 at construction.
        let mut tracker = CreditTracker::new(32, key.verifying_key(), fixed_identity(), Some(10));
        assert_eq!(
            tracker.remaining(),
            10,
            "initial window clamped to max_billable at open"
        );

        // Emit 4 billable chunks (consume + record).
        for _ in 0..4u32 {
            tracker.try_consume().unwrap();
            tracker.record_billed_emission();
        }
        assert_eq!(tracker.billed_emitted(), 4);
        assert_eq!(tracker.remaining(), 6);

        // A massive grant cannot raise the cumulative ceiling: with 4
        // billed, only 6 cumulative headroom remains (10 - 4), so the
        // clamped remaining is 6 — NOT 6 + 100.
        let grant = make_grant(&key, &fixed_identity(), &fixed_request_id(), 100, 1);
        let new_total = tracker
            .grant(&grant)
            .expect("grant accepted (clamped, not rejected)");
        assert_eq!(
            new_total, 6,
            "remaining clamped to max_billable - billed_emitted"
        );
        assert_eq!(tracker.remaining(), 6);

        // Consume the remaining 6 (total 10 billable) and record them.
        for _ in 0..6u32 {
            tracker.try_consume().unwrap();
            tracker.record_billed_emission();
        }
        assert_eq!(tracker.billed_emitted(), 10);
        assert!(
            tracker.cumulative_ceiling_reached(),
            "ceiling reached at exactly max_calls billable chunks"
        );

        // A further grant yields zero cumulative headroom — the ceiling
        // holds regardless of executor behavior.
        let grant2 = make_grant(&key, &fixed_identity(), &fixed_request_id(), 100, 2);
        let after = tracker
            .grant(&grant2)
            .expect("grant accepted but clamped to zero");
        assert_eq!(after, 0, "no headroom past the cumulative ceiling");
    }

    /// `max_billable = None` (no `max_calls` caveat) is unbounded — the
    /// cumulative ceiling never trips and grants are plain saturating adds.
    #[test]
    fn unbounded_max_billable_never_trips_cumulative_ceiling() {
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(32, key.verifying_key(), fixed_identity(), None);
        assert_eq!(tracker.remaining(), 32, "no clamp when unbounded");
        for _ in 0..1000u32 {
            tracker.record_billed_emission();
        }
        assert!(
            !tracker.cumulative_ceiling_reached(),
            "unbounded stream never reaches a cumulative ceiling"
        );
    }

    #[test]
    fn billing_integration_no_grant_stalls_at_32() {
        // Executor exhausts 32 and gets no grant.
        let key = fixed_signing_key();
        let mut tracker = CreditTracker::new(32, key.verifying_key(), fixed_identity(), None);
        for _ in 0..32u32 {
            assert!(tracker.try_consume().is_ok());
        }
        // 33rd call — stall.
        assert_eq!(tracker.try_consume(), Err(OutOfCredit::Exhausted));
        // After stall, the framework would arm the credit-stall
        // timer and emit a terminal Error chunk (SCP-OUTLET-6133)
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
        let mut tracker = CreditTracker::new(0, key.verifying_key(), fixed_identity(), None);
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
