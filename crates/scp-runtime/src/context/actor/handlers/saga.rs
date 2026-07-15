//! Saga-phase handlers — see
//! [`SagaPhaseMessage`](crate::context::actor::commands::SagaPhaseMessage)
//! and spec §6.2.4 (cross-context outlet-invocation saga).
//!
//! # What runs here
//!
//! The supervisor FSM dispatches per-phase messages to a participant actor;
//! this module implements every phase handler, each running on a LOCAL actor.
//! All phases are fully implemented AND supervisor-driven (the FSM in
//! `supervisor/supervisor.rs` drives them end-to-end via
//! [`Supervisor::start_cross_context_outlet_invocation_saga`](crate::context::supervisor::supervisor::Supervisor::start_cross_context_outlet_invocation_saga)).
//!
//! - **Prepare-A** ([`prepare_a`]) — on the caller-context actor. Validates the
//!   caller holds `outlet:interface` and is in `OutboundPolicy.allowed_callers`,
//!   stages (not applies) the outbound rate-limit decrement + escrow
//!   reservation via the existing
//!   [`reserve_outlet_economy`](crate::context::outlets_helpers::reserve_outlet_economy)
//!   mechanism, Class-S sync-persists fail-closed, and replies the `Send`
//!   reservation handles for the FSM to hold (RAII release on abort).
//!
//! - **Prepare-B** ([`prepare_b`]) — on the target-context actor. In order:
//!   (1) resolves `ucan_proof_id` from B's own UCAN store and re-runs the full
//!   §7 validation RE-BOUND to the carried `caller_did` + `outlet_registration_id`
//!   (the confused-deputy defense), (2) inbound policy, (3) input
//!   schema-specificity floor (§9.2.1), (4) target-context binding, (5)
//!   freshness (§9.14 skew + B's nonce-dedup cache), (6) chain-depth. Then it
//!   captures B-controlled provenance (`recorded_timestamp_ms` = B's clock,
//!   `recorded_nonce` = staged copy, `recorded_chain_depth` = incoming + 1),
//!   stages the eight-field
//!   [`CrossContextOutletInvocationPrepared`] into `saga_pending`, and Class-S
//!   sync-persists fail-closed before replying.
//!
//! - **Commit** — split into [`commit_b_reserve`] → (supervisor-side execute) →
//!   [`commit_b_settle`] (B records `OutletInvoked`, signs the
//!   [`CrossContextOutletReceipt`], durably captures the output keyed by `SagaId`
//!   for replay) and [`commit_a`] (A re-acks from the durable
//!   `xctx_committed_invocations` witness, settles escrow, records
//!   `CrossContextOutletInvoked`), with [`commit_a_check_witness`] serving the
//!   §17.16.4 recovery witness query — all idempotent by `SagaId`.
//!
//! - **Abort** ([`abort`]) — releases the staged reservations (live carrier or
//!   the durable caller-reservation record on the crash-recovery `None` path).
//!
//! - **Divergence marker** ([`emit_divergence_marker`]) — on a one-sided
//!   `NeedsRepair`, each reachable side signs + appends its OWN
//!   [`CrossContextDivergenceMarker`] into its own log.
//!
//! # Error band
//!
//! Prepare-phase rejections surface as typed [`ContextError`]s carrying
//! `SCP-SAGA-13xxx` codes (the `13000-13999` saga band, ADR-049 §3a). The
//! caller-asserted timestamp / chain-depth are NEVER recorded — they feed only
//! the freshness check and the `+1` re-derivation base (spec §6.2.4).

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, TokenNbCaveatResolver, ValidationContext,
};

use scp_protocol::context::outlets::cross_context_saga::{
    CommittedSide, CrossContextDivergenceMarker, CrossContextDivergenceMarkerFields,
    CrossContextOutletReceipt, CrossContextOutletReceiptFields,
};

use crate::context::actor::commands::{
    CommitBReserveOutcome, CommitBReserveReply, CommitBSettleOutcome, CommitBSettleReply,
    PrepareAOutcome, PrepareBOutcome, PreparedAFields, PreparedBFields, SagaPhaseMessage,
    SagaReject, SigningKeyBytes, saga_reject,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::{Outcome, outcome_error_sketch};
use crate::context::actor::state::PerContextState;
use crate::context::economy_logic::{ContextRevocationChecker, KeyResolverDidResolver};
use crate::context::messaging_helpers::{
    build_snapshot_for_persist, persist_snapshot_fail_closed, persist_state_best_effort,
};
use crate::context::outlets_helpers::reserve_outlet_economy;
use crate::context::supervisor::saga_journal::SagaId;
use crate::context::supervisor::saga_prepared_state::{
    CommittedOutletInvocation, CrossContextOutletInvocationPrepared, SagaPreparedState,
};

/// Eviction TTL for B's per-target cross-context-saga nonce-dedup cache
/// ([`PerContextState::xctx_nonce_dedup`]).
///
/// Set to **strictly more than** the §9.14 clock-skew tolerance the Prepare-B
/// freshness check applies (`DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`) — here exactly
/// twice it. The two windows must NOT be coterminous: were the dedup TTL equal
/// to the skew tolerance, a `nonce` recorded at the trailing edge of its
/// freshness window could expire from the dedup cache while a replay carrying a
/// *refreshed* `asserted_timestamp_ms` is still inside the freshness window —
/// slipping past both gates (BLACK-XCTX-01). With the TTL strictly exceeding
/// the skew tolerance, any envelope that passes the freshness check has its
/// `nonce` still remembered by the dedup cache, closing the coterminous-window
/// gap for the in-window case. See the *Freshness / anti-replay* clause of
/// spec §6.2.4 for the forward obligation this leaves for an untrusted
/// cross-node transport.
pub(crate) const SAGA_NONCE_DEDUP_TTL_SECS: u64 = DEFAULT_CLOCK_SKEW_TOLERANCE_SECS * 2;

/// Runtime configuration ceiling for an interface's inbound §6.2.0.2 rate
/// (`InboundPolicy::max_calls_per_minute`) — the highest inbound rate B will
/// admit at Prepare-B before rejecting the interface as cache-eviction-unsafe
/// (spec §6.2.4 "Cache-eviction bound", normative "Sizing relative to the
/// configured ceiling").
///
/// Derived from the dedup cache capacity, the saga dedup TTL window
/// ([`SAGA_NONCE_DEDUP_TTL_SECS`] = 600s = 10 min), and the required ≥2× safety
/// margin: at this per-minute rate the worst-case distinct-nonce volume over
/// the TTL window stays at or below half the
/// [`NONCE_DEDUP_CAPACITY`](scp_protocol::crypto::sender_keys::NONCE_DEDUP_CAPACITY)
/// (10 000), so a sustained in-budget inbound stream THROUGH ONE INTERFACE can
/// never fill the cache and evict a still-within-TTL `nonce` — TTL expiry, not
/// capacity eviction, bounds the replay window for that interface.
/// `500/min × 10 min × 2 = 10 000 = capacity`. A higher ceiling would let one
/// interface's in-budget traffic erode the replay bound, so an interface
/// configuring an inbound rate above this is REJECTED at Prepare-B
/// (`consume_inbound_interface_rate_limit`, `SCP-SAGA-13027`). The
/// `nonce_dedup_replay_bound_holds` test asserts this PER-INTERFACE derivation
/// mechanically.
///
/// **Scope: per-interface, NOT aggregate (honest bound).** This ceiling is
/// enforced per interface, but `xctx_nonce_dedup` is a SINGLE per-context-B
/// cache shared across ALL inbound interfaces. With ≥3 distinct interfaces each
/// at this ceiling, their summed volume CAN exceed the cache capacity over the
/// TTL window and evict a still-fresh nonce — so this constant does NOT by
/// itself bound the AGGREGATE replay window. The aggregate bound rests on the
/// channel-authenticated `caller_did` gate (spec §6.2.4 *Cache-eviction bound* /
/// *Caller authentication*): a replay must pass the supervisor's gate-1
/// `is_member`/`caller_did` check on the attacker's OWN channel, so evicting a
/// victim's nonce yields no usable replay (a third party cannot present the
/// victim's `caller_did`; a caller replaying its own invocation re-spends its
/// own non-refundable budget). This per-interface ceiling is defense-in-depth
/// under that channel-auth argument, not a standalone aggregate guarantee.
pub(crate) const MAX_SAFE_INBOUND_CALLS_PER_MINUTE: u64 = 500;

/// Lowercase-hex encode a raw 32-byte context-id digest (the wire / role-state
/// id-form, never the `"standing-"`-prefixed display string — spec §6.2.4
/// id-form rule).
///
/// Delegates to [`hex::encode`] (the same lowercase encoding the supervisor side
/// of this path uses) so caller / target context ids render byte-identically
/// across both layers — a divergence here would split a saga's log lines.
fn hex_context_id(id: &[u8; 32]) -> String {
    hex::encode(id)
}

/// No-op [`NonceTracker`](scp_protocol::crypto::ucan::validate::NonceTracker)
/// for the cross-context UCAN re-bind path (`validate_ucan_rebind`).
///
/// The UCAN's OWN nonce is a long-lived delegation-proof concern and is
/// deliberately NOT tracked here: re-validating the SAME stored proof on a
/// later legitimate invocation must not falsely trip UCAN-nonce replay, and a
/// long-lived proof's nonce timestamp is legitimately stale (well outside the
/// §9.14 freshness window). The cross-context ENVELOPE replay is owned
/// separately by B's `xctx_nonce_dedup` (the `validate_freshness` check). Both
/// methods return `Ok(())` unconditionally — `validate_ucan` consults the
/// tracker exactly once (Step 9, single token nonce; the delegation-chain walk
/// never touches it), so this provides identical (zero) intra-call dedup to a
/// fresh per-call tracker. Mirrors the accepted production `NoopNonceTracker`
/// pattern in `broadcast.rs`.
struct NoopNonceTracker;
impl scp_protocol::crypto::ucan::validate::NonceTracker for NoopNonceTracker {
    fn check_replay(
        &self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }

    fn record(
        &mut self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }
}

/// Dispatch a [`SagaPhaseMessage`] against actor state.
pub(crate) async fn dispatch(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        // Prepare arms (slice 3b) route to a dedicated helper to keep this
        // router within the per-function line budget.
        prepare @ (SagaPhaseMessage::PrepareA { .. } | SagaPhaseMessage::PrepareB { .. }) => {
            dispatch_prepare_phase(cell, deps, prepare).await
        }
        // Commit (split) / Abort / divergence-marker arms (slice 4).
        other => dispatch_commit_phase(cell, deps, other).await,
    }
}

/// Dispatch the Prepare-A / Prepare-B saga phases (slice 3b). Split out of
/// [`dispatch`] so each router stays within the per-function line budget.
async fn dispatch_prepare_phase(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        SagaPhaseMessage::PrepareA {
            saga_id,
            caller_context_id,
            caller_did,
            outlet_registration_id,
            reply,
        } => {
            prepare_a(
                cell,
                deps,
                &saga_id,
                &caller_context_id,
                &caller_did,
                &outlet_registration_id,
                reply,
            )
            .await
        }
        SagaPhaseMessage::PrepareB {
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
        } => {
            let req = PrepareBRequest {
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
            };
            prepare_b(cell, deps, req, reply).await
        }
        // Commit-side phases are matched in `dispatch` and never routed here.
        // The `dispatch` router partitions Prepare vs Commit before calling
        // this helper, so these arms are statically unreachable; return a typed
        // error (NEVER panic — ADR-049 §10 handler panic ban) rather than
        // `unreachable!`, routing each phase's reply to its typed sender.
        SagaPhaseMessage::CommitBReserve { reply, .. } => misrouted(reply, "CommitBReserve"),
        SagaPhaseMessage::CommitBSettle { reply, .. } => misrouted(reply, "CommitBSettle"),
        SagaPhaseMessage::CommitACheckWitness { reply, .. } => {
            misrouted(reply, "CommitACheckWitness")
        }
        SagaPhaseMessage::CommitA { reply, .. } => misrouted(reply, "CommitA"),
        SagaPhaseMessage::Abort { reply, .. } => misrouted(reply, "Abort"),
        SagaPhaseMessage::EmitDivergenceMarker { reply, .. } => {
            misrouted(reply, "EmitDivergenceMarker")
        }
    }
}

/// Dispatch the Commit (split reserve/settle), Abort, and divergence-marker
/// saga phases (slice 4). Split out of [`dispatch`] to keep each router within
/// the per-function line budget.
async fn dispatch_commit_phase(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        SagaPhaseMessage::CommitBReserve { saga_id, reply } => {
            commit_b_reserve(cell, &saga_id, reply)
        }
        SagaPhaseMessage::CommitBSettle {
            saga_id,
            output_bytes,
            target_signing_key,
            reply,
        } => {
            commit_b_settle(
                cell,
                deps,
                &saga_id,
                output_bytes,
                &target_signing_key,
                reply,
            )
            .await
        }
        SagaPhaseMessage::CommitA {
            saga_id,
            reservation,
            caller_context_id,
            caller_did,
            target_context_id,
            nonce,
            receipt,
            output_bytes,
            reply,
        } => {
            let req = CommitARequest {
                saga_id,
                reservation: *reservation,
                caller_context_id,
                caller_did,
                target_context_id,
                nonce,
                receipt,
                output_bytes,
            };
            commit_a(cell, deps, req, reply).await
        }
        SagaPhaseMessage::CommitACheckWitness { saga_id, reply } => {
            commit_a_check_witness(cell, &saga_id, reply)
        }
        SagaPhaseMessage::Abort {
            saga_id,
            reservation,
            reply,
        } => abort(cell, deps, &saga_id, reservation.map(|b| *b), reply).await,
        SagaPhaseMessage::EmitDivergenceMarker {
            saga_id,
            nonce,
            committed_side,
            committed_event_id,
            committed_timestamp_secs,
            signing_key,
            reply,
        } => {
            // Build the owned snapshot HERE (holding `&mut ClassSCell`) and hand
            // it to the handler, so no `&PerContextState` is held across the
            // handler's persist `.await` (ADR-049 Decision 7 `Send` discipline).
            let ctx_id = cell.context_id;
            let context_hex = hex_context_id(&ctx_id);
            let snapshot = build_snapshot_for_persist(cell, deps, &context_hex);
            emit_divergence_marker(
                ctx_id,
                snapshot,
                deps,
                &saga_id,
                nonce,
                committed_side,
                &committed_event_id,
                committed_timestamp_secs,
                &signing_key,
                reply,
            )
            .await
        }
        // Prepare arms are matched in `dispatch` and never routed here. They
        // are statically unreachable; return a typed error per their reply
        // shape (NEVER panic — ADR-049 §10 handler panic ban).
        SagaPhaseMessage::PrepareA { reply, .. } => misrouted(reply, "PrepareA"),
        SagaPhaseMessage::PrepareB { reply, .. } => misrouted(reply, "PrepareB"),
    }
}

/// Typed error for a statically-unreachable mis-routed saga phase (the
/// `dispatch` router partitions Prepare vs Commit, so neither helper should
/// ever see the other's phases). Returning this — never `panic!`/`unreachable!`
/// — keeps the handler panic ban (ADR-049 §10) intact even on an impossible
/// branch.
fn misrouted_err(phase: &str) -> ContextError {
    ContextError::InvalidState(format!(
        "SCP-SAGA-13038: saga phase '{phase}' reached the wrong dispatch helper \
         (router partition invariant violated)"
    ))
}

/// Mis-route reply for ANY saga phase's typed `oneshot` sender. Every saga
/// phase reply is an `oneshot::Sender<Result<T, ContextError>>`; this single
/// generic collapses the per-phase reply helpers (which were byte-identical
/// except the reply payload type `T` and the phase label) into one. The
/// statically-unreachable mis-routed branch sends the typed error to its sender
/// and returns `Outcome::err` — NEVER `panic!`/`unreachable!` (ADR-049 §10
/// handler panic ban).
fn misrouted<T>(
    reply: tokio::sync::oneshot::Sender<Result<T, ContextError>>,
    phase: &str,
) -> Outcome<()> {
    let err = misrouted_err(phase);
    let sketch = outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

// ---------------------------------------------------------------------------
// Prepare-A — caller-context actor
// ---------------------------------------------------------------------------

/// Prepare-A handler (spec §6.2.4 "Prepare", caller side). Runs on the LOCAL
/// caller-context actor on owned state.
///
/// Validates that the caller holds `outlet:interface` and is in the interface's
/// `OutboundPolicy.allowed_callers`, then stages (does NOT apply) the outbound
/// rate-limit decrement + escrow reservation via the existing reserve
/// mechanism. The escrow amount is the outlet's REGISTERED per-invocation cost —
/// [`reserve_outlet_economy`] derives it from the caller context's economy policy
/// / outlet registry via `economy_pre_check`, NEVER from any caller-asserted
/// value (a caller must not declare its own cheaper cost; spec §6.2.4 / §19.3).
/// The resulting `Send` [`OutletEconomyReservation`] is a `#[must_use]` RAII
/// carrier the FSM holds — its drop releases the held escrow/rate-limit on every
/// terminal non-commit path. The staged saga state is Class-S sync-persisted
/// fail-closed BEFORE the reply, so a crash in the coalesce window cannot
/// acknowledge a Prepare-A whose reservation did not durably land.
async fn prepare_a(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    caller_context_id: &[u8; 32],
    caller_did: &DID,
    outlet_registration_id: &str,
    reply: tokio::sync::oneshot::Sender<Result<PrepareAOutcome, ContextError>>,
) -> Outcome<()> {
    let context_id_hex = hex_context_id(caller_context_id);

    // ── PREPARE-A-SEAM (read gate via Deref + step-2 Class-C consume via view) ─
    // The cell is held so the spending-nonce-bearing `reserve_outlet_economy` leaf
    // receives it (it routes its OWN Class-S consume through a combinator). The
    // read-only outbound-caller gate reads through the cell `Deref` (`&*cell`),
    // and the §6.2.0.2 outbound-rate window consume mutates ONLY
    // `governance.outlet_interfaces` (Class-C) through the non-persisting
    // `class_c_view()`. The consume carries NO own persist on the SUCCESS path
    // (it falls through to the `reserve_outlet_economy` / staging combinators,
    // which persist it). On the over-budget REJECT path the window may have
    // partially incremented, so an EXPLICIT `persist_state_best_effort(&*cell)`
    // (a shared `&PerContextState` Deref read) lands the partial increment
    // before replying `err_mutated`. This is an already-failing terminal path:
    // no success is acked and the only durable state is the soft Class-C
    // increment (no Class-S state), so best-effort — not fail-closed — is the
    // honest intent. The conditional persist is expressed explicitly here, NOT
    // folded into a combinator's fixed persist-on-`Ok` / persist-never shape.
    // Each borrow ends before the next.

    // 1. Caller must hold `outlet:interface` AND be in the interface's outbound
    //    allowed_callers (empty = any member). REUSES the role-state capability
    //    surface (`member_has_capability`) and the `OutboundPolicy.allowed_callers`
    //    enforcement shape `invoke_cross_context` uses for the single-context path.
    // `&*cell` deref-coerces &mut ClassSCell → &PerContextState (read-only gate).
    //
    // A §6.2.4 POLICY reject replies `Ok(PrepareAOutcome::Rejected(SagaReject))`
    // — carrying the structural `SCP-SAGA-13xxx` code on the SUCCESS channel —
    // yet still returns `Outcome::err` so the actor's own Class-S persistence
    // accounting records the reject. The two are intentionally ORTHOGONAL: the
    // reply payload is the saga FSM's typed terminal; `Outcome::err` drives the
    // actor-local accounting and is unrelated to how the FSM lifts the reject.
    if let Err(rej) = validate_outbound_caller(&*cell, caller_did, outlet_registration_id) {
        let sketch = outcome_error_sketch(&rej.error);
        let _ = reply.send(Ok(PrepareAOutcome::Rejected(rej)));
        return Outcome::err(sketch);
    }

    // 2. Consume the §6.2.0.2 per-interface + per-caller sliding-window budget
    //    on the OUTBOUND interface (spec §6.2.4 "Prepare", "Initiation consumes
    //    budget; no terminal outcome refunds it"). This is the binding
    //    constraint behind the §6.2.4 "Cache-eviction bound": a single caller's
    //    TTL-window budget sized far below the dedup-cache capacity is what
    //    forecloses a flood from evicting a still-within-TTL nonce. The consume
    //    is non-refundable at initiation — once the sliding window is
    //    incremented it is NEVER decremented back on any terminal outcome
    //    (Aborted / timeout / NeedsRepair), so a caller that stalls or diverges
    //    sagas burns its own quota. REUSES the same `RateLimit` /
    //    `PerCallerRateLimit::check_and_increment` sliding-window mechanism the
    //    single-context `invoke_cross_context` path consumes (spec §6.2.0.2).
    if let Err(rej) = consume_outbound_interface_rate_limit(
        cell.class_c_view(),
        deps,
        caller_did,
        outlet_registration_id,
    ) {
        // The §6.2.0.2 consume is non-refundable: if it incremented the window
        // and THEN this branch is reached, the increment stays. (In practice a
        // rejection here means the window was NOT incremented — `RateLimited`
        // is the over-budget case where the call is denied.) Persist so any
        // partial increment durably lands, then reply. This is an
        // already-failing terminal reject: no success is acked and the only
        // durable state is the soft Class-C anti-spam window increment (no
        // Class-S state), so best-effort — not fail-closed — is the honest
        // intent; a persist failure here just records the metric.
        // `persist_state_best_effort` reads a shared `&PerContextState` via the
        // cell `Deref` (`&*cell`) — no `state_mut()`.
        //
        // POLICY reject ⇒ `Ok(PrepareAOutcome::Rejected(SagaReject))` on the
        // SUCCESS channel (structural code), but `Outcome::err_mutated` for the
        // actor's Class-S accounting — the reply payload and the Outcome are
        // intentionally orthogonal (see the validate_outbound_caller reject).
        persist_state_best_effort(&*cell, deps, &context_id_hex).await;
        let sketch = outcome_error_sketch(&rej.error);
        let _ = reply.send(Ok(PrepareAOutcome::Rejected(rej)));
        return Outcome::err_mutated(sketch);
    }

    // 3. Stage (not apply) the escrow reservation + the actor-owned
    //    velocity/budget/hard-rate-limit bookkeeping via the existing reserve
    //    mechanism. The reservation holds the escrow; apply happens at Commit-A
    //    settle. The escrow amount is the outlet's REGISTERED per-invocation cost
    //    (derived by `reserve_outlet_economy` from the economy policy / outlet
    //    registry via `economy_pre_check`), NEVER a caller-asserted value — a
    //    caller must not declare its own cheaper cost. No spending UCAN is
    //    presented on the OUTBOUND leg — the inbound `require_spending_ucan`
    //    gate and §7 proof live on B's Prepare-B side.
    let now_secs = deps.clock.now_secs();
    // `reserve_outlet_economy` is the spending-nonce-bearing leaf and takes the
    // cell; the prior `state` borrow has ended (NLL) so `cell` is free here.
    // §7.3.8 value-caveat enforcement is scoped to single-shot SAME-context
    // invocation. The cross-context saga Prepare-A leg is a later slice, so no
    // caveat binding is threaded here and the input is not schema-checked
    // against a caveat (`Null`); the counter gate stays inert.
    let reservation = match reserve_outlet_economy(
        cell,
        deps,
        &context_id_hex,
        caller_did,
        None,
        None,
        &serde_json::Value::Null,
        now_secs,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(err) => {
            // reserve_outlet_economy rolls back its OWN staged bookkeeping on
            // every failure branch, so no escrow/velocity/budget leaked — and
            // its Class-S state is rolled back too, leaving nothing security-
            // critical to durably land here. The §6.2.0.2 budget consumed above
            // is NOT rolled back (non-refundable at initiation); persist so it
            // durably lands, then reply. This is an already-failing terminal
            // error: no success is acked and the only durable state is the soft
            // Class-C anti-spam window increment, so best-effort — not fail-
            // closed — is the honest intent; a persist failure just records the
            // metric. `persist_state_best_effort` takes a SHARED
            // `&PerContextState`, so this reads through the cell's `Deref`
            // (`&*cell`) — no `state_mut()`.
            persist_state_best_effort(&*cell, deps, &context_id_hex).await;
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err_mutated(sketch);
        }
    };

    // 4. Stage the DURABLE caller-reservation reversal record (spec §6.2.4
    //    "Reservation release on every terminal path"), keyed by `SagaId`,
    //    BEFORE the fail-closed persist so the deduction and the means to
    //    reverse it land atomically in the SAME Class-S snapshot. The live
    //    `OutletEconomyReservation` RAII carrier (held by the FSM) is the
    //    AUTHORITATIVE reversal on the live abort / Commit-A paths and dies with
    //    an actor/process crash; this record is the crash-only fallback the
    //    §17.16.4 recovery sweep's `Abort { reservation: None }` uses to reverse
    //    the caller deduction + void the escrow WITHOUT the carrier. Inserting
    //    it does not double-charge: the live paths CONSUME (remove without
    //    re-reversing) the record, and the record's own reversal runs only when
    //    the carrier is absent — the two paths are mutually exclusive.
    //
    //    `to_caller_reservation_record(&self)` only BORROWS the ticket, so
    //    `reservation` stays owned in this scope across the combinator — it is
    //    returned to the supervisor on success or rolled back below on failure.
    let record = reservation.ticket.to_caller_reservation_record(now_secs);

    // 5. Class-S sync-persist fail-closed BEFORE replying (ADR-049 §9): the
    //    reserve mutated actor-owned velocity / rate-limit / budget bookkeeping
    //    and the durable reversal record above; a crash in the coalesce window
    //    must not acknowledge a Prepare-A whose staged reservation did not
    //    durably land. `commit_class_s_restore` stages the record in `f` and, on
    //    persist failure, RESTORES Class-S — un-inserting the just-staged record
    //    (matching the prior manual `xctx_caller_reservations.remove`: the record
    //    described a reservation that is now reversed in-memory and was never
    //    durably persisted, so leaving it would let a later crash-abort
    //    double-reverse).
    //
    //    The economy rollback that completes the §6.2.4 "Reservation release on
    //    every terminal path" RAII contract (the `OutletEconomyTicket` MUST be
    //    settled or rolled back, never merely dropped — releasing the staged
    //    escrow/rate-limit/velocity/budget) is Class-C + EXTERNAL (escrow void)
    //    and runs AFTER the combinator on the Err arm, exactly as before. It is
    //    kept outside the combinator — not folded into a `compensate` closure —
    //    because the `#[must_use]` `reservation.ticket` it consumes must survive
    //    onto the SUCCESS path too (it is replied to the supervisor); a
    //    `commit_class_s_compensating` splits the success value `T` from the
    //    compensation handle `X` and drops `X` on success, which would drop the
    //    carrier and trip its unbalanced-drop guard. See FLAG-PREPARE-A below.
    if let Err(persist_err) = cell
        .commit_class_s_restore(deps, &context_id_hex, |mut view| {
            view.class_s_mut()
                .xctx_caller_reservations
                .insert(saga_id.clone(), record);
            Ok(())
        })
        .await
    {
        // Combinator already un-inserted the record (Class-S restore). Complete
        // the RAII release: reverse the Class-C economy + void the external
        // escrow from the still-owned reservation, exactly as the prior inline
        // path did. `rollback_outlet_economy` reverses ONLY Class-C governance
        // economy (`velocity_tracker` / `budget_tracker` / `hard_rate_limit`) +
        // an external escrow void, so it takes the field-granular `ClassCMut`
        // (non-persisting — the combinator above already persisted the Class-S
        // restore; this reversal rides the run-loop coalesce, matching the prior
        // inline no-extra-persist behaviour).
        crate::context::outlets_helpers::rollback_outlet_economy(
            cell.class_c_view(),
            deps,
            reservation.ticket,
        )
        .await;
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    // Reply with the staged reservation. The `PreparedAFields` carries the
    // `#[must_use]` `OutletEconomyTicket`, whose `Drop` guard fires (a
    // `debug_assert!` panic under `--features testing`, an escrow leak in
    // release) if the value is dropped without being settled or rolled back. If
    // the supervisor's reply receiver is GONE — the §6.2.4 `dispatch_prepare_phase`
    // 30s phase-timeout fired (or the start was cancelled) and dropped the
    // oneshot receiver AFTER this handler already durably persisted the
    // deduction + the `xctx_caller_reservations` record — `reply.send` returns
    // `Err(returned_prepared)` and would otherwise drop the carrier INSIDE this
    // actor, tripping the unbalanced-drop guard. Recover the ticket and BALANCE
    // it via `void_external_and_consume` (consumes the `#[must_use]` ticket +
    // voids any external escrow idempotently) — but DELIBERATELY leave the
    // durable deduction + record in place. The saga can only ABORT after a lost
    // Prepare-A reply (a `Commit-A` is impossible — the supervisor never received
    // the carrier it needs), and that abort reverses the LOCAL economy from the
    // durable record (supervisor `prepared_a == None` → record-based
    // `Abort { None }`), which idempotently re-voids the same escrow. Reversing
    // the local deduction HERE too would double-reverse — so we void escrow +
    // balance the ticket only, and let the abort's record path own the single
    // local reversal.
    // `reply.send(Ok(prepared))` returns `Err(Ok(prepared))` if the receiver is
    // gone (the sent value — an `Ok(PrepareAOutcome::Prepared)` — handed back).
    // The inner `Ok(Prepared(..))` destructure recovers the carrier; it always
    // matches because we sent an `Ok(Prepared(..))`.
    if let Err(returned_prepared) = reply.send(Ok(PrepareAOutcome::Prepared(PreparedAFields {
        reservation,
    }))) && let Ok(PrepareAOutcome::Prepared(PreparedAFields { reservation })) =
        returned_prepared
    {
        tracing::warn!(
            saga_id = %saga_id.0,
            context = %context_id_hex,
            "cross-context saga Prepare-A — the supervisor's reply receiver was gone \
             (phase-timeout / cancel) after the deduction + durable reservation record \
             were persisted; balancing the held reservation ticket (void external escrow \
             + consume) and leaving the durable record so the supervisor's abort reverses \
             the LOCAL economy from it (no double-reverse)"
        );
        reservation
            .ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;
    }
    Outcome::ok_mutated(())
}

/// Validate the Prepare-A outbound caller gate: the caller holds
/// `outlet:interface` and is in the established interface's
/// `OutboundPolicy.allowed_callers` (empty = any holder). Returns a typed
/// `SCP-SAGA-13xxx` rejection otherwise.
fn validate_outbound_caller(
    state: &PerContextState,
    caller_did: &DID,
    outlet_registration_id: &str,
) -> Result<(), SagaReject> {
    use scp_protocol::context::roles::Capability;

    // `outlet:interface` capability (the caller is authorized to USE interfaces).
    if !state
        .role_state
        .member_has_capability(caller_did.as_ref(), &Capability::OutletInterface)
    {
        return Err(saga_reject!(
            13010,
            PermissionDenied,
            "caller '{}' lacks outlet:interface capability for cross-context invocation",
            caller_did
        ));
    }

    // Outbound policy: the interface whose source outlet is this registration.
    // `allowed_callers` empty ⇒ any member with the capability above.
    if let Some(interface) = state
        .governance
        .outlet_interfaces
        .iter()
        .find(|i| i.outlet_id == outlet_registration_id)
        && let Some(outbound) = interface.outbound_policy.as_ref()
        && !outbound.allowed_callers.is_empty()
        && !outbound.allowed_callers.contains(caller_did)
    {
        return Err(saga_reject!(
            13011,
            PermissionDenied,
            "caller '{}' not in outbound allowed_callers for outlet '{}'",
            caller_did,
            outlet_registration_id
        ));
    }

    Ok(())
}

/// Consume one §6.2.0.2 sliding-window budget unit on the OUTBOUND interface for
/// `outlet_registration_id` — both the per-interface (`rate_limit`) AND the
/// per-caller (`per_caller_rate_limit`) windows, exactly as the single-context
/// [`invoke_cross_context`](scp_protocol::context::outlets::interface::invoke_cross_context)
/// path consumes them. Returns [`ContextError::RateLimited`] (the over-budget
/// case) without incrementing the OTHER window when either is exhausted.
///
/// The consume is the §6.2.4 "Initiation consumes budget" point: each
/// initiation increments the caller's sliding window, and NO terminal outcome
/// decrements it back (the increment is non-refundable). This is the binding
/// constraint behind the §6.2.4 "Cache-eviction bound" — a per-caller budget
/// sized far below the dedup-cache capacity forecloses a flood from evicting a
/// still-within-TTL nonce.
///
/// An interface with no configured limit (`None`) is unbounded by design and
/// consumes nothing; the per-interface limit is checked first, then the
/// per-caller limit, so an exhausted per-interface window short-circuits before
/// the per-caller window is touched (matching `invoke_cross_context` order).
fn consume_outbound_interface_rate_limit(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    caller_did: &DID,
    outlet_registration_id: &str,
) -> Result<(), SagaReject> {
    let clock = deps.clock.as_ref();

    // The §6.2.0.2 outbound window lives on `governance.outlet_interfaces` — a
    // Class-C field reached through the field-granular governance view.
    let Some(interface) = view
        .governance_class_c_mut()
        .outlet_interfaces_mut()
        .iter_mut()
        .find(|i| i.outlet_id == outlet_registration_id)
    else {
        // No interface row for this outlet. The target-axis authorize-before-
        // reserve gate already proved an established interface exists for the
        // (caller, target, outlet) triple before the saga reserved, so a missing
        // row here is not the unauthorized-target case; there is simply no
        // configured §6.2.0.2 window to consume (unbounded by design).
        return Ok(());
    };

    // Per-interface sliding window first (spec §6.2.0.2, `invoke_cross_context`
    // order): a single per-interface check_and_increment is the consume.
    if let Some(rate_limit) = interface.rate_limit.as_mut()
        && !rate_limit.check_and_increment(clock)
    {
        let retry_after_secs = rate_limit.retry_after_secs(clock);
        return Err(saga_reject!(
            13023,
            RateLimited {
                resource: "outlet_interface".to_owned(),
                retry_after_ms: Some(retry_after_secs.saturating_mul(1000))
            },
            "per-interface §6.2.0.2 rate limit exceeded for outlet '{}' (retry after {}s)",
            outlet_registration_id,
            retry_after_secs
        ));
    }

    // Per-caller sliding window, independent of the per-interface window.
    if let Some(per_caller) = interface.per_caller_rate_limit.as_mut()
        && !per_caller.check_and_increment(caller_did, clock)
    {
        let retry_after_secs = per_caller.retry_after_secs_for(caller_did, clock);
        return Err(saga_reject!(
            13024,
            RateLimited {
                resource: "outlet_interface_caller".to_owned(),
                retry_after_ms: Some(retry_after_secs.saturating_mul(1000))
            },
            "per-caller §6.2.0.2 rate limit exceeded for caller '{}' on outlet '{}' (retry after {}s)",
            caller_did,
            outlet_registration_id,
            retry_after_secs
        ));
    }

    Ok(())
}

/// Consume one §6.2.0.2 sliding-window unit on B's INBOUND interface window at
/// Prepare-B (spec §6.2.4 "Prepare-B validates `InboundPolicy` (… inbound rate
/// …)"; §6.2.0 effective `min(outbound, inbound)`). The OUTBOUND window is
/// consumed by the caller (A) at Prepare-A; this is the symmetric TARGET-side
/// (B-owned) window, so both ends enforce their respective per-interface limit
/// and the effective rate is their `min`.
///
/// The window is materialized LAZILY from
/// [`InboundPolicy::max_calls_per_minute`](scp_protocol::context::outlets::interface::InboundPolicy)
/// into `OutletInterface::inbound_rate_limit` the first time B prepares an
/// invocation over the interface, then carried with the interface so the
/// window state persists. An interface with no inbound policy (unbounded by
/// design) consumes nothing.
///
/// The consume is NON-REFUNDABLE — consistent with the §6.2.4
/// "initiation-consumes" discipline: an exhausted window rejects with a typed
/// `SCP-SAGA-13026` and NO terminal outcome decrements it back.
///
/// **Config-time eviction guard (spec §6.2.4 "Cache-eviction bound", normative
/// "Sizing relative to the configured ceiling").** Before materializing the
/// window, the configured inbound rate is checked against
/// [`MAX_SAFE_INBOUND_CALLS_PER_MINUTE`]: an interface whose configured inbound
/// rate over the dedup-TTL window would approach `NONCE_DEDUP_CAPACITY` (the
/// ≥2× margin) is REJECTED (`SCP-SAGA-13027`) — a high inbound ceiling must not
/// erode the replay bound the §6.2.4 dedup cache provides. This makes the
/// eviction bound a mechanical function of the configured ceiling at runtime,
/// not merely a `cfg(test)` invariant.
fn consume_inbound_interface_rate_limit(
    mut view: crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    outlet_registration_id: &str,
) -> Result<(), SagaReject> {
    use scp_protocol::context::outlets::interface::{DEFAULT_WINDOW_SECONDS, RateLimit};

    let clock = deps.clock.as_ref();

    // The §6.2.0.2 inbound window lives on `governance.outlet_interfaces` — a
    // Class-C field reached through the field-granular governance view.
    let Some(interface) = view
        .governance_class_c_mut()
        .outlet_interfaces_mut()
        .iter_mut()
        .find(|i| i.outlet_id == outlet_registration_id)
    else {
        // No interface row ⇒ no configured inbound window to consume (the
        // authorize-before-reserve gate already proved an established interface
        // exists; a missing row here is the unbounded-by-design case).
        return Ok(());
    };

    // No inbound policy ⇒ unbounded inbound by design; consume nothing.
    let Some(inbound) = interface.inbound_policy.as_ref() else {
        return Ok(());
    };
    let max_per_min = u64::from(inbound.max_calls_per_minute);

    // Config-time eviction guard (spec §6.2.4 "Sizing relative to the configured
    // ceiling"): an inbound ceiling whose TTL-window volume approaches the dedup
    // capacity (below the ≥2× margin) would let in-budget traffic evict a
    // still-within-TTL nonce. Reject such an interface rather than admit it.
    if max_per_min > MAX_SAFE_INBOUND_CALLS_PER_MINUTE {
        return Err(saga_reject!(
            13027,
            PermissionDenied,
            "interface inbound rate {}/min for outlet '{}' exceeds the cache-eviction-safe ceiling \
             ({}/min): its dedup-TTL-window volume would approach the nonce-dedup capacity and \
             erode the §6.2.4 replay bound",
            max_per_min,
            outlet_registration_id,
            MAX_SAFE_INBOUND_CALLS_PER_MINUTE
        ));
    }

    // Materialize the inbound window lazily from the inbound policy (same
    // RateLimit mechanism + default 60s window the outbound side uses).
    let window = interface.inbound_rate_limit.get_or_insert_with(|| {
        RateLimit::new(
            max_per_min,
            std::time::Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            clock,
        )
    });

    if !window.check_and_increment(clock) {
        let retry_after_secs = window.retry_after_secs(clock);
        return Err(saga_reject!(
            13026,
            RateLimited {
                resource: "outlet_interface_inbound".to_owned(),
                retry_after_ms: Some(retry_after_secs.saturating_mul(1000))
            },
            "per-interface §6.2.0.2 INBOUND rate limit exceeded at Prepare-B for outlet '{}' \
             (retry after {}s)",
            outlet_registration_id,
            retry_after_secs
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Prepare-B — target-context actor
// ---------------------------------------------------------------------------

/// Owned inputs for [`prepare_b`], grouped to keep the handler signature within
/// the clippy argument budget. Mirrors the
/// [`SagaPhaseMessage::PrepareB`](crate::context::actor::commands::SagaPhaseMessage::PrepareB)
/// payload (minus the reply channel).
struct PrepareBRequest {
    saga_id: crate::context::supervisor::saga_journal::SagaId,
    caller_context_id: [u8; 32],
    target_context_id: [u8; 32],
    caller_did: DID,
    outlet_registration_id: String,
    ucan_proof_id: Option<String>,
    input: serde_json::Value,
    asserted_chain_depth: u8,
    asserted_nonce: [u8; 16],
    asserted_timestamp_ms: u64,
    /// Channel-authenticated caller role in the caller context (NOT
    /// envelope-asserted); enforced against `InboundPolicy.allowed_source_roles`.
    caller_source_role: Option<String>,
}

/// Prepare-B handler (spec §6.2.4 "Prepare", target side). Runs on the LOCAL
/// target-context actor on owned state.
///
/// Validation order (spec §6.2.4): (1) §7 UCAN re-bind / confused-deputy,
/// (2) inbound policy, (3) input schema-specificity floor, (4) target-context
/// binding, (5) freshness, (6) chain-depth. Then it captures B-controlled
/// provenance, stages the eight-field prepared into `saga_pending`, and
/// Class-S sync-persists fail-closed before replying. Any check failure ⇒ typed
/// rejection with no staging.
async fn prepare_b(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    req: PrepareBRequest,
    reply: tokio::sync::oneshot::Sender<Result<PrepareBOutcome, ContextError>>,
) -> Outcome<()> {
    // ── PREPARE-B-CHECKS (read-only gate through `&*cell`) ───────────────────
    // The validation gate (checks 1–6) is now fully READ-ONLY: check 5
    // (freshness / anti-replay) takes its decision via `NonceDedup::is_replayed_read`
    // (`&self`), so no Class-S `&mut` mutation happens here. The mutating TTL
    // eviction `is_replayed` used to fold into the read has been hoisted into
    // the staging combinator's KEEP closure below (it already mutates
    // `xctx_nonce_dedup` via `record`), so the eviction rides the SAME single
    // fail-closed persist as the accepted-nonce record — preserving the prior
    // "evict-then-decide-then-record under one persist" net effect with NO
    // un-persisted Class-S mutation. The read gate therefore runs through the
    // cell's shared-read `Deref` (`&*cell`), not `state_mut()`. The step-7
    // inbound-rate consume (the ONLY Class-C mutation) is HOISTED OUT to run
    // through `class_c_view()` below.
    // A §6.2.4 POLICY reject replies `Ok(PrepareBOutcome::Rejected(SagaReject))`
    // (structural `SCP-SAGA-13xxx` code on the SUCCESS channel) yet returns
    // `Outcome::err` for the actor's Class-S accounting — the reply payload and
    // the Outcome are intentionally orthogonal.
    if let Err(rej) = run_prepare_b_checks(&*cell, deps, &req) {
        let sketch = outcome_error_sketch(&rej.error);
        let _ = reply.send(Ok(PrepareBOutcome::Rejected(rej)));
        return Outcome::err(sketch);
    }

    // (7) Inbound RATE (the ONLY Class-C mutation in the Prepare-B gate): consume
    //     B's INBOUND §6.2.0.2 sliding window (spec §6.2.4 "Prepare-B validates
    //     InboundPolicy (… inbound rate …)"; §6.2.0 effective min(outbound,
    //     inbound)) through the non-persisting `class_c_view()` — it mutates ONLY
    //     `governance.outlet_interfaces`. It carries NO own persist: on success its
    //     window increment is persisted by the SUBSEQUENT staging combinator (one
    //     persist covers window + nonce + slot). It runs AFTER the read-only
    //     rejects (a rejected call never consumes the budget) but BEFORE the
    //     staging combinator, so a clean reject here surfaces as `Outcome::err`
    //     (no slot staged), DISTINCT from a later persist failure's
    //     `Outcome::err_mutated`. The over-CEILING reject (13027) returns BEFORE
    //     window materialization, so it makes no mutation at all. The over-BUDGET
    //     reject (13026) DOES touch Class-C — it lazily materializes the inbound
    //     window and `check_and_increment` may roll its counter — but only
    //     idempotent, wall-clock-re-derivable state (deterministically rebuilt from
    //     the inbound policy + clock on the next call), never a durable increment of
    //     admitted volume. So an un-persisted `Outcome::err` is correct: the ≤50ms
    //     coalesce-window rollback re-derives the identical window on the retry.
    if let Err(rej) =
        consume_inbound_interface_rate_limit(cell.class_c_view(), deps, &req.outlet_registration_id)
    {
        // POLICY reject ⇒ `Ok(Rejected)` (structural code) on the SUCCESS
        // channel; `Outcome::err` for the actor's Class-S accounting (orthogonal).
        let sketch = outcome_error_sketch(&rej.error);
        let _ = reply.send(Ok(PrepareBOutcome::Rejected(rej)));
        return Outcome::err(sketch);
    }

    // All checks passed. Capture B-controlled, replay-deterministic provenance:
    //   recorded_timestamp_ms = B's OWN clock NOW (never the caller's send time)
    //   recorded_nonce        = B's staged COPY of the wire nonce
    //   recorded_chain_depth  = incoming + 1 (B re-derives; never the asserted)
    let recorded_timestamp_ms = deps.clock.now_millis();
    let recorded_nonce = req.asserted_nonce;
    let recorded_chain_depth = req.asserted_chain_depth.saturating_add(1);
    let now_secs = deps.clock.now_secs();

    // Stage the eight-field public-metadata projection into saga_pending.
    let prepared = CrossContextOutletInvocationPrepared {
        caller_context_id: req.caller_context_id,
        target_context_id: req.target_context_id,
        caller_did: req.caller_did.clone(),
        outlet_registration_id: req.outlet_registration_id.clone(),
        // The journal projection carries a string proof id; an ungated outlet
        // has no proof — the empty string is the "no proof" sentinel for the
        // public projection (the wire field is `<string|null>`).
        ucan_proof_id: req.ucan_proof_id.clone().unwrap_or_default(),
        recorded_timestamp_ms,
        recorded_nonce,
        recorded_chain_depth,
    };

    // ── PREPARE-B (keep+restore SPLIT) ───────────────────────────────────────
    // Prepare-B stages TWO Class-S fields under ONE fail-closed persist with
    // OPPOSITE rollback directions:
    //   (a) `xctx_nonce_dedup.record` — KEEP on persist failure. Un-recording an
    //       accepted nonce re-opens the §6.2.4 replay window the dedup cache
    //       exists to close (the fail-closed direction).
    //   (b) `saga_pending.insert` — RESTORE on persist failure. A staged slot
    //       that did not durably land must be removed so a retry re-stages
    //       cleanly and no orphaned reservation linkage survives.
    // No all-or-nothing combinator expresses keep-one-field / restore-another:
    // the `*_restore` snapshot/restore is all-or-nothing over the Class-S
    // sub-structs, and `*_keep_compensating`'s `on_persist_failure` hook is
    // handed a `ClassCMut` that STRUCTURALLY cannot reach `saga_pending`
    // (Class-S) to remove it. `commit_class_s_keep_restore_split` is the
    // field-granular combinator for exactly this shape: it snapshots ONLY the
    // restore-targeted field (`saga_pending`) BEFORE `f`, runs `f` (recording the
    // nonce — KEEP — and staging the slot — RESTORE) under ONE fail-closed
    // persist, and on persist FAILURE runs `restore_on_failure` (which rolls the
    // slot back while LEAVING the recorded nonce). A check REJECT inside `f`
    // returns immediately and runs NEITHER the persist NOR `restore_on_failure`
    // (clean `Outcome::err`), distinct from a persist failure (slot staged then
    // rolled back, `Outcome::err_mutated`) — preserving EXACT prior behaviour:
    // one persist, nonce kept, slot rolled back only on persist failure.
    let target_hex = hex_context_id(&req.target_context_id);
    let saga_id = req.saga_id.clone();
    if let Err(persist_err) = cell
        .commit_class_s_keep_restore_split(
            deps,
            &target_hex,
            // Snapshot ONLY the restore-targeted field (`saga_pending`) — the
            // pre-`f` key set, so the failure restore removes exactly the slot `f`
            // stages and nothing else (the kept nonce is NOT snapshotted).
            |class_s| class_s.saga_pending.keys().cloned().collect::<Vec<_>>(),
            |mut view| {
                let class_s = view.class_s_mut();
                // (a) Record the accepted nonce in B's dedup cache (freshness state
                //     lives on B) — KEEP direction. First evict TTL-expired entries
                //     (the mutating side-effect hoisted out of the now-read-only
                //     freshness check) so the net effect matches the prior
                //     "evict-then-decide-then-record under one fail-closed persist".
                //     Both eviction and record are KEEP-direction Class-S maintenance
                //     of `xctx_nonce_dedup` covered by this combinator's single
                //     persist.
                class_s.xctx_nonce_dedup.evict_expired(now_secs);
                class_s
                    .xctx_nonce_dedup
                    .record(req.asserted_nonce, now_secs);
                // (b) Stage the prepared projection — RESTORE direction.
                class_s.saga_pending.insert(
                    saga_id.clone(),
                    SagaPreparedState::CrossContextOutletInvocation(prepared),
                );
                Ok(())
            },
            // RESTORE on persist failure: drop any `saga_pending` key not present
            // before `f` (i.e. the just-staged slot), so a retry re-stages cleanly.
            // The recorded nonce is NOT restored here (KEEP direction — fail-closed).
            |class_s, keys_before| {
                class_s.saga_pending.retain(|k, _| keys_before.contains(k));
            },
        )
        .await
    {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        // The persist just FAILED, so the recorded nonce did NOT durably land;
        // report mutated so the actor flags the in-memory mutation as
        // diverged-from-durable (it does not claim the state persisted).
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(PrepareBOutcome::Prepared(PreparedBFields {
        recorded_timestamp_ms,
        recorded_nonce,
        recorded_chain_depth,
    })));
    Outcome::ok_mutated(())
}

/// Run the Prepare-B checks in spec order. Returns `Ok(())` if every check
/// passes; a typed `SCP-SAGA-13xxx` rejection otherwise.
///
/// All six checks this function runs are read-only; the only state-MUTATING gate
/// — the inbound-rate consume (step 7) — is performed by the `prepare_b` CALLER
/// AFTER this function returns `Ok(())`, because it needs the `ClassCMut` view the
/// cell-holding caller owns. The consume is therefore ordered LAST, AFTER the
/// freshness (5) and chain-depth (6) read-only rejects, deliberately: a call that
/// any read-only check rejects never reaches — and so never consumes (or durably
/// persists) — B's INBOUND §6.2.0.2 sliding window. By the "initiation-consumes"
/// discipline, an arrival that DOES reach the inbound-rate gate is counted as
/// inbound load and stays consumed even if some later step aborts.
fn run_prepare_b_checks(
    state: &PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), SagaReject> {
    // (1) Confused-deputy: resolve the UCAN proof from B's OWN store and re-run
    //     full §7 validation RE-BOUND to caller_did + outlet_registration_id.
    validate_ucan_rebind(state, deps, req)?;

    // (2) Inbound policy: source role + require_spending_ucan (the gated-proof
    //     requirement is satisfied by (1) above when a proof is present). The
    //     third InboundPolicy axis — inbound RATE — is consumed LAST (step 7),
    //     because it is the only state-MUTATING gate: all the read-only
    //     rejections below must fire first so a rejected call never consumes
    //     (and durably persists) the inbound window.
    validate_inbound_policy(state, req)?;

    // (3) Input schema specificity floor (§9.2.1): degenerate broad-schema
    //     input is rejected at Prepare-B.
    validate_input_specificity(state, req)?;

    // (4) Target-context binding: the asserted target_context_id MUST equal B's
    //     own context (spec §6.2.4 "Target-context binding").
    if req.target_context_id != state.context_id {
        return Err(saga_reject!(
            13014,
            PermissionDenied,
            "target_context_id mismatch — invocation targets a different context than this \
             executing actor (outlet '{}')",
            req.outlet_registration_id
        ));
    }

    // (5) Freshness / anti-replay: reject if the asserted send-time is outside
    //     §9.14 skew OR the nonce is already in B's TTL dedup cache.
    validate_freshness(state, deps, req)?;

    // (6) Chain-depth: reject if asserted_chain_depth + 1 would exceed the
    //     context-configured max (spec §6.2.4 "Chain-depth enforcement").
    validate_chain_depth(state, req)?;

    // (7) Inbound RATE — the ONLY Class-C-mutating check — is consumed by the
    //     `prepare_b` CALLER after these checks (it needs the `ClassCMut` view,
    //     and the caller owns the cell). Placed AFTER every read-only reject
    //     above so a rejected call never consumes the inbound window. The
    //     §6.2.0 effective `min(outbound, inbound)` rate and the cache-eviction
    //     config guard are enforced there.
    Ok(())
}

/// (1) Confused-deputy defense (spec §6.2.4 normative (1)). Resolves
/// `ucan_proof_id` from B's OWN UCAN store and re-runs the full §7 validation
/// RE-BOUND to the carried `caller_did` (audience) + `outlet_registration_id`
/// (capability). REUSES the single-context
/// [`validate_ucan`](scp_protocol::crypto::ucan::validate::validate_ucan)
/// pipeline through the same DID/revocation adapters the spending-UCAN path
/// uses, so a stronger proof delegated to a DIFFERENT principal is rejected
/// (audience mismatch) exactly as the single-context path would reject it.
///
/// An ungated outlet carries `ucan_proof_id = None` and presents no proof — there
/// is nothing to confuse, so the check is a no-op for that case.
fn validate_ucan_rebind(
    state: &PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), SagaReject> {
    use scp_protocol::crypto::ucan::capability::CapabilityUri;
    use scp_protocol::crypto::ucan::validate::{ProofResolver, validate_ucan};

    let Some(proof_id) = req.ucan_proof_id.as_deref() else {
        return Ok(()); // ungated outlet — no proof to re-bind
    };

    // Resolve the proof from B's OWN store (the index, NOT proof bytes).
    let token: UcanToken = state
        .xctx_ucan_proofs
        .resolve_proof(proof_id)
        .map_err(|e| {
            saga_reject!(
                13012,
                PermissionDenied,
                "ucan_proof_id '{}' not resolvable in target UCAN store: {}",
                proof_id,
                e
            )
        })?;

    // Required capability bound to B's OWN context + THIS outlet + outlet_call.
    let target_hex = hex_context_id(&req.target_context_id);
    let required_cap = CapabilityUri::new(
        target_hex,
        "outlet_call",
        req.outlet_registration_id.clone(),
    );

    // The ceiling URI set + B's context-creator are taken from B's role state.
    let ceiling = state.role_state.ceiling().to_ucan_string_set();
    let creator_did = state.role_state.creator_did.clone();
    let revoked = state.governance.revoked_spending_ucan_cids.clone();

    let did_resolver = KeyResolverDidResolver::new(&deps.key_resolver);
    let revocation_checker = ContextRevocationChecker {
        revoked_cids: &revoked,
    };
    // The cross-context ENVELOPE replay is owned by B's `xctx_nonce_dedup`
    // (the freshness check above in `validate_freshness`); the UCAN's OWN
    // nonce is a long-lived delegation-proof concern, so it is deliberately
    // NOT tracked here — a no-op tracker is correct. Re-validating the SAME
    // stored proof on a later legitimate invocation must not falsely trip
    // UCAN-nonce replay, and a long-lived proof's nonce timestamp is
    // legitimately stale (well outside the §9.14 freshness window), so a
    // format/freshness-checking tracker would wrongly reject it. This mirrors
    // the accepted production `NoopNonceTracker` pattern in `broadcast.rs`.
    let mut nonce_tracker = NoopNonceTracker;

    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        // B's store doubles as the delegation-chain proof resolver.
        proof_resolver: &state.xctx_ucan_proofs,
        ceiling: &ceiling,
        context_creator_did: &creator_did,
        // CONFUSED-DEPUTY BINDING: the presenting principal is the carried
        // caller_did. validate_ucan step 5 rejects (AudienceMismatch) if the
        // resolved proof's audience is a DIFFERENT principal.
        presenting_agent_did: req.caller_did.as_ref(),
        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: deps.clock.as_ref(),
        // Cross-context saga RE-VALIDATION of a stored delegation proof re-checks
        // an outlet-INVOCATION gate (`required_cap` = `outlet_call:{outlet}`), so it
        // is an outlet-invocation site and MUST resolve §7.3.8 caveats from each
        // token's own `nb` — matching every other outlet-invocation site
        // (ffi/outlets.rs, napi/outlets.rs, uniffi/bridge.rs). A delegated
        // cross-context outlet token now carries a materialized `origin_kind`
        // (`build_delegated_caveats`); `TokenNbCaveatResolver` surfaces it so the
        // per-edge origin_kind check validates the chain instead of rejecting a
        // resolved-`None` outlet edge (`OriginKindUnspecified`).
        caveat_resolver: &TokenNbCaveatResolver,
    };

    validate_ucan(&token, &required_cap, &mut ctx).map_err(|e| {
        saga_reject!(
            13013,
            PermissionDenied,
            "UCAN re-validation failed (re-bound to caller_did '{}' + outlet '{}'): {}",
            req.caller_did,
            req.outlet_registration_id,
            e
        )
    })
}

/// (2a) Inbound policy — source role + `require_spending_ucan` (spec §6.2.4
/// "Prepare-B... validates `InboundPolicy` (source role, inbound rate,
/// `require_spending_ucan`)"). Two binding gates at this layer:
///
/// - **`allowed_source_roles`** — the channel-authenticated caller's role
///   (`req.caller_source_role`, resolved supervisor-side from the caller
///   context, NEVER envelope-asserted) MUST be in the allow-set. Empty allow-set
///   = any role (matching the `InboundPolicy` default). A caller whose
///   authenticated role is absent from a non-empty allow-set is rejected.
/// - **`require_spending_ucan`** — when set, a proof MUST be present (validated
///   in step (1)).
///
/// The third InboundPolicy axis — the per-interface INBOUND **rate** — is
/// consumed separately in [`consume_inbound_interface_rate_limit`] (step (2b) of
/// `run_prepare_b_checks`), because it is a state mutation (a non-refundable
/// sliding-window decrement) and this function is read-only.
fn validate_inbound_policy(
    state: &PerContextState,
    req: &PrepareBRequest,
) -> Result<(), SagaReject> {
    let Some(interface) = state
        .governance
        .outlet_interfaces
        .iter()
        .find(|i| i.outlet_id == req.outlet_registration_id)
    else {
        return Ok(());
    };
    let Some(inbound) = interface.inbound_policy.as_ref() else {
        return Ok(());
    };

    // `allowed_source_roles`: empty = any role. A non-empty allow-set requires
    // the channel-authenticated caller's role to be present.
    if !inbound.allowed_source_roles.is_empty() {
        let role_allowed = req
            .caller_source_role
            .as_ref()
            .is_some_and(|role| inbound.allowed_source_roles.iter().any(|r| r == role));
        if !role_allowed {
            return Err(saga_reject!(
                13025,
                PermissionDenied,
                "caller role {} is not in inbound allowed_source_roles for outlet '{}'",
                req.caller_source_role
                    .as_deref()
                    .map_or_else(|| "<none>".to_owned(), |r| format!("'{r}'")),
                req.outlet_registration_id
            ));
        }
    }

    // `require_spending_ucan`: a gated interface demands a proof (validated in
    // step (1) when present).
    if inbound.require_spending_ucan && req.ucan_proof_id.is_none() {
        return Err(saga_reject!(
            13015,
            PermissionDenied,
            "inbound policy requires a spending UCAN but none was carried for outlet '{}'",
            req.outlet_registration_id
        ));
    }

    Ok(())
}

/// (3) Input schema specificity floor + input conformance (§9.2.1, §6.2.4
/// normative (2)). REUSES the single-context
/// [`validate_specificity_floor`](scp_protocol::context::outlets::schema::validate_specificity_floor)
/// against the target outlet's REGISTERED schemas — degenerate broad-schema outlets
/// that function as arbitrary message channels are rejected — and then
/// validates the carried `input` value against the registered input schema (the
/// same `validate_value_against_schema` the single-context outlet path applies).
fn validate_input_specificity(
    state: &PerContextState,
    req: &PrepareBRequest,
) -> Result<(), SagaReject> {
    use scp_protocol::context::outlets::schema::{
        validate_specificity_floor, validate_value_against_schema,
    };

    let Some(registration) = state
        .governance
        .registered_outlets
        .iter()
        .find(|t| t.outlet_id == req.outlet_registration_id)
    else {
        return Err(saga_reject!(
            13016,
            PermissionDenied,
            "outlet '{}' not found in target registry",
            req.outlet_registration_id
        ));
    };

    // Floor: degenerate broad-schema outlets are rejected (independent of the
    // concrete input value).
    validate_specificity_floor(
        &registration.schema.input_schema,
        &registration.schema.output_schema,
    )
    .map_err(|(side, fields)| {
        saga_reject!(
            13017,
            PermissionDenied,
            "input schema specificity floor not met for outlet '{}' ({} schema has {} fields)",
            req.outlet_registration_id,
            side,
            fields
        )
    })?;

    // Conformance: the carried input value MUST validate against the registered
    // input schema (§6.2.4 normative (2)).
    validate_value_against_schema(&req.input, &registration.schema.input_schema).map_err(|msg| {
        saga_reject!(
            13021,
            PermissionDenied,
            "input does not conform to registered schema for outlet '{}': {}",
            req.outlet_registration_id,
            msg
        )
    })
}

/// (5) Freshness / anti-replay (spec §6.2.4). Rejects if the caller-asserted
/// send-time is outside §9.14 clock-skew tolerance OR the nonce is already in
/// B's TTL dedup cache. Performs the dedup READ only; the accept-path record
/// happens in [`prepare_b`] after every check passes.
///
/// **Window relationship (BLACK-XCTX-01).** The nonce-dedup TTL
/// ([`SAGA_NONCE_DEDUP_TTL_SECS`]) STRICTLY exceeds this freshness check's
/// skew tolerance (`DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`), so a `nonce` recorded
/// at the trailing edge of its freshness window is still remembered by the
/// dedup cache through the rest of that window — a replay carrying a *refreshed*
/// `asserted_timestamp_ms` therefore still hits the dedup gate rather than
/// slipping past a coterminous (equal-length) window.
///
/// **Forward obligation (untrusted transport).** `asserted_timestamp_ms` is
/// caller-asserted and, in the co-resident SDK seam this code implements, the
/// caller leg is **channel-authenticated** (`caller_did`/`caller_context_id`
/// are the transport-leg identity, not envelope-asserted — see the §6.2.4
/// *Cache-eviction bound* clause) and there is no capturable wire envelope, so
/// exactly-once-per-envelope holds by construction. A future cross-node
/// child-bridge transport carrying this envelope over an UNTRUSTED link does
/// NOT satisfy that by construction: the longer-than-skew window bounds, but
/// does not eliminate, a replay that refreshes the timestamp once the original
/// `nonce` finally ages out. Before such a transport ships, the asserted
/// timestamp MUST be AUTHENTICATED/BOUND — signed by the caller, or the dedup
/// keyed so a replay cannot refresh the freshness window. This forward
/// obligation is recorded in the spec §6.2.4 *Freshness / anti-replay* clause,
/// mirroring the ADR-049 §3a forward-obligation discipline.
fn validate_freshness(
    state: &PerContextState,
    deps: &ActorDeps,
    req: &PrepareBRequest,
) -> Result<(), SagaReject> {
    let now_ms = deps.clock.now_millis();
    let skew_ms = DEFAULT_CLOCK_SKEW_TOLERANCE_SECS.saturating_mul(1000);
    let delta_ms = now_ms.abs_diff(req.asserted_timestamp_ms);
    if delta_ms > skew_ms {
        return Err(saga_reject!(
            13018,
            PermissionDenied,
            "invocation timestamp outside §9.14 skew tolerance (Δ={}ms > {}ms) for outlet '{}'",
            delta_ms,
            skew_ms,
            req.outlet_registration_id
        ));
    }

    // PURE READ (ADR-049 §9): the replay decision uses `is_replayed_read`
    // (`&self`), which applies the SAME TTL freshness filter as `is_replayed`
    // inline but mutates nothing — so this whole gate runs through a shared
    // `&PerContextState`. The mutating TTL eviction `is_replayed` used to fold
    // in is hoisted into the staging combinator's KEEP closure in `prepare_b`
    // (it already mutates `xctx_nonce_dedup` via `record`), so the eviction
    // rides the SAME single fail-closed persist as the accepted-nonce record —
    // no Class-S `&mut` mutation happens during the read-only check phase.
    let now_secs = deps.clock.now_secs();
    if state
        .class_s
        .xctx_nonce_dedup
        .is_replayed_read(&req.asserted_nonce, now_secs)
    {
        return Err(saga_reject!(
            13019,
            PermissionDenied,
            "invocation nonce already seen in target dedup cache (replay) for outlet '{}'",
            req.outlet_registration_id
        ));
    }
    Ok(())
}

/// (6) Chain-depth enforcement (spec §6.2.4). Rejects if the re-derived inbound
/// depth (`asserted + 1`) would exceed the context-configured `max_chain_depth`
/// (default 8 via
/// [`effective_max_chain_depth`](scp_protocol::provenance::attach::effective_max_chain_depth)).
fn validate_chain_depth(state: &PerContextState, req: &PrepareBRequest) -> Result<(), SagaReject> {
    use scp_protocol::provenance::attach::effective_max_chain_depth;

    let max_depth = effective_max_chain_depth(state.handle.params().max_chain_depth);
    // B re-derives depth = incoming + 1; reject if that would exceed the cap.
    if u16::from(req.asserted_chain_depth) + 1 > u16::from(max_depth) {
        return Err(saga_reject!(
            13020,
            PermissionDenied,
            "chain depth {} +1 exceeds max_chain_depth {} for outlet '{}'",
            req.asserted_chain_depth,
            max_depth,
            req.outlet_registration_id
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Commit-B — target-context actor (split reserve / settle, spec §6.2.4)
// ---------------------------------------------------------------------------

/// Derive the `SagaId`-stable `OutletInvoked` event-log entry id (spec §6.2.4
/// "`SagaId`-idempotent event-log append"). The id MUST be reproducible from
/// durable state on a replayed Commit — it is a signed receipt-preimage field —
/// so it is derived deterministically from the `SagaId` rather than minted from
/// a fresh counter. The `OutletInvoked:` prefix matches the §5.16 event-name
/// convention so the §6.2.4 auditor can recognise the entry type.
fn outlet_invoked_event_id(saga_id: &SagaId) -> String {
    format!("OutletInvoked:{}", saga_id.0)
}

/// Commit-B reserve half (spec §6.2.4 "Commit", split-execution model). Runs on
/// the LOCAL target actor. Confirms the staged prepared + session reservation
/// are present and decides whether the FSM must run the executor.
///
/// Idempotency (§6.2.4 / §17.16.4): if this `SagaId`'s output was already
/// captured (a replayed Commit), reply [`CommitBReserveOutcome::AlreadyCommitted`]
/// with the STORED output + receipt + event id — the outlet is NEVER re-invoked.
/// Otherwise the staged `saga_pending` slot for this `SagaId` MUST be a
/// cross-context outlet invocation; reply [`CommitBReserveOutcome::ReadyToExecute`].
///
/// Read-only — no mutation, no Class-S persist.
fn commit_b_reserve(
    state: &PerContextState,
    saga_id: &SagaId,
    reply: CommitBReserveReply,
) -> Outcome<()> {
    // Replay short-circuit: a prior Commit-B already captured the output.
    if let Some(committed) = state.class_s.xctx_committed_outputs.get(saga_id) {
        let receipt = match jcs_receipt_bytes(&committed.receipt) {
            Ok(bytes) => bytes,
            Err(err) => {
                let sketch = outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                return Outcome::err(sketch);
            }
        };
        let _ = reply.send(Ok(CommitBReserveOutcome::AlreadyCommitted {
            receipt,
            output_bytes: committed.output_bytes.clone(),
            outlet_invoked_event_id: committed.outlet_invoked_event_id.clone(),
        }));
        return Outcome::ok(());
    }

    // Not yet committed: the staged prepared MUST be present (Prepare-B ran).
    if let Some(SagaPreparedState::CrossContextOutletInvocation(_)) =
        state.class_s.saga_pending.get(saga_id)
    {
        let _ = reply.send(Ok(CommitBReserveOutcome::ReadyToExecute));
        return Outcome::ok(());
    }
    let err = ContextError::InvalidState(format!(
        "SCP-SAGA-13030: Commit-B reserve for saga '{}' found no staged cross-context \
         outlet-invocation prepared state (Prepare-B never ran, or the slot was rolled back)",
        saga_id.0
    ));
    let sketch = outcome_error_sketch(&err);
    let _ = reply.send(Err(err));
    Outcome::err(sketch)
}

/// Commit-B settle half (spec §6.2.4 "Commit", target side). Runs on the LOCAL
/// target actor with the executor's captured `output_bytes`.
///
/// On the FIRST settle: canonicalizes the output to JCS, signs the
/// [`CrossContextOutletReceipt`] over the STAGED `recorded_nonce` /
/// `recorded_chain_depth` / `recorded_timestamp_ms` + `output_hash` + the
/// `SagaId`-stable `outlet_invoked_event_id` using the target's Active Signing
/// Key, durably captures the receipt + output keyed by `SagaId`, appends
/// `OutletInvoked` to the local log, clears the staged `saga_pending` slot,
/// Class-S sync-persists fail-closed, and replies. On a REPLAY (output already
/// captured) re-emits the STORED bytes verbatim — no re-invoke, no re-append,
/// no re-sign.
async fn commit_b_settle(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    output_bytes: Vec<u8>,
    target_signing_key: &SigningKeyBytes,
    reply: CommitBSettleReply,
) -> Outcome<()> {
    // Replay: re-emit the stored capture byte-for-byte; never re-invoke / re-sign.
    if let Some(committed) = cell.class_s.xctx_committed_outputs.get(saga_id) {
        return reemit_committed_settle(committed, reply);
    }

    match commit_b_first_settle(cell, deps, saga_id, &output_bytes, target_signing_key).await {
        Ok(outcome) => {
            let _ = reply.send(Ok(outcome));
            Outcome::ok_mutated(())
        }
        // `mutated` is reported by the settle body itself: a pre-append failure
        // (no staged slot, signing) leaves state untouched; an at/after-append
        // failure (then rolled back) still touched the event log, so the actor
        // must persist. This is precise — never code-string-sniffed.
        Err((mutated, err)) => {
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            if mutated {
                Outcome::err_mutated(sketch)
            } else {
                Outcome::err(sketch)
            }
        }
    }
}

/// Re-emit a durably-captured Commit-B settle on a replay (spec §6.2.4
/// "Crash recovery §17.16.4"): the stored receipt + output are returned
/// verbatim. The outlet is NOT re-invoked and nothing is re-signed.
fn reemit_committed_settle(
    committed: &CommittedOutletInvocation,
    reply: CommitBSettleReply,
) -> Outcome<()> {
    match jcs_receipt_bytes(&committed.receipt) {
        Ok(receipt) => {
            let _ = reply.send(Ok(CommitBSettleOutcome {
                receipt,
                output_bytes: committed.output_bytes.clone(),
                outlet_invoked_event_id: committed.outlet_invoked_event_id.clone(),
            }));
            Outcome::ok(())
        }
        Err(err) => {
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
    }
}

/// First (non-replay) Commit-B settle: sign the receipt over the STAGED
/// provenance + captured output, append `OutletInvoked`, durably capture the
/// output keyed by `SagaId`, clear the staged slot, and Class-S persist
/// fail-closed. Returns the settle outcome (the caller sends the reply).
///
/// On a persist failure the durable capture + staged slot are rolled back so a
/// retried settle re-runs cleanly. The error is returned as `(mutated, err)`:
/// `mutated == false` for the pre-append failures (no staged slot — 13031; or
/// receipt signing — 13032-13034), `true` once the `OutletInvoked` append has
/// run (the event log was touched even if the durable capture was rolled back).
// Sync wrapper preserved for the existing call shape; the body is now `async`
// (the combinators are `async`-friendly but the persists here are sync — the
// `async` keyword is required because `commit_b_settle` awaits this). See the
// FLAG below for why this site uses a TWO-combinator decomposition rather than
// the single `commit_class_s_then_append`.
//
// ── FLAG-COMMIT-B (then_append NOT used — persist-fail direction mismatch) ───
// The roadmap maps this site to `commit_class_s_then_append` (Class-S commit in
// `f`, event-log append in `after`). That combinator's PERSIST-FAILURE arm
// KEEPS the Class-S mutation in memory and reports `durability_diverged: true`
// (its doc step 3: "the restore is the caller's call … matches `*_keep`"). But
// `commit_b_first_settle`'s persist-failure arm must RESTORE — it removes the
// just-inserted `xctx_committed_outputs` capture and RE-INSERTS the owned
// `saga_pending` slot so a retried settle sees `ReadyToExecute` and re-runs.
// Keeping the capture (the `then_append` behaviour) would make the next
// `commit_b_reserve` report `AlreadyCommitted` against an in-memory-only capture
// and SKIP the `OutletInvoked` append forever — a missing convergent leaf on an
// in-process retry after a survived persist failure. `then_append` exposes no
// way to recover the owned `prepared` on its persist-failure arm (the
// `append_input` is dropped by the early `?`), and `CrossContextOutletInvocationPrepared`
// is deliberately NOT `Clone` (§9.4.3 non-derive barrier), so the slot cannot be
// reconstructed afterward. The faithful, behaviour-preserving form is therefore
// a TWO-combinator decomposition:
//   (1) `commit_class_s_restore` — capture (remove slot, sign, insert outputs) +
//       fail-closed persist; on persist failure RESTORE (snapshot taken before
//       `f` ⇒ slot back, capture gone) — byte-identical to the prior inline
//       persist-failure rollback, reported `(false, persist_err)`.
//   (2) the event-log append runs AFTER (1) succeeds; on append failure the
//       compensating rollback (remove capture, re-insert the owned slot) + its
//       RE-PERSIST is wrapped in `commit_class_s_keep` — keep-on-persist-failure
//       matches the prior `(true, persist_err)` (re-persist failed ⇒ capture
//       stays durable) / `(false, original_err)` (re-persist succeeded) mapping.
// No Class-S mutation is left outside a combinator.
async fn commit_b_first_settle(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    output_bytes: &[u8],
    target_signing_key: &SigningKeyBytes,
) -> Result<CommitBSettleOutcome, (bool, ContextError)> {
    // Peek the staged slot to derive the persist `context_id` (target hex) BEFORE
    // the capture combinator (which needs `context_id` up front) and to reject the
    // no-slot / wrong-variant case as `(false, 13031)` with NO persist — exactly
    // as the prior inline remove+match did (the authoritative move-out happens
    // inside `f` below).
    let Some(SagaPreparedState::CrossContextOutletInvocation(peek)) =
        cell.class_s.saga_pending.get(saga_id)
    else {
        return Err((
            false,
            ContextError::InvalidState(format!(
                "SCP-SAGA-13031: Commit-B settle for saga '{}' found no staged cross-context \
                 outlet-invocation prepared state",
                saga_id.0
            )),
        ));
    };
    let target_hex = hex_context_id(&peek.target_context_id);

    // (1) CAPTURE + fail-closed persist with RESTORE-on-persist-failure.
    //
    // `f` MOVES the staged slot out (owning the original `SagaPreparedState` for a
    // lossless rollback), signs the receipt, and inserts the durable output
    // capture. On a signing failure `f` re-inserts the owned original and returns
    // the error (no persist). `commit_class_s_restore` snapshots Class-S BEFORE
    // `f`, so its persist-failure RESTORE rolls the capture back and re-stages the
    // slot verbatim (matching the prior inline rollback). Both the `f`-error
    // (13031 already handled above, or signing 13032-13034) and the persist
    // failure surface as `(false, err)` — `mutated = false` (no event-log touch).
    //
    // `f` returns the data the post-persist append + reply need, plus the OWNED
    // `prepared` so the append-failure compensation in (2) can re-insert the slot.
    let captured = cell.commit_class_s_restore(deps, &target_hex, |mut view| {
        let saga_pending = &mut view.class_s_mut().saga_pending;
        // Move the staged slot OUT (owning the original for a lossless rollback).
        // The peek above already proved a cross-context slot is present, so this
        // match is infallible; the `else` is a defensive re-insert + 13031.
        let removed = saga_pending.remove(saga_id);
        let Some(SagaPreparedState::CrossContextOutletInvocation(prepared)) = removed else {
            if let Some(other) = removed {
                saga_pending.insert(saga_id.clone(), other);
            }
            return Err(ContextError::InvalidState(format!(
                "SCP-SAGA-13031: Commit-B settle for saga '{}' found no staged cross-context \
                 outlet-invocation prepared state",
                saga_id.0
            )));
        };

        // Build the signed receipt from STAGED provenance + the captured output.
        // A signing failure leaves state as found (re-insert the owned original).
        let event_id = outlet_invoked_event_id(saga_id);
        let receipt =
            match build_signed_receipt(&prepared, output_bytes, &event_id, target_signing_key) {
                Ok(r) => r,
                Err(e) => {
                    view.class_s_mut().saga_pending.insert(
                        saga_id.clone(),
                        SagaPreparedState::CrossContextOutletInvocation(prepared),
                    );
                    return Err(e);
                }
            };
        // The receipt's JCS output bytes are the canonical preimage A re-hashes.
        let canonical_output = receipt.output_jcs.clone();

        // Snapshot the fields the OutletInvoked record needs. `recorded_chain_depth`
        // / `recorded_timestamp_ms` are B's staged values (never re-read from
        // wire).
        let caller_did_str = prepared.caller_did.0.clone();
        let target_context_id = prepared.target_context_id;
        let caller_context_id = prepared.caller_context_id;
        let outlet_registration_id = prepared.outlet_registration_id.clone();

        // Order matters (provenance-integrity): the durable output capture +
        // Class-S persist land BEFORE the `OutletInvoked` event-log append. The
        // event log is a SEPARATE provider not covered by
        // `persist_state_fail_closed` and the append is NOT provider-idempotent,
        // so appending FIRST would double-append on a persist-failure retry: a
        // persist failure rolls the capture back and re-stages the slot, the next
        // reserve reports `ReadyToExecute`, and `commit_b_first_settle` re-runs —
        // re-appending a SECOND `OutletInvoked` for one saga. Appending only after
        // the capture + persist succeed makes a persist failure leave NO orphan
        // log entry, so the retry produces exactly one `OutletInvoked`.

        // Durably capture the output + signed receipt keyed by SagaId (§6.2.4
        // "Exactly-once execution with durable output capture"). The staged slot
        // was already removed up front (the session reservation is now applied via
        // the capture). No event-log mutation yet — a failure before the append is
        // recoverable by re-inserting the owned staged slot.
        view.class_s_mut().xctx_committed_outputs.insert(
            saga_id.clone(),
            CommittedOutletInvocation {
                receipt: receipt.clone(),
                output_bytes: canonical_output.clone(),
                outlet_invoked_event_id: event_id.clone(),
            },
        );

        Ok(CommitBCaptured {
            prepared,
            receipt,
            canonical_output,
            event_id,
            caller_did_str,
            target_context_id,
            caller_context_id,
            outlet_registration_id,
        })
    });

    // Both `f`-error and persist-failure surface as `(false, err)` (mutated =
    // false). `commit_class_s_restore` already restored Class-S on persist
    // failure (capture rolled back, slot re-staged).
    let captured_fields = match captured.await {
        Ok(c) => c,
        Err(err) => return Err((false, err)),
    };

    // (2) Append `OutletInvoked` + finalize (split out to keep this helper within
    // the per-function line budget).
    commit_b_settle_finalize(cell, deps, saga_id, &target_hex, captured_fields).await
}

/// Post-capture half of [`commit_b_first_settle`] (step 2): append the
/// `OutletInvoked` event-log leaf, and on append failure roll the capture back +
/// re-stage the owned slot + RE-PERSIST via [`ClassSCell::commit_class_s_keep`].
/// Split out of [`commit_b_first_settle`] only to stay within the per-function
/// line budget — the behaviour is exactly the prior inline append path. See
/// FLAG-COMMIT-B on the capture side for why this is a two-combinator
/// decomposition rather than `commit_class_s_then_append`.
async fn commit_b_settle_finalize(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    target_hex: &str,
    captured: CommitBCaptured,
) -> Result<CommitBSettleOutcome, (bool, ContextError)> {
    let CommitBCaptured {
        prepared,
        receipt,
        canonical_output,
        event_id,
        caller_did_str,
        target_context_id,
        caller_context_id,
        outlet_registration_id,
    } = captured;

    // Append `OutletInvoked` to the local (target) log (spec §6.2.4 "Commit"):
    // caller ctx id / caller DID actor / B's re-derived depth + staged timestamp.
    // Runs ONLY after the capture + persist landed, so it appears exactly once
    // across retries.
    let outlet_invoked_payload = serde_json::json!({
        "saga_id": saga_id.0,
        "outlet_invoked_event_id": event_id,
        "caller_context_id": hex_context_id(&caller_context_id),
        "outlet_registration_id": outlet_registration_id,
        "chain_depth": receipt.chain_depth,
        "timestamp_ms": receipt.timestamp_ms,
    });
    // CONVERGENT committer-assigned leaf timestamp: the saga's `OutletInvoked` is a
    // commit-ordered convergent durable leaf (ADR-011 Amendment §6 carve-out),
    // NOT a per-author-excluded event. Draw the timestamp from B's signed
    // `recorded_timestamp_ms` (the receipt's `timestamp_ms`, in ms) — the single
    // staged value B also wrote into the receipt and that a replayed Commit
    // reproduces byte-for-byte — never a fresh Commit-time `now()`, so two honest
    // members reconstruct the identical leaf (§7.3.1, §9.9.3).
    let append_result = match serde_json::to_vec(&outlet_invoked_payload) {
        Ok(outlet_invoked_payload_bytes) => {
            deps.event_log
                .append_context_event_with_payload(
                    &target_context_id,
                    scp_event_log::EventType::OutletInvoked,
                    &caller_did_str,
                    scp_event_log::EventPayload {
                        data: outlet_invoked_payload_bytes,
                    },
                    receipt.timestamp_ms / 1000,
                )
                .await
        }
        Err(e) => Err(ContextError::EventLogFailed(format!(
            "SCP-SAGA-13038: OutletInvoked payload serialization failed: {e}"
        ))),
    };

    if let Err(append_err) = append_result {
        // The append (or its payload encode) failed AFTER the capture+persist
        // landed. Roll the capture back and re-stage the owned slot, then
        // RE-PERSIST so the rolled-back state is durable — otherwise the next
        // reserve would see the already-persisted capture, report
        // `AlreadyCommitted`, and SKIP the append forever (a missing
        // `OutletInvoked`). With the compensating re-persist, the retry sees
        // `ReadyToExecute` and re-runs settle, appending exactly once. The
        // rollback+re-persist is a fail-closed Class-S commit of the rolled-back
        // state — `commit_class_s_keep` keeps it on a re-persist failure (matching
        // the prior `(true, persist_err)`: capture stays durable, a genuine
        // fail-closed terminal the operator / crash-recovery sweep reconciles);
        // on re-persist success the original append error surfaces as
        // `(false, append_err)`.
        return match cell
            .commit_class_s_keep(deps, target_hex, |mut view| {
                let class_s = view.class_s_mut();
                class_s.xctx_committed_outputs.remove(saga_id);
                class_s.saga_pending.insert(
                    saga_id.clone(),
                    SagaPreparedState::CrossContextOutletInvocation(prepared),
                );
                Ok(())
            })
            .await
        {
            Ok(()) => Err((false, append_err)),
            Err(persist_err) => Err((true, persist_err)),
        };
    }

    // The capture + persist + append all landed; serializing the receipt for the
    // reply is a pure encode of already-committed state — a failure here is
    // `mutated`.
    let receipt_bytes = jcs_receipt_bytes(&receipt).map_err(|e| (true, e))?;
    Ok(CommitBSettleOutcome {
        receipt: receipt_bytes,
        output_bytes: canonical_output,
        outlet_invoked_event_id: event_id,
    })
}

/// The data `commit_b_first_settle`'s capture combinator (`f`) produces for the
/// post-persist event-log append + reply: the OWNED original `prepared` (so the
/// append-failure compensation can re-stage the slot losslessly), the signed
/// receipt + canonical output + stable event id, and the `OutletInvoked` record
/// fields. Lives only between the two combinators in that one helper.
struct CommitBCaptured {
    prepared: CrossContextOutletInvocationPrepared,
    receipt: CrossContextOutletReceipt,
    canonical_output: Vec<u8>,
    event_id: String,
    caller_did_str: String,
    target_context_id: [u8; 32],
    caller_context_id: [u8; 32],
    outlet_registration_id: String,
}

/// Sign the [`CrossContextOutletReceipt`] over the staged B-recorded provenance +
/// `SHA-256(jcs(output))` + the `SagaId`-stable event id, using the target's
/// Active Signing Key (spec §6.2.4 "Receipt / response return path"). The
/// output is canonicalized to JCS so the receipt is self-verifying (the
/// verifier re-hashes the carried bytes with no re-canonicalization step).
fn build_signed_receipt(
    prepared: &CrossContextOutletInvocationPrepared,
    output_bytes: &[u8],
    event_id: &str,
    target_signing_key: &SigningKeyBytes,
) -> Result<CrossContextOutletReceipt, ContextError> {
    // Canonicalize the executor output to JCS — the exact bytes the preimage
    // hashes and the receipt carries (Output canonicalization obligation).
    let output_value: serde_json::Value = serde_json::from_slice(output_bytes).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13032: Commit-B outlet output is not valid JSON, cannot canonicalize \
             for the receipt: {e}"
        ))
    })?;
    let output_jcs = scp_protocol::jcs::to_vec(&output_value).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13033: Commit-B receipt output JCS canonicalization failed: {e}"
        ))
    })?;

    let signing_key = target_signing_key.to_signing_key();
    CrossContextOutletReceipt::sign(
        &signing_key,
        CrossContextOutletReceiptFields {
            caller_context_id: prepared.caller_context_id,
            target_context_id: prepared.target_context_id,
            caller_did: prepared.caller_did.0.clone(),
            nonce: prepared.recorded_nonce,
            outlet_registration_id: prepared.outlet_registration_id.clone(),
            output_jcs,
            outlet_invoked_event_id: event_id.to_owned(),
            chain_depth: prepared.recorded_chain_depth,
            timestamp_ms: prepared.recorded_timestamp_ms,
        },
    )
    .map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13034: Commit-B receipt signing failed: {e}"
        ))
    })
}

/// JCS-encode a [`CrossContextOutletReceipt`] to the wire bytes the FSM forwards.
fn jcs_receipt_bytes(receipt: &CrossContextOutletReceipt) -> Result<Vec<u8>, ContextError> {
    scp_protocol::jcs::to_vec(receipt).map_err(|e| {
        ContextError::CryptoFailed(format!(
            "SCP-SAGA-13035: Commit-B receipt serialization failed: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Commit-A — caller-context actor (spec §6.2.4)
// ---------------------------------------------------------------------------

/// Owned inputs for [`commit_a`], grouped to keep the handler signature within
/// the clippy argument budget.
struct CommitARequest {
    saga_id: SagaId,
    reservation: PreparedAFields,
    caller_context_id: [u8; 32],
    caller_did: DID,
    target_context_id: [u8; 32],
    nonce: [u8; 16],
    receipt: Vec<u8>,
    output_bytes: Vec<u8>,
}

/// Builds the caller-side `CrossContextOutletInvoked` leaf: its CONVERGENT
/// committer-assigned timestamp (seconds) + its JSON payload bytes.
///
/// The caller-side record is a commit-ordered convergent durable leaf (ADR-011
/// Amendment §6 carve-out), NOT a per-author-excluded event. It MUST hash the
/// SAME instant as B's `OutletInvoked` leaf so the two `nonce`-joined records date
/// the one provenance edge identically. That instant is B's signed
/// `recorded_timestamp_ms`, carried in the forwarded, already-verified
/// `CrossContextOutletReceipt` (`timestamp_ms`, in ms). Re-deriving it from the
/// receipt bytes rather than any local clock keeps every honest member's leaf
/// byte-identical (§7.3.1, §9.9.3, §6.2.4 *Recorded timestamp*).
///
/// Every payload field is convergent committed data — `saga_id`, the target ctx
/// id, B's staged `nonce`, the receipt output hash, and the JCS-canonical
/// receipt's byte length — so no per-member value enters the leaf.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if the receipt cannot be parsed for
/// its timestamp or the payload cannot be serialized.
//
// Takes the individual fields rather than `&CommitARequest` because by this
// point `req.reservation` has been partially moved (its ticket was consumed by
// the settle path), so a whole-`req` borrow would not compile.
fn cross_context_invoked_leaf(
    receipt_bytes: &[u8],
    saga_id: &str,
    target_context_id: &[u8; 32],
    nonce: &[u8; 16],
    output_bytes: &[u8],
) -> Result<(u64, Vec<u8>), ContextError> {
    let receipt: CrossContextOutletReceipt =
        serde_json::from_slice(receipt_bytes).map_err(|err| {
            ContextError::EventLogFailed(format!(
                "SCP-SAGA-13039: CrossContextOutletInvoked timestamp could not be \
                 read from the receipt: {err}"
            ))
        })?;
    let invoked_leaf_secs = receipt.timestamp_ms / 1000;
    let invoked_payload = serde_json::json!({
        "saga_id": saga_id,
        "target_context_id": hex_context_id(target_context_id),
        "nonce": hex::encode(nonce),
        "output_hash": hex_output_hash(output_bytes),
        "receipt_len": receipt_bytes.len(),
    });
    let invoked_payload_bytes = serde_json::to_vec(&invoked_payload).map_err(|err| {
        ContextError::EventLogFailed(format!(
            "SCP-SAGA-13040: CrossContextOutletInvoked payload serialization failed: {err}"
        ))
    })?;
    Ok((invoked_leaf_secs, invoked_payload_bytes))
}

/// Commit-A handler (spec §6.2.4 "Commit", caller side). Runs on the LOCAL
/// caller-context actor.
///
/// Settles the escrow + outbound-rate-limit reservation staged at Prepare-A
/// (§19.2.2), appends `CrossContextOutletInvoked` referencing the target ctx id +
/// the SAME `nonce` (the join key between the two records, §6.2.4 "Dual
/// event-log recording"), Class-S sync-persists fail-closed, and acks.
/// Idempotent by `SagaId`: a replay re-acks without re-settling or re-appending
/// (the reservation's RAII ticket is consumed, so a true double-settle cannot
/// occur — but the durable marker is the idempotency witness).
async fn commit_a(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    req: CommitARequest,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use crate::context::outlets_helpers::{OutletSettleRequest, settle_outlet_economy};

    let caller_hex = hex_context_id(&req.caller_context_id);

    // Idempotency: a prior Commit-A already recorded this saga. Re-ack as a
    // no-op; the reservation handed back on replay is released (RAII) rather
    // than double-settled. (`xctx_committed_invocations` records committed A-side
    // sagas; absent ⇒ first Commit-A.)
    if cell
        .class_s
        .xctx_committed_invocations
        .contains(&req.saga_id)
    {
        // GENERATION-CHECKED rollback of the handed-back reservation: if this
        // actor was despawned+respawned between Prepare-A and this replayed
        // Commit-A, refunding against the new instance's owned state would
        // corrupt the WRONG context. On a mismatch the helper voids only the
        // external escrow and consumes the ticket (mirrors `settle_outlet_economy`).
        let class_c_economy_reversed =
            crate::context::outlets_helpers::rollback_outlet_economy_generation_checked(
                cell.class_c_view(),
                deps,
                req.reservation.reservation.generation,
                req.reservation.reservation.ticket,
            )
            .await;
        // ── COMMIT-A-REPLAY (idempotent Class-S remove, NO fail-closed persist — SECURITY) ───
        // The durable reversal record (if still present) was consumed at the
        // FIRST Commit-A; remove any straggler so it cannot reverse settled
        // state. A removal here is rare (the first Commit-A already removed it),
        // so it is DELIBERATELY not folded into a persist decision —
        // `xctx_committed_invocations` already witnesses the committed terminal
        // durably (checked above via `contains`), and this arm replies `Ok(())`
        // with NO persist. `clear_committed_reservation_idempotent` is the single
        // named no-persist Class-S primitive for exactly this idempotent
        // straggler cleanup: adding a fail-closed persist would turn this
        // idempotent `Ok` re-ack into a fallible write (a behaviour change), and
        // the committed terminal is already durable, so the removal is
        // rebuilt-irrelevant on respawn. It can never widen to a closure form.
        let _ = cell.clear_committed_reservation_idempotent(&req.saga_id);
        let _ = reply.send(Ok(()));
        // ADR-049 §Decision 9 / finding N1: on a GENERATION MATCH the
        // generation-checked rollback above reversed Class-C economy bookkeeping
        // (velocity / budget / hard-rate refund) through the non-persisting
        // `class_c_view`, so its durability rides this handler's `mutated` flag —
        // report `ok_mutated` to mark the actor dirty for the ordinary COALESCED
        // best-effort persist. That is NOT the fail-closed write the Class-S
        // straggler removal above deliberately rules out; a coalesced persist keeps
        // this idempotent `Ok` re-ack infallible while still making the Class-C
        // reversal durable. This branch is guarded-unreachable in today's FSM (a
        // committed Commit-A leaves `prepared_a == None`, so a live reservation is
        // not re-delivered on the same generation), but marking `mutated` keeps the
        // handler correct-by-construction if that ever changes. On a generation
        // MISMATCH the helper voided only external escrow and touched no Class-C
        // field, so nothing local changed → `ok` (unmutated).
        return if class_c_economy_reversed {
            Outcome::ok_mutated(())
        } else {
            Outcome::ok(())
        };
    }

    // Settle (capture) the escrow + outbound rate-limit reservation. The
    // reservation was staged at Prepare-A and held by the FSM; Commit-A applies
    // it via the existing single-context settle/capture path (§19.2.2).
    let settle_request = OutletSettleRequest::Capture {
        generation: req.reservation.reservation.generation,
        ticket: req.reservation.reservation.ticket,
    };
    if let Err(err) =
        settle_outlet_economy(cell, deps, &caller_hex, &req.caller_did, settle_request).await
    {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err_mutated(sketch);
    }

    // Order matters (provenance-integrity), mirroring `commit_b_first_settle`:
    // the idempotency witness + Class-S persist land BEFORE the
    // `CrossContextOutletInvoked` event-log append. The event log is a SEPARATE
    // provider not covered by `persist_state_fail_closed` and the append is NOT
    // provider-idempotent, so appending FIRST (the inverse, B-side-documented
    // hazard) would leave a DURABLE A-side `CrossContextOutletInvoked` orphan when
    // the post-append persist fails: the witness is rolled back, but the log
    // entry already landed — an A-without-B record that B's log denies and that
    // `divergence_marker_plan` (keyed off the B-committed event id) would not
    // surface, a silent one-sided A-record. Appending only AFTER the witness +
    // persist succeed makes a persist failure leave NO orphan log entry.

    // Order matters (provenance-integrity), mirroring `commit_b_first_settle`:
    // the idempotency witness + Class-S persist land BEFORE the
    // `CrossContextOutletInvoked` event-log append. The same persist-fail-direction
    // mismatch as `commit_b_first_settle` applies here, so this site uses the SAME
    // two-combinator decomposition — see FLAG-COMMIT-B. `commit_class_s_then_append`
    // would KEEP the witness on a persist failure; Commit-A must RESTORE it (roll
    // the witness back AND re-stash the consumed record). Decomposition:
    //   (1) `commit_class_s_restore` — insert the witness + remove the durable
    //       caller-reservation record, fail-closed persist; on persist failure
    //       RESTORE both (witness un-inserted, record re-inserted) — byte-identical
    //       to the prior inline rollback, reported `err_mutated` (the settle above
    //       already mutated owned economy).
    //   (2) the leaf build + append run AFTER (1); on either failure the
    //       compensation rolls back the WITNESS ONLY (the consumed record stays
    //       consumed — matching the prior leaf/append arms, which re-insert the
    //       witness but NOT the record) and re-persists via `commit_class_s_keep`
    //       (keep on re-persist failure ⇒ witness stays durable, the prior
    //       `err_mutated` terminal).

    // (1) Record the committed A-side saga (the idempotency witness) and consume
    // the durable caller-reservation record in the SAME Class-S snapshot, then
    // persist fail-closed BEFORE the append. A crash that rolled the settle/marker
    // back behind an acked Commit-A would double-settle on replay; the consumed
    // record (the reservation was just SETTLED via the carrier) must go in the
    // same snapshot so a surviving record can never let a later spurious abort
    // reverse already-settled state. On persist failure `commit_class_s_restore`
    // rolls BOTH back together (witness removed, record re-inserted) and the saga
    // is retried from a clean state. The settle already mutated owned economy and
    // NO `CrossContextOutletInvoked` was appended, so the failure is reported
    // `err_mutated` with no orphan log entry.
    if let Err(persist_err) = cell
        .commit_class_s_restore(deps, &caller_hex, |mut view| {
            let class_s = view.class_s_mut();
            class_s
                .xctx_committed_invocations
                .insert(req.saga_id.clone());
            class_s.xctx_caller_reservations.remove(&req.saga_id);
            Ok(())
        })
        .await
    {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    // (2) Build the convergent `CrossContextOutletInvoked` leaf (timestamp + payload
    // bytes) from the forwarded receipt + request. A malformed receipt or
    // serialization failure here is a post-witness fault handled by the SAME
    // witness-only rollback + re-persist as the append-failure path below.
    let leaf = cross_context_invoked_leaf(
        &req.receipt,
        &req.saga_id.0,
        &req.target_context_id,
        &req.nonce,
        &req.output_bytes,
    );
    let append_result = match leaf {
        Ok((invoked_leaf_secs, invoked_payload_bytes)) => {
            deps.event_log
                .append_context_event_with_payload(
                    &req.caller_context_id,
                    scp_event_log::EventType::CrossContextOutletInvoked,
                    req.caller_did.as_ref(),
                    scp_event_log::EventPayload {
                        data: invoked_payload_bytes,
                    },
                    invoked_leaf_secs,
                )
                .await
        }
        Err(err) => Err(err),
    };

    if let Err(append_err) = append_result {
        // The leaf build or append failed AFTER the witness + persist landed. Roll
        // the WITNESS back (the consumed record stays consumed — the prior arms
        // re-inserted the witness but NOT the record) and RE-PERSIST so the
        // rolled-back state is durable — otherwise the next Commit-A would see the
        // already-persisted witness, re-ack as committed, and SKIP the append
        // forever (a missing `CrossContextOutletInvoked`). With the compensating
        // re-persist, a retry re-runs Commit-A and appends exactly once. The
        // rollback+re-persist is a fail-closed Class-S commit — `commit_class_s_keep`
        // keeps it on a re-persist failure (witness stays durable, a genuine
        // fail-closed terminal the operator / crash-recovery sweep reconciles).
        // Mirrors `commit_b_first_settle`'s append-failure compensation. Both arms
        // reply + return `err_mutated`.
        let (reply_err, sketch) = match cell
            .commit_class_s_keep(deps, &caller_hex, |mut view| {
                view.class_s_mut()
                    .xctx_committed_invocations
                    .remove(&req.saga_id);
                Ok(())
            })
            .await
        {
            Ok(()) => {
                let sketch = outcome_error_sketch(&append_err);
                (append_err, sketch)
            }
            Err(persist_err) => {
                let sketch = outcome_error_sketch(&persist_err);
                (persist_err, sketch)
            }
        };
        let _ = reply.send(Err(reply_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Commit-A witness check (spec §17.16.4). Runs on the LOCAL caller-context
/// actor. READ-ONLY: reports whether this `SagaId`'s Commit-A is already durably
/// recorded in `xctx_committed_invocations`. The FSM calls this to resolve a
/// Commit-A whose ACK was lost AFTER the handler durably committed (the held
/// reservation is gone, so a fresh `CommitA` send cannot re-drive it). A `true`
/// reply IS the idempotent A-side re-ack — the saga resolves to `Committed`
/// rather than a spurious `NeedsRepair`. No mutation, no Class-S persist.
fn commit_a_check_witness(
    state: &PerContextState,
    saga_id: &SagaId,
    reply: tokio::sync::oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let recorded = state.class_s.xctx_committed_invocations.contains(saga_id);
    let _ = reply.send(Ok(recorded));
    Outcome::ok(())
}

// ---------------------------------------------------------------------------
// Abort — either side (spec §6.2.4 "Reservation release on every terminal path")
// ---------------------------------------------------------------------------

/// Abort handler (spec §6.2.4 "Reservation release on every terminal path").
/// Runs on EITHER side's local actor.
///
/// RAII-releases the staged reservations — escrow / outbound-RL on the CALLER
/// side; the outlet-session on the TARGET side is released by clearing the staged
/// `saga_pending` slot (B stages no `OutletEconomyTicket`).
///
/// On the CALLER side the reversal source depends on whether the in-memory
/// carrier survived:
///
/// * **Live abort** (`Some(reservation)`): the carrier is authoritative — it
///   reverses through the generation-checked ticket rollback (precise
///   velocity-token rollback + escrow void). The durable
///   `xctx_caller_reservations` record is then CONSUMED (removed) WITHOUT
///   re-reversing.
/// * **Crash-recovery abort** (`None`, the §17.16.4 re-drive): the carrier died
///   with the crash, so the reversal runs FROM the durable record —
///   UNCONDITIONAL budget / hard-rate-limit / velocity (by the persisted
///   timestamp) reversal + external escrow void. The reversal is NOT gated on a
///   generation match: the record AND the deductions it reverses are rehydrated
///   from ONE consistent snapshot into the same `context_id`-routed actor, keyed
///   by `record.actor_did` + the `SagaId`, so a fresh respawn-stamped generation
///   never matches the pre-crash record — a gate here would wrongly SKIP every
///   real crash-recovery refund. This is the path the HIGH finding exposed: it
///   previously no-op'd, durably over-charging the caller and leaking the escrow.
///
/// The two paths are mutually exclusive (carrier present ⟺ `Some`), so a saga
/// is never double-reversed.
///
/// Class-S sync-persists fail-closed whenever an OWNED-state mutation occurred —
/// the caller refund (the rollback ran against matching-generation owned state),
/// a consumed durable record (its removal must outlive a crash), OR a cleared
/// target slot — then acks. Persisting the caller refund is mandatory:
/// Prepare-A durably persisted the matching deduction, so skipping the refund
/// persist would permanently over-charge the caller on a crash-after-ack (the
/// saga is Aborted, nothing re-drives it). Idempotent: an already-terminal saga
/// (no slot, no record) — or a generation-mismatch caller Abort that touched
/// nothing — is a clean no-op with no redundant persist.
async fn abort(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    saga_id: &SagaId,
    reservation: Option<PreparedAFields>,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // ── ABORT (keep direction; deferred Class-S removes hoisted into the combinator) ─
    // Abort's caller-side reversal is INTERLEAVED with order-critical async
    // EXTERNAL effects (escrow void via `rollback_outlet_economy_generation_checked`
    // / `reverse_caller_reservation_record`) that a sync combinator `f` cannot
    // host, and the whole reversal must run BEFORE the fail-closed persist so the
    // crash-window void→persist ordering is preserved (persist-then-void would
    // change the crash-window semantics). The economy reversals reverse ONLY
    // Class-C governance economy + an external escrow void, so they take the
    // field-granular `ClassCMut` (`cell.class_c_view()`) — they cannot touch
    // Class-S. The Class-S `xctx_caller_reservations` removal is the only Class-S
    // mutation, and it is DEFERRED into the trailing `commit_class_s_keep` `f`
    // alongside the `saga_pending` clear (both Class-S removals land in the SINGLE
    // fail-closed persist that always covered them). The async reversal reads the
    // record via `get().cloned()` (a shared Deref read — NOT a remove), so the
    // remove no longer needs to precede the reversal to obtain the record; the
    // observable order is unchanged (reverse → single remove+persist).
    //
    // KEEP direction: on a persist FAILURE today's abort does NOT roll anything
    // back — the reversal + removes + slot clear stay applied and it returns
    // `err_mutated` (the durable deduction was already persisted at Prepare-A, so
    // the in-memory refund must NOT be un-applied — un-applying would re-open the
    // over-charge a respawn-from-durable would itself fix). So this is `*_keep`,
    // NOT `*_restore` (the roadmap's default-suggested combinator for abort) —
    // flagged here as a deliberate, behaviour-preserving deviation.
    let context_hex = hex_context_id(&cell.context_id);

    // CALLER side: release the held escrow + outbound-RL reservation (RAII). The
    // durable `xctx_caller_reservations` record is CONSUMED on every caller-side
    // terminal path (here and Commit-A) so it can never double-reverse. Which
    // path REVERSES depends on whether the in-memory carrier survived:
    //
    //   * `Some(reservation)` — the LIVE abort. The carrier rolls back via the
    //     GENERATION-CHECKED ticket rollback. On a generation MATCH the carrier
    //     is authoritative (precise velocity-token rollback + escrow void) and we
    //     REMOVE the durable record WITHOUT re-reversing. On a generation
    //     MISMATCH — a despawn+respawn-from-OWN-snapshot between Prepare-A and
    //     this Abort rehydrated the deduction + record under a fresh generation
    //     while the supervisor still holds the OLD-generation carrier — the
    //     generation-checked rollback voids ONLY the external escrow + consumes
    //     the ticket and DOES NOT reverse the rehydrated instance's LOCAL economy
    //     (it correctly refuses a confused-deputy write keyed on the stale
    //     generation). The LOCAL deduction is real and still durable, so we FALL
    //     THROUGH to reverse it from the still-present record via the
    //     gen-agnostic `reverse_caller_reservation_record` (the SAME path the
    //     `None` arm uses, keyed by `record.actor_did` not by generation) BEFORE
    //     removing the record. Each case reverses LOCAL exactly once (match: the
    //     carrier; mismatch: the record), the record path's escrow re-void is
    //     idempotent, and the record is removed exactly once.
    //
    //   * `None` — the §17.16.4 crash-recovery abort. The carrier died with the
    //     crash, so we reverse FROM the durable record UNCONDITIONALLY (NO
    //     generation gate): budget / hard-rate-limit / velocity (by the persisted
    //     timestamp) + external escrow void. A gate would be wrong here — a fresh
    //     respawn stamps a new generation that never matches the pre-crash
    //     record, so gating would skip every real refund. Safety rests on the
    //     record + its deductions being rehydrated from ONE snapshot into the
    //     same `context_id`-routed actor, keyed by `record.actor_did` + the
    //     `SagaId`. This is the path the HIGH finding exposed — it previously
    //     no-op'd, durably over-charging the caller and leaking the escrow.
    //
    // The two reversal paths are mutually exclusive by construction (carrier
    // present ⟺ `Some`; record-reversal only on `None`), so a saga is never
    // double-reversed.
    //
    // `local_rollback_ran` — the LOCAL owned economy (velocity/budget/hard-rate-
    // limit) was reversed against THIS actor instance (Prepare-A durably
    // persisted the matching DEDUCTION, so the refund MUST be persisted or a
    // crash-after-ack permanently over-charges). `had_caller_record_consumed` —
    // a durable record was REMOVED on this path (even if no local reversal ran,
    // e.g. a generation mismatch), an owned-state mutation that must be persisted
    // so the removal outlives a crash and cannot reverse a released reservation.
    let (local_rollback_ran, had_caller_record_consumed) = match reservation {
        Some(prepared) => {
            let carrier_ran =
                crate::context::outlets_helpers::rollback_outlet_economy_generation_checked(
                    cell.class_c_view(),
                    deps,
                    prepared.reservation.generation,
                    prepared.reservation.ticket,
                )
                .await;
            // On a generation MISMATCH the carrier voided only the external
            // escrow and refused the confused-deputy LOCAL write (`carrier_ran ==
            // false`), so the rehydrated instance's LOCAL budget / velocity /
            // hard-rate-limit are STILL deducted. The durable record is the
            // source of truth for the caller reversal: fall through and reverse
            // the LOCAL economy from a CLONED copy of it via the gen-agnostic
            // record path (which idempotently re-voids the same escrow). On a
            // MATCH the carrier already reversed LOCAL — we only consume the
            // record, never re-reversing. Either way LOCAL is reversed exactly
            // once and the record is removed exactly once (the removal is the
            // combinator `f`'s Class-S mutation below).
            let record = cell.class_s.xctx_caller_reservations.get(saga_id).cloned();
            let local_ran = if carrier_ran {
                true
            } else if let Some(ref record) = record {
                crate::context::outlets_helpers::reverse_caller_reservation_record(
                    cell.class_c_view(),
                    deps,
                    record,
                )
                .await
            } else {
                // No record to reverse from (e.g. a generation-mismatch carrier
                // for a saga whose record was already drained). Nothing local ran.
                false
            };
            // A record present here WILL be consumed (removed) by the combinator
            // `f` below — its removal is an owned mutation that MUST be persisted
            // so a later spurious crash-abort cannot reverse an already-released
            // reservation from a stale record.
            (local_ran, record.is_some())
        }
        None => {
            // Crash-recovery abort: reverse from the durable record if present.
            // `reverse_caller_reservation_record` voids the external escrow AND
            // reverses the LOCAL economy UNCONDITIONALLY — there is no generation
            // gate (and a gate would be wrong: a fresh respawn stamps a new
            // generation that never matches the pre-crash record, so gating would
            // SKIP every real refund and over-charge the caller). Its safety
            // rests on the invariant that the record and the deductions it
            // reverses are rehydrated from ONE snapshot into the same
            // `context_id`-routed actor, keyed by `record.actor_did` + the
            // `SagaId` — not on a generation check. Returns whether the local
            // reversal ran (always `true` for a present record on this path). The
            // record is read via a Deref `get().cloned()` (NOT a remove) so the
            // async reverse can run BEFORE the single persist; the actual
            // Class-S removal is hoisted into the combinator `f` below.
            match cell.class_s.xctx_caller_reservations.get(saga_id).cloned() {
                Some(record) => {
                    let ran = crate::context::outlets_helpers::reverse_caller_reservation_record(
                        cell.class_c_view(),
                        deps,
                        &record,
                    )
                    .await;
                    (ran, true)
                }
                None => (false, false),
            }
        }
    };

    // TARGET side: whether a staged outlet-session slot is present (cleared below).
    // Peeked (not yet removed) so the no-mutation gate can decide BEFORE the
    // combinator; the actual clear is the combinator `f`'s Class-S mutation. A
    // missing slot is a clean no-op (the gate skips the combinator, and there is
    // nothing to remove).
    let had_slot = cell.class_s.saga_pending.contains_key(saga_id);

    // Persist if the caller-side owned economy was refunded (`local_rollback_ran`),
    // a durable caller record was consumed (`had_caller_record_consumed` — its
    // removal must outlive a crash so it cannot reverse a released reservation),
    // OR a target-side slot was cleared (`had_slot`): each is an owned-state
    // mutation whose loss on a crash-after-ack would corrupt durable state — an
    // unpersisted caller refund permanently over-charges (the deduction WAS
    // persisted at Prepare-A); a surviving stale record could double-reverse; an
    // unpersisted slot clear re-stages a stale saga on respawn. The ONLY
    // no-persist path is a caller Abort that touched nothing (generation-mismatch
    // with no record + no slot) or an idempotent already-terminal Abort — both
    // clean no-ops.
    if !local_rollback_ran && !had_caller_record_consumed && !had_slot {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    // Class-S sync-persist fail-closed before acking, KEEPING the in-memory
    // reversal/removals on a persist failure (the refunded economy + consumed
    // record + cleared slot stay applied — un-applying would re-open the
    // over-charge a respawn-from-durable already corrects). `commit_class_s_keep`
    // performs the BOTH Class-S removals (the caller-reservation record consumed
    // above is removed here, and the target-side staged slot is cleared) under
    // the SINGLE fail-closed persist that always covered them. On failure it
    // returns the persist error without restoring — byte-identical to the prior
    // inline persist-failure arm's `err_mutated`. Removing an absent key is a
    // no-op, so the unconditional removes are safe on every arm.
    if let Err(persist_err) = cell
        .commit_class_s_keep(deps, &context_hex, |mut view| {
            let class_s = view.class_s_mut();
            // Consume the durable caller-reservation record (no-op if absent — e.g. a
            // target-side abort or a gen-mismatch with no record).
            class_s.xctx_caller_reservations.remove(saga_id);
            // Clear the target-side staged outlet-session slot.
            class_s.saga_pending.remove(saga_id);
            Ok(())
        })
        .await
    {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

// ---------------------------------------------------------------------------
// EmitDivergenceMarker — either side (spec §6.2.4 "Dual event-log recording")
// ---------------------------------------------------------------------------

/// Emit a signed [`CrossContextDivergenceMarker`] into the LOCAL event log on a
/// `NeedsRepair` outcome (spec §6.2.4 "Dual event-log recording"). Runs on the
/// LOCAL actor; the emitting side's Active Signing Key is passed per-call (the
/// actor holds no key).
///
/// The marker records which side committed, the `SagaId`, the `nonce`, and the
/// committed-side event id — making a one-sided commit durably auditable rather
/// than a silent repudiation primitive. Class-S sync-persists fail-closed.
///
/// `committed_timestamp_secs` is the CONVERGENT committer-assigned leaf
/// timestamp — B's staged `recorded_timestamp_ms / 1000`, the same convergent
/// instant the committed-side `OutletInvoked` leaf carries (spec §6.2.4 *Recorded
/// timestamp*). The marker is a commit-ordered convergent durable leaf (ADR-011
/// Amendment §6 carve-out), so the timestamp MUST be this convergent value and
/// NOT an actor-local clock read, or two honest members would derive divergent
/// marker leaves (§9.9.3).
// `Send` discipline (ADR-049 Decision 7): the Class-S persist is now `.await`ed
// (async `ContextPersistence`), so this handler takes the ALREADY-BUILT owned
// `snapshot` and the `Copy` `context_id` — NOT a `&PerContextState`. A shared
// `&PerContextState` (`!Sync`, holds a `dyn FnMut` sink) held across the persist
// `.await` would make the actor future `!Send` and fail `tokio::spawn`. The
// caller builds the snapshot (holding its `&mut ClassSCell`) BEFORE calling this,
// then hands over the owned snapshot; the event-log append targets
// `deps.event_log` (independent of `state`), so building the snapshot first is
// behaviour-preserving.
#[allow(clippy::too_many_arguments)]
async fn emit_divergence_marker(
    context_id: [u8; 32],
    snapshot: crate::context::state::ContextSnapshot,
    deps: &ActorDeps,
    saga_id: &SagaId,
    nonce: [u8; 16],
    committed_side: CommittedSide,
    committed_event_id: &str,
    committed_timestamp_secs: u64,
    signing_key: &SigningKeyBytes,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_hex = hex_context_id(&context_id);

    let key = signing_key.to_signing_key();
    let marker = match CrossContextDivergenceMarker::sign(
        &key,
        CrossContextDivergenceMarkerFields {
            saga_id: saga_id.0.clone(),
            nonce,
            committed_side,
            committed_event_id: committed_event_id.to_owned(),
        },
    ) {
        Ok(m) => m,
        Err(e) => {
            let err = ContextError::CryptoFailed(format!(
                "SCP-SAGA-13036: divergence-marker signing failed for saga '{}': {e}",
                saga_id.0
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };

    // Serialize the signed marker as the event-leaf payload so an auditor can
    // verify it directly from the log entry. The `saga_id` provenance formerly
    // carried in the event-name string now rides INSIDE the payload — `saga_id`
    // is a signed field of the `CrossContextDivergenceMarker` — while the typed
    // `EventType::CrossContextDivergenceMarker` replaces the string name.
    let marker_payload_bytes = match serde_json::to_vec(&marker) {
        Ok(bytes) => bytes,
        Err(e) => {
            let err = ContextError::CryptoFailed(format!(
                "SCP-SAGA-13037: divergence-marker serialization failed for saga '{}': {e}",
                saga_id.0
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Outcome::err(sketch);
        }
    };
    if let Err(err) = deps
        .event_log
        .append_context_event_with_payload(
            &context_id,
            scp_event_log::EventType::CrossContextDivergenceMarker,
            scp_event_log::system_actors::SYSTEM_SAGA_ACTOR,
            scp_event_log::EventPayload {
                data: marker_payload_bytes,
            },
            committed_timestamp_secs,
        )
        .await
    {
        let sketch = outcome_error_sketch(&err);
        let _ = reply.send(Err(err));
        return Outcome::err(sketch);
    }

    // Class-S persist fail-closed: the divergence record is the durable
    // audit witness operator-repair relies on; it MUST land before acking. The
    // `snapshot` was built by the caller (from its `&mut ClassSCell`) before this
    // handler ran, so no `&PerContextState` is held across the persist `.await`.
    if let Err(persist_err) = persist_snapshot_fail_closed(&snapshot, deps, &context_hex).await {
        let sketch = outcome_error_sketch(&persist_err);
        let _ = reply.send(Err(persist_err));
        return Outcome::err_mutated(sketch);
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Lowercase-hex of `SHA-256(jcs(output))` — the verifiable link from the
/// caller's `CrossContextOutletInvoked` record to the receipt's `output_hash`
/// without journaling the (possibly large/sensitive) output (§6.2.4).
fn hex_output_hash(output_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(output_bytes).into();
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use scp_did::DID;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};
    use scp_protocol::context::ContextError;
    use scp_protocol::context::governance::KeyResolver;
    use scp_protocol::context::outlets::registry::{OutletRegistration, OutletSchema};
    use scp_protocol::context::roles::Capability;
    use scp_protocol::crypto::ucan::UcanToken;
    use tokio::sync::oneshot;

    use crate::crypto::ucan::mint::{MintParams, mint_ucan};

    use super::*;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::persistence::ContextPersistence;
    use crate::context::supervisor::saga_journal::SagaId;
    use crate::context::supervisor::supervisor::Supervisor;

    const CALLER: &str = "did:dht:z6MkCallerPrincipalXX";
    const OTHER: &str = "did:dht:z6MkOtherPrincipalXXX";
    const OUTLET: &str = "calculator-v1";

    /// Destructure a Prepare-A reply expecting a §6.2.4 POLICY reject. A policy
    /// reject rides `Ok(PrepareAOutcome::Rejected(SagaReject))` on the SUCCESS
    /// channel (NOT `Err`), so the structural `SCP-SAGA-13xxx` code can be read
    /// without parsing the message. Returns the [`SagaReject`] for the per-site
    /// `code` + `error` assertions.
    fn expect_prepare_a_reject(reply: Result<PrepareAOutcome, ContextError>) -> SagaReject {
        match reply.expect("a §6.2.4 Prepare-A policy reject replies Ok(Rejected), never Err") {
            PrepareAOutcome::Rejected(reject) => reject,
            PrepareAOutcome::Prepared(prepared) => {
                // Should never happen in a reject test. The carrier holds a
                // `#[must_use]` OutletEconomyTicket whose drop guard would panic
                // under `--features testing`; forget it so the assertion failure
                // (not a double-panic) is what surfaces.
                std::mem::forget(prepared);
                panic!("expected a §6.2.4 Prepare-A policy reject, got Prepared");
            }
        }
    }

    /// Destructure a Prepare-B reply expecting a §6.2.4 POLICY reject (the
    /// target-side sibling of [`expect_prepare_a_reject`]).
    fn expect_prepare_b_reject(reply: Result<PrepareBOutcome, ContextError>) -> SagaReject {
        match reply.expect("a §6.2.4 Prepare-B policy reject replies Ok(Rejected), never Err") {
            PrepareBOutcome::Rejected(reject) => reject,
            PrepareBOutcome::Prepared(prepared) => {
                panic!("expected a §6.2.4 Prepare-B policy reject, got Prepared: {prepared:?}")
            }
        }
    }

    /// Destructure a SUCCESSFUL Prepare-A reply, returning the staged
    /// [`PreparedAFields`] reservation carrier. `context` labels the call site.
    fn expect_prepared_a(
        reply: Result<PrepareAOutcome, ContextError>,
        context: &str,
    ) -> PreparedAFields {
        match reply
            .unwrap_or_else(|e| panic!("Prepare-A ({context}) must reply Ok, got Err: {e:?}"))
        {
            PrepareAOutcome::Prepared(prepared) => prepared,
            PrepareAOutcome::Rejected(reject) => {
                panic!("Prepare-A ({context}) must succeed, got reject {reject:?}")
            }
        }
    }

    /// Destructure a SUCCESSFUL Prepare-B reply, returning B's recorded
    /// [`PreparedBFields`] provenance.
    fn expect_prepared_b(
        reply: Result<PrepareBOutcome, ContextError>,
        context: &str,
    ) -> PreparedBFields {
        match reply
            .unwrap_or_else(|e| panic!("Prepare-B ({context}) must reply Ok, got Err: {e:?}"))
        {
            PrepareBOutcome::Prepared(prepared) => prepared,
            PrepareBOutcome::Rejected(reject) => {
                panic!("Prepare-B ({context}) must succeed, got reject {reject:?}")
            }
        }
    }

    /// Defense-in-depth (PER-INTERFACE bound only): the §6.2.4 per-target nonce
    /// dedup cache ([`PerContextState::xctx_nonce_dedup`]) should be bounded by
    /// its TTL (`SAGA_NONCE_DEDUP_TTL_SECS`), not by capacity eviction, for a
    /// SINGLE interface's replay guarantee to hold. The worst-case number of
    /// distinct nonces ONE interface can land within the TTL window is its
    /// configured inbound accept rate (`InboundPolicy::max_calls_per_minute`)
    /// scaled to the window. This test asserts that (a) the DEFAULT inbound
    /// ceiling and (b) the documented per-interface ceiling
    /// [`MAX_SAFE_INBOUND_CALLS_PER_MINUTE`] each leave a ≥2× margin under the
    /// shared cache capacity, so one in-budget interface can never fill the
    /// cache and evict its own still-within-TTL nonce.
    ///
    /// **This per-interface guard does NOT bound the AGGREGATE (honest scope).**
    /// `xctx_nonce_dedup` is a SINGLE per-context-B cache shared across ALL
    /// inbound interfaces, but `consume_inbound_interface_rate_limit` enforces
    /// `MAX_SAFE_INBOUND_CALLS_PER_MINUTE` PER INTERFACE. With ≥3 distinct
    /// interfaces each at the ceiling, their summed in-budget volume CAN exceed
    /// the cache capacity over the TTL window and evict a still-fresh nonce — so
    /// this test's invariant, and the per-interface guard, do NOT establish the
    /// aggregate replay bound. The aggregate replay bound rests instead on the
    /// channel-authenticated `caller_did` gate (spec §6.2.4 *Cache-eviction
    /// bound*, *Caller authentication*): a replayed `CrossContextOutletInvoke`
    /// must pass the supervisor's gate-1 `is_member`/`caller_did` check on the
    /// ATTACKER's OWN authenticated channel — a third party cannot present a
    /// victim's `caller_did`, and a caller replaying its own evicted invocation
    /// merely re-spends its own non-refundable budget. Eviction therefore yields
    /// no usable replay regardless of aggregate cache pressure. The per-interface
    /// guard asserted below is DEFENSE-IN-DEPTH layered under that channel-auth
    /// bound, not the aggregate bound itself. (No clean, cheap, NON-dynamic
    /// aggregate guard exists: a static cap on the number of inbound interfaces
    /// that actually preserved the cache margin would have to be 1 — arbitrary
    /// and over-restrictive — and a per-context aggregate-rate accountant would
    /// be exactly the dynamic mechanism the spec deliberately avoids in favor of
    /// the channel-auth argument.)
    #[test]
    fn nonce_dedup_replay_bound_holds() {
        use scp_protocol::context::outlets::interface::DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE;
        use scp_protocol::crypto::sender_keys::NONCE_DEDUP_CAPACITY;

        // The bound is computed against the SAGA dedup TTL — the cache this
        // invariant protects is `PerContextState::xctx_nonce_dedup`, which is
        // built with `SAGA_NONCE_DEDUP_TTL_SECS` (strictly longer than the
        // freshness skew tolerance, BLACK-XCTX-01), NOT the sender-key
        // `NONCE_EXPIRY_SECS`. A longer window admits more nonces, so the safe
        // per-minute ceiling is correspondingly lower.
        const {
            assert!(
                SAGA_NONCE_DEDUP_TTL_SECS > DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                "the saga dedup TTL must strictly exceed the freshness skew tolerance \
                 so an in-window envelope's nonce is always still remembered"
            );
        }

        // Distinct nonces a caller can land within one TTL window at a given
        // per-minute accept ceiling.
        let window_minutes = SAGA_NONCE_DEDUP_TTL_SECS / 60;
        assert_eq!(
            window_minutes, 10,
            "saga dedup TTL window is 10 minutes (600s)"
        );

        let capacity = NONCE_DEDUP_CAPACITY as u64;

        let worst_case_default = u64::from(DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE) * window_minutes;
        assert!(
            worst_case_default.saturating_mul(2) <= capacity,
            "default inbound ceiling ({DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE}/min ⇒ \
             {worst_case_default} nonces over the TTL) must leave a ≥2× margin under the \
             {capacity}-entry dedup capacity, else eviction (not TTL) bounds replay",
        );

        let worst_case_ceiling = MAX_SAFE_INBOUND_CALLS_PER_MINUTE * window_minutes;
        assert!(
            worst_case_ceiling.saturating_mul(2) <= capacity,
            "the documented inbound ceiling ({MAX_SAFE_INBOUND_CALLS_PER_MINUTE}/min ⇒ \
             {worst_case_ceiling} nonces over the TTL) must leave a ≥2× margin under the \
             {capacity}-entry dedup capacity; raise the cache capacity before raising this \
             ceiling",
        );
    }

    /// FIX 4 (test/prod TTL parity): the handler-test fixture
    /// (`new_for_test_*` → `new_for_test_with_mode`) MUST seed the PRODUCTION
    /// saga dedup TTL (`SAGA_NONCE_DEDUP_TTL_SECS`), not `NonceDedup::new()`'s
    /// default 300s (which equals the skew tolerance — the coterminous window the
    /// spec FORBIDS). Without this, handler tests would run a different
    /// anti-replay window than production. Also asserts the `debug_assert`
    /// helper the spawn / restore sites call accepts the fixture's cache.
    #[tokio::test]
    async fn test_fixture_seeds_production_saga_dedup_ttl() {
        let st = target_state(0x5B, OTHER, CALLER).await;
        assert_eq!(
            st.class_s.xctx_nonce_dedup.ttl_secs(),
            SAGA_NONCE_DEDUP_TTL_SECS,
            "the test fixture must seed the production saga dedup TTL, not NonceDedup::new()'s \
             default (which is coterminous with the skew tolerance)"
        );
    }

    // --- test event-log / persistence stubs -------------------------------

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
            _event_type: scp_event_log::EventType,
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
    }

    /// Persistence that accepts every write (success path).
    struct OkPersistence;
    /// Persistence whose `persist_context` ALWAYS fails (fail-closed path).
    struct FailPersistence;

    macro_rules! impl_persistence {
        ($ty:ty, $persist:expr) => {
            #[async_trait::async_trait]
            impl ContextPersistence for $ty {
                async fn persist_context(
                    &self,
                    _: &str,
                    _: &crate::context::state::ContextSnapshot,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    $persist
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
        };
    }
    impl_persistence!(OkPersistence, Ok(()));
    impl_persistence!(FailPersistence, Err("induced persist failure".into()));

    /// Event log that COUNTS typed `OutletInvoked` appends — used to assert a
    /// Commit-B persist-retry produces EXACTLY ONE `OutletInvoked` (FIX 3).
    struct CountingEventLog {
        outlet_invoked_appends: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for CountingEventLog {
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
            if event_type == scp_event_log::EventType::OutletInvoked {
                self.outlet_invoked_appends
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
    }

    /// Persistence that FAILS its first `persist_context` call, then SUCCEEDS —
    /// drives the Commit-B persist-failure-then-retry path (FIX 3).
    struct FailFirstPersistence {
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait::async_trait]
    impl ContextPersistence for FailFirstPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Err("induced first-persist failure".into())
            } else {
                Ok(())
            }
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

    /// Persistence that SUCCEEDS every call EXCEPT the `fail_at` (0-based) call,
    /// which FAILS — drives the Commit-A witness-persist-failure path: Prepare-A's
    /// own persists (reserve + Prepare-A tail) succeed, then the Commit-A
    /// idempotency-witness persist fails, proving the `CrossContextOutletInvoked`
    /// append is sequenced AFTER (and gated on) that persist.
    struct FailNthPersistence {
        calls: std::sync::atomic::AtomicUsize,
        fail_at: usize,
    }
    #[async_trait::async_trait]
    impl ContextPersistence for FailNthPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == self.fail_at {
                Err("induced nth-persist failure".into())
            } else {
                Ok(())
            }
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

    /// Event log that COUNTS typed `CrossContextOutletInvoked` appends (the
    /// A-side record) — used to assert a Commit-A whose witness-persist FAILS
    /// appends NO `CrossContextOutletInvoked` orphan (the append is gated behind
    /// the successful witness persist).
    struct CrossContextCountingEventLog {
        xctx_invoked_appends: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for CrossContextCountingEventLog {
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
            if event_type == scp_event_log::EventType::CrossContextOutletInvoked {
                self.xctx_invoked_appends
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
    }

    /// Persistence SPY: accepts every write but records the number of
    /// `persist_context` calls through a shared counter, so a test can assert a
    /// handler actually performed its Class-S persist (FIX 1: the caller-side
    /// abort refund MUST durably land). The counter is `Arc`-shared so the test
    /// reads it after the spy has been boxed into `ActorDeps`.
    struct SpyPersistence {
        persist_calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl ContextPersistence for SpyPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persist_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

    // --- deps + state fixtures --------------------------------------------

    /// Build an `ActorDeps` whose `key_resolver` resolves `issuer_did` to
    /// `issuer_key` and whose persistence is `persistence`.
    async fn build_deps(
        issuer_did: String,
        issuer_key: ed25519_dalek::VerifyingKey,
        persistence: Box<dyn ContextPersistence>,
    ) -> ActorDeps {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestSagaActor".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
            if did.as_ref() == issuer_did {
                Some(issuer_key)
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
            .build_actor_deps(&DID("did:example:saga-test-owner".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// Like [`build_deps`] but with caller-supplied event-log + persistence
    /// providers, so a test can observe event-log appends and drive a
    /// fail-once persistence (FIX 3 Commit-B persist-retry).
    async fn build_deps_with_providers(
        issuer_did: String,
        issuer_key: ed25519_dalek::VerifyingKey,
        event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
        persistence: Box<dyn ContextPersistence>,
    ) -> ActorDeps {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestSagaActor".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
            if did.as_ref() == issuer_did {
                Some(issuer_key)
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
            .build_actor_deps(&DID("did:example:saga-test-owner".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// An encrypted state whose `context_id == [ctx_byte; 32]`, with `member`
    /// holding `OutletInterface`, `creator_did = creator`, and a registered outlet
    /// `OUTLET` with a 2-field input schema (passes the specificity floor).
    async fn target_state(ctx_byte: u8, creator: &str, member: &str) -> PerContextState {
        let mut st = PerContextState::new_for_test_encrypted(
            [ctx_byte; 32],
            1_700_000_000,
            DID(creator.to_owned()),
        );
        st.handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("active");
        // creator_did binds the UCAN root issuer (validate_ucan step 4).
        st.role_state.creator_did = creator.to_owned();
        // Grant the caller OutletInterface + OutletCallAll so both the outbound
        // capability gate and the ceiling (outlet_call:*) admit the proof.
        st.role_state.members.insert(member.to_owned());
        let mut caps = HashSet::new();
        caps.insert(Capability::OutletInterface);
        caps.insert(Capability::OutletCallAll);
        st.role_state
            .member_capabilities
            .insert(member.to_owned(), caps);
        st.role_state
            .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new([
                Capability::OutletInterface,
                Capability::OutletCallAll,
            ]))
            .expect("well-formed built-in ceiling");
        st.governance.registered_outlets.push(OutletRegistration {
            outlet_id: OUTLET.to_owned(),
            kind: scp_protocol::context::outlets::OutletKind::default(),
            name: "Calculator".to_owned(),
            description: "adds".to_owned(),
            schema: OutletSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "a": {"type": "number"}, "b": {"type": "number"} }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "result": {"type": "number"} }
                }),
                aggregate_schema: None,
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: DID(creator.to_owned()),
            cost: None,
            message_catalog: Vec::new(),
            registered_at: 0,
            signature: Vec::new(),
        });
        st
    }

    /// Mint a UCAN with `outlet_call:OUTLET` capability, issued by `creator`
    /// (the context creator = root issuer) to `audience`, scoped to the hex
    /// of `[ctx_byte; 32]`. Returns the issuer pubkey + the token.
    async fn mint_outlet_ucan(
        ctx_byte: u8,
        creator_did: &str,
        creator_key: &scp_platform::traits::KeyHandle,
        custody: &InMemoryKeyCustody,
        audience: &str,
    ) -> UcanToken {
        let ctx_hex = hex_context_id(&[ctx_byte; 32]);
        let caps = vec![format!("outlet_call:{OUTLET}")];
        let params = MintParams {
            issuer_did: creator_did,
            issuer_key: creator_key,
            audience_did: audience,
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
        mint_ucan(&params, custody, &scp_clock::SystemClock)
            .await
            .expect("mint")
    }

    fn valid_input() -> serde_json::Value {
        serde_json::json!({ "a": 1, "b": 2 })
    }

    fn prepare_b_request(
        ctx_byte: u8,
        ucan_proof_id: Option<String>,
        asserted_chain_depth: u8,
        now_ms: u64,
    ) -> PrepareBRequest {
        prepare_b_request_with_role(ctx_byte, ucan_proof_id, asserted_chain_depth, now_ms, None)
    }

    fn prepare_b_request_with_role(
        ctx_byte: u8,
        ucan_proof_id: Option<String>,
        asserted_chain_depth: u8,
        now_ms: u64,
        caller_source_role: Option<String>,
    ) -> PrepareBRequest {
        PrepareBRequest {
            saga_id: SagaId("saga-xctx-1".to_owned()),
            caller_context_id: [0x99; 32],
            target_context_id: [ctx_byte; 32],
            caller_did: DID(CALLER.to_owned()),
            outlet_registration_id: OUTLET.to_owned(),
            ucan_proof_id,
            input: valid_input(),
            asserted_chain_depth,
            asserted_nonce: [0x42; 16],
            asserted_timestamp_ms: now_ms,
            caller_source_role,
        }
    }

    // --- Prepare-A tests --------------------------------------------------

    #[tokio::test]
    async fn prepare_a_accepts_stages_and_persists() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        // Prepare-A runs on the CALLER context; the caller is a member here.
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-accepts".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        assert!(out.result.is_ok(), "prepare_a outcome: {:?}", out.result);
        let prepared = expect_prepared_a(rx.await.unwrap(), "prepared-A");
        // The reservation handle is the Send carrier the FSM holds; the FSM
        // settles it on Commit-A or releases it on a terminal non-commit path.
        // This test stands in for that terminal release (RAII contract,
        // §6.2.4 "Reservation release on every terminal path") by rolling the
        // reservation back — dropping a live OutletEconomyTicket is a balance-
        // invariant violation by design.
        crate::context::outlets_helpers::rollback_outlet_economy(
            st_cell.class_c_view(),
            &deps,
            prepared.reservation.ticket,
        )
        .await;
    }

    #[tokio::test]
    async fn prepare_a_rejects_caller_without_outlet_interface() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        // Strip the OutletInterface capability.
        st.role_state
            .member_capabilities
            .insert(CALLER.to_owned(), HashSet::new());
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-no-iface".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let reject = expect_prepare_a_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13010));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13010"))
        );
    }

    #[tokio::test]
    async fn prepare_a_rejects_caller_not_in_allowed_callers() {
        use scp_protocol::context::outlets::interface::{OutboundPolicy, OutletInterface};
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        // Establish an interface whose allowed_callers excludes the caller.
        st.governance.outlet_interfaces.push(OutletInterface {
            source_context: hex_context_id(&[0x11; 32]),
            target_context: hex_context_id(&[0x22; 32]),
            outlet_id: OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: Some(OutboundPolicy {
                allowed_callers: vec![DID(OTHER.to_owned())],
                ..OutboundPolicy::default()
            }),
            inbound_policy: None,
        });
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-not-allowed".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let reject = expect_prepare_a_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13011));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13011"))
        );
    }

    #[tokio::test]
    async fn prepare_a_fail_closed_persist_returns_err_without_applying() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-failclose".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
    }

    /// FIX C (escrow reserves the REGISTERED cost, never a caller-asserted one).
    /// `prepare_a` no longer takes any caller-supplied cost — the escrow amount
    /// is derived entirely by `reserve_outlet_economy` from the context's own
    /// economic policy. With the default (no policy ⇒ free) policy the reserve
    /// deducts NOTHING from the caller's budget, proving no caller-asserted
    /// positive cost can leak into the reservation. The compile-time absence of
    /// a cost parameter on `prepare_a` is the structural half of this guard.
    #[tokio::test]
    async fn prepare_a_escrow_uses_registered_cost_not_caller_value() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        // No economic policy is configured ⇒ the REGISTERED cost is 0; the
        // reserve must deduct exactly the registered (policy-derived) amount.
        let budget_before = st
            .governance
            .budget_tracker
            .remaining(&DID(CALLER.to_owned()))
            .0;
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-cost".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        assert!(out.result.is_ok(), "prepare_a outcome: {:?}", out.result);
        let prepared = expect_prepared_a(rx.await.unwrap(), "prepared-A");

        // The registered cost is 0, so the budget is untouched — no
        // caller-asserted positive cost was reserved.
        let budget_after = st_cell
            .governance
            .budget_tracker
            .remaining(&DID(CALLER.to_owned()))
            .0;
        assert_eq!(
            budget_before, budget_after,
            "the escrow reservation must reserve the REGISTERED (policy-derived) cost — \
             with no policy that is 0, so the budget must be untouched"
        );

        crate::context::outlets_helpers::rollback_outlet_economy(
            st_cell.class_c_view(),
            &deps,
            prepared.reservation.ticket,
        )
        .await;
    }

    /// FIX B.1 (§6.2.0.2 per-interface sliding-window budget consumed at
    /// initiation, non-refundable). An interface whose per-interface `rate_limit`
    /// is already exhausted (max_calls = 0) rejects Prepare-A with a typed
    /// `RateLimited` (SCP-SAGA-13023) BEFORE the escrow reserve runs — the
    /// initiation-consumes-budget gate.
    #[tokio::test]
    async fn prepare_a_rejects_when_per_interface_rate_budget_exhausted() {
        use scp_protocol::context::outlets::interface::{OutletInterface, RateLimit};
        use std::time::Duration;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // A per-interface §6.2.0.2 window with ZERO budget (no calls, no burst)
        // is already exhausted, so the consume rejects at initiation.
        let zero_budget = RateLimit::with_burst(
            0,
            Duration::from_mins(1),
            0,
            Duration::from_secs(1),
            deps.clock.as_ref(),
        );
        st.governance.outlet_interfaces.push(OutletInterface {
            source_context: hex_context_id(&[0x11; 32]),
            target_context: hex_context_id(&[0x22; 32]),
            outlet_id: OUTLET.to_owned(),
            rate_limit: Some(zero_budget),
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        });

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-iface-rl".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let reject = expect_prepare_a_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13023));
        assert!(
            matches!(&reject.error, ContextError::RateLimited { message, .. } if message.contains("SCP-SAGA-13023")),
            "expected per-interface §6.2.0.2 RateLimited (SCP-SAGA-13023), got {:?}",
            reject.error
        );
    }

    /// FIX B.1 — per-CALLER §6.2.0.2 window. An interface whose per-caller window
    /// is exhausted (max_calls_per_caller = 0) rejects Prepare-A with
    /// `RateLimited` (SCP-SAGA-13024), independent of the per-interface window.
    #[tokio::test]
    async fn prepare_a_rejects_when_per_caller_rate_budget_exhausted() {
        use scp_protocol::context::outlets::interface::{OutletInterface, PerCallerRateLimit};
        use std::time::Duration;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x11, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let zero_caller_budget =
            PerCallerRateLimit::with_burst(0, Duration::from_mins(1), 0, Duration::from_secs(1));
        st.governance.outlet_interfaces.push(OutletInterface {
            source_context: hex_context_id(&[0x11; 32]),
            target_context: hex_context_id(&[0x22; 32]),
            outlet_id: OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: Some(zero_caller_budget),
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        });

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("prep-a-caller-rl".to_owned()),
            &[0x11; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let reject = expect_prepare_a_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13024));
        assert!(
            matches!(&reject.error, ContextError::RateLimited { message, .. } if message.contains("SCP-SAGA-13024")),
            "expected per-caller §6.2.0.2 RateLimited (SCP-SAGA-13024), got {:?}",
            reject.error
        );
    }

    // --- Prepare-B tests --------------------------------------------------

    #[tokio::test]
    async fn prepare_b_accepts_stages_all_eight_b_recorded_fields() {
        let custody = InMemoryKeyCustody::new();
        let creator_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let creator_pk = custody.public_key(&creator_handle).await.unwrap();
        let creator_did = format!("did:dht:z{}", zbase32::encode(creator_pk.as_bytes()));
        let creator_verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(creator_pk.as_bytes().try_into().unwrap())
                .unwrap();

        let mut st = target_state(0x33, &creator_did, CALLER).await;
        // The proof is delegated to the CALLER (correct principal).
        let token = mint_outlet_ucan(0x33, &creator_did, &creator_handle, &custody, CALLER).await;
        st.xctx_ucan_proofs
            .proofs
            .insert("proof-1".to_owned(), token);
        let deps = build_deps(creator_did, creator_verifying_key, Box::new(OkPersistence)).await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x33, Some("proof-1".to_owned()), 2, now_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_b(&mut st_cell, &deps, req, tx).await;
        assert!(out.result.is_ok(), "prepare_b: {:?}", out.result);
        let fields = expect_prepared_b(rx.await.unwrap(), "prepared-B");

        // B re-derived chain depth = incoming(2) + 1.
        assert_eq!(fields.recorded_chain_depth, 3);
        // B staged its copy of the wire nonce.
        assert_eq!(fields.recorded_nonce, [0x42; 16]);
        // recorded_timestamp_ms is B's own clock (NOT the caller-asserted ts).
        assert!(fields.recorded_timestamp_ms >= now_ms);

        // The eight-field prepared was staged into saga_pending with B-recorded
        // provenance, NOT the caller-asserted advisory depth.
        let staged = st_cell
            .class_s
            .saga_pending
            .get(&SagaId("saga-xctx-1".to_owned()))
            .unwrap();
        let SagaPreparedState::CrossContextOutletInvocation(p) = staged else {
            panic!("expected the unary cross-context outlet-invocation variant");
        };
        assert_eq!(p.target_context_id, [0x33; 32]);
        assert_eq!(p.caller_did, DID(CALLER.to_owned()));
        assert_eq!(p.outlet_registration_id, OUTLET);
        assert_eq!(p.ucan_proof_id, "proof-1");
        assert_eq!(p.recorded_chain_depth, 3);
        assert_eq!(p.recorded_nonce, [0x42; 16]);
    }

    /// FIX B.2 (`InboundPolicy.allowed_source_roles` enforced at Prepare-B). An
    /// ungated outlet whose interface restricts `allowed_source_roles` to a set
    /// that does NOT contain the channel-authenticated caller's role rejects
    /// with SCP-SAGA-13025 and stages nothing — the role is evaluated against
    /// the supervisor-resolved `caller_source_role`, never an envelope value.
    #[tokio::test]
    async fn prepare_b_rejects_caller_role_not_in_allowed_source_roles() {
        use scp_protocol::context::outlets::interface::{InboundPolicy, OutletInterface};
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // Ungated outlet (no UCAN proof) on the TARGET context 0x55.
        let mut st = target_state(0x55, OTHER, CALLER).await;
        st.governance.outlet_interfaces.push(OutletInterface {
            source_context: hex_context_id(&[0x99; 32]),
            target_context: hex_context_id(&[0x55; 32]),
            outlet_id: OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: Some(InboundPolicy {
                allowed_source_roles: vec!["admin".to_owned()],
                ..InboundPolicy::default()
            }),
        });
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        // The channel-authenticated caller role is "member", NOT in {admin}.
        let req = prepare_b_request_with_role(0x55, None, 2, now_ms, Some("member".to_owned()));
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_b(&mut st_cell, &deps, req, tx).await;
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13025));
        assert!(
            matches!(&reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13025")),
            "expected allowed_source_roles rejection (SCP-SAGA-13025), got {:?}",
            reject.error
        );
        // Nothing was staged.
        assert!(
            !st_cell
                .class_s
                .saga_pending
                .contains_key(&SagaId("saga-xctx-1".to_owned())),
            "a rejected Prepare-B must not stage a prepared slot"
        );
    }

    /// FIX B.2 — the allow path: a caller whose channel-authenticated role IS in
    /// `allowed_source_roles` is admitted (the inbound gate does not over-block).
    #[tokio::test]
    async fn prepare_b_accepts_caller_role_in_allowed_source_roles() {
        use scp_protocol::context::outlets::interface::{InboundPolicy, OutletInterface};
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x56, OTHER, CALLER).await;
        st.governance.outlet_interfaces.push(OutletInterface {
            source_context: hex_context_id(&[0x99; 32]),
            target_context: hex_context_id(&[0x56; 32]),
            outlet_id: OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: Some(InboundPolicy {
                allowed_source_roles: vec!["member".to_owned(), "admin".to_owned()],
                ..InboundPolicy::default()
            }),
        });
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let req = prepare_b_request_with_role(0x56, None, 2, now_ms, Some("member".to_owned()));
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_b(&mut st_cell, &deps, req, tx).await;
        assert!(out.result.is_ok(), "prepare_b: {:?}", out.result);
        expect_prepared_b(rx.await.unwrap(), "an allowed role must be admitted");
    }

    /// Push a `OUTLET` interface with the given inbound `max_calls_per_minute`
    /// onto `st` (target context `ctx_byte`), approved both sides — the fixture
    /// for the inbound-rate consume tests.
    fn push_inbound_interface(st: &mut PerContextState, ctx_byte: u8, inbound_per_min: u32) {
        use scp_protocol::context::outlets::interface::{InboundPolicy, OutletInterface};
        st.governance.outlet_interfaces.push(OutletInterface {
            source_context: hex_context_id(&[0x99; 32]),
            target_context: hex_context_id(&[ctx_byte; 32]),
            outlet_id: OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: Some(InboundPolicy {
                max_calls_per_minute: inbound_per_min,
                ..InboundPolicy::default()
            }),
        });
    }

    /// FIX 3 (B-side inbound rate enforced). Prepare-B consumes B's OWN INBOUND
    /// §6.2.0.2 sliding window; once it is exhausted the consume rejects with a
    /// typed `SCP-SAGA-13026`. The window is materialized lazily from
    /// `InboundPolicy.max_calls_per_minute` and the consume is non-refundable.
    #[tokio::test]
    async fn prepare_b_inbound_rate_limit_rejects_when_exhausted() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x57, OTHER, CALLER).await;
        // Inbound ceiling 1/min: base allows 1 call, then up to the default
        // burst allowance (5) within the burst window, then rejects.
        push_inbound_interface(&mut st, 0x57, 1);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // The consume takes the field-granular `ClassCMut`; wrap the test state
        // in a `ClassSCell` to construct the view per call.
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        // Drain the base + burst budget (1 base + 5 burst = 6 admitted).
        for i in 0..6 {
            consume_inbound_interface_rate_limit(st_cell.class_c_view(), &deps, OUTLET)
                .unwrap_or_else(|e| panic!("call {i} within budget must be admitted: {e:?}"));
        }
        // The next consume exhausts the window ⇒ typed SCP-SAGA-13026.
        let reject = consume_inbound_interface_rate_limit(st_cell.class_c_view(), &deps, OUTLET)
            .expect_err("inbound window exhausted must reject");
        assert_eq!(reject.code, Some(13026));
        assert!(
            matches!(&reject.error, ContextError::RateLimited { message, .. } if message.contains("SCP-SAGA-13026")),
            "expected inbound-rate rejection (SCP-SAGA-13026), got {:?}",
            reject.error
        );
    }

    /// FIX 3 (cache-eviction config guard, runtime — NOT cfg(test)). An interface
    /// whose configured inbound rate exceeds the eviction-safe ceiling
    /// (`MAX_SAFE_INBOUND_CALLS_PER_MINUTE`) is REJECTED at Prepare-B with a typed
    /// `SCP-SAGA-13027` BEFORE the window is materialized — a high inbound ceiling
    /// (e.g. the §6.2.0.2-permitted 6000/min) must not erode the §6.2.4 replay
    /// bound. This is the runtime config guard the spec requires, not merely the
    /// `nonce_dedup_replay_bound_holds` cfg(test) invariant.
    #[tokio::test]
    async fn prepare_b_inbound_rate_above_eviction_ceiling_is_rejected() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x58, OTHER, CALLER).await;
        // 6000/min is §6.2.0.2-permissible but far above the eviction-safe
        // ceiling (500/min) — its TTL-window volume would approach the dedup
        // capacity and erode the replay bound.
        let over_ceiling = u32::try_from(MAX_SAFE_INBOUND_CALLS_PER_MINUTE + 1).unwrap();
        push_inbound_interface(&mut st, 0x58, over_ceiling);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let reject = consume_inbound_interface_rate_limit(st_cell.class_c_view(), &deps, OUTLET)
            .expect_err("an inbound ceiling above the eviction-safe limit must reject");
        assert_eq!(reject.code, Some(13027));
        assert!(
            matches!(&reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13027")),
            "expected cache-eviction config-guard rejection (SCP-SAGA-13027), got {:?}",
            reject.error
        );
        // The guard fires BEFORE materializing the window — nothing was created.
        let iface = st_cell
            .governance
            .outlet_interfaces
            .iter()
            .find(|i| i.outlet_id == OUTLET)
            .expect("interface present");
        assert!(
            iface.inbound_rate_limit.is_none(),
            "the config guard must reject BEFORE materializing the inbound window"
        );
    }

    /// FIX 3 (boundary): an inbound rate EXACTLY at the eviction-safe ceiling is
    /// admitted (the guard rejects only ABOVE it), confirming the guard does not
    /// over-block the maximum safe configuration.
    #[tokio::test]
    async fn prepare_b_inbound_rate_at_eviction_ceiling_is_admitted() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x59, OTHER, CALLER).await;
        let at_ceiling = u32::try_from(MAX_SAFE_INBOUND_CALLS_PER_MINUTE).unwrap();
        push_inbound_interface(&mut st, 0x59, at_ceiling);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        consume_inbound_interface_rate_limit(st_cell.class_c_view(), &deps, OUTLET)
            .expect("the maximum safe inbound ceiling must be admitted");
    }

    /// FIX 3 (end-to-end): an accepted Prepare-B over an interface with a
    /// (safe) inbound policy materializes B's inbound window and consumes one
    /// unit — proving the consume is wired into the Prepare-B path, not just the
    /// standalone helper.
    #[tokio::test]
    async fn prepare_b_through_path_materializes_and_consumes_inbound_window() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x5A, OTHER, CALLER).await;
        // Ungated outlet with a safe inbound ceiling.
        push_inbound_interface(&mut st, 0x5A, 60);
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let req = prepare_b_request_with_role(0x5A, None, 2, now_ms, Some("member".to_owned()));
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_b(&mut st_cell, &deps, req, tx).await;
        assert!(out.result.is_ok(), "prepare_b: {:?}", out.result);
        expect_prepared_b(rx.await.unwrap(), "prepared-B");

        // The inbound window was materialized and one unit consumed.
        let iface = st_cell
            .governance
            .outlet_interfaces
            .iter()
            .find(|i| i.outlet_id == OUTLET)
            .expect("interface present");
        let window = iface
            .inbound_rate_limit
            .as_ref()
            .expect("Prepare-B materialized B's inbound window");
        assert_eq!(
            window.current_count, 1,
            "Prepare-B consumed exactly one inbound unit"
        );
    }

    #[tokio::test]
    async fn prepare_b_confused_deputy_audience_mismatch_is_rejected() {
        // The UCAN is VALID and grants outlet_call:OUTLET — but it is delegated to
        // a DIFFERENT principal (OTHER) than the carried caller_did (CALLER). A
        // confused-deputy attempt: the carried caller references a stronger
        // proof in B's store delegated to someone else. MUST be rejected.
        let custody = InMemoryKeyCustody::new();
        let creator_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let creator_pk = custody.public_key(&creator_handle).await.unwrap();
        let creator_did = format!("did:dht:z{}", zbase32::encode(creator_pk.as_bytes()));
        let creator_verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(creator_pk.as_bytes().try_into().unwrap())
                .unwrap();

        let mut st = target_state(0x44, &creator_did, CALLER).await;
        // Proof audience = OTHER, NOT the carried caller_did (CALLER).
        let token = mint_outlet_ucan(0x44, &creator_did, &creator_handle, &custody, OTHER).await;
        st.xctx_ucan_proofs
            .proofs
            .insert("proof-other".to_owned(), token);
        let deps = build_deps(creator_did, creator_verifying_key, Box::new(OkPersistence)).await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x44, Some("proof-other".to_owned()), 1, now_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_b(&mut st_cell, &deps, req, tx).await;
        assert!(
            out.result.is_err(),
            "confused-deputy proof must be rejected"
        );
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13013));
        assert!(
            matches!(&reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13013")),
            "expected SCP-SAGA-13013 confused-deputy rejection, got {:?}",
            reject.error
        );
        // Nothing staged — the slot stays empty on rejection.
        assert!(st_cell.class_s.saga_pending.is_empty());
    }

    #[tokio::test]
    async fn prepare_b_rejects_stale_timestamp() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0x55, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // 1 hour in the past — far outside the §9.14 5-minute skew.
        let stale_ms = now_ms.saturating_sub(60 * 60 * 1000);

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x55, None, 1, stale_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_b(&mut st_cell, &deps, req, tx).await;
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13018));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13018"))
        );
    }

    #[tokio::test]
    async fn prepare_b_rejects_duplicate_nonce() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x66, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // Pre-seed the dedup cache with the request nonce.
        st.class_s
            .xctx_nonce_dedup
            .record([0x42; 16], deps.clock.now_secs());

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x66, None, 1, now_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_b(&mut st_cell, &deps, req, tx).await;
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13019));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13019"))
        );
    }

    /// FIX 4 (BLACK-624-01): the nonce-dedup replay protection SURVIVES a crash.
    /// A `CrossContextOutletInvoke` whose nonce was accepted, then the actor
    /// crashes and restores from its snapshot, then the SAME envelope is
    /// re-submitted under a FRESH `SagaId`, MUST be rejected by the rehydrated
    /// nonce-dedup cache. Before this fix the cache reinitialized EMPTY on
    /// restore, so a crash inside the 5-minute TTL re-opened the replay.
    ///
    /// We accept a nonce via `prepare_b`, project the live state to a snapshot
    /// (the Class-S persistence path), simulate restore by rehydrating a FRESH
    /// state's nonce-dedup from that snapshot (mirroring `restore_context`), then
    /// re-submit the same nonce under a new `SagaId` — it is rejected.
    #[tokio::test]
    async fn nonce_dedup_survives_crash_and_blocks_fresh_saga_replay() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0x6A, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let now_secs = deps.clock.now_secs();

        // Accept the envelope under its original SagaId — records the nonce.
        let replay_nonce = [0x42u8; 16];
        let mut first = prepare_b_request(0x6A, None, 2, now_ms);
        first.saga_id = SagaId("original-saga".to_owned());
        first.asserted_nonce = replay_nonce;
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_b(&mut st_cell, &deps, first, tx).await;
        assert!(out.result.is_ok(), "first prepare_b: {:?}", out.result);
        expect_prepared_b(rx.await.unwrap(), "first prepare_b accepts");
        assert!(
            st_cell
                .class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&replay_nonce),
            "the accepted nonce was recorded"
        );

        // Project the live state to its Class-S snapshot — the persisted form a
        // restore rehydrates from. The nonce-dedup cache must be carried.
        let snapshot = crate::context::messaging_helpers::build_snapshot_from_state(&st_cell);
        assert!(
            snapshot.xctx_nonce_dedup.contains_key(&replay_nonce),
            "the nonce-dedup cache MUST be in the Class-S snapshot (crash-surviving)"
        );

        // Simulate restore: a FRESH actor state whose nonce-dedup is rehydrated
        // from the snapshot (mirrors `restore_context`'s
        // `NonceDedup::from_entries_with_ttl` — the saga dedup TTL, strictly
        // longer than the freshness skew tolerance, is preserved on restore).
        let mut restored = target_state(0x6A, OTHER, CALLER).await;
        restored.class_s.xctx_nonce_dedup =
            scp_protocol::crypto::sender_keys::NonceDedup::from_entries_with_ttl(
                snapshot.xctx_nonce_dedup,
                SAGA_NONCE_DEDUP_TTL_SECS,
            );

        // Re-submit the SAME envelope under a FRESH SagaId after the "crash".
        let mut replay = prepare_b_request(0x6A, None, 2, now_ms);
        replay.saga_id = SagaId("fresh-replay-saga".to_owned());
        replay.asserted_nonce = replay_nonce;
        let _ = now_secs; // freshness uses the clock; nonce dedup is the gate here.
        let (tx, rx) = oneshot::channel();
        let mut restored_cell = crate::context::actor::class_s::ClassSCell::new(restored);
        let out = prepare_b(&mut restored_cell, &deps, replay, tx).await;
        assert!(out.result.is_err(), "fresh-SagaId replay must be rejected");
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13019));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13019")),
            "the rehydrated nonce-dedup cache MUST reject the cross-crash fresh-SagaId replay"
        );
    }

    /// SAME-NODE RESTORE: the caller-side durable reservation record Prepare-A
    /// stages survives a crash. We project the live state to its Class-S snapshot
    /// (through the shared `xctx_caller_reservations_snapshot` helper) and
    /// rehydrate a FRESH actor state from that snapshot (mirroring
    /// `restore_context`), asserting the record lands in the restored
    /// `xctx_caller_reservations` value-stable — so the crash-recovery abort can
    /// reverse the caller deduction + void the escrow from it without the
    /// in-memory carrier.
    #[tokio::test]
    async fn caller_reservation_record_survives_same_node_restore() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0x6B, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        let saga = SagaId("saga-same-node-restore".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(&mut st_cell, &deps, &saga, &[0x6B; 32], &caller, OUTLET, tx).await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");
        let staged = st_cell
            .class_s
            .xctx_caller_reservations
            .get(&saga)
            .expect("Prepare-A staged the durable record")
            .clone();

        // This test exercises only the DURABLE record's restore path, not the
        // carrier; release the in-memory ticket explicitly so its RAII
        // must-settle-or-rollback guard stays quiet (a real crash would drop it,
        // and the §17.16.4 abort reverses from the durable record instead).
        prepared_a
            .reservation
            .ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;

        // Project the live state to its Class-S snapshot — the persisted form a
        // restore rehydrates from. The record MUST be carried (through the shared
        // snapshot helper).
        let snapshot = crate::context::messaging_helpers::build_snapshot_from_state(&st_cell);
        assert_eq!(
            snapshot.xctx_caller_reservations.get(&saga),
            Some(&staged),
            "the caller-reservation record MUST be in the Class-S snapshot (crash-surviving)"
        );

        // Simulate same-node restore: a FRESH actor state whose
        // `xctx_caller_reservations` is rehydrated from the snapshot (mirrors
        // `restore_context`, which assigns `ctx_snapshot.xctx_caller_reservations`
        // directly — caller economy is local, so same-node restore rehydrates it
        // verbatim).
        let mut restored = target_state(0x6B, OTHER, CALLER).await;
        restored.class_s.xctx_caller_reservations = snapshot.xctx_caller_reservations.clone();

        assert_eq!(
            restored.class_s.xctx_caller_reservations.get(&saga),
            Some(&staged),
            "the restored state MUST rehydrate the caller-reservation record value-stable"
        );
    }

    #[tokio::test]
    async fn prepare_b_rejects_chain_depth_overflow() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0x77, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // Default max_chain_depth is 8; incoming 8 → 8+1 = 9 > 8 ⇒ reject.
        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x77, None, 8, now_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_b(&mut st_cell, &deps, req, tx).await;
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13020));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13020"))
        );
    }

    #[tokio::test]
    async fn prepare_b_rejects_target_context_mismatch() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0x88, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        // Build a request whose target_context_id is a DIFFERENT context.
        let mut req = prepare_b_request(0x88, None, 1, now_ms);
        req.target_context_id = [0xEE; 32];

        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_b(&mut st_cell, &deps, req, tx).await;
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13014));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13014"))
        );
    }

    #[tokio::test]
    async fn prepare_b_rejects_degenerate_broad_input_schema() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0x99, OTHER, CALLER).await;
        // Replace the registered outlet's schemas with degenerate broad ones
        // (zero declared fields on both sides ⇒ below the specificity floor).
        if let Some(reg) = st
            .governance
            .registered_outlets
            .iter_mut()
            .find(|t| t.outlet_id == OUTLET)
        {
            reg.schema.input_schema = serde_json::json!({ "type": "object" });
            reg.schema.output_schema = serde_json::json!({ "type": "object" });
        }
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        let req = prepare_b_request(0x99, None, 1, now_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let _ = prepare_b(&mut st_cell, &deps, req, tx).await;
        let reject = expect_prepare_b_reject(rx.await.unwrap());
        assert_eq!(reject.code, Some(13017));
        assert!(
            matches!(reject.error, ContextError::PermissionDenied(m) if m.contains("SCP-SAGA-13017"))
        );
    }

    #[tokio::test]
    async fn prepare_b_fail_closed_persist_returns_err() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xAA, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();

        let (tx, rx) = oneshot::channel();
        // Ungated outlet (no proof) so every other check passes and we reach the
        // Class-S persist, which fails.
        let req = prepare_b_request(0xAA, None, 1, now_ms);
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_b(&mut st_cell, &deps, req, tx).await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
        // The staged slot was rolled back on persist failure.
        assert!(st_cell.class_s.saga_pending.is_empty());
    }

    // --- Commit-B / Commit-A / Abort tests --------------------------------

    /// A target signing key wrapped for the per-call receipt-signing argument.
    fn signing_key_bytes(seed: u8) -> SigningKeyBytes {
        SigningKeyBytes::from_signing_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    /// Build a valid JCS-serialized `CrossContextOutletReceipt` for Commit-A
    /// tests. Commit-A re-reads the convergent leaf timestamp from the forwarded
    /// receipt (spec §6.2.4 *Recorded timestamp*), so a Commit-A test must pass a
    /// well-formed receipt rather than a stub blob. `timestamp_ms` is B's staged
    /// `recorded_timestamp_ms`; the leaf the handler appends carries
    /// `timestamp_ms / 1000`.
    fn test_receipt_bytes(timestamp_ms: u64) -> Vec<u8> {
        let target_key = ed25519_dalek::SigningKey::from_bytes(&[0x5A; 32]);
        let receipt = CrossContextOutletReceipt::sign(
            &target_key,
            CrossContextOutletReceiptFields {
                caller_context_id: [0xC4; 32],
                target_context_id: [0xEE; 32],
                caller_did: CALLER.to_owned(),
                nonce: [0x42; 16],
                outlet_registration_id: OUTLET.to_owned(),
                output_jcs: br#"{"result":1}"#.to_vec(),
                outlet_invoked_event_id: "OutletInvoked:saga-commit-a-1".to_owned(),
                chain_depth: 3,
                timestamp_ms,
            },
        )
        .expect("sign test receipt");
        jcs_receipt_bytes(&receipt).expect("serialize test receipt")
    }

    /// Stage a Prepare-B slot for `saga_id` by running the real `prepare_b`
    /// (ungated outlet) so Commit-B has the B-recorded provenance to sign over.
    async fn stage_prepared_b(
        cell: &mut crate::context::actor::class_s::ClassSCell,
        deps: &ActorDeps,
        ctx_byte: u8,
        saga_id: &str,
        now_ms: u64,
    ) {
        let mut req = prepare_b_request(ctx_byte, None, 2, now_ms);
        req.saga_id = SagaId(saga_id.to_owned());
        let (tx, rx) = oneshot::channel();
        let out = prepare_b(cell, deps, req, tx).await;
        assert!(out.result.is_ok(), "stage prepare_b: {:?}", out.result);
        expect_prepared_b(rx.await.unwrap(), "prepared-B staged");
    }

    #[tokio::test]
    async fn commit_b_reserve_then_settle_stages_output_appends_and_signs() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC1, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-commit-b-1".to_owned());
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        stage_prepared_b(&mut st_cell, &deps, 0xC1, &saga.0, now_ms).await;

        // Reserve: slot present, not yet committed ⇒ ReadyToExecute.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_reserve(&st_cell, &saga, tx);
        assert!(out.result.is_ok());
        assert!(matches!(
            rx.await.unwrap().expect("reserve"),
            CommitBReserveOutcome::ReadyToExecute
        ));

        // Settle: capture output, append OutletInvoked, sign a verifiable receipt.
        let target_key = signing_key_bytes(0x55);
        let output = br#"{"result":42}"#.to_vec();
        let (tx, rx) = oneshot::channel();
        let out =
            commit_b_settle(&mut st_cell, &deps, &saga, output.clone(), &target_key, tx).await;
        assert!(out.result.is_ok(), "settle: {:?}", out.result);
        let settled = rx.await.unwrap().expect("settled");

        // The receipt verifies against the target's signing key.
        let receipt: CrossContextOutletReceipt =
            serde_json::from_slice(&settled.receipt).expect("receipt json");
        receipt
            .verify(&target_key.to_signing_key().verifying_key())
            .expect("receipt verifies against target signing key");
        // The receipt is signed over B's STAGED provenance: re-derived depth 3
        // (incoming 2 + 1) and the staged wire nonce.
        assert_eq!(receipt.chain_depth, 3);
        assert_eq!(receipt.nonce, [0x42; 16]);
        assert_eq!(
            receipt.outlet_invoked_event_id,
            settled.outlet_invoked_event_id
        );
        // The output was captured durably and the staged slot cleared.
        assert!(st_cell.class_s.xctx_committed_outputs.contains_key(&saga));
        assert!(st_cell.class_s.saga_pending.is_empty());
    }

    #[tokio::test]
    async fn commit_b_settle_replay_re_emits_identical_receipt_without_re_append() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC2, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-commit-b-replay".to_owned());
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        stage_prepared_b(&mut st_cell, &deps, 0xC2, &saga.0, now_ms).await;

        let target_key = signing_key_bytes(0x66);
        let output = br#"{"result":7}"#.to_vec();

        let (tx, rx) = oneshot::channel();
        commit_b_settle(&mut st_cell, &deps, &saga, output.clone(), &target_key, tx).await;
        let first = rx.await.unwrap().expect("first settle");
        // Capture the durable event id; a replay must reproduce it.
        let captured_event_id = st_cell
            .class_s
            .xctx_committed_outputs
            .get(&saga)
            .unwrap()
            .outlet_invoked_event_id
            .clone();

        // Replay: a DIFFERENT output + a DIFFERENT key would re-sign divergently
        // if the outlet were re-invoked — but the replay re-emits the STORED
        // capture, so the receipt + event id are byte-for-byte identical.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(
            &mut st_cell,
            &deps,
            &saga,
            br#"{"result":999}"#.to_vec(),
            &signing_key_bytes(0x77),
            tx,
        )
        .await;
        assert!(out.result.is_ok());
        let replay = rx.await.unwrap().expect("replay settle");

        assert_eq!(
            first.receipt, replay.receipt,
            "receipt must be identical on replay"
        );
        assert_eq!(
            first.output_bytes, replay.output_bytes,
            "stored output re-emitted"
        );
        assert_eq!(replay.outlet_invoked_event_id, captured_event_id);
        // Reserve on a committed saga short-circuits to AlreadyCommitted.
        let (tx, rx) = oneshot::channel();
        commit_b_reserve(&st_cell, &saga, tx);
        assert!(matches!(
            rx.await.unwrap().expect("reserve replay"),
            CommitBReserveOutcome::AlreadyCommitted { .. }
        ));
    }

    #[tokio::test]
    async fn commit_b_settle_canonicalizes_output_so_receipt_self_verifies() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC3, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-commit-b-jcs".to_owned());
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        stage_prepared_b(&mut st_cell, &deps, 0xC3, &saga.0, now_ms).await;

        let target_key = signing_key_bytes(0x88);
        // Non-canonical (pretty-printed, reordered keys) output — the handler
        // re-canonicalizes so the receipt's output_jcs is the hashed preimage.
        let output = br#"{ "b": 2, "a": 1 }"#.to_vec();
        let (tx, rx) = oneshot::channel();
        commit_b_settle(&mut st_cell, &deps, &saga, output, &target_key, tx).await;
        let settled = rx.await.unwrap().expect("settled");
        let receipt: CrossContextOutletReceipt =
            serde_json::from_slice(&settled.receipt).expect("receipt json");
        // Self-verifying: output_hash recomputes from the carried JCS bytes.
        receipt
            .verify(&target_key.to_signing_key().verifying_key())
            .expect("self-verifying receipt");
        assert_eq!(receipt.output_jcs, br#"{"a":1,"b":2}"#.to_vec());
    }

    #[tokio::test]
    async fn commit_a_settles_escrow_and_appends_invoked_idempotently() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // Prepare-A runs on the CALLER context.
        let mut st = target_state(0xC4, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // Stage Prepare-A to obtain the held reservation (FSM carries it). The
        // saga id is shared across Prepare-A / Commit-A so the durable
        // reservation record staged at Prepare-A is the one Commit-A consumes.
        let saga = SagaId("saga-commit-a-1".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(
            &mut st_cell,
            &deps,
            &saga,
            &[0xC4; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");

        let nonce = [0x42; 16];
        let req = CommitARequest {
            saga_id: saga.clone(),
            reservation: prepared_a,
            caller_context_id: [0xC4; 32],
            caller_did: DID(CALLER.to_owned()),
            target_context_id: [0xEE; 32],
            nonce,
            receipt: test_receipt_bytes(1_700_000_000_000),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st_cell, &deps, req, tx).await;
        assert!(out.result.is_ok(), "commit_a: {:?}", out.result);
        rx.await.unwrap().expect("commit-a ack");
        // The committed A-side saga is the idempotency witness.
        assert!(st_cell.class_s.xctx_committed_invocations.contains(&saga));

        // Replay: a fresh reservation handed back is released (RAII); re-ack
        // without re-settling (the witness short-circuits).
        let (tx2, rx2) = oneshot::channel();
        prepare_a(
            &mut st_cell,
            &deps,
            &saga,
            &[0xC4; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx2,
        )
        .await;
        let replay_reservation = expect_prepared_a(rx2.await.unwrap(), "prepared-A replay");
        let replay_req = CommitARequest {
            saga_id: saga.clone(),
            reservation: replay_reservation,
            caller_context_id: [0xC4; 32],
            caller_did: DID(CALLER.to_owned()),
            target_context_id: [0xEE; 32],
            nonce,
            receipt: test_receipt_bytes(1_700_000_000_000),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st_cell, &deps, replay_req, tx).await;
        assert!(out.result.is_ok());
        rx.await.unwrap().expect("commit-a replay ack");
    }

    /// Provenance-integrity (regression): a Commit-A whose idempotency-witness
    /// Class-S persist FAILS must NOT durably append the A-side
    /// `CrossContextOutletInvoked` record. The append is sequenced AFTER (and gated
    /// on) the witness persist — mirroring `commit_b_first_settle` — so a persist
    /// failure leaves NO orphan A-side "the call happened" record that B's log
    /// denies (the silent one-sided A-record / reverse-direction repudiation
    /// primitive the append-before-persist inverse produced). The handler returns
    /// `Err`/`mutated` (the escrow settle ran) and the witness is not left set, so
    /// the FSM retry re-acks from the absent witness and resolves correctly.
    #[tokio::test]
    async fn commit_a_witness_persist_failure_appends_no_invoked_orphan() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // Prepare-A runs on the CALLER context.
        let mut st = target_state(0xC7, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();

        // Stage Prepare-A with an Ok persistence to obtain the held reservation
        // (the FSM carries it) — the reserve + Prepare-A tail persists must
        // succeed so the reservation lands.
        let stage_deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let saga = SagaId("saga-commit-a-witness-failclose".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(
            &mut st_cell,
            &stage_deps,
            &saga,
            &[0xC7; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");

        // Commit-A deps: a counting event log (observes the A-side append) + a
        // persistence whose FIRST call (the Commit-A witness persist) FAILS. The
        // escrow capture itself performs no payment (test deps carry no payment
        // adapter), so the only persist Commit-A drives is the witness persist.
        let xctx_invoked_appends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let commit_deps = build_deps_with_providers(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(CrossContextCountingEventLog {
                xctx_invoked_appends: Arc::clone(&xctx_invoked_appends),
            }),
            Box::new(FailNthPersistence {
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail_at: 0,
            }),
        )
        .await;

        let req = CommitARequest {
            saga_id: saga.clone(),
            reservation: prepared_a,
            caller_context_id: [0xC7; 32],
            caller_did: DID(CALLER.to_owned()),
            target_context_id: [0xEE; 32],
            nonce: [0x42; 16],
            receipt: test_receipt_bytes(1_700_000_000_000),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st_cell, &commit_deps, req, tx).await;

        // The witness persist failed: the handler returns Err and reports
        // `mutated` (the escrow settle ran before the failed persist).
        assert!(out.result.is_err(), "witness persist must fail-close");
        assert!(
            out.mutated,
            "the escrow settle mutated owned economy ⇒ mutated"
        );
        let err = rx
            .await
            .unwrap()
            .expect_err("commit-a must fail-close on witness persist");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));

        // No orphan A-side record: the `CrossContextOutletInvoked` append is gated
        // behind the (failed) witness persist, so it NEVER ran.
        assert_eq!(
            xctx_invoked_appends.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a witness-persist failure must NOT append CrossContextOutletInvoked \
             (append is sequenced after the witness persist)"
        );
        // The witness is not left set — a retry re-acks from the absent witness.
        assert!(
            !st_cell.class_s.xctx_committed_invocations.contains(&saga),
            "the rolled-back witness must not survive a persist failure"
        );
    }

    #[tokio::test]
    async fn abort_b_side_releases_session_by_clearing_slot() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC5, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = deps.clock.now_millis();
        let saga = SagaId("saga-abort-b".to_owned());
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        stage_prepared_b(&mut st_cell, &deps, 0xC5, &saga.0, now_ms).await;
        assert!(!st_cell.class_s.saga_pending.is_empty());

        // Abort on the B side (no reservation): clears the staged slot.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok(), "abort: {:?}", out.result);
        rx.await.unwrap().expect("abort ack");
        assert!(st_cell.class_s.saga_pending.is_empty());

        // Idempotent: a second abort on the now-terminal saga is a clean no-op.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok());
        rx.await.unwrap().expect("abort idempotent ack");
    }

    #[tokio::test]
    async fn abort_a_side_releases_escrow_reservation() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xC6, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // The caller starts with a finite budget; reserve, then abort releases it.
        // The saga id is shared across Prepare-A / abort so the abort consumes
        // the durable reservation record Prepare-A staged.
        let saga = SagaId("saga-abort-a".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(
            &mut st_cell,
            &deps,
            &saga,
            &[0xC6; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");

        // No staged slot on A (B stages the slot); abort releases the held
        // escrow/rate-limit reservation via the rollback path and acks.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, Some(prepared_a), tx).await;
        assert!(out.result.is_ok(), "abort-a: {:?}", out.result);
        rx.await.unwrap().expect("abort-a ack");
    }

    /// FIX 1 (regression): a CALLER-side abort that refunds the held economy
    /// reservation MUST Class-S PERSIST that refund — Prepare-A durably
    /// persisted the matching DEDUCTION, so without a refund persist a
    /// crash-after-ack loses the in-memory refund while the deduction survives,
    /// permanently over-charging the caller (the saga is Aborted, nothing
    /// re-drives it). Prepare-A never stages a `saga_pending` slot on the caller
    /// (only Prepare-B does), so the old `had_slot`-gated persist short-circuited
    /// to `Outcome::ok(())` with NO persist on this exact path. This drives the
    /// abort through a PERSISTENCE SPY and asserts (a) `persist_context` was
    /// invoked, and (b) the hard-rate-limit token + velocity the reserve consumed
    /// are durably restored. The existing `abort_a_side_releases_escrow_reservation`
    /// uses `OkPersistence` and asserts only the ack — it cannot catch this.
    #[tokio::test]
    async fn abort_a_side_persists_caller_refund() {
        use std::sync::atomic::Ordering;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xC8, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let persist_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(SpyPersistence {
                persist_calls: Arc::clone(&persist_calls),
            }),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        // Shared across Prepare-A / abort so the abort consumes the durable
        // reservation record Prepare-A staged.
        let saga = SagaId("saga-abort-a-persist".to_owned());
        // The token-bucket burst capacity, in the limiter's internal milli-token
        // units (1000 milli-tokens per token) — a fresh caller starts FULL and a
        // reserve drains exactly one token; a refund restores it.
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;
        // Observe pre-reserve velocity for `caller`.
        let now_secs = deps.clock.now_secs();
        let velocity_before = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);

        // Prepare-A consumes a hard-rate-limit token + records velocity (and
        // persists the deduction once via the spy).
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(&mut st_cell, &deps, &saga, &[0xC8; 32], &caller, OUTLET, tx).await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");

        // Reserve actually moved owned economy state (else the test proves
        // nothing): the hard-rate-limit token bucket dropped exactly one token
        // below full burst, and velocity rose.
        let hrl_after_reserve = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry for the caller");
        assert!(
            hrl_after_reserve < burst_milli,
            "reserve must have consumed a hard-rate-limit token \
             (burst_milli={burst_milli}, after_reserve={hrl_after_reserve})"
        );
        let velocity_after_reserve = st_cell
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);
        assert!(
            velocity_after_reserve > velocity_before,
            "reserve must have recorded velocity \
             (before={velocity_before}, after_reserve={velocity_after_reserve})"
        );

        // Reset the persist counter so we measure ONLY the abort's persist.
        persist_calls.store(0, Ordering::SeqCst);

        // Caller-side abort (no staged slot — Prepare-A stages none). The refund
        // runs against MATCHING generation, so it mutates owned economy state
        // and MUST persist.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, Some(prepared_a), tx).await;
        assert!(out.result.is_ok(), "abort-a: {:?}", out.result);
        assert!(out.mutated, "the abort refunded owned state ⇒ mutated");
        rx.await.unwrap().expect("abort-a ack");

        // (a) the refund was Class-S persisted — the core regression assertion.
        assert!(
            persist_calls.load(Ordering::SeqCst) >= 1,
            "caller-side abort MUST persist the refunded economy (Prepare-A persisted the \
             matching deduction; skipping this persist permanently over-charges the caller \
             on a crash-after-ack)"
        );

        // (b) the refund durably restored the consumed hard-rate-limit token
        // (back to full burst) and rolled the velocity back to its pre-reserve
        // value.
        let hrl_after_abort = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry present after abort");
        assert_eq!(
            hrl_after_abort, burst_milli,
            "abort must refund the consumed hard-rate-limit token (restore to full burst)"
        );
        assert!(
            hrl_after_abort > hrl_after_reserve,
            "the abort refund restored a token the reserve had consumed \
             (after_reserve={hrl_after_reserve}, after_abort={hrl_after_abort})"
        );
        let velocity_after_abort = st_cell
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);
        assert_eq!(
            velocity_after_abort, velocity_before,
            "abort must roll back the recorded velocity"
        );
    }

    /// FIX 2 (confused-deputy): the abort handler rolls back the held
    /// reservation through the GENERATION-CHECKED path. If the actor was
    /// despawned+respawned (generation bumped) between Prepare-A and an
    /// in-flight Abort, the rollback MUST NOT refund velocity/budget/rate-limit
    /// against the new instance's owned state — it voids only the external
    /// escrow and consumes the ticket (no panic). A MATCHING generation rolls
    /// back locally as before.
    #[tokio::test]
    async fn rollback_generation_checked_voids_external_not_local_on_mismatch() {
        use crate::context::outlets_helpers::rollback_outlet_economy_generation_checked;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xD1, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        // Reservation made at the live generation (0).
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("genmismatch-1".to_owned()),
            &[0xD1; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let prepared_match = expect_prepared_a(rx.await.unwrap(), "prepared-A (match)");
        let gen_match = prepared_match.reservation.generation;
        assert_eq!(
            gen_match, st_cell.generation,
            "reservation made at live generation"
        );

        // Generations MATCH ⇒ local rollback runs.
        let ran_local = rollback_outlet_economy_generation_checked(
            st_cell.class_c_view(),
            &deps,
            prepared_match.reservation.generation,
            prepared_match.reservation.ticket,
        )
        .await;
        assert!(ran_local, "matching generation must run the local rollback");

        // A second reservation, then SIMULATE a despawn+respawn by bumping the
        // live generation. The reservation now carries the STALE generation.
        let (tx, rx) = oneshot::channel();
        prepare_a(
            &mut st_cell,
            &deps,
            &SagaId("genmismatch-2".to_owned()),
            &[0xD1; 32],
            &DID(CALLER.to_owned()),
            OUTLET,
            tx,
        )
        .await;
        let prepared_stale = expect_prepared_a(rx.await.unwrap(), "prepared-A (stale)");
        let stale_gen = prepared_stale.reservation.generation;
        st_cell.set_generation_for_test(st_cell.generation.wrapping_add(1));
        assert_ne!(
            stale_gen, st_cell.generation,
            "the respawn bumped the live generation past the reservation's"
        );

        // Generations MISMATCH ⇒ external-only (local untouched), ticket consumed
        // (no unbalanced-drop panic). Routing through the saga `abort` handler
        // would call `rollback_outlet_economy` directly without this guard.
        let ran_local = rollback_outlet_economy_generation_checked(
            st_cell.class_c_view(),
            &deps,
            stale_gen,
            prepared_stale.reservation.ticket,
        )
        .await;
        assert!(
            !ran_local,
            "a generation mismatch must NOT run the local rollback (confused-deputy guard)"
        );
        // Reaching here without a Drop panic ⇒ the ticket was consumed on the
        // external-only path.
    }

    /// HIGH 1 (gen-mismatch `Abort { Some }` record fallthrough): a CALLER-side
    /// `Abort { Some(reservation) }` whose carrier generation MISMATCHES the live
    /// instance — a watchdog respawn-FROM-OWN-SNAPSHOT between Prepare-A and the
    /// abort rehydrated the deduction + durable record under a fresh generation
    /// while the supervisor still holds the OLD-generation carrier — MUST still
    /// reverse the caller's LOCAL economy. The generation-checked carrier
    /// rollback correctly refuses the confused-deputy LOCAL write (voiding only
    /// the external escrow), so the handler MUST FALL THROUGH to reverse the
    /// rehydrated LOCAL economy from the still-present durable record before
    /// consuming it.
    ///
    /// PRE-FIX this path voided only the escrow and removed the record
    /// UNCONDITIONALLY — the LOCAL deduction stayed forever (a durable
    /// over-charge) and the only repair record was destroyed. This test bumps the
    /// live generation so the carrier mismatches and asserts the hard-rate-limit
    /// token + velocity ARE reversed (and the refund persisted). It FAILS against
    /// the pre-fix code (no local reversal) and PASSES once the fallthrough lands.
    #[tokio::test]
    async fn abort_a_side_gen_mismatch_reverses_local_from_record() {
        use std::sync::atomic::Ordering;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xD2, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let persist_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(SpyPersistence {
                persist_calls: Arc::clone(&persist_calls),
            }),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;
        let now_secs = deps.clock.now_secs();
        let velocity_before = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);

        let saga = SagaId("saga-abort-stale-gen".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(&mut st_cell, &deps, &saga, &[0xD2; 32], &caller, OUTLET, tx).await;
        let prepared = expect_prepared_a(rx.await.unwrap(), "prepared-A");
        // Prepare-A staged the durable record + moved owned economy.
        assert!(
            st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "Prepare-A must stage a durable caller-reservation record"
        );
        let hrl_after_reserve = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            hrl_after_reserve < burst_milli,
            "reserve must have consumed a hard-rate-limit token"
        );
        assert!(
            st_cell
                .governance
                .velocity_tracker
                .get_velocity(&caller, now_secs)
                > velocity_before,
            "reserve must have recorded velocity"
        );

        // Simulate the respawn-from-own-snapshot: bump the live generation past
        // the carrier's so the generation-checked carrier rollback refuses the
        // LOCAL write. The deduction + record are the rehydrated owned state.
        st_cell.set_generation_for_test(st_cell.generation.wrapping_add(1));

        // Measure ONLY the abort's persist.
        persist_calls.store(0, Ordering::SeqCst);

        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, Some(prepared), tx).await;
        assert!(out.result.is_ok(), "abort with stale gen: {:?}", out.result);
        assert!(
            out.mutated,
            "reversing LOCAL from the record on the mismatch path mutates owned state ⇒ mutated"
        );
        rx.await.unwrap().expect("abort ack");

        // The record was consumed.
        assert!(
            !st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "the durable record must be consumed on the mismatch abort"
        );
        // The refund was Class-S persisted (Prepare-A persisted the deduction;
        // skipping this persist permanently over-charges on a crash-after-ack).
        assert!(
            persist_calls.load(Ordering::SeqCst) >= 1,
            "the gen-mismatch abort MUST persist the record-driven refund"
        );
        // CORE: the LOCAL economy IS reversed from the record — hard-rate-limit
        // back to full burst, velocity rolled back. PRE-FIX these stay deducted.
        let hrl_after_abort = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry present after abort");
        assert_eq!(
            hrl_after_abort, burst_milli,
            "the gen-mismatch abort must refund the hard-rate-limit token from the record \
             (full burst) — NOT leave the caller over-charged"
        );
        assert_eq!(
            st_cell
                .governance
                .velocity_tracker
                .get_velocity(&caller, now_secs),
            velocity_before,
            "the gen-mismatch abort must roll back the recorded velocity from the record"
        );
    }

    #[tokio::test]
    async fn emit_divergence_marker_appends_verifiable_marker() {
        use scp_protocol::context::outlets::cross_context_saga::CrossContextDivergenceMarker;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC7, OTHER, CALLER).await;
        let deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let signing = signing_key_bytes(0x99);
        let saga = SagaId("saga-divergence".to_owned());
        let (tx, rx) = oneshot::channel();
        let ctx_hex = hex_context_id(&st.context_id);
        let snap = build_snapshot_for_persist(&st, &deps, &ctx_hex);
        let out = emit_divergence_marker(
            st.context_id,
            snap,
            &deps,
            &saga,
            [0xAB; 16],
            CommittedSide::Target,
            "evt-committed-9",
            // Convergent committer-assigned leaf timestamp (B's staged
            // recorded_timestamp_ms / 1000); fixed here so the test is
            // deterministic.
            1_700_000_000,
            &signing,
            tx,
        )
        .await;
        assert!(out.result.is_ok(), "emit: {:?}", out.result);
        rx.await.unwrap().expect("emit ack");

        // The marker the handler signed verifies against the emitting key.
        let marker = CrossContextDivergenceMarker::sign(
            &signing.to_signing_key(),
            CrossContextDivergenceMarkerFields {
                saga_id: saga.0.clone(),
                nonce: [0xAB; 16],
                committed_side: CommittedSide::Target,
                committed_event_id: "evt-committed-9".to_owned(),
            },
        )
        .expect("marker");
        marker
            .verify(&signing.to_signing_key().verifying_key())
            .expect("marker verifies");
    }

    #[tokio::test]
    async fn commit_b_reserve_without_staged_slot_is_rejected() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC8, OTHER, CALLER).await;
        // `commit_b_reserve` is a sync, deps-less read-only check.
        let _deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let out = commit_b_reserve(&st, &SagaId("never-prepared".to_owned()), tx);
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("must reject");
        assert!(matches!(err, ContextError::InvalidState(m) if m.contains("SCP-SAGA-13030")));
    }

    #[tokio::test]
    async fn commit_b_settle_fail_closed_rolls_back_capture() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xC9, OTHER, CALLER).await;
        // Stage with a passing persistence, then swap to a failing one for settle.
        let ok_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = ok_deps.clock.now_millis();
        let saga = SagaId("saga-settle-failclose".to_owned());
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        stage_prepared_b(&mut st_cell, &ok_deps, 0xC9, &saga.0, now_ms).await;

        let fail_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(
            &mut st_cell,
            &fail_deps,
            &saga,
            br#"{"result":1}"#.to_vec(),
            &signing_key_bytes(0xAA),
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
        // The capture was rolled back; the staged slot restored for a retry.
        assert!(!st_cell.class_s.xctx_committed_outputs.contains_key(&saga));
        assert!(st_cell.class_s.saga_pending.contains_key(&saga));
    }

    /// FIX 3 (provenance-integrity): a Commit-B persist FAILURE followed by a
    /// successful RETRY appends EXACTLY ONE `OutletInvoked`. The `OutletInvoked`
    /// event-log append (a separate, non-idempotent provider) is sequenced AFTER
    /// the durable capture + Class-S persist succeed, so a persist failure leaves
    /// no orphan log entry to double-append on retry.
    #[tokio::test]
    async fn commit_b_persist_retry_appends_outlet_invoked_exactly_once() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = target_state(0xCD, OTHER, CALLER).await;
        let saga = SagaId("saga-persist-retry-once".to_owned());

        // Stage Prepare-B with an Ok persistence + a throwaway event log (the
        // stage append is a `Prepared`-class event, not `OutletInvoked`).
        let stage_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;
        let now_ms = stage_deps.clock.now_millis();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        stage_prepared_b(&mut st_cell, &stage_deps, 0xCD, &saga.0, now_ms).await;

        // Settle deps: a counting event log + a persistence that FAILS the first
        // call then succeeds. Both providers live behind the same shared counter.
        let outlet_invoked_appends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let settle_deps = build_deps_with_providers(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(CountingEventLog {
                outlet_invoked_appends: Arc::clone(&outlet_invoked_appends),
            }),
            Box::new(FailFirstPersistence {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        )
        .await;
        let output = br#"{"result":7}"#.to_vec();
        let signing = signing_key_bytes(0xAA);

        // FIRST settle: the persist fails BEFORE the append — capture rolled back,
        // staged slot restored, and (FIX 3) NO `OutletInvoked` appended.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(
            &mut st_cell,
            &settle_deps,
            &saga,
            output.clone(),
            &signing,
            tx,
        )
        .await;
        assert!(
            out.result.is_err(),
            "first settle must fail-close on persist"
        );
        let err = rx.await.unwrap().expect_err("first settle persist failure");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));
        assert_eq!(
            outlet_invoked_appends.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a persist failure must NOT append OutletInvoked (append is sequenced after persist)"
        );
        assert!(!st_cell.class_s.xctx_committed_outputs.contains_key(&saga));
        assert!(st_cell.class_s.saga_pending.contains_key(&saga));

        // RETRY settle on the SAME deps (the persistence now succeeds): capture
        // lands, persist succeeds, and `OutletInvoked` appends EXACTLY ONCE.
        let (tx, rx) = oneshot::channel();
        let out = commit_b_settle(&mut st_cell, &settle_deps, &saga, output, &signing, tx).await;
        assert!(
            out.result.is_ok(),
            "retry settle must succeed: {:?}",
            out.result
        );
        rx.await.unwrap().expect("retry settle ack");
        assert_eq!(
            outlet_invoked_appends.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a persist-failure-then-retry Commit-B must append OutletInvoked EXACTLY ONCE"
        );
        assert!(st_cell.class_s.xctx_committed_outputs.contains_key(&saga));
        assert!(!st_cell.class_s.saga_pending.contains_key(&saga));
    }

    /// FIX 6 (simplifier): a Commit-B settle persist-failure rollback RE-INSERTS
    /// the OWNED ORIGINAL staged slot verbatim — no lossy reconstruction. The
    /// deleted `reprepare_from_receipt` rebuilt the slot from the receipt and
    /// DROPPED `ucan_proof_id` (the receipt does not carry it), so a gated outlet's
    /// restored slot lost its proof index. This stages a slot with a non-empty
    /// `ucan_proof_id`, fails the settle persist, and asserts the restored slot
    /// preserves the proof index byte-for-byte.
    #[tokio::test]
    async fn commit_b_settle_persist_failure_restores_full_original_slot() {
        use crate::context::supervisor::saga_prepared_state::{
            CrossContextOutletInvocationPrepared, SagaPreparedState,
        };

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut st = target_state(0xCB, OTHER, CALLER).await;
        let saga = SagaId("saga-settle-restore-full".to_owned());

        // Stage a slot DIRECTLY with a non-empty `ucan_proof_id` (a gated outlet's
        // proof index) — the field the lossy inverse used to drop.
        let original = CrossContextOutletInvocationPrepared {
            caller_context_id: [0xCC; 32],
            target_context_id: [0xCB; 32],
            caller_did: DID(CALLER.to_owned()),
            outlet_registration_id: OUTLET.to_owned(),
            ucan_proof_id: "gated-proof-index-42".to_owned(),
            recorded_timestamp_ms: 1_700_000_000_000,
            recorded_nonce: [0x42; 16],
            recorded_chain_depth: 3,
        };
        st.class_s.saga_pending.insert(
            saga.clone(),
            SagaPreparedState::CrossContextOutletInvocation(original),
        );

        // Settle with a FAILING persistence: the capture rolls back and the slot
        // is re-inserted.
        let fail_deps = build_deps(
            OTHER.to_owned(),
            issuer.verifying_key(),
            Box::new(FailPersistence),
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = commit_b_settle(
            &mut st_cell,
            &fail_deps,
            &saga,
            br#"{"result":5}"#.to_vec(),
            &signing_key_bytes(0xBB),
            tx,
        )
        .await;
        assert!(out.result.is_err());
        let err = rx.await.unwrap().expect_err("persist must fail-close");
        assert!(matches!(err, ContextError::PersistenceFailed(_)));

        // The restored slot preserves the FULL original — including the
        // `ucan_proof_id` the deleted lossy inverse would have dropped.
        let restored = st_cell
            .class_s
            .saga_pending
            .get(&saga)
            .expect("slot restored");
        let SagaPreparedState::CrossContextOutletInvocation(p) = restored else {
            panic!("expected the unary cross-context outlet-invocation variant");
        };
        assert_eq!(
            p.ucan_proof_id, "gated-proof-index-42",
            "the restored slot must preserve ucan_proof_id (no lossy reconstruction)"
        );
        assert_eq!(p.recorded_nonce, [0x42; 16]);
        assert_eq!(p.recorded_chain_depth, 3);
        assert!(!st_cell.class_s.xctx_committed_outputs.contains_key(&saga));
    }

    // -----------------------------------------------------------------------
    // Durable caller-reservation record (spec §6.2.4 "Reservation release on
    // every terminal path") — the PreparingB-crash over-charge / escrow-leak fix.
    // -----------------------------------------------------------------------

    /// Build deps carrying a payment adapter (the default `build_deps` passes
    /// `None`), so a reversal that voids the external escrow can be observed.
    async fn build_deps_with_payment(
        issuer_did: String,
        issuer_key: ed25519_dalek::VerifyingKey,
        payment_adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    ) -> ActorDeps {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestSagaActor".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: KeyResolver = Arc::new(move |did: &DID, _| {
            if did.as_ref() == issuer_did {
                Some(issuer_key)
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
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(Box::new(OkPersistence)),
            Some(payment_adapter),
            None,
            None,
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID("did:example:saga-test-owner".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// CRASH-RECOVERY REFUND (the HIGH finding): a `PreparingB`-window crash
    /// drives the §17.16.4 recovery sweep's CLEAN abort — `Abort { None }` — to
    /// the caller actor. With no in-memory carrier, the reversal MUST come from
    /// the durable `xctx_caller_reservations` record Prepare-A staged: the
    /// caller's velocity + hard-rate-limit (the currently-reachable durable
    /// deductions) MUST be reversed. Before the fix this path no-op'd, durably
    /// over-charging the caller. Asserts the durable refund actually moved owned
    /// state — not merely that the abort acked.
    ///
    /// CRITICAL — this drives a REAL crash-recovery generation bump. A real
    /// §17.16.4 restore rehydrates the snapshot into a freshly spawned actor,
    /// and EVERY spawn stamps a fresh monotonic `state.generation` via
    /// `spawn_generation.fetch_add(1) + 1` (`spawn_actor_with_watchdog`), while
    /// the restored record carries the PRE-CRASH generation. So
    /// `record.generation != state.generation` ALWAYS holds post-restart. We
    /// reproduce that exact condition by bumping `st.generation` to a fresh value
    /// distinct from the staged record's BEFORE the `Abort { None }`. A
    /// spawn-generation gate on the local reversal would therefore SKIP the
    /// refund on every real restart, leaving the caller over-charged — this test
    /// FAILS against that gated code and PASSES once the gate is removed.
    #[tokio::test]
    async fn crash_recovery_abort_none_reverses_caller_deduction_from_record() {
        use std::sync::atomic::Ordering;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xD8, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let persist_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(SpyPersistence {
                persist_calls: Arc::clone(&persist_calls),
            }),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;
        let now_secs = deps.clock.now_secs();
        let velocity_before = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);

        // Prepare-A persists the deduction AND stages the durable record under
        // `saga`.
        let saga = SagaId("saga-crash-recovery-refund".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(&mut st_cell, &deps, &saga, &[0xD8; 32], &caller, OUTLET, tx).await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");
        // The durable record landed.
        assert!(
            st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "Prepare-A must stage a durable caller-reservation record"
        );
        // The reservation moved owned economy state.
        let hrl_after_reserve = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(hrl_after_reserve < burst_milli);
        assert!(
            st_cell
                .governance
                .velocity_tracker
                .get_velocity(&caller, now_secs)
                > velocity_before
        );

        // Simulate the crash: the in-memory carrier is GONE. We release the
        // carrier's ticket explicitly (a crash would drop it; the test must keep
        // the unbalanced-drop guard quiet) WITHOUT touching owned economy via the
        // generation-checked path is not what a crash does — so instead drop it
        // through the same external-only consume a despawn uses.
        prepared_a
            .reservation
            .ticket
            .void_external_and_consume(deps.payment_adapter.as_ref())
            .await;

        // Reproduce the REAL crash-recovery generation bump: a §17.16.4 restore
        // rehydrates this snapshot into a freshly spawned actor whose
        // `state.generation` is re-stamped by `spawn_generation.fetch_add(1) + 1`
        // (`spawn_actor_with_watchdog`), distinct from the generation in force
        // when Prepare-A staged the record. Bump `st_cell.generation` to a fresh value
        // so the post-restart "live generation differs from the reservation's"
        // condition holds. A spawn-generation gate on the local reversal would
        // SKIP the refund here (over-charging the caller); the fix removes it, so
        // the refund runs regardless of generation.
        st_cell.set_generation_for_test(st_cell.generation.wrapping_add(7));

        // Reset the persist counter so we measure ONLY the recovery abort.
        persist_calls.store(0, Ordering::SeqCst);

        // The §17.16.4 recovery abort: `Abort { None }`. The fix reverses from
        // the durable record.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok(), "crash-recovery abort: {:?}", out.result);
        assert!(
            out.mutated,
            "reversing the caller deduction from the record mutates owned state ⇒ mutated"
        );
        rx.await.unwrap().expect("abort ack");

        // The durable refund was Class-S persisted (the deduction was persisted
        // at Prepare-A; skipping this persist permanently over-charges).
        assert!(
            persist_calls.load(Ordering::SeqCst) >= 1,
            "crash-recovery abort MUST persist the refunded economy"
        );
        // The record is consumed.
        assert!(
            !st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "the durable record must be consumed on the recovery abort"
        );
        // The durable deductions are reversed: hard-rate-limit back to full
        // burst, velocity back to its pre-reserve value.
        let hrl_after_abort = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry present after abort");
        assert_eq!(
            hrl_after_abort, burst_milli,
            "crash-recovery abort must refund the hard-rate-limit token from the record"
        );
        assert_eq!(
            st_cell
                .governance
                .velocity_tracker
                .get_velocity(&caller, now_secs),
            velocity_before,
            "crash-recovery abort must roll back the recorded velocity from the record"
        );
    }

    /// CRASH-RECOVERY ESCROW VOID: a `reverse_caller_reservation_record` on a
    /// record carrying an external escrow authorization VOIDS that hold via the
    /// payment adapter (closing the escrow leak), AND reverses the local economy
    /// UNCONDITIONALLY. Exercises the escrow handle directly (the outbound caller
    /// leg carries no spending UCAN today, so the Prepare-A escrow path is
    /// forward-looking — this asserts the reversal that fires once it is).
    ///
    /// The live `st_cell.generation` is bumped to a fresh value distinct from the
    /// generation in force when the reservation was staged — exactly what a real
    /// crash-recovery respawn produces — to prove the reversal does NOT gate on
    /// spawn-generation: the escrow is still voided and the local velocity entry
    /// is still reversed even though the live actor's generation has moved on.
    #[tokio::test]
    async fn reverse_caller_reservation_record_voids_external_escrow() {
        use crate::context::supervisor::saga_prepared_state::CallerReservationRecord;
        use std::sync::atomic::Ordering;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xD9, OTHER, CALLER).await;
        let caller = DID(CALLER.to_owned());
        let voided = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn> =
            Arc::new(crate::economy::adapter::CountingPaymentAdapter {
                voided: Arc::clone(&voided),
                ..Default::default()
            });
        let deps =
            build_deps_with_payment(CALLER.to_owned(), issuer.verifying_key(), adapter).await;

        // Seed a deduction we can observe being reversed (record a velocity
        // entry the record will reverse by timestamp).
        let now_secs = deps.clock.now_secs();
        st.governance
            .velocity_tracker
            .record_message(&caller, now_secs);
        let velocity_seeded = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);
        assert_eq!(velocity_seeded, 1);

        let record = CallerReservationRecord {
            actor_did: caller.clone(),
            deducted_cost: None,
            needs_hard_rate_limit_refund: false,
            recorded_at_secs: now_secs,
            escrow_authorization: Some(crate::economy::adapter::PaymentAuthorization {
                auth_id: [3u8; 32],
                payer: caller.clone(),
                payee: DID("did:example:payee".to_owned()),
                amount: scp_protocol::economy::types::Amount(10),
                currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                adapter_id: "void-counting".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![],
            }),
        };

        // Move the live actor generation on, as a crash-recovery respawn would.
        // The reversal must still run — it is NOT generation-gated.
        st.generation = st.generation.wrapping_add(11);

        // The helper takes the field-granular `ClassCMut`; wrap the test state in
        // a `ClassSCell` to construct the view, then read results back via Deref.
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let ran = crate::context::outlets_helpers::reverse_caller_reservation_record(
            st_cell.class_c_view(),
            &deps,
            &record,
        )
        .await;
        assert!(
            ran,
            "crash-recovery reversal runs unconditionally (no spawn-generation gate)"
        );
        // The external escrow hold was voided (no leak).
        assert_eq!(
            voided.load(Ordering::SeqCst),
            1,
            "the external escrow authorization must be voided exactly once"
        );
        // The local velocity entry was reversed by timestamp.
        assert_eq!(
            st_cell
                .governance
                .velocity_tracker
                .get_velocity(&caller, now_secs),
            0,
            "the seeded velocity entry must be reversed by timestamp"
        );
    }

    /// LIVE ABORT NO-DOUBLE-REVERSE: a live `Abort { Some(reservation) }`
    /// reverses via the carrier and CONSUMES the durable record WITHOUT
    /// re-reversing. The reversal happens exactly once (carrier), the record is
    /// removed, and a subsequent crash-recovery `Abort { None }` for the same
    /// saga is a clean no-op (no second reversal).
    #[tokio::test]
    async fn live_abort_consumes_record_without_double_reverse() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xDA, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;
        let now_secs = deps.clock.now_secs();
        let velocity_before = st
            .governance
            .velocity_tracker
            .get_velocity(&caller, now_secs);

        let saga = SagaId("saga-live-no-double".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(&mut st_cell, &deps, &saga, &[0xDA; 32], &caller, OUTLET, tx).await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");
        assert!(st_cell.class_s.xctx_caller_reservations.contains_key(&saga));

        // Live abort via the carrier.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, Some(prepared_a), tx).await;
        assert!(out.result.is_ok(), "live abort: {:?}", out.result);
        rx.await.unwrap().expect("abort ack");

        // The record is consumed and the reversal ran EXACTLY once (state back
        // to pre-reserve, not over-refunded).
        assert!(
            !st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "the live abort must consume the durable record"
        );
        let hrl_after = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry present after abort");
        assert_eq!(
            hrl_after, burst_milli,
            "the carrier reversal restored exactly one token (full burst)"
        );
        assert_eq!(
            st_cell
                .governance
                .velocity_tracker
                .get_velocity(&caller, now_secs),
            velocity_before,
            "the carrier reversal rolled velocity back exactly once"
        );

        // A subsequent crash-recovery `Abort { None }` for the same saga is a
        // clean no-op — the record is gone, so nothing is double-reversed.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok(), "redundant abort: {:?}", out.result);
        assert!(
            !out.mutated,
            "a second abort on a consumed record must NOT mutate (no double-reverse)"
        );
        rx.await.unwrap().expect("redundant abort ack");
        // State unchanged from the single reversal.
        assert_eq!(
            st_cell
                .governance
                .hard_rate_limit
                .snapshot_entries()
                .get(CALLER)
                .map(|(tokens, _)| *tokens),
            Some(burst_milli),
            "a second abort must not over-refund the hard-rate-limit"
        );
    }

    /// COMMIT-A REMOVES RECORD: after a successful Commit-A the durable record
    /// is consumed, so a subsequent spurious `Abort { None }` is a no-op and
    /// does NOT reverse the already-settled reservation.
    #[tokio::test]
    async fn commit_a_consumes_record_so_later_abort_is_noop() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xDB, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(OkPersistence),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;

        let saga = SagaId("saga-commit-a-consumes".to_owned());
        let (tx, rx) = oneshot::channel();
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        prepare_a(&mut st_cell, &deps, &saga, &[0xDB; 32], &caller, OUTLET, tx).await;
        let prepared_a = expect_prepared_a(rx.await.unwrap(), "prepared-A");
        assert!(st_cell.class_s.xctx_caller_reservations.contains_key(&saga));
        // After Prepare-A the hard-rate-limit token is consumed (below burst).
        let hrl_after_reserve = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry");
        assert!(hrl_after_reserve < burst_milli);

        // Commit-A settles via the carrier and consumes the record.
        let req = CommitARequest {
            saga_id: saga.clone(),
            reservation: prepared_a,
            caller_context_id: [0xDB; 32],
            caller_did: caller.clone(),
            target_context_id: [0xEE; 32],
            nonce: [0x42; 16],
            receipt: test_receipt_bytes(1_700_000_000_000),
            output_bytes: br#"{"result":1}"#.to_vec(),
        };
        let (tx, rx) = oneshot::channel();
        let out = commit_a(&mut st_cell, &deps, req, tx).await;
        assert!(out.result.is_ok(), "commit_a: {:?}", out.result);
        rx.await.unwrap().expect("commit-a ack");
        assert!(st_cell.class_s.xctx_committed_invocations.contains(&saga));
        assert!(
            !st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "Commit-A must consume the durable reservation record"
        );
        // Capture the settled hard-rate-limit state (the settle does NOT refund
        // — the token stays consumed for a committed invocation).
        let hrl_after_commit = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("hard-rate-limit entry after commit");

        // A spurious crash-recovery `Abort { None }` is a clean no-op: the
        // record is gone, so the settled reservation is NOT reversed.
        let (tx, rx) = oneshot::channel();
        let out = abort(&mut st_cell, &deps, &saga, None, tx).await;
        assert!(out.result.is_ok(), "spurious abort: {:?}", out.result);
        assert!(
            !out.mutated,
            "a spurious abort after Commit-A must NOT mutate (settled state untouched)"
        );
        rx.await.unwrap().expect("spurious abort ack");
        assert_eq!(
            st_cell
                .governance
                .hard_rate_limit
                .snapshot_entries()
                .get(CALLER)
                .map(|(tokens, _)| *tokens),
            Some(hrl_after_commit),
            "a spurious abort must not reverse the already-settled reservation"
        );
    }

    /// HIGH 3 (lost Prepare-A reply balances the must-use ticket): `prepare_a`
    /// durably persists the deduction + record, then replies with the
    /// `PreparedAFields` carrying the `#[must_use]` `OutletEconomyTicket`. If the
    /// supervisor's reply RECEIVER is gone (the §6.2.4 30s phase-timeout fired /
    /// the start was cancelled and dropped the oneshot receiver), `reply.send`
    /// returns `Err(prepared)` and the carrier would otherwise be dropped INSIDE
    /// the actor — tripping the ticket's unbalanced-drop guard (a `debug_assert!`
    /// PANIC under `--features testing`, an escrow leak in release). The fix
    /// recovers the ticket and BALANCES it via `void_external_and_consume`,
    /// leaving the durable deduction + record so the supervisor's eventual abort
    /// reverses the LOCAL economy from the record.
    ///
    /// This drops the receiver BEFORE calling `prepare_a` and asserts (a) NO
    /// panic (the `debug_assert` is live under `--features testing`), (b) the
    /// handler still reports a mutation, and (c) the deduction + durable record
    /// are persisted (left for the abort's record path). PRE-FIX this PANICS on
    /// the unbalanced drop.
    #[tokio::test]
    async fn prepare_a_lost_reply_balances_ticket_and_keeps_record() {
        use std::sync::atomic::Ordering;

        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut st = target_state(0xDC, OTHER, CALLER).await;
        st.role_state.creator_did = CALLER.to_owned();
        let persist_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deps = build_deps(
            CALLER.to_owned(),
            issuer.verifying_key(),
            Box::new(SpyPersistence {
                persist_calls: Arc::clone(&persist_calls),
            }),
        )
        .await;

        let caller = DID(CALLER.to_owned());
        let burst_milli = st.governance.hard_rate_limit.config().burst * 1000;
        let saga = SagaId("saga-prepare-a-lost-reply".to_owned());

        // The supervisor's reply receiver is already GONE before the handler
        // runs — exactly the phase-timeout / cancel window. `reply.send` will
        // return `Err(prepared)` and the handler must balance the recovered
        // ticket rather than drop it (the `#[must_use]` guard PANICS under
        // `--features testing` on an unbalanced drop).
        let (tx, rx) = oneshot::channel();
        drop(rx);

        // No panic here ⇒ the recovered ticket was balanced. (Pre-fix this
        // unwinds on the debug_assert in `OutletEconomyTicket::drop`.)
        let mut st_cell = crate::context::actor::class_s::ClassSCell::new(st);
        let out = prepare_a(&mut st_cell, &deps, &saga, &[0xDC; 32], &caller, OUTLET, tx).await;
        assert!(
            out.result.is_ok(),
            "prepare_a with a dropped reply receiver must still complete: {:?}",
            out.result
        );
        assert!(
            out.mutated,
            "prepare_a staged + persisted the deduction/record ⇒ mutated"
        );

        // The durable deduction + record are LEFT in place — the abort's record
        // path (supervisor `prepared_a == None` → `Abort { None }`) owns the
        // single LOCAL reversal, so the deduction must survive here.
        assert!(
            st_cell.class_s.xctx_caller_reservations.contains_key(&saga),
            "the durable reservation record must survive a lost Prepare-A reply \
             (the abort reverses LOCAL from it)"
        );
        let hrl_after = st_cell
            .governance
            .hard_rate_limit
            .snapshot_entries()
            .get(CALLER)
            .map(|(tokens, _)| *tokens)
            .expect("reserve created a hard-rate-limit entry");
        assert!(
            hrl_after < burst_milli,
            "the deduction must NOT be reversed here (left for the abort's record path): \
             burst_milli={burst_milli}, after={hrl_after}"
        );
        // The deduction + record were Class-S persisted (fail-closed before the
        // reply attempt).
        assert!(
            persist_calls.load(Ordering::SeqCst) >= 1,
            "prepare_a must Class-S persist the deduction + record before replying"
        );
    }
}
